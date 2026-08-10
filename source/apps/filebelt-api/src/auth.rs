// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Json, Router, routing};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use filebelt_database::SessionRecord;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::ApiError;

const SESSION_COOKIE: &str = "filebelt_session";
const CSRF_COOKIE: &str = "filebelt_csrf";
const OIDC_ATTEMPT_COOKIE: &str = "filebelt_oidc_attempt";
const SESSION_DIGEST_DOMAIN: &[u8] = b"filebelt.session.v1\0";
const CSRF_DIGEST_DOMAIN: &[u8] = b"filebelt.csrf.v1\0";
const OIDC_STATE_DIGEST_DOMAIN: &[u8] = b"filebelt.oidc.state.v1\0";
const OIDC_NONCE_DIGEST_DOMAIN: &[u8] = b"filebelt.oidc.nonce.v1\0";
const OIDC_PKCE_DIGEST_DOMAIN: &[u8] = b"filebelt.oidc.pkce.v1\0";
const SESSION_IDLE_SECONDS: i64 = 12 * 60 * 60;
const SESSION_ABSOLUTE_SECONDS: i64 = 7 * 24 * 60 * 60;
const RECENT_AUTH_SECONDS: i64 = 10 * 60;

pub(crate) type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Debug, Deserialize)]
struct LoginQuery {
    #[serde(default = "default_return_path")]
    return_path: String,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    session_id: Uuid,
    user_id: Uuid,
    principal_id: Uuid,
    display_name: String,
    verified_email: Option<String>,
    tenant_admin: bool,
    reauthenticated_recently: bool,
    csrf_token: String,
}

#[derive(Debug, Serialize)]
struct SessionListItem {
    id: Uuid,
    current: bool,
    created_at: String,
    last_seen_at: String,
    idle_expires_at: String,
    absolute_expires_at: String,
    revoked: bool,
    user_agent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RevokeAllRequest {
    #[serde(default)]
    keep_current: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedSession {
    pub(crate) record: SessionRecord,
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", routing::get(login))
        .route("/auth/callback", routing::get(callback))
        .route("/session", routing::get(session_state).delete(logout))
        .route("/sessions", routing::get(list_sessions))
        .route("/sessions/revoke-all", routing::post(revoke_all_sessions))
        .route("/sessions/{session_id}", routing::delete(revoke_session))
}

async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let return_path = validate_return_path(&query.return_path)?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let oidc = state.oidc_client().await?;
    let (authorization_url, csrf_state, nonce) = oidc
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .set_max_age(Duration::from_secs(
            u64::try_from(RECENT_AUTH_SECONDS).map_err(|_| ApiError::internal())?,
        ))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let existing_session_id = authenticate_optional(&state, &headers)
        .await
        .map(|session| session.record.session_id);
    state
        .database
        .create_oidc_attempt(
            state.tenant_id,
            &state.digest(OIDC_STATE_DIGEST_DOMAIN, csrf_state.secret().as_bytes()),
            &state.digest(OIDC_NONCE_DIGEST_DOMAIN, nonce.secret().as_bytes()),
            &state.digest(OIDC_PKCE_DIGEST_DOMAIN, pkce_verifier.secret().as_bytes()),
            nonce.secret(),
            pkce_verifier.secret(),
            return_path,
            existing_session_id,
        )
        .await?;
    let mut response = Redirect::to(authorization_url.as_str()).into_response();
    append_cookie(
        &mut response,
        oidc_attempt_cookie(csrf_state.secret(), false)?,
    )?;
    Ok(response)
}

async fn callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if query.error.is_some() {
        return Err(ApiError::unauthorized());
    }
    let code = bounded_parameter(query.code, "oidc.code_missing")?;
    let returned_state = bounded_parameter(query.state, "oidc.state_missing")?;
    let browser_state = cookie_value(&headers, OIDC_ATTEMPT_COOKIE)
        .filter(|value| value.len() <= 256)
        .ok_or_else(ApiError::unauthorized)?;
    if !bool::from(browser_state.as_bytes().ct_eq(returned_state.as_bytes())) {
        return Err(ApiError::unauthorized());
    }
    let attempt = state
        .database
        .consume_oidc_attempt(
            state.tenant_id,
            &state.digest(OIDC_STATE_DIGEST_DOMAIN, returned_state.as_bytes()),
        )
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "OIDC callback attempt could not be consumed");
            ApiError::unauthorized()
        })?;

    let oidc = state.oidc_client().await?;
    let token_response = oidc
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| ApiError::unauthorized())?
        .set_pkce_verifier(PkceCodeVerifier::new(attempt.pkce_verifier))
        .request_async(&state.oidc_http)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "OIDC token exchange failed");
            ApiError::unauthorized()
        })?;
    let id_token = token_response
        .id_token()
        .ok_or_else(ApiError::unauthorized)?;
    let verifier = oidc.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &Nonce::new(attempt.nonce))
        .map_err(|error| {
            tracing::warn!(error = %error, "OIDC ID token validation failed");
            ApiError::unauthorized()
        })?;

    if let Some(expected_hash) = claims.access_token_hash() {
        let actual_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            id_token
                .signing_alg()
                .map_err(|_| ApiError::unauthorized())?,
            id_token
                .signing_key(&verifier)
                .map_err(|_| ApiError::unauthorized())?,
        )
        .map_err(|_| ApiError::unauthorized())?;
        if actual_hash != *expected_hash {
            return Err(ApiError::unauthorized());
        }
    }
    validate_authentication_context(&state, claims)?;

    let subject = claims.subject().as_str();
    let display_name = claims.name().and_then(|claim| claim.get(None)).map_or_else(
        || {
            claims.preferred_username().map_or_else(
                || subject.to_owned(),
                |username| username.as_str().to_owned(),
            )
        },
        |name| name.as_str().to_owned(),
    );
    let verified_email = if claims.email_verified() == Some(true) {
        claims
            .email()
            .map(|email| email.as_str().trim().to_lowercase())
    } else {
        None
    };
    let claims_snapshot = serde_json::to_value(claims).map_err(|_| ApiError::internal())?;
    let identity = state
        .database
        .link_oidc_identity(
            state.tenant_id,
            state.config.oidc.issuer.as_str(),
            subject,
            &display_name,
            verified_email.as_deref(),
            &claims_snapshot,
        )
        .await?;
    if identity.suspended {
        return Err(ApiError::forbidden(
            "identity.suspended",
            "The local identity is suspended",
        ));
    }

    let session_secret = random_secret()?;
    let csrf_secret = random_secret()?;
    let session_token = format!(
        "fbs1.{}.{}",
        state.config.keys.digest_key_generation, session_secret
    );
    let session_id = state
        .database
        .create_session(
            &identity,
            i32::try_from(state.config.keys.digest_key_generation)
                .map_err(|_| ApiError::internal())?,
            &state.digest(SESSION_DIGEST_DOMAIN, session_token.as_bytes()),
            &state.digest(CSRF_DIGEST_DOMAIN, csrf_secret.as_bytes()),
            SESSION_IDLE_SECONDS,
            SESSION_ABSOLUTE_SECONDS,
            user_agent(&headers),
        )
        .await?;
    if let Some(previous_session_id) = attempt.session_id
        && previous_session_id != session_id
    {
        state
            .database
            .revoke_session(state.tenant_id, identity.principal_id, previous_session_id)
            .await?;
    }

    let mut response = Redirect::to(&attempt.return_path).into_response();
    append_cookie(&mut response, session_cookie(&session_token, false)?)?;
    append_cookie(&mut response, csrf_cookie(&csrf_secret, false)?)?;
    append_cookie(&mut response, oidc_attempt_cookie("", true)?)?;
    response.headers_mut().insert(
        "x-filebelt-csrf",
        HeaderValue::from_str(&csrf_secret).map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}

async fn session_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let csrf_token = csrf_cookie_value(&headers).ok_or_else(ApiError::unauthorized)?;
    validate_csrf_digest(&state, &session.record, csrf_token).await?;
    Ok(Json(SessionResponse {
        session_id: session.record.session_id,
        user_id: session.record.user_id,
        principal_id: session.record.principal_id,
        display_name: session.record.display_name,
        verified_email: session.record.verified_email,
        tenant_admin: session.record.tenant_admin,
        reauthenticated_recently: session.record.reauthenticated_recently,
        csrf_token: csrf_token.to_owned(),
    }))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    state
        .database
        .revoke_session(
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
        )
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    append_cookie(&mut response, session_cookie("", true)?)?;
    append_cookie(&mut response, csrf_cookie("", true)?)?;
    Ok(response)
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionListItem>>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let rows = state
        .database
        .list_sessions(state.tenant_id, session.record.user_id)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| {
                Ok(SessionListItem {
                    id: row.session_id,
                    current: row.session_id == session.record.session_id,
                    created_at: postgres_timestamp(&row.created_at)?,
                    last_seen_at: postgres_timestamp(&row.last_seen_at)?,
                    idle_expires_at: postgres_timestamp(&row.idle_expires_at)?,
                    absolute_expires_at: postgres_timestamp(&row.absolute_expires_at)?,
                    revoked: row.revoked,
                    user_agent: row.user_agent,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
    ))
}

async fn revoke_session(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let session_id = parse_uuid_v4(&session_id)?;
    let owned = state
        .database
        .list_sessions(state.tenant_id, session.record.user_id)
        .await?
        .iter()
        .any(|candidate| candidate.session_id == session_id);
    if !owned {
        return Err(ApiError::not_found());
    }
    state
        .database
        .revoke_session(state.tenant_id, session.record.principal_id, session_id)
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    if session_id == session.record.session_id {
        append_cookie(&mut response, session_cookie("", true)?)?;
        append_cookie(&mut response, csrf_cookie("", true)?)?;
    }
    Ok(response)
}

async fn revoke_all_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeAllRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    if !session.record.reauthenticated_recently {
        return Err(ApiError::forbidden(
            "session.reauthentication_required",
            "Recent OIDC authentication is required",
        ));
    }
    state
        .database
        .revoke_all_sessions(
            state.tenant_id,
            session.record.principal_id,
            session.record.user_id,
            request.keep_current.then_some(session.record.session_id),
        )
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    if !request.keep_current {
        append_cookie(&mut response, session_cookie("", true)?)?;
        append_cookie(&mut response, csrf_cookie("", true)?)?;
    }
    Ok(response)
}

pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    let token = cookie_value(headers, SESSION_COOKIE).ok_or_else(ApiError::unauthorized)?;
    let (generation, _) = parse_session_token(token).ok_or_else(ApiError::unauthorized)?;
    let record = state
        .database
        .resolve_session(
            state.tenant_id,
            generation,
            &state.digest(SESSION_DIGEST_DOMAIN, token.as_bytes()),
            SESSION_IDLE_SECONDS,
        )
        .await
        .map_err(|_| ApiError::unauthorized())?;
    Ok(AuthenticatedSession { record })
}

pub(crate) async fn authenticate_mutation(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    validate_request_origin(state, headers)?;
    let session = authenticate(state, headers).await?;
    let token = headers
        .get("x-filebelt-csrf")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| {
            ApiError::forbidden("csrf.invalid", "The CSRF proof is missing or invalid")
        })?;
    validate_csrf_digest(state, &session.record, token).await?;
    Ok(session)
}

async fn authenticate_optional(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<AuthenticatedSession> {
    authenticate(state, headers).await.ok()
}

async fn validate_csrf_digest(
    state: &AppState,
    session: &SessionRecord,
    token: &str,
) -> Result<(), ApiError> {
    let expected = state.digest(CSRF_DIGEST_DOMAIN, token.as_bytes());
    let matches: bool = expected
        .as_slice()
        .ct_eq(session.csrf_digest.as_slice())
        .into();
    if matches {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "csrf.invalid",
            "The CSRF proof is missing or invalid",
        ))
    }
}

fn validate_request_origin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    let fetch_site = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok());
    if origin != Some(state.public_origin.as_str()) || fetch_site != Some("same-origin") {
        return Err(ApiError::forbidden(
            "csrf.origin_invalid",
            "The request origin is not permitted",
        ));
    }
    Ok(())
}

fn validate_authentication_context(
    state: &AppState,
    claims: &openidconnect::core::CoreIdTokenClaims,
) -> Result<(), ApiError> {
    if let Some(required) = &state.config.oidc.required_acr
        && claims.auth_context_ref().map(AsRef::as_ref) != Some(required.as_str())
    {
        return Err(ApiError::unauthorized());
    }
    let auth_time = claims.auth_time().ok_or_else(ApiError::unauthorized)?;
    let now = unix_time()?;
    let age = now.saturating_sub(auth_time.timestamp());
    if auth_time.timestamp() > now + 60 || age > RECENT_AUTH_SECONDS {
        return Err(ApiError::unauthorized());
    }
    Ok(())
}

fn bounded_parameter(value: Option<String>, code: &'static str) -> Result<String, ApiError> {
    value
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .ok_or_else(|| ApiError::bad_request(code, "The OIDC callback is invalid"))
}

fn default_return_path() -> String {
    "/".into()
}

fn validate_return_path(value: &str) -> Result<&str, ApiError> {
    if value.is_empty()
        || value.len() > 2_048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains(['\\', '\r', '\n'])
        || value.starts_with("/public/")
    {
        return Err(ApiError::bad_request(
            "auth.return_path_invalid",
            "The return path is invalid",
        ));
    }
    Ok(value)
}

fn parse_session_token(value: &str) -> Option<(i32, &str)> {
    if value.len() > 256 {
        return None;
    }
    let mut parts = value.split('.');
    if parts.next()? != "fbs1" {
        return None;
    }
    let generation = parts.next()?.parse::<i32>().ok()?;
    let secret = parts.next()?;
    if generation <= 0 || parts.next().is_some() || URL_SAFE_NO_PAD.decode(secret).ok()?.len() != 32
    {
        return None;
    }
    Some((generation, secret))
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

fn random_secret() -> Result<String, ApiError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn unix_time() -> Result<i64, ApiError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal())?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ApiError::internal())
}

fn user_agent(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 512)
}

pub(crate) fn postgres_timestamp(value: &str) -> Result<String, ApiError> {
    let Some(space) = value.find(' ') else {
        return Err(ApiError::internal());
    };
    let mut normalized = value.to_owned();
    normalized.replace_range(space..=space, "T");
    let offset_start = normalized[space + 1..]
        .rfind(['+', '-'])
        .map(|index| index + space + 1)
        .ok_or_else(ApiError::internal)?;
    if normalized.len() - offset_start == 3 {
        normalized.push_str(":00");
    }
    Ok(normalized)
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header_value in headers.get_all(header::COOKIE) {
        let header_value = header_value.to_str().ok()?;
        for pair in header_value.split(';') {
            let (candidate_name, candidate_value) = pair.trim().split_once('=')?;
            if candidate_name == name {
                if found.is_some() || candidate_value.is_empty() {
                    return None;
                }
                found = Some(candidate_value);
            }
        }
    }
    found
}

fn csrf_cookie_value(headers: &HeaderMap) -> Option<&str> {
    cookie_value(headers, CSRF_COOKIE)
}

fn session_cookie(value: &str, expired: bool) -> Result<HeaderValue, ApiError> {
    cookie_header(SESSION_COOKIE, value, expired, true, "Lax")
}

fn csrf_cookie(value: &str, expired: bool) -> Result<HeaderValue, ApiError> {
    cookie_header(CSRF_COOKIE, value, expired, false, "Strict")
}

fn oidc_attempt_cookie(value: &str, expired: bool) -> Result<HeaderValue, ApiError> {
    let max_age = if expired { 0 } else { 10 * 60 };
    HeaderValue::from_str(&format!(
        "{OIDC_ATTEMPT_COOKIE}={value}; Path=/api/v1/auth/callback; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax"
    ))
    .map_err(|_| ApiError::internal())
}

fn cookie_header(
    name: &str,
    value: &str,
    expired: bool,
    http_only: bool,
    same_site: &str,
) -> Result<HeaderValue, ApiError> {
    let max_age = if expired { 0 } else { SESSION_ABSOLUTE_SECONDS };
    let http_only = if http_only { "; HttpOnly" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/api/v1; Max-Age={max_age}; Secure{http_only}; SameSite={same_site}"
    ))
    .map_err(|_| ApiError::internal())
}

fn append_cookie(response: &mut Response, cookie: HeaderValue) -> Result<(), ApiError> {
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{cookie_value, parse_session_token, postgres_timestamp, validate_return_path};

    #[test]
    fn session_token_parser_rejects_noncanonical_shapes() {
        let token = format!("fbs1.7.{}", "AQ".repeat(16));
        assert!(parse_session_token(&token).is_none());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [1_u8; 32],
        );
        assert_eq!(
            parse_session_token(&format!("fbs1.7.{encoded}")),
            Some((7, encoded.as_str()))
        );
        assert!(parse_session_token(&format!("fbs1.0.{encoded}")).is_none());
    }

    #[test]
    fn return_path_is_local_and_excludes_public_share_boundary() {
        assert_eq!(validate_return_path("/drives").unwrap(), "/drives");
        for value in [
            "",
            "https://evil.test/",
            "//evil.test",
            "/public/share",
            "/a\\b",
        ] {
            assert!(validate_return_path(value).is_err());
        }
    }

    #[test]
    fn duplicate_session_cookies_fail_closed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("filebelt_session=a; filebelt_csrf=b"),
        );
        assert_eq!(cookie_value(&headers, "filebelt_session"), Some("a"));
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("filebelt_session=c"),
        );
        assert_eq!(cookie_value(&headers, "filebelt_session"), None);
    }

    #[test]
    fn postgres_timestamps_are_exposed_as_rfc3339() {
        assert_eq!(
            postgres_timestamp("2026-08-06 12:30:00.123+00").unwrap(),
            "2026-08-06T12:30:00.123+00:00"
        );
        assert!(postgres_timestamp("not-a-timestamp").is_err());
    }
}

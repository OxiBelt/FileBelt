// SPDX-License-Identifier: AGPL-3.0-only

use crate::config::{AdapterConfig, JwtKeySet, MAX_ACTIVE_TABS, MAX_OUTPUT_BYTES};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub origin: Option<String>,
    pub provider_jwt: Option<String>,
    pub range: Option<ByteRange>,
    pub launch_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    pub start: u64,
    pub end_inclusive: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: body.as_bytes().to_vec(),
        }
    }
}

/// Public, unauthenticated source and license information. This remains
/// available even while private Core integration is deliberately fail-closed.
pub fn public_info_response(method: &str, path: &str) -> Option<Response> {
    let revision = option_env!("FILEBELT_SOURCE_REVISION").unwrap_or("unreleased-worktree");
    let source_root =
        option_env!("FILEBELT_SOURCE_URL").unwrap_or("https://github.com/OxiBelt/FileBelt");
    let source_ref = option_env!("FILEBELT_SOURCE_REF").unwrap_or("unreleased");
    match (method, path) {
        ("GET", "/health/live") => Some(Response::text(200, "live\n")),
        ("GET", "/health/ready") => Some(Response::text(200, "ready\n")),
        ("GET", "/onlyoffice/source") => Some(Response::text(
            200,
            &format!(
                "Component: FileBelt ONLYOFFICE Adapter\nLicense: AGPL-3.0-only\nVersion: {}\nRevision: {revision}\nCorresponding Source: {source_root}/tree/{revision}\nSource Ref: {source_ref}\nBuild instructions: {source_root}/blob/{revision}/adapters/onlyoffice/README.md\nUpstream ONLYOFFICE version: 9.4.0\nProvider assets included: no\n",
                env!("CARGO_PKG_VERSION")
            ),
        )),
        ("GET", "/onlyoffice/about") => Some(Response::text(
            200,
            &format!(
                "Component: FileBelt ONLYOFFICE Adapter\nVersion: {}\nRevision: {revision}\nSource Ref: {source_ref}\nLicense: AGPL-3.0-only\nCorresponding Source: {source_root}/tree/{revision}\nBuild instructions: {source_root}/blob/{revision}/adapters/onlyoffice/README.md\nProvider: operator-supplied ONLYOFFICE Docs Community 9.4.0\nNotices: {source_root}/blob/{revision}/adapters/onlyoffice/THIRD_PARTY_NOTICES.md\n",
                env!("CARGO_PKG_VERSION")
            ),
        )),
        _ => None,
    }
}

/// A transport implementation belongs outside this crate.  It exchanges only
/// provider-neutral FileBelt identifiers, one-use launch IDs, and fresh scoped
/// capabilities: never an adapter type, database row, host path, or payload
/// locator.
pub trait CoreClient {
    fn redeem_one_use_launch(&self, launch_id: &str) -> Result<LaunchGrant, CoreError>;
    fn issue_fresh_read_capability(
        &self,
        document_id: &str,
        participant_id: &str,
    ) -> Result<ReadCapability, CoreError>;
    fn fetch_input_with_capability(
        &self,
        capability: &ReadCapability,
        range: ByteRange,
    ) -> Result<FetchedInput, CoreError>;
    fn record_callback(
        &self,
        event: &CallbackEvent,
        fingerprint: &EventFingerprint,
        participant_id: &str,
    ) -> Result<Idempotency, CoreError>;
    fn commit_callback_output(
        &self,
        event: &CallbackEvent,
        fingerprint: &EventFingerprint,
        output: &CallbackOutput,
    ) -> Result<Idempotency, CoreError>;
}

pub trait ProviderJwtVerifier {
    /// Verifies the documented `HS256` DocumentServer outbox token with the
    /// current key and then a still-overlapping retiring key. ONLYOFFICE signs
    /// the exact request payload; it does not add FileBelt issuer, audience,
    /// expiry, generation, or purpose claims.
    fn verify(
        &self,
        compact_jwt: &str,
        config: &AdapterConfig,
        keys: &JwtKeySet,
        now: SystemTime,
    ) -> Result<ProviderClaims, JwtError>;
}

pub trait EventFingerprintDeriver {
    /// Produce a canonical cryptographic fingerprint of the verified callback
    /// event. It must include document, status, save type, URL, revision, and
    /// provider event ID.  A process may not acknowledge a callback if it
    /// cannot derive one.
    fn derive(&self, event: &CallbackEvent) -> Result<EventFingerprint, FingerprintError>;
}

pub trait EgressGateway {
    /// The adapter supplies an already validated HTTPS URL and immutable size
    /// ceiling. The gateway performs mTLS target authorization and refuses all
    /// redirects; no direct HTTP client exists in this adapter.
    fn fetch_no_redirect(
        &self,
        url: &str,
        maximum_bytes: u64,
    ) -> Result<CallbackOutput, EgressError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchGrant {
    pub document_id: String,
    pub editor_config_json: String,
    pub active_tabs: usize,
    pub source_read_capability: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadCapability {
    pub authorization: String,
    pub url_path: String,
    pub size_bytes: u64,
}

impl ReadCapability {
    pub fn range_header(range: ByteRange) -> String {
        format!("bytes={}-{}", range.start, range.end_inclusive)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderClaims {
    /// Exact HS256-authenticated provider payload. No FileBelt issuer,
    /// audience, expiry, generation, or purpose claims are expected.
    pub payload: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchedInput {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// Bounded callback output spooled to the adapter's ephemeral `/tmp` volume.
/// It is deleted on all in-process success and error paths; the chart mounts
/// that directory as an in-memory emptyDir so a process crash cannot persist
/// payload bytes beyond the pod lifetime.
#[derive(Debug)]
pub struct CallbackOutput {
    pub(crate) path: PathBuf,
    pub(crate) content_type: String,
    pub(crate) size: u64,
}

impl CallbackOutput {
    pub(crate) fn new(path: PathBuf, content_type: String, size: u64) -> Self {
        Self {
            path,
            content_type,
            size,
        }
    }

    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Drop for CallbackOutput {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventFingerprint(pub [u8; 32]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Idempotency {
    New,
    /// A prior output fetch failed before Core committed a resulting version.
    /// Retrying the same verified event is permitted.
    Pending,
    Duplicate,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreError {
    Unavailable,
    Denied,
    Gone,
    Invalid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtError {
    Unavailable,
    Invalid,
    Expired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FingerprintError {
    Unavailable,
    Invalid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressError {
    Denied,
    TooLarge,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackStatus {
    Editing = 1,
    MustSave = 2,
    SaveError = 3,
    ClosedNoChanges = 4,
    ForceSave = 6,
    ForceSaveError = 7,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForceSaveType {
    Command = 0,
    UserSave = 1,
    Timer = 2,
    FormSubmit = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParticipantActivity {
    Unspecified,
    Connected,
    Disconnected,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityParseError {
    Invalid,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackEvent {
    pub document_id: String,
    pub participant_id: String,
    pub status: CallbackStatus,
    pub force_save_type: Option<ForceSaveType>,
    pub activity: ParticipantActivity,
    /// The ONLYOFFICE `actions[0].userid` consumed for a status-1 callback.
    /// It must equal the route-bound participant UUID.
    pub activity_user_id: String,
    pub output_url: Option<String>,
    pub provider_event_id: String,
    pub revision: String,
}

pub fn callback_requires_output(event: &CallbackEvent) -> bool {
    matches!(
        event.status,
        CallbackStatus::MustSave | CallbackStatus::ForceSave
    )
}

pub fn allowed_document_media_type(value: &str) -> bool {
    matches!(
        value.split(';').next().unwrap_or_default().trim(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    )
}

pub fn validate_callback(
    event: &CallbackEvent,
    config: &AdapterConfig,
) -> Result<(), CallbackError> {
    if event.document_id.is_empty() || !is_uuid(&event.participant_id) {
        return Err(CallbackError::Malformed);
    }
    if matches!(event.status, CallbackStatus::Editing)
        && (event.activity == ParticipantActivity::Unspecified
            || event.activity_user_id != event.participant_id)
    {
        return Err(CallbackError::Malformed);
    }
    if !matches!(event.status, CallbackStatus::Editing)
        && (event.activity != ParticipantActivity::Unspecified
            || !event.activity_user_id.is_empty())
    {
        return Err(CallbackError::Malformed);
    }
    if matches!(event.status, CallbackStatus::MustSave) && event.revision.is_empty() {
        return Err(CallbackError::Malformed);
    }
    if matches!(
        event.status,
        CallbackStatus::ForceSave | CallbackStatus::ForceSaveError
    ) && event.force_save_type.is_none()
    {
        return Err(CallbackError::MissingForceSaveType);
    }
    if callback_requires_output(event) {
        let Some(url) = &event.output_url else {
            return Err(CallbackError::MissingOutput);
        };
        if !config.document_server_origin.exact_url(url) {
            return Err(CallbackError::OutputOrigin);
        }
    } else if matches!(
        event.status,
        CallbackStatus::SaveError | CallbackStatus::ForceSaveError
    ) {
        if event
            .output_url
            .as_deref()
            .is_some_and(|url| !config.document_server_origin.exact_url(url))
        {
            return Err(CallbackError::OutputOrigin);
        }
    } else if event.output_url.is_some() {
        return Err(CallbackError::UnexpectedOutput);
    }
    Ok(())
}

const MAX_SERVER_VERSION: u64 = 9_007_199_254_740_991;

/// ONLYOFFICE documents `history.serverVersion` as a JSON number, although
/// deployments also emit a quoted integer. Normalize both representations so
/// callback body and signed payload compare in one canonical form.
pub fn normalize_server_version(value: &Value) -> Option<String> {
    let number = match value {
        Value::Number(number) => number.as_u64()?,
        Value::String(value)
            if !value.is_empty()
                && value.len() <= 16
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value.parse().ok()?
        }
        _ => return None,
    };
    (number <= MAX_SERVER_VERSION).then(|| number.to_string())
}

/// Status-1 actions are participant presence events. The adapter accepts one
/// exact action only, preventing a provider callback for one editor from
/// changing another participant's activity.
pub fn participant_activity_from_actions(
    status: CallbackStatus,
    actions: Option<&Value>,
    participant_id: &str,
) -> Result<(ParticipantActivity, String), ActivityParseError> {
    if status != CallbackStatus::Editing {
        return Ok((ParticipantActivity::Unspecified, String::new()));
    }
    let actions = actions
        .and_then(Value::as_array)
        .ok_or(ActivityParseError::Invalid)?;
    let [action] = actions.as_slice() else {
        return Err(ActivityParseError::Invalid);
    };
    let user_id = action
        .get("userid")
        .and_then(Value::as_str)
        .ok_or(ActivityParseError::Invalid)?;
    if user_id != participant_id {
        return Err(ActivityParseError::Invalid);
    }
    let activity = match action.get("type").and_then(Value::as_u64) {
        Some(0) => ParticipantActivity::Disconnected,
        Some(1) => ParticipantActivity::Connected,
        _ => return Err(ActivityParseError::Invalid),
    };
    Ok((activity, user_id.to_owned()))
}

/// The HTTP body is only a transport envelope. It is accepted only when its
/// security-relevant fields exactly match the verified DocumentServer outbox
/// JWT payload (or its documented `payload` wrapper).
pub fn signed_callback_matches(payload: &Value, event: &CallbackEvent) -> bool {
    let payload = payload
        .get("payload")
        .filter(|value| value.is_object())
        .unwrap_or(payload);
    if payload.get("key").and_then(Value::as_str) != Some(event.document_id.as_str())
        || payload.get("status").and_then(Value::as_u64) != Some(event.status as u64)
        || payload.get("url").and_then(Value::as_str) != event.output_url.as_deref()
    {
        return false;
    }
    let signed_force = payload.get("forcesavetype").and_then(Value::as_u64);
    if signed_force != event.force_save_type.map(|value| value as u64) {
        return false;
    }
    let signed_revision = payload
        .get("history")
        .and_then(|history| history.get("serverVersion"))
        .and_then(normalize_server_version)
        .or_else(|| payload.get("revision").and_then(normalize_server_version))
        .unwrap_or_default();
    if signed_revision != event.revision {
        return false;
    }
    let Ok((signed_activity, signed_user_id)) = participant_activity_from_actions(
        event.status,
        payload.get("actions"),
        &event.participant_id,
    ) else {
        return false;
    };
    if signed_activity != event.activity || signed_user_id != event.activity_user_id {
        return false;
    }
    let signed_event_id = payload
        .get("userdata")
        .and_then(Value::as_str)
        .or_else(|| payload.get("event_id").and_then(Value::as_str))
        .unwrap_or(&signed_revision);
    signed_event_id == event.provider_event_id
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackError {
    Malformed,
    MissingForceSaveType,
    MissingOutput,
    UnexpectedOutput,
    OutputOrigin,
    Jwt,
    Fingerprint,
    Core,
    Egress,
    MediaType,
}

pub struct AdapterService<C, J, F, E> {
    pub config: AdapterConfig,
    pub core: C,
    pub jwt: J,
    pub fingerprints: F,
    pub egress: E,
}

impl<C: CoreClient, J: ProviderJwtVerifier, F: EventFingerprintDeriver, E: EgressGateway>
    AdapterService<C, J, F, E>
{
    pub fn dispatch(&self, request: Request, now: SystemTime) -> Response {
        if let Some(response) = public_info_response(&request.method, &request.path) {
            return response;
        }
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/onlyoffice/launch") => self.launch(request, now),
            ("GET", path) if input_session_and_participant(path).is_some() => {
                self.input(request, now)
            }
            _ => Response::text(404, "not found"),
        }
    }

    fn launch(&self, request: Request, _now: SystemTime) -> Response {
        if request
            .origin
            .as_deref()
            .is_some_and(|origin| origin != self.config.public_origin.as_str())
        {
            return Response::text(403, "launch origin denied");
        }
        let Some(launch_id) = request.launch_id else {
            return Response::text(400, "missing one-use launch");
        };
        match self.core.redeem_one_use_launch(&launch_id) {
            Ok(grant) if grant.active_tabs < MAX_ACTIVE_TABS => {
                let mut response = Response::text(200, &grant.editor_config_json);
                // Host-only: deliberately omit Domain. The cookie holds only a
                // non-authoritative launch correlation, never a Core session.
                response
                    .headers
                    .insert("Cache-Control".into(), "no-store".into());
                response.headers.insert(
                    "Set-Cookie".into(),
                    format!(
                        "filebelt_onlyoffice_launch={}; Path=/; Secure; HttpOnly; SameSite=Lax",
                        opaque_launch_cookie(&grant.document_id)
                    ),
                );
                response
            }
            Ok(_) => Response::text(429, "active tab limit reached"),
            Err(CoreError::Gone) => Response::text(410, "launch already consumed"),
            Err(CoreError::Denied) => Response::text(403, "launch denied"),
            Err(_) => Response::text(503, "core unavailable"),
        }
    }

    fn input(&self, request: Request, now: SystemTime) -> Response {
        let Some((document_id, participant_id)) = input_session_and_participant(&request.path)
        else {
            return Response::text(404, "not found");
        };
        let Some(jwt) = request.provider_jwt else {
            return Response::text(401, "provider jwt required");
        };
        let keys = match self.config.load_outbox_keys(now) {
            Ok(keys) => keys,
            Err(_) => return Response::text(503, "jwt key unavailable"),
        };
        let claims = match self.jwt.verify(&jwt, &self.config, &keys, now) {
            Ok(claims) => claims,
            Err(_) => return Response::text(401, "invalid provider jwt"),
        };
        if provider_input_url(&claims.payload)
            != Some(self.config.public_origin.as_str().to_owned() + &request.path)
        {
            return Response::text(401, "invalid provider jwt");
        }
        let capability = match self
            .core
            .issue_fresh_read_capability(document_id, participant_id)
        {
            Ok(capability) => capability,
            Err(CoreError::Denied | CoreError::Gone) => {
                return Response::text(404, "input unavailable");
            }
            Err(_) => return Response::text(503, "core unavailable"),
        };
        let partial = request.range.is_some();
        let mut range = request.range.unwrap_or(ByteRange {
            start: 0,
            end_inclusive: capability.size_bytes.saturating_sub(1),
        });
        if range.end_inclusive == u64::MAX {
            range.end_inclusive = capability.size_bytes.saturating_sub(1);
        }
        if capability.size_bytes == 0
            || range.start > range.end_inclusive
            || range.end_inclusive >= capability.size_bytes
        {
            return Response::text(416, "invalid range");
        }
        match self.core.fetch_input_with_capability(&capability, range) {
            Ok(input) => {
                let mut response = Response {
                    status: if partial { 206 } else { 200 },
                    headers: BTreeMap::new(),
                    body: input.bytes,
                };
                response
                    .headers
                    .insert("Content-Type".into(), input.content_type);
                response
                    .headers
                    .insert("Accept-Ranges".into(), "bytes".into());
                response
                    .headers
                    .insert("Cache-Control".into(), "no-store".into());
                if partial {
                    response.headers.insert(
                        "Content-Range".into(),
                        format!(
                            "bytes {}-{}/{}",
                            range.start, range.end_inclusive, capability.size_bytes
                        ),
                    );
                }
                response
            }
            Err(CoreError::Denied | CoreError::Gone) => Response::text(404, "input unavailable"),
            Err(_) => Response::text(503, "core unavailable"),
        }
    }

    pub fn callback(
        &self,
        compact_jwt: &str,
        event: CallbackEvent,
        now: SystemTime,
    ) -> Result<Idempotency, CallbackError> {
        validate_callback(&event, &self.config)?;
        let keys = self
            .config
            .load_outbox_keys(now)
            .map_err(|_| CallbackError::Jwt)?;
        let claims = self
            .jwt
            .verify(compact_jwt, &self.config, &keys, now)
            .map_err(|_| CallbackError::Jwt)?;
        if !signed_callback_matches(&claims.payload, &event) {
            return Err(CallbackError::Jwt);
        }
        let fingerprint = self
            .fingerprints
            .derive(&event)
            .map_err(|_| CallbackError::Fingerprint)?;
        let result = self
            .core
            .record_callback(&event, &fingerprint, &event.participant_id)
            .map_err(|_| CallbackError::Core)?;
        if result == Idempotency::Duplicate || !callback_requires_output(&event) {
            return Ok(result);
        }
        let url = event
            .output_url
            .as_deref()
            .ok_or(CallbackError::MissingOutput)?;
        let output = self
            .egress
            .fetch_no_redirect(url, MAX_OUTPUT_BYTES)
            .map_err(|_| CallbackError::Egress)?;
        if output.size() > MAX_OUTPUT_BYTES {
            return Err(CallbackError::Egress);
        }
        if !allowed_document_media_type(output.content_type()) {
            return Err(CallbackError::MediaType);
        }
        self.core
            .commit_callback_output(&event, &fingerprint, &output)
            .map_err(|_| CallbackError::Core)
    }
}

fn input_session_and_participant(path: &str) -> Option<(&str, &str)> {
    let value = path.strip_prefix("/onlyoffice/input/")?;
    let (session, participant) = value.split_once('/')?;
    if is_uuid(session) && is_uuid(participant) {
        Some((session, participant))
    } else {
        None
    }
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) && byte == b'-' || byte.is_ascii_hexdigit()
        })
}

fn provider_input_url(payload: &Value) -> Option<String> {
    payload
        .get("payload")
        .and_then(|value| value.get("url"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn opaque_launch_cookie(document_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"filebelt.onlyoffice.launch-cookie.v1\0");
    hasher.update(document_id.as_bytes());
    hasher.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DOCUMENT_SERVER_VERSION, MtlsClientConfig, Origin, Provider, ServerTlsConfig,
    };
    use std::path::PathBuf;
    use url::Url;

    fn config() -> AdapterConfig {
        AdapterConfig {
            provider: Provider::OnlyOfficeDocumentServer940,
            document_server_version: DOCUMENT_SERVER_VERSION.into(),
            public_origin: Origin::parse("https://files.example.test").unwrap(),
            document_server_origin: Origin::parse("https://office.example.test").unwrap(),
            document_server_api_js:
                "https://office.example.test/web-apps/apps/api/documents/api.js".into(),
            browser_jwt_file: PathBuf::from("browser"),
            outbox_jwt_current_file: PathBuf::from("outbox-current"),
            outbox_jwt_retiring_file: None,
            outbox_jwt_retiring_until: None,
            tenant_id: "00000000-0000-4000-8000-000000000001".into(),
            core: endpoint("https://core.example.test"),
            io: endpoint("https://io.example.test"),
            egress_gateway: endpoint("https://egress.example.test"),
            server_tls: ServerTlsConfig {
                certificate_chain_file: "server-certificate".into(),
                private_key_file: "server-key".into(),
                client_ca_file: "client-ca".into(),
                allowed_client_uri_san: "spiffe://filebelt/oxibelt/onlyoffice".into(),
            },
        }
    }

    fn endpoint(url: &str) -> MtlsClientConfig {
        MtlsClientConfig {
            url: Url::parse(url).unwrap(),
            certificate_chain_file: "certificate".into(),
            private_key_file: "key".into(),
            server_ca_file: "ca".into(),
        }
    }

    #[test]
    fn callback_statuses_and_force_save_rules_are_explicit() {
        for status in [
            CallbackStatus::Editing,
            CallbackStatus::MustSave,
            CallbackStatus::SaveError,
            CallbackStatus::ClosedNoChanges,
            CallbackStatus::ForceSave,
            CallbackStatus::ForceSaveError,
        ] {
            let event = CallbackEvent {
                document_id: "d".into(),
                participant_id: "550e8400-e29b-41d4-a716-446655440001".into(),
                status,
                force_save_type: if matches!(
                    status,
                    CallbackStatus::ForceSave | CallbackStatus::ForceSaveError
                ) {
                    Some(ForceSaveType::UserSave)
                } else {
                    None
                },
                activity: if status == CallbackStatus::Editing {
                    ParticipantActivity::Connected
                } else {
                    ParticipantActivity::Unspecified
                },
                activity_user_id: if status == CallbackStatus::Editing {
                    "550e8400-e29b-41d4-a716-446655440001".into()
                } else {
                    String::new()
                },
                output_url: if matches!(
                    status,
                    CallbackStatus::MustSave | CallbackStatus::ForceSave
                ) {
                    Some("https://office.example.test/cache/x".into())
                } else {
                    None
                },
                provider_event_id: "e".into(),
                revision: "r".into(),
            };
            assert_eq!(validate_callback(&event, &config()), Ok(()));
        }
    }

    #[test]
    fn callback_rejects_cross_origin_and_missing_force_save_type() {
        let event = CallbackEvent {
            document_id: "d".into(),
            participant_id: "550e8400-e29b-41d4-a716-446655440001".into(),
            status: CallbackStatus::MustSave,
            force_save_type: None,
            activity: ParticipantActivity::Unspecified,
            activity_user_id: String::new(),
            output_url: Some("https://evil.example/cache".into()),
            provider_event_id: "e".into(),
            revision: "r".into(),
        };
        assert_eq!(
            validate_callback(&event, &config()),
            Err(CallbackError::OutputOrigin)
        );
        let event = CallbackEvent {
            status: CallbackStatus::ForceSave,
            output_url: Some("https://office.example.test/cache".into()),
            ..event
        };
        assert_eq!(
            validate_callback(&event, &config()),
            Err(CallbackError::MissingForceSaveType)
        );
        let error_with_url = CallbackEvent {
            status: CallbackStatus::ForceSaveError,
            force_save_type: Some(ForceSaveType::Timer),
            output_url: Some("https://evil.example/cache".into()),
            ..event
        };
        assert_eq!(
            validate_callback(&error_with_url, &config()),
            Err(CallbackError::OutputOrigin)
        );
    }

    #[test]
    fn callback_transport_must_match_the_verified_provider_payload() {
        let event = CallbackEvent {
            document_id: "session".into(),
            participant_id: "550e8400-e29b-41d4-a716-446655440001".into(),
            status: CallbackStatus::MustSave,
            force_save_type: None,
            activity: ParticipantActivity::Unspecified,
            activity_user_id: String::new(),
            output_url: Some("https://office.example.test/cache/output".into()),
            provider_event_id: "event".into(),
            revision: "42".into(),
        };
        let payload = serde_json::json!({
            "key": "session", "status": 2,
            "url": "https://office.example.test/cache/output",
            "userdata": "event", "history": {"serverVersion": 42}
        });
        assert!(signed_callback_matches(&payload, &event));
        let tampered = serde_json::json!({"payload": {"key": "other", "status": 2}});
        assert!(!signed_callback_matches(&tampered, &event));
    }

    #[test]
    fn editing_activity_requires_one_route_bound_signed_action() {
        let participant = "550e8400-e29b-41d4-a716-446655440001";
        let actions = serde_json::json!([{"type": 1, "userid": participant}]);
        assert_eq!(
            participant_activity_from_actions(CallbackStatus::Editing, Some(&actions), participant),
            Ok((ParticipantActivity::Connected, participant.into()))
        );
        for actions in [
            serde_json::json!([]),
            serde_json::json!([{"type": 1, "userid": participant}, {"type": 0, "userid": participant}]),
            serde_json::json!([{"type": 9, "userid": participant}]),
            serde_json::json!([{"type": 1, "userid": "other"}]),
        ] {
            assert!(
                participant_activity_from_actions(
                    CallbackStatus::Editing,
                    Some(&actions),
                    participant
                )
                .is_err()
            );
        }
        assert_eq!(
            participant_activity_from_actions(CallbackStatus::MustSave, None, participant),
            Ok((ParticipantActivity::Unspecified, String::new()))
        );
    }

    #[test]
    fn signed_editing_action_cannot_be_substituted() {
        let participant = "550e8400-e29b-41d4-a716-446655440001";
        let event = CallbackEvent {
            document_id: "session".into(),
            participant_id: participant.into(),
            status: CallbackStatus::Editing,
            force_save_type: None,
            activity: ParticipantActivity::Connected,
            activity_user_id: participant.into(),
            output_url: None,
            provider_event_id: String::new(),
            revision: String::new(),
        };
        let payload = serde_json::json!({
            "key": "session", "status": 1,
            "actions": [{"type": 1, "userid": participant}]
        });
        assert!(signed_callback_matches(&payload, &event));
        let replaced = serde_json::json!({
            "key": "session", "status": 1,
            "actions": [{"type": 0, "userid": participant}]
        });
        assert!(!signed_callback_matches(&replaced, &event));
    }

    #[test]
    fn normalizes_bounded_numeric_server_versions() {
        assert_eq!(
            normalize_server_version(&serde_json::json!(42)),
            Some("42".into())
        );
        assert_eq!(
            normalize_server_version(&serde_json::json!("00042")),
            Some("42".into())
        );
        assert_eq!(normalize_server_version(&serde_json::json!(-1)), None);
        assert_eq!(
            normalize_server_version(&serde_json::json!("revision")),
            None
        );
        assert_eq!(
            normalize_server_version(&serde_json::json!(9_007_199_254_740_992_u64)),
            None
        );
    }

    #[test]
    fn source_information_is_public_without_core_authority() {
        let response = public_info_response("GET", "/onlyoffice/source").unwrap();
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.to_ascii_lowercase().contains("source"));
        assert!(body.contains("Corresponding Source: https://github.com/OxiBelt/FileBelt/tree/"));
        assert!(!body.contains("/adapters/onlyoffice\nSource Ref:"));
        assert!(public_info_response("POST", "/onlyoffice/source").is_none());
    }

    #[test]
    fn input_path_and_launch_cookie_are_not_prefix_or_identifier_leaks() {
        assert_eq!(
            input_session_and_participant(
                "/onlyoffice/input/550e8400-e29b-41d4-a716-446655440000/550e8400-e29b-41d4-a716-446655440001"
            ),
            Some((
                "550e8400-e29b-41d4-a716-446655440000",
                "550e8400-e29b-41d4-a716-446655440001"
            ))
        );
        assert_eq!(
            input_session_and_participant("/onlyoffice/input/../session"),
            None
        );
        assert_ne!(opaque_launch_cookie("session-1"), "session-1");
    }

    #[test]
    fn admits_only_supported_office_media_types() {
        assert!(allowed_document_media_type(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ));
        assert!(allowed_document_media_type(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; charset=binary"
        ));
        assert!(!allowed_document_media_type("application/octet-stream"));
        assert!(!allowed_document_media_type("application/pdf"));
    }

    impl CallbackEvent {
        pub(crate) fn test_event() -> Self {
            Self {
                document_id: "session".into(),
                participant_id: "550e8400-e29b-41d4-a716-446655440001".into(),
                status: CallbackStatus::MustSave,
                force_save_type: None,
                activity: ParticipantActivity::Unspecified,
                activity_user_id: String::new(),
                output_url: Some("https://office.example.test/cache/output".into()),
                provider_event_id: "provider-event".into(),
                revision: "revision".into(),
            }
        }
    }
}

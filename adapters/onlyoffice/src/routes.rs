// SPDX-License-Identifier: AGPL-3.0-only

use crate::config::{AdapterConfig, JwtKeySet, MAX_ACTIVE_TABS, MAX_OUTPUT_BYTES};
use quick_xml::events::{BytesStart, Event as XmlEvent};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read as _};
use std::path::{Component, Path, PathBuf};
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
    /// event. The legacy `callback.v1` field set includes document, status,
    /// save type, activity, URL, revision, and provider event ID, but not the
    /// later-added file type. A process may not acknowledge a callback if it
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
    /// The exact lower-case ONLYOFFICE file type, authenticated in both the
    /// callback body and provider outbox JWT.
    pub file_type: String,
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
    normalized_document_media_type(value).is_some()
}

pub fn normalized_document_media_type(value: &str) -> Option<&'static str> {
    match value.split(';').next().unwrap_or_default().trim() {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        }
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => {
            Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        }
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            Some("application/vnd.openxmlformats-officedocument.presentationml.presentation")
        }
        "application/vnd.oasis.opendocument.text" => {
            Some("application/vnd.oasis.opendocument.text")
        }
        "application/vnd.oasis.opendocument.spreadsheet" => {
            Some("application/vnd.oasis.opendocument.spreadsheet")
        }
        "application/vnd.oasis.opendocument.presentation" => {
            Some("application/vnd.oasis.opendocument.presentation")
        }
        _ => None,
    }
}

pub fn document_media_type_for_file_type(value: &str) -> Option<&'static str> {
    match value {
        "docx" => Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "xlsx" => Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "pptx" => Some("application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "odt" => Some("application/vnd.oasis.opendocument.text"),
        "ods" => Some("application/vnd.oasis.opendocument.spreadsheet"),
        "odp" => Some("application/vnd.oasis.opendocument.presentation"),
        _ => None,
    }
}

pub fn validate_callback(
    event: &CallbackEvent,
    config: &AdapterConfig,
) -> Result<(), CallbackError> {
    if event.document_id.is_empty() || !is_uuid(&event.participant_id) {
        return Err(CallbackError::Malformed);
    }
    if document_media_type_for_file_type(&event.file_type).is_none() {
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
        || payload.get("filetype").and_then(Value::as_str) != Some(event.file_type.as_str())
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
    Package,
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
        if !has_exact_launch_origin(&request, &self.config) {
            return Response::text(403, "launch origin denied");
        }
        let Some(launch_id) = request.launch_id else {
            return Response::text(400, "missing one-use launch");
        };
        match self.core.redeem_one_use_launch(&launch_id) {
            Ok(grant) if grant.active_tabs < MAX_ACTIVE_TABS => {
                let mut response = Response::text(200, &grant.editor_config_json);
                response
                    .headers
                    .insert("Cache-Control".into(), "no-store".into());
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
        if normalized_document_media_type(output.content_type())
            != document_media_type_for_file_type(&event.file_type)
        {
            return Err(CallbackError::MediaType);
        }
        validate_output_package(&output, &event.file_type)?;
        self.core
            .commit_callback_output(&event, &fingerprint, &output)
            .map_err(|_| CallbackError::Core)
    }
}

const MAX_ZIP_ENTRIES: usize = 10_000;
const MAX_ZIP_UNCOMPRESSED_BYTES: u64 = 1_073_741_824;
const MAX_REQUIRED_METADATA_BYTES: u64 = 1_048_576;
const MAX_ODF_CONTENT_XML_BYTES: u64 = 100 * 1024 * 1024;
// Legitimate ODF documents are shallow trees. This compatibility ceiling is
// deliberately far below quick-xml 0.41's internal u16 namespace depth, so an
// attacker cannot wrap the resolver while preserving ordinary document shape.
const MAX_ODF_XML_NESTING_DEPTH: usize = 256;
const ODF_OFFICE_NAMESPACE: &[u8] = b"urn:oasis:names:tc:opendocument:xmlns:office:1.0";
const ODF_SCRIPT_NAMESPACE: &[u8] = b"urn:oasis:names:tc:opendocument:xmlns:script:1.0";
const ODF_TEXT_NAMESPACE: &[u8] = b"urn:oasis:names:tc:opendocument:xmlns:text:1.0";
const ODF_TABLE_NAMESPACE: &[u8] = b"urn:oasis:names:tc:opendocument:xmlns:table:1.0";

/// Validates the bounded, preserved-format package before FileBelt accepts a
/// provider save. This owns no payload publication; Core/I/O retain the
/// capability-scoped write and finalization seam.
pub(crate) fn validate_output_package(
    output: &CallbackOutput,
    file_type: &str,
) -> Result<(), CallbackError> {
    let expected_media_type =
        document_media_type_for_file_type(file_type).ok_or(CallbackError::Package)?;
    let file = std::fs::File::open(&output.path).map_err(|_| CallbackError::Package)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| CallbackError::Package)?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(CallbackError::Package);
    }
    let mut names = BTreeSet::new();
    let mut total = 0_u64;
    let mut required = BTreeSet::new();
    let mut mimetype_is_first = false;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| CallbackError::Package)?;
        let name = entry.name();
        let canonical = canonical_zip_path(name).ok_or(CallbackError::Package)?;
        if !names.insert(canonical.clone())
            || entry.encrypted()
            || !matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
        {
            return Err(CallbackError::Package);
        }
        total = total
            .checked_add(entry.size())
            .ok_or(CallbackError::Package)?;
        if total > MAX_ZIP_UNCOMPRESSED_BYTES || is_macro_path(&canonical) {
            return Err(CallbackError::Package);
        }
        if canonical == "mimetype" {
            mimetype_is_first = index == 0;
        }
        if required_metadata_path(file_type, &canonical)
            && entry.size() > MAX_REQUIRED_METADATA_BYTES
        {
            return Err(CallbackError::Package);
        }
        if matches!(file_type, "odt" | "ods" | "odp")
            && canonical == "content.xml"
            && !odf_content_size_allowed(entry.size())
        {
            return Err(CallbackError::Package);
        }
        if required_package_path(file_type, &canonical) {
            required.insert(canonical);
        }
    }
    let expected = required_paths(file_type).ok_or(CallbackError::Package)?;
    if !expected.iter().all(|path| required.contains(*path)) {
        return Err(CallbackError::Package);
    }
    if matches!(file_type, "odt" | "ods" | "odp") {
        let bytes = {
            let mimetype = archive
                .by_name("mimetype")
                .map_err(|_| CallbackError::Package)?;
            if mimetype.compression() != zip::CompressionMethod::Stored || !mimetype_is_first {
                return Err(CallbackError::Package);
            }
            let mut mimetype = mimetype.take(MAX_REQUIRED_METADATA_BYTES + 1);
            let mut bytes = Vec::new();
            mimetype
                .read_to_end(&mut bytes)
                .map_err(|_| CallbackError::Package)?;
            bytes
        };
        if bytes.len() as u64 > MAX_REQUIRED_METADATA_BYTES
            || bytes != expected_media_type.as_bytes()
        {
            return Err(CallbackError::Package);
        }
        let manifest = read_required_metadata(&mut archive, "META-INF/manifest.xml")?;
        if !manifest.starts_with(b"<") {
            return Err(CallbackError::Package);
        }
        validate_odf_content_xml(&mut archive)?;
    } else {
        let content_types = read_required_metadata(&mut archive, "[Content_Types].xml")?;
        if !content_types
            .windows(expected_media_type.len())
            .any(|window| window == expected_media_type.as_bytes())
        {
            return Err(CallbackError::Package);
        }
        let relationships = read_required_metadata(&mut archive, "_rels/.rels")?;
        if !relationships.starts_with(b"<") {
            return Err(CallbackError::Package);
        }
    }
    Ok(())
}

fn odf_content_size_allowed(size: u64) -> bool {
    size <= MAX_ODF_CONTENT_XML_BYTES
}

fn validate_odf_content_xml(
    archive: &mut zip::ZipArchive<std::fs::File>,
) -> Result<(), CallbackError> {
    let entry = archive
        .by_name("content.xml")
        .map_err(|_| CallbackError::Package)?;
    if !odf_content_size_allowed(entry.size()) {
        return Err(CallbackError::Package);
    }
    let bounded = entry.take(MAX_ODF_CONTENT_XML_BYTES + 1);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().check_end_names = true;
    let mut buffer = Vec::new();
    let mut depth = 0_usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut declaration_seen = false;
    let mut declaration_allowed = true;
    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| CallbackError::Package)?;
        match event {
            XmlEvent::Start(element) => {
                declaration_allowed = false;
                if depth == 0 {
                    if root_seen || root_closed {
                        return Err(CallbackError::Package);
                    }
                    root_seen = true;
                }
                let next_depth = depth.checked_add(1).ok_or(CallbackError::Package)?;
                if next_depth > MAX_ODF_XML_NESTING_DEPTH {
                    return Err(CallbackError::Package);
                }
                validate_odf_element(&element, reader.resolver())?;
                depth = next_depth;
            }
            XmlEvent::Empty(element) => {
                declaration_allowed = false;
                if depth == 0 {
                    if root_seen || root_closed {
                        return Err(CallbackError::Package);
                    }
                    root_seen = true;
                    root_closed = true;
                }
                validate_odf_element(&element, reader.resolver())?;
            }
            XmlEvent::End(element) => {
                declaration_allowed = false;
                if depth == 0 {
                    return Err(CallbackError::Package);
                }
                if matches!(
                    reader.resolver().resolve_element(element.name()).0,
                    ResolveResult::Unknown(_)
                ) {
                    return Err(CallbackError::Package);
                }
                depth -= 1;
                if depth == 0 {
                    root_closed = true;
                }
            }
            XmlEvent::DocType(_) => return Err(CallbackError::Package),
            XmlEvent::Decl(_) => {
                if declaration_seen || !declaration_allowed || root_seen {
                    return Err(CallbackError::Package);
                }
                declaration_seen = true;
                declaration_allowed = false;
            }
            XmlEvent::Text(text) => {
                let text: &[u8] = text.as_ref();
                if !text.is_empty() {
                    declaration_allowed = false;
                }
                if depth == 0 && text.iter().any(|byte| !byte.is_ascii_whitespace()) {
                    return Err(CallbackError::Package);
                }
            }
            XmlEvent::CData(_) if depth == 0 => return Err(CallbackError::Package),
            XmlEvent::CData(_) | XmlEvent::Comment(_) | XmlEvent::PI(_) => {
                declaration_allowed = false;
            }
            XmlEvent::GeneralRef(reference) => {
                declaration_allowed = false;
                if depth == 0 || !allowed_xml_reference(reference.as_ref()) {
                    return Err(CallbackError::Package);
                }
            }
            XmlEvent::Eof => {
                if !root_seen || !root_closed || depth != 0 {
                    return Err(CallbackError::Package);
                }
                break;
            }
        }
        buffer.clear();
    }
    let bounded = reader.into_inner().into_inner();
    if bounded.limit() == 0 {
        return Err(CallbackError::Package);
    }
    Ok(())
}

fn validate_odf_element(
    element: &BytesStart<'_>,
    resolver: &quick_xml::name::NamespaceResolver,
) -> Result<(), CallbackError> {
    let namespace = resolver.resolve_element(element.name()).0;
    if matches!(namespace, ResolveResult::Unknown(_)) {
        return Err(CallbackError::Package);
    }
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|_| CallbackError::Package)?;
        if attribute.key.as_namespace_binding().is_none()
            && matches!(
                resolver.resolve_attribute(attribute.key).0,
                ResolveResult::Unknown(_)
            )
        {
            return Err(CallbackError::Package);
        }
    }
    let ResolveResult::Bound(namespace) = namespace else {
        return Ok(());
    };
    let namespace = normalize_xml_reference_bytes(namespace.as_ref())?;
    let local = element.local_name();
    let active = (namespace.as_slice() == ODF_OFFICE_NAMESPACE
        && matches!(local.as_ref(), b"scripts" | b"script" | b"event-listeners"))
        || (namespace.as_slice() == ODF_SCRIPT_NAMESPACE && local.as_ref() == b"event-listener")
        || (namespace.as_slice() == ODF_TEXT_NAMESPACE && local.as_ref() == b"execute-macro")
        || (namespace.as_slice() == ODF_TABLE_NAMESPACE && local.as_ref() == b"error-macro");
    (!active).then_some(()).ok_or(CallbackError::Package)
}

fn normalize_xml_reference_bytes(value: &[u8]) -> Result<Vec<u8>, CallbackError> {
    let mut normalized = Vec::with_capacity(value.len());
    let mut remaining = value;
    while let Some(index) = remaining.iter().position(|byte| *byte == b'&') {
        normalized.extend_from_slice(&remaining[..index]);
        let reference_with_end = &remaining[index + 1..];
        let end = reference_with_end
            .iter()
            .position(|byte| *byte == b';')
            .ok_or(CallbackError::Package)?;
        let reference = &reference_with_end[..end];
        match reference {
            b"amp" => normalized.push(b'&'),
            b"lt" => normalized.push(b'<'),
            b"gt" => normalized.push(b'>'),
            b"apos" => normalized.push(b'\''),
            b"quot" => normalized.push(b'"'),
            _ => {
                let (digits, radix) = reference
                    .strip_prefix(b"#x")
                    .map(|digits| (digits, 16))
                    .or_else(|| reference.strip_prefix(b"#").map(|digits| (digits, 10)))
                    .ok_or(CallbackError::Package)?;
                let digits = std::str::from_utf8(digits).map_err(|_| CallbackError::Package)?;
                let codepoint =
                    u32::from_str_radix(digits, radix).map_err(|_| CallbackError::Package)?;
                let character = char::from_u32(codepoint).ok_or(CallbackError::Package)?;
                let mut encoded = [0_u8; 4];
                normalized.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
        }
        remaining = &remaining[index + end + 2..];
    }
    normalized.extend_from_slice(remaining);
    Ok(normalized)
}

fn allowed_xml_reference(reference: &[u8]) -> bool {
    matches!(reference, b"amp" | b"lt" | b"gt" | b"apos" | b"quot")
        || reference
            .strip_prefix(b"#")
            .is_some_and(|value| !value.is_empty() && value.iter().all(u8::is_ascii_digit))
        || reference
            .strip_prefix(b"#x")
            .is_some_and(|value| !value.is_empty() && value.iter().all(u8::is_ascii_hexdigit))
}

fn read_required_metadata(
    archive: &mut zip::ZipArchive<std::fs::File>,
    path: &str,
) -> Result<Vec<u8>, CallbackError> {
    let mut entry = archive.by_name(path).map_err(|_| CallbackError::Package)?;
    let mut bytes = Vec::new();
    entry
        .by_ref()
        .take(MAX_REQUIRED_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CallbackError::Package)?;
    (bytes.len() as u64 <= MAX_REQUIRED_METADATA_BYTES)
        .then_some(bytes)
        .ok_or(CallbackError::Package)
}

fn canonical_zip_path(value: &str) -> Option<String> {
    if value.is_empty() || value.contains('\\') || value.contains('\0') || value.starts_with('/') {
        return None;
    }
    let path = Path::new(value);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn is_macro_path(path: &str) -> bool {
    path.starts_with("basic/") || path.starts_with("scripts/") || path.contains("vba")
}

fn required_package_path(file_type: &str, path: &str) -> bool {
    required_paths(file_type).is_some_and(|required| required.contains(&path))
}

fn required_metadata_path(file_type: &str, path: &str) -> bool {
    match file_type {
        "docx" | "xlsx" | "pptx" => matches!(path, "[content_types].xml" | "_rels/.rels"),
        "odt" | "ods" | "odp" => matches!(path, "mimetype" | "meta-inf/manifest.xml"),
        _ => false,
    }
}

fn required_paths(file_type: &str) -> Option<&'static [&'static str]> {
    match file_type {
        "docx" => Some(&["[content_types].xml", "_rels/.rels", "word/document.xml"]),
        "xlsx" => Some(&["[content_types].xml", "_rels/.rels", "xl/workbook.xml"]),
        "pptx" => Some(&["[content_types].xml", "_rels/.rels", "ppt/presentation.xml"]),
        "odt" | "ods" | "odp" => Some(&["mimetype", "meta-inf/manifest.xml", "content.xml"]),
        _ => None,
    }
}

fn has_exact_launch_origin(request: &Request, config: &AdapterConfig) -> bool {
    request.origin.as_deref() == Some(config.public_origin.as_str())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DOCUMENT_SERVER_VERSION, MtlsClientConfig, Origin, Provider, ServerTlsConfig,
    };
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use url::Url;

    fn config() -> AdapterConfig {
        AdapterConfig {
            provider: Provider::OnlyOfficeDocumentServer940,
            document_server_version: DOCUMENT_SERVER_VERSION.into(),
            public_origin: Origin::parse("https://files.example.test").unwrap(),
            launch_origin: Origin::parse("https://launch.example.test").unwrap(),
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

    fn output_fixture(entries: &[(&str, &[u8], u16)]) -> CallbackOutput {
        let path = std::env::temp_dir().join(format!(
            "filebelt-onlyoffice-package-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&zip_fixture(entries)).unwrap();
        drop(file);
        CallbackOutput::new(path, "application/vnd.oasis.opendocument.text".into(), 0)
    }

    fn zip_fixture(entries: &[(&str, &[u8], u16)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut central = Vec::new();
        for (name, contents, method) in entries {
            let offset = u32::try_from(bytes.len()).unwrap();
            let name = name.as_bytes();
            let crc = crc32(contents);
            push_u32(&mut bytes, 0x0403_4b50);
            push_u16(&mut bytes, 20);
            push_u16(&mut bytes, 0);
            push_u16(&mut bytes, *method);
            push_u16(&mut bytes, 0);
            push_u16(&mut bytes, 0);
            push_u32(&mut bytes, crc);
            push_u32(&mut bytes, u32::try_from(contents.len()).unwrap());
            push_u32(&mut bytes, u32::try_from(contents.len()).unwrap());
            push_u16(&mut bytes, u16::try_from(name.len()).unwrap());
            push_u16(&mut bytes, 0);
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(contents);

            push_u32(&mut central, 0x0201_4b50);
            push_u16(&mut central, 20);
            push_u16(&mut central, 20);
            push_u16(&mut central, 0);
            push_u16(&mut central, *method);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u32(&mut central, crc);
            push_u32(&mut central, u32::try_from(contents.len()).unwrap());
            push_u32(&mut central, u32::try_from(contents.len()).unwrap());
            push_u16(&mut central, u16::try_from(name.len()).unwrap());
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u32(&mut central, 0);
            push_u32(&mut central, offset);
            central.extend_from_slice(name);
        }
        let central_offset = u32::try_from(bytes.len()).unwrap();
        bytes.extend_from_slice(&central);
        push_u32(&mut bytes, 0x0605_4b50);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, u16::try_from(entries.len()).unwrap());
        push_u16(&mut bytes, u16::try_from(entries.len()).unwrap());
        push_u32(&mut bytes, u32::try_from(central.len()).unwrap());
        push_u32(&mut bytes, central_offset);
        push_u16(&mut bytes, 0);
        bytes
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0_u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & u32::wrapping_neg(crc & 1));
            }
        }
        !crc
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
                file_type: "docx".into(),
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
            file_type: "docx".into(),
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
            file_type: "docx".into(),
            provider_event_id: "event".into(),
            revision: "42".into(),
        };
        let payload = serde_json::json!({
            "key": "session", "status": 2,
            "url": "https://office.example.test/cache/output",
            "filetype": "docx",
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
            file_type: "docx".into(),
            provider_event_id: String::new(),
            revision: String::new(),
        };
        let payload = serde_json::json!({
            "key": "session", "status": 1,
            "filetype": "docx",
            "actions": [{"type": 1, "userid": participant}]
        });
        assert!(signed_callback_matches(&payload, &event));
        let changed_file_type = serde_json::json!({
            "key": "session", "status": 2,
            "url": "https://office.example.test/cache/output",
            "filetype": "odt",
            "userdata": "event", "history": {"serverVersion": 42}
        });
        assert!(!signed_callback_matches(&changed_file_type, &event));
        let replaced = serde_json::json!({
            "key": "session", "status": 1,
            "filetype": "docx",
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
    fn input_path_is_not_a_prefix_or_identifier_leak() {
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
    }

    #[test]
    fn launch_origin_must_be_the_exact_public_origin() {
        let config = config();
        let request = |origin: Option<&str>| Request {
            method: "POST".into(),
            path: "/onlyoffice/launch".into(),
            origin: origin.map(ToOwned::to_owned),
            provider_jwt: None,
            range: None,
            launch_id: Some("one-use-launch".into()),
        };
        assert!(has_exact_launch_origin(
            &request(Some("https://files.example.test")),
            &config
        ));
        assert!(!has_exact_launch_origin(&request(None), &config));
        assert!(!has_exact_launch_origin(
            &request(Some("https://launch.example.test")),
            &config
        ));
    }

    #[test]
    fn admits_only_supported_office_media_types() {
        assert!(allowed_document_media_type(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ));
        assert!(allowed_document_media_type(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; charset=binary"
        ));
        assert!(allowed_document_media_type(
            "application/vnd.oasis.opendocument.text"
        ));
        assert!(allowed_document_media_type(
            "application/vnd.oasis.opendocument.spreadsheet"
        ));
        assert!(allowed_document_media_type(
            "application/vnd.oasis.opendocument.presentation"
        ));
        assert!(!allowed_document_media_type("application/octet-stream"));
        assert!(!allowed_document_media_type("application/pdf"));
    }

    #[test]
    fn validates_preserved_odf_package_and_rejects_malicious_variants() {
        let ordinary_odf_content = br#"<office:document-content
            xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
            xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
            xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
            xmlns:xlink="http://www.w3.org/1999/xlink">
            <office:body><text:p><text:a xlink:href="https://example.test/">external &amp; link</text:a></text:p>
            <draw:object xlink:href="./Object 1"/></office:body>
        </office:document-content>"#;
        let valid = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", ordinary_odf_content, 0),
        ]);
        assert_eq!(validate_output_package(&valid, "odt"), Ok(()));

        let valid_ooxml = output_fixture(&[
            (
                "[Content_Types].xml",
                b"<Types><Override ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>",
                0,
            ),
            ("_rels/.rels", b"<Relationships/>", 0),
            ("word/document.xml", b"<w:document/>", 0),
        ]);
        assert_eq!(validate_output_package(&valid_ooxml, "docx"), Ok(()));

        let duplicate = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", b"<content/>", 0),
            ("CONTENT.XML", b"<other/>", 0),
        ]);
        assert_eq!(
            validate_output_package(&duplicate, "odt"),
            Err(CallbackError::Package)
        );

        let macro_path = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", b"<content/>", 0),
            ("Basic/Standard/script-lb.xml", b"<macro/>", 0),
        ]);
        assert_eq!(
            validate_output_package(&macro_path, "odt"),
            Err(CallbackError::Package)
        );

        let format_mismatch = output_fixture(&[
            (
                "mimetype",
                b"application/vnd.oasis.opendocument.spreadsheet",
                0,
            ),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", b"<content/>", 0),
        ]);
        assert_eq!(
            validate_output_package(&format_mismatch, "odt"),
            Err(CallbackError::Package)
        );
    }

    #[test]
    fn rejects_every_executable_odf_content_construct_by_namespace() {
        let constructs = [
            (ODF_OFFICE_NAMESPACE, "scripts"),
            (ODF_OFFICE_NAMESPACE, "script"),
            (ODF_OFFICE_NAMESPACE, "event-listeners"),
            (ODF_SCRIPT_NAMESPACE, "event-listener"),
            (ODF_TEXT_NAMESPACE, "execute-macro"),
            (ODF_TABLE_NAMESPACE, "error-macro"),
        ];
        for (namespace, local) in constructs {
            let namespace = std::str::from_utf8(namespace).unwrap();
            let content = format!("<root xmlns:alias=\"{namespace}\"><alias:{local}/></root>");
            let output = output_fixture(&[
                ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
                ("META-INF/manifest.xml", b"<manifest/>", 0),
                ("content.xml", content.as_bytes(), 0),
            ]);
            assert_eq!(
                validate_output_package(&output, "odt"),
                Err(CallbackError::Package),
                "active ODF element {{{namespace}}}{local} was admitted"
            );
        }

        let default_namespace = format!(
            "<scripts xmlns=\"{}\"/>",
            std::str::from_utf8(ODF_OFFICE_NAMESPACE).unwrap()
        );
        let output = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", default_namespace.as_bytes(), 0),
        ]);
        assert_eq!(
            validate_output_package(&output, "odt"),
            Err(CallbackError::Package)
        );
    }

    #[test]
    fn odf_content_parser_rejects_dtd_malformed_and_unbound_prefixes() {
        let invalid_documents: [&[u8]; 8] = [
            br#"<!DOCTYPE root [<!ENTITY payload "replacement">]><root>&payload;</root>"#,
            br#"<root><child></root>"#,
            br#"<root><unbound:child/></root>"#,
            br#"<root unbound:attribute="value"/>"#,
            br#"<root/><second/>"#,
            br#"<root/>trailing"#,
            br#""#,
            br#" <?xml version="1.0"?><root/>"#,
        ];
        for content in invalid_documents {
            let output = output_fixture(&[
                ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
                ("META-INF/manifest.xml", b"<manifest/>", 0),
                ("content.xml", content, 0),
            ]);
            assert_eq!(
                validate_output_package(&output, "odt"),
                Err(CallbackError::Package)
            );
        }

        let encoded_namespace = format!(
            "<alias:scripts xmlns:alias=\"{}&#x3a;1.0\"/>",
            "urn:oasis:names:tc:opendocument:xmlns:office"
        );
        let output = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", encoded_namespace.as_bytes(), 0),
        ]);
        assert_eq!(
            validate_output_package(&output, "odt"),
            Err(CallbackError::Package)
        );
    }

    #[test]
    fn odf_active_content_matching_is_exact_and_content_has_a_hard_ceiling() {
        let harmless = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            (
                "content.xml",
                br#"<safe:scripts xmlns:safe="urn:filebelt:test"><safe:event-listener/></safe:scripts>"#,
                0,
            ),
        ]);
        assert_eq!(validate_output_package(&harmless, "odt"), Ok(()));
        assert!(odf_content_size_allowed(MAX_ODF_CONTENT_XML_BYTES));
        assert!(!odf_content_size_allowed(MAX_ODF_CONTENT_XML_BYTES + 1));
    }

    #[test]
    fn odf_nesting_accepts_the_exact_ceiling_and_rejects_one_more_level() {
        let at_ceiling = nested_odf_xml(MAX_ODF_XML_NESTING_DEPTH);
        let output = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", at_ceiling.as_bytes(), 0),
        ]);
        assert_eq!(validate_output_package(&output, "odt"), Ok(()));

        let excessive = nested_odf_xml(MAX_ODF_XML_NESTING_DEPTH + 1);
        let output = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", excessive.as_bytes(), 0),
        ]);
        assert_eq!(
            validate_output_package(&output, "odt"),
            Err(CallbackError::Package)
        );
    }

    #[test]
    fn odf_nesting_rejects_namespace_shadowing_before_resolver_wrap() {
        let mut content = format!(
            "<root xmlns:p=\"{}\">",
            std::str::from_utf8(ODF_OFFICE_NAMESPACE).unwrap()
        );
        for _ in 1..MAX_ODF_XML_NESTING_DEPTH {
            content.push_str("<n>");
        }
        content.push_str("<shadow xmlns:p=\"urn:filebelt:safe\"></shadow>");
        for _ in 1..MAX_ODF_XML_NESTING_DEPTH {
            content.push_str("</n>");
        }
        content.push_str("<p:scripts/></root>");
        let output = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", content.as_bytes(), 0),
        ]);
        assert_eq!(
            validate_output_package(&output, "odt"),
            Err(CallbackError::Package)
        );
    }

    fn nested_odf_xml(depth: usize) -> String {
        let mut content = String::new();
        for _ in 0..depth {
            content.push_str("<n>");
        }
        for _ in 0..depth {
            content.push_str("</n>");
        }
        content
    }

    #[test]
    fn rejects_unsafe_compression_and_oversized_required_metadata() {
        let unsafe_path = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("../content.xml", b"<content/>", 0),
        ]);
        assert_eq!(
            validate_output_package(&unsafe_path, "odt"),
            Err(CallbackError::Package)
        );

        let unsupported_compression = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", b"<manifest/>", 0),
            ("content.xml", b"<content/>", 99),
        ]);
        assert_eq!(
            validate_output_package(&unsupported_compression, "odt"),
            Err(CallbackError::Package)
        );

        let oversized = vec![b'x'; usize::try_from(MAX_REQUIRED_METADATA_BYTES + 1).unwrap()];
        let oversized_metadata = output_fixture(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", 0),
            ("META-INF/manifest.xml", oversized.as_slice(), 0),
            ("content.xml", b"<content/>", 0),
        ]);
        assert_eq!(
            validate_output_package(&oversized_metadata, "odt"),
            Err(CallbackError::Package)
        );
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
                file_type: "docx".into(),
                provider_event_id: "provider-event".into(),
                revision: "revision".into(),
            }
        }
    }
}

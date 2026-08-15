// SPDX-License-Identifier: AGPL-3.0-only

//! Concrete, narrowly scoped transports used by the standalone adapter.
//!
//! These implementations deliberately know only the documented document
//! protobuf envelope and the egress-gateway fetch contract. This AGPL crate
//! directly links the Apache document-protocol crate and generated types at
//! compile time. At runtime the adapter and Apache Core remain separate mTLS
//! processes; Apache code does not link adapter types. The adapter opens no
//! database connection and makes no direct connection to DocumentServer.

use crate::config::{AdapterConfig, JwtKeySet, MAX_OUTPUT_BYTES, MtlsClientConfig};
use crate::routes::{
    ByteRange, CallbackEvent, CallbackOutput, CoreClient, CoreError, EgressError, EgressGateway,
    EventFingerprint, EventFingerprintDeriver, FetchedInput, FingerprintError, Idempotency,
    JwtError, LaunchGrant, ProviderClaims, ProviderJwtVerifier, ReadCapability,
    callback_requires_output,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use filebelt_document_protocol::{
    BeginDocumentRevisionCommand, CommitDocumentRevisionCommand, DocumentCallbackKind,
    DocumentCallbackReceipt, DocumentCallbackState, DocumentCommitState, DocumentExecuteRequest,
    DocumentExecuteResponse, DocumentParticipantActivity, DocumentRevisionKind,
    ReceiveDocumentCallbackCommand, RedeemDocumentLaunchCommand, RefreshDocumentSourceCommand,
    document_execute_request, document_execute_response,
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use prost::Message as _;
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq as _;
use url::Url;

const EXECUTE_CONTENT_TYPE: &str = "application/x-protobuf";
// Core is the durable fingerprint-to-revision authority. This cache only
// bridges one adapter request to its scoped I/O write, so eviction is safe:
// retrying the callback makes Core replay the same revision ID.
const MAX_CALLBACK_CONTEXTS: usize = 1_024;
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

type HmacSha256 = Hmac<Sha256>;

pub struct Hs256JwtVerifier;

impl ProviderJwtVerifier for Hs256JwtVerifier {
    fn verify(
        &self,
        compact_jwt: &str,
        config: &AdapterConfig,
        keys: &JwtKeySet,
        now: SystemTime,
    ) -> Result<ProviderClaims, JwtError> {
        let mut parts = compact_jwt.split('.');
        let (Some(encoded_header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwtError::Invalid);
        };
        let header: Value = decode_json(encoded_header)?;
        if header.get("alg").and_then(Value::as_str) != Some("HS256")
            || header.get("typ").and_then(Value::as_str) != Some("JWT")
            || header.get("kid").is_some()
        {
            return Err(JwtError::Invalid);
        }
        let signing_input = format!("{encoded_header}.{payload}");
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| JwtError::Invalid)?;
        if signature.len() != 32
            || !verify_hs256(&keys.current, signing_input.as_bytes(), &signature)
                && !keys
                    .retiring
                    .as_ref()
                    .is_some_and(|key| verify_hs256(key, signing_input.as_bytes(), &signature))
        {
            return Err(JwtError::Invalid);
        }
        let claims: Value = decode_json(payload)?;
        if !claims.is_object() {
            return Err(JwtError::Invalid);
        }
        let _ = (config, now);
        Ok(ProviderClaims { payload: claims })
    }
}

/// Sign the exact documented DocEditor initialization configuration. The
/// browser token is deliberately separate from the inbound outbox verifier.
pub fn sign_browser_config_token(browser_key: &[u8], config: &Value) -> Result<String, JwtError> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(config).map_err(|_| JwtError::Invalid)?);
    let signing_input = format!("{header}.{payload}");
    let mut mac = HmacSha256::new_from_slice(browser_key).map_err(|_| JwtError::Invalid)?;
    mac.update(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

pub struct Sha256FingerprintDeriver;

impl EventFingerprintDeriver for Sha256FingerprintDeriver {
    fn derive(&self, event: &CallbackEvent) -> Result<EventFingerprint, FingerprintError> {
        // Length-delimited fields make this representation unambiguous without
        // relying on provider JSON key ordering or presentation whitespace.
        let mut hasher = Sha256::new();
        hasher.update(b"filebelt.onlyoffice.callback.v1\0");
        add_field(&mut hasher, &event.document_id);
        hasher.update([event.status as u8]);
        hasher.update([event.force_save_type.map_or(255, |value| value as u8)]);
        hasher.update([match event.activity {
            crate::routes::ParticipantActivity::Unspecified => 0,
            crate::routes::ParticipantActivity::Connected => 1,
            crate::routes::ParticipantActivity::Disconnected => 2,
        }]);
        add_field(&mut hasher, &event.activity_user_id);
        add_field(&mut hasher, event.output_url.as_deref().unwrap_or_default());
        add_field(&mut hasher, &event.provider_event_id);
        add_field(&mut hasher, &event.revision);
        Ok(EventFingerprint(hasher.finalize().into()))
    }
}

pub struct HttpCoreClient {
    config: AdapterConfig,
    core: Client,
    io: Client,
    callbacks: Mutex<CallbackContexts>,
}

#[derive(Clone)]
struct CallbackContext {
    revision_id: String,
}

#[derive(Default)]
struct CallbackContexts {
    by_fingerprint: BTreeMap<[u8; 32], CallbackContext>,
    insertion_order: VecDeque<[u8; 32]>,
}

impl CallbackContexts {
    fn remember(&mut self, fingerprint: [u8; 32], context: CallbackContext) {
        if self.by_fingerprint.contains_key(&fingerprint) {
            self.insertion_order
                .retain(|candidate| candidate != &fingerprint);
        }
        self.by_fingerprint.insert(fingerprint, context);
        self.insertion_order.push_back(fingerprint);
        while self.by_fingerprint.len() > MAX_CALLBACK_CONTEXTS {
            let Some(evicted) = self.insertion_order.pop_front() else {
                break;
            };
            self.by_fingerprint.remove(&evicted);
        }
    }

    fn remove(&mut self, fingerprint: &[u8; 32]) {
        self.by_fingerprint.remove(fingerprint);
        self.insertion_order
            .retain(|candidate| candidate != fingerprint);
    }
}

impl HttpCoreClient {
    pub fn new(config: AdapterConfig) -> Result<Self, CoreError> {
        Ok(Self {
            core: mtls_client(&config.core).map_err(|_| CoreError::Unavailable)?,
            io: mtls_client(&config.io).map_err(|_| CoreError::Unavailable)?,
            config,
            callbacks: Mutex::new(CallbackContexts::default()),
        })
    }

    fn execute(
        &self,
        command: document_execute_request::Command,
    ) -> Result<document_execute_response::Result, CoreError> {
        let request_id = request_id();
        let request = DocumentExecuteRequest {
            request_id: request_id.clone(),
            command: Some(command),
        };
        let endpoint = self
            .config
            .core
            .url
            .join("internal/v1/document/execute")
            .map_err(|_| CoreError::Unavailable)?;
        let response = self
            .core
            .post(endpoint)
            .header(reqwest::header::CONTENT_TYPE, EXECUTE_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, EXECUTE_CONTENT_TYPE)
            .body(request.encode_to_vec())
            .send()
            .map_err(|_| CoreError::Unavailable)?;
        let status = response.status();
        let body = response.bytes().map_err(|_| CoreError::Unavailable)?;
        if body.len() > 1_048_576 {
            return Err(CoreError::Unavailable);
        }
        let response =
            DocumentExecuteResponse::decode(body.as_ref()).map_err(|_| CoreError::Invalid)?;
        if !bool::from(response.request_id.as_bytes().ct_eq(request_id.as_bytes())) {
            return Err(CoreError::Invalid);
        }
        let result = response.result.ok_or(CoreError::Invalid)?;
        if status.is_success() {
            return Ok(result);
        }
        match status {
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Err(CoreError::Denied),
            StatusCode::NOT_FOUND | StatusCode::GONE => Err(CoreError::Gone),
            StatusCode::BAD_REQUEST => Err(CoreError::Invalid),
            _ => Err(CoreError::Unavailable),
        }
    }
}

impl CoreClient for HttpCoreClient {
    fn redeem_one_use_launch(&self, launch_id: &str) -> Result<LaunchGrant, CoreError> {
        let launch_token = URL_SAFE_NO_PAD
            .decode(launch_id)
            .map_err(|_| CoreError::Invalid)?;
        let result = self.execute(document_execute_request::Command::RedeemLaunch(
            RedeemDocumentLaunchCommand {
                tenant_id: self.config.tenant_id.clone(),
                launch_token,
            },
        ))?;
        let document_execute_response::Result::Launch(launch) = result else {
            return Err(CoreError::Invalid);
        };
        let detail = launch.detail.ok_or(CoreError::Invalid)?;
        let session = detail.session.ok_or(CoreError::Invalid)?;
        let participant = detail.participants.first().ok_or(CoreError::Invalid)?;
        let browser_key = self
            .config
            .load_browser_key(SystemTime::now())
            .map_err(|_| CoreError::Unavailable)?;
        if !allowed_media_type(&launch.media_type)
            || launch.display_name.is_empty()
            || launch.display_name.chars().count() > 128
            || !has_exact_source_extension(&launch.display_name, &launch.media_type)
        {
            return Err(CoreError::Invalid);
        }
        let mode = document_mode(session.mode)?;
        let input_url = self.config.public_origin.as_str().to_owned()
            + "/onlyoffice/input/"
            + &session.session_id
            + "/"
            + &participant.participant_id;
        let callback_url = self.config.public_origin.as_str().to_owned()
            + "/onlyoffice/callback/"
            + &session.session_id
            + "/"
            + &participant.participant_id;
        let mut editor_config = json!({
            "documentType": document_type(&launch.media_type).ok_or(CoreError::Invalid)?,
            "document": {
                "key": session.session_id,
                "title": launch.display_name,
                "fileType": file_extension(&launch.media_type).ok_or(CoreError::Invalid)?,
                "url": input_url,
                "permissions": mode.permissions(),
            },
            "editorConfig": {
                "callbackUrl": callback_url,
                "assemblyFormatAsOrigin": true,
                "mode": mode.name(),
                // Bind ONLYOFFICE status-1 `actions[].userid` to the same
                // opaque participant UUID carried in the callback route.
                "user": { "id": participant.participant_id },
            },
        });
        let token = sign_browser_config_token(&browser_key, &editor_config)
            .map_err(|_| CoreError::Unavailable)?;
        editor_config
            .as_object_mut()
            .ok_or(CoreError::Invalid)?
            .insert("token".into(), Value::String(token));
        let editor_config_json = serde_json::to_string(&json!({
            "apiJsUrl": self.config.document_server_api_js,
            "editorConfig": editor_config,
        }))
        .map_err(|_| CoreError::Unavailable)?;
        Ok(LaunchGrant {
            document_id: session.session_id,
            editor_config_json,
            active_tabs: detail.participants.len(),
            source_read_capability: launch.source_read_capability,
        })
    }

    fn issue_fresh_read_capability(
        &self,
        document_id: &str,
        participant_id: &str,
    ) -> Result<ReadCapability, CoreError> {
        let result = self.execute(document_execute_request::Command::RefreshSource(
            RefreshDocumentSourceCommand {
                tenant_id: self.config.tenant_id.clone(),
                document_session_id: document_id.to_owned(),
                participant_id: participant_id.to_owned(),
            },
        ))?;
        let document_execute_response::Result::Launch(launch) = result else {
            return Err(CoreError::Invalid);
        };
        if launch.detail.is_some()
            || launch.base_version_id.is_empty()
            || launch.source_read_capability.is_empty()
            || launch.size_bytes == 0
            || launch.size_bytes > MAX_OUTPUT_BYTES
        {
            return Err(CoreError::Invalid);
        }
        Ok(ReadCapability {
            authorization: launch.source_read_capability,
            url_path: format!(
                "io/v1/documents/{document_id}/versions/{}",
                launch.base_version_id
            ),
            size_bytes: launch.size_bytes,
        })
    }

    fn fetch_input_with_capability(
        &self,
        capability: &ReadCapability,
        range: ByteRange,
    ) -> Result<FetchedInput, CoreError> {
        let endpoint = self
            .config
            .io
            .url
            .join(&capability.url_path)
            .map_err(|_| CoreError::Unavailable)?;
        let response = self
            .io
            .get(endpoint)
            .header(reqwest::header::AUTHORIZATION, &capability.authorization)
            .header(reqwest::header::RANGE, ReadCapability::range_header(range))
            .send()
            .map_err(|_| CoreError::Unavailable)?;
        if response.status() == StatusCode::NOT_FOUND || response.status() == StatusCode::FORBIDDEN
        {
            return Err(CoreError::Gone);
        }
        if response.status() != StatusCode::PARTIAL_CONTENT {
            return Err(CoreError::Unavailable);
        }
        let expected_length = range
            .end_inclusive
            .checked_sub(range.start)
            .and_then(|length| length.checked_add(1))
            .ok_or(CoreError::Invalid)?;
        if expected_length > MAX_OUTPUT_BYTES
            || range.end_inclusive >= capability.size_bytes
            || response.content_length() != Some(expected_length)
            || response
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                != Some(
                    format!(
                        "bytes {}-{}/{}",
                        range.start, range.end_inclusive, capability.size_bytes
                    )
                    .as_str(),
                )
        {
            return Err(CoreError::Invalid);
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let bytes = response.bytes().map_err(|_| CoreError::Unavailable)?;
        if bytes.len() as u64 != expected_length {
            return Err(CoreError::Invalid);
        }
        Ok(FetchedInput {
            bytes: bytes.to_vec(),
            content_type,
        })
    }

    fn record_callback(
        &self,
        event: &CallbackEvent,
        fingerprint: &EventFingerprint,
        participant_id: &str,
    ) -> Result<Idempotency, CoreError> {
        let result = self.execute(document_execute_request::Command::ReceiveCallback(
            ReceiveDocumentCallbackCommand {
                tenant_id: self.config.tenant_id.clone(),
                document_session_id: event.document_id.clone(),
                participant_id: participant_id.to_owned(),
                provider_event_digest: fingerprint.0.to_vec(),
                callback_kind: callback_kind(event) as i32,
                revision_kind: callback_revision_kind(event) as i32,
                activity: callback_activity(event) as i32,
                output_file_type: event.file_type.clone(),
            },
        ))?;
        let document_execute_response::Result::CallbackReceipt(receipt) = result else {
            return Err(CoreError::Invalid);
        };
        match receipt_for_event(&receipt, callback_requires_output(event))? {
            Idempotency::Duplicate => return Ok(Idempotency::Duplicate),
            Idempotency::New | Idempotency::Pending => {}
        }
        if !callback_requires_output(event) {
            return Ok(Idempotency::New);
        }
        if receipt.revision_id.is_empty() {
            return Err(CoreError::Invalid);
        }
        self.callbacks
            .lock()
            .map_err(|_| CoreError::Unavailable)?
            .remember(
                fingerprint.0,
                CallbackContext {
                    revision_id: receipt.revision_id,
                },
            );
        Ok(Idempotency::New)
    }

    fn commit_callback_output(
        &self,
        event: &CallbackEvent,
        fingerprint: &EventFingerprint,
        output: &CallbackOutput,
    ) -> Result<Idempotency, CoreError> {
        let callback = self
            .callbacks
            .lock()
            .map_err(|_| CoreError::Unavailable)?
            .by_fingerprint
            .get(&fingerprint.0)
            .cloned()
            .ok_or(CoreError::Gone)?;
        let result = self.execute(document_execute_request::Command::BeginRevision(
            BeginDocumentRevisionCommand {
                tenant_id: self.config.tenant_id.clone(),
                revision_id: callback.revision_id.clone(),
                reserved_bytes: output.size(),
            },
        ))?;
        let document_execute_response::Result::RevisionAdmission(admission) = result else {
            return Err(CoreError::Invalid);
        };
        if admission.revision_id != callback.revision_id
            || admission.staged_write_capability.is_empty()
            || admission.finalize_capability.is_empty()
        {
            return Err(CoreError::Invalid);
        }
        let write_url = self
            .config
            .io
            .url
            .join(&format!(
                "io/v1/document-revisions/{}",
                admission.revision_id
            ))
            .map_err(|_| CoreError::Unavailable)?;
        let response = self
            .io
            .put(write_url)
            .header(
                reqwest::header::AUTHORIZATION,
                admission.staged_write_capability,
            )
            .header(reqwest::header::CONTENT_TYPE, output.content_type())
            .header(reqwest::header::CONTENT_LENGTH, output.size())
            .body(reqwest::blocking::Body::new(
                File::open(&output.path).map_err(|_| CoreError::Unavailable)?,
            ))
            .send()
            .map_err(|_| CoreError::Unavailable)?;
        if !response.status().is_success() {
            return Err(status_core_error(response.status()));
        }
        let finalize_url = self
            .config
            .io
            .url
            .join(&format!(
                "io/v1/document-revisions/{}/finalize",
                admission.revision_id
            ))
            .map_err(|_| CoreError::Unavailable)?;
        let response = self
            .io
            .post(finalize_url)
            .header(
                reqwest::header::AUTHORIZATION,
                admission.finalize_capability,
            )
            .send()
            .map_err(|_| CoreError::Unavailable)?;
        if !response.status().is_success() {
            return Err(status_core_error(response.status()));
        }
        // A timer force-save is a durable checkpoint, not a document-head
        // commit. Core marks it terminal as part of finalize, so invoking the
        // ordinary CommitRevision path would incorrectly advance the head.
        if !requires_ordinary_commit(event) {
            remove_callback_context(&self.callbacks, fingerprint)?;
            return Ok(Idempotency::New);
        }
        let result = self.execute(document_execute_request::Command::CommitRevision(
            CommitDocumentRevisionCommand {
                tenant_id: self.config.tenant_id.clone(),
                revision_id: callback.revision_id,
            },
        ))?;
        let document_execute_response::Result::Commit(outcome) = result else {
            return Err(CoreError::Invalid);
        };
        let idempotency = match DocumentCommitState::try_from(outcome.state).ok() {
            Some(DocumentCommitState::Committed | DocumentCommitState::NoOp) => Idempotency::New,
            Some(DocumentCommitState::Conflict) => Idempotency::Duplicate,
            _ => return Err(CoreError::Invalid),
        };
        // Terminal outcomes are durable in Core. Keep this in-process map only
        // while an I/O or Core error remains retryable.
        remove_callback_context(&self.callbacks, fingerprint)?;
        Ok(idempotency)
    }
}

pub struct HttpEgressGateway {
    endpoint: Url,
    client: Client,
}

impl HttpEgressGateway {
    pub fn new(config: &MtlsClientConfig) -> Result<Self, EgressError> {
        Ok(Self {
            endpoint: config
                .url
                .join("v1/fetch")
                .map_err(|_| EgressError::Failed)?,
            client: mtls_client(config).map_err(|_| EgressError::Failed)?,
        })
    }
}

impl EgressGateway for HttpEgressGateway {
    fn fetch_no_redirect(
        &self,
        url: &str,
        maximum_bytes: u64,
    ) -> Result<CallbackOutput, EgressError> {
        if maximum_bytes > MAX_OUTPUT_BYTES {
            return Err(EgressError::Denied);
        }
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(json!({"url": url, "maximum_bytes": maximum_bytes}).to_string())
            .send()
            .map_err(|_| EgressError::Failed)?;
        if response.status() == StatusCode::FORBIDDEN {
            return Err(EgressError::Denied);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > maximum_bytes)
        {
            return Err(EgressError::Failed);
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let (mut file, path) = create_spool_file()?;
        let mut size = 0_u64;
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            let read = match response.read(&mut chunk) {
                Ok(read) => read,
                Err(_) => {
                    let _ = fs::remove_file(&path);
                    return Err(EgressError::Failed);
                }
            };
            if read == 0 {
                break;
            }
            size = size
                .checked_add(u64::try_from(read).map_err(|_| EgressError::Failed)?)
                .ok_or(EgressError::TooLarge)?;
            if size > maximum_bytes {
                let _ = fs::remove_file(&path);
                return Err(EgressError::TooLarge);
            }
            if file.write_all(&chunk[..read]).is_err() {
                let _ = fs::remove_file(&path);
                return Err(EgressError::Failed);
            }
        }
        if file.flush().is_err() {
            let _ = fs::remove_file(&path);
            return Err(EgressError::Failed);
        }
        drop(file);
        Ok(CallbackOutput::new(path, content_type, size))
    }
}

fn remove_callback_context(
    callbacks: &Mutex<CallbackContexts>,
    fingerprint: &EventFingerprint,
) -> Result<(), CoreError> {
    callbacks
        .lock()
        .map_err(|_| CoreError::Unavailable)?
        .remove(&fingerprint.0);
    Ok(())
}

fn create_spool_file() -> Result<(File, PathBuf), EgressError> {
    for _ in 0..8 {
        let sequence = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "filebelt-onlyoffice-output-{}-{sequence:016x}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(EgressError::Failed),
        }
    }
    Err(EgressError::Failed)
}

fn mtls_client(config: &MtlsClientConfig) -> Result<Client, ()> {
    let mut identity_pem = fs::read(&config.certificate_chain_file).map_err(|_| ())?;
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&fs::read(&config.private_key_file).map_err(|_| ())?);
    let identity = Identity::from_pem(&identity_pem).map_err(|_| ())?;
    let ca = fs::read(&config.server_ca_file).map_err(|_| ())?;
    let certificates = Certificate::from_pem_bundle(&ca).map_err(|_| ())?;
    let mut builder = Client::builder()
        .https_only(true)
        .tls_built_in_root_certs(false)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .identity(identity);
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().map_err(|_| ())
}

fn decode_json(value: &str) -> Result<Value, JwtError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| JwtError::Invalid)?;
    serde_json::from_slice(&bytes).map_err(|_| JwtError::Invalid)
}

fn verify_hs256(key: &[u8], signing_input: &[u8], signature: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(signing_input);
    bool::from(mac.finalize().into_bytes().as_slice().ct_eq(signature))
}

fn allowed_media_type(value: &str) -> bool {
    file_extension(value).is_some()
}

fn file_extension(media_type: &str) -> Option<&'static str> {
    match media_type {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some("docx"),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some("xlsx"),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => Some("pptx"),
        "application/vnd.oasis.opendocument.text" => Some("odt"),
        "application/vnd.oasis.opendocument.spreadsheet" => Some("ods"),
        "application/vnd.oasis.opendocument.presentation" => Some("odp"),
        _ => None,
    }
}

fn document_type(media_type: &str) -> Option<&'static str> {
    match media_type {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some("word"),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some("cell"),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            Some("slide")
        }
        "application/vnd.oasis.opendocument.text" => Some("word"),
        "application/vnd.oasis.opendocument.spreadsheet" => Some("cell"),
        "application/vnd.oasis.opendocument.presentation" => Some("slide"),
        _ => None,
    }
}

fn has_exact_source_extension(display_name: &str, media_type: &str) -> bool {
    file_extension(media_type)
        .is_some_and(|extension| display_name.ends_with(&format!(".{extension}")))
}

#[derive(Clone, Copy)]
enum DocumentMode {
    View,
    Comment,
    Review,
    Edit,
}

impl DocumentMode {
    fn name(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Comment => "edit",
            Self::Review => "edit",
            Self::Edit => "edit",
        }
    }

    fn permissions(self) -> Value {
        let (edit, comment, review) = match self {
            Self::View => (false, false, false),
            Self::Comment => (false, true, false),
            Self::Review => (false, false, true),
            Self::Edit => (true, false, false),
        };
        json!({
            "edit": edit,
            "comment": comment,
            "review": review,
            "copy": false,
            "download": false,
            "print": false,
        })
    }
}

fn document_mode(value: i32) -> Result<DocumentMode, CoreError> {
    match value {
        1 => Ok(DocumentMode::View),
        2 => Ok(DocumentMode::Comment),
        3 => Ok(DocumentMode::Review),
        4 => Ok(DocumentMode::Edit),
        _ => Err(CoreError::Invalid),
    }
}

fn callback_kind(event: &CallbackEvent) -> DocumentCallbackKind {
    match event.status {
        crate::routes::CallbackStatus::Editing => DocumentCallbackKind::Editing,
        crate::routes::CallbackStatus::MustSave | crate::routes::CallbackStatus::ForceSave => {
            DocumentCallbackKind::OutputRequired
        }
        crate::routes::CallbackStatus::SaveError => DocumentCallbackKind::Corrupted,
        crate::routes::CallbackStatus::ForceSaveError => DocumentCallbackKind::ForceSaveError,
        crate::routes::CallbackStatus::ClosedNoChanges => DocumentCallbackKind::ClosedNoChanges,
    }
}

fn callback_revision_kind(event: &CallbackEvent) -> DocumentRevisionKind {
    if !callback_requires_output(event) {
        return DocumentRevisionKind::Unspecified;
    }
    match (event.status, event.force_save_type) {
        (crate::routes::CallbackStatus::ForceSave, Some(crate::routes::ForceSaveType::Timer)) => {
            DocumentRevisionKind::Checkpoint
        }
        (crate::routes::CallbackStatus::ForceSave, _) => DocumentRevisionKind::UserSave,
        _ => DocumentRevisionKind::FinalSave,
    }
}

fn callback_is_checkpoint(event: &CallbackEvent) -> bool {
    callback_revision_kind(event) == DocumentRevisionKind::Checkpoint
}

fn requires_ordinary_commit(event: &CallbackEvent) -> bool {
    !callback_is_checkpoint(event)
}

fn callback_activity(event: &CallbackEvent) -> DocumentParticipantActivity {
    match event.activity {
        crate::routes::ParticipantActivity::Unspecified => DocumentParticipantActivity::Unspecified,
        crate::routes::ParticipantActivity::Connected => DocumentParticipantActivity::Connected,
        crate::routes::ParticipantActivity::Disconnected => {
            DocumentParticipantActivity::Disconnected
        }
    }
}

fn status_core_error(status: StatusCode) -> CoreError {
    match status {
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => CoreError::Denied,
        StatusCode::NOT_FOUND | StatusCode::GONE => CoreError::Gone,
        StatusCode::BAD_REQUEST | StatusCode::CONFLICT | StatusCode::PAYLOAD_TOO_LARGE => {
            CoreError::Invalid
        }
        _ => CoreError::Unavailable,
    }
}

/// Core owns callback durability. Terminal receipt states are an acknowledgement
/// only: repeating egress fetches for one would create an unnecessary retry
/// loop. Received and staged states retain their revision allocation and can
/// safely resume the begin/write/finalize/commit path.
fn receipt_idempotency(state: i32) -> Result<Idempotency, CoreError> {
    match DocumentCallbackState::try_from(state).ok() {
        Some(
            DocumentCallbackState::Received
            | DocumentCallbackState::Staging
            | DocumentCallbackState::Staged,
        ) => Ok(Idempotency::New),
        Some(
            DocumentCallbackState::Committed
            | DocumentCallbackState::Checkpoint
            | DocumentCallbackState::NoOp
            | DocumentCallbackState::Conflict,
        ) => Ok(Idempotency::Duplicate),
        Some(DocumentCallbackState::Rejected) => Err(CoreError::Invalid),
        Some(DocumentCallbackState::Failed | DocumentCallbackState::Unspecified) | None => {
            Err(CoreError::Unavailable)
        }
    }
}

fn receipt_for_event(
    receipt: &DocumentCallbackReceipt,
    output_required: bool,
) -> Result<Idempotency, CoreError> {
    if receipt.event_id.is_empty() {
        return Err(CoreError::Invalid);
    }
    let idempotency = receipt_idempotency(receipt.state)?;
    if matches!(idempotency, Idempotency::New | Idempotency::Pending)
        && output_required
        && receipt.revision_id.is_empty()
    {
        return Err(CoreError::Invalid);
    }
    Ok(idempotency)
}

fn add_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn request_id() -> String {
    let count = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("adapter-{seconds:x}-{count:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DOCUMENT_SERVER_VERSION, Origin, Provider, ServerTlsConfig};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    fn config() -> AdapterConfig {
        let endpoint = |url| MtlsClientConfig {
            url: Url::parse(url).unwrap(),
            certificate_chain_file: PathBuf::from("certificate"),
            private_key_file: PathBuf::from("key"),
            server_ca_file: PathBuf::from("ca"),
        };
        AdapterConfig {
            provider: Provider::OnlyOfficeDocumentServer940,
            document_server_version: DOCUMENT_SERVER_VERSION.into(),
            public_origin: Origin::parse("https://files.example.test").unwrap(),
            launch_origin: Origin::parse("https://launch.example.test").unwrap(),
            document_server_origin: Origin::parse("https://office.example.test").unwrap(),
            document_server_api_js:
                "https://office.example.test/web-apps/apps/api/documents/api.js".into(),
            browser_jwt_file: "browser".into(),
            outbox_jwt_current_file: "outbox-current".into(),
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

    #[test]
    fn hs256_rejects_algorithm_confusion_and_accepts_retiring_key() {
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let cfg = config();
        let current = JwtKeySet {
            current: b"a-valid-current-secret-that-is-long-enough".to_vec(),
            retiring: None,
        };
        let token = sign_browser_config_token(
            &current.current,
            &json!({"payload": {"url": "https://files.example.test/onlyoffice/input/session/participant"}}),
        )
        .unwrap();
        let parts = token.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert!(verify_hs256(
            &current.current,
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &signature
        ));
        assert_eq!(decode_json(parts[0]).unwrap()["alg"], "HS256");
        let claims = Hs256JwtVerifier
            .verify(&token, &cfg, &current, now)
            .unwrap();
        assert_eq!(
            claims.payload["payload"]["url"],
            "https://files.example.test/onlyoffice/input/session/participant"
        );
        let (_, payload_and_signature) = token.split_once('.').unwrap();
        let bad_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let confused = format!("{bad_header}.{payload_and_signature}");
        assert_eq!(
            Hs256JwtVerifier.verify(&confused, &cfg, &current, now),
            Err(JwtError::Invalid)
        );
        let retiring = JwtKeySet {
            current: b"different-current-secret-that-is-long-enough".to_vec(),
            retiring: Some(current.current),
        };
        assert!(
            Hs256JwtVerifier
                .verify(&token, &cfg, &retiring, now)
                .is_ok()
        );
    }

    #[test]
    fn browser_token_signs_exact_doceditor_configuration_and_mode_mapping() {
        let key = b"browser-signing-secret-that-is-long-enough";
        let configuration = json!({
            "documentType": "word",
            "document": {"key": "session", "title": "Report.docx"},
            "editorConfig": {"mode": "edit"},
        });
        let token = sign_browser_config_token(key, &configuration).unwrap();
        let payload = token.split('.').nth(1).unwrap();
        assert_eq!(decode_json(payload).unwrap(), configuration);
        assert_eq!(
            document_type(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            Some("word")
        );
        assert_eq!(
            document_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            Some("cell")
        );
        assert_eq!(
            document_type(
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            ),
            Some("slide")
        );
        assert_eq!(
            file_extension("application/vnd.oasis.opendocument.text"),
            Some("odt")
        );
        assert_eq!(
            document_type("application/vnd.oasis.opendocument.spreadsheet"),
            Some("cell")
        );
        assert!(has_exact_source_extension(
            "report.odp",
            "application/vnd.oasis.opendocument.presentation"
        ));
        assert!(!has_exact_source_extension(
            "report.ODP",
            "application/vnd.oasis.opendocument.presentation"
        ));
        assert_eq!(document_mode(1).unwrap().permissions()["edit"], false);
        assert_eq!(document_mode(2).unwrap().permissions()["comment"], true);
        assert_eq!(document_mode(3).unwrap().permissions()["review"], true);
        assert_eq!(document_mode(4).unwrap().permissions()["edit"], true);
    }

    #[test]
    fn callback_v1_fingerprint_matches_the_legacy_known_answer() {
        let event = CallbackEvent::test_event();
        let first = Sha256FingerprintDeriver.derive(&event).unwrap();
        assert_eq!(
            first.0,
            [
                178, 43, 89, 29, 77, 172, 189, 152, 101, 112, 154, 161, 42, 73, 138, 67, 88, 100,
                54, 85, 6, 154, 1, 100, 160, 198, 129, 47, 98, 185, 60, 4,
            ]
        );
    }

    #[test]
    fn callback_v1_fingerprint_is_stable_across_file_type_rollout_retries() {
        let event = CallbackEvent::test_event();
        let first = Sha256FingerprintDeriver.derive(&event).unwrap();
        assert_eq!(first, Sha256FingerprintDeriver.derive(&event).unwrap());
        let mut changed = event.clone();
        changed.output_url = Some("https://office.example.test/cache/next".into());
        assert_ne!(first, Sha256FingerprintDeriver.derive(&changed).unwrap());
        let mut changed_file_type = event.clone();
        changed_file_type.file_type = "odt".into();
        assert_eq!(
            first,
            Sha256FingerprintDeriver.derive(&changed_file_type).unwrap()
        );
        changed = event;
        changed.activity = crate::routes::ParticipantActivity::Connected;
        changed.activity_user_id = changed.participant_id.clone();
        assert_ne!(first, Sha256FingerprintDeriver.derive(&changed).unwrap());
    }

    #[test]
    fn spooled_callback_output_is_private_and_removed_on_drop() {
        let (file, path) = create_spool_file().unwrap();
        drop(file);
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
        let output = CallbackOutput::new(path.clone(), "application/test".into(), 0);
        drop(output);
        assert!(!path.exists());
    }

    #[test]
    fn terminal_callback_receipts_do_not_refetch_provider_output() {
        for state in [
            DocumentCallbackState::Committed,
            DocumentCallbackState::Checkpoint,
            DocumentCallbackState::NoOp,
            DocumentCallbackState::Conflict,
        ] {
            assert_eq!(
                receipt_idempotency(state as i32),
                Ok(Idempotency::Duplicate)
            );
        }
        for state in [
            DocumentCallbackState::Received,
            DocumentCallbackState::Staging,
            DocumentCallbackState::Staged,
        ] {
            assert_eq!(receipt_idempotency(state as i32), Ok(Idempotency::New));
        }
    }

    #[test]
    fn non_output_no_op_receipt_needs_event_id_but_not_a_revision() {
        let receipt = DocumentCallbackReceipt {
            revision_id: String::new(),
            state: DocumentCallbackState::NoOp as i32,
            event_id: "core-event".into(),
        };
        assert_eq!(
            receipt_for_event(&receipt, false),
            Ok(Idempotency::Duplicate)
        );
        let output_receipt = DocumentCallbackReceipt {
            state: DocumentCallbackState::Received as i32,
            ..receipt.clone()
        };
        assert_eq!(
            receipt_for_event(&output_receipt, true),
            Err(CoreError::Invalid)
        );
    }

    #[test]
    fn callback_kind_and_revision_kind_match_provider_statuses() {
        let mut event = CallbackEvent::test_event();
        event.status = crate::routes::CallbackStatus::Editing;
        event.output_url = None;
        assert_eq!(callback_kind(&event), DocumentCallbackKind::Editing);
        assert_eq!(
            callback_revision_kind(&event),
            DocumentRevisionKind::Unspecified
        );
        for status in [
            crate::routes::CallbackStatus::MustSave,
            crate::routes::CallbackStatus::ForceSave,
        ] {
            event.status = status;
            event.output_url = Some("https://office.example.test/cache/output".into());
            assert_eq!(callback_kind(&event), DocumentCallbackKind::OutputRequired);
        }
        event.status = crate::routes::CallbackStatus::ForceSaveError;
        event.output_url = None;
        assert_eq!(callback_kind(&event), DocumentCallbackKind::ForceSaveError);
        event.status = crate::routes::CallbackStatus::SaveError;
        assert_eq!(callback_kind(&event), DocumentCallbackKind::Corrupted);
        event.status = crate::routes::CallbackStatus::ClosedNoChanges;
        assert_eq!(callback_kind(&event), DocumentCallbackKind::ClosedNoChanges);
    }

    #[test]
    fn timer_force_save_is_finalized_without_ordinary_commit() {
        let mut event = CallbackEvent::test_event();
        event.status = crate::routes::CallbackStatus::ForceSave;
        event.force_save_type = Some(crate::routes::ForceSaveType::Timer);
        assert_eq!(
            callback_revision_kind(&event),
            DocumentRevisionKind::Checkpoint
        );
        assert!(callback_is_checkpoint(&event));
        assert!(!requires_ordinary_commit(&event));
        event.force_save_type = Some(crate::routes::ForceSaveType::UserSave);
        assert!(!callback_is_checkpoint(&event));
        assert!(requires_ordinary_commit(&event));
    }

    #[test]
    fn terminal_callback_cleanup_releases_in_process_context() {
        let fingerprint = EventFingerprint([7_u8; 32]);
        let mut contexts = CallbackContexts::default();
        contexts.remember(
            fingerprint.0,
            CallbackContext {
                revision_id: "revision".into(),
            },
        );
        let callbacks = Mutex::new(contexts);
        remove_callback_context(&callbacks, &fingerprint).unwrap();
        let callbacks = callbacks.lock().unwrap();
        assert!(callbacks.by_fingerprint.is_empty());
        assert!(callbacks.insertion_order.is_empty());
    }

    #[test]
    fn callback_context_cache_enforces_exact_cap_and_recovers_evicted_retry() {
        let mut contexts = CallbackContexts::default();
        for index in 0..MAX_CALLBACK_CONTEXTS {
            contexts.remember(
                test_fingerprint(index),
                CallbackContext {
                    revision_id: format!("revision-{index}"),
                },
            );
        }
        assert_eq!(contexts.by_fingerprint.len(), MAX_CALLBACK_CONTEXTS);
        assert_eq!(contexts.insertion_order.len(), MAX_CALLBACK_CONTEXTS);

        contexts.remember(
            test_fingerprint(MAX_CALLBACK_CONTEXTS),
            CallbackContext {
                revision_id: format!("revision-{MAX_CALLBACK_CONTEXTS}"),
            },
        );
        assert_eq!(contexts.by_fingerprint.len(), MAX_CALLBACK_CONTEXTS);
        assert_eq!(contexts.insertion_order.len(), MAX_CALLBACK_CONTEXTS);
        assert!(!contexts.by_fingerprint.contains_key(&test_fingerprint(0)));
        assert_eq!(contexts.insertion_order.front(), Some(&test_fingerprint(1)));
        assert!(
            contexts
                .by_fingerprint
                .contains_key(&test_fingerprint(MAX_CALLBACK_CONTEXTS))
        );

        // Core replays the durable revision ID when the evicted callback is
        // retried; remembering it again restores the local write bridge.
        contexts.remember(
            test_fingerprint(0),
            CallbackContext {
                revision_id: "revision-0".into(),
            },
        );
        assert_eq!(contexts.by_fingerprint.len(), MAX_CALLBACK_CONTEXTS);
        assert_eq!(contexts.insertion_order.len(), MAX_CALLBACK_CONTEXTS);
        assert_eq!(
            contexts
                .by_fingerprint
                .get(&test_fingerprint(0))
                .map(|context| context.revision_id.as_str()),
            Some("revision-0")
        );
        assert!(!contexts.by_fingerprint.contains_key(&test_fingerprint(1)));
        assert_eq!(contexts.insertion_order.front(), Some(&test_fingerprint(2)));
        assert_eq!(contexts.insertion_order.back(), Some(&test_fingerprint(0)));
    }

    fn test_fingerprint(index: usize) -> [u8; 32] {
        let mut fingerprint = [0_u8; 32];
        fingerprint[..8].copy_from_slice(&(index as u64).to_be_bytes());
        fingerprint
    }
}

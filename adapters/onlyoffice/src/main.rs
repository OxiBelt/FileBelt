// SPDX-License-Identifier: AGPL-3.0-only

//! mTLS HTTP boundary for the separately deployed AGPL adapter.
//!
//! The process accepts TLS 1.3 only from OxiBelt's exact SPIFFE identity;
//! DocumentServer reaches it through that edge. All outbound Core, I/O, and
//! egress calls use explicit mTLS clients.

#![deny(unsafe_code)]

use filebelt_onlyoffice_adapter::config::AdapterConfig;
use filebelt_onlyoffice_adapter::routes::{
    AdapterService, ByteRange, CallbackError, CallbackEvent, CallbackStatus, ForceSaveType,
    Request, Response, callback_requires_output, normalize_server_version,
    participant_activity_from_actions,
};
use filebelt_onlyoffice_adapter::tls::AdapterTlsListener;
use filebelt_onlyoffice_adapter::{
    Hs256JwtVerifier, HttpCoreClient, HttpEgressGateway, Sha256FingerprintDeriver,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PRIVATE_CONNECTIONS: usize = 16;
const MAX_INPUT_TRANSFERS: usize = 4;
const MAX_CALLBACK_TRANSFERS: usize = 2;
const LAUNCHER_ASSET: &str = include_str!("../ui/launcher.js");

type Service =
    AdapterService<HttpCoreClient, Hs256JwtVerifier, Sha256FingerprintDeriver, HttpEgressGateway>;

#[derive(Clone)]
struct RouteLimits {
    input_transfers: Arc<Semaphore>,
    callback_transfers: Arc<Semaphore>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| std::io::Error::other("cannot install aws-lc crypto provider"))?;
    let (config_path, bind) = arguments()?;
    let config = AdapterConfig::load(&config_path, SystemTime::now())
        .map_err(|_| std::io::Error::other("invalid ONLYOFFICE adapter configuration"))?;
    // Fail startup when the mounted mTLS trust is invalid instead of reporting
    // ready and subsequently widening a failure mode at a request boundary.
    let core = HttpCoreClient::new(config.clone())
        .map_err(|_| std::io::Error::other("invalid Core/I-O mTLS configuration"))?;
    let egress = HttpEgressGateway::new(&config.egress_gateway)
        .map_err(|_| std::io::Error::other("invalid egress-gateway mTLS configuration"))?;
    let service = Service {
        config,
        core,
        jwt: Hs256JwtVerifier,
        fingerprints: Sha256FingerprintDeriver,
        egress,
    };
    let address = bind
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid adapter bind address"))?;
    let listener = AdapterTlsListener::bind(address, &service.config.server_tls)
        .await
        .map_err(io::Error::other)?;
    let operations_bind: std::net::SocketAddr = env::var("FILEBELT_ONLYOFFICE_OPERATIONS_BIND")
        .unwrap_or_else(|_| "0.0.0.0:9090".into())
        .parse()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid operations bind address",
            )
        })?;
    let operations_listener = tokio::net::TcpListener::bind(operations_bind).await?;
    let service = Arc::new(service);
    let connection_budget = Arc::new(Semaphore::new(MAX_PRIVATE_CONNECTIONS));
    let route_limits = RouteLimits {
        input_transfers: Arc::new(Semaphore::new(MAX_INPUT_TRANSFERS)),
        callback_transfers: Arc::new(Semaphore::new(MAX_CALLBACK_TRANSFERS)),
    };
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = operations_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = serve_operations(stream).await;
            });
        }
    });
    loop {
        let stream = listener.accept().await.map_err(io::Error::other)?;
        let Ok(connection_permit) = Arc::clone(&connection_budget).try_acquire_owned() else {
            tokio::spawn(async move {
                let mut stream = stream;
                let _ = write_response(&mut stream, Response::text(429, "adapter busy\n")).await;
            });
            continue;
        };
        let service = Arc::clone(&service);
        let route_limits = route_limits.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let _ = serve(stream, service, route_limits).await;
        });
    }
}

fn arguments() -> std::io::Result<(PathBuf, String)> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("serve") || args.next().as_deref() != Some("--config") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: filebelt-onlyoffice-adapter serve --config PATH",
        ));
    }
    let config = args.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "config path is absent")
    })?;
    if args.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unexpected adapter argument",
        ));
    }
    let bind = env::var("FILEBELT_ONLYOFFICE_BIND").unwrap_or_else(|_| "0.0.0.0:8089".into());
    Ok((config.into(), bind))
}

async fn serve<S>(mut stream: S, service: Arc<Service>, limits: RouteLimits) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let parsed = read_request(&mut stream).await;
    let response = match parsed {
        Ok(request) => tokio::task::spawn_blocking(move || route(&service, &limits, request))
            .await
            .unwrap_or_else(|_| Response::text(503, "adapter unavailable\n")),
        Err(_) => Response::text(400, "malformed request\n"),
    };
    write_response(&mut stream, response).await
}

async fn serve_operations(mut stream: tokio::net::TcpStream) -> io::Result<()> {
    let response = match read_request(&mut stream).await {
        Ok(request)
            if request.method == "GET"
                && matches!(request.path.as_str(), "/health/live" | "/health/ready") =>
        {
            Response::text(200, "ok\n")
        }
        Ok(_) => Response::text(404, "not found\n"),
        Err(_) => Response::text(400, "malformed request\n"),
    };
    write_response(&mut stream, response).await
}

/// Read a single request incrementally. The process closes the connection
/// after every response, so a second pipelined request is rejected rather than
/// being ambiguously parsed as body bytes.
async fn read_request<S>(stream: &mut S) -> Result<ParsedRequest, ()>
where
    S: AsyncRead + Unpin,
{
    timeout(REQUEST_TIMEOUT, read_request_inner(stream))
        .await
        .map_err(|_| ())?
}

async fn read_request_inner<S>(stream: &mut S) -> Result<ParsedRequest, ()>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(1024);
    let boundary = loop {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(());
        }
        if let Some(boundary) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            break boundary;
        }
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || bytes.len() + read > MAX_REQUEST_BYTES {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    let (method, path, headers, content_length) = parse_request_head(&bytes[..boundary])?;
    if content_length > MAX_REQUEST_BYTES - boundary - 4 {
        return Err(());
    }
    let total = boundary + 4 + content_length;
    while bytes.len() < total {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || bytes.len() + read > total {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    if bytes.len() != total {
        return Err(());
    }
    Ok(ParsedRequest {
        method,
        path,
        headers,
        body: bytes[boundary + 4..].to_vec(),
    })
}

#[derive(Clone)]
struct ParsedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[cfg(test)]
fn parse_request(bytes: &[u8]) -> Result<ParsedRequest, ()> {
    let boundary = bytes
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .ok_or(())?;
    let (method, path, headers, length) = parse_request_head(&bytes[..boundary])?;
    let body = bytes[boundary + 4..].to_vec();
    if length != body.len() || length > MAX_REQUEST_BYTES / 2 {
        return Err(());
    }
    Ok(ParsedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn parse_request_head(
    bytes: &[u8],
) -> Result<(String, String, BTreeMap<String, String>, usize), ()> {
    let head = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(())?;
    let mut request_parts = request_line.split_ascii_whitespace();
    let method = request_parts.next().ok_or(())?.to_owned();
    let path = request_parts.next().ok_or(())?.to_owned();
    if request_parts.next() != Some("HTTP/1.1")
        || request_parts.next().is_some()
        || !path.starts_with('/')
        || path.contains('?')
        || path.contains('#')
    {
        return Err(());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(())?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || value == b'-')
        {
            return Err(());
        }
        let key = name.to_ascii_lowercase();
        if headers.insert(key, value.trim().to_owned()).is_some() {
            return Err(());
        }
    }
    let length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>().map_err(|_| ()))
        .transpose()?
        .unwrap_or(0);
    if length > MAX_REQUEST_BYTES / 2 {
        return Err(());
    }
    if headers.contains_key("transfer-encoding") {
        return Err(());
    }
    Ok((method, path, headers, length))
}

fn route(service: &Service, limits: &RouteLimits, request: ParsedRequest) -> Response {
    let now = SystemTime::now();
    if !has_allowed_route_host(&request, &service.config) {
        return Response::text(404, "not found\n");
    }
    let is_launcher = request.method == "GET" && request.path == "/onlyoffice/launcher.js";
    let is_launch = request.method == "POST" && request.path == "/onlyoffice/launch";
    if is_launcher {
        let mut response = Response::text(200, LAUNCHER_ASSET);
        response.headers.insert(
            "Content-Type".into(),
            "text/javascript; charset=utf-8".into(),
        );
        response
            .headers
            .insert("Cache-Control".into(), "no-store".into());
        response
            .headers
            .insert("X-Content-Type-Options".into(), "nosniff".into());
        response
            .headers
            .insert("Referrer-Policy".into(), "no-referrer".into());
        return response;
    }
    if request.method == "POST" && request.path == "/onlyoffice/callback" {
        return Response::text(404, "not found\n");
    }
    if request.method == "POST" && request.path.starts_with("/onlyoffice/callback/") {
        let Some((route_document_id, route_participant_id)) = request
            .path
            .strip_prefix("/onlyoffice/callback/")
            .and_then(|value| value.split_once('/'))
        else {
            return Response::text(404, "not found\n");
        };
        return callback_response(
            service,
            limits,
            route_document_id,
            route_participant_id,
            &request,
            now,
        );
    }
    let launch_id = if request.method == "POST" && request.path == "/onlyoffice/launch" {
        form_field(&request.body, "launch_grant")
    } else {
        None
    };
    let provider_jwt = request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(ToOwned::to_owned);
    let range = match request.headers.get("range") {
        Some(value) => match parse_range(value) {
            Some(range) => Some(range),
            None => return Response::text(416, "invalid range\n"),
        },
        None => None,
    };
    let _input_transfer =
        if request.method == "GET" && request.path.starts_with("/onlyoffice/input/") {
            match limits.input_transfers.try_acquire() {
                Ok(permit) => Some(permit),
                Err(_) => return Response::text(429, "input transfer busy\n"),
            }
        } else {
            None
        };
    let mut response = service.dispatch(
        Request {
            method: request.method,
            path: request.path,
            origin: request.headers.get("origin").cloned(),
            provider_jwt,
            range,
            launch_id,
        },
        now,
    );
    if is_launch && response.status == 200 {
        return launch_shell_response(&service.config, response);
    }
    if response.status == 200 && !response.headers.contains_key("Content-Type") {
        response
            .headers
            .insert("Content-Type".into(), "text/plain; charset=utf-8".into());
    }
    response
}

fn has_exact_host(
    request: &ParsedRequest,
    origin: &filebelt_onlyoffice_adapter::config::Origin,
) -> bool {
    request
        .headers
        .get("host")
        .is_some_and(|host| host.eq_ignore_ascii_case(origin.host()))
}

fn has_allowed_route_host(request: &ParsedRequest, config: &AdapterConfig) -> bool {
    let is_launcher = request.method == "GET" && request.path == "/onlyoffice/launcher.js";
    let is_launch = request.method == "POST" && request.path == "/onlyoffice/launch";
    if is_launcher || is_launch {
        return has_exact_host(request, &config.launch_origin);
    }
    let is_public_route = matches!(
        (request.method.as_str(), request.path.as_str()),
        ("GET", "/onlyoffice/source") | ("GET", "/onlyoffice/about")
    ) || (request.method == "GET"
        && request.path.starts_with("/onlyoffice/input/"))
        || (request.method == "POST" && request.path.starts_with("/onlyoffice/callback"));
    is_public_route && has_exact_host(request, &config.public_origin)
}

fn launch_shell_response(config: &AdapterConfig, mut launch: Response) -> Response {
    let Ok(descriptor) = String::from_utf8(launch.body) else {
        return Response::text(503, "launch unavailable\n");
    };
    let Ok(value) = serde_json::from_str::<Value>(&descriptor) else {
        return Response::text(503, "launch unavailable\n");
    };
    // The descriptor is data, never executable JavaScript. Escaping prevents a
    // provider-controlled display name from terminating the inert script tag.
    let descriptor = value
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    let document_server = config.document_server_origin.as_str();
    let source_and_license_url = format!("{}/onlyoffice/source", config.public_origin.as_str());
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><title>FileBelt document editor</title></head><body><main><p id=\"onlyoffice-launch-state\" aria-live=\"polite\"></p><button id=\"onlyoffice-launch-button\" type=\"button\">Open editor</button><div id=\"onlyoffice-editor\"></div></main><footer><a href=\"{source_and_license_url}\" target=\"_blank\" rel=\"noopener noreferrer\">Source &amp; License</a></footer><script id=\"onlyoffice-launch-descriptor\" type=\"application/json\">{descriptor}</script><script type=\"module\" src=\"/onlyoffice/launcher.js\"></script></body></html>"
    );
    launch.body = body.into_bytes();
    launch.headers.remove("Set-Cookie");
    launch
        .headers
        .insert("Content-Type".into(), "text/html; charset=utf-8".into());
    launch
        .headers
        .insert("Cache-Control".into(), "no-store".into());
    launch
        .headers
        .insert("Referrer-Policy".into(), "no-referrer".into());
    launch
        .headers
        .insert("X-Content-Type-Options".into(), "nosniff".into());
    launch
        .headers
        .insert("X-Frame-Options".into(), "DENY".into());
    launch.headers.insert(
        "Content-Security-Policy".into(),
        format!(
            "default-src 'none'; base-uri 'none'; connect-src {document_server}; form-action 'none'; frame-src {document_server}; frame-ancestors 'none'; img-src {document_server}; media-src 'none'; object-src 'none'; script-src 'self' {document_server}; style-src 'self'; sandbox allow-scripts allow-same-origin allow-forms allow-downloads allow-popups"
        ),
    );
    launch
}

fn callback_response(
    service: &Service,
    limits: &RouteLimits,
    route_document_id: &str,
    route_participant_id: &str,
    request: &ParsedRequest,
    now: SystemTime,
) -> Response {
    if !is_uuid(route_document_id) || !is_uuid(route_participant_id) {
        return Response::text(404, "not found\n");
    }
    let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
        return Response::text(400, "invalid callback\n");
    };
    let token = request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| body.get("token").and_then(Value::as_str));
    let Some(token) = token else {
        return Response::text(401, "provider jwt required\n");
    };
    let Ok(event) = callback_event(route_document_id, route_participant_id, &body) else {
        return Response::text(400, "invalid callback\n");
    };
    let _callback_transfer = if callback_requires_output(&event) {
        match limits.callback_transfers.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => return Response::text(429, "callback transfer busy\n"),
        }
    } else {
        None
    };
    match service.callback(token, event, now) {
        Ok(_) => response_json(200, "{\"error\":0}\n"),
        Err(CallbackError::Jwt) => Response::text(401, "invalid provider jwt\n"),
        Err(
            CallbackError::Malformed
            | CallbackError::MissingForceSaveType
            | CallbackError::MissingOutput
            | CallbackError::UnexpectedOutput
            | CallbackError::OutputOrigin,
        ) => Response::text(400, "invalid callback\n"),
        Err(
            CallbackError::Fingerprint
            | CallbackError::Core
            | CallbackError::Egress
            | CallbackError::MediaType
            | CallbackError::Package,
        ) => Response::text(503, "callback unavailable\n"),
    }
}

fn callback_event(
    route_document_id: &str,
    route_participant_id: &str,
    body: &Value,
) -> Result<CallbackEvent, ()> {
    let document_id = body.get("key").and_then(Value::as_str).ok_or(())?;
    if document_id != route_document_id {
        return Err(());
    }
    let status = match body.get("status").and_then(Value::as_u64).ok_or(())? {
        1 => CallbackStatus::Editing,
        2 => CallbackStatus::MustSave,
        3 => CallbackStatus::SaveError,
        4 => CallbackStatus::ClosedNoChanges,
        6 => CallbackStatus::ForceSave,
        7 => CallbackStatus::ForceSaveError,
        _ => return Err(()),
    };
    let force_save_type = match body.get("forcesavetype").and_then(Value::as_u64) {
        None => None,
        Some(0) => Some(ForceSaveType::Command),
        Some(1) => Some(ForceSaveType::UserSave),
        Some(2) => Some(ForceSaveType::Timer),
        Some(3) => Some(ForceSaveType::FormSubmit),
        Some(_) => return Err(()),
    };
    let (activity, activity_user_id) =
        participant_activity_from_actions(status, body.get("actions"), route_participant_id)
            .map_err(|_| ())?;
    let revision = body
        .get("history")
        .and_then(|history| history.get("serverVersion"))
        .and_then(normalize_server_version)
        .or_else(|| body.get("revision").and_then(normalize_server_version))
        .unwrap_or_default();
    let provider_event_id = body
        .get("userdata")
        .and_then(Value::as_str)
        .or_else(|| body.get("event_id").and_then(Value::as_str))
        .unwrap_or(&revision);
    Ok(CallbackEvent {
        document_id: document_id.to_owned(),
        participant_id: route_participant_id.to_owned(),
        status,
        force_save_type,
        activity,
        activity_user_id,
        output_url: body
            .get("url")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        file_type: body
            .get("filetype")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or(())?,
        provider_event_id: provider_event_id.to_owned(),
        revision: revision.to_owned(),
    })
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            (matches!(index, 8 | 13 | 18 | 23) && byte == b'-') || byte.is_ascii_hexdigit()
        })
}

fn form_field(body: &[u8], expected: &str) -> Option<String> {
    let body = std::str::from_utf8(body).ok()?;
    let mut result = None;
    for pair in body.split('&') {
        let (key, value) = pair.split_once('=')?;
        if percent_decode(key)? == expected {
            if result.is_some() {
                return None;
            }
            result = Some(percent_decode(value)?);
        }
    }
    result.filter(|value| !value.is_empty() && value.len() <= 512)
}

fn percent_decode(value: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(value) = input.next() {
        match value {
            b'+' => bytes.push(b' '),
            b'%' => {
                let high = input.next()?.to_ascii_lowercase();
                let low = input.next()?.to_ascii_lowercase();
                let hex = |value| match value {
                    b'0'..=b'9' => Some(value - b'0'),
                    b'a'..=b'f' => Some(value - b'a' + 10),
                    _ => None,
                };
                bytes.push((hex(high)? << 4) | hex(low)?);
            }
            value if value.is_ascii() => bytes.push(value),
            _ => return None,
        }
    }
    String::from_utf8(bytes).ok()
}

fn parse_range(value: &str) -> Option<ByteRange> {
    let range = value.strip_prefix("bytes=")?;
    if range.contains(',') {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    let start = start.parse().ok()?;
    let end_inclusive = if end.is_empty() {
        u64::MAX
    } else {
        end.parse().ok()?
    };
    (start <= end_inclusive).then_some(ByteRange {
        start,
        end_inclusive,
    })
}

fn response_json(status: u16, body: &str) -> Response {
    let mut response = Response::text(status, body);
    response.headers.insert(
        "Content-Type".into(),
        "application/json; charset=utf-8".into(),
    );
    response
}

async fn write_response<S>(stream: &mut S, response: Response) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let reason = match response.status {
        200 => "OK",
        206 => "Partial Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        response.body.len(),
    );
    for (name, value) in response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use filebelt_onlyoffice_adapter::config::{
        DOCUMENT_SERVER_VERSION, MtlsClientConfig, Origin, Provider, ServerTlsConfig,
    };
    use std::path::PathBuf;
    use url::Url;

    #[test]
    fn parses_only_single_explicit_ranges() {
        assert_eq!(
            parse_range("bytes=1-9"),
            Some(ByteRange {
                start: 1,
                end_inclusive: 9
            })
        );
        assert_eq!(parse_range("bytes=1-9,11-12"), None);
        assert_eq!(parse_range("bytes=-9"), None);
        assert_eq!(
            parse_range("bytes=1-"),
            Some(ByteRange {
                start: 1,
                end_inclusive: u64::MAX
            })
        );
    }

    #[test]
    fn callback_mapping_is_exact_and_binds_route_to_key() {
        let body = serde_json::json!({
            "key": "session-1", "status": 6, "forcesavetype": 1,
            "url": "https://office.example.test/cache/output", "event_id": "event",
            "filetype": "docx",
            "history": {"serverVersion": 42}
        });
        let event =
            callback_event("session-1", "550e8400-e29b-41d4-a716-446655440001", &body).unwrap();
        assert_eq!(event.status, CallbackStatus::ForceSave);
        assert_eq!(event.force_save_type, Some(ForceSaveType::UserSave));
        assert!(
            callback_event("session-2", "550e8400-e29b-41d4-a716-446655440001", &body,).is_err()
        );
    }

    #[test]
    fn callback_status_numbers_match_onlyoffice_semantics() {
        for (code, expected) in [
            (1, CallbackStatus::Editing),
            (2, CallbackStatus::MustSave),
            (3, CallbackStatus::SaveError),
            (4, CallbackStatus::ClosedNoChanges),
            (6, CallbackStatus::ForceSave),
            (7, CallbackStatus::ForceSaveError),
        ] {
            let mut body = serde_json::json!({
                "key": "session-1", "status": code, "forcesavetype": 1,
                "url": "https://office.example.test/cache/output",
                "filetype": "docx",
                "userdata": "event", "history": {"serverVersion": 42}
            });
            if code == 1 {
                body["actions"] = serde_json::json!([
                    {"type": 1, "userid": "550e8400-e29b-41d4-a716-446655440001"}
                ]);
            }
            assert_eq!(
                callback_event("session-1", "550e8400-e29b-41d4-a716-446655440001", &body,)
                    .unwrap()
                    .status,
                expected
            );
        }
        let invalid = serde_json::json!({"key": "session-1", "status": 5});
        assert!(
            callback_event(
                "session-1",
                "550e8400-e29b-41d4-a716-446655440001",
                &invalid,
            )
            .is_err()
        );
    }

    #[test]
    fn form_parser_rejects_duplicate_grants() {
        assert_eq!(
            form_field(b"launch_grant=one", "launch_grant"),
            Some("one".into())
        );
        assert_eq!(form_field(b"grant=one", "launch_grant"), None);
        assert_eq!(
            form_field(b"launch_grant=one&launch_grant=two", "launch_grant"),
            None
        );
    }

    #[test]
    fn request_parser_requires_an_exact_content_length() {
        let parsed =
            parse_request(b"GET /health/live HTTP/1.1\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert_eq!(parsed.path, "/health/live");
        assert!(parse_request(b"GET /health/live HTTP/1.1\r\nContent-Length: 1\r\n\r\n").is_err());
        assert!(
            parse_request(
                b"POST /onlyoffice/launch HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .is_err()
        );
    }

    #[test]
    fn transfer_and_connection_budgets_fail_fast_at_declared_limits() {
        let inputs = Arc::new(Semaphore::new(MAX_INPUT_TRANSFERS));
        let input_permits = (0..MAX_INPUT_TRANSFERS)
            .map(|_| inputs.try_acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(inputs.try_acquire().is_err());
        drop(input_permits);
        let callbacks = Arc::new(Semaphore::new(MAX_CALLBACK_TRANSFERS));
        let callback_permits = (0..MAX_CALLBACK_TRANSFERS)
            .map(|_| callbacks.try_acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(callbacks.try_acquire().is_err());
        drop(callback_permits);
        let connections = Arc::new(Semaphore::new(MAX_PRIVATE_CONNECTIONS));
        let connection_permits = (0..MAX_PRIVATE_CONNECTIONS)
            .map(|_| connections.try_acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(connections.try_acquire().is_err());
        drop(connection_permits);
    }

    #[tokio::test]
    async fn reads_a_segmented_request_with_an_exact_bounded_body() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let reading = tokio::spawn(async move { read_request(&mut server).await });
        client
            .write_all(b"POST /onlyoffice/launch HTTP/1.1\r\nContent-Length: 16\r\n\r\nlaunch_")
            .await
            .unwrap();
        client.write_all(b"grant=one").await.unwrap();
        let request = reading.await.unwrap().unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, b"launch_grant=one");
    }

    #[test]
    fn launch_shell_keeps_descriptor_inert_and_isolates_the_provider() {
        let mut launch = Response::text(
            200,
            r#"{"apiJsUrl":"https://office.example.test/web-apps/apps/api/documents/api.js","editorConfig":{"document":{"title":"</script><img>"}}}"#,
        );
        launch.headers.insert("Set-Cookie".into(), "opaque".into());
        let shell = launch_shell_response(&config(), launch);
        let body = String::from_utf8(shell.body).unwrap();
        assert!(body.contains("type=\"application/json\""));
        assert!(body.contains("src=\"/onlyoffice/launcher.js\""));
        assert!(body.contains("\\u003c/script\\u003e"));
        let link = "<a href=\"https://files.example.test/onlyoffice/source\" target=\"_blank\" rel=\"noopener noreferrer\">Source &amp; License</a>";
        assert!(body.contains(link));
        assert!(body.find(link).unwrap() < body.find("onlyoffice-launch-descriptor").unwrap());
        assert_eq!(body.matches("/onlyoffice/source").count(), 1);
        assert!(!body.contains("https://office.example.test/onlyoffice/source"));
        let csp = shell.headers.get("Content-Security-Policy").unwrap();
        assert!(csp.contains("script-src 'self' https://office.example.test"));
        assert!(csp.contains("connect-src https://office.example.test"));
        assert!(csp.contains("frame-src https://office.example.test"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert_eq!(
            csp.split("; ")
                .find(|directive| directive.starts_with("sandbox ")),
            Some(
                "sandbox allow-scripts allow-same-origin allow-forms allow-downloads allow-popups"
            )
        );
        assert!(!csp.contains("https://files.example.test"));
        assert!(!csp.contains("unsafe-inline"));
        assert_eq!(shell.headers.get("X-Frame-Options"), Some(&"DENY".into()));
        assert_eq!(
            shell.headers.get("Referrer-Policy"),
            Some(&"no-referrer".into())
        );
        assert_eq!(shell.headers.get("Cache-Control"), Some(&"no-store".into()));
        assert!(!shell.headers.contains_key("Set-Cookie"));
        assert!(
            shell
                .headers
                .keys()
                .all(|name| !name.starts_with("Access-Control-"))
        );
    }

    #[test]
    fn routes_require_the_exact_launch_or_public_host() {
        let config = config();
        let request = ParsedRequest {
            method: "POST".into(),
            path: "/onlyoffice/launch".into(),
            headers: BTreeMap::from([("host".into(), "launch.example.test".into())]),
            body: Vec::new(),
        };
        assert!(has_allowed_route_host(&request, &config));
        let public_request = ParsedRequest {
            headers: BTreeMap::from([("host".into(), "FILES.EXAMPLE.TEST".into())]),
            ..request
        };
        assert!(!has_allowed_route_host(&public_request, &config));
        let source_request = ParsedRequest {
            method: "GET".into(),
            path: "/onlyoffice/source".into(),
            ..public_request
        };
        assert!(has_allowed_route_host(&source_request, &config));
        for (method, path) in [
            ("GET", "/onlyoffice/input/session/participant"),
            ("POST", "/onlyoffice/callback/session/participant"),
        ] {
            let public_endpoint = ParsedRequest {
                method: method.into(),
                path: path.into(),
                ..source_request.clone()
            };
            assert!(has_allowed_route_host(&public_endpoint, &config));
            let launch_endpoint = ParsedRequest {
                headers: BTreeMap::from([("host".into(), "launch.example.test".into())]),
                ..public_endpoint
            };
            assert!(!has_allowed_route_host(&launch_endpoint, &config));
        }
        let port_request = ParsedRequest {
            headers: BTreeMap::from([("host".into(), "launch.example.test:443".into())]),
            ..source_request
        };
        assert!(!has_allowed_route_host(&port_request, &config));
        for host in ["files.example.test", "launch.example.test"] {
            let health_request = ParsedRequest {
                method: "GET".into(),
                path: "/health/live".into(),
                headers: BTreeMap::from([("host".into(), host.into())]),
                body: Vec::new(),
            };
            assert!(!has_allowed_route_host(&health_request, &config));
        }
    }

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
}

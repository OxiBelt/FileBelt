// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request as AxumRequest, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::post;
use filebelt_runtime::{
    OperationsState, backend_server_config, operations_router, wait_for_shutdown,
};
use http_body_util::{Full, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{info, warn};
use url::Url;

use crate::config::TargetPolicy;
use crate::policy::{
    McpRequestPolicy, OnlyofficeFetchRequest, OnlyofficeRequestPolicy, PolicyError,
    admit_response_status,
};
use crate::tls::TunnelConnector;
use crate::{GatewayConfig, GatewayMode};

const ROLE: &str = "filebelt-private-egress-gateway";
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_PENDING_TLS_HANDSHAKES: usize = 128;
const INBOUND_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct AppState {
    policy: RequestPolicy,
    tunnel: TunnelConnector,
    permits: Arc<Semaphore>,
    max_request_bytes: usize,
    max_response_bytes: usize,
    request_timeout: std::time::Duration,
}

#[derive(Clone)]
enum RequestPolicy {
    Mcp(McpRequestPolicy),
    Onlyoffice(OnlyofficeRequestPolicy),
}

pub async fn serve(config: GatewayConfig) -> Result<()> {
    config
        .validate()
        .map_err(|_| anyhow!("invalid gateway config"))?;
    let target = config
        .target_policy()
        .map_err(|_| anyhow!("invalid target policy"))?;
    let (policy, target_server_name, target_ca_file) = match target {
        TargetPolicy::Mcp {
            url,
            trust_profile,
            server_name,
            ca_file,
        } => (
            RequestPolicy::Mcp(McpRequestPolicy::new(url, trust_profile)),
            server_name,
            ca_file,
        ),
        TargetPolicy::OnlyofficeOutput {
            origin,
            path_prefix,
            server_name,
            ca_file,
        } => (
            RequestPolicy::Onlyoffice(OnlyofficeRequestPolicy::new(
                origin,
                path_prefix,
                config.limits.max_response_bytes,
            )),
            server_name,
            ca_file,
        ),
    };
    let tunnel = TunnelConnector::new(
        &config.relay,
        &target_server_name,
        &target_ca_file,
        config.limits.connect_timeout(),
    )
    .map_err(|_| anyhow!("cannot configure tunnel TLS"))?;
    let state = AppState {
        policy,
        tunnel: tunnel.clone(),
        permits: Arc::new(Semaphore::new(config.limits.max_concurrency)),
        max_request_bytes: config.limits.max_request_bytes,
        max_response_bytes: config.limits.max_response_bytes,
        request_timeout: config.limits.request_timeout(),
    };
    let application = match config.mode {
        GatewayMode::Mcp => Router::new().route("/", post(mcp_request)),
        GatewayMode::OnlyofficeOutput => Router::new().route("/v1/fetch", post(onlyoffice_request)),
    }
    .layer(axum::extract::DefaultBodyLimit::max(
        config.limits.max_request_bytes,
    ))
    .layer(tower::limit::ConcurrencyLimitLayer::new(
        config.limits.max_concurrency,
    ))
    .layer(axum::middleware::from_fn_with_state(
        config.limits.request_timeout(),
        inbound_request_timeout,
    ))
    .with_state(state);

    let ready_tunnel = tunnel.clone();
    let readiness_permit = Arc::new(Semaphore::new(1));
    let operations = OperationsState::new(ROLE, true, move || {
        let tunnel = ready_tunnel.clone();
        let readiness_permit = Arc::clone(&readiness_permit);
        async move {
            let Ok(_permit) = readiness_permit.try_acquire_owned() else {
                return false;
            };
            tunnel.connect().await.is_ok()
        }
    });
    let operations_listener = tokio::net::TcpListener::bind(config.operations_address)
        .await
        .context("cannot bind gateway operations listener")?;
    let operations_state = operations.clone();
    let mut operations_server = tokio::spawn(async move {
        axum::serve(operations_listener, operations_router(operations_state))
            .await
            .map_err(anyhow::Error::from)
    });
    let listener = RedactedMtlsListener::bind(config.listen_address, &config.server_tls).await?;
    let mut application_server = tokio::spawn(async move {
        axum::serve(listener, application)
            .await
            .map_err(anyhow::Error::from)
    });
    info!(code = "private_egress_gateway_ready");
    tokio::select! {
        result = &mut application_server => {
            result.context("gateway application task failed")??;
        }
        result = &mut operations_server => {
            result.context("gateway operations task failed")??;
        }
        () = wait_for_shutdown() => {
            operations.begin_draining();
            application_server.abort();
            operations_server.abort();
        }
    }
    Ok(())
}

async fn inbound_request_timeout(
    State(timeout): State<Duration>,
    request: AxumRequest,
    next: Next,
) -> Response<Body> {
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => stable_error(StatusCode::REQUEST_TIMEOUT, "gateway.request.timeout"),
    }
}

struct RedactedMtlsListener {
    accepted: mpsc::Receiver<(TlsStream<tokio::net::TcpStream>, SocketAddr)>,
    local_address: SocketAddr,
}

impl RedactedMtlsListener {
    async fn bind(
        address: SocketAddr,
        settings: &filebelt_control_protocol::BackendServerTlsConfig,
    ) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .context("cannot bind gateway mTLS listener")?;
        let local_address = listener
            .local_addr()
            .context("cannot inspect gateway mTLS listener")?;
        let server = backend_server_config(settings)
            .map_err(|_| anyhow!("cannot configure gateway mTLS"))?;
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let (sender, accepted) = mpsc::channel(MAX_PENDING_TLS_HANDSHAKES);
        tokio::spawn(accept_mtls_connections(listener, acceptor, sender));
        Ok(Self {
            accepted,
            local_address,
        })
    }
}

async fn accept_mtls_connections(
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
    sender: mpsc::Sender<(TlsStream<tokio::net::TcpStream>, SocketAddr)>,
) {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_TLS_HANDSHAKES));
    loop {
        if sender.is_closed() {
            return;
        }
        let Ok(permit) = Arc::clone(&pending).acquire_owned().await else {
            return;
        };
        let Ok((stream, address)) = listener.accept().await else {
            warn!(code = "private_egress_tcp_accept_failed");
            drop(permit);
            continue;
        };
        let acceptor = acceptor.clone();
        let sender = sender.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(INBOUND_TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
            {
                Ok(Ok(stream)) => {
                    let _ = sender.send((stream, address)).await;
                }
                Ok(Err(_)) => warn!(code = "private_egress_tls_handshake_rejected"),
                Err(_) => warn!(code = "private_egress_tls_handshake_timeout"),
            }
        });
    }
}

impl axum::serve::Listener for RedactedMtlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Some(connection) = self.accepted.recv().await {
                return connection;
            }
            warn!(code = "private_egress_tls_accept_loop_stopped");
            std::future::pending::<()>().await;
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local_address)
    }
}

async fn mcp_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let RequestPolicy::Mcp(policy) = &state.policy else {
        return stable_error(StatusCode::NOT_FOUND, "gateway.route.not_found");
    };
    if !headers_within_limit(&headers) {
        return policy_error(PolicyError::InvalidControl);
    }
    let admitted = match policy.admit(&headers) {
        Ok(admitted) => admitted,
        Err(error) => return policy_error(error),
    };
    if admitted.method == http::Method::GET && !body.is_empty() {
        return policy_error(PolicyError::InvalidControl);
    }
    forward(
        &state,
        admitted.method,
        admitted.target,
        admitted.headers,
        body,
        state.max_response_bytes,
    )
    .await
}

async fn onlyoffice_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let RequestPolicy::Onlyoffice(policy) = &state.policy else {
        return stable_error(StatusCode::NOT_FOUND, "gateway.route.not_found");
    };
    if !headers_within_limit(&headers)
        || !headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
    {
        return policy_error(PolicyError::InvalidControl);
    }
    let request: OnlyofficeFetchRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return policy_error(PolicyError::InvalidControl),
    };
    let admitted = match policy.admit(&headers, &request) {
        Ok(admitted) => admitted,
        Err(error) => return policy_error(error),
    };
    forward(
        &state,
        http::Method::GET,
        admitted.target,
        Vec::new(),
        Bytes::new(),
        admitted.maximum_bytes,
    )
    .await
}

async fn forward(
    state: &AppState,
    method: http::Method,
    target: Url,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
    response_limit: usize,
) -> Response<Body> {
    if body.len() > state.max_request_bytes {
        return policy_error(PolicyError::RequestTooLarge);
    }
    let Ok(_permit) = state.permits.clone().try_acquire_owned() else {
        return stable_error(StatusCode::TOO_MANY_REQUESTS, "gateway.busy");
    };
    match tokio::time::timeout(
        state.request_timeout,
        forward_bounded(&state.tunnel, method, target, headers, body, response_limit),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(ForwardError::Redirect)) => {
            stable_error(StatusCode::BAD_GATEWAY, "gateway.redirect.denied")
        }
        Ok(Err(ForwardError::ResponseTooLarge)) => {
            stable_error(StatusCode::BAD_GATEWAY, "gateway.response.too_large")
        }
        Ok(Err(ForwardError::Unavailable)) => {
            stable_error(StatusCode::BAD_GATEWAY, "gateway.upstream.unavailable")
        }
        Err(_) => stable_error(StatusCode::GATEWAY_TIMEOUT, "gateway.upstream.timeout"),
    }
}

#[derive(Clone, Copy, Debug)]
enum ForwardError {
    Redirect,
    ResponseTooLarge,
    Unavailable,
}

async fn forward_bounded(
    tunnel: &TunnelConnector,
    method: http::Method,
    target: Url,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
    response_limit: usize,
) -> Result<Response<Body>, ForwardError> {
    let stream = tunnel
        .connect()
        .await
        .map_err(|_| ForwardError::Unavailable)?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| ForwardError::Unavailable)?;
    tokio::spawn(async move {
        if connection.await.is_err() {
            warn!(code = "private_egress_http_connection_failed");
        }
    });
    let path = match target.query() {
        Some(query) => format!("{}?{query}", target.path()),
        None => target.path().to_owned(),
    };
    let mut request = Request::builder().method(method).uri(path);
    let request_headers = request.headers_mut().ok_or(ForwardError::Unavailable)?;
    request_headers.insert(
        HOST,
        HeaderValue::from_str(&target_host(&target)).map_err(|_| ForwardError::Unavailable)?,
    );
    for (name, value) in headers {
        request_headers.insert(name, value);
    }
    request_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).map_err(|_| ForwardError::Unavailable)?,
    );
    let response = sender
        .send_request(
            request
                .body(Full::new(body))
                .map_err(|_| ForwardError::Unavailable)?,
        )
        .await
        .map_err(|_| ForwardError::Unavailable)?;
    admit_response_status(response.status()).map_err(|_| ForwardError::Redirect)?;
    if !headers_within_limit(response.headers())
        || response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|size| size > response_limit)
    {
        return Err(ForwardError::ResponseTooLarge);
    }
    let status = response.status();
    let response_headers = response.headers().clone();
    let body = Body::new(Limited::new(response.into_body(), response_limit));
    let mut output = Response::builder().status(status);
    let output_headers = output.headers_mut().ok_or(ForwardError::Unavailable)?;
    for name in [CONTENT_TYPE, HeaderName::from_static("mcp-session-id")] {
        if let Some(value) = response_headers.get(&name) {
            output_headers.insert(name, value.clone());
        }
    }
    output.body(body).map_err(|_| ForwardError::Unavailable)
}

fn target_host(target: &Url) -> String {
    let host = match target.host() {
        Some(url::Host::Domain(host)) => host.to_owned(),
        Some(url::Host::Ipv4(host)) => host.to_string(),
        Some(url::Host::Ipv6(host)) => format!("[{host}]"),
        None => String::new(),
    };
    match target.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn headers_within_limit(headers: &HeaderMap) -> bool {
    headers
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())
                .filter(|size| *size <= MAX_HEADER_BYTES)
        })
        .is_some()
}

fn policy_error(error: PolicyError) -> Response<Body> {
    stable_error(error.status(), error.code())
}

fn stable_error(status: StatusCode, code: &'static str) -> Response<Body> {
    (status, axum::Json(serde_json::json!({ "error": code }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_uses_only_the_configured_url_authority() {
        assert_eq!(
            target_host(&Url::parse("https://llm.private.example/mcp").unwrap()),
            "llm.private.example"
        );
        assert_eq!(
            target_host(&Url::parse("https://llm.private.example:8443/mcp").unwrap()),
            "llm.private.example:8443"
        );
        assert_eq!(
            target_host(&Url::parse("https://[fd7a:115c:a1e0::1]/mcp").unwrap()),
            "[fd7a:115c:a1e0::1]"
        );
    }

    #[test]
    fn header_budget_is_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-test",
            HeaderValue::from_bytes(&vec![b'a'; MAX_HEADER_BYTES]).unwrap(),
        );
        assert!(!headers_within_limit(&headers));
    }

    #[test]
    fn stable_errors_contain_no_network_or_request_values() {
        let response = stable_error(StatusCode::BAD_GATEWAY, "gateway.upstream.unavailable");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }
}

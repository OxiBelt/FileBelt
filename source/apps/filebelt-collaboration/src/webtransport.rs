// SPDX-License-Identifier: Apache-2.0

//! HTTP/3 WebTransport admission for the collaboration protocol.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use h3::ext::Protocol;
use h3_webtransport::server::{AcceptedBi, WebTransportSession};
use http::{Method, Request, Response, StatusCode, header};
use quinn::{Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use tokio::task::JoinSet;
use url::Url;

use filebelt_control_protocol::{BackendServerTlsConfig, Config, DeploymentMode};
use filebelt_runtime::backend_server_config;

use crate::server::{CollaborationServerState, webtransport_stream};

const CONNECTION_ERROR: u32 = 0x10;
const STREAM_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 128;

type Session = WebTransportSession<h3_quinn::Connection, Bytes>;

pub async fn serve(
    config: Arc<Config>,
    state: CollaborationServerState,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    if config.deployment.mode != DeploymentMode::Kubernetes {
        bail!("WebTransport is admitted only behind the Kubernetes OxiBelt mTLS route");
    }
    let tls = config
        .backend_tls
        .as_ref()
        .and_then(|backend| backend.collaboration.as_ref())
        .ok_or_else(|| anyhow!("collaboration backend TLS is absent"))?;
    let server_config = quic_server_config(tls, config.collaboration.webtransport_idle_seconds)?;
    let endpoint = Endpoint::server(server_config, config.listeners.collaboration_webtransport)
        .context("cannot bind collaboration WebTransport listener")?;
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let connection_state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    match incoming.await {
                        Ok(connection) => {
                            let close = connection.clone();
                            if let Err(error) = handle_connection(connection, connection_state).await {
                                tracing::warn!(%error, "WebTransport connection rejected");
                                close.close(VarInt::from_u32(CONNECTION_ERROR), b"protocol rejected");
                            }
                        }
                        Err(error) => tracing::warn!(%error, "WebTransport QUIC handshake rejected"),
                    }
                });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!(%error, "WebTransport connection task failed");
                }
            }
        }
    }
    endpoint.close(VarInt::from_u32(0), b"server draining");
    let drain = Duration::from_secs(config.collaboration.webtransport_drain_seconds);
    if tokio::time::timeout(drain, async {
        while tasks.join_next().await.is_some() {}
        endpoint.wait_idle().await;
    })
    .await
    .is_err()
    {
        tasks.abort_all();
    }
    Ok(())
}

fn quic_server_config(tls: &BackendServerTlsConfig, idle_seconds: u64) -> Result<ServerConfig> {
    let mut tls = backend_server_config(tls).map_err(anyhow::Error::msg)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("cannot adapt collaboration TLS policy to QUIC")?;
    let mut server = ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(2));
    transport.max_concurrent_uni_streams(VarInt::from_u32(4));
    let idle: IdleTimeout = Duration::from_secs(idle_seconds)
        .try_into()
        .context("WebTransport idle timeout is invalid")?;
    transport.max_idle_timeout(Some(idle));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    server.transport_config(Arc::new(transport));
    Ok(server)
}

async fn handle_connection(
    connection: quinn::Connection,
    state: CollaborationServerState,
) -> Result<()> {
    let quic = h3_quinn::Connection::new(connection.clone());
    let mut h3 = h3::server::builder()
        .max_field_section_size(16 * 1024)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .enable_webtransport(true)
        .max_webtransport_sessions(1)
        .build(quic)
        .await
        .context("cannot establish HTTP/3 connection")?;
    let resolver = h3
        .accept()
        .await
        .context("cannot accept WebTransport CONNECT")?
        .ok_or_else(|| anyhow!("HTTP/3 connection closed before CONNECT"))?;
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .context("cannot resolve WebTransport CONNECT")?;
    if !valid_connect(&request, &state.public_origin) {
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(())
                    .map_err(|_| anyhow!("cannot build rejection response"))?,
            )
            .await
            .context("cannot send WebTransport rejection")?;
        bail!("CONNECT route, origin, or authentication envelope is invalid");
    }
    let session = Session::accept(request, stream, h3)
        .await
        .context("cannot accept WebTransport session")?;
    let session_id = session.session_id();
    let accepted = tokio::time::timeout(STREAM_AUTHENTICATION_TIMEOUT, session.accept_bi())
        .await
        .context("client did not open the collaboration stream")?
        .context("cannot accept collaboration stream")?
        .ok_or_else(|| anyhow!("WebTransport session closed before its collaboration stream"))?;
    let AcceptedBi::BidiStream(received_session_id, stream) = accepted else {
        bail!("only one client-created WebTransport stream is allowed");
    };
    if received_session_id != session_id {
        bail!("WebTransport stream is bound to a different session");
    }
    let mut datagrams = session.datagram_reader();
    let driver = webtransport_stream(stream, state);
    tokio::pin!(driver);
    tokio::select! {
        () = &mut driver => Ok(()),
        extra = session.accept_bi() => {
            let _ = extra;
            bail!("extra WebTransport streams are not allowed")
        }
        extra = session.accept_uni() => {
            let _ = extra;
            bail!("unidirectional WebTransport streams are not allowed")
        }
        datagram = datagrams.read_datagram() => {
            let _ = datagram;
            bail!("WebTransport datagrams are not allowed")
        }
        _ = connection.closed() => Ok(()),
    }
}

fn valid_connect(request: &Request<()>, public_origin: &str) -> bool {
    if request.method() != Method::CONNECT
        || request.extensions().get::<Protocol>() != Some(&Protocol::WEB_TRANSPORT)
        || request.uri().path() != "/collaboration/v1/wt"
        || request.uri().query().is_some()
        || request.headers().contains_key(header::AUTHORIZATION)
        || request.headers().contains_key(header::COOKIE)
    {
        return false;
    }
    let expected = Url::parse(public_origin).ok().map(|url| url.origin());
    let received = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .map(|url| url.origin());
    expected.is_some()
        && expected == received
        && request
            .headers()
            .get("sec-fetch-site")
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| matches!(value, "same-origin" | "same-site"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_admission_rejects_tokens_and_wrong_origins() {
        let mut valid = Request::builder()
            .method(Method::CONNECT)
            .uri("https://files.example/collaboration/v1/wt")
            .header(header::ORIGIN, "https://files.example")
            .body(())
            .unwrap();
        valid.extensions_mut().insert(Protocol::WEB_TRANSPORT);
        assert!(valid_connect(&valid, "https://files.example"));
        valid
            .headers_mut()
            .insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        assert!(!valid_connect(&valid, "https://files.example"));
        valid.headers_mut().remove(header::AUTHORIZATION);
        assert!(!valid_connect(&valid, "https://other.example"));
    }
}

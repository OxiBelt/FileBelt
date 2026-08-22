// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow};
use filebelt_runtime::{
    OperationsState, backend_server_config, operations_router, wait_for_shutdown,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::{RELAY_ALPN, RelayConfig};

const ROLE: &str = "filebelt-tunnel-relay";
const RELAY_BUFFER_BYTES: usize = 32 * 1024;

pub async fn serve(config: RelayConfig) -> Result<()> {
    config
        .validate()
        .map_err(|_| anyhow!("invalid relay config"))?;
    let listener = TcpListener::bind(config.listen_address)
        .await
        .context("cannot bind tunnel relay listener")?;
    let operations_listener = TcpListener::bind(config.operations_address)
        .await
        .context("cannot bind tunnel relay operations listener")?;
    let mut tls = backend_server_config(&config.server_tls)
        .map_err(|_| anyhow!("cannot configure tunnel relay mTLS"))?;
    tls.alpn_protocols = vec![RELAY_ALPN.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let targets: Arc<[std::net::SocketAddr]> = Arc::from(config.target_addresses.clone());
    let ready_targets = Arc::clone(&targets);
    let socks5_proxy = config.socks5_proxy;
    let connect_timeout = config.limits.connect_timeout();
    let readiness_permit = Arc::new(Semaphore::new(1));
    let operations = OperationsState::new(ROLE, true, move || {
        let targets = Arc::clone(&ready_targets);
        let readiness_permit = Arc::clone(&readiness_permit);
        async move {
            let Ok(_permit) = readiness_permit.try_acquire_owned() else {
                return false;
            };
            connect_target(&targets, socks5_proxy, connect_timeout)
                .await
                .is_ok()
        }
    });
    let operations_state = operations.clone();
    let mut operations_server = tokio::spawn(async move {
        axum::serve(operations_listener, operations_router(operations_state))
            .await
            .map_err(anyhow::Error::from)
    });
    let limits = Arc::new(Semaphore::new(config.limits.max_connections));
    let handshake_timeout = config.limits.handshake_timeout();
    let inactivity_timeout = config.limits.inactivity_timeout();
    info!(code = "tunnel_relay_ready");
    loop {
        tokio::select! {
            result = &mut operations_server => {
                result.context("tunnel relay operations task failed")??;
                return Ok(());
            }
            () = wait_for_shutdown() => {
                operations.begin_draining();
                break;
            }
            accepted = listener.accept() => {
                let (client, _) = accepted.context("cannot accept tunnel relay connection")?;
                let Ok(permit) = Arc::clone(&limits).try_acquire_owned() else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let targets = Arc::clone(&targets);
                tokio::spawn(async move {
                    let _permit = permit;
                    if relay_connection(
                        client,
                        acceptor,
                        &targets,
                        socks5_proxy,
                        handshake_timeout,
                        connect_timeout,
                        inactivity_timeout,
                    )
                    .await
                    .is_err()
                    {
                        warn!(code = "tunnel_relay_connection_failed");
                    }
                });
            }
        }
    }
    let drain = tokio::time::timeout(
        config.limits.drain_timeout(),
        Arc::clone(&limits).acquire_many_owned(config.limits.max_connections as u32),
    )
    .await;
    if drain.is_err() {
        warn!(code = "tunnel_relay_drain_timeout");
    }
    operations_server.abort();
    Ok(())
}

async fn relay_connection(
    client: TcpStream,
    acceptor: TlsAcceptor,
    targets: &[std::net::SocketAddr],
    socks5_proxy: Option<std::net::SocketAddr>,
    handshake_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
    inactivity_timeout: std::time::Duration,
) -> Result<()> {
    let client = tokio::time::timeout(handshake_timeout, acceptor.accept(client))
        .await
        .map_err(|_| anyhow!("relay TLS handshake timed out"))?
        .map_err(|_| anyhow!("relay TLS handshake was rejected"))?;
    if client.get_ref().1.alpn_protocol() != Some(RELAY_ALPN) {
        return Err(anyhow!("relay ALPN was not negotiated"));
    }
    let target = connect_target(targets, socks5_proxy, connect_timeout).await?;
    relay_bidirectional(client, target, inactivity_timeout).await
}

async fn connect_target(
    targets: &[std::net::SocketAddr],
    socks5_proxy: Option<std::net::SocketAddr>,
    connect_timeout: std::time::Duration,
) -> Result<TcpStream> {
    for target in targets {
        let connection = async {
            let mut stream = TcpStream::connect(socks5_proxy.unwrap_or(*target)).await?;
            if socks5_proxy.is_some() {
                socks5_handshake(&mut stream, *target).await?;
            }
            std::io::Result::Ok(stream)
        };
        if let Ok(Ok(stream)) = tokio::time::timeout(connect_timeout, connection).await {
            return Ok(stream);
        }
    }
    Err(anyhow!("configured relay target is unavailable"))
}

async fn socks5_handshake<S>(stream: &mut S, target: std::net::SocketAddr) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(std::io::Error::other("SOCKS5 authentication denied"));
    }
    let mut request = Vec::with_capacity(22);
    request.extend_from_slice(&[5, 1, 0]);
    match target.ip() {
        std::net::IpAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 5 || response[1] != 0 || response[2] != 0 {
        return Err(std::io::Error::other("SOCKS5 CONNECT denied"));
    }
    let address_bytes = match response[3] {
        1 => 4,
        4 => 16,
        _ => {
            return Err(std::io::Error::other("SOCKS5 reply address is not numeric"));
        }
    };
    let mut ignored = vec![0_u8; address_bytes + 2];
    stream.read_exact(&mut ignored).await?;
    Ok(())
}

async fn relay_bidirectional<C, T>(
    client: C,
    target: T,
    inactivity_timeout: std::time::Duration,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (target_read, target_write) = tokio::io::split(target);
    let (activity_sender, mut activity) = watch::channel(0_u64);
    let client_to_target = relay_direction(client_read, target_write, activity_sender.clone());
    let target_to_client = relay_direction(target_read, client_write, activity_sender);
    tokio::pin!(client_to_target);
    tokio::pin!(target_to_client);
    let mut client_closed = false;
    let mut target_closed = false;
    let mut activity_open = true;
    let inactivity = tokio::time::sleep(inactivity_timeout);
    tokio::pin!(inactivity);
    loop {
        tokio::select! {
            () = &mut inactivity => return Err(anyhow!("relay connection was inactive")),
            result = &mut client_to_target, if !client_closed => {
                result?;
                client_closed = true;
            }
            result = &mut target_to_client, if !target_closed => {
                result?;
                target_closed = true;
            }
            changed = activity.changed(), if activity_open => {
                if changed.is_ok() {
                    inactivity.as_mut().reset(tokio::time::Instant::now() + inactivity_timeout);
                } else {
                    activity_open = false;
                }
            }
        }
        if client_closed && target_closed {
            return Ok(());
        }
    }
}

async fn relay_direction<R, W>(
    mut reader: R,
    mut writer: W,
    activity: watch::Sender<u64>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; RELAY_BUFFER_BYTES];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buffer[..count]).await?;
        activity.send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_exact_and_does_not_offer_generic_http() {
        assert_eq!(RELAY_ALPN, b"filebelt-private-egress/1");
        assert_ne!(RELAY_ALPN, b"h2");
        assert_ne!(RELAY_ALPN, b"http/1.1");
    }

    #[tokio::test]
    async fn relay_consumes_no_destination_preamble() {
        let (mut caller, relay_caller) = tokio::io::duplex(128);
        let (relay_target, mut target) = tokio::io::duplex(128);
        let relay = tokio::spawn(relay_bidirectional(
            relay_caller,
            relay_target,
            std::time::Duration::from_secs(1),
        ));
        let first_tls_record = b"\x16\x03\x03\x00\x04test";
        caller.write_all(first_tls_record).await.unwrap();
        caller.shutdown().await.unwrap();
        let mut received = Vec::new();
        target.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, first_tls_record);
        target.shutdown().await.unwrap();
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn idle_streams_fail_closed() {
        let (caller, relay_caller) = tokio::io::duplex(8);
        let (relay_target, target) = tokio::io::duplex(8);
        assert!(
            relay_bidirectional(
                relay_caller,
                relay_target,
                std::time::Duration::from_millis(5),
            )
            .await
            .is_err()
        );
        drop((caller, target));
    }

    #[tokio::test]
    async fn socks5_connect_encodes_only_the_fixed_numeric_ipv4_target() {
        let (mut relay, mut proxy) = tokio::io::duplex(128);
        let proxy_task = tokio::spawn(async move {
            let mut greeting = [0_u8; 3];
            proxy.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            proxy.write_all(&[5, 0]).await.unwrap();
            let mut request = [0_u8; 10];
            proxy.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 1, 100, 100, 100, 100, 1, 187]);
            proxy
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });
        socks5_handshake(&mut relay, "100.100.100.100:443".parse().unwrap())
            .await
            .unwrap();
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_connect_uses_numeric_ipv6_and_rejects_domain_reply() {
        let (mut relay, mut proxy) = tokio::io::duplex(128);
        let proxy_task = tokio::spawn(async move {
            let mut greeting = [0_u8; 3];
            proxy.read_exact(&mut greeting).await.unwrap();
            proxy.write_all(&[5, 0]).await.unwrap();
            let mut request = [0_u8; 22];
            proxy.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 4]);
            assert_eq!(&request[20..], &443_u16.to_be_bytes());
            proxy.write_all(&[5, 0, 0, 3]).await.unwrap();
        });
        assert!(
            socks5_handshake(&mut relay, "[fd7a:115c:a1e0::1]:443".parse().unwrap())
                .await
                .is_err()
        );
        proxy_task.await.unwrap();
    }
}

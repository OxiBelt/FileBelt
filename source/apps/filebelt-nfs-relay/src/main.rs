// SPDX-License-Identifier: Apache-2.0

//! Opaque, bounded TCP relay for NFS traffic between the tailnet edge and Ganesha.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use clap::{Parser, Subcommand};
use filebelt_runtime::{OperationsState, operations_router, wait_for_shutdown};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tracing::{info, warn};

const ROLE: &str = "filebelt-nfs-relay";
const NFS_PORT: u16 = 2049;
const DEFAULT_MAX_CONNECTIONS: usize = 4096;
const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: usize = 64;
const DEFAULT_CONNECT_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_INACTIVITY_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_DRAIN_TIMEOUT_SECONDS: u64 = 180;
const MAX_CONNECTIONS: usize = 65_535;
const MAX_TIMEOUT_SECONDS: u64 = 86_400;
const RELAY_BUFFER_BYTES: usize = 32 * 1024;

#[derive(Debug, Parser)]
#[command(name = "filebelt-nfs-relay", disable_version_flag = true)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve(ServeArguments),
}

#[derive(Debug, clap::Args)]
struct ServeArguments {
    /// Numeric NFS listener address. The NFS relay always uses TCP port 2049.
    #[arg(long, default_value = "[::]:2049", value_parser = parse_nfs_address)]
    listen_address: SocketAddr,
    /// One numeric Ganesha backend address. The NFS relay always uses TCP port 2049.
    #[arg(long, value_parser = parse_nfs_address)]
    backend_address: SocketAddr,
    /// Numeric listener address for liveness, readiness, and Prometheus metrics.
    #[arg(long, default_value = "[::]:9090")]
    operations_address: SocketAddr,
    #[arg(
        long,
        default_value_t = DEFAULT_MAX_CONNECTIONS,
        value_parser = parse_connection_limit
    )]
    max_connections: usize,
    #[arg(
        long,
        default_value_t = DEFAULT_MAX_CONNECTIONS_PER_SOURCE,
        value_parser = parse_connection_limit
    )]
    max_connections_per_source: usize,
    #[arg(
        long,
        default_value_t = DEFAULT_CONNECT_TIMEOUT_SECONDS,
        value_parser = parse_timeout_seconds
    )]
    connect_timeout_seconds: u64,
    #[arg(
        long,
        default_value_t = DEFAULT_INACTIVITY_TIMEOUT_SECONDS,
        value_parser = parse_timeout_seconds
    )]
    inactivity_timeout_seconds: u64,
    #[arg(
        long,
        default_value_t = DEFAULT_DRAIN_TIMEOUT_SECONDS,
        value_parser = parse_timeout_seconds
    )]
    drain_timeout_seconds: u64,
}

#[derive(Clone)]
struct ConnectionLimits {
    total: Arc<Semaphore>,
    per_source: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_source: usize,
}

struct ConnectionPermit {
    _total: OwnedSemaphorePermit,
    per_source: Arc<Mutex<HashMap<IpAddr, usize>>>,
    source: IpAddr,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let per_source = Arc::clone(&self.per_source);
        let source = self.source;
        let mut active = per_source
            .lock()
            .expect("NFS relay source limit lock poisoned");
        let Some(count) = active.get_mut(&source) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            active.remove(&source);
        }
    }
}

impl ConnectionLimits {
    fn new(max_connections: usize, max_per_source: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(max_connections)),
            per_source: Arc::new(Mutex::new(HashMap::new())),
            max_per_source,
        }
    }

    fn admit(&self, source: IpAddr) -> Option<ConnectionPermit> {
        let total = self.total.clone().try_acquire_owned().ok()?;
        let mut active = self
            .per_source
            .lock()
            .expect("NFS relay source limit lock poisoned");
        let count = active.entry(source).or_default();
        if *count == self.max_per_source {
            return None;
        }
        *count += 1;
        Some(ConnectionPermit {
            _total: total,
            per_source: Arc::clone(&self.per_source),
            source,
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    if matches!(
        env::args().nth(1).as_deref(),
        Some("--version" | "--build-info=json")
    ) {
        return filebelt_deployment_diagnostics::run_probe(ROLE);
    }
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            warn!(code = "nfs_relay_stopped", %error);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let Arguments {
        command: Command::Serve(arguments),
    } = Arguments::parse();
    serve(arguments).await
}

async fn serve(arguments: ServeArguments) -> Result<()> {
    let listener = TcpListener::bind(arguments.listen_address)
        .await
        .context("cannot bind NFS relay listener")?;
    let operations_listener = TcpListener::bind(arguments.operations_address)
        .await
        .context("cannot bind NFS relay operations listener")?;
    let connect_timeout = Duration::from_secs(arguments.connect_timeout_seconds);
    let inactivity_timeout = Duration::from_secs(arguments.inactivity_timeout_seconds);
    let drain_timeout = Duration::from_secs(arguments.drain_timeout_seconds);
    let ready = Arc::new(AtomicBool::new(true));
    let ready_check = Arc::clone(&ready);
    let ready_backend = arguments.backend_address;
    let operations = OperationsState::new(ROLE, true, move || {
        let ready = Arc::clone(&ready_check);
        async move {
            ready.load(Ordering::Acquire)
                && matches!(
                    tokio::time::timeout(connect_timeout, TcpStream::connect(ready_backend)).await,
                    Ok(Ok(_))
                )
        }
    });
    let accepted = operations.register_counter(
        "nfs_relay_connections_accepted",
        "NFS relay connections accepted without inspecting their payload.",
    );
    let rejected = operations.register_counter(
        "nfs_relay_connections_rejected",
        "NFS relay connections rejected by the configured connection bounds.",
    );
    let failures = operations.register_counter(
        "nfs_relay_connection_failures",
        "NFS relay connections that terminated due to transport failure or inactivity.",
    );
    let active = operations.register_gauge(
        "nfs_relay_connections_active",
        "NFS relay connections currently holding an admission slot.",
    );
    let draining_operations = operations.clone();
    let mut operations_server = tokio::spawn(async move {
        axum::serve(operations_listener, operations_router(operations))
            .await
            .map_err(anyhow::Error::from)
    });
    let limits = ConnectionLimits::new(
        arguments.max_connections,
        arguments.max_connections_per_source,
    );
    loop {
        tokio::select! {
            operations_result = &mut operations_server => {
                operations_result.context("NFS relay operations task failed")??;
                return Ok(());
            }
            () = wait_for_shutdown() => {
                draining_operations.begin_draining();
                ready.store(false, Ordering::Release);
                break;
            }
            accepted_connection = listener.accept() => {
                let (client, peer) = accepted_connection.context("cannot accept NFS relay connection")?;
                let Some(permit) = limits.admit(peer.ip()) else {
                    rejected.inc();
                    continue;
                };
                accepted.inc();
                active.inc();
                let backend = arguments.backend_address;
                let active = active.clone();
                let failures = failures.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let result = relay_connection(client, backend, connect_timeout, inactivity_timeout).await;
                    active.dec();
                    if result.is_err() {
                        failures.inc();
                    }
                });
            }
        }
    }

    info!(code = "nfs_relay_draining");
    let drained = tokio::time::timeout(
        drain_timeout,
        limits
            .total
            .clone()
            .acquire_many_owned(arguments.max_connections as u32),
    )
    .await;
    if drained.is_err() {
        warn!(code = "nfs_relay_drain_timeout");
    }
    Ok(())
}

async fn relay_connection(
    client: TcpStream,
    backend_address: SocketAddr,
    connect_timeout: Duration,
    inactivity_timeout: Duration,
) -> Result<()> {
    let backend = tokio::time::timeout(connect_timeout, TcpStream::connect(backend_address))
        .await
        .map_err(|_| anyhow!("NFS relay backend connection timed out"))?
        .context("cannot connect NFS relay backend")?;
    relay_bidirectional(client, backend, inactivity_timeout).await
}

async fn relay_bidirectional<C, B>(
    client: C,
    backend: B,
    inactivity_timeout: Duration,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (backend_read, backend_write) = tokio::io::split(backend);
    let (activity_sender, mut activity) = watch::channel(0_u64);
    let client_to_backend = relay_direction(client_read, backend_write, activity_sender.clone());
    let backend_to_client = relay_direction(backend_read, client_write, activity_sender);
    tokio::pin!(client_to_backend);
    tokio::pin!(backend_to_client);
    let mut client_closed = false;
    let mut backend_closed = false;
    let mut activity_open = true;
    let inactivity = tokio::time::sleep(inactivity_timeout);
    tokio::pin!(inactivity);
    loop {
        tokio::select! {
            () = &mut inactivity => {
                return Err(anyhow!("NFS relay connection was inactive"));
            }
            result = &mut client_to_backend, if !client_closed => {
                result?;
                client_closed = true;
            }
            result = &mut backend_to_client, if !backend_closed => {
                result?;
                backend_closed = true;
            }
            changed = activity.changed(), if activity_open => {
                if changed.is_ok() {
                    inactivity.as_mut().reset(tokio::time::Instant::now() + inactivity_timeout);
                } else {
                    activity_open = false;
                }
            }
        }
        if client_closed && backend_closed {
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
        let count = reader
            .read(&mut buffer)
            .await
            .context("NFS relay transport read failure")?;
        if count == 0 {
            writer
                .shutdown()
                .await
                .context("cannot half-close NFS relay connection")?;
            return Ok(());
        }
        writer
            .write_all(&buffer[..count])
            .await
            .context("NFS relay transport write failure")?;
        activity.send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

fn parse_nfs_address(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "must be a numeric IP address with port 2049".to_owned())?;
    if address.port() != NFS_PORT {
        return Err("must use TCP port 2049".into());
    }
    Ok(address)
}

fn parse_connection_limit(value: &str) -> Result<usize, String> {
    let limit: usize = value
        .parse()
        .map_err(|_| "must be a whole number".to_owned())?;
    if !(1..=MAX_CONNECTIONS).contains(&limit) {
        return Err(format!("must be between 1 and {MAX_CONNECTIONS}"));
    }
    Ok(limit)
}

fn parse_timeout_seconds(value: &str) -> Result<u64, String> {
    let seconds: u64 = value
        .parse()
        .map_err(|_| "must be a whole number of seconds".to_owned())?;
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&seconds) {
        return Err(format!(
            "must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"
        ));
    }
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use clap::Parser as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[test]
    fn nfs_addresses_require_numeric_port_2049() {
        assert_eq!(
            parse_nfs_address("192.0.2.17:2049").unwrap(),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 17), 2049))
        );
        assert!(parse_nfs_address("ganesha.example:2049").is_err());
        assert!(parse_nfs_address("192.0.2.17:111").is_err());
    }

    #[test]
    fn command_defaults_and_limits_are_bounded() {
        let arguments = Arguments::try_parse_from([
            "filebelt-nfs-relay",
            "serve",
            "--backend-address",
            "192.0.2.17:2049",
        ])
        .unwrap();
        let Command::Serve(serve) = arguments.command;
        assert_eq!(serve.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(
            serve.max_connections_per_source,
            DEFAULT_MAX_CONNECTIONS_PER_SOURCE
        );
        assert_eq!(
            serve.connect_timeout_seconds,
            DEFAULT_CONNECT_TIMEOUT_SECONDS
        );
        assert_eq!(
            serve.inactivity_timeout_seconds,
            DEFAULT_INACTIVITY_TIMEOUT_SECONDS
        );
        assert_eq!(serve.drain_timeout_seconds, DEFAULT_DRAIN_TIMEOUT_SECONDS);
        assert!(
            Arguments::try_parse_from([
                "filebelt-nfs-relay",
                "serve",
                "--backend-address",
                "192.0.2.17:2049",
                "--max-connections",
                "0",
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn limits_release_the_source_slot_after_connection_drop() {
        let limits = ConnectionLimits::new(2, 1);
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17));
        let permit = limits.admit(source).expect("first connection admitted");
        assert!(limits.admit(source).is_none());
        drop(permit);
        assert!(limits.admit(source).is_some());
    }

    #[tokio::test]
    async fn relay_preserves_half_close_and_bytes_in_both_directions() {
        let (mut client, relay_client) = tokio::io::duplex(128);
        let (relay_backend, mut backend) = tokio::io::duplex(128);
        let relay = tokio::spawn(relay_bidirectional(
            relay_client,
            relay_backend,
            Duration::from_secs(1),
        ));

        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        backend.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        backend.write_all(b"response").await.unwrap();
        backend.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn idle_directions_fail_closed() {
        let (client, relay_client) = tokio::io::duplex(128);
        let (relay_backend, backend) = tokio::io::duplex(128);
        let result =
            relay_bidirectional(relay_client, relay_backend, Duration::from_millis(10)).await;
        drop((client, backend));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn traffic_in_one_direction_keeps_the_connection_active() {
        let (client, relay_client) = tokio::io::duplex(128);
        let (relay_backend, mut backend) = tokio::io::duplex(128);
        let relay = tokio::spawn(relay_bidirectional(
            relay_client,
            relay_backend,
            Duration::from_millis(30),
        ));

        for _ in 0..4 {
            backend.write_all(b"response").await.unwrap();
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        backend.shutdown().await.unwrap();
        drop(client);
        relay.await.unwrap().unwrap();
    }
}

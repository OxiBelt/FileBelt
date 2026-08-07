// SPDX-License-Identifier: Apache-2.0

//! Trusted relay and fixed-command stdio shim for one-shot MCP runner Pods.

#![deny(unsafe_code)]

use std::env;
use std::fs::FileType;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::time::Duration;

use clap::{Args as ClapArgs, Parser, Subcommand};
use filebelt_mcp_protocol::{
    MAX_RUNNER_RELAY_MESSAGE_BYTES, MAX_RUNNER_RELAY_PAYLOAD_BYTES, RUNNER_RELAY_PROTOCOL_VERSION,
    RunnerRelayFrame, RunnerRelayFrameKind, RunnerRelayHello, decode_runner_relay_frame,
    encode_runner_hello, encode_runner_relay_frame,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::process::Command;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{info, warn};
use zeroize::{Zeroize as _, Zeroizing};

const ROLE: &str = "filebelt-mcp-runner";
const INSTALL_DESTINATION: &str = "/filebelt/bin/filebelt-mcp-runner";
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_STDERR_BYTES: usize = 4096;
const MAX_RELAY_STREAM_BYTES: u64 = 67_108_864;
const MAX_ENDPOINT_ADDRESSES: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(disable_version_flag = true)]
struct Arguments {
    #[command(subcommand)]
    command: RunnerCommand,
}

#[derive(Debug, Subcommand)]
enum RunnerCommand {
    Install {
        #[arg(long)]
        destination: PathBuf,
    },
    Relay {
        #[command(flatten)]
        options: Box<RelayOptions>,
    },
    Child {
        #[arg(long)]
        socket: PathBuf,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, ClapArgs)]
struct RelayOptions {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    invocation_id: String,
    #[arg(long, required = true)]
    broker_address: Vec<String>,
    #[arg(long)]
    broker_server_name: String,
    #[arg(long)]
    broker_ca: PathBuf,
    #[arg(long)]
    broker_certificate: PathBuf,
    #[arg(long)]
    broker_private_key: PathBuf,
    #[arg(long, required = true)]
    gateway_address: Vec<String>,
    #[arg(long)]
    gateway_server_name: String,
    #[arg(long)]
    gateway_ca: PathBuf,
    #[arg(long)]
    gateway_certificate: PathBuf,
    #[arg(long)]
    gateway_private_key: PathBuf,
    #[arg(long)]
    bootstrap_token_file: PathBuf,
}

struct TlsClientFiles<'a> {
    ca: &'a Path,
    certificate: &'a Path,
    private_key: &'a Path,
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
    let result = match Arguments::parse().command {
        RunnerCommand::Install { destination } => install(&destination).await,
        RunnerCommand::Relay { options } => relay(*options).await,
        RunnerCommand::Child { socket, command } => child(&socket, &command).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{ROLE}: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn install(destination: &Path) -> Result<(), String> {
    if destination != Path::new(INSTALL_DESTINATION) {
        return Err("runner install destination is not allowlisted".into());
    }
    let source = env::current_exe().map_err(|error| format!("cannot locate runner: {error}"))?;
    tokio::fs::copy(&source, destination)
        .await
        .map_err(|error| format!("cannot install runner shim: {error}"))?;
    tokio::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o555))
        .await
        .map_err(|error| format!("cannot set runner shim permissions: {error}"))?;
    Ok(())
}

async fn relay(options: RelayOptions) -> Result<(), String> {
    ensure_runtime_socket_path(&options.socket)?;
    remove_stale_socket(&options.socket).await?;
    let listener = UnixListener::bind(&options.socket)
        .map_err(|error| format!("cannot bind runner stdio socket: {error}"))?;
    tokio::fs::set_permissions(&options.socket, std::fs::Permissions::from_mode(0o660))
        .await
        .map_err(|error| format!("cannot set runner socket permissions: {error}"))?;
    let broker_connector = tls_connector(&TlsClientFiles {
        ca: &options.broker_ca,
        certificate: &options.broker_certificate,
        private_key: &options.broker_private_key,
    })?;
    let gateway_connector = tls_connector(&TlsClientFiles {
        ca: &options.gateway_ca,
        certificate: &options.gateway_certificate,
        private_key: &options.gateway_private_key,
    })?;
    let gateway_addresses = Arc::new(numeric_addresses(&options.gateway_address, "gateway")?);
    let gateway_server_name = server_name(&options.gateway_server_name)?;
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:7777")
        .await
        .map_err(|error| format!("cannot bind runner gateway proxy: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = proxy_loop(
            proxy_listener,
            gateway_addresses,
            gateway_server_name,
            gateway_connector,
        )
        .await
        {
            warn!(code = "runner_gateway_proxy_failed", %error);
        }
    });

    let token_metadata = tokio::fs::metadata(&options.bootstrap_token_file)
        .await
        .map_err(|error| format!("cannot inspect bootstrap token: {error}"))?;
    if token_metadata.len() < 32 || token_metadata.len() > MAX_TOKEN_BYTES as u64 {
        return Err("bootstrap token size is outside the allowed range".into());
    }
    let mut token = Zeroizing::new(
        tokio::fs::read(&options.bootstrap_token_file)
            .await
            .map_err(|error| format!("cannot read bootstrap token: {error}"))?,
    );
    let broker_addresses = numeric_addresses(&options.broker_address, "broker")?;
    let broker_server_name = server_name(&options.broker_server_name)?;
    let mut broker =
        connect_tls_any(&broker_addresses, broker_server_name, broker_connector).await?;
    let mut hello = RunnerRelayHello {
        protocol_version: RUNNER_RELAY_PROTOCOL_VERSION.into(),
        invocation_id: options.invocation_id.clone(),
        bootstrap_token: std::mem::take(token.as_mut()),
    };
    let hello_wire = Zeroizing::new(
        encode_runner_hello(&hello).map_err(|error| format!("invalid runner hello: {error}"))?,
    );
    hello.bootstrap_token.zeroize();
    write_wire_message(&mut broker, &hello_wire).await?;
    let (mut local, _) = tokio::time::timeout(Duration::from_secs(15), listener.accept())
        .await
        .map_err(|_| "runner child did not connect within 15 seconds")?
        .map_err(|error| format!("cannot accept runner child: {error}"))?;
    info!("runner child connected to authenticated broker relay");
    relay_framed(&mut local, &mut broker, &options.invocation_id).await
}

async fn relay_framed<L, B>(
    local: &mut L,
    broker: &mut B,
    invocation_id: &str,
) -> Result<(), String>
where
    L: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let (mut broker_read, mut broker_write) = tokio::io::split(broker);
    let outbound_invocation = invocation_id.to_owned();
    let inbound_invocation = invocation_id.to_owned();
    let to_broker = async move {
        let mut sequence = 1_u64;
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; MAX_RUNNER_RELAY_PAYLOAD_BYTES];
        loop {
            let count = local_read
                .read(&mut buffer)
                .await
                .map_err(|error| format!("cannot read runner stdio: {error}"))?;
            let (kind, payload, terminal) = if count == 0 {
                (RunnerRelayFrameKind::Close, Vec::new(), true)
            } else {
                total = total
                    .checked_add(count as u64)
                    .filter(|total| *total <= MAX_RELAY_STREAM_BYTES)
                    .ok_or("runner output exceeded the relay byte limit")?;
                (RunnerRelayFrameKind::Data, buffer[..count].to_vec(), false)
            };
            let frame = RunnerRelayFrame {
                invocation_id: outbound_invocation.clone(),
                sequence,
                kind: kind as i32,
                payload,
                code: String::new(),
                terminal,
            };
            let wire = encode_runner_relay_frame(&frame)
                .map_err(|error| format!("cannot encode runner relay frame: {error}"))?;
            write_wire_message(&mut broker_write, &wire).await?;
            if terminal {
                return Ok(());
            }
            sequence = sequence
                .checked_add(1)
                .ok_or("runner relay sequence exhausted")?;
        }
    };
    let from_broker = async move {
        let mut expected_sequence = 1_u64;
        let mut total = 0_u64;
        loop {
            let wire = read_wire_message(&mut broker_read).await?;
            let frame = decode_runner_relay_frame(&wire)
                .map_err(|error| format!("invalid broker relay frame: {error}"))?;
            if frame.invocation_id != inbound_invocation || frame.sequence != expected_sequence {
                return Err("broker relay frame identity or sequence is invalid".into());
            }
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or("broker relay sequence exhausted")?;
            match RunnerRelayFrameKind::try_from(frame.kind) {
                Ok(RunnerRelayFrameKind::Data) => {
                    total = total
                        .checked_add(frame.payload.len() as u64)
                        .filter(|total| *total <= MAX_RELAY_STREAM_BYTES)
                        .ok_or("broker input exceeded the relay byte limit")?;
                    local_write
                        .write_all(&frame.payload)
                        .await
                        .map_err(|error| format!("cannot write runner stdio: {error}"))?;
                }
                Ok(RunnerRelayFrameKind::Close) => {
                    local_write
                        .shutdown()
                        .await
                        .map_err(|error| format!("cannot close runner stdio: {error}"))?;
                    return Ok(());
                }
                Ok(RunnerRelayFrameKind::Error) => {
                    return Err(format!("broker terminated runner relay: {}", frame.code));
                }
                Ok(RunnerRelayFrameKind::Unspecified) | Err(_) => {
                    return Err("broker relay frame kind is invalid".into());
                }
            }
        }
    };
    tokio::select! {
        result = to_broker => result,
        result = from_broker => result,
    }
}

async fn write_wire_message<W>(writer: &mut W, message: &[u8]) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    if message.is_empty() || message.len() > MAX_RUNNER_RELAY_MESSAGE_BYTES {
        return Err("runner relay message size is outside its allowed range".into());
    }
    writer
        .write_u32(message.len() as u32)
        .await
        .map_err(|error| format!("cannot write runner relay frame length: {error}"))?;
    writer
        .write_all(message)
        .await
        .map_err(|error| format!("cannot write runner relay frame: {error}"))?;
    writer
        .flush()
        .await
        .map_err(|error| format!("cannot flush runner relay frame: {error}"))
}

async fn read_wire_message<R>(reader: &mut R) -> Result<Vec<u8>, String>
where
    R: AsyncRead + Unpin,
{
    let length = reader
        .read_u32()
        .await
        .map_err(|error| format!("cannot read runner relay frame length: {error}"))?
        as usize;
    if length == 0 || length > MAX_RUNNER_RELAY_MESSAGE_BYTES {
        return Err("broker relay message size is outside its allowed range".into());
    }
    let mut message = vec![0_u8; length];
    reader
        .read_exact(&mut message)
        .await
        .map_err(|error| format!("cannot read runner relay frame: {error}"))?;
    Ok(message)
}

async fn child(socket_path: &Path, command: &[String]) -> Result<(), String> {
    ensure_runtime_socket_path(socket_path)?;
    let executable = command.first().ok_or("runner child command is empty")?;
    if !Path::new(executable).is_absolute()
        || command.len() > 34
        || command
            .iter()
            .any(|argument| argument.len() > 4096 || argument.contains('\0'))
    {
        return Err("runner child command is outside the catalog envelope".into());
    }
    let socket = tokio::time::timeout(Duration::from_secs(15), UnixStream::connect(socket_path))
        .await
        .map_err(|_| "runner relay socket was unavailable for 15 seconds")?
        .map_err(|error| format!("cannot connect to runner relay: {error}"))?;
    let mut process = Command::new(executable);
    process
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_remove("FILEBELT_MCP_BOOTSTRAP_TOKEN")
        .env_remove("KUBERNETES_SERVICE_HOST")
        .env_remove("KUBERNETES_SERVICE_PORT");
    let mut child = process
        .spawn()
        .map_err(|error| format!("cannot spawn catalog command: {error}"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or("catalog command stdin is unavailable")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("catalog command stdout is unavailable")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("catalog command stderr is unavailable")?;
    tokio::spawn(drain_stderr(stderr));
    let (socket_read, socket_write) = socket.into_split();
    let to_child = bounded_copy(socket_read, stdin);
    let from_child = bounded_copy(stdout, socket_write);
    tokio::pin!(to_child);
    tokio::pin!(from_child);
    let completed = tokio::select! {
        result = &mut to_child => result.map(|_| false),
        result = &mut from_child => result.map(|_| false),
        status = child.wait() => status
            .map(|status| status.success())
            .map_err(|error| format!("cannot wait for catalog command: {error}")),
    }?;
    if !completed {
        child
            .start_kill()
            .map_err(|error| format!("cannot terminate catalog command: {error}"))?;
        let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
        return Err("catalog command ended before the relay completed".into());
    }
    Ok(())
}

async fn bounded_copy<R, W>(mut reader: R, mut writer: W) -> Result<u64, String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(&mut reader, &mut writer)
        .await
        .map_err(|error| format!("runner stdio forwarding failed: {error}"))
}

async fn drain_stderr<R>(mut stderr: R)
where
    R: AsyncRead + Unpin,
{
    let mut read = 0_usize;
    let mut buffer = [0_u8; 1024];
    loop {
        match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => {
                read = read.saturating_add(count);
                if read > MAX_STDERR_BYTES {
                    // Continue draining to avoid blocking the child, but never log or persist it.
                    read = MAX_STDERR_BYTES;
                }
                buffer.fill(0);
            }
        }
    }
}

async fn proxy_loop(
    listener: tokio::net::TcpListener,
    gateway_addresses: Arc<Vec<SocketAddr>>,
    gateway_server_name: ServerName<'static>,
    connector: TlsConnector,
) -> Result<(), String> {
    loop {
        let (mut local, _) = listener
            .accept()
            .await
            .map_err(|error| format!("cannot accept runner proxy connection: {error}"))?;
        let connector = connector.clone();
        let server_name = gateway_server_name.clone();
        let gateway_addresses = Arc::clone(&gateway_addresses);
        tokio::spawn(async move {
            match connect_tls_any(&gateway_addresses, server_name, connector).await {
                Ok(mut upstream) => {
                    let _ = tokio::io::copy_bidirectional(&mut local, &mut upstream).await;
                }
                Err(error) => warn!(code = "runner_gateway_connect_failed", %error),
            }
        });
    }
}

fn tls_connector(files: &TlsClientFiles<'_>) -> Result<TlsConnector, String> {
    let mut roots = RootCertStore::empty();
    let root_certificates = CertificateDer::pem_file_iter(files.ca)
        .map_err(|error| format!("cannot read TLS CA: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("TLS CA is invalid PEM: {error}"))?;
    if root_certificates.is_empty() {
        return Err("TLS CA is empty".into());
    }
    for certificate in root_certificates {
        roots
            .add(certificate)
            .map_err(|error| format!("TLS CA certificate is invalid: {error}"))?;
    }
    let certificates = CertificateDer::pem_file_iter(files.certificate)
        .map_err(|error| format!("cannot read TLS client certificate: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("TLS client certificate is invalid PEM: {error}"))?;
    if certificates.is_empty() {
        return Err("TLS client certificate chain is empty".into());
    }
    let private_key = PrivateKeyDer::from_pem_file(files.private_key)
        .map_err(|error| format!("TLS client private key is invalid PEM: {error}"))?;
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| format!("cannot select TLS protocol versions: {error}"))?
    .with_root_certificates(roots)
    .with_client_auth_cert(certificates, private_key)
    .map_err(|error| format!("cannot configure TLS client identity: {error}"))?;
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn connect_tls(
    address: SocketAddr,
    server_name: ServerName<'static>,
    connector: TlsConnector,
) -> Result<TlsStream<TcpStream>, String> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| "TLS connection timed out")?
        .map_err(|error| format!("cannot connect TLS socket: {error}"))?;
    tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "TLS handshake timed out")?
        .map_err(|error| format!("TLS handshake failed: {error}"))
}

async fn connect_tls_any(
    addresses: &[SocketAddr],
    server_name: ServerName<'static>,
    connector: TlsConnector,
) -> Result<TlsStream<TcpStream>, String> {
    let mut last_error = None;
    for address in addresses {
        match connect_tls(*address, server_name.clone(), connector.clone()).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| "TLS endpoint address list is empty".into()))
}

fn server_name(value: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(value.to_owned()).map_err(|_| "TLS server name is invalid".into())
}

fn numeric_addresses(values: &[String], role: &str) -> Result<Vec<SocketAddr>, String> {
    if values.is_empty() || values.len() > MAX_ENDPOINT_ADDRESSES {
        return Err(format!("{role} address count is outside the allowed range"));
    }
    let mut addresses = values
        .iter()
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|_| format!("{role} address must be a numeric socket address"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}

fn ensure_runtime_socket_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some("stdio.sock")
        || path.parent() != Some(Path::new("/run/filebelt-mcp"))
    {
        return Err("runner socket path is not allowlisted".into());
    }
    Ok(())
}

async fn remove_stale_socket(path: &Path) -> Result<(), String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if is_socket(metadata.file_type()) => tokio::fs::remove_file(path)
            .await
            .map_err(|error| format!("cannot remove stale runner socket: {error}")),
        Ok(_) => Err("runner socket path is occupied by a non-socket".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect runner socket path: {error}")),
    }
}

fn is_socket(file_type: FileType) -> bool {
    file_type.is_socket()
}

#[cfg(test)]
mod tests {
    use super::{ensure_runtime_socket_path, numeric_addresses, server_name};
    use std::path::Path;

    #[test]
    fn runtime_socket_is_fixed() {
        assert!(ensure_runtime_socket_path(Path::new("/run/filebelt-mcp/stdio.sock")).is_ok());
        assert!(ensure_runtime_socket_path(Path::new("/tmp/stdio.sock")).is_err());
        assert!(ensure_runtime_socket_path(Path::new("/run/filebelt-mcp/../token")).is_err());
    }

    #[test]
    fn tls_server_name_rejects_addresses() {
        assert!(server_name("filebelt-mcp-broker").is_ok());
        assert!(server_name("").is_err());
    }

    #[test]
    fn relay_endpoints_are_bounded_numeric_socket_addresses() {
        let addresses = numeric_addresses(
            &[
                "10.96.0.21:8084".into(),
                "[fd00::21]:8084".into(),
                "10.96.0.21:8084".into(),
            ],
            "broker",
        )
        .expect("numeric addresses");
        assert_eq!(addresses.len(), 2);
        assert!(numeric_addresses(&["filebelt-mcp-broker:8084".into()], "broker").is_err());
        assert!(numeric_addresses(&[], "broker").is_err());
        assert!(numeric_addresses(&vec!["127.0.0.1:1".into(); 17], "broker").is_err());
    }
}

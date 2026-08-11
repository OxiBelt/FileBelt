// SPDX-License-Identifier: Apache-2.0

//! Fail-closed outbound Model Context Protocol mediation.

#![deny(unsafe_code)]

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::{Parser, Subcommand};
use filebelt_capability_keyset::ApiMcpDelegationKeyset;
use filebelt_control_protocol::{
    Config, DeploymentMode, McpLimitConfig, McpTrustProfile, read_secret_string,
};
use filebelt_database::mcp::{
    McpAuthoritySnapshot, McpRegistrationRecord, McpSecretEnvelope, NewMcpOAuthAttempt,
    NewMcpRunnerSlotReservation, RegistrationConfigurationUpdate,
};
use filebelt_database::{Database, DatabaseError};
use filebelt_mcp_protocol::{
    AttachmentClaim, AttachmentDisclosure, AttachmentEncoding, AttachmentFieldClaim,
    CreateRunnerLeaseRequest, CreateRunnerLeaseResponse, DeleteRunnerLeaseRequest,
    DeleteRunnerLeaseResponse, InvocationFrame, InvocationFrameKind, InvocationRequest,
    MAX_RUNNER_RELAY_MESSAGE_BYTES, MAX_RUNNER_RELAY_PAYLOAD_BYTES, McpOperation, McpPrimitive,
    RunnerRelayFrame, RunnerRelayFrameKind, decode_runner_hello, decode_runner_relay_frame,
    encode_frame, encode_runner_relay_frame, verify_mcp_delegation,
};
use filebelt_mcp_vault::{Keyring, SecretContext, SecretEnvelope};
use filebelt_runtime::{
    MtlsListener, OperationsState, init_telemetry, install_crypto_provider, observe_request,
    operations_router, trace_request, wait_for_shutdown,
};
use prost::Message as _;
use reqwest::{Certificate, Client, Identity};
use rmcp::model::{CallToolResult, InitializeResult};
use serde_json::{Value, json};
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const ARGUMENT_DIGEST_DOMAIN: &[u8] = b"filebelt.mcp.arguments.v1\0";
const CURRENT_PROTOCOL: &str = "2026-07-28";
const FALLBACK_PROTOCOL: &str = "2025-11-25";
const INTERNAL_CONTENT_TYPE: &str = "application/vnd.filebelt.mcp.v1+protobuf";
const PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";
const CONTROLLER_RESPONSE_MAX_BYTES: usize = 16_384;
const MAX_STDIO_MESSAGES_PER_REQUEST: usize = 128;
const MAX_SEMANTIC_MARKDOWN_BYTES: usize = 2 * 1_024 * 1_024;

#[derive(Debug, Parser)]
#[command(name = "filebelt-mcp-broker", disable_version_flag = true)]
struct Arguments {
    #[arg(long, global = true, default_value = "/etc/filebelt/filebelt.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum Command {
    Serve,
}

#[derive(Clone)]
struct BrokerState {
    database: Database,
    keyring: Arc<Keyring>,
    verification_keys: Arc<ApiMcpDelegationKeyset>,
    gateway: Client,
    gateway_url: Url,
    attachment_client: Client,
    attachment_io_url: Url,
    limits: McpLimitConfig,
    concurrency: Arc<ConcurrencyLimits>,
    runners: Option<Arc<RunnerBrokerState>>,
    oauth_clients: Arc<HashMap<String, OauthClientState>>,
    current_kek_generation: u32,
    trust_profiles: Arc<BTreeMap<String, McpTrustProfile>>,
}

struct OauthClientState {
    client_id: String,
    client_secret: Option<Zeroizing<String>>,
}

trait RelayIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> RelayIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}
type RelayStream = Box<dyn RelayIo>;

struct PendingRunner {
    bootstrap_digest: [u8; 32],
    sender: oneshot::Sender<RelayStream>,
}

struct RunnerBrokerState {
    admission: Option<RunnerAdmission>,
    controller: Client,
    create_url: Url,
    delete_url: Url,
    pending: Mutex<HashMap<Uuid, PendingRunner>>,
    lifecycles: Mutex<HashMap<Uuid, Arc<RunnerLifecycle>>>,
    relay_accepts: Arc<Semaphore>,
    hello_timeout: Duration,
}

struct RunnerAdmission {
    database: Database,
    tenant_limit: i64,
    principal_limit: i64,
    reservation_seconds: i64,
}

struct RunnerLifecycle {
    tenant_id: Uuid,
    principal_id: Uuid,
    cancelled: AtomicBool,
    cleanup_complete: AtomicBool,
    reserved: AtomicBool,
    mutation: Mutex<()>,
}

struct RunnerCleanupGuard {
    runners: Arc<RunnerBrokerState>,
    lifecycle: Arc<RunnerLifecycle>,
    invocation_id: Uuid,
    armed: bool,
}

struct RunnerInvocationGuard {
    runners: Arc<RunnerBrokerState>,
    invocation_id: Uuid,
    lifecycle: Arc<RunnerLifecycle>,
}

struct ConcurrencyLimits {
    global: Arc<Semaphore>,
    queue: Arc<Semaphore>,
    principals: Mutex<HashMap<Uuid, Weak<Semaphore>>>,
    registrations: Mutex<HashMap<Uuid, Weak<Semaphore>>>,
    principal_limit: usize,
    registration_limit: usize,
}

struct InvocationPermits {
    _global: OwnedSemaphorePermit,
    _principal: OwnedSemaphorePermit,
    _registration: OwnedSemaphorePermit,
}

struct DecryptedCredential {
    kind: String,
    secret: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
struct BrokerError {
    status: StatusCode,
    code: &'static str,
}

fn main() -> ExitCode {
    let raw = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(raw.as_slice(), [argument] if argument == "--version" || argument == "--build-info=json")
    {
        return filebelt_deployment_diagnostics::run_probe("filebelt-mcp-broker");
    }
    let arguments = Arguments::parse();
    let _command = arguments.command.unwrap_or(Command::Serve);
    let config = match Config::load(&arguments.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("filebelt-mcp-broker: invalid configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = install_crypto_provider() {
        eprintln!("filebelt-mcp-broker: {error}");
        return ExitCode::FAILURE;
    }
    let _telemetry = match init_telemetry(&config.telemetry, "filebelt-mcp-broker") {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("filebelt-mcp-broker: {error}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("filebelt-mcp-broker: cannot initialize runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "MCP broker stopped");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<()> {
    if !config.mcp.enabled {
        bail!("MCP is not enabled in configuration");
    }
    let database_path = config
        .mcp
        .database_url_file
        .as_ref()
        .ok_or_else(|| anyhow!("MCP database URL is absent"))?;
    let database_url = read_secret_string(database_path).context("cannot read MCP database URL")?;
    let database = Database::connect(&database_url, config.database.max_connections)
        .await
        .context("cannot connect to MCP PostgreSQL role")?;
    database
        .health()
        .await
        .context("PostgreSQL is unavailable")?;
    let keyring_path = config
        .mcp
        .vault
        .keyring_file
        .as_ref()
        .ok_or_else(|| anyhow!("MCP keyring path is absent"))?;
    let keyring = Arc::new(Keyring::load(keyring_path).context("cannot load MCP keyring")?);
    let delegation = config
        .keys
        .api_mcp_delegation
        .as_ref()
        .ok_or_else(|| anyhow!("API MCP delegation signing is absent"))?;
    let verification_keys = Arc::new(load_verification_keys(&delegation.public_keyset_file)?);
    let gateway = gateway_client(&config)?;
    let (attachment_client, attachment_io_url) = attachment_client(&config)?;
    let gateway_url = config
        .mcp
        .egress
        .gateway_url
        .clone()
        .ok_or_else(|| anyhow!("MCP gateway URL is absent"))?;
    let limits = config.mcp.limits.clone();
    let oauth_clients = Arc::new(load_oauth_clients(&config)?);
    let runners = if config.mcp.runners.enabled {
        Some(Arc::new(runner_broker_state(&config, database.clone())?))
    } else {
        None
    };
    let concurrency = Arc::new(ConcurrencyLimits {
        global: Arc::new(Semaphore::new(limits.replica_concurrency as usize)),
        queue: Arc::new(Semaphore::new(limits.queue_depth as usize)),
        principals: Mutex::new(HashMap::new()),
        registrations: Mutex::new(HashMap::new()),
        principal_limit: limits.principal_concurrency as usize,
        registration_limit: limits.registration_concurrency as usize,
    });
    let state = BrokerState {
        database: database.clone(),
        keyring,
        verification_keys,
        gateway,
        gateway_url,
        attachment_client,
        attachment_io_url,
        limits,
        concurrency,
        runners: runners.clone(),
        oauth_clients,
        current_kek_generation: config.mcp.vault.current_generation,
        trust_profiles: Arc::new(config.mcp.trust_profiles.clone()),
    };
    let operations = OperationsState::new(
        "filebelt-mcp-broker",
        config.telemetry.prometheus_enabled,
        move || {
            let database = database.clone();
            async move { database.health().await.is_ok() }
        },
    );
    let app = Router::new()
        .route("/internal/v1/mcp/invocations", routing::post(invoke))
        .layer(axum::extract::DefaultBodyLimit::max(
            config.mcp.limits.message_bytes as usize,
        ))
        .layer(axum::middleware::from_fn(trace_request))
        .layer(axum::middleware::from_fn_with_state(
            operations.clone(),
            observe_request,
        ))
        .with_state(state);
    let operation_listener = tokio::net::TcpListener::bind(config.listeners.operations)
        .await
        .context("cannot bind operations listener")?;
    let (operations_stop, operations_stopped) = tokio::sync::oneshot::channel();
    let operation_server = tokio::spawn(async move {
        axum::serve(operation_listener, operations_router(operations))
            .with_graceful_shutdown(async move {
                let _ = operations_stopped.await;
            })
            .await
            .map_err(|error| error.to_string())
    });
    let listener_address = config.listeners.mcp_broker;
    let runner_reconciler = runners.as_ref().map(|runners| {
        let runners = runners.clone();
        tokio::spawn(async move { runner_reconciliation_loop(runners).await })
    });
    let relay_server = if let Some(runners) = runners {
        let relay_address = config.listeners.mcp_runner_relay;
        let handle = match config.deployment.mode {
            DeploymentMode::Development => {
                let listener = tokio::net::TcpListener::bind(relay_address).await?;
                tokio::spawn(runner_relay_tcp_loop(listener, runners))
            }
            DeploymentMode::Kubernetes => {
                let tls = config
                    .backend_tls
                    .as_ref()
                    .and_then(|tls| tls.mcp_broker.as_ref())
                    .ok_or_else(|| anyhow!("MCP runner relay backend TLS is absent"))?;
                let listener = MtlsListener::bind(relay_address, tls)
                    .await
                    .map_err(anyhow::Error::msg)?;
                tokio::spawn(runner_relay_mtls_loop(listener, runners))
            }
        };
        tracing::info!(address = %relay_address, "MCP runner relay is ready");
        Some(handle)
    } else {
        None
    };
    let (application_stop, application_stopped) = tokio::sync::oneshot::channel();
    let mut server = match config.deployment.mode {
        DeploymentMode::Development => {
            let listener = tokio::net::TcpListener::bind(listener_address).await?;
            tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(|error| error.to_string())
            })
        }
        DeploymentMode::Kubernetes => {
            let tls = config
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.mcp_broker.as_ref())
                .ok_or_else(|| anyhow!("MCP broker backend TLS is absent"))?;
            let listener = MtlsListener::bind(listener_address, tls)
                .await
                .map_err(anyhow::Error::msg)?;
            tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(|error| error.to_string())
            })
        }
    };
    tracing::info!(address = %listener_address, "MCP broker is ready");
    tokio::select! {
        result = &mut server => result.context("MCP broker task failed")?.map_err(anyhow::Error::msg)?,
        () = wait_for_shutdown() => {
            let _ = application_stop.send(());
            if tokio::time::timeout(Duration::from_secs(45), &mut server).await.is_err() {
                server.abort();
            }
        }
    }
    let _ = operations_stop.send(());
    if let Some(relay_server) = relay_server {
        relay_server.abort();
    }
    if let Some(runner_reconciler) = runner_reconciler {
        runner_reconciler.abort();
    }
    operation_server
        .await
        .context("operations task failed")?
        .map_err(anyhow::Error::msg)?;
    Ok(())
}

fn runner_broker_state(config: &Config, database: Database) -> Result<RunnerBrokerState> {
    let runners = &config.mcp.runners;
    let base = runners
        .controller_url
        .clone()
        .ok_or_else(|| anyhow!("MCP runner controller URL is absent"))?;
    let create_url = base
        .join("internal/v1/mcp/runners")
        .context("MCP runner controller create URL is invalid")?;
    let delete_url = base
        .join("internal/v1/mcp/runners:delete")
        .context("MCP runner controller delete URL is invalid")?;
    let certificate = std::fs::read(
        runners
            .controller_client_certificate_chain_file
            .as_ref()
            .ok_or_else(|| anyhow!("MCP runner controller client certificate is absent"))?,
    )?;
    let private_key = std::fs::read(
        runners
            .controller_client_private_key_file
            .as_ref()
            .ok_or_else(|| anyhow!("MCP runner controller client key is absent"))?,
    )?;
    let mut identity_pem = certificate;
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&private_key);
    let identity = Identity::from_pem(&identity_pem)
        .context("MCP runner controller client identity is invalid")?;
    let ca = std::fs::read(
        runners
            .controller_server_ca_file
            .as_ref()
            .ok_or_else(|| anyhow!("MCP runner controller CA is absent"))?,
    )?;
    let roots = Certificate::from_pem_bundle(&ca).context("MCP runner controller CA is invalid")?;
    let mut builder = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .identity(identity)
        .connect_timeout(Duration::from_secs(
            config.mcp.limits.connect_timeout_seconds,
        ))
        .timeout(Duration::from_secs(
            config.mcp.limits.connect_timeout_seconds,
        ));
    for root in roots {
        builder = builder.add_root_certificate(root);
    }
    Ok(RunnerBrokerState {
        admission: Some(RunnerAdmission {
            database,
            tenant_limit: i64::from(runners.max_per_tenant),
            principal_limit: i64::from(runners.max_per_principal),
            reservation_seconds: i64::try_from(
                config
                    .mcp
                    .limits
                    .absolute_timeout_seconds
                    .saturating_add(config.mcp.limits.connect_timeout_seconds.saturating_mul(2)),
            )
            .unwrap_or(900)
            .clamp(1, 900),
        }),
        controller: builder
            .build()
            .context("cannot initialize MCP runner controller client")?,
        create_url,
        delete_url,
        pending: Mutex::new(HashMap::new()),
        lifecycles: Mutex::new(HashMap::new()),
        relay_accepts: Arc::new(Semaphore::new(
            config.mcp.limits.replica_concurrency as usize,
        )),
        hello_timeout: Duration::from_secs(config.mcp.limits.connect_timeout_seconds),
    })
}

async fn runner_relay_tcp_loop(listener: tokio::net::TcpListener, runners: Arc<RunnerBrokerState>) {
    loop {
        let Ok(permit) = runners.relay_accepts.clone().acquire_owned().await else {
            return;
        };
        match listener.accept().await {
            Ok((stream, _)) => {
                let runners = runners.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = accept_runner_relay(Box::new(stream), runners).await {
                        tracing::warn!(code = error.code, "MCP runner relay rejected");
                    }
                });
            }
            Err(error) => {
                drop(permit);
                tracing::warn!(code = "mcp.runner.accept_failed", %error);
            }
        }
    }
}

async fn runner_relay_mtls_loop(mut listener: MtlsListener, runners: Arc<RunnerBrokerState>) {
    loop {
        let Ok(permit) = runners.relay_accepts.clone().acquire_owned().await else {
            return;
        };
        let (stream, _) = axum::serve::Listener::accept(&mut listener).await;
        let runners = runners.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = accept_runner_relay(Box::new(stream), runners).await {
                tracing::warn!(code = error.code, "MCP runner relay rejected");
            }
        });
    }
}

async fn accept_runner_relay(
    mut stream: RelayStream,
    runners: Arc<RunnerBrokerState>,
) -> Result<(), BrokerError> {
    let message = Zeroizing::new(
        tokio::time::timeout(runners.hello_timeout, read_runner_message(&mut stream))
            .await
            .map_err(|_| BrokerError::gateway_timeout("mcp.runner.hello_timeout"))??,
    );
    let mut hello = decode_runner_hello(&message)
        .map_err(|_| BrokerError::forbidden("mcp.runner.hello_invalid"))?;
    let invocation_id = parse_uuid(&hello.invocation_id)?;
    let supplied = blake3::hash(&hello.bootstrap_token);
    hello.bootstrap_token.fill(0);
    let pending = take_authenticated_pending(&runners, invocation_id, supplied.as_bytes()).await?;
    pending
        .sender
        .send(stream)
        .map_err(|_| BrokerError::unavailable("mcp.runner.request_cancelled"))
}

async fn take_authenticated_pending(
    runners: &RunnerBrokerState,
    invocation_id: Uuid,
    supplied_digest: &[u8; 32],
) -> Result<PendingRunner, BrokerError> {
    let mut pending = runners.pending.lock().await;
    let expected = pending
        .get(&invocation_id)
        .ok_or_else(|| BrokerError::forbidden("mcp.runner.lease_unknown"))?;
    if supplied_digest
        .ct_eq(&expected.bootstrap_digest)
        .unwrap_u8()
        != 1
    {
        return Err(BrokerError::forbidden("mcp.runner.token_invalid"));
    }
    pending
        .remove(&invocation_id)
        .ok_or_else(|| BrokerError::forbidden("mcp.runner.lease_unknown"))
}

async fn insert_pending_runner(
    runners: &RunnerBrokerState,
    invocation_id: Uuid,
    pending: PendingRunner,
) -> Result<(), BrokerError> {
    match runners.pending.lock().await.entry(invocation_id) {
        Entry::Vacant(entry) => {
            entry.insert(pending);
            Ok(())
        }
        Entry::Occupied(_) => Err(BrokerError::bad_request("mcp.runner.invocation_reused")),
    }
}

async fn register_runner_invocation(
    runners: Arc<RunnerBrokerState>,
    invocation_id: Uuid,
    tenant_id: Uuid,
    principal_id: Uuid,
) -> Result<RunnerInvocationGuard, BrokerError> {
    let lifecycle = Arc::new(RunnerLifecycle {
        tenant_id,
        principal_id,
        cancelled: AtomicBool::new(false),
        cleanup_complete: AtomicBool::new(false),
        reserved: AtomicBool::new(false),
        mutation: Mutex::new(()),
    });
    match runners.lifecycles.lock().await.entry(invocation_id) {
        Entry::Vacant(entry) => {
            entry.insert(lifecycle.clone());
        }
        Entry::Occupied(_) => {
            return Err(BrokerError::bad_request("mcp.runner.invocation_reused"));
        }
    }
    Ok(RunnerInvocationGuard {
        runners,
        invocation_id,
        lifecycle,
    })
}

impl Drop for RunnerInvocationGuard {
    fn drop(&mut self) {
        let runners = self.runners.clone();
        let invocation_id = self.invocation_id;
        let lifecycle = self.lifecycle.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let mut lifecycles = runners.lifecycles.lock().await;
                if lifecycles
                    .get(&invocation_id)
                    .is_some_and(|current| Arc::ptr_eq(current, &lifecycle))
                {
                    lifecycles.remove(&invocation_id);
                }
            });
        }
    }
}

async fn read_runner_message(stream: &mut RelayStream) -> Result<Vec<u8>, BrokerError> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.runner.frame_invalid"))?
        as usize;
    if length == 0 || length > MAX_RUNNER_RELAY_MESSAGE_BYTES {
        return Err(BrokerError::bad_gateway("mcp.runner.frame_invalid"));
    }
    let mut message = vec![0_u8; length];
    stream
        .read_exact(&mut message)
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.runner.frame_invalid"))?;
    Ok(message)
}

async fn write_runner_message(stream: &mut RelayStream, message: &[u8]) -> Result<(), BrokerError> {
    if message.is_empty() || message.len() > MAX_RUNNER_RELAY_MESSAGE_BYTES {
        return Err(BrokerError::bad_gateway("mcp.runner.frame_invalid"));
    }
    stream
        .write_u32(message.len() as u32)
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.runner.unavailable"))?;
    stream
        .write_all(message)
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.runner.unavailable"))?;
    stream
        .flush()
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.runner.unavailable"))
}

async fn invoke(
    State(state): State<BrokerState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, BrokerError> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some(INTERNAL_CONTENT_TYPE)
    {
        return Err(BrokerError::bad_request("mcp.protocol.content_type"));
    }
    let request = InvocationRequest::decode(body)
        .map_err(|_| BrokerError::bad_request("mcp.protocol.invalid"))?;
    let operation = operation_for(&request)?;
    let now = unix_time()?;
    let claims = verify_request_delegation(
        &request.delegation,
        &state.verification_keys,
        operation,
        now,
    )?;
    if Uuid::parse_str(&request.request_id).is_err()
        || request.arguments_json.len() > state.limits.message_bytes as usize
        || request.semantic_input_json.len() > MAX_SEMANTIC_MARKDOWN_BYTES + 128
        || request.deadline_unix_milliseconds <= now.saturating_mul(1_000)
        || request.deadline_unix_milliseconds
            > now.saturating_add(state.limits.absolute_timeout_seconds as i64) * 1_000
        || !matches!(
            request.protocol_version.as_str(),
            CURRENT_PROTOCOL | FALLBACK_PROTOCOL
        )
    {
        return Err(BrokerError::bad_request("mcp.request.invalid"));
    }
    let semantic_input = parse_semantic_markdown_input(&request.semantic_input_json)?;
    if operation != McpOperation::Invoke && semantic_input.is_some() {
        return Err(BrokerError::bad_request("mcp.semantic.operation_invalid"));
    }
    let mut arguments_hasher = blake3::Hasher::new();
    arguments_hasher
        .update(ARGUMENT_DIGEST_DOMAIN)
        .update(&(request.arguments_json.len() as u64).to_be_bytes())
        .update(&request.arguments_json);
    if request.semantic_input_json.is_empty() {
        arguments_hasher.update(&0_u64.to_be_bytes());
    } else {
        arguments_hasher
            .update(&(request.semantic_input_json.len() as u64).to_be_bytes())
            .update(&request.semantic_input_json);
    }
    let digest = arguments_hasher.finalize();
    if claims.arguments_digest != digest.as_bytes() {
        return Err(BrokerError::forbidden("mcp.arguments.mismatch"));
    }
    let tenant_id = parse_uuid(&claims.tenant_id)?;
    let principal_id = parse_uuid(&claims.principal_id)?;
    let registration_id = parse_uuid(&claims.registration_id)?;
    let registration = state
        .database
        .mcp_registration(tenant_id, principal_id, registration_id)
        .await
        .map_err(|_| BrokerError::forbidden("mcp.authority.unavailable"))?;
    let generations = state
        .database
        .mcp_revocation_generations(tenant_id, principal_id, registration_id)
        .await
        .map_err(|_| BrokerError::forbidden("mcp.authority.unavailable"))?;
    if claims.membership_generation != generations.principal as u64
        || claims.policy_generation != generations.registration as u64
    {
        return Err(BrokerError::forbidden("mcp.authority.stale"));
    }
    validate_registration(&registration, &claims, &request, operation)?;
    if operation != McpOperation::Invoke && !claims.attachments.is_empty() {
        return Err(BrokerError::forbidden("mcp.attachments.operation_invalid"));
    }
    if operation == McpOperation::Invoke {
        validate_attachment_authority(&state, &claims, tenant_id, principal_id, registration_id)
            .await?;
    }
    enforce_admin_blocks(
        &state,
        &registration,
        &request,
        &claims.capability_fingerprint,
    )
    .await?;
    if operation == McpOperation::Invoke {
        let snapshot = state
            .database
            .mcp_current_capability_snapshot(tenant_id, registration_id)
            .await
            .map_err(|_| BrokerError::forbidden("mcp.capability.snapshot_unavailable"))?;
        if !snapshot_contains_capability(
            &snapshot.document,
            &request,
            &claims.capability_fingerprint,
        )? {
            return Err(BrokerError::forbidden("mcp.capability.snapshot_mismatch"));
        }
        let approved = state
            .database
            .mcp_capability_reviews(tenant_id, registration_id)
            .await
            .map_err(|_| BrokerError::forbidden("mcp.authority.unavailable"))?
            .into_iter()
            .any(|review| {
                !review.revoked
                    && review.decision == "approved"
                    && review.capability_fingerprint == claims.capability_fingerprint
            });
        if !approved {
            return Err(BrokerError::forbidden("mcp.capability.not_reviewed"));
        }
    }
    enforce_rate_limits(
        &state,
        &registration,
        principal_id,
        registration_id,
        operation,
        now,
    )
    .await?;
    let _permits = state
        .concurrency
        .acquire(principal_id, registration_id)
        .await?;
    let runner_invocation =
        if operation == McpOperation::Invoke && registration.transport == "stdio_catalog" {
            let runners = state
                .runners
                .as_ref()
                .ok_or_else(|| BrokerError::unavailable("mcp.runner.disabled"))?
                .clone();
            Some(
                register_runner_invocation(
                    runners,
                    parse_uuid(&request.request_id)?,
                    tenant_id,
                    principal_id,
                )
                .await?,
            )
        } else {
            None
        };
    let result = tokio::time::timeout(
        Duration::from_secs(state.limits.absolute_timeout_seconds),
        async {
            let execution = async {
                if matches!(
                    operation,
                    McpOperation::OauthDiscover
                        | McpOperation::OauthBegin
                        | McpOperation::OauthComplete
                        | McpOperation::CredentialReplace
                        | McpOperation::CredentialErase
                        | McpOperation::RegistrationConfigure
                ) {
                    return broker_management_operation(
                        &state,
                        &registration,
                        &request,
                        operation,
                        &claims,
                    )
                    .await;
                }
                let arguments_json =
                    materialize_attachments(&state, &claims, &request.arguments_json).await?;
                let credential = decrypt_credential(&state, &registration).await?;
                match registration.transport.as_str() {
                    "streamable_http" => {
                        let endpoint = validate_endpoint(&registration)?;
                        enforce_endpoint_policy(&state, &registration, &endpoint)?;
                        remote_operation(
                            &state,
                            &request,
                            &registration,
                            &endpoint,
                            credential.as_ref(),
                            &arguments_json,
                        )
                        .await
                    }
                    "stdio_catalog" => {
                        let lifecycle = runner_invocation
                            .as_ref()
                            .ok_or_else(|| BrokerError::unavailable("mcp.runner.disabled"))?
                            .lifecycle
                            .clone();
                        stdio_operation(&state, &request, &registration, &arguments_json, lifecycle)
                            .await
                    }
                    _ => Err(BrokerError::forbidden("mcp.registration.not_authorized")),
                }
            };
            if operation == McpOperation::Invoke {
                tokio::select! {
                    result = execution => result,
                    result = wait_for_invocation_cancellation(
                        &state,
                        tenant_id,
                        principal_id,
                        parse_uuid(&request.request_id)?,
                        runner_invocation
                            .as_ref()
                            .map(|invocation| invocation.lifecycle.clone()),
                    ) => result,
                }
            } else {
                execution.await
            }
        },
    )
    .await
    .map_err(|_| BrokerError::gateway_timeout("mcp.remote.deadline"))??;
    let frames = result_frames(
        &request.request_id,
        result,
        state.limits.result_bytes as usize,
    )?;
    let mut encoded = Vec::new();
    for frame in &frames {
        encoded.extend_from_slice(
            &encode_frame(frame)
                .map_err(|_| BrokerError::bad_gateway("mcp.remote.result_too_large"))?,
        );
    }
    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(INTERNAL_CONTENT_TYPE),
        )],
        encoded,
    )
        .into_response())
}

async fn wait_for_invocation_cancellation(
    state: &BrokerState,
    tenant_id: Uuid,
    principal_id: Uuid,
    invocation_id: Uuid,
    runner_lifecycle: Option<Arc<RunnerLifecycle>>,
) -> Result<Value, BrokerError> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let active = state
            .database
            .mcp_invocation_is_active(tenant_id, principal_id, invocation_id)
            .await
            .map_err(|_| BrokerError::unavailable("mcp.invocation.state_unavailable"))?;
        if !active {
            if let Some(lifecycle) = runner_lifecycle {
                let runners = state
                    .runners
                    .as_ref()
                    .ok_or_else(|| BrokerError::unavailable("mcp.runner.disabled"))?;
                cancel_runner_lifecycle(runners, invocation_id, lifecycle).await?;
            }
            return Err(BrokerError::unavailable("mcp.invocation.cancelled"));
        }
    }
}

fn snapshot_contains_capability(
    document: &Value,
    request: &InvocationRequest,
    expected_fingerprint: &[u8],
) -> Result<bool, BrokerError> {
    let key = match McpPrimitive::try_from(request.primitive).ok() {
        Some(McpPrimitive::Tool) => "tools",
        Some(McpPrimitive::Resource) => "resources",
        Some(McpPrimitive::Prompt) => "prompts",
        _ => return Ok(false),
    };
    let values = document
        .get(key)
        .and_then(|value| value.get(key))
        .and_then(Value::as_array)
        .ok_or_else(|| BrokerError::forbidden("mcp.capability.snapshot_invalid"))?;
    for descriptor in values {
        if descriptor.get("name").and_then(Value::as_str) != Some(request.capability_name.as_str())
        {
            continue;
        }
        let fingerprint = filebelt_mcp_policy::policy_json_digest(b"capability", descriptor)
            .map_err(|_| BrokerError::forbidden("mcp.capability.snapshot_invalid"))?;
        return Ok(fingerprint.as_slice() == expected_fingerprint);
    }
    Ok(false)
}

async fn validate_attachment_authority(
    state: &BrokerState,
    claims: &filebelt_mcp_protocol::DelegationClaims,
    tenant_id: Uuid,
    principal_id: Uuid,
    registration_id: Uuid,
) -> Result<(), BrokerError> {
    let mut total_bytes = 0_u64;
    let mut targets = HashSet::new();
    for attachment in &claims.attachments {
        let drive_id = parse_uuid(&attachment.drive_id)?;
        let node_id = parse_uuid(&attachment.node_id)?;
        let version_id = parse_uuid(&attachment.version_id)?;
        let data_grant_id = parse_uuid(&attachment.data_grant_id)?;
        total_bytes = total_bytes
            .checked_add(attachment.size_bytes)
            .ok_or_else(|| BrokerError::forbidden("mcp.attachments.too_large"))?;
        if attachment.maximum_raw_bytes > state.limits.attachment_hard_bytes
            || attachment.size_bytes > attachment.maximum_raw_bytes
            || total_bytes > state.limits.attachment_bytes
            || attachment
                .fields
                .iter()
                .any(|field| !targets.insert(field.target_json_pointer.clone()))
        {
            return Err(BrokerError::forbidden("mcp.attachments.invalid"));
        }
        let data_grant = state
            .database
            .mcp_data_grants(tenant_id, principal_id, drive_id, node_id)
            .await
            .map_err(|_| BrokerError::unavailable("mcp.authority.unavailable"))?
            .into_iter()
            .find(|grant| {
                grant.id == data_grant_id
                    && grant.registration_id == registration_id
                    && grant.version_id == version_id
                    && !grant.revoked
            })
            .ok_or_else(|| BrokerError::forbidden("mcp.attachment.grant_invalid"))?;
        let snapshot = state
            .database
            .mcp_authority_snapshot(tenant_id, principal_id, registration_id, data_grant_id)
            .await
            .map_err(|_| BrokerError::forbidden("mcp.attachment.grant_stale"))?;
        let needs_content = attachment
            .fields
            .iter()
            .any(|field| field.disclosure == AttachmentDisclosure::Content as i32);
        let needs_metadata = attachment
            .fields
            .iter()
            .any(|field| field.disclosure != AttachmentDisclosure::Content as i32);
        if !attachment_authority_generations_match(claims, attachment, &snapshot)
            || (needs_content && (!data_grant.allow_content || !snapshot.allow_content))
            || (needs_metadata && (!data_grant.allow_metadata || !snapshot.allow_metadata))
        {
            return Err(BrokerError::forbidden("mcp.attachment.authority_stale"));
        }
    }
    Ok(())
}

fn attachment_authority_generations_match(
    claims: &filebelt_mcp_protocol::DelegationClaims,
    attachment: &AttachmentClaim,
    snapshot: &McpAuthoritySnapshot,
) -> bool {
    claims.membership_generation == attachment.membership_generation
        && snapshot.principal_generation == attachment.membership_generation as i64
        && snapshot.registration_generation == claims.policy_generation as i64
        && snapshot.drive_acl_generation == attachment.drive_acl_generation as i64
        && snapshot.acl_generation == attachment.resource_acl_generation as i64
        && snapshot.namespace_generation == attachment.namespace_generation as i64
}

async fn materialize_attachments(
    state: &BrokerState,
    claims: &filebelt_mcp_protocol::DelegationClaims,
    arguments_json: &[u8],
) -> Result<Vec<u8>, BrokerError> {
    if claims.attachments.is_empty() {
        return Ok(arguments_json.to_vec());
    }
    let mut arguments: Value = serde_json::from_slice(arguments_json)
        .map_err(|_| BrokerError::bad_request("mcp.arguments.invalid"))?;
    for attachment in &claims.attachments {
        let content = if attachment
            .fields
            .iter()
            .any(|field| field.disclosure == AttachmentDisclosure::Content as i32)
        {
            Some(download_attachment(state, attachment).await?)
        } else {
            None
        };
        for field in &attachment.fields {
            let value = attachment_value(
                attachment,
                field,
                content.as_ref().map(|bytes| bytes.as_slice()),
            )?;
            inject_attachment_value(&mut arguments, &field.target_json_pointer, value)?;
        }
    }
    let encoded = serde_json::to_vec(&arguments)
        .map_err(|_| BrokerError::bad_request("mcp.arguments.invalid"))?;
    if encoded.len() > state.limits.encoded_wire_bytes as usize {
        return Err(BrokerError::bad_request("mcp.attachments.wire_too_large"));
    }
    Ok(encoded)
}

async fn download_attachment(
    state: &BrokerState,
    claim: &AttachmentClaim,
) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let url = state
        .attachment_io_url
        .join(claim.download_path.trim_start_matches('/'))
        .map_err(|_| BrokerError::forbidden("mcp.attachment.path_invalid"))?;
    if url.origin() != state.attachment_io_url.origin() {
        return Err(BrokerError::forbidden("mcp.attachment.path_invalid"));
    }
    let authorization = HeaderValue::from_str(&claim.authorization)
        .map_err(|_| BrokerError::forbidden("mcp.attachment.capability_invalid"))?;
    let mut response = state
        .attachment_client
        .get(url)
        .header(header::AUTHORIZATION, authorization)
        .header(header::ACCEPT, "application/octet-stream")
        .timeout(Duration::from_secs(state.limits.operation_timeout_seconds))
        .send()
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.attachment.unavailable"))?;
    if response.status() != StatusCode::OK
        || response
            .content_length()
            .is_some_and(|length| length != claim.size_bytes || length > claim.maximum_raw_bytes)
    {
        return Err(BrokerError::bad_gateway("mcp.attachment.response_invalid"));
    }
    let capacity = usize::try_from(claim.size_bytes)
        .map_err(|_| BrokerError::forbidden("mcp.attachments.too_large"))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.attachment.response_invalid"))?
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > capacity || length > claim.maximum_raw_bytes as usize)
        {
            return Err(BrokerError::bad_gateway(
                "mcp.attachment.response_too_large",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != capacity {
        return Err(BrokerError::bad_gateway("mcp.attachment.response_invalid"));
    }
    Ok(bytes)
}

fn attachment_value(
    claim: &AttachmentClaim,
    field: &AttachmentFieldClaim,
    content: Option<&[u8]>,
) -> Result<Value, BrokerError> {
    let disclosure = AttachmentDisclosure::try_from(field.disclosure)
        .map_err(|_| BrokerError::forbidden("mcp.attachments.invalid"))?;
    let encoding = AttachmentEncoding::try_from(field.encoding)
        .map_err(|_| BrokerError::forbidden("mcp.attachments.invalid"))?;
    let bytes = match disclosure {
        AttachmentDisclosure::Content => {
            content.ok_or_else(|| BrokerError::forbidden("mcp.attachments.invalid"))?
        }
        AttachmentDisclosure::Basename => claim.basename.as_bytes(),
        AttachmentDisclosure::MediaType => claim.media_type.as_bytes(),
        AttachmentDisclosure::Size => {
            return Ok(Value::from(claim.size_bytes));
        }
        AttachmentDisclosure::Unspecified => {
            return Err(BrokerError::forbidden("mcp.attachments.invalid"));
        }
    };
    match encoding {
        AttachmentEncoding::Utf8 => std::str::from_utf8(bytes)
            .map(|value| Value::String(value.to_owned()))
            .map_err(|_| BrokerError::bad_request("mcp.attachment.utf8_invalid")),
        AttachmentEncoding::Base64 => Ok(Value::String(STANDARD.encode(bytes))),
        AttachmentEncoding::Decimal | AttachmentEncoding::Unspecified => {
            Err(BrokerError::forbidden("mcp.attachments.invalid"))
        }
    }
}

fn inject_attachment_value(
    arguments: &mut Value,
    pointer: &str,
    value: Value,
) -> Result<(), BrokerError> {
    let mut tokens = pointer
        .split('/')
        .skip(1)
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>();
    let key = tokens
        .pop()
        .ok_or_else(|| BrokerError::bad_request("mcp.attachment.target_invalid"))?;
    let mut parent = arguments;
    for token in tokens {
        parent = match parent {
            Value::Object(object) => object
                .get_mut(&token)
                .ok_or_else(|| BrokerError::bad_request("mcp.attachment.target_missing"))?,
            Value::Array(array) => array
                .get_mut(parse_array_index(&token)?)
                .ok_or_else(|| BrokerError::bad_request("mcp.attachment.target_missing"))?,
            _ => return Err(BrokerError::bad_request("mcp.attachment.target_invalid")),
        };
    }
    match parent {
        Value::Object(object) => {
            if object.get(&key).is_some_and(|existing| !existing.is_null()) {
                return Err(BrokerError::bad_request("mcp.attachment.target_occupied"));
            }
            object.insert(key, value);
        }
        Value::Array(array) => {
            let index = parse_array_index(&key)?;
            let target = array
                .get_mut(index)
                .ok_or_else(|| BrokerError::bad_request("mcp.attachment.target_missing"))?;
            if !target.is_null() {
                return Err(BrokerError::bad_request("mcp.attachment.target_occupied"));
            }
            *target = value;
        }
        _ => return Err(BrokerError::bad_request("mcp.attachment.target_invalid")),
    }
    Ok(())
}

fn parse_array_index(value: &str) -> Result<usize, BrokerError> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(BrokerError::bad_request("mcp.attachment.target_invalid"));
    }
    value
        .parse()
        .map_err(|_| BrokerError::bad_request("mcp.attachment.target_invalid"))
}

async fn enforce_rate_limits(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    principal_id: Uuid,
    registration_id: Uuid,
    operation: McpOperation,
    now: i64,
) -> Result<(), BrokerError> {
    let (window, principal_limit) = match operation {
        McpOperation::Test | McpOperation::Discover => (600, 10),
        McpOperation::OauthDiscover
        | McpOperation::OauthBegin
        | McpOperation::OauthComplete
        | McpOperation::CredentialReplace
        | McpOperation::CredentialErase
        | McpOperation::RegistrationConfigure => (900, 10),
        McpOperation::Invoke if registration.owner_kind == "service" => (3_600, 600),
        McpOperation::Invoke => (3_600, 60),
        _ => return Err(BrokerError::forbidden("mcp.operation.prohibited")),
    };
    let operation_name = match operation {
        McpOperation::Test => "test",
        McpOperation::Discover => "discover",
        McpOperation::Invoke => "invoke",
        McpOperation::OauthDiscover => "oauth_discover",
        McpOperation::OauthBegin => "oauth_begin",
        McpOperation::OauthComplete => "oauth_complete",
        McpOperation::CredentialReplace => "credential_replace",
        McpOperation::CredentialErase => "credential_erase",
        McpOperation::RegistrationConfigure => "registration_configure",
        _ => "prohibited",
    };
    let principal_bucket = format!("{operation_name}:principal");
    let registration_bucket = format!("{operation_name}:registration:{registration_id}");
    let registration_limit =
        if operation == McpOperation::Invoke && registration.source_kind == "personal" {
            20
        } else {
            principal_limit
        };
    for (bucket, limit) in [
        (principal_bucket.as_str(), principal_limit),
        (registration_bucket.as_str(), registration_limit),
    ] {
        let decision = state
            .database
            .mcp_take_rate_limit(
                registration.tenant_id,
                principal_id,
                bucket,
                now - now.rem_euclid(window),
                window,
                1,
                limit,
            )
            .await
            .map_err(|_| BrokerError::unavailable("mcp.rate_limit.unavailable"))?;
        if !decision.allowed {
            return Err(BrokerError::too_many_requests("mcp.rate_limited"));
        }
    }
    Ok(())
}

fn operation_for(request: &InvocationRequest) -> Result<McpOperation, BrokerError> {
    if request.capability_name.len() > 256 {
        return Err(BrokerError::bad_request("mcp.capability.invalid"));
    }
    match McpPrimitive::try_from(request.primitive).ok() {
        Some(McpPrimitive::Tool | McpPrimitive::Resource | McpPrimitive::Prompt) => {
            Ok(McpOperation::Invoke)
        }
        Some(McpPrimitive::Unspecified) if request.capability_name == "$discover" => {
            Ok(McpOperation::Discover)
        }
        Some(McpPrimitive::Unspecified) if request.capability_name == "$test" => {
            Ok(McpOperation::Test)
        }
        Some(McpPrimitive::Unspecified) if request.capability_name == "$oauth_discover" => {
            Ok(McpOperation::OauthDiscover)
        }
        Some(McpPrimitive::Unspecified) if request.capability_name == "$oauth_begin" => {
            Ok(McpOperation::OauthBegin)
        }
        Some(McpPrimitive::Unspecified) if request.capability_name == "$oauth_complete" => {
            Ok(McpOperation::OauthComplete)
        }
        Some(McpPrimitive::Unspecified) if request.capability_name == "$credential_replace" => {
            Ok(McpOperation::CredentialReplace)
        }
        Some(McpPrimitive::Unspecified) if request.capability_name == "$credential_erase" => {
            Ok(McpOperation::CredentialErase)
        }
        Some(McpPrimitive::Unspecified) if request.capability_name == "$registration_configure" => {
            Ok(McpOperation::RegistrationConfigure)
        }
        _ => Err(BrokerError::bad_request("mcp.primitive.invalid")),
    }
}

fn validate_registration(
    registration: &McpRegistrationRecord,
    claims: &filebelt_mcp_protocol::DelegationClaims,
    request: &InvocationRequest,
    operation: McpOperation,
) -> Result<(), BrokerError> {
    if !matches!(
        registration.transport.as_str(),
        "streamable_http" | "stdio_catalog"
    ) || registration.state.revoked
        || registration.state.quarantine != filebelt_mcp_policy::QuarantineState::Clear
        || claims.policy_generation != registration.revocation_generation as u64
    {
        return Err(BrokerError::forbidden("mcp.registration.not_authorized"));
    }
    if operation == McpOperation::Invoke
        && (!registration.state.enabled
            || registration.protocol_version.as_deref() != Some(request.protocol_version.as_str()))
    {
        return Err(BrokerError::forbidden("mcp.registration.not_authorized"));
    }
    if matches!(
        operation,
        McpOperation::OauthDiscover | McpOperation::OauthBegin | McpOperation::OauthComplete
    ) && registration.transport != "streamable_http"
    {
        return Err(BrokerError::forbidden("mcp.oauth.transport_invalid"));
    }
    Ok(())
}

async fn enforce_admin_blocks(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    request: &InvocationRequest,
    capability_fingerprint: &[u8],
) -> Result<(), BrokerError> {
    let rules = state
        .database
        .mcp_admin_block_rules(registration.tenant_id)
        .await
        .map_err(|_| BrokerError::unavailable("mcp.block_policy.unavailable"))?;
    let endpoint_origin = registration
        .endpoint_uri
        .as_deref()
        .and_then(|value| Url::parse(value).ok())
        .map(|value| value.origin().ascii_serialization());
    let registration_id = registration.id.to_string();
    let fingerprint = encode_hex(capability_fingerprint);
    if rules.into_iter().any(|rule| {
        if !rule.enabled {
            return false;
        }
        match rule.scope.as_str() {
            "origin" => endpoint_origin.as_deref() == Some(rule.matcher.as_str()),
            "trust_profile" => registration.trust_profile.as_deref() == Some(rule.matcher.as_str()),
            "catalog_entry" => registration.catalog_entry.as_deref() == Some(rule.matcher.as_str()),
            "registration" => registration_id == rule.matcher,
            "capability" => request.capability_name == rule.matcher || fingerprint == rule.matcher,
            _ => true,
        }
    }) {
        return Err(BrokerError::forbidden("mcp.block_policy.denied"));
    }
    Ok(())
}

async fn decrypt_credential(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
) -> Result<Option<DecryptedCredential>, BrokerError> {
    if registration.state.authentication == filebelt_mcp_policy::AuthenticationState::NoneRequired {
        return Ok(None);
    }
    let issuer = registration.endpoint_uri.as_deref().unwrap_or_default();
    let mut candidates = vec![
        (issuer.to_owned(), "bearer".to_owned()),
        (issuer.to_owned(), "api_key".to_owned()),
    ];
    if let Ok(metadata) = state
        .database
        .mcp_secret_metadata(
            registration.tenant_id,
            registration.id,
            registration.owner_principal_id,
        )
        .await
    {
        candidates.extend(
            metadata
                .into_iter()
                .filter(|metadata| metadata.secret_kind == "oauth_access")
                .map(|metadata| (metadata.issuer, metadata.secret_kind)),
        );
    }
    for (issuer, kind) in candidates {
        let envelope = match state
            .database
            .mcp_secret_envelope(
                registration.tenant_id,
                registration.id,
                registration.owner_principal_id,
                &issuer,
                &kind,
            )
            .await
        {
            Ok(envelope) => envelope,
            Err(_) => continue,
        };
        if envelope.credential_generation != registration.credential_generation {
            return Err(BrokerError::forbidden("mcp.credential.stale"));
        }
        let context = SecretContext {
            tenant_id: envelope.tenant_id,
            registration_id: envelope.registration_id,
            owner_principal_id: envelope.owner_principal_id,
            issuer: &envelope.issuer,
            secret_kind: &envelope.secret_kind,
            credential_generation: envelope.credential_generation,
        };
        let encrypted = SecretEnvelope {
            ciphertext: envelope.ciphertext,
            nonce: envelope
                .nonce
                .try_into()
                .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"))?,
            wrapped_dek: envelope.wrapped_dek,
            wrap_nonce: envelope
                .wrap_nonce
                .try_into()
                .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"))?,
            kek_generation: envelope
                .kek_generation
                .try_into()
                .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"))?,
            aad_version: envelope
                .aad_version
                .try_into()
                .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"))?,
        };
        let secret = state
            .keyring
            .decrypt(&context, &encrypted)
            .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"));
        let secret = secret?;
        if envelope.secret_kind == "oauth_access" {
            return oauth_credential(state, registration, &envelope.issuer, secret)
                .await
                .map(Some);
        }
        return Ok(Some(DecryptedCredential {
            kind: envelope.secret_kind,
            secret,
        }));
    }
    Err(BrokerError::forbidden("mcp.credential.missing"))
}

async fn oauth_credential(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    issuer: &str,
    secret: Zeroizing<Vec<u8>>,
) -> Result<DecryptedCredential, BrokerError> {
    let value: Value = serde_json::from_slice(&secret)
        .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"))?;
    let endpoint = validate_endpoint(registration)?;
    if value.get("resource").and_then(Value::as_str) != Some(endpoint.as_str()) {
        return Err(BrokerError::forbidden("mcp.oauth.resource_mismatch"));
    }
    let expires_at = value
        .get("expires_at")
        .and_then(Value::as_i64)
        .ok_or_else(|| BrokerError::forbidden("mcp.credential.invalid"))?;
    if expires_at > unix_time()?.saturating_add(30) {
        let access_token = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty() && token.len() <= 16_384)
            .ok_or_else(|| BrokerError::forbidden("mcp.credential.invalid"))?;
        return Ok(DecryptedCredential {
            kind: "oauth_access".into(),
            secret: Zeroizing::new(access_token.as_bytes().to_vec()),
        });
    }
    let refresh_token = value
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty() && token.len() <= 16_384)
        .ok_or_else(|| BrokerError::forbidden("mcp.oauth.reauthorization_required"))?;
    let discovery = oauth_discover(state, registration, &json!({"issuer": issuer})).await?;
    let rotated = oauth_refresh_exchange(
        state,
        registration,
        discovery["token_endpoint"].as_str().unwrap_or_default(),
        issuer,
        refresh_token,
        endpoint.as_str(),
    )
    .await?;
    let token_bytes = serde_json::to_vec(&rotated)
        .map_err(|_| BrokerError::unavailable("mcp.oauth.token_invalid"))?;
    store_registration_secret(state, registration, issuer, "oauth_access", &token_bytes).await?;
    let access_token = rotated
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| BrokerError::forbidden("mcp.credential.invalid"))?;
    Ok(DecryptedCredential {
        kind: "oauth_access".into(),
        secret: Zeroizing::new(access_token.as_bytes().to_vec()),
    })
}

fn validate_endpoint(registration: &McpRegistrationRecord) -> Result<Url, BrokerError> {
    let endpoint = registration
        .endpoint_uri
        .as_deref()
        .and_then(|value| Url::parse(value).ok())
        .ok_or_else(|| BrokerError::forbidden("mcp.endpoint.invalid"))?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || endpoint.port_or_known_default() != Some(443)
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(BrokerError::forbidden("mcp.endpoint.invalid"));
    }
    Ok(endpoint)
}

fn enforce_endpoint_policy(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    endpoint: &Url,
) -> Result<(), BrokerError> {
    let profile_name = registration
        .trust_profile
        .as_deref()
        .ok_or_else(|| BrokerError::forbidden("mcp.trust_profile.invalid"))?;
    let profile = state
        .trust_profiles
        .get(profile_name)
        .ok_or_else(|| BrokerError::forbidden("mcp.trust_profile.invalid"))?;
    let host = endpoint.host_str().unwrap_or_default().to_ascii_lowercase();
    if !profile.public_webpki
        || profile.custom_ca_file.is_some()
        || !profile.ports.contains(&443)
        || (!profile.hosts.is_empty()
            && !profile
                .hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&host)))
    {
        return Err(BrokerError::forbidden("mcp.endpoint.policy_denied"));
    }
    Ok(())
}

async fn broker_management_operation(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    request: &InvocationRequest,
    operation: McpOperation,
    claims: &filebelt_mcp_protocol::DelegationClaims,
) -> Result<Value, BrokerError> {
    let arguments: Value = serde_json::from_slice(&request.arguments_json)
        .map_err(|_| BrokerError::bad_request("mcp.management.invalid"))?;
    match operation {
        McpOperation::CredentialReplace => {
            replace_credential(state, registration, &arguments).await
        }
        McpOperation::CredentialErase => erase_credential(state, registration, &arguments).await,
        McpOperation::RegistrationConfigure => {
            configure_registration(state, registration, &arguments).await
        }
        McpOperation::OauthDiscover => oauth_discover(state, registration, &arguments).await,
        McpOperation::OauthBegin => begin_oauth(state, registration, claims, &arguments).await,
        McpOperation::OauthComplete => {
            complete_oauth(state, registration, claims, &arguments).await
        }
        _ => Err(BrokerError::bad_request("mcp.management.invalid")),
    }
}

async fn configure_registration(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    arguments: &Value,
) -> Result<Value, BrokerError> {
    let object = arguments
        .as_object()
        .filter(|object| {
            object.len() == 7
                && object.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "expected_revision"
                            | "display_name"
                            | "description"
                            | "endpoint_uri"
                            | "trust_profile"
                            | "catalog_entry"
                            | "policy"
                    )
                })
        })
        .ok_or_else(|| BrokerError::bad_request("mcp.registration.invalid"))?;
    let expected_revision = object
        .get("expected_revision")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let display_name = object
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let description = object
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let endpoint_uri = optional_string(object.get("endpoint_uri"))?;
    let trust_profile = optional_string(object.get("trust_profile"))?;
    let catalog_entry = optional_string(object.get("catalog_entry"))?;
    let policy = object
        .get("policy")
        .filter(|value| value.is_object())
        .ok_or_else(|| BrokerError::bad_request("mcp.registration.invalid"))?;
    if expected_revision != registration.revision
        || display_name.is_empty()
        || display_name.len() > 120
        || description.len() > 1_000
        || trust_profile.is_none_or(|profile| !state.trust_profiles.contains_key(profile))
    {
        return Err(BrokerError::bad_request("mcp.registration.invalid"));
    }
    match registration.transport.as_str() {
        "streamable_http" => {
            if catalog_entry.is_some() {
                return Err(BrokerError::bad_request("mcp.registration.invalid"));
            }
            let mut candidate = registration.clone();
            candidate.endpoint_uri = endpoint_uri.map(ToOwned::to_owned);
            candidate.trust_profile = trust_profile.map(ToOwned::to_owned);
            let endpoint = validate_endpoint(&candidate)?;
            enforce_endpoint_policy(state, &candidate, &endpoint)?;
        }
        "stdio_catalog" => {
            if endpoint_uri.is_some()
                || catalog_entry.is_none_or(|entry| {
                    entry.is_empty()
                        || entry.len() > 128
                        || !entry.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                })
            {
                return Err(BrokerError::bad_request("mcp.registration.invalid"));
            }
        }
        _ => return Err(BrokerError::forbidden("mcp.registration.not_authorized")),
    }
    state
        .database
        .mcp_replace_registration_configuration_and_erase(&RegistrationConfigurationUpdate {
            tenant_id: registration.tenant_id,
            registration_id: registration.id,
            owner_principal_id: registration.owner_principal_id,
            expected_revision,
            display_name,
            description,
            endpoint_uri,
            trust_profile,
            catalog_entry,
            policy,
        })
        .await
        .map_err(|_| BrokerError::forbidden("mcp.registration.stale"))?;
    Ok(json!({}))
}

fn optional_string(value: Option<&Value>) -> Result<Option<&str>, BrokerError> {
    match value {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        _ => Err(BrokerError::bad_request("mcp.registration.invalid")),
    }
}

async fn replace_credential(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    arguments: &Value,
) -> Result<Value, BrokerError> {
    let kind = arguments
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let secret = arguments
        .get("secret")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_revision = arguments
        .get("expected_revision")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    if !matches!(kind, "bearer" | "api_key")
        || secret.is_empty()
        || secret.len() > 8_192
        || expected_revision != registration.revision
    {
        return Err(BrokerError::bad_request("mcp.credential.invalid"));
    }
    let issuer = registration
        .endpoint_uri
        .as_deref()
        .unwrap_or("stdio-catalog");
    store_registration_secret(state, registration, issuer, kind, secret.as_bytes()).await?;
    Ok(json!({}))
}

async fn erase_credential(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    arguments: &Value,
) -> Result<Value, BrokerError> {
    let expected_revision = arguments
        .get("expected_revision")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    if expected_revision != registration.revision {
        return Err(BrokerError::forbidden("mcp.credential.stale"));
    }
    state
        .database
        .mcp_cryptographically_erase_registration_at_revision(
            registration.tenant_id,
            registration.id,
            registration.owner_principal_id,
            expected_revision,
        )
        .await
        .map_err(|_| BrokerError::unavailable("mcp.credential.store_failed"))?;
    Ok(json!({}))
}

async fn store_registration_secret(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    issuer: &str,
    kind: &str,
    secret: &[u8],
) -> Result<(), BrokerError> {
    let credential_generation = registration
        .credential_generation
        .checked_add(1)
        .ok_or_else(|| BrokerError::unavailable("mcp.credential.generation_exhausted"))?;
    let context = SecretContext {
        tenant_id: registration.tenant_id,
        registration_id: registration.id,
        owner_principal_id: registration.owner_principal_id,
        issuer,
        secret_kind: kind,
        credential_generation,
    };
    let encrypted = state
        .keyring
        .encrypt(state.current_kek_generation, &context, secret)
        .map_err(|_| BrokerError::unavailable("mcp.credential.encrypt_failed"))?;
    state
        .database
        .mcp_replace_registration_secret(&McpSecretEnvelope {
            tenant_id: registration.tenant_id,
            registration_id: registration.id,
            owner_principal_id: registration.owner_principal_id,
            issuer: issuer.to_owned(),
            secret_kind: kind.to_owned(),
            credential_generation,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce.to_vec(),
            wrapped_dek: encrypted.wrapped_dek,
            wrap_nonce: encrypted.wrap_nonce.to_vec(),
            kek_generation: encrypted.kek_generation as i32,
            aad_version: encrypted.aad_version as i32,
        })
        .await
        .map_err(|_| BrokerError::unavailable("mcp.credential.store_failed"))?;
    Ok(())
}

async fn oauth_discover(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    arguments: &Value,
) -> Result<Value, BrokerError> {
    let issuer = canonical_oauth_issuer(
        arguments
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let client = state
        .oauth_clients
        .get(&issuer)
        .ok_or_else(|| BrokerError::forbidden("mcp.oauth.issuer_not_configured"))?;
    let endpoint = validate_endpoint(registration)?;
    enforce_endpoint_policy(state, registration, &endpoint)?;
    let resource = endpoint.as_str();
    let protected_url = oauth_well_known_url(&endpoint, "oauth-protected-resource");
    let protected =
        gateway_json(state, registration, &protected_url, "GET", None, Vec::new()).await?;
    if protected
        .get("resource")
        .and_then(Value::as_str)
        .is_none_or(|value| value != resource)
    {
        return Err(BrokerError::forbidden("mcp.oauth.resource_mismatch"));
    }
    let issuer_allowed = protected
        .get("authorization_servers")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values.iter().any(|value| {
                value
                    .as_str()
                    .and_then(|value| canonical_oauth_issuer(value).ok())
                    .as_deref()
                    == Some(issuer.as_str())
            })
        });
    if !issuer_allowed {
        return Err(BrokerError::forbidden("mcp.oauth.resource_mismatch"));
    }
    let issuer_url =
        Url::parse(&issuer).map_err(|_| BrokerError::forbidden("mcp.oauth.issuer_invalid"))?;
    let metadata_url = oauth_well_known_url(&issuer_url, "oauth-authorization-server");
    let metadata =
        gateway_json(state, registration, &metadata_url, "GET", None, Vec::new()).await?;
    if metadata
        .get("issuer")
        .and_then(Value::as_str)
        .and_then(|value| canonical_oauth_issuer(value).ok())
        .as_deref()
        != Some(issuer.as_str())
    {
        return Err(BrokerError::forbidden("mcp.oauth.discovery_invalid"));
    }
    let authorization_endpoint = oauth_endpoint(&metadata, "authorization_endpoint", &issuer)?;
    let token_endpoint = oauth_endpoint(&metadata, "token_endpoint", &issuer)?;
    Ok(json!({
        "issuer": issuer,
        "client_id": client.client_id,
        "resource": resource,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
    }))
}

async fn begin_oauth(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    claims: &filebelt_mcp_protocol::DelegationClaims,
    arguments: &Value,
) -> Result<Value, BrokerError> {
    let discovery = oauth_discover(state, registration, arguments).await?;
    let issuer = discovery["issuer"].as_str().unwrap_or_default();
    let state_value = arguments
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let state_digest = decode_hex_digest(
        arguments
            .get("state_digest")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let verifier = arguments
        .get("verifier")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let challenge = arguments
        .get("challenge")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let redirect_uri = arguments
        .get("redirect_uri")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let return_path = arguments
        .get("return_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let attempt_id = arguments
        .get("attempt_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| BrokerError::bad_request("mcp.oauth.attempt_invalid"))?;
    if state_value.len() < 32
        || state_value.len() > 256
        || verifier.len() < 43
        || verifier.len() > 128
        || challenge.len() < 43
        || challenge.len() > 128
        || !return_path.starts_with("/settings/mcp")
        || return_path.len() > 256
        || Url::parse(redirect_uri).ok().is_none_or(|url| {
            url.path() != "/api/v1/mcp/oauth/callback"
                || url.query().is_some()
                || url.fragment().is_some()
        })
    {
        return Err(BrokerError::bad_request("mcp.oauth.attempt_invalid"));
    }
    let attempt_secret = serde_json::to_vec(&json!({
        "verifier": verifier,
        "redirect_uri": redirect_uri,
        "resource": discovery["resource"],
    }))
    .map_err(|_| BrokerError::unavailable("mcp.oauth.attempt_invalid"))?;
    let owner_principal_id = parse_uuid(&claims.principal_id)?;
    let session_id = parse_uuid(&claims.session_id)?;
    let context = SecretContext {
        tenant_id: registration.tenant_id,
        registration_id: registration.id,
        owner_principal_id,
        issuer,
        secret_kind: "oauth_attempt",
        credential_generation: registration.credential_generation,
    };
    let encrypted = state
        .keyring
        .encrypt(state.current_kek_generation, &context, &attempt_secret)
        .map_err(|_| BrokerError::unavailable("mcp.oauth.attempt_store_failed"))?;
    state
        .database
        .mcp_begin_oauth_attempt(&NewMcpOAuthAttempt {
            tenant_id: registration.tenant_id,
            id: attempt_id,
            registration_id: registration.id,
            owner_principal_id,
            credential_generation: registration.credential_generation,
            session_id,
            state_digest: &state_digest,
            issuer,
            redirect_path: return_path,
            ciphertext: &encrypted.ciphertext,
            nonce: &encrypted.nonce,
            wrapped_dek: &encrypted.wrapped_dek,
            wrap_nonce: &encrypted.wrap_nonce,
            kek_generation: encrypted.kek_generation as i32,
        })
        .await
        .map_err(|_| BrokerError::unavailable("mcp.oauth.attempt_store_failed"))?;
    let mut authorization_url = Url::parse(
        discovery["authorization_endpoint"]
            .as_str()
            .unwrap_or_default(),
    )
    .map_err(|_| BrokerError::unavailable("mcp.oauth.discovery_invalid"))?;
    authorization_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair(
            "client_id",
            discovery["client_id"].as_str().unwrap_or_default(),
        )
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state_value)
        .append_pair(
            "resource",
            discovery["resource"].as_str().unwrap_or_default(),
        )
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(json!({"authorization_url": authorization_url.as_str()}))
}

async fn complete_oauth(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    claims: &filebelt_mcp_protocol::DelegationClaims,
    arguments: &Value,
) -> Result<Value, BrokerError> {
    let state_digest = decode_hex_digest(
        arguments
            .get("state_digest")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let session_id = parse_uuid(&claims.session_id)?;
    let attempt = state
        .database
        .mcp_consume_oauth_attempt(registration.tenant_id, session_id, &state_digest)
        .await
        .map_err(|_| BrokerError::forbidden("mcp.oauth.state_invalid"))?;
    if attempt.registration_id != registration.id
        || attempt.owner_principal_id != registration.owner_principal_id
        || arguments
            .get("iss")
            .and_then(Value::as_str)
            .is_some_and(|issuer| {
                canonical_oauth_issuer(issuer).ok().as_deref() != Some(attempt.issuer.as_str())
            })
    {
        return Err(BrokerError::forbidden("mcp.oauth.state_invalid"));
    }
    let context = SecretContext {
        tenant_id: registration.tenant_id,
        registration_id: registration.id,
        owner_principal_id: registration.owner_principal_id,
        issuer: &attempt.issuer,
        secret_kind: "oauth_attempt",
        credential_generation: registration.credential_generation,
    };
    let plaintext = state
        .keyring
        .decrypt(
            &context,
            &SecretEnvelope {
                ciphertext: attempt.ciphertext,
                nonce: attempt
                    .nonce
                    .try_into()
                    .map_err(|_| BrokerError::forbidden("mcp.oauth.state_invalid"))?,
                wrapped_dek: attempt.wrapped_dek,
                wrap_nonce: attempt
                    .wrap_nonce
                    .try_into()
                    .map_err(|_| BrokerError::forbidden("mcp.oauth.state_invalid"))?,
                kek_generation: attempt
                    .kek_generation
                    .try_into()
                    .map_err(|_| BrokerError::forbidden("mcp.oauth.state_invalid"))?,
                aad_version: 1,
            },
        )
        .map_err(|_| BrokerError::forbidden("mcp.oauth.state_invalid"))?;
    let secret: Value = serde_json::from_slice(&plaintext)
        .map_err(|_| BrokerError::forbidden("mcp.oauth.state_invalid"))?;
    if arguments.get("error").and_then(Value::as_str).is_some() {
        return Ok(json!({"return_path": attempt.redirect_path, "authorized": false}));
    }
    let code = arguments
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if code.is_empty() || code.len() > 4_096 {
        return Err(BrokerError::bad_request("mcp.oauth.code_invalid"));
    }
    let discovery = oauth_discover(state, registration, &json!({"issuer": attempt.issuer})).await?;
    let token = oauth_token_exchange(
        state,
        registration,
        &OauthTokenExchange {
            token_endpoint: discovery["token_endpoint"].as_str().unwrap_or_default(),
            issuer: discovery["issuer"].as_str().unwrap_or_default(),
            code,
            verifier: secret
                .get("verifier")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            redirect_uri: secret
                .get("redirect_uri")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            resource: secret
                .get("resource")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        },
    )
    .await?;
    let token_bytes = serde_json::to_vec(&token)
        .map_err(|_| BrokerError::unavailable("mcp.oauth.token_invalid"))?;
    store_registration_secret(
        state,
        registration,
        discovery["issuer"].as_str().unwrap_or_default(),
        "oauth_access",
        &token_bytes,
    )
    .await?;
    Ok(json!({"return_path": attempt.redirect_path, "authorized": true}))
}

struct OauthTokenExchange<'a> {
    token_endpoint: &'a str,
    issuer: &'a str,
    code: &'a str,
    verifier: &'a str,
    redirect_uri: &'a str,
    resource: &'a str,
}

async fn oauth_token_exchange(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    exchange: &OauthTokenExchange<'_>,
) -> Result<Value, BrokerError> {
    let client = state
        .oauth_clients
        .get(exchange.issuer)
        .ok_or_else(|| BrokerError::forbidden("mcp.oauth.issuer_not_configured"))?;
    let endpoint = Url::parse(exchange.token_endpoint)
        .map_err(|_| BrokerError::forbidden("mcp.oauth.discovery_invalid"))?;
    let body = {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "authorization_code")
            .append_pair("code", exchange.code)
            .append_pair("redirect_uri", exchange.redirect_uri)
            .append_pair("code_verifier", exchange.verifier)
            .append_pair("resource", exchange.resource);
        if client.client_secret.is_none() {
            form.append_pair("client_id", &client.client_id);
        }
        form.finish().into_bytes()
    };
    let authorization = client.client_secret.as_ref().map(|secret| {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", client.client_id, secret.as_str()))
        )
    });
    let token = gateway_json(
        state,
        registration,
        &endpoint,
        "POST",
        authorization.as_deref(),
        body,
    )
    .await?;
    let access_token = token
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if access_token.is_empty()
        || access_token.len() > 16_384
        || !token
            .get("token_type")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("bearer"))
        || token
            .get("refresh_token")
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() > 16_384)
    {
        return Err(BrokerError::bad_gateway("mcp.oauth.token_invalid"));
    }
    let expires_in = token
        .get("expires_in")
        .and_then(Value::as_i64)
        .filter(|value| (60..=86_400).contains(value))
        .ok_or_else(|| BrokerError::bad_gateway("mcp.oauth.token_invalid"))?;
    if Url::parse(exchange.resource)
        .ok()
        .is_none_or(|value| value.as_str() != exchange.resource)
    {
        return Err(BrokerError::forbidden("mcp.oauth.resource_mismatch"));
    }
    Ok(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "refresh_token": token.get("refresh_token"),
        "expires_at": unix_time()?.saturating_add(expires_in),
        "scope": token.get("scope"),
        "resource": exchange.resource,
    }))
}

async fn oauth_refresh_exchange(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    token_endpoint: &str,
    issuer: &str,
    refresh_token: &str,
    resource: &str,
) -> Result<Value, BrokerError> {
    let client = state
        .oauth_clients
        .get(issuer)
        .ok_or_else(|| BrokerError::forbidden("mcp.oauth.issuer_not_configured"))?;
    let endpoint = Url::parse(token_endpoint)
        .map_err(|_| BrokerError::forbidden("mcp.oauth.discovery_invalid"))?;
    let body = {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", refresh_token)
            .append_pair("resource", resource);
        if client.client_secret.is_none() {
            form.append_pair("client_id", &client.client_id);
        }
        form.finish().into_bytes()
    };
    let authorization = client.client_secret.as_ref().map(|secret| {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", client.client_id, secret.as_str()))
        )
    });
    let token = gateway_json(
        state,
        registration,
        &endpoint,
        "POST",
        authorization.as_deref(),
        body,
    )
    .await?;
    let access_token = token
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 16_384)
        .ok_or_else(|| BrokerError::bad_gateway("mcp.oauth.token_invalid"))?;
    let rotated_refresh = token
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 16_384)
        .ok_or_else(|| BrokerError::bad_gateway("mcp.oauth.refresh_rotation_required"))?;
    if bool::from(refresh_token.as_bytes().ct_eq(rotated_refresh.as_bytes())) {
        return Err(BrokerError::bad_gateway(
            "mcp.oauth.refresh_rotation_required",
        ));
    }
    if !token
        .get("token_type")
        .and_then(Value::as_str)
        .is_some_and(|value| value.eq_ignore_ascii_case("bearer"))
    {
        return Err(BrokerError::bad_gateway("mcp.oauth.token_invalid"));
    }
    let expires_in = token
        .get("expires_in")
        .and_then(Value::as_i64)
        .filter(|value| (60..=86_400).contains(value))
        .ok_or_else(|| BrokerError::bad_gateway("mcp.oauth.token_invalid"))?;
    Ok(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "refresh_token": rotated_refresh,
        "expires_at": unix_time()?.saturating_add(expires_in),
        "scope": token.get("scope"),
        "resource": resource,
    }))
}

async fn gateway_json(
    state: &BrokerState,
    registration: &McpRegistrationRecord,
    target: &Url,
    method: &str,
    authorization: Option<&str>,
    body: Vec<u8>,
) -> Result<Value, BrokerError> {
    if target.scheme() != "https"
        || target.port_or_known_default() != Some(443)
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
    {
        return Err(BrokerError::forbidden("mcp.oauth.endpoint_invalid"));
    }
    let mut request = state
        .gateway
        .post(state.gateway_url.clone())
        .header("x-filebelt-mcp-target", target.as_str())
        .header(
            "x-filebelt-mcp-trust-profile",
            registration.trust_profile.as_deref().unwrap_or_default(),
        )
        .header("x-filebelt-mcp-upstream-method", method)
        .header(header::ACCEPT, "application/json")
        .header(
            header::CONTENT_TYPE,
            if method == "POST" {
                "application/x-www-form-urlencoded"
            } else {
                "application/octet-stream"
            },
        )
        .body(body);
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.oauth.upstream_unavailable"))?;
    if !response.status().is_success()
        || !response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"))
    {
        return Err(BrokerError::bad_gateway("mcp.oauth.upstream_invalid"));
    }
    if response
        .content_length()
        .is_some_and(|length| length > 1_048_576)
    {
        return Err(BrokerError::bad_gateway("mcp.oauth.upstream_invalid"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.oauth.upstream_invalid"))?
    {
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > 1_048_576)
        {
            return Err(BrokerError::bad_gateway("mcp.oauth.upstream_invalid"));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|_| BrokerError::bad_gateway("mcp.oauth.upstream_invalid"))
}

fn oauth_well_known_url(issuer: &Url, suffix: &str) -> Url {
    let mut url = issuer.clone();
    let issuer_path = issuer.path().trim_end_matches('/');
    url.set_path(&format!("/.well-known/{suffix}{issuer_path}"));
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn canonical_oauth_issuer(value: &str) -> Result<String, BrokerError> {
    let issuer =
        Url::parse(value).map_err(|_| BrokerError::forbidden("mcp.oauth.issuer_invalid"))?;
    if issuer.scheme() != "https"
        || issuer.host_str().is_none()
        || issuer.port_or_known_default() != Some(443)
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err(BrokerError::forbidden("mcp.oauth.issuer_invalid"));
    }
    Ok(issuer.as_str().trim_end_matches('/').to_owned())
}

fn oauth_endpoint(metadata: &Value, name: &str, issuer: &str) -> Result<String, BrokerError> {
    let endpoint = metadata
        .get(name)
        .and_then(Value::as_str)
        .and_then(|value| Url::parse(value).ok())
        .ok_or_else(|| BrokerError::forbidden("mcp.oauth.discovery_invalid"))?;
    let issuer = Url::parse(&format!("{issuer}/"))
        .map_err(|_| BrokerError::forbidden("mcp.oauth.discovery_invalid"))?;
    if endpoint.scheme() != "https"
        || endpoint.port_or_known_default() != Some(443)
        || endpoint.origin() != issuer.origin()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(BrokerError::forbidden("mcp.oauth.discovery_invalid"));
    }
    Ok(endpoint.into())
}

fn decode_hex_digest(value: &str) -> Result<[u8; 32], BrokerError> {
    if value.len() != 64 {
        return Err(BrokerError::bad_request("mcp.oauth.state_invalid"));
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, BrokerError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(BrokerError::bad_request("mcp.oauth.state_invalid")),
    }
}

async fn stdio_operation(
    state: &BrokerState,
    request: &InvocationRequest,
    registration: &McpRegistrationRecord,
    arguments_json: &[u8],
    lifecycle: Arc<RunnerLifecycle>,
) -> Result<Value, BrokerError> {
    let runners = state
        .runners
        .as_ref()
        .ok_or_else(|| BrokerError::unavailable("mcp.runner.disabled"))?;
    let invocation_id = Uuid::parse_str(&request.request_id)
        .map_err(|_| BrokerError::bad_request("mcp.request.invalid"))?;
    let catalog_entry = registration
        .catalog_entry
        .as_deref()
        .ok_or_else(|| BrokerError::forbidden("mcp.runner.catalog_missing"))?;
    reserve_runner_lifecycle(runners, invocation_id, lifecycle.clone()).await?;
    let mut cleanup = RunnerCleanupGuard {
        runners: runners.clone(),
        lifecycle: lifecycle.clone(),
        invocation_id,
        armed: true,
    };
    let mut bootstrap_token = Zeroizing::new(vec![0_u8; 32]);
    SystemRandom::new()
        .fill(bootstrap_token.as_mut_slice())
        .map_err(|_| BrokerError::unavailable("mcp.random.unavailable"))?;
    let bootstrap_digest = *blake3::hash(bootstrap_token.as_slice()).as_bytes();
    let (sender, receiver) = oneshot::channel();
    insert_pending_runner(
        runners,
        invocation_id,
        PendingRunner {
            bootstrap_digest,
            sender,
        },
    )
    .await?;
    let create = CreateRunnerLeaseRequest {
        invocation_id: invocation_id.to_string(),
        tenant_id: registration.tenant_id.to_string(),
        principal_id: registration.owner_principal_id.to_string(),
        catalog_entry: catalog_entry.to_owned(),
        bootstrap_token: std::mem::take(bootstrap_token.as_mut()),
    };
    let create_runners = runners.clone();
    let create_lifecycle = lifecycle.clone();
    let created = tokio::spawn(async move {
        create_runner_lifecycle(create_runners, invocation_id, create_lifecycle, create).await
    })
    .await
    .map_err(|_| BrokerError::unavailable("mcp.runner.controller_unavailable"))??;
    if created.resource_name != format!("filebelt-mcp-{}", invocation_id.simple()) {
        return Err(BrokerError::unavailable("mcp.runner.controller_invalid"));
    }
    let stream = match tokio::time::timeout(Duration::from_secs(30), receiver).await {
        Ok(Ok(stream)) => stream,
        _ => {
            if cancel_runner_lifecycle(runners, invocation_id, lifecycle.clone())
                .await
                .is_ok()
            {
                cleanup.disarm();
            }
            return Err(BrokerError::gateway_timeout("mcp.runner.start_timeout"));
        }
    };
    let result =
        stdio_session_operation(state, request, arguments_json, invocation_id, stream).await;
    let deletion = cancel_runner_lifecycle(runners, invocation_id, lifecycle).await;
    if deletion.is_ok() {
        cleanup.disarm();
    }
    if result.is_ok() && deletion.is_err() {
        return Err(BrokerError::unavailable("mcp.runner.cleanup_failed"));
    }
    result
}

impl RunnerCleanupGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RunnerCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let runners = self.runners.clone();
        let lifecycle = self.lifecycle.clone();
        let invocation_id = self.invocation_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) =
                    cancel_runner_lifecycle(&runners, invocation_id, lifecycle).await
                {
                    tracing::warn!(
                        code = error.code,
                        invocation_id = %invocation_id,
                        "MCP runner cancellation cleanup failed"
                    );
                }
            });
        }
    }
}

async fn create_runner_lifecycle(
    runners: Arc<RunnerBrokerState>,
    invocation_id: Uuid,
    lifecycle: Arc<RunnerLifecycle>,
    create: CreateRunnerLeaseRequest,
) -> Result<CreateRunnerLeaseResponse, BrokerError> {
    let _mutation = lifecycle.mutation.lock().await;
    if lifecycle.cancelled.load(Ordering::Acquire) {
        return Err(BrokerError::unavailable("mcp.runner.request_cancelled"));
    }
    let response = runners
        .controller
        .post(runners.create_url.clone())
        .header(header::CONTENT_TYPE, PROTOBUF_CONTENT_TYPE)
        .body(create.encode_to_vec())
        .send()
        .await
        .map_err(|_| BrokerError::unavailable("mcp.runner.controller_unavailable"))?;
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        return Err(BrokerError::too_many_requests("mcp.runner.capacity"));
    }
    if !matches!(response.status(), StatusCode::OK | StatusCode::ACCEPTED) {
        return Err(BrokerError::unavailable(
            "mcp.runner.controller_unavailable",
        ));
    }
    let response_body = bounded_protobuf_body(
        response,
        "mcp.runner.controller_unavailable",
        "mcp.runner.controller_invalid",
    )
    .await?;
    let created = CreateRunnerLeaseResponse::decode(response_body.as_slice())
        .map_err(|_| BrokerError::unavailable("mcp.runner.controller_invalid"))?;
    if created.invocation_id != invocation_id.to_string() {
        return Err(BrokerError::unavailable("mcp.runner.controller_invalid"));
    }
    Ok(created)
}

async fn reserve_runner_lifecycle(
    runners: &Arc<RunnerBrokerState>,
    invocation_id: Uuid,
    lifecycle: Arc<RunnerLifecycle>,
) -> Result<(), BrokerError> {
    let _mutation = lifecycle.mutation.lock().await;
    if lifecycle.cancelled.load(Ordering::Acquire) {
        return Err(BrokerError::unavailable("mcp.runner.request_cancelled"));
    }
    let admission = runners
        .admission
        .as_ref()
        .ok_or_else(|| BrokerError::unavailable("mcp.runner.admission_unavailable"))?;
    admission
        .database
        .mcp_reserve_runner_slot(NewMcpRunnerSlotReservation {
            tenant_id: lifecycle.tenant_id,
            invocation_id,
            principal_id: lifecycle.principal_id,
            tenant_limit: admission.tenant_limit,
            principal_limit: admission.principal_limit,
            lease_seconds: admission.reservation_seconds,
        })
        .await
        .map_err(|error| match error {
            DatabaseError::AdmissionLimited => {
                BrokerError::too_many_requests("mcp.runner.capacity")
            }
            _ => BrokerError::unavailable("mcp.runner.admission_unavailable"),
        })?;
    lifecycle.reserved.store(true, Ordering::Release);
    Ok(())
}

async fn cancel_runner_lifecycle(
    runners: &Arc<RunnerBrokerState>,
    invocation_id: Uuid,
    lifecycle: Arc<RunnerLifecycle>,
) -> Result<(), BrokerError> {
    lifecycle.cancelled.store(true, Ordering::Release);
    let _mutation = lifecycle.mutation.lock().await;
    runners.pending.lock().await.remove(&invocation_id);
    if lifecycle.cleanup_complete.load(Ordering::Acquire) {
        return Ok(());
    }
    delete_runner(runners, invocation_id).await?;
    if lifecycle.reserved.load(Ordering::Acquire) {
        let admission = runners
            .admission
            .as_ref()
            .ok_or_else(|| BrokerError::unavailable("mcp.runner.cleanup_failed"))?;
        admission
            .database
            .mcp_release_runner_slot_after_confirmed_delete(
                lifecycle.tenant_id,
                invocation_id,
                lifecycle.principal_id,
            )
            .await
            .map_err(|_| BrokerError::unavailable("mcp.runner.cleanup_failed"))?;
        lifecycle.reserved.store(false, Ordering::Release);
    }
    lifecycle.cleanup_complete.store(true, Ordering::Release);
    Ok(())
}

async fn runner_reconciliation_loop(runners: Arc<RunnerBrokerState>) {
    let Some(admission) = runners.admission.as_ref() else {
        return;
    };
    loop {
        match admission.database.mcp_expired_runner_slots(100).await {
            Ok(reservations) => {
                for reservation in reservations {
                    if delete_runner(&runners, reservation.invocation_id)
                        .await
                        .is_ok()
                        && let Err(error) = admission
                            .database
                            .mcp_release_runner_slot_after_confirmed_delete(
                                reservation.tenant_id,
                                reservation.invocation_id,
                                reservation.principal_id,
                            )
                            .await
                    {
                        tracing::warn!(
                            invocation_id = %reservation.invocation_id,
                            %error,
                            "MCP runner reservation release failed"
                        );
                    }
                }
            }
            Err(error) => tracing::warn!(%error, "MCP runner reconciliation query failed"),
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

async fn bounded_protobuf_body(
    mut response: reqwest::Response,
    transport_error: &'static str,
    invalid_error: &'static str,
) -> Result<Vec<u8>, BrokerError> {
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(PROTOBUF_CONTENT_TYPE)
        || response
            .content_length()
            .is_some_and(|length| length > CONTROLLER_RESPONSE_MAX_BYTES as u64)
    {
        return Err(BrokerError::unavailable(invalid_error));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BrokerError::unavailable(transport_error))?
    {
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > CONTROLLER_RESPONSE_MAX_BYTES)
        {
            return Err(BrokerError::unavailable(invalid_error));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn delete_runner(
    runners: &RunnerBrokerState,
    invocation_id: Uuid,
) -> Result<(), BrokerError> {
    let request = DeleteRunnerLeaseRequest {
        invocation_id: invocation_id.to_string(),
    };
    let response = runners
        .controller
        .post(runners.delete_url.clone())
        .header(header::CONTENT_TYPE, PROTOBUF_CONTENT_TYPE)
        .body(request.encode_to_vec())
        .send()
        .await
        .map_err(|_| BrokerError::unavailable("mcp.runner.cleanup_failed"))?;
    if response.status() != StatusCode::OK {
        return Err(BrokerError::unavailable("mcp.runner.cleanup_failed"));
    }
    let response = bounded_protobuf_body(
        response,
        "mcp.runner.cleanup_failed",
        "mcp.runner.cleanup_failed",
    )
    .await?;
    let response = DeleteRunnerLeaseResponse::decode(response.as_slice())
        .map_err(|_| BrokerError::unavailable("mcp.runner.cleanup_failed"))?;
    if response.invocation_id != invocation_id.to_string() {
        return Err(BrokerError::unavailable("mcp.runner.cleanup_failed"));
    }
    Ok(())
}

async fn stdio_session_operation(
    state: &BrokerState,
    request: &InvocationRequest,
    arguments_json: &[u8],
    invocation_id: Uuid,
    stream: RelayStream,
) -> Result<Value, BrokerError> {
    let mut session = StdioSession::new(
        stream,
        invocation_id,
        state.limits.encoded_wire_bytes as usize,
    );
    let initialize = session
        .request(
            1,
            "initialize",
            json!({
                "protocolVersion": request.protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "FileBelt MCP broker", "version": env!("CARGO_PKG_VERSION")}
            }),
        )
        .await?;
    let initialized: InitializeResult = serde_json::from_value(initialize.clone())
        .map_err(|_| BrokerError::bad_gateway("mcp.runner.initialize_invalid"))?;
    let negotiated = initialized.protocol_version.to_string();
    if negotiated != request.protocol_version
        || !matches!(negotiated.as_str(), CURRENT_PROTOCOL | FALLBACK_PROTOCOL)
    {
        return Err(BrokerError::bad_gateway("mcp.runner.protocol_mismatch"));
    }
    session
        .notify("notifications/initialized", json!({}))
        .await?;
    if request.capability_name == "$test" {
        let result = json!({
            "protocolVersion": negotiated,
            "serverInfo": initialized.server_info,
            "capabilities": initialized.capabilities,
        });
        session.close().await?;
        return Ok(result);
    }
    if request.capability_name == "$discover" {
        let tools = session.request(2, "tools/list", json!({})).await?;
        let resources = session.request(3, "resources/list", json!({})).await?;
        let prompts = session.request(4, "prompts/list", json!({})).await?;
        validate_discovery(&tools, &resources, &prompts)?;
        let result = json!({
            "protocolVersion": negotiated,
            "tools": tools,
            "resources": resources,
            "prompts": prompts,
        });
        session.close().await?;
        return Ok(result);
    }
    let arguments: Value = serde_json::from_slice(arguments_json)
        .map_err(|_| BrokerError::bad_request("mcp.arguments.invalid"))?;
    let (method, parameters) = invocation_parameters(request, arguments)?;
    let result = session.request(5, method, parameters).await?;
    validate_result(request.primitive, &result)?;
    session.close().await?;
    Ok(result)
}

struct StdioSession {
    stream: RelayStream,
    invocation_id: Uuid,
    outbound_sequence: u64,
    inbound_sequence: u64,
    buffered: Vec<u8>,
    limit: usize,
}

impl StdioSession {
    fn new(stream: RelayStream, invocation_id: Uuid, limit: usize) -> Self {
        Self {
            stream,
            invocation_id,
            outbound_sequence: 1,
            inbound_sequence: 1,
            buffered: Vec::new(),
            limit,
        }
    }

    async fn request(
        &mut self,
        id: u64,
        method: &str,
        params: Value,
    ) -> Result<Value, BrokerError> {
        self.send_json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await?;
        for _ in 0..MAX_STDIO_MESSAGES_PER_REQUEST {
            let value = self.read_json().await?;
            if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                return Err(BrokerError::bad_gateway("mcp.runner.response_invalid"));
            }
            let Some(response_id) = value.get("id") else {
                continue;
            };
            if response_id != &Value::from(id) {
                return Err(BrokerError::bad_gateway("mcp.runner.response_mismatch"));
            }
            return match (value.get("result"), value.get("error")) {
                (Some(result), None) => Ok(result.clone()),
                (None, Some(_)) => Err(BrokerError::bad_gateway("mcp.runner.remote_error")),
                _ => Err(BrokerError::bad_gateway("mcp.runner.response_invalid")),
            };
        }
        Err(BrokerError::bad_gateway(
            "mcp.runner.unexpected_message_limit",
        ))
    }

    async fn notify(&mut self, method: &str, params: Value) -> Result<(), BrokerError> {
        self.send_json(&json!({"jsonrpc":"2.0","method":method,"params":params}))
            .await
    }

    async fn send_json(&mut self, value: &Value) -> Result<(), BrokerError> {
        let mut payload = serde_json::to_vec(value)
            .map_err(|_| BrokerError::bad_request("mcp.request.invalid"))?;
        payload.push(b'\n');
        if payload.len() > self.limit {
            return Err(BrokerError::bad_request("mcp.request.too_large"));
        }
        for payload in payload.chunks(MAX_RUNNER_RELAY_PAYLOAD_BYTES) {
            let frame = RunnerRelayFrame {
                invocation_id: self.invocation_id.to_string(),
                sequence: self.take_outbound_sequence()?,
                kind: RunnerRelayFrameKind::Data as i32,
                payload: payload.to_vec(),
                code: String::new(),
                terminal: false,
            };
            let message = encode_runner_relay_frame(&frame)
                .map_err(|_| BrokerError::bad_request("mcp.runner.frame_invalid"))?;
            write_runner_message(&mut self.stream, &message).await?;
        }
        Ok(())
    }

    async fn read_json(&mut self) -> Result<Value, BrokerError> {
        loop {
            if let Some(position) = self.buffered.iter().position(|byte| *byte == b'\n') {
                let line = self.buffered.drain(..=position).collect::<Vec<_>>();
                if line.len() <= 1 {
                    continue;
                }
                return serde_json::from_slice(&line[..line.len() - 1])
                    .map_err(|_| BrokerError::bad_gateway("mcp.runner.response_invalid"));
            }
            let message = read_runner_message(&mut self.stream).await?;
            let frame = decode_runner_relay_frame(&message)
                .map_err(|_| BrokerError::bad_gateway("mcp.runner.frame_invalid"))?;
            if frame.invocation_id != self.invocation_id.to_string()
                || frame.sequence != self.inbound_sequence
            {
                return Err(BrokerError::bad_gateway("mcp.runner.sequence_invalid"));
            }
            self.inbound_sequence = self
                .inbound_sequence
                .checked_add(1)
                .ok_or_else(|| BrokerError::bad_gateway("mcp.runner.sequence_invalid"))?;
            match RunnerRelayFrameKind::try_from(frame.kind) {
                Ok(RunnerRelayFrameKind::Data) => {
                    if self
                        .buffered
                        .len()
                        .checked_add(frame.payload.len())
                        .is_none_or(|length| length > self.limit)
                    {
                        return Err(BrokerError::bad_gateway("mcp.runner.response_too_large"));
                    }
                    self.buffered.extend_from_slice(&frame.payload);
                }
                Ok(RunnerRelayFrameKind::Close | RunnerRelayFrameKind::Error) => {
                    return Err(BrokerError::bad_gateway("mcp.runner.closed"));
                }
                _ => return Err(BrokerError::bad_gateway("mcp.runner.frame_invalid")),
            }
        }
    }

    async fn close(&mut self) -> Result<(), BrokerError> {
        let frame = RunnerRelayFrame {
            invocation_id: self.invocation_id.to_string(),
            sequence: self.take_outbound_sequence()?,
            kind: RunnerRelayFrameKind::Close as i32,
            payload: Vec::new(),
            code: String::new(),
            terminal: true,
        };
        let message = encode_runner_relay_frame(&frame)
            .map_err(|_| BrokerError::bad_request("mcp.runner.frame_invalid"))?;
        write_runner_message(&mut self.stream, &message).await
    }

    fn take_outbound_sequence(&mut self) -> Result<u64, BrokerError> {
        let sequence = self.outbound_sequence;
        self.outbound_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| BrokerError::bad_request("mcp.runner.frame_invalid"))?;
        Ok(sequence)
    }
}

async fn remote_operation(
    state: &BrokerState,
    request: &InvocationRequest,
    registration: &McpRegistrationRecord,
    endpoint: &Url,
    credential: Option<&DecryptedCredential>,
    arguments_json: &[u8],
) -> Result<Value, BrokerError> {
    let mut session = RemoteSession::new(
        state.gateway.clone(),
        state.gateway_url.clone(),
        endpoint,
        registration.trust_profile.as_deref().unwrap_or_default(),
        request.protocol_version.as_str(),
        credential,
        state.limits.result_bytes as usize,
    )?;
    let initialize = session
        .request(
            1,
            "initialize",
            json!({
                "protocolVersion": request.protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "FileBelt MCP broker", "version": env!("CARGO_PKG_VERSION")}
            }),
            Duration::from_secs(state.limits.connect_timeout_seconds),
        )
        .await?;
    let initialized: InitializeResult = serde_json::from_value(initialize.clone())
        .map_err(|_| BrokerError::bad_gateway("mcp.remote.initialize_invalid"))?;
    let negotiated = initialized.protocol_version.to_string();
    if negotiated != request.protocol_version
        || !matches!(negotiated.as_str(), CURRENT_PROTOCOL | FALLBACK_PROTOCOL)
    {
        return Err(BrokerError::bad_gateway("mcp.remote.protocol_mismatch"));
    }
    session
        .notify("notifications/initialized", json!({}))
        .await?;
    if request.capability_name == "$test" {
        return Ok(json!({
            "protocolVersion": negotiated,
            "serverInfo": initialized.server_info,
            "capabilities": initialized.capabilities,
        }));
    }
    if request.capability_name == "$discover" {
        let tools = session
            .request(
                2,
                "tools/list",
                json!({}),
                Duration::from_secs(state.limits.discovery_timeout_seconds),
            )
            .await?;
        let resources = session
            .request(
                3,
                "resources/list",
                json!({}),
                Duration::from_secs(state.limits.discovery_timeout_seconds),
            )
            .await?;
        let prompts = session
            .request(
                4,
                "prompts/list",
                json!({}),
                Duration::from_secs(state.limits.discovery_timeout_seconds),
            )
            .await?;
        validate_discovery(&tools, &resources, &prompts)?;
        return Ok(json!({
            "protocolVersion": negotiated,
            "tools": tools,
            "resources": resources,
            "prompts": prompts,
        }));
    }
    let arguments: Value = serde_json::from_slice(arguments_json)
        .map_err(|_| BrokerError::bad_request("mcp.arguments.invalid"))?;
    let (method, parameters) = invocation_parameters(request, arguments)?;
    let result = session
        .request(
            5,
            method,
            parameters,
            Duration::from_secs(state.limits.operation_timeout_seconds),
        )
        .await?;
    validate_result(request.primitive, &result)?;
    Ok(result)
}

struct RemoteSession {
    client: Client,
    gateway: Url,
    target: HeaderValue,
    trust_profile: HeaderValue,
    protocol: HeaderValue,
    authorization: Option<HeaderValue>,
    api_key: Option<HeaderValue>,
    session_id: Option<HeaderValue>,
    limit: usize,
}

impl RemoteSession {
    fn new(
        client: Client,
        gateway: Url,
        endpoint: &Url,
        trust_profile: &str,
        protocol: &str,
        credential: Option<&DecryptedCredential>,
        limit: usize,
    ) -> Result<Self, BrokerError> {
        let credential_header = credential
            .map(|secret| {
                let text = std::str::from_utf8(secret.secret.as_slice())
                    .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"))?;
                HeaderValue::from_str(text)
                    .map(|value| (secret.kind.as_str(), value))
                    .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"))
            })
            .transpose()?;
        let authorization = match credential_header.as_ref() {
            Some(("bearer" | "oauth_access", value)) => Some(
                HeaderValue::from_str(&format!(
                    "Bearer {}",
                    value
                        .to_str()
                        .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"))?
                ))
                .map_err(|_| BrokerError::forbidden("mcp.credential.invalid"))?,
            ),
            Some(("api_key", _)) | None => None,
            Some(_) => return Err(BrokerError::forbidden("mcp.credential.invalid")),
        };
        let api_key = match credential_header {
            Some(("api_key", value)) => Some(value),
            _ => None,
        };
        Ok(Self {
            client,
            gateway,
            target: HeaderValue::from_str(endpoint.as_str())
                .map_err(|_| BrokerError::forbidden("mcp.endpoint.invalid"))?,
            trust_profile: HeaderValue::from_str(trust_profile)
                .map_err(|_| BrokerError::forbidden("mcp.trust_profile.invalid"))?,
            protocol: HeaderValue::from_str(protocol)
                .map_err(|_| BrokerError::bad_request("mcp.protocol.invalid"))?,
            authorization,
            api_key,
            session_id: None,
            limit,
        })
    }

    async fn request(
        &mut self,
        id: u64,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, BrokerError> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|_| BrokerError::bad_request("mcp.request.invalid"))?;
        let response = self.send(body, timeout).await?;
        let value = parse_remote_response(response, self.limit).await?;
        if value.get("id") != Some(&Value::from(id)) {
            return Err(BrokerError::bad_gateway("mcp.remote.response_mismatch"));
        }
        if value.get("error").is_some() {
            return Err(BrokerError::bad_gateway("mcp.remote.error"));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| BrokerError::bad_gateway("mcp.remote.response_invalid"))
    }

    async fn notify(&mut self, method: &str, params: Value) -> Result<(), BrokerError> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }))
        .map_err(|_| BrokerError::bad_request("mcp.request.invalid"))?;
        let response = self.send(body, Duration::from_secs(5)).await?;
        if !response.status().is_success() {
            return Err(BrokerError::bad_gateway("mcp.remote.notification_failed"));
        }
        Ok(())
    }

    async fn send(
        &mut self,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<reqwest::Response, BrokerError> {
        let mut builder = self
            .client
            .post(self.gateway.clone())
            .timeout(timeout)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", self.protocol.clone())
            .header("x-filebelt-mcp-target", self.target.clone())
            .header("x-filebelt-mcp-trust-profile", self.trust_profile.clone())
            .header("x-filebelt-mcp-upstream-method", "POST")
            .body(body);
        if let Some(value) = &self.authorization {
            builder = builder.header(header::AUTHORIZATION, value.clone());
        }
        if let Some(value) = &self.api_key {
            builder = builder.header("x-api-key", value.clone());
        }
        if let Some(value) = &self.session_id {
            builder = builder.header("mcp-session-id", value.clone());
        }
        let response = builder
            .send()
            .await
            .map_err(|_| BrokerError::bad_gateway("mcp.remote.unavailable"))?;
        if let Some(value) = response.headers().get("mcp-session-id") {
            self.session_id = Some(value.clone());
        }
        if !response.status().is_success() {
            return Err(BrokerError::bad_gateway("mcp.remote.http_error"));
        }
        Ok(response)
    }
}

async fn parse_remote_response(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Value, BrokerError> {
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(BrokerError::bad_gateway("mcp.remote.message_too_large"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BrokerError::bad_gateway("mcp.remote.response_invalid"))?
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > limit)
        {
            return Err(BrokerError::bad_gateway("mcp.remote.message_too_large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    let payload = if content_type.starts_with("text/event-stream") {
        parse_sse_data(&bytes)?
    } else if content_type.starts_with("application/json") {
        bytes.to_vec()
    } else {
        return Err(BrokerError::bad_gateway("mcp.remote.content_type"));
    };
    serde_json::from_slice(&payload)
        .map_err(|_| BrokerError::bad_gateway("mcp.remote.response_invalid"))
}

fn parse_sse_data(bytes: &[u8]) -> Result<Vec<u8>, BrokerError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| BrokerError::bad_gateway("mcp.remote.sse_invalid"))?;
    let mut output = Vec::new();
    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            if !output.is_empty() {
                output.push(b'\n');
            }
            output.extend_from_slice(data.trim_start().as_bytes());
        }
    }
    if output.is_empty() {
        return Err(BrokerError::bad_gateway("mcp.remote.sse_invalid"));
    }
    Ok(output)
}

fn validate_discovery(
    tools: &Value,
    resources: &Value,
    prompts: &Value,
) -> Result<(), BrokerError> {
    let tool_items = tools
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| BrokerError::bad_gateway("mcp.remote.capabilities_invalid"))?;
    if tool_items.len() > 1_000
        || tool_items.iter().any(|tool| {
            !valid_capability_name(tool.get("name"))
                || tool
                    .pointer("/annotations/readOnlyHint")
                    .and_then(Value::as_bool)
                    != Some(true)
        })
    {
        return Err(BrokerError::bad_gateway(
            "mcp.remote.capabilities_prohibited",
        ));
    }
    for (document, key) in [(resources, "resources"), (prompts, "prompts")] {
        let values = document
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| BrokerError::bad_gateway("mcp.remote.capabilities_invalid"))?;
        if values.len() > 1_000
            || values
                .iter()
                .any(|item| !valid_capability_name(item.get("name")))
        {
            return Err(BrokerError::bad_gateway("mcp.remote.capabilities_invalid"));
        }
    }
    Ok(())
}

fn valid_capability_name(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|name| !name.is_empty() && name.len() <= 256)
}

fn validate_result(primitive: i32, result: &Value) -> Result<(), BrokerError> {
    if McpPrimitive::try_from(primitive).ok() == Some(McpPrimitive::Tool) {
        let typed: CallToolResult = serde_json::from_value(result.clone())
            .map_err(|_| BrokerError::bad_gateway("mcp.remote.result_invalid"))?;
        if typed.content.len() > 128 {
            return Err(BrokerError::bad_gateway("mcp.remote.result_invalid"));
        }
    }
    validate_content_blocks(result)
}

fn validate_content_blocks(value: &Value) -> Result<(), BrokerError> {
    let Some(content) = value.get("content").and_then(Value::as_array) else {
        return Ok(());
    };
    for block in content {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if block
                    .get("text")
                    .and_then(Value::as_str)
                    .is_none_or(|text| text.len() > 1_048_576)
                {
                    return Err(BrokerError::bad_gateway("mcp.remote.result_invalid"));
                }
            }
            Some("image") => validate_media(block, &["image/png", "image/jpeg", "image/webp"])?,
            Some("audio") => validate_media(block, &["audio/mpeg", "audio/ogg", "audio/wav"])?,
            _ => {
                return Err(BrokerError::bad_gateway(
                    "mcp.remote.result_type_prohibited",
                ));
            }
        }
    }
    Ok(())
}

fn validate_media(block: &Value, allowed: &[&str]) -> Result<(), BrokerError> {
    let media_type = block
        .get("mimeType")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let data = block
        .get("data")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !allowed.contains(&media_type)
        || data.len() > 5_592_408
        || STANDARD
            .decode(data)
            .ok()
            .is_none_or(|bytes| bytes.len() > 4_194_304)
    {
        return Err(BrokerError::bad_gateway("mcp.remote.media_prohibited"));
    }
    Ok(())
}

fn parse_semantic_markdown_input(bytes: &[u8]) -> Result<Option<Value>, BrokerError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| BrokerError::bad_request("mcp.semantic.invalid"))?;
    validate_semantic_markdown_input(&value)
        .map_err(|_| BrokerError::bad_request("mcp.semantic.invalid"))?;
    Ok(Some(value))
}

fn validate_semantic_markdown_input(value: &Value) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != 4
        || object.get("format").and_then(Value::as_str) != Some("filebelt.markdown.semantic.v1")
        || object
            .get("node_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .is_none()
        || object
            .get("base_version_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .is_none()
    {
        return Err(());
    }
    let markdown = object.get("markdown").and_then(Value::as_str).ok_or(())?;
    if markdown.len() > MAX_SEMANTIC_MARKDOWN_BYTES
        || markdown.contains('\0')
        || markdown.contains('\r')
    {
        return Err(());
    }
    Ok(())
}

fn validate_semantic_markdown_output(value: &Value) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != 2
        || object.get("format").and_then(Value::as_str) != Some("filebelt.markdown.semantic.v1")
    {
        return Err(());
    }
    let markdown = object.get("markdown").and_then(Value::as_str).ok_or(())?;
    if markdown.len() > MAX_SEMANTIC_MARKDOWN_BYTES
        || markdown.contains('\0')
        || markdown.contains('\r')
    {
        return Err(());
    }
    Ok(())
}

fn invocation_parameters(
    request: &InvocationRequest,
    arguments: Value,
) -> Result<(&'static str, Value), BrokerError> {
    let metadata = parse_semantic_markdown_input(&request.semantic_input_json)?
        .map(|semantic| json!({"filebelt/semantic": semantic}));
    let mut parameters = match McpPrimitive::try_from(request.primitive).ok() {
        Some(McpPrimitive::Tool) => (
            "tools/call",
            json!({"name": request.capability_name, "arguments": arguments}),
        ),
        Some(McpPrimitive::Resource) => ("resources/read", json!({"uri": request.capability_name})),
        Some(McpPrimitive::Prompt) => (
            "prompts/get",
            json!({"name": request.capability_name, "arguments": arguments}),
        ),
        _ => return Err(BrokerError::bad_request("mcp.primitive.invalid")),
    };
    if let Some(metadata) = metadata {
        parameters
            .1
            .as_object_mut()
            .ok_or_else(|| BrokerError::bad_request("mcp.arguments.invalid"))?
            .insert("_meta".into(), metadata);
    }
    Ok(parameters)
}

fn semantic_output(result: &Value) -> Result<Option<Vec<u8>>, BrokerError> {
    let Some(value) = result
        .get("_meta")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("filebelt/semantic"))
    else {
        return Ok(None);
    };
    validate_semantic_markdown_output(value)
        .map_err(|_| BrokerError::bad_gateway("mcp.remote.semantic_invalid"))?;
    serde_json::to_vec(value)
        .map(Some)
        .map_err(|_| BrokerError::bad_gateway("mcp.remote.semantic_invalid"))
}

fn result_frames(
    request_id: &str,
    result: Value,
    limit: usize,
) -> Result<Vec<InvocationFrame>, BrokerError> {
    let payload = serde_json::to_vec(&result)
        .map_err(|_| BrokerError::bad_gateway("mcp.remote.result_invalid"))?;
    if payload.len() > limit {
        return Err(BrokerError::bad_gateway("mcp.remote.result_too_large"));
    }
    let semantic = semantic_output(&result)?;
    let mut frames = vec![
        InvocationFrame {
            request_id: request_id.to_owned(),
            sequence: 1,
            kind: InvocationFrameKind::Accepted as i32,
            payload: Vec::new(),
            code: String::new(),
            terminal: false,
        },
        InvocationFrame {
            request_id: request_id.to_owned(),
            sequence: 2,
            kind: InvocationFrameKind::Json as i32,
            payload,
            code: String::new(),
            terminal: false,
        },
    ];
    if let Some(payload) = semantic {
        frames.push(InvocationFrame {
            request_id: request_id.to_owned(),
            sequence: 3,
            kind: InvocationFrameKind::Semantic as i32,
            payload,
            code: String::new(),
            terminal: false,
        });
    }
    frames.push(InvocationFrame {
        request_id: request_id.to_owned(),
        sequence: frames.len() as u64 + 1,
        kind: InvocationFrameKind::Complete as i32,
        payload: Vec::new(),
        code: String::new(),
        terminal: true,
    });
    Ok(frames)
}

impl ConcurrencyLimits {
    async fn acquire(
        &self,
        principal: Uuid,
        registration: Uuid,
    ) -> Result<InvocationPermits, BrokerError> {
        let queue = self
            .queue
            .clone()
            .try_acquire_owned()
            .map_err(|_| BrokerError::too_many_requests("mcp.queue.full"))?;
        let global = self
            .global
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| BrokerError::unavailable("mcp.broker.draining"))?;
        let principal_semaphore =
            keyed_semaphore(&self.principals, principal, self.principal_limit).await;
        let registration_semaphore =
            keyed_semaphore(&self.registrations, registration, self.registration_limit).await;
        let principal_permit = principal_semaphore
            .acquire_owned()
            .await
            .map_err(|_| BrokerError::unavailable("mcp.broker.draining"))?;
        let registration_permit = registration_semaphore
            .acquire_owned()
            .await
            .map_err(|_| BrokerError::unavailable("mcp.broker.draining"))?;
        drop(queue);
        Ok(InvocationPermits {
            _global: global,
            _principal: principal_permit,
            _registration: registration_permit,
        })
    }
}

async fn keyed_semaphore(
    values: &Mutex<HashMap<Uuid, Weak<Semaphore>>>,
    key: Uuid,
    permits: usize,
) -> Arc<Semaphore> {
    let mut values = values.lock().await;
    if let Some(existing) = values.get(&key).and_then(Weak::upgrade) {
        return existing;
    }
    values.retain(|_, value| value.strong_count() > 0);
    let semaphore = Arc::new(Semaphore::new(permits));
    values.insert(key, Arc::downgrade(&semaphore));
    semaphore
}

fn gateway_client(config: &Config) -> Result<Client> {
    let egress = &config.mcp.egress;
    let certificate = std::fs::read(
        egress
            .client_certificate_chain_file
            .as_ref()
            .ok_or_else(|| anyhow!("gateway client certificate is absent"))?,
    )?;
    let private_key = std::fs::read(
        egress
            .client_private_key_file
            .as_ref()
            .ok_or_else(|| anyhow!("gateway client key is absent"))?,
    )?;
    let mut identity_pem = certificate;
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&private_key);
    let identity =
        Identity::from_pem(&identity_pem).context("gateway client identity is invalid")?;
    let ca_bytes = std::fs::read(
        egress
            .server_ca_file
            .as_ref()
            .ok_or_else(|| anyhow!("gateway CA is absent"))?,
    )?;
    let certificates = Certificate::from_pem_bundle(&ca_bytes).context("gateway CA is invalid")?;
    let mut builder = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .identity(identity)
        .connect_timeout(Duration::from_secs(
            config.mcp.limits.connect_timeout_seconds,
        ));
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .context("cannot initialize MCP gateway client")
}

fn attachment_client(config: &Config) -> Result<(Client, Url)> {
    let attachments = &config.mcp.attachments;
    let io_url = attachments
        .io_url
        .clone()
        .ok_or_else(|| anyhow!("MCP attachment I/O URL is absent"))?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(
            config.mcp.limits.connect_timeout_seconds,
        ));
    if config.deployment.mode == DeploymentMode::Kubernetes {
        let certificate = std::fs::read(
            attachments
                .client_certificate_chain_file
                .as_ref()
                .ok_or_else(|| anyhow!("MCP attachment client certificate is absent"))?,
        )?;
        let private_key = std::fs::read(
            attachments
                .client_private_key_file
                .as_ref()
                .ok_or_else(|| anyhow!("MCP attachment client key is absent"))?,
        )?;
        let mut identity_pem = certificate;
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&private_key);
        let identity = Identity::from_pem(&identity_pem)
            .context("MCP attachment client identity is invalid")?;
        let ca = std::fs::read(
            attachments
                .server_ca_file
                .as_ref()
                .ok_or_else(|| anyhow!("MCP attachment I/O CA is absent"))?,
        )?;
        let roots =
            Certificate::from_pem_bundle(&ca).context("MCP attachment I/O CA is invalid")?;
        builder = builder.https_only(true).identity(identity);
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
    }
    Ok((
        builder
            .build()
            .context("cannot initialize MCP attachment client")?,
        io_url,
    ))
}

fn load_oauth_clients(config: &Config) -> Result<HashMap<String, OauthClientState>> {
    let mut clients = HashMap::new();
    for client in config.mcp.oauth_clients.values() {
        let client_secret = client
            .client_secret_file
            .as_deref()
            .map(read_secret_string)
            .transpose()
            .context("cannot read MCP OAuth client secret")?
            .map(Zeroizing::new);
        let issuer = client.issuer.as_str().trim_end_matches('/').to_owned();
        if clients
            .insert(
                issuer,
                OauthClientState {
                    client_id: client.client_id.clone(),
                    client_secret,
                },
            )
            .is_some()
        {
            bail!("MCP OAuth issuer is configured more than once");
        }
    }
    Ok(clients)
}

fn load_verification_keys(path: &std::path::Path) -> Result<ApiMcpDelegationKeyset> {
    let source = std::fs::read_to_string(path).context("cannot read capability public keyset")?;
    ApiMcpDelegationKeyset::parse(&source)
        .map_err(|_| anyhow!("capability public keyset is invalid"))
}

fn verify_request_delegation(
    wire: &str,
    keys: &ApiMcpDelegationKeyset,
    operation: McpOperation,
    now: i64,
) -> Result<filebelt_mcp_protocol::DelegationClaims, BrokerError> {
    verify_mcp_delegation(wire, keys, "filebelt-mcp-broker", operation, now)
        .map(|verified| verified.claims)
        .map_err(|_| BrokerError::forbidden("mcp.delegation.invalid"))
}

fn parse_uuid(value: &str) -> Result<Uuid, BrokerError> {
    Uuid::parse_str(value).map_err(|_| BrokerError::forbidden("mcp.delegation.invalid"))
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn unix_time() -> Result<i64, BrokerError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerError::unavailable("mcp.clock.invalid"))?
        .as_secs();
    seconds
        .try_into()
        .map_err(|_| BrokerError::unavailable("mcp.clock.invalid"))
}

impl BrokerError {
    const fn bad_request(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
        }
    }
    const fn forbidden(code: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code,
        }
    }
    const fn too_many_requests(code: &'static str) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code,
        }
    }
    const fn unavailable(code: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
        }
    }
    const fn bad_gateway(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code,
        }
    }
    const fn gateway_timeout(code: &'static str) -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            code,
        }
    }
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            axum::Json(json!({
                "type": format!("https://filebelt.dev/problems/{}", self.code),
                "status": self.status.as_u16(),
                "code": self.code,
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};

    fn delegation_claims(operation: McpOperation) -> filebelt_mcp_protocol::DelegationClaims {
        filebelt_mcp_protocol::DelegationClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: "filebelt-mcp-broker".into(),
            operation: operation as i32,
            tenant_id: Uuid::new_v4().to_string(),
            principal_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            application_id: "filebelt.settings.mcp-test".into(),
            registration_id: Uuid::new_v4().to_string(),
            capability_fingerprint: vec![3; 32],
            arguments_digest: vec![4; 32],
            attachments: Vec::new(),
            policy_generation: 1,
            membership_generation: 1,
            nonce: vec![5; 32],
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 220,
            service_grant_id: String::new(),
        }
    }

    fn test_runner_state() -> RunnerBrokerState {
        let _ = install_crypto_provider();
        RunnerBrokerState {
            admission: None,
            controller: Client::new(),
            create_url: Url::parse("https://controller.example.test/internal/v1/mcp/runners")
                .unwrap(),
            delete_url: Url::parse(
                "https://controller.example.test/internal/v1/mcp/runners:delete",
            )
            .unwrap(),
            pending: Mutex::new(HashMap::new()),
            lifecycles: Mutex::new(HashMap::new()),
            relay_accepts: Arc::new(Semaphore::new(1)),
            hello_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn endpoint_rejects_embedded_authority_and_non_default_ports() {
        let mut registration = test_registration();
        registration.endpoint_uri = Some("https://user@example.test/mcp".into());
        assert!(validate_endpoint(&registration).is_err());
        registration.endpoint_uri = Some("https://example.test:8443/mcp".into());
        assert!(validate_endpoint(&registration).is_err());
    }

    #[test]
    fn broker_admission_rejects_foreign_signer_before_broker_effects() {
        let retiring = Ed25519KeyPair::generate().unwrap();
        let current = Ed25519KeyPair::generate().unwrap();
        let foreign = Ed25519KeyPair::generate().unwrap();
        let keys = ApiMcpDelegationKeyset::parse(
            &filebelt_capability_keyset::encode_keyset(
                filebelt_capability_keyset::KeyPurpose::ApiMcpDelegation,
                &[
                    (1, retiring.public_key().as_ref().try_into().unwrap()),
                    (2, current.public_key().as_ref().try_into().unwrap()),
                ],
            )
            .unwrap(),
        )
        .unwrap();
        let claims = delegation_claims(McpOperation::Invoke);

        for (generation, signer) in [(1, &retiring), (2, &current)] {
            let wire =
                filebelt_mcp_protocol::sign_mcp_delegation(&claims, generation, signer).unwrap();
            assert!(verify_request_delegation(&wire, &keys, McpOperation::Invoke, 110).is_ok());
        }

        let forged = filebelt_mcp_protocol::sign_mcp_delegation(&claims, 1, &foreign).unwrap();
        assert_eq!(
            verify_request_delegation(&forged, &keys, McpOperation::Invoke, 110)
                .unwrap_err()
                .code,
            "mcp.delegation.invalid"
        );
    }

    #[test]
    fn sse_parser_ignores_control_fields() {
        assert_eq!(
            parse_sse_data(b"event: message\nid: secret\ndata: {\"jsonrpc\":\"2.0\"}\n\n").unwrap(),
            b"{\"jsonrpc\":\"2.0\"}"
        );
    }

    #[test]
    fn unsafe_active_content_is_rejected() {
        assert!(
            validate_content_blocks(
                &json!({"content": [{"type":"image","mimeType":"image/svg+xml","data":""}]})
            )
            .is_err()
        );
        assert!(
            validate_content_blocks(
                &json!({"content": [{"type":"resource","resource":{"uri":"https://example.test"}}]})
            )
            .is_err()
        );
    }

    #[test]
    fn semantic_markdown_is_bounded_and_forwarded_as_metadata() {
        let semantic = json!({
            "format": "filebelt.markdown.semantic.v1",
            "node_id": Uuid::new_v4(),
            "base_version_id": Uuid::new_v4(),
            "markdown": "# Proposed\n",
        });
        let request = InvocationRequest {
            primitive: McpPrimitive::Tool as i32,
            capability_name: "rewrite".into(),
            semantic_input_json: serde_json::to_vec(&semantic).unwrap(),
            ..Default::default()
        };
        let (method, parameters) =
            invocation_parameters(&request, json!({"tone":"plain"})).unwrap();
        assert_eq!(method, "tools/call");
        assert_eq!(parameters["_meta"]["filebelt/semantic"], semantic);
        assert_eq!(parameters["arguments"], json!({"tone":"plain"}));

        let invalid = serde_json::to_vec(&json!({
            "format": "filebelt.markdown.semantic.v1",
            "node_id": Uuid::new_v4(),
            "base_version_id": Uuid::new_v4(),
            "markdown": "bad\u{0}source",
        }))
        .unwrap();
        assert_eq!(
            parse_semantic_markdown_input(&invalid).unwrap_err().code,
            "mcp.semantic.invalid"
        );
    }

    #[test]
    fn semantic_result_is_a_distinct_nonterminal_proposal_frame() {
        let result = json!({
            "content": [{"type":"text","text":"proposal"}],
            "_meta": {
                "filebelt/semantic": {
                    "format": "filebelt.markdown.semantic.v1",
                    "markdown": "# Proposal\n",
                }
            }
        });
        let frames = result_frames("00000000-0000-4000-8000-000000000000", result, 8_192).unwrap();
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[2].kind, InvocationFrameKind::Semantic as i32);
        assert!(!frames[2].terminal);
        assert_eq!(frames[3].kind, InvocationFrameKind::Complete as i32);
        assert!(frames[3].terminal);
    }

    #[test]
    fn semantic_result_cannot_redefine_input_context() {
        assert!(
            validate_semantic_markdown_output(&json!({
                "format": "filebelt.markdown.semantic.v1",
                "node_id": Uuid::new_v4(),
                "base_version_id": Uuid::new_v4(),
                "markdown": "# Proposal\n",
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn invalid_bootstrap_digest_does_not_consume_pending_runner() {
        let runners = test_runner_state();
        let invocation_id = Uuid::new_v4();
        let expected = *blake3::hash(b"expected").as_bytes();
        let supplied = *blake3::hash(b"supplied").as_bytes();
        let (sender, _receiver) = oneshot::channel::<RelayStream>();
        insert_pending_runner(
            &runners,
            invocation_id,
            PendingRunner {
                bootstrap_digest: expected,
                sender,
            },
        )
        .await
        .unwrap();

        let error = take_authenticated_pending(&runners, invocation_id, &supplied)
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, "mcp.runner.token_invalid");
        assert!(runners.pending.lock().await.contains_key(&invocation_id));
        assert!(
            take_authenticated_pending(&runners, invocation_id, &expected)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn duplicate_pending_runner_does_not_replace_original_sender() {
        let runners = test_runner_state();
        let invocation_id = Uuid::new_v4();
        let digest = *blake3::hash(b"expected").as_bytes();
        let (first_sender, first_receiver) = oneshot::channel::<RelayStream>();
        insert_pending_runner(
            &runners,
            invocation_id,
            PendingRunner {
                bootstrap_digest: digest,
                sender: first_sender,
            },
        )
        .await
        .unwrap();
        let (second_sender, _second_receiver) = oneshot::channel::<RelayStream>();

        let error = insert_pending_runner(
            &runners,
            invocation_id,
            PendingRunner {
                bootstrap_digest: digest,
                sender: second_sender,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "mcp.runner.invocation_reused");

        let pending = take_authenticated_pending(&runners, invocation_id, &digest)
            .await
            .unwrap();
        let (stream, _peer) = tokio::io::duplex(64);
        assert!(pending.sender.send(Box::new(stream)).is_ok());
        assert!(first_receiver.await.is_ok());
    }

    #[tokio::test]
    async fn stdio_session_fragments_large_json_at_relay_payload_limit() {
        let invocation_id = Uuid::new_v4();
        let (broker, mut runner) = tokio::io::duplex(200_000);
        let mut session = StdioSession::new(Box::new(broker), invocation_id, 100_000);
        let payload = json!({"value": "x".repeat(MAX_RUNNER_RELAY_PAYLOAD_BYTES)});

        session.send_json(&payload).await.unwrap();

        let first_length = runner.read_u32().await.unwrap() as usize;
        let mut first_message = vec![0_u8; first_length];
        runner.read_exact(&mut first_message).await.unwrap();
        let second_length = runner.read_u32().await.unwrap() as usize;
        let mut second_message = vec![0_u8; second_length];
        runner.read_exact(&mut second_message).await.unwrap();
        let first = decode_runner_relay_frame(&first_message).unwrap();
        let second = decode_runner_relay_frame(&second_message).unwrap();
        assert_eq!((first.sequence, second.sequence), (1, 2));
        assert_eq!(first.payload.len(), MAX_RUNNER_RELAY_PAYLOAD_BYTES);
        let mut actual = first.payload;
        actual.extend_from_slice(&second.payload);
        let mut expected = serde_json::to_vec(&payload).unwrap();
        expected.push(b'\n');
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn stdio_session_rejects_mismatched_response_id() {
        let invocation_id = Uuid::new_v4();
        let (broker, mut runner) = tokio::io::duplex(8_192);
        let response = RunnerRelayFrame {
            invocation_id: invocation_id.to_string(),
            sequence: 1,
            kind: RunnerRelayFrameKind::Data as i32,
            payload: b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n".to_vec(),
            code: String::new(),
            terminal: false,
        };
        let message = encode_runner_relay_frame(&response).unwrap();
        runner.write_u32(message.len() as u32).await.unwrap();
        runner.write_all(&message).await.unwrap();
        let mut session = StdioSession::new(Box::new(broker), invocation_id, 8_192);

        let error = session
            .request(1, "tools/list", json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.code, "mcp.runner.response_mismatch");
    }

    fn test_registration() -> McpRegistrationRecord {
        McpRegistrationRecord {
            tenant_id: Uuid::new_v4(),
            id: Uuid::new_v4(),
            owner_principal_id: Uuid::new_v4(),
            owner_kind: "user".into(),
            source_kind: "personal".into(),
            template_id: None,
            display_name: "test".into(),
            description: String::new(),
            transport: "streamable_http".into(),
            endpoint_uri: Some("https://example.test/mcp".into()),
            trust_profile: Some("public".into()),
            catalog_entry: None,
            state: filebelt_mcp_policy::RegistrationPolicyState {
                validation: filebelt_mcp_policy::ValidationState::Valid,
                authentication: filebelt_mcp_policy::AuthenticationState::NoneRequired,
                capabilities: filebelt_mcp_policy::CapabilityState::Approved,
                quarantine: filebelt_mcp_policy::QuarantineState::Clear,
                enabled: true,
                revoked: false,
            },
            policy: json!({}),
            revision: 1,
            revocation_generation: 1,
            credential_generation: 1,
            credential_kind: "none".into(),
            protocol_version: Some(CURRENT_PROTOCOL.into()),
            created_at: "2026-08-07 00:00:00+00".into(),
            updated_at: "2026-08-07 00:00:00+00".into(),
        }
    }

    #[test]
    fn attachment_injection_requires_an_empty_exact_target() {
        let mut arguments = json!({"input": null, "nested": {}});
        inject_attachment_value(&mut arguments, "/input", json!("contents")).unwrap();
        inject_attachment_value(&mut arguments, "/nested/name", json!("file.txt")).unwrap();
        assert_eq!(arguments["input"], "contents");
        assert_eq!(arguments["nested"]["name"], "file.txt");
        assert_eq!(
            inject_attachment_value(&mut arguments, "/input", json!("replacement"))
                .unwrap_err()
                .code,
            "mcp.attachment.target_occupied"
        );
    }

    #[test]
    fn attachment_values_preserve_type_and_encoding() {
        let claim = AttachmentClaim {
            size_bytes: 3,
            basename: "a.txt".into(),
            media_type: "text/plain".into(),
            ..Default::default()
        };
        let size = AttachmentFieldClaim {
            disclosure: AttachmentDisclosure::Size as i32,
            encoding: AttachmentEncoding::Decimal as i32,
            ..Default::default()
        };
        let content = AttachmentFieldClaim {
            disclosure: AttachmentDisclosure::Content as i32,
            encoding: AttachmentEncoding::Base64 as i32,
            ..Default::default()
        };
        assert_eq!(attachment_value(&claim, &size, None).unwrap(), json!(3));
        assert_eq!(
            attachment_value(&claim, &content, Some(b"abc")).unwrap(),
            json!("YWJj")
        );
    }

    #[test]
    fn attachment_authority_rejects_drive_only_staleness() {
        let claims = delegation_claims(McpOperation::Invoke);
        let attachment = AttachmentClaim {
            membership_generation: claims.membership_generation,
            drive_acl_generation: 11,
            resource_acl_generation: 13,
            namespace_generation: 17,
            ..Default::default()
        };
        let snapshot = McpAuthoritySnapshot {
            principal_generation: claims.membership_generation as i64,
            registration_generation: claims.policy_generation as i64,
            drive_acl_generation: 11,
            acl_generation: 13,
            namespace_generation: 17,
            allow_metadata: true,
            allow_content: true,
        };
        assert!(attachment_authority_generations_match(
            &claims,
            &attachment,
            &snapshot
        ));
        assert!(!attachment_authority_generations_match(
            &claims,
            &attachment,
            &McpAuthoritySnapshot {
                drive_acl_generation: 12,
                ..snapshot
            },
        ));
    }

    #[test]
    fn oauth_well_known_paths_preserve_the_resource_path() {
        let issuer = Url::parse("https://authorization.example/tenant").unwrap();
        assert_eq!(
            oauth_well_known_url(&issuer, "oauth-authorization-server").as_str(),
            "https://authorization.example/.well-known/oauth-authorization-server/tenant"
        );
        let resource = Url::parse("https://mcp.example/service").unwrap();
        assert_eq!(
            oauth_well_known_url(&resource, "oauth-protected-resource").as_str(),
            "https://mcp.example/.well-known/oauth-protected-resource/service"
        );
    }
}

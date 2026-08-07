// SPDX-License-Identifier: Apache-2.0

//! Namespace-scoped controller for one-shot curated MCP runner Pods.

#![deny(unsafe_code)]

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use filebelt_control_protocol::Config;
use filebelt_controller::catalog::VerifiedCatalog;
use filebelt_controller::kubernetes::{KubernetesClient, LeaseState};
use filebelt_controller::pod::{
    RunnerPodRequest, RunnerPodSettings, build_runner_pod, build_runner_secret,
    runner_resource_name,
};
use filebelt_mcp_protocol::{
    CreateRunnerLeaseRequest, CreateRunnerLeaseResponse, DeleteRunnerLeaseRequest,
    DeleteRunnerLeaseResponse,
};
use filebelt_runtime::{
    MtlsListener, OperationsState, init_telemetry, install_crypto_provider, observe_request,
    operations_router, trace_request, wait_for_shutdown,
};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prost::Message as _;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

const ROLE: &str = "filebelt-controller";
const LEASE_NAME: &str = "filebelt-mcp-controller";
const LEASE_SECONDS: u64 = 15;
const MAX_RESOLVED_ENDPOINT_ADDRESSES: usize = 16;
const ENDPOINT_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(disable_version_flag = true)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
}

#[derive(Clone)]
struct ControllerState {
    kubernetes: KubernetesClient,
    catalog: Arc<VerifiedCatalog>,
    pod_settings: OwnedPodSettings,
    created: Counter,
    cancelled: Counter,
    leader: Arc<AtomicBool>,
    mutation_lock: Arc<Mutex<()>>,
    max_per_principal: u32,
    max_per_tenant: u32,
}

#[derive(Clone)]
struct OwnedPodSettings {
    namespace: String,
    release_name: String,
    runner_image: String,
    runner_service_account: String,
    broker_address: String,
    broker_server_name: String,
    broker_client_tls_secret: String,
    gateway_address: String,
    gateway_server_name: String,
    gateway_client_tls_secret: String,
    gateway_egress_profile: String,
}

impl OwnedPodSettings {
    fn resolved<'a>(
        &'a self,
        broker_addresses: &'a [String],
        gateway_addresses: &'a [String],
    ) -> RunnerPodSettings<'a> {
        RunnerPodSettings {
            namespace: &self.namespace,
            release_name: &self.release_name,
            runner_image: &self.runner_image,
            runner_service_account: &self.runner_service_account,
            broker_addresses,
            broker_server_name: &self.broker_server_name,
            broker_client_tls_secret: &self.broker_client_tls_secret,
            gateway_addresses,
            gateway_server_name: &self.gateway_server_name,
            gateway_client_tls_secret: &self.gateway_client_tls_secret,
            gateway_egress_profile: &self.gateway_egress_profile,
        }
    }
}

#[derive(Serialize)]
struct Problem {
    r#type: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
}

enum ControllerError {
    BadRequest,
    CatalogDenied,
    LimitExceeded,
    NotLeader,
    Kubernetes,
}

#[tokio::main]
async fn main() -> ExitCode {
    if matches!(
        env::args().nth(1).as_deref(),
        Some("--version" | "--build-info=json")
    ) {
        return filebelt_deployment_diagnostics::run_probe(ROLE);
    }
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{ROLE}: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    install_crypto_provider()?;
    let Arguments {
        command: Command::Serve { config },
    } = Arguments::parse();
    let config = Config::load(&config).map_err(|error| error.to_string())?;
    if !config.mcp.enabled || !config.mcp.runners.enabled {
        return Err("controller requires mcp.enabled=true and mcp.runners.enabled=true".into());
    }
    let backend_tls = config
        .backend_tls
        .as_ref()
        .and_then(|tls| tls.controller.as_ref())
        .ok_or("controller backend mTLS configuration is required")?;
    let _telemetry = init_telemetry(&config.telemetry, ROLE)?;

    let controller_namespace = required_env("FILEBELT_CONTROLLER_POD_NAMESPACE")?;
    let runner_namespace = config.mcp.runners.namespace.clone();
    if !is_kubernetes_name(&controller_namespace) {
        return Err("FILEBELT_CONTROLLER_POD_NAMESPACE is invalid".into());
    }
    if controller_namespace == runner_namespace {
        return Err("mcp.runners.namespace must be separate from the controller namespace".into());
    }
    let catalog_file = config
        .mcp
        .runners
        .catalog_file
        .as_deref()
        .ok_or("mcp.runners.catalog_file is required")?;
    let trusted_root_file = config
        .mcp
        .runners
        .trusted_root_file
        .as_deref()
        .ok_or("mcp.runners.trusted_root_file is required")?;
    let bundle_directory = config
        .mcp
        .runners
        .bundle_directory
        .as_deref()
        .ok_or("mcp.runners.bundle_directory is required")?;
    let catalog = Arc::new(VerifiedCatalog::load(
        catalog_file,
        trusted_root_file,
        bundle_directory,
    )?);
    info!(entries = catalog.len(), "verified MCP runner catalog");

    let pod_settings = load_pod_settings(
        runner_namespace.clone(),
        config
            .mcp
            .runners
            .runner_image
            .as_deref()
            .ok_or("mcp.runners.runner_image is required")?,
    )?;
    let kubernetes = KubernetesClient::in_cluster(runner_namespace)?;
    let holder = env::var("FILEBELT_CONTROLLER_POD_NAME")
        .map_err(|_| "FILEBELT_CONTROLLER_POD_NAME is required")?;
    if !is_kubernetes_name(&holder) {
        return Err("FILEBELT_CONTROLLER_POD_NAME is invalid".into());
    }

    let leader = Arc::new(AtomicBool::new(false));
    let readiness_leader = Arc::clone(&leader);
    let operations = OperationsState::new(ROLE, config.telemetry.prometheus_enabled, move || {
        let readiness_leader = Arc::clone(&readiness_leader);
        async move { readiness_leader.load(Ordering::Acquire) }
    });
    let leadership = operations.register_gauge(
        "controller_leader",
        "Whether this controller currently owns the reconciliation Lease.",
    );
    let reconciled = operations.register_counter(
        "controller_runner_reconciliations",
        "Finished MCP runner resources removed by the controller.",
    );
    let created = operations.register_counter(
        "controller_runner_created",
        "MCP runner Pod requests accepted by the controller.",
    );
    let cancelled = operations.register_counter(
        "controller_runner_cancelled",
        "MCP runner Pod cancellation requests accepted by the controller.",
    );
    let failures = operations.register_counter(
        "controller_reconciliation_failures",
        "Controller Lease or cleanup reconciliation failures.",
    );
    tokio::spawn(run_reconciliation(
        kubernetes.clone(),
        holder,
        Arc::clone(&leader),
        leadership,
        reconciled,
        failures,
    ));

    let state = ControllerState {
        kubernetes,
        catalog,
        pod_settings,
        created,
        cancelled,
        leader,
        mutation_lock: Arc::new(Mutex::new(())),
        max_per_principal: config.mcp.runners.max_per_principal,
        max_per_tenant: config.mcp.runners.max_per_tenant,
    };
    let application = Router::new()
        .route("/internal/v1/mcp/runners", post(create_runner))
        .route("/internal/v1/mcp/runners:delete", post(cancel_runner))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(trace_request))
        .layer(middleware::from_fn_with_state(
            operations.clone(),
            observe_request,
        ))
        .with_state(state);
    let application_listener = MtlsListener::bind(config.listeners.controller, backend_tls).await?;
    let operations_listener = TcpListener::bind(config.listeners.operations)
        .await
        .map_err(|error| format!("cannot bind operations listener: {error}"))?;
    info!(
        controller = %config.listeners.controller,
        operations = %config.listeners.operations,
        "controller started"
    );
    let application_server = axum::serve(application_listener, application);
    let operations_server = axum::serve(operations_listener, operations_router(operations));
    tokio::select! {
        result = application_server => result.map_err(|error| format!("controller server failed: {error}"))?,
        result = operations_server => result.map_err(|error| format!("operations server failed: {error}"))?,
        () = wait_for_shutdown() => {},
    }
    Ok(())
}

async fn create_runner(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ControllerError> {
    require_protobuf(&headers)?;
    let mut wire =
        CreateRunnerLeaseRequest::decode(body).map_err(|_| ControllerError::BadRequest)?;
    let invocation_id =
        Uuid::parse_str(&wire.invocation_id).map_err(|_| ControllerError::BadRequest)?;
    let tenant_id = Uuid::parse_str(&wire.tenant_id).map_err(|_| ControllerError::BadRequest)?;
    let principal_id =
        Uuid::parse_str(&wire.principal_id).map_err(|_| ControllerError::BadRequest)?;
    let request = RunnerPodRequest {
        invocation_id,
        tenant_id,
        principal_id,
        catalog_entry: wire.catalog_entry,
        bootstrap_token: Zeroizing::new(std::mem::take(&mut wire.bootstrap_token)),
    };
    let entry = state
        .catalog
        .get(&request.catalog_entry)
        .ok_or(ControllerError::CatalogDenied)?;
    let _guard = state.mutation_lock.lock().await;
    if !state.leader.load(Ordering::Acquire) {
        return Err(ControllerError::NotLeader);
    }
    let broker_addresses = resolve_endpoint(&state.pod_settings.broker_address, "broker")
        .await
        .map_err(|error| {
            warn!(code = "runner_broker_resolution_failed", %error);
            ControllerError::Kubernetes
        })?;
    let gateway_addresses = resolve_endpoint(&state.pod_settings.gateway_address, "gateway")
        .await
        .map_err(|error| {
            warn!(code = "runner_gateway_resolution_failed", %error);
            ControllerError::Kubernetes
        })?;
    let secret = build_runner_secret(&request, &state.pod_settings.namespace)
        .map_err(|_| ControllerError::BadRequest)?;
    let pod_settings = state
        .pod_settings
        .resolved(&broker_addresses, &gateway_addresses);
    let pod = build_runner_pod(&request, entry, &pod_settings)
        .map_err(|_| ControllerError::CatalogDenied)?;
    let labels = pod["metadata"]["labels"]
        .as_object()
        .ok_or(ControllerError::CatalogDenied)?;
    let resource_name = runner_resource_name(request.invocation_id);
    if state
        .kubernetes
        .existing_runner_matches(&resource_name, labels)
        .await
        .map_err(|error| {
            warn!(code = "runner_read_failed", %error);
            ControllerError::Kubernetes
        })?
    {
        state
            .kubernetes
            .create_runner(&secret, &pod)
            .await
            .map_err(|error| {
                warn!(code = "runner_idempotent_create_failed", %error);
                ControllerError::Kubernetes
            })?;
        return Ok(protobuf_response(
            StatusCode::OK,
            &CreateRunnerLeaseResponse {
                invocation_id: request.invocation_id.to_string(),
                resource_name,
            },
        ));
    }
    let (tenant_count, principal_count) = state
        .kubernetes
        .active_runner_counts(
            &request.tenant_id.to_string(),
            &request.principal_id.to_string(),
        )
        .await
        .map_err(|error| {
            warn!(code = "runner_quota_check_failed", %error);
            ControllerError::Kubernetes
        })?;
    if tenant_count >= state.max_per_tenant || principal_count >= state.max_per_principal {
        return Err(ControllerError::LimitExceeded);
    }
    if !state.leader.load(Ordering::Acquire) {
        return Err(ControllerError::NotLeader);
    }
    state
        .kubernetes
        .create_runner(&secret, &pod)
        .await
        .map_err(|error| {
            warn!(code = "runner_create_failed", %error);
            ControllerError::Kubernetes
        })?;
    state.created.inc();
    Ok(protobuf_response(
        StatusCode::ACCEPTED,
        &CreateRunnerLeaseResponse {
            invocation_id: request.invocation_id.to_string(),
            resource_name,
        },
    ))
}

async fn cancel_runner(
    State(state): State<ControllerState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ControllerError> {
    require_protobuf(&headers)?;
    let wire = DeleteRunnerLeaseRequest::decode(body).map_err(|_| ControllerError::BadRequest)?;
    let invocation_id =
        Uuid::parse_str(&wire.invocation_id).map_err(|_| ControllerError::BadRequest)?;
    let _guard = state.mutation_lock.lock().await;
    if !state.leader.load(Ordering::Acquire) {
        return Err(ControllerError::NotLeader);
    }
    state
        .kubernetes
        .delete_runner(&runner_resource_name(invocation_id))
        .await
        .map_err(|error| {
            warn!(code = "runner_cancel_failed", %error);
            ControllerError::Kubernetes
        })?;
    state.cancelled.inc();
    Ok(protobuf_response(
        StatusCode::OK,
        &DeleteRunnerLeaseResponse {
            invocation_id: invocation_id.to_string(),
        },
    ))
}

fn require_protobuf(headers: &HeaderMap) -> Result<(), ControllerError> {
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/x-protobuf")
    {
        return Err(ControllerError::BadRequest);
    }
    Ok(())
}

fn protobuf_response(status: StatusCode, message: &impl prost::Message) -> Response {
    (
        status,
        [(CONTENT_TYPE, "application/x-protobuf")],
        message.encode_to_vec(),
    )
        .into_response()
}

async fn run_reconciliation(
    kubernetes: KubernetesClient,
    holder: String,
    leader: Arc<AtomicBool>,
    leadership: Gauge,
    reconciled: Counter,
    failures: Counter,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        match kubernetes
            .try_acquire_lease(LEASE_NAME, &holder, LEASE_SECONDS)
            .await
        {
            Ok(LeaseState::Leader) => {
                leader.store(true, Ordering::Release);
                leadership.set(1);
                match kubernetes.reconcile_finished_runners().await {
                    Ok(count) => {
                        reconciled.inc_by(count as u64);
                    }
                    Err(error) => {
                        failures.inc();
                        warn!(code = "runner_reconciliation_failed", %error);
                    }
                }
            }
            Ok(LeaseState::Follower) => {
                leader.store(false, Ordering::Release);
                leadership.set(0);
            }
            Err(error) => {
                leader.store(false, Ordering::Release);
                leadership.set(0);
                failures.inc();
                error!(code = "controller_lease_failed", %error);
            }
        }
    }
}

fn load_pod_settings(namespace: String, runner_image: &str) -> Result<OwnedPodSettings, String> {
    if !runner_image.contains("@sha256:") || runner_image.len() < 72 {
        return Err("mcp.runners.runner_image must be digest-pinned".into());
    }
    Ok(OwnedPodSettings {
        namespace,
        release_name: required_env("FILEBELT_RELEASE_NAME")?,
        runner_image: runner_image.to_owned(),
        runner_service_account: env::var("FILEBELT_MCP_RUNNER_SERVICE_ACCOUNT")
            .unwrap_or_else(|_| "filebelt-mcp-runner".into()),
        broker_address: required_env("FILEBELT_MCP_BROKER_ADDRESS")?,
        broker_server_name: required_env("FILEBELT_MCP_BROKER_SERVER_NAME")?,
        broker_client_tls_secret: required_env("FILEBELT_MCP_BROKER_CLIENT_TLS_SECRET")?,
        gateway_address: required_env("FILEBELT_MCP_GATEWAY_ADDRESS")?,
        gateway_server_name: required_env("FILEBELT_MCP_GATEWAY_SERVER_NAME")?,
        gateway_client_tls_secret: required_env("FILEBELT_MCP_GATEWAY_CLIENT_TLS_SECRET")?,
        gateway_egress_profile: required_env("FILEBELT_MCP_GATEWAY_EGRESS_PROFILE")?,
    })
}

async fn resolve_endpoint(value: &str, role: &str) -> Result<Vec<String>, String> {
    let mut addresses =
        tokio::time::timeout(ENDPOINT_RESOLUTION_TIMEOUT, tokio::net::lookup_host(value))
            .await
            .map_err(|_| format!("{role} address resolution timed out"))?
            .map_err(|error| format!("cannot resolve {role} address: {error}"))?
            .collect::<Vec<SocketAddr>>();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ENDPOINT_ADDRESSES {
        return Err(format!(
            "{role} address resolution is outside its allowed range"
        ));
    }
    Ok(addresses
        .into_iter()
        .map(|address| address.to_string())
        .collect())
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.is_empty() || value.len() > 2048 || value.contains(['\r', '\n', '\0']) {
        return Err(format!("{name} is invalid"));
    }
    Ok(value)
}

fn is_kubernetes_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'-' => index > 0 && index + 1 < value.len(),
            _ => false,
        })
}

impl IntoResponse for ControllerError {
    fn into_response(self) -> Response {
        let (status, code, title) = match self {
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                "mcp.runner.invalid_request",
                "Invalid runner request",
            ),
            Self::CatalogDenied => (
                StatusCode::FORBIDDEN,
                "mcp.runner.catalog_denied",
                "Runner catalog policy denied the request",
            ),
            Self::LimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "mcp.runner.limit_exceeded",
                "Runner concurrency limit exceeded",
            ),
            Self::NotLeader => (
                StatusCode::SERVICE_UNAVAILABLE,
                "mcp.runner.not_leader",
                "Controller leader is not available",
            ),
            Self::Kubernetes => (
                StatusCode::SERVICE_UNAVAILABLE,
                "mcp.runner.unavailable",
                "Runner orchestration is unavailable",
            ),
        };
        (
            status,
            Json(Problem {
                r#type: "about:blank",
                title,
                status: status.as_u16(),
                code,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{is_kubernetes_name, resolve_endpoint};

    #[test]
    fn kubernetes_names_are_strict_dns_labels() {
        assert!(is_kubernetes_name("filebelt-mcp-runners"));
        assert!(!is_kubernetes_name("filebelt/mcp-runners"));
    }

    #[tokio::test]
    async fn endpoint_resolution_emits_only_numeric_socket_addresses() {
        let addresses = resolve_endpoint("127.0.0.1:8084", "broker")
            .await
            .expect("numeric endpoint");
        assert_eq!(addresses, ["127.0.0.1:8084"]);
    }
}

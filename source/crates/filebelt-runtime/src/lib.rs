// SPDX-License-Identifier: Apache-2.0

//! Shared, fail-closed runtime mechanics for FileBelt services.

#![deny(unsafe_code)]

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Router, serve::Listener};
use filebelt_control_protocol::{
    BackendServerTlsConfig, LogFormat, TelemetryConfig, read_secret_string,
};
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{
    BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider,
};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore,
    SignatureScheme,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing_subscriber::layer::{Layer as _, SubscriberExt as _};
use tracing_subscriber::util::SubscriberInitExt as _;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

type ReadyFuture = Pin<Box<dyn Future<Output = bool> + Send>>;
type ReadyCheck = Arc<dyn Fn() -> ReadyFuture + Send + Sync>;

#[derive(Clone)]
pub struct OperationsState {
    inner: Arc<OperationsInner>,
}

#[derive(Clone)]
pub struct LabeledGauge {
    family: Family<Vec<(&'static str, &'static str)>, Gauge>,
    labels: Vec<(&'static str, &'static str)>,
}

impl LabeledGauge {
    pub fn set(&self, value: i64) {
        self.family.get_or_create(&self.labels).set(value);
    }
}

struct OperationsInner {
    draining: AtomicBool,
    prometheus_enabled: bool,
    ready: ReadyCheck,
    registry: Mutex<Registry>,
    requests: Counter,
    failures: Counter,
    active: Gauge,
    duration: Histogram,
    readiness: Gauge,
    drain: Gauge,
}

impl OperationsState {
    pub fn new<F, Fut>(role: &'static str, prometheus_enabled: bool, ready: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        let requests = Counter::default();
        let failures = Counter::default();
        let active = Gauge::default();
        let duration = Histogram::new(exponential_buckets(0.001, 2.0, 16));
        let readiness = Gauge::default();
        let drain = Gauge::default();
        let mut registry = Registry::with_prefix("filebelt");
        registry.register(
            "http_requests",
            "Completed application requests.",
            requests.clone(),
        );
        registry.register(
            "http_failures",
            "Application responses with a 5xx status.",
            failures.clone(),
        );
        registry.register(
            "http_active",
            "Application requests currently executing.",
            active.clone(),
        );
        registry.register(
            "http_duration_seconds",
            "Application request latency.",
            duration.clone(),
        );
        registry.register(
            "ready",
            "Whether this role currently accepts traffic.",
            readiness.clone(),
        );
        registry.register(
            "draining",
            "Whether graceful shutdown has begun.",
            drain.clone(),
        );
        registry.register(
            "build",
            "Static runtime role identity.",
            prometheus_client::metrics::info::Info::new([("role", role)]),
        );
        Self {
            inner: Arc::new(OperationsInner {
                draining: AtomicBool::new(false),
                prometheus_enabled,
                ready: Arc::new(move || Box::pin(ready())),
                registry: Mutex::new(registry),
                requests,
                failures,
                active,
                duration,
                readiness,
                drain,
            }),
        }
    }

    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::Acquire)
    }

    pub fn begin_draining(&self) {
        self.inner.draining.store(true, Ordering::Release);
        self.inner.drain.set(1);
        self.inner.readiness.set(0);
    }

    pub fn register_gauge(&self, name: &'static str, help: &'static str) -> Gauge {
        let metric = Gauge::default();
        self.inner
            .registry
            .lock()
            .expect("operations metrics registry lock poisoned")
            .register(name, help, metric.clone());
        metric
    }

    pub fn register_counter(&self, name: &'static str, help: &'static str) -> Counter {
        let metric = Counter::default();
        self.inner
            .registry
            .lock()
            .expect("operations metrics registry lock poisoned")
            .register(name, help, metric.clone());
        metric
    }

    pub fn register_gauge_family(
        &self,
        name: &'static str,
        help: &'static str,
        label_name: &'static str,
        label_values: &[&'static str],
    ) -> Vec<LabeledGauge> {
        let family = Family::<Vec<(&'static str, &'static str)>, Gauge>::default();
        self.inner
            .registry
            .lock()
            .expect("operations metrics registry lock poisoned")
            .register(name, help, family.clone());
        label_values
            .iter()
            .map(|value| LabeledGauge {
                family: family.clone(),
                labels: vec![(label_name, *value)],
            })
            .collect()
    }

    async fn is_ready(&self) -> bool {
        let ready = !self.is_draining() && (self.inner.ready)().await;
        self.inner.readiness.set(i64::from(ready));
        ready
    }
}

pub fn operations_router(state: OperationsState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .with_state(state)
}

pub async fn observe_request(
    State(state): State<OperationsState>,
    request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    state.inner.active.inc();
    let response = next.run(request).await;
    state.inner.active.dec();
    state.inner.requests.inc();
    if response.status().is_server_error() {
        state.inner.failures.inc();
    }
    state
        .inner
        .duration
        .observe(started.elapsed().as_secs_f64());
    response
}

async fn live() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn ready(State(state): State<OperationsState>) -> StatusCode {
    if state.is_ready().await {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn metrics(State(state): State<OperationsState>) -> Response {
    if !state.inner.prometheus_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let _ = state.is_ready().await;
    let mut body = String::new();
    if encode(
        &mut body,
        &state
            .inner
            .registry
            .lock()
            .expect("operations metrics registry lock poisoned"),
    )
    .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub struct MtlsListener {
    accepted: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local_address: SocketAddr,
}

const MAX_PENDING_TLS_HANDSHAKES: usize = 128;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

impl MtlsListener {
    pub async fn bind(
        address: SocketAddr,
        settings: &BackendServerTlsConfig,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("cannot bind TLS listener {address}: {error}"))?;
        let local_address = listener
            .local_addr()
            .map_err(|error| format!("cannot inspect TLS listener {address}: {error}"))?;
        let server = server_config(settings)?;
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
    listener: TcpListener,
    acceptor: TlsAcceptor,
    sender: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
) {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_TLS_HANDSHAKES));
    loop {
        if sender.is_closed() {
            return;
        }
        let permit = match Arc::clone(&pending).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return,
        };
        let (stream, address) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(code = "tls_tcp_accept_failed", %error);
                drop(permit);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let connection_acceptor = acceptor.clone();
        let connection_sender = sender.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, connection_acceptor.accept(stream))
                .await
            {
                Ok(Ok(stream)) => {
                    let _ = connection_sender.send((stream, address)).await;
                }
                Ok(Err(error)) => tracing::warn!(code = "tls_handshake_rejected", %error),
                Err(_) => tracing::warn!(code = "tls_handshake_timed_out", %address),
            }
        });
    }
}

impl Listener for MtlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Some(connection) = self.accepted.recv().await {
                return connection;
            }
            tracing::error!(code = "tls_accept_loop_stopped");
            std::future::pending::<()>().await;
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local_address)
    }
}

fn server_config(settings: &BackendServerTlsConfig) -> Result<rustls::ServerConfig, String> {
    let chain = CertificateDer::pem_file_iter(&settings.certificate_chain_file)
        .map_err(|error| format!("cannot read backend TLS certificate chain: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("backend TLS certificate chain is invalid PEM: {error}"))?;
    if chain.is_empty() {
        return Err("backend TLS certificate chain is empty".into());
    }
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(&settings.private_key_file)
        .map_err(|error| format!("backend TLS private key is invalid PEM: {error}"))?;
    let mut roots = RootCertStore::empty();
    let ca_certificates = CertificateDer::pem_file_iter(&settings.client_ca_file)
        .map_err(|error| format!("cannot read backend TLS client CA: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("backend TLS client CA is invalid PEM: {error}"))?;
    if ca_certificates.is_empty() {
        return Err("backend TLS client CA is empty".into());
    }
    for certificate in ca_certificates {
        roots
            .add(certificate)
            .map_err(|error| format!("backend TLS client CA is invalid: {error}"))?;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
        .build()
        .map_err(|error| format!("cannot build backend client verifier: {error}"))?;
    let verifier = PolicyUriClientVerifier {
        inner,
        allowed: settings.allowed_client_uri_sans.iter().cloned().collect(),
        trust_domains: settings
            .allowed_client_trust_domains
            .iter()
            .cloned()
            .collect(),
    };
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("cannot build backend TLS 1.3 configuration: {error}"))?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(chain, key)
        .map_err(|error| format!("backend TLS certificate/key pair is invalid: {error}"))
}

pub fn certificate_not_after_unix_seconds(
    settings: &BackendServerTlsConfig,
) -> Result<i64, String> {
    let certificate = CertificateDer::pem_file_iter(&settings.certificate_chain_file)
        .map_err(|error| format!("cannot read backend TLS certificate chain: {error}"))?
        .next()
        .transpose()
        .map_err(|error| format!("backend TLS certificate chain is invalid PEM: {error}"))?
        .ok_or_else(|| "backend TLS certificate chain is empty".to_owned())?;
    let (_, certificate) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| "backend TLS certificate is invalid DER".to_owned())?;
    Ok(certificate.validity().not_after.timestamp())
}

#[derive(Debug)]
struct PolicyUriClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allowed: BTreeSet<String>,
    trust_domains: BTreeSet<String>,
}

impl ClientCertVerifier for PolicyUriClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let allowed =
            certificate_has_allowed_uri(end_entity.as_ref(), &self.allowed, &self.trust_domains)
                .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if !allowed {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn certificate_has_allowed_uri(
    certificate: &[u8],
    allowed: &BTreeSet<String>,
    trust_domains: &BTreeSet<String>,
) -> Result<bool, ()> {
    let (_, certificate) = parse_x509_certificate(certificate).map_err(|_| ())?;
    let san = certificate.subject_alternative_name().map_err(|_| ())?;
    Ok(san.is_some_and(|extension| {
        let uri_names = extension
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::URI(uri) => Some(*uri),
                _ => None,
            })
            .collect::<Vec<_>>();
        uri_names.len() == 1
            && (allowed.contains(uri_names[0])
                || spiffe_trust_domain(uri_names[0])
                    .is_some_and(|domain| trust_domains.contains(domain)))
    }))
}

fn spiffe_trust_domain(uri: &str) -> Option<&str> {
    let remainder = uri.strip_prefix("spiffe://")?;
    let (domain, path) = remainder.split_once('/')?;
    (!domain.is_empty() && !path.is_empty()).then_some(domain)
}

pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

pub fn install_crypto_provider() -> Result<(), String> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "a conflicting Rustls crypto provider is already installed".to_owned())
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

pub fn init_telemetry(
    settings: &TelemetryConfig,
    role: &'static str,
) -> Result<TelemetryGuard, String> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let provider = build_tracer_provider(settings, role)?;
    let otel_layer = provider.as_ref().map(|provider| {
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer(role))
            .boxed()
    });
    let fmt_layer = match settings.log_format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_target(false)
            .flatten_event(true)
            .boxed(),
        LogFormat::Text => tracing_subscriber::fmt::layer().with_target(false).boxed(),
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .map_err(|error| format!("cannot initialize telemetry: {error}"))?;
    if let Some(provider) = &provider {
        global::set_tracer_provider(provider.clone());
    }
    Ok(TelemetryGuard { provider })
}

fn build_tracer_provider(
    settings: &TelemetryConfig,
    role: &'static str,
) -> Result<Option<SdkTracerProvider>, String> {
    let Some(endpoint) = &settings.otlp_http_endpoint else {
        return Ok(None);
    };
    let mut http = reqwest::blocking::ClientBuilder::new()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3));
    if let Some(path) = &settings.otlp_custom_ca_file {
        let pem = std::fs::read(path)
            .map_err(|error| format!("cannot read OTLP custom CA bundle: {error}"))?;
        for certificate in reqwest::tls::Certificate::from_pem_bundle(&pem)
            .map_err(|error| format!("OTLP custom CA bundle is invalid PEM: {error}"))?
        {
            http = http.add_root_certificate(certificate);
        }
    }
    let http = http
        .build()
        .map_err(|error| format!("cannot build OTLP HTTP client: {error}"))?;
    let headers = settings
        .otlp_header_files
        .iter()
        .map(|(name, path)| {
            read_secret_string(path)
                .and_then(|value| {
                    if value.contains(['\r', '\n']) {
                        return Err(filebelt_control_protocol::ConfigError::Invalid(
                            "OTLP header value contains a line break".into(),
                        ));
                    }
                    Ok((name.clone(), value))
                })
                .map_err(|error| format!("cannot read OTLP header file: {error}"))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_http_client(http)
        .with_endpoint(endpoint.as_str())
        .with_timeout(Duration::from_secs(3))
        .with_headers(headers)
        .build()
        .map_err(|error| format!("cannot build OTLP HTTP exporter: {error}"))?;
    let batch = BatchSpanProcessor::builder(exporter)
        .with_batch_config(
            BatchConfigBuilder::default()
                .with_max_queue_size(1_024)
                .with_max_export_batch_size(256)
                .with_scheduled_delay(Duration::from_secs(5))
                .build(),
        )
        .build();
    let ratio = settings.effective_trace_sample_ratio();
    let provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::TraceIdRatioBased(ratio))
        .with_span_processor(batch)
        .with_resource(Resource::builder_empty().with_service_name(role).build())
        .build();
    Ok(Some(provider))
}

pub async fn trace_request(request: Request, next: Next) -> Response {
    use tracing::Instrument as _;
    let span = tracing::info_span!(
        "http.request",
        http.request.method = %request.method(),
    );
    next.run(request).instrument(span).await
}

pub async fn wait_for_shutdown() {
    let control_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = control_c => {},
        () = terminate => {},
    }
}

impl fmt::Debug for OperationsState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationsState")
            .field("draining", &self.is_draining())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MtlsListener, OperationsState, PolicyUriClientVerifier, certificate_has_allowed_uri,
    };
    use axum::serve::Listener as _;
    use filebelt_control_protocol::BackendServerTlsConfig;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType, date_time_ymd,
    };
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::server::WebPkiClientVerifier;
    use rustls::server::danger::ClientCertVerifier as _;
    use rustls::{ClientConfig, RootCertStore};
    use std::collections::BTreeSet;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    fn client_certificate(uri: &str) -> Vec<u8> {
        let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        parameters.is_ca = IsCa::NoCa;
        parameters.subject_alt_names = vec![SanType::URI(uri.try_into().unwrap())];
        parameters
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .to_vec()
    }

    fn signed_client_certificate(
        uri: &str,
        not_before_year: i32,
        not_after_year: i32,
        purpose: ExtendedKeyUsagePurpose,
    ) -> (CertificateDer<'static>, RootCertStore) {
        let mut ca_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        ca_parameters.not_before = date_time_ymd(2020, 1, 1);
        ca_parameters.not_after = date_time_ymd(2040, 1, 1);
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_parameters, ca_key);

        let mut client_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_parameters.is_ca = IsCa::NoCa;
        client_parameters.subject_alt_names = vec![SanType::URI(uri.try_into().unwrap())];
        client_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_parameters.extended_key_usages = vec![purpose];
        client_parameters.not_before = date_time_ymd(not_before_year, 1, 1);
        client_parameters.not_after = date_time_ymd(not_after_year, 1, 1);
        let client_key = KeyPair::generate().unwrap();
        let client = client_parameters.signed_by(&client_key, &issuer).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(ca_certificate.der().clone()).unwrap();
        (client.der().clone(), roots)
    }

    fn verifier(roots: RootCertStore, allowed: &str) -> PolicyUriClientVerifier {
        let inner = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap();
        PolicyUriClientVerifier {
            inner,
            allowed: BTreeSet::from([allowed.to_owned()]),
            trust_domains: BTreeSet::new(),
        }
    }

    fn test_time() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(1_767_225_600))
    }

    #[test]
    fn exact_uri_san_is_required() {
        let certificate = client_certificate("spiffe://filebelt.test/web-api");
        let allowed = BTreeSet::from(["spiffe://filebelt.test/web-api".to_owned()]);
        assert!(certificate_has_allowed_uri(&certificate, &allowed, &BTreeSet::new()).unwrap());
        let wrong = BTreeSet::from(["spiffe://filebelt.test/web-io".to_owned()]);
        assert!(!certificate_has_allowed_uri(&certificate, &wrong, &BTreeSet::new()).unwrap());
        assert!(
            certificate_has_allowed_uri(
                &certificate,
                &BTreeSet::new(),
                &BTreeSet::from(["filebelt.test".to_owned()]),
            )
            .unwrap()
        );
    }

    #[test]
    fn multiple_uri_sans_are_rejected_even_when_one_is_allowed() {
        let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        parameters.is_ca = IsCa::NoCa;
        parameters.subject_alt_names = vec![
            SanType::URI("spiffe://filebelt.test/web-api".try_into().unwrap()),
            SanType::URI("spiffe://filebelt.test/web-io".try_into().unwrap()),
        ];
        let certificate = parameters
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        let allowed = BTreeSet::from(["spiffe://filebelt.test/web-api".to_owned()]);
        assert!(
            !certificate_has_allowed_uri(certificate.der(), &allowed, &BTreeSet::new()).unwrap()
        );
    }

    #[test]
    fn bounded_gauge_family_encodes_one_metric_family() {
        let state = OperationsState::new("test-role", true, || async { true });
        let capacity = state.register_gauge_family(
            "storage_capacity_bytes",
            "Last observed payload storage capacity.",
            "kind",
            &["total", "free"],
        );
        capacity[0].set(10);
        capacity[1].set(4);
        let mut output = String::new();
        prometheus_client::encoding::text::encode(
            &mut output,
            &state.inner.registry.lock().unwrap(),
        )
        .unwrap();
        assert_eq!(
            output
                .matches("# HELP filebelt_storage_capacity_bytes")
                .count(),
            1
        );
        assert!(output.contains("filebelt_storage_capacity_bytes{kind=\"total\"} 10"));
        assert!(output.contains("filebelt_storage_capacity_bytes{kind=\"free\"} 4"));
        assert!(output.contains("filebelt_build_info{role=\"test-role\"} 1"));
        assert!(!output.contains("filebelt_build_info_info"));
    }

    #[test]
    fn client_chain_expiry_eku_and_exact_uri_are_enforced() {
        let allowed = "spiffe://filebelt.test/web-api";
        let (valid, roots) =
            signed_client_certificate(allowed, 2025, 2030, ExtendedKeyUsagePurpose::ClientAuth);
        let valid_verifier = verifier(roots, allowed);
        assert!(valid_verifier.client_auth_mandatory());
        assert!(
            valid_verifier
                .verify_client_cert(&valid, &[], test_time())
                .is_ok()
        );

        let (wrong_uri, roots) = signed_client_certificate(
            "spiffe://filebelt.test/wrong",
            2025,
            2030,
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        assert!(
            verifier(roots, allowed)
                .verify_client_cert(&wrong_uri, &[], test_time())
                .is_err()
        );

        let (expired, roots) =
            signed_client_certificate(allowed, 2020, 2021, ExtendedKeyUsagePurpose::ClientAuth);
        assert!(
            verifier(roots, allowed)
                .verify_client_cert(&expired, &[], test_time())
                .is_err()
        );

        let (server_only, roots) =
            signed_client_certificate(allowed, 2025, 2030, ExtendedKeyUsagePurpose::ServerAuth);
        assert!(
            verifier(roots, allowed)
                .verify_client_cert(&server_only, &[], test_time())
                .is_err()
        );
    }

    #[tokio::test]
    async fn stalled_handshake_does_not_block_a_valid_client() {
        let mut ca_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_parameters, ca_key);

        let mut server_parameters = CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_certificate = server_parameters.signed_by(&server_key, &issuer).unwrap();

        let identity = "spiffe://filebelt.test/web-api";
        let mut client_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_parameters.subject_alt_names = vec![SanType::URI(identity.try_into().unwrap())];
        client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_certificate = client_parameters.signed_by(&client_key, &issuer).unwrap();

        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "filebelt-runtime-mtls-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let certificate_path = directory.join("server.crt");
        let private_key_path = directory.join("server.key");
        let client_ca_path = directory.join("client-ca.crt");
        fs::write(&certificate_path, server_certificate.pem()).unwrap();
        fs::write(&private_key_path, server_key.serialize_pem()).unwrap();
        fs::write(&client_ca_path, ca_certificate.pem()).unwrap();

        let settings = BackendServerTlsConfig {
            certificate_chain_file: certificate_path,
            private_key_file: private_key_path,
            client_ca_file: client_ca_path,
            allowed_client_uri_sans: vec![identity.into()],
            allowed_client_trust_domains: Vec::new(),
        };
        let mut listener = MtlsListener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &settings,
        )
        .await
        .unwrap();
        let address = listener.local_addr().unwrap();
        let _stalled = TcpStream::connect(address).await.unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(ca_certificate.der().clone()).unwrap();
        let client_config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![client_certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
        )
        .unwrap();
        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap().to_owned();
        let (connected, _) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(connector.connect(server_name, stream), listener.accept())
        })
        .await
        .expect("valid handshake was blocked by the stalled connection");
        connected.unwrap();

        fs::remove_dir_all(directory).unwrap();
    }
}

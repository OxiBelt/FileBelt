// SPDX-License-Identifier: Apache-2.0

//! Private TLS listener for the isolated FileBelt Git revision adapter.

#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use filebelt_git_adapter::{
    DEFAULT_MAX_CONCURRENT_GIT_PROCESSES, GitRepository, MAX_MAX_CONCURRENT_GIT_PROCESSES,
    MIN_MAX_CONCURRENT_GIT_PROCESSES, dispatch,
};
use filebelt_revision_protocol::{MAX_FRAME_BYTES, RevisionExecuteRequest, encode_frame};
use prost::Message as _;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore,
    SignatureScheme,
};
use serde::Deserialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const COORDINATOR_URI_SAN: &str = "spiffe://filebelt/revision-coordinator/git";
const DEFAULT_MAX_CONCURRENT_PRIVATE_REQUESTS: usize = 8;
const MIN_MAX_CONCURRENT_PRIVATE_REQUESTS: usize = 1;
const MAX_MAX_CONCURRENT_PRIVATE_REQUESTS: usize = 64;
const USAGE: &str = "usage: filebelt-git-adapter serve --config <strict-toml-path> [--max-concurrent-private-requests <1..64>] [--max-concurrent-git-processes <1..16>]";

#[derive(Debug, Eq, PartialEq)]
struct ServeArguments {
    config_path: PathBuf,
    max_concurrent_private_requests: usize,
    max_concurrent_git_processes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: std::net::SocketAddr,
    operations_listen: std::net::SocketAddr,
    repository_root: PathBuf,
    git_binary: PathBuf,
    server_tls: ServerTls,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerTls {
    certificate_chain_file: PathBuf,
    private_key_file: PathBuf,
    client_ca_file: PathBuf,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("filebelt-git-adapter: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let arguments = parse_serve_arguments(env::args_os().skip(1))?;
    let config: Config = toml::from_str(
        &std::fs::read_to_string(&arguments.config_path)
            .map_err(|_| "cannot read configuration")?,
    )
    .map_err(|_| "configuration is invalid")?;
    let repository = Arc::new(
        GitRepository::with_max_concurrent_processes(
            config.repository_root,
            config.git_binary,
            arguments.max_concurrent_git_processes,
        )
        .map_err(|_| "Git process admission limit is invalid")?,
    );
    repository
        .verify_system_git()
        .await
        .map_err(|_| "requires exactly system Git 2.55.0")?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config(&config.server_tls)?));
    let private_listener = TcpListener::bind(config.listen)
        .await
        .map_err(|_| "cannot bind private listener")?;
    let operations_listener = TcpListener::bind(config.operations_listen)
        .await
        .map_err(|_| "cannot bind operations listener")?;
    tokio::select! {
        result = serve_private(
            private_listener,
            acceptor,
            repository,
            arguments.max_concurrent_private_requests,
        ) => result,
        result = serve_operations(operations_listener) => result,
    }
}

fn parse_serve_arguments(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<ServeArguments, String> {
    if arguments.next().as_deref() != Some(OsStr::new("serve")) {
        return Err(USAGE.into());
    }
    let mut config_path = None;
    let mut max_concurrent_private_requests = DEFAULT_MAX_CONCURRENT_PRIVATE_REQUESTS;
    let mut max_concurrent_git_processes = DEFAULT_MAX_CONCURRENT_GIT_PROCESSES;
    let mut saw_private_limit = false;
    let mut saw_git_limit = false;
    while let Some(argument) = arguments.next() {
        match argument.as_os_str() {
            value if value == OsStr::new("--config") => {
                if config_path.is_some() {
                    return Err("configuration path was provided more than once".into());
                }
                config_path = Some(PathBuf::from(
                    arguments.next().ok_or("missing configuration path")?,
                ));
            }
            value if value == OsStr::new("--max-concurrent-private-requests") => {
                if saw_private_limit {
                    return Err("private request limit was provided more than once".into());
                }
                saw_private_limit = true;
                max_concurrent_private_requests = parse_limit(
                    arguments.next().ok_or("missing private request limit")?,
                    "private request limit",
                    MIN_MAX_CONCURRENT_PRIVATE_REQUESTS,
                    MAX_MAX_CONCURRENT_PRIVATE_REQUESTS,
                )?;
            }
            value if value == OsStr::new("--max-concurrent-git-processes") => {
                if saw_git_limit {
                    return Err("Git process limit was provided more than once".into());
                }
                saw_git_limit = true;
                max_concurrent_git_processes = parse_limit(
                    arguments.next().ok_or("missing Git process limit")?,
                    "Git process limit",
                    MIN_MAX_CONCURRENT_GIT_PROCESSES,
                    MAX_MAX_CONCURRENT_GIT_PROCESSES,
                )?;
            }
            _ => return Err("unexpected command-line argument".into()),
        }
    }
    if max_concurrent_git_processes > max_concurrent_private_requests {
        return Err("Git process limit exceeds the private request limit".into());
    }
    Ok(ServeArguments {
        config_path: config_path.ok_or("missing configuration path")?,
        max_concurrent_private_requests,
        max_concurrent_git_processes,
    })
}

fn parse_limit(
    value: OsString,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<usize, String> {
    let parsed = value
        .to_str()
        .ok_or_else(|| format!("{name} is invalid"))?
        .parse::<usize>()
        .map_err(|_| format!("{name} is invalid"))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(format!("{name} is outside {minimum}..={maximum}"));
    }
    Ok(parsed)
}

async fn serve_private(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    repository: Arc<GitRepository>,
    max_concurrent_private_requests: usize,
) -> Result<(), String> {
    let task_admission = Arc::new(Semaphore::new(max_concurrent_private_requests));
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|_| "cannot accept private connection")?;
        let Some(task_permit) = admit_private_task(&task_admission) else {
            continue;
        };
        let acceptor = acceptor.clone();
        let repository = Arc::clone(&repository);
        tokio::spawn(async move {
            let _task_permit = task_permit;
            let Ok(Ok(stream)) = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await else {
                return;
            };
            let _ = timeout(REQUEST_TIMEOUT, handle_request(stream, repository)).await;
        });
    }
}

fn admit_private_task(admission: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(admission).try_acquire_owned().ok()
}

async fn handle_request(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    repository: Arc<GitRepository>,
) -> Result<(), ()> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).await.map_err(|_| ())?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(());
    }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).await.map_err(|_| ())?;
    let request = RevisionExecuteRequest::decode(body.as_slice()).map_err(|_| ())?;
    let response = dispatch(&repository, request).await;
    let frame = encode_frame(&response).map_err(|_| ())?;
    stream.write_all(&frame).await.map_err(|_| ())?;
    stream.shutdown().await.map_err(|_| ())
}

async fn serve_operations(listener: TcpListener) -> Result<(), String> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|_| "cannot accept operations connection")?;
        tokio::spawn(async move {
            let mut request = [0_u8; 256];
            let Ok(length) = timeout(Duration::from_secs(2), stream.read(&mut request)).await
            else {
                return;
            };
            let Ok(length) = length else { return };
            let status = if request[..length].starts_with(b"GET /health/live ")
                || request[..length].starts_with(b"GET /health/ready ")
            {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".as_slice()
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .as_slice()
            };
            let _ = stream.write_all(status).await;
        });
    }
}

fn server_config(config: &ServerTls) -> Result<rustls::ServerConfig, String> {
    let chain = CertificateDer::pem_file_iter(&config.certificate_chain_file)
        .map_err(|_| "cannot read server certificate")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "server certificate is invalid")?;
    let key = PrivateKeyDer::from_pem_file(&config.private_key_file)
        .map_err(|_| "server private key is invalid")?;
    let ca = CertificateDer::pem_file_iter(&config.client_ca_file)
        .map_err(|_| "cannot read client CA")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "client CA is invalid")?;
    if chain.is_empty() || ca.is_empty() {
        return Err("TLS material is empty".into());
    }
    let mut roots = RootCertStore::empty();
    for certificate in ca {
        roots.add(certificate).map_err(|_| "client CA is invalid")?;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
        .build()
        .map_err(|_| "cannot configure client CA")?;
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "cannot require TLS 1.3")?
        .with_client_cert_verifier(Arc::new(ExactUriVerifier {
            inner,
            allowed: COORDINATOR_URI_SAN,
        }))
        .with_single_cert(chain, key)
        .map_err(|_| "server key and certificate do not match".into())
}

#[derive(Debug)]
struct ExactUriVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allowed: &'static str,
}

impl ClientCertVerifier for ExactUriVerifier {
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
        if has_exact_uri(end_entity.as_ref(), self.allowed) {
            Ok(verified)
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
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

fn has_exact_uri(certificate: &[u8], allowed: &str) -> bool {
    let Ok((_, certificate)) = parse_x509_certificate(certificate) else {
        return false;
    };
    let Ok(Some(extension)) = certificate.subject_alternative_name() else {
        return false;
    };
    let uris = extension
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    uris.len() == 1 && uris.contains(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> impl Iterator<Item = OsString> {
        values
            .iter()
            .map(|value| OsString::from(*value))
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn serve_arguments_apply_bounded_defaults_and_overrides() {
        assert_eq!(
            parse_serve_arguments(arguments(&["serve", "--config", "/adapter.toml"])).unwrap(),
            ServeArguments {
                config_path: PathBuf::from("/adapter.toml"),
                max_concurrent_private_requests: 8,
                max_concurrent_git_processes: 2,
            }
        );
        assert_eq!(
            parse_serve_arguments(arguments(&[
                "serve",
                "--max-concurrent-git-processes",
                "4",
                "--config",
                "/adapter.toml",
                "--max-concurrent-private-requests",
                "12",
            ]))
            .unwrap(),
            ServeArguments {
                config_path: PathBuf::from("/adapter.toml"),
                max_concurrent_private_requests: 12,
                max_concurrent_git_processes: 4,
            }
        );
    }

    #[test]
    fn serve_arguments_reject_invalid_admission_limits() {
        for values in [
            vec![
                "serve",
                "--config",
                "/adapter.toml",
                "--max-concurrent-private-requests",
                "0",
            ],
            vec![
                "serve",
                "--config",
                "/adapter.toml",
                "--max-concurrent-git-processes",
                "17",
            ],
            vec![
                "serve",
                "--config",
                "/adapter.toml",
                "--max-concurrent-private-requests",
                "1",
                "--max-concurrent-git-processes",
                "2",
            ],
        ] {
            assert!(parse_serve_arguments(arguments(&values)).is_err());
        }
    }

    #[test]
    fn private_request_task_admission_closes_and_reuses_capacity() {
        let admission = Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_PRIVATE_REQUESTS));
        let mut admitted = (0..DEFAULT_MAX_CONCURRENT_PRIVATE_REQUESTS)
            .map(|_| admit_private_task(&admission).expect("request should be admitted"))
            .collect::<Vec<_>>();
        assert!(admit_private_task(&admission).is_none());
        admitted.pop();
        assert!(admit_private_task(&admission).is_some());
    }
}

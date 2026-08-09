// SPDX-License-Identifier: AGPL-3.0-only

//! Adapter-local TLS 1.3 server with one exact OxiBelt SPIFFE client identity.

use crate::config::ServerTlsConfig;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore,
    SignatureScheme,
};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct AdapterTlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl AdapterTlsListener {
    pub async fn bind(address: SocketAddr, config: &ServerTlsConfig) -> Result<Self, String> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("cannot bind adapter TLS listener: {error}"))?;
        let server = server_config(config)?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(server)),
        })
    }

    pub async fn accept(&self) -> Result<TlsStream<TcpStream>, String> {
        loop {
            let (stream, _) = self
                .listener
                .accept()
                .await
                .map_err(|error| format!("cannot accept adapter TLS connection: {error}"))?;
            match timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(stream)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(_)) | Err(_) => continue,
            }
        }
    }
}

fn server_config(config: &ServerTlsConfig) -> Result<rustls::ServerConfig, String> {
    let chain = CertificateDer::pem_file_iter(&config.certificate_chain_file)
        .map_err(|error| format!("cannot read adapter server certificate chain: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("adapter server certificate chain is invalid PEM: {error}"))?;
    if chain.is_empty() {
        return Err("adapter server certificate chain is empty".into());
    }
    let key = PrivateKeyDer::from_pem_file(&config.private_key_file)
        .map_err(|error| format!("adapter server private key is invalid PEM: {error}"))?;
    let ca = CertificateDer::pem_file_iter(&config.client_ca_file)
        .map_err(|error| format!("cannot read adapter client CA: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("adapter client CA is invalid PEM: {error}"))?;
    if ca.is_empty() {
        return Err("adapter client CA is empty".into());
    }
    let mut roots = RootCertStore::empty();
    for certificate in ca {
        roots
            .add(certificate)
            .map_err(|error| format!("adapter client CA is invalid: {error}"))?;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
        .build()
        .map_err(|error| format!("cannot build adapter client verifier: {error}"))?;
    let verifier = ExactUriClientVerifier {
        inner,
        allowed: config.allowed_client_uri_san.clone(),
    };
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("cannot build adapter TLS 1.3 configuration: {error}"))?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(chain, key)
        .map_err(|error| format!("adapter certificate/key pair is invalid: {error}"))
}

#[derive(Debug)]
struct ExactUriClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allowed: String,
}

impl ClientCertVerifier for ExactUriClientVerifier {
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
        if !certificate_has_exact_uri(end_entity.as_ref(), &self.allowed) {
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

fn certificate_has_exact_uri(certificate: &[u8], allowed: &str) -> bool {
    let Ok((_, certificate)) = parse_x509_certificate(certificate) else {
        return false;
    };
    let Ok(Some(extension)) = certificate.subject_alternative_name() else {
        return false;
    };
    let names = extension
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    names.len() == 1 && names.contains(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absent_or_multiple_uri_identity() {
        assert!(!certificate_has_exact_uri(
            &[],
            "spiffe://filebelt/oxibelt/onlyoffice"
        ));
    }
}

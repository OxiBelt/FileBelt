// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::{RELAY_ALPN, RelayConfig};

pub(crate) type RelayTlsStream = TlsStream<TcpStream>;
pub(crate) type TargetTlsStream = TlsStream<RelayTlsStream>;

#[derive(Clone)]
pub(crate) struct TunnelConnector {
    relay_addresses: Arc<[SocketAddr]>,
    relay_server_name: ServerName<'static>,
    relay_tls: TlsConnector,
    target_server_name: ServerName<'static>,
    target_tls: TlsConnector,
    connect_timeout: Duration,
}

impl TunnelConnector {
    pub(crate) fn new(
        relay: &RelayConfig,
        target_server_name: &str,
        target_ca_file: &Path,
        connect_timeout: Duration,
    ) -> Result<Self, String> {
        let mut relay_config = client_identity_config(
            &relay.ca_file,
            &relay.certificate_chain_file,
            &relay.private_key_file,
        )?;
        relay_config.alpn_protocols = vec![RELAY_ALPN.to_vec()];
        let target_config = server_auth_config(target_ca_file)?;
        Ok(Self {
            relay_addresses: Arc::from(relay.addresses.clone()),
            relay_server_name: server_name(&relay.server_name)?,
            relay_tls: TlsConnector::from(Arc::new(relay_config)),
            target_server_name: server_name(target_server_name)?,
            target_tls: TlsConnector::from(Arc::new(target_config)),
            connect_timeout,
        })
    }

    pub(crate) async fn connect(&self) -> Result<TargetTlsStream, TunnelError> {
        for address in self.relay_addresses.iter() {
            let Ok(Ok(tcp)) =
                tokio::time::timeout(self.connect_timeout, TcpStream::connect(*address)).await
            else {
                continue;
            };
            let Ok(Ok(relay)) = tokio::time::timeout(
                self.connect_timeout,
                self.relay_tls.connect(self.relay_server_name.clone(), tcp),
            )
            .await
            else {
                continue;
            };
            if relay.get_ref().1.alpn_protocol() != Some(RELAY_ALPN) {
                continue;
            }
            let target = tokio::time::timeout(
                self.connect_timeout,
                self.target_tls
                    .connect(self.target_server_name.clone(), relay),
            )
            .await
            .map_err(|_| TunnelError::TargetTls)?
            .map_err(|_| TunnelError::TargetTls)?;
            return Ok(target);
        }
        Err(TunnelError::RelayUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunnelError {
    RelayUnavailable,
    TargetTls,
}

fn client_identity_config(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<ClientConfig, String> {
    let roots = root_store(ca_file)?;
    let certificates = CertificateDer::pem_file_iter(certificate_file)
        .map_err(|_| "cannot read relay client certificate")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "relay client certificate is invalid PEM")?;
    if certificates.is_empty() {
        return Err("relay client certificate chain is empty".into());
    }
    let private_key = PrivateKeyDer::from_pem_file(private_key_file)
        .map_err(|_| "relay client private key is invalid PEM")?;
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "cannot configure relay TLS version")?
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, private_key)
        .map_err(|_| "cannot configure relay client identity".into())
}

fn server_auth_config(ca_file: &Path) -> Result<ClientConfig, String> {
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "cannot configure target TLS versions")?
    .with_root_certificates(root_store(ca_file)?)
    .with_no_client_auth();
    Ok(config)
}

fn root_store(path: &Path) -> Result<RootCertStore, String> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|_| "cannot read TLS CA")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "TLS CA is invalid PEM")?;
    if certificates.is_empty() {
        return Err("TLS CA is empty".into());
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| "TLS CA certificate is invalid")?;
    }
    Ok(roots)
}

fn server_name(value: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(value.to_owned()).map_err(|_| "TLS server name is invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_alpn_is_exact_and_versioned() {
        assert_eq!(RELAY_ALPN, b"filebelt-private-egress/1");
        assert!(!RELAY_ALPN.contains(&b'\n'));
    }
}

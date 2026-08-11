// SPDX-License-Identifier: LGPL-3.0-or-later

//! Bounded, exact-origin mTLS transport for the generic VFS protocol.

use crate::config::{BridgeConfig, REQUIRED_GATEWAY_URI_SAN, require_regular_file};
use filebelt_vfs_protocol::{MAX_RESPONSE_BYTES, VfsRequest, VfsResponse};
use prost::Message;
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use reqwest::redirect::Policy;
use reqwest::tls::Version;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use std::fs;
use std::io::Read;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;
use zeroize::{Zeroize, Zeroizing};

const PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";
const MAX_ATTEMPTS: usize = 5;
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(5);
static TLS_PROVIDER: OnceLock<Result<(), ()>> = OnceLock::new();

#[derive(Clone)]
pub struct VfsClient {
    endpoint: reqwest::Url,
    client: Client,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum VfsClientError {
    #[error("VFS mTLS configuration is invalid")]
    Tls,
    #[error("VFS request is invalid")]
    Request,
    #[error("VFS transport is unavailable")]
    Unavailable,
    #[error("VFS response is invalid or exceeds its bound")]
    Response,
}

impl VfsClient {
    pub fn new(config: &BridgeConfig) -> Result<Self, VfsClientError> {
        require_regular_file(&config.tls.certificate_chain_file, false)
            .map_err(|_| VfsClientError::Tls)?;
        require_regular_file(&config.tls.private_key_file, true)
            .map_err(|_| VfsClientError::Tls)?;
        require_regular_file(&config.tls.server_ca_file, false).map_err(|_| VfsClientError::Tls)?;

        let certificates = CertificateDer::pem_file_iter(&config.tls.certificate_chain_file)
            .map_err(|_| VfsClientError::Tls)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| VfsClientError::Tls)?;
        if certificates.is_empty()
            || !certificate_has_exact_uri(certificates[0].as_ref(), REQUIRED_GATEWAY_URI_SAN)
        {
            return Err(VfsClientError::Tls);
        }

        let mut identity_pem = Zeroizing::new(
            fs::read(&config.tls.certificate_chain_file).map_err(|_| VfsClientError::Tls)?,
        );
        identity_pem.extend_from_slice(b"\n");
        let mut private_key = Zeroizing::new(
            fs::read(&config.tls.private_key_file).map_err(|_| VfsClientError::Tls)?,
        );
        identity_pem.extend_from_slice(private_key.as_slice());
        private_key.zeroize();
        let identity = reqwest::Identity::from_pem(identity_pem.as_slice())
            .map_err(|_| VfsClientError::Tls)?;
        identity_pem.zeroize();
        let ca_pem = fs::read(&config.tls.server_ca_file).map_err(|_| VfsClientError::Tls)?;
        let roots =
            reqwest::Certificate::from_pem_bundle(&ca_pem).map_err(|_| VfsClientError::Tls)?;
        if roots.is_empty() {
            return Err(VfsClientError::Tls);
        }
        TLS_PROVIDER
            .get_or_init(|| {
                rustls::crypto::aws_lc_rs::default_provider()
                    .install_default()
                    .map_err(|_| ())
            })
            .as_ref()
            .map_err(|_| VfsClientError::Tls)?;
        let mut builder = Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .min_tls_version(Version::TLS_1_3)
            .max_tls_version(Version::TLS_1_3)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .identity(identity);
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
        let client = builder.build().map_err(|_| VfsClientError::Tls)?;
        let endpoint = reqwest::Url::parse(&config.vfs_url).map_err(|_| VfsClientError::Tls)?;
        Ok(Self { endpoint, client })
    }

    pub fn execute(&self, request: &VfsRequest) -> Result<VfsResponse, VfsClientError> {
        self.execute_with_policy(request, MAX_ATTEMPTS, Duration::from_secs(20))
    }

    /// Gateway lease work runs outside the callback lock, but still uses one
    /// bounded attempt so stale lifecycle work cannot accumulate indefinitely.
    pub fn execute_lifecycle(&self, request: &VfsRequest) -> Result<VfsResponse, VfsClientError> {
        self.execute_with_policy(request, 1, LIFECYCLE_TIMEOUT)
    }

    fn execute_with_policy(
        &self,
        request: &VfsRequest,
        attempts: usize,
        timeout: Duration,
    ) -> Result<VfsResponse, VfsClientError> {
        let fence = request.validate().map_err(|_| VfsClientError::Request)?;
        let request_id = fence.request_id;
        let encoded = Zeroizing::new(request.encode_to_vec());
        let mut delay = Duration::from_millis(50);
        for attempt in 0..attempts {
            let response = self
                .client
                .post(self.endpoint.clone())
                .header(CONTENT_TYPE, PROTOBUF_CONTENT_TYPE)
                .body(encoded.as_slice().to_vec())
                .timeout(timeout)
                .send();
            match response {
                Ok(response) if response.status().is_success() => {
                    if response
                        .headers()
                        .get(CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        != Some(PROTOBUF_CONTENT_TYPE)
                    {
                        return Err(VfsClientError::Response);
                    }
                    return decode_response(response, request_id);
                }
                Ok(response) if !response.status().is_server_error() => {
                    return Err(VfsClientError::Unavailable);
                }
                Ok(_) | Err(_) if attempt + 1 < attempts => {
                    thread::sleep(delay);
                    delay = delay.saturating_mul(2);
                }
                Ok(_) | Err(_) => return Err(VfsClientError::Unavailable),
            }
        }
        Err(VfsClientError::Unavailable)
    }
}

fn decode_response(
    response: reqwest::blocking::Response,
    request_id: Uuid,
) -> Result<VfsResponse, VfsClientError> {
    let mut encoded = Vec::new();
    response
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| VfsClientError::Response)?;
    if encoded.len() > MAX_RESPONSE_BYTES {
        encoded.zeroize();
        return Err(VfsClientError::Response);
    }
    let decoded = VfsResponse::decode(encoded.as_slice()).map_err(|_| VfsClientError::Response);
    encoded.zeroize();
    let decoded = decoded?;
    decoded
        .validate_for(request_id)
        .map_err(|_| VfsClientError::Response)?;
    Ok(decoded)
}

fn certificate_has_exact_uri(certificate: &[u8], allowed: &str) -> bool {
    let Ok((_, certificate)) = parse_x509_certificate(certificate) else {
        return false;
    };
    let Ok(Some(extension)) = certificate.subject_alternative_name() else {
        return false;
    };
    let mut names = extension
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        });
    names.next() == Some(allowed) && names.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::certificate_has_exact_uri;

    #[test]
    fn arbitrary_or_absent_certificates_cannot_assert_the_gateway_identity() {
        assert!(!certificate_has_exact_uri(
            b"not a certificate",
            "spiffe://filebelt/nfs-gateway/vfs"
        ));
    }
}

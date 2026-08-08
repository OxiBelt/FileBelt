// SPDX-License-Identifier: GPL-3.0-or-later

//! Typed boundary for the Apache-licensed, protocol-neutral VFS RPC.
//!
//! The FTPS `Authenticate.exchange` bytes carry the raw FTP `PASS` value only
//! across the mutually authenticated VFS transport. Core verifies it against
//! its encrypted `HMAC(pepper, password)` verifier; the gateway neither holds
//! the pepper nor computes a verifier. The password is never logged or
//! persisted and the transport must clear the envelope after each attempt.

use filebelt_vfs_protocol::vfs_request::Operation;
use filebelt_vfs_protocol::{
    AuthenticateRequest, AuthenticationScheme, GatewayHelloRequest, MountProtocol,
    PROTOCOL_VERSION, VfsError, VfsRequest, VfsResponse,
};
use std::fmt;
use std::net::IpAddr;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::GatewayError;

/// Identity of one gateway instance, used in every VFS envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayIdentity {
    pub tenant_id: Uuid,
    pub gateway_id: String,
    pub gateway_epoch: u64,
}

impl GatewayIdentity {
    /// Builds the epoch-claim request. The VFS protocol requires epoch zero for
    /// this bootstrap operation; the caller must replace it with the returned
    /// epoch before sending any authentication or filesystem operation.
    pub fn gateway_hello(&self, shard_key: impl Into<String>) -> VfsRequest {
        VfsRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            tenant_id: self.tenant_id.to_string(),
            protocol: MountProtocol::Ftps as i32,
            gateway_id: self.gateway_id.clone(),
            gateway_epoch: 0,
            operation: Some(Operation::GatewayHello(GatewayHelloRequest {
                shard_key: shard_key.into(),
            })),
            ..VfsRequest::default()
        }
    }
}

/// An ephemeral FTPS password exchange value.
///
/// The generated protocol currently names the scheme `PASSWORD_HMAC_SHA256`,
/// but its `exchange` field is the raw password that VFS verifies server-side.
/// This type avoids exposing password bytes through `Debug` and zeroizes its
/// owned buffer if request construction fails.
pub struct EphemeralPassword(Zeroizing<Vec<u8>>);

impl EphemeralPassword {
    pub fn new(password: Vec<u8>) -> Result<Self, GatewayError> {
        if !(32..=4_096).contains(&password.len()) {
            return Err(GatewayError::AuthenticationFailed);
        }
        Ok(Self(Zeroizing::new(password)))
    }

    fn into_exchange(mut self) -> Vec<u8> {
        std::mem::take(self.0.as_mut())
    }
}

impl fmt::Debug for EphemeralPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralPassword(***)")
    }
}

/// Owns an authentication envelope whose raw password exchange is cleared on
/// explicit completion and on drop. A transport must encode only
/// [`Self::request`] and must independently zeroize any serialized request
/// buffer it creates.
pub struct EphemeralAuthenticationRequest {
    request: VfsRequest,
}

impl EphemeralAuthenticationRequest {
    pub fn request(&self) -> &VfsRequest {
        &self.request
    }

    /// Clears the password as soon as the mTLS transport has finished using
    /// the request, regardless of its outcome.
    pub fn clear(&mut self) {
        clear_authentication_exchange(&mut self.request);
    }
}

impl fmt::Debug for EphemeralAuthenticationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralAuthenticationRequest(***)")
    }
}

impl Drop for EphemeralAuthenticationRequest {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Builds only validated VFS envelopes. Transport, mTLS material, and retry
/// policy remain replaceable adapter concerns.
#[derive(Clone, Debug)]
pub struct VfsRequestFactory {
    identity: GatewayIdentity,
}

impl VfsRequestFactory {
    pub fn new(identity: GatewayIdentity) -> Result<Self, GatewayError> {
        if identity.gateway_epoch == 0 || identity.gateway_id.is_empty() {
            return Err(GatewayError::GatewayDraining);
        }
        Ok(Self { identity })
    }

    /// Creates the FTPS authentication envelope without retaining a second
    /// password copy. The mTLS transport must call
    /// [`EphemeralAuthenticationRequest::clear`] after every send attempt; it
    /// must never log or persist this request. A response must be checked with
    /// [`validate_response`] before a session is admitted to the storage bridge.
    pub fn authenticate(
        &self,
        username: impl Into<String>,
        password: EphemeralPassword,
        source_address: IpAddr,
        device_id: Option<Uuid>,
        channel_binding: Vec<u8>,
    ) -> Result<EphemeralAuthenticationRequest, GatewayError> {
        let mut request = VfsRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            tenant_id: self.identity.tenant_id.to_string(),
            protocol: MountProtocol::Ftps as i32,
            gateway_id: self.identity.gateway_id.clone(),
            gateway_epoch: self.identity.gateway_epoch,
            operation: Some(Operation::Authenticate(AuthenticateRequest {
                username: username.into(),
                scheme: AuthenticationScheme::PasswordHmacSha256 as i32,
                exchange: password.into_exchange(),
                channel_binding,
                source_address: source_address.to_string(),
                device_id: device_id.map_or_else(String::new, |id| id.to_string()),
            })),
            ..VfsRequest::default()
        };
        if request.validate().is_err() {
            clear_authentication_exchange(&mut request);
            return Err(GatewayError::AuthenticationFailed);
        }
        Ok(EphemeralAuthenticationRequest { request })
    }
}

/// Clears raw `PASS` material from an authentication envelope after its mTLS
/// transport attempt, whether that attempt succeeds, fails, or times out.
pub fn clear_authentication_exchange(request: &mut VfsRequest) {
    if let Some(Operation::Authenticate(authentication)) = request.operation.as_mut() {
        authentication.exchange.zeroize();
    }
}

/// Validates response correlation and maps the VFS's deliberately-small error
/// vocabulary into the FTP-facing gateway vocabulary without exposing whether
/// a resource exists.
pub fn validate_response(request: &VfsRequest, response: &VfsResponse) -> Result<(), GatewayError> {
    let request_id =
        Uuid::parse_str(&request.request_id).map_err(|_| GatewayError::StorageUnavailable)?;
    response
        .validate_for(request_id)
        .map_err(|_| GatewayError::StorageUnavailable)?;
    match VfsError::try_from(response.error).map_err(|_| GatewayError::StorageUnavailable)? {
        VfsError::Ok => Ok(()),
        VfsError::Unauthenticated => Err(GatewayError::SessionRevoked),
        VfsError::AccessDenied
        | VfsError::NotFound
        | VfsError::NotDirectory
        | VfsError::IsDirectory
        | VfsError::DirectoryNotEmpty
        | VfsError::NameInvalid => Err(GatewayError::AuthorizationDenied),
        VfsError::AlreadyExists
        | VfsError::Conflict
        | VfsError::StaleGeneration
        | VfsError::LockConflict
        | VfsError::LeaseBreakRequired => Err(GatewayError::Conflict),
        VfsError::QuotaExceeded => Err(GatewayError::QuotaExceeded),
        VfsError::InvalidRequest | VfsError::NotSupported => Err(GatewayError::UnsupportedCommand),
        VfsError::StorageUnavailable
        | VfsError::RateLimited
        | VfsError::Unavailable
        | VfsError::Unspecified => Err(GatewayError::StorageUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> GatewayIdentity {
        GatewayIdentity {
            tenant_id: Uuid::new_v4(),
            gateway_id: "ftp-ftps-0".into(),
            gateway_epoch: 7,
        }
    }

    #[test]
    fn hello_uses_only_the_zero_epoch_bootstrap_envelope() {
        let request = identity().gateway_hello("zone-a");
        assert_eq!(request.gateway_epoch, 0);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn authentication_carries_the_ephemeral_raw_password_exchange() {
        let factory = VfsRequestFactory::new(identity()).unwrap();
        let mut request = factory
            .authenticate(
                "fb-0123456789abcdef",
                EphemeralPassword::new(vec![5; 32]).unwrap(),
                "192.0.2.10".parse().unwrap(),
                None,
                Vec::new(),
            )
            .unwrap();
        assert!(request.request().validate().is_ok());
        let Some(Operation::Authenticate(authentication)) = request.request().operation.as_ref()
        else {
            panic!("expected authentication operation");
        };
        assert_eq!(
            authentication.scheme,
            AuthenticationScheme::PasswordHmacSha256 as i32
        );
        assert_eq!(authentication.exchange, vec![5; 32]);
        request.clear();
        let Some(Operation::Authenticate(authentication)) = request.request().operation.as_ref()
        else {
            panic!("expected authentication operation");
        };
        assert!(authentication.exchange.is_empty());
    }

    #[test]
    fn response_mapping_hides_denied_and_missing_resources() {
        let request = identity().gateway_hello("zone-a");
        let request_id = Uuid::parse_str(&request.request_id).unwrap();
        let response =
            VfsResponse::failure(request_id, VfsError::NotFound, "vfs.resource_not_found");
        assert_eq!(
            validate_response(&request, &response),
            Err(GatewayError::AuthorizationDenied)
        );
    }
}

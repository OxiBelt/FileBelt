// SPDX-License-Identifier: Apache-2.0

//! Capability-limited storage protocol and purpose-bound AWS-LC Ed25519 envelopes.

#![deny(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::Ed25519KeyPair;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use filebelt_capability_keyset::{
    ApiStorageKeyset, CollaborationStorageKeyset, DocumentStorageKeyset, KeysetError,
    MountStorageKeyset,
};
use prost::Message;
use thiserror::Error;
use uuid::Uuid;

/// Maximum admission lifetime for a freshly issued data-plane capability.
pub const MAX_CAPABILITY_LIFETIME_SECONDS: i64 = 60;
pub const MAX_MOUNT_CAPABILITY_LIFETIME_SECONDS: i64 = 15;
const CAPABILITY_SIGNATURE_DOMAIN: &[u8] = b"filebelt.storage.capability.v1\0";
const MOUNT_CAPABILITY_SIGNATURE_DOMAIN: &[u8] = b"filebelt.storage.mount-capability.v2\0";

mod generated {
    include!("../../../../protocol/generated/rust/filebelt/storage/v1/filebelt.storage.v1.rs");
}

pub use generated::{
    CapabilityClaims, CapabilityOperation, MountCapabilityClaims, MountCapabilityOperation,
    SignedCapability, SignedMountCapability,
};

/// An authenticated claim together with the rotation generation that verified it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified<T> {
    pub claims: T,
    pub generation: u32,
}

/// The only API-issued `fbcap1` uses accepted by the I/O worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiStorageCapabilityUse {
    UploadPart,
    FinalizeUpload,
    Download,
}

/// The only collaboration-issued `fbcap1` uses accepted by the I/O worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollaborationStorageCapabilityUse {
    WriteObject,
    FinalizeObject,
    ReadObject,
}

/// The only document-issued `fbcap1` uses accepted by the I/O worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentStorageCapabilityUse {
    ReadVersion,
    WriteRevision,
    FinalizeRevision,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("capability wire encoding is invalid")]
    InvalidEncoding,
    #[error("capability signature is invalid")]
    InvalidSignature,
    #[error("capability key generation is unknown")]
    UnknownKey,
    #[error("capability claims are invalid")]
    InvalidClaims,
    #[error("capability audience does not match")]
    WrongAudience,
    #[error("capability operation does not match")]
    WrongOperation,
    #[error("capability is expired or not yet valid")]
    Expired,
    #[error("capability lifetime exceeds the admission maximum")]
    LifetimeTooLong,
}

impl ApiStorageCapabilityUse {
    const fn operation(self) -> CapabilityOperation {
        match self {
            Self::UploadPart => CapabilityOperation::UploadPart,
            Self::FinalizeUpload => CapabilityOperation::FinalizeUpload,
            Self::Download => CapabilityOperation::Download,
        }
    }
}

impl CollaborationStorageCapabilityUse {
    const fn operation(self) -> CapabilityOperation {
        match self {
            Self::WriteObject => CapabilityOperation::WriteCollaborationObject,
            Self::FinalizeObject => CapabilityOperation::FinalizeCollaborationObject,
            Self::ReadObject => CapabilityOperation::ReadCollaborationObject,
        }
    }
}

impl DocumentStorageCapabilityUse {
    const fn operation(self) -> CapabilityOperation {
        match self {
            Self::ReadVersion => CapabilityOperation::ReadDocumentVersion,
            Self::WriteRevision => CapabilityOperation::WriteDocumentRevision,
            Self::FinalizeRevision => CapabilityOperation::FinalizeDocumentRevision,
        }
    }
}

/// Signs an API storage capability for one permitted API storage operation.
pub fn sign_api_storage_capability(
    claims: &CapabilityClaims,
    purpose: ApiStorageCapabilityUse,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> Result<String, CapabilityError> {
    sign_capability(claims, purpose.operation(), generation, key_pair)
}

/// Verifies an API storage capability with an API-storage keyset.
pub fn verify_api_storage_capability(
    wire: &str,
    keys: &ApiStorageKeyset,
    expected_audience: &str,
    purpose: ApiStorageCapabilityUse,
    now_unix_seconds: i64,
) -> Result<Verified<CapabilityClaims>, CapabilityError> {
    verify_capability(
        wire,
        keys,
        expected_audience,
        purpose.operation(),
        now_unix_seconds,
    )
}

/// Signs a collaboration storage capability for one permitted collaboration operation.
pub fn sign_collaboration_storage_capability(
    claims: &CapabilityClaims,
    purpose: CollaborationStorageCapabilityUse,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> Result<String, CapabilityError> {
    sign_capability(claims, purpose.operation(), generation, key_pair)
}

/// Verifies a collaboration storage capability with a collaboration-storage keyset.
pub fn verify_collaboration_storage_capability(
    wire: &str,
    keys: &CollaborationStorageKeyset,
    expected_audience: &str,
    purpose: CollaborationStorageCapabilityUse,
    now_unix_seconds: i64,
) -> Result<Verified<CapabilityClaims>, CapabilityError> {
    verify_capability(
        wire,
        keys,
        expected_audience,
        purpose.operation(),
        now_unix_seconds,
    )
}

/// Signs a document storage capability for one permitted document operation.
pub fn sign_document_storage_capability(
    claims: &CapabilityClaims,
    purpose: DocumentStorageCapabilityUse,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> Result<String, CapabilityError> {
    sign_capability(claims, purpose.operation(), generation, key_pair)
}

/// Verifies a document storage capability with a document-storage keyset.
pub fn verify_document_storage_capability(
    wire: &str,
    keys: &DocumentStorageKeyset,
    expected_audience: &str,
    purpose: DocumentStorageCapabilityUse,
    now_unix_seconds: i64,
) -> Result<Verified<CapabilityClaims>, CapabilityError> {
    verify_capability(
        wire,
        keys,
        expected_audience,
        purpose.operation(),
        now_unix_seconds,
    )
}

/// Signs a mount-storage read capability.
pub fn sign_mount_storage_read_capability(
    claims: &MountCapabilityClaims,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> Result<String, CapabilityError> {
    if claims.operation != MountCapabilityOperation::Read as i32 || generation == 0 {
        return Err(CapabilityError::InvalidClaims);
    }
    let claims_bytes = claims.encode_to_vec();
    let input = [MOUNT_CAPABILITY_SIGNATURE_DOMAIN, claims_bytes.as_slice()].concat();
    let signed = SignedMountCapability {
        key_generation: generation,
        signature: key_pair.sign(&input).as_ref().to_vec(),
        claims: claims_bytes,
    };
    Ok(format!(
        "fbcap2.{}",
        URL_SAFE_NO_PAD.encode(signed.encode_to_vec())
    ))
}

/// Verifies a mount-storage read capability with a mount-storage keyset.
pub fn verify_mount_storage_read_capability(
    wire: &str,
    keys: &MountStorageKeyset,
    expected_audience: &str,
    now_unix_seconds: i64,
) -> Result<Verified<MountCapabilityClaims>, CapabilityError> {
    let encoded = wire
        .strip_prefix("fbcap2.")
        .ok_or(CapabilityError::InvalidEncoding)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CapabilityError::InvalidEncoding)?;
    let signed = SignedMountCapability::decode(bytes.as_slice())
        .map_err(|_| CapabilityError::InvalidEncoding)?;
    let input = [MOUNT_CAPABILITY_SIGNATURE_DOMAIN, signed.claims.as_slice()].concat();
    keys.verify(signed.key_generation, &input, &signed.signature)
        .map_err(map_keyset_error)?;
    let claims = MountCapabilityClaims::decode(signed.claims.as_slice())
        .map_err(|_| CapabilityError::InvalidClaims)?;
    validate_mount_claims(&claims, expected_audience, now_unix_seconds)?;
    Ok(Verified {
        claims,
        generation: signed.key_generation,
    })
}

fn sign_capability(
    claims: &CapabilityClaims,
    expected_operation: CapabilityOperation,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> Result<String, CapabilityError> {
    if generation == 0 || claims.operation != expected_operation as i32 {
        return Err(CapabilityError::InvalidClaims);
    }
    let claims_bytes = claims.encode_to_vec();
    let input = [CAPABILITY_SIGNATURE_DOMAIN, claims_bytes.as_slice()].concat();
    let signed = SignedCapability {
        key_generation: generation,
        signature: key_pair.sign(&input).as_ref().to_vec(),
        claims: claims_bytes,
    };
    Ok(format!(
        "fbcap1.{}",
        URL_SAFE_NO_PAD.encode(signed.encode_to_vec())
    ))
}

fn verify_capability(
    wire: &str,
    keys: &impl CapabilityKeyset,
    expected_audience: &str,
    expected_operation: CapabilityOperation,
    now_unix_seconds: i64,
) -> Result<Verified<CapabilityClaims>, CapabilityError> {
    let encoded = wire
        .strip_prefix("fbcap1.")
        .ok_or(CapabilityError::InvalidEncoding)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CapabilityError::InvalidEncoding)?;
    let signed =
        SignedCapability::decode(bytes.as_slice()).map_err(|_| CapabilityError::InvalidEncoding)?;
    let input = [CAPABILITY_SIGNATURE_DOMAIN, signed.claims.as_slice()].concat();
    keys.verify(signed.key_generation, &input, &signed.signature)
        .map_err(map_keyset_error)?;
    let claims = CapabilityClaims::decode(signed.claims.as_slice())
        .map_err(|_| CapabilityError::InvalidClaims)?;
    validate_capability_claims(
        &claims,
        expected_audience,
        expected_operation,
        now_unix_seconds,
    )?;
    Ok(Verified {
        claims,
        generation: signed.key_generation,
    })
}

trait CapabilityKeyset {
    fn verify(&self, generation: u32, message: &[u8], signature: &[u8]) -> Result<(), KeysetError>;
}

macro_rules! capability_keyset {
    ($type:ty) => {
        impl CapabilityKeyset for $type {
            fn verify(
                &self,
                generation: u32,
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), KeysetError> {
                self.verify(generation, message, signature)
            }
        }
    };
}

capability_keyset!(ApiStorageKeyset);
capability_keyset!(CollaborationStorageKeyset);
capability_keyset!(DocumentStorageKeyset);

fn validate_capability_claims(
    claims: &CapabilityClaims,
    expected_audience: &str,
    expected_operation: CapabilityOperation,
    now_unix_seconds: i64,
) -> Result<(), CapabilityError> {
    for identifier in [
        &claims.capability_id,
        &claims.tenant_id,
        &claims.principal_id,
        &claims.grant_id,
    ] {
        Uuid::parse_str(identifier).map_err(|_| CapabilityError::InvalidClaims)?;
    }
    if claims.audience != expected_audience {
        return Err(CapabilityError::WrongAudience);
    }
    if claims.operation != expected_operation as i32 {
        return Err(CapabilityError::WrongOperation);
    }
    validate_lifetime(
        claims.issued_at_unix_seconds,
        claims.expires_at_unix_seconds,
        MAX_CAPABILITY_LIFETIME_SECONDS,
        now_unix_seconds,
    )?;
    if !(16..=64).contains(&claims.nonce.len())
        || claims.range_end < claims.range_start
        || claims.resource_acl_generation == 0
        || claims.drive_acl_generation == 0
        || claims.membership_generation == 0
        || claims.namespace_generation == 0
    {
        return Err(CapabilityError::InvalidClaims);
    }
    Ok(())
}

fn validate_mount_claims(
    claims: &MountCapabilityClaims,
    expected_audience: &str,
    now_unix_seconds: i64,
) -> Result<(), CapabilityError> {
    for identifier in [
        &claims.capability_id,
        &claims.tenant_id,
        &claims.principal_id,
        &claims.mount_session_id,
        &claims.credential_id,
        &claims.drive_id,
        &claims.resource_id,
        &claims.grant_id,
        &claims.version_id,
    ] {
        Uuid::parse_str(identifier).map_err(|_| CapabilityError::InvalidClaims)?;
    }
    if claims.audience != expected_audience {
        return Err(CapabilityError::WrongAudience);
    }
    if claims.operation != MountCapabilityOperation::Read as i32 {
        return Err(CapabilityError::WrongOperation);
    }
    validate_lifetime(
        claims.issued_at_unix_seconds,
        claims.expires_at_unix_seconds,
        MAX_MOUNT_CAPABILITY_LIFETIME_SECONDS,
        now_unix_seconds,
    )?;
    if !(16..=64).contains(&claims.nonce.len())
        || claims.range_end < claims.range_start
        || claims.credential_generation == 0
        || claims.authorization_generation == 0
        || claims.membership_generation == 0
        || claims.drive_acl_generation == 0
        || claims.namespace_generation == 0
        || claims.resource_acl_generation == 0
        || claims.gateway_epoch == 0
        || claims.fencing_token == 0
        || !claims.write_session_id.is_empty()
    {
        return Err(CapabilityError::InvalidClaims);
    }
    Ok(())
}

fn validate_lifetime(
    issued: i64,
    expires: i64,
    maximum: i64,
    now: i64,
) -> Result<(), CapabilityError> {
    if expires < issued || expires - issued > maximum {
        return Err(CapabilityError::LifetimeTooLong);
    }
    if now < issued || now >= expires {
        return Err(CapabilityError::Expired);
    }
    Ok(())
}

const fn map_keyset_error(error: KeysetError) -> CapabilityError {
    match error {
        KeysetError::UnknownKey => CapabilityError::UnknownKey,
        KeysetError::InvalidSignature | KeysetError::InvalidEncoding => {
            CapabilityError::InvalidSignature
        }
    }
}

pub fn unix_time_now() -> Result<i64, CapabilityError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CapabilityError::InvalidClaims)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| CapabilityError::InvalidClaims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair as _;

    fn api_keyset(pair: &Ed25519KeyPair, generation: u32) -> ApiStorageKeyset {
        ApiStorageKeyset::parse(&format!(
            "filebelt-capability-keyset-v2\npurpose=api-storage\n{generation}:{}\n",
            URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
        ))
        .unwrap()
    }
    fn collaboration_keyset(pair: &Ed25519KeyPair, generation: u32) -> CollaborationStorageKeyset {
        CollaborationStorageKeyset::parse(&format!(
            "filebelt-capability-keyset-v2\npurpose=collaboration-storage\n{generation}:{}\n",
            URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
        ))
        .unwrap()
    }
    fn claims(operation: CapabilityOperation) -> CapabilityClaims {
        CapabilityClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: "filebelt-worker-io".into(),
            operation: operation as i32,
            tenant_id: Uuid::new_v4().to_string(),
            principal_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            resource_id: Uuid::new_v4().to_string(),
            upload_id: Uuid::new_v4().to_string(),
            payload_id: Uuid::new_v4().to_string(),
            part_number: 1,
            range_start: 0,
            range_end: 15,
            resource_acl_generation: 1,
            membership_generation: 1,
            namespace_generation: 1,
            fencing_token: 1,
            nonce: vec![7; 32],
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 160,
            drive_acl_generation: 1,
            grant_id: Uuid::new_v4().to_string(),
        }
    }
    fn mount_claims() -> MountCapabilityClaims {
        MountCapabilityClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: "filebelt-worker-io".into(),
            operation: MountCapabilityOperation::Read as i32,
            tenant_id: Uuid::new_v4().to_string(),
            principal_id: Uuid::new_v4().to_string(),
            mount_session_id: Uuid::new_v4().to_string(),
            credential_id: Uuid::new_v4().to_string(),
            drive_id: Uuid::new_v4().to_string(),
            resource_id: Uuid::new_v4().to_string(),
            version_id: Uuid::new_v4().to_string(),
            write_session_id: String::new(),
            range_start: 0,
            range_end: 4095,
            credential_generation: 2,
            authorization_generation: 3,
            membership_generation: 4,
            drive_acl_generation: 5,
            namespace_generation: 6,
            resource_acl_generation: 7,
            gateway_epoch: 8,
            fencing_token: 9,
            nonce: vec![11; 32],
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 115,
            grant_id: Uuid::new_v4().to_string(),
        }
    }

    #[test]
    fn correct_purpose_succeeds_and_foreign_purpose_or_operation_fails() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let wire = sign_api_storage_capability(
            &claims(CapabilityOperation::UploadPart),
            ApiStorageCapabilityUse::UploadPart,
            7,
            &pair,
        )
        .unwrap();
        let api = api_keyset(&pair, 7);
        assert_eq!(
            verify_api_storage_capability(
                &wire,
                &api,
                "filebelt-worker-io",
                ApiStorageCapabilityUse::UploadPart,
                120
            )
            .unwrap()
            .generation,
            7
        );
        let collaboration = collaboration_keyset(&pair, 7);
        assert_eq!(
            verify_collaboration_storage_capability(
                &wire,
                &collaboration,
                "filebelt-worker-io",
                CollaborationStorageCapabilityUse::WriteObject,
                120
            ),
            Err(CapabilityError::WrongOperation)
        );
        assert_eq!(
            sign_api_storage_capability(
                &claims(CapabilityOperation::DeletePayload),
                ApiStorageCapabilityUse::UploadPart,
                7,
                &pair
            ),
            Err(CapabilityError::InvalidClaims)
        );
    }

    #[test]
    fn same_generation_isolated_and_rotation_overlap_verifies() {
        let old = Ed25519KeyPair::generate().unwrap();
        let new = Ed25519KeyPair::generate().unwrap();
        let old_wire = sign_api_storage_capability(
            &claims(CapabilityOperation::Download),
            ApiStorageCapabilityUse::Download,
            7,
            &old,
        )
        .unwrap();
        let new_wire = sign_api_storage_capability(
            &claims(CapabilityOperation::Download),
            ApiStorageCapabilityUse::Download,
            8,
            &new,
        )
        .unwrap();
        let keys = ApiStorageKeyset::parse(&format!(
            "filebelt-capability-keyset-v2\npurpose=api-storage\n7:{}\n8:{}\n",
            URL_SAFE_NO_PAD.encode(old.public_key().as_ref()),
            URL_SAFE_NO_PAD.encode(new.public_key().as_ref())
        ))
        .unwrap();
        assert!(
            verify_api_storage_capability(
                &old_wire,
                &keys,
                "filebelt-worker-io",
                ApiStorageCapabilityUse::Download,
                120
            )
            .is_ok()
        );
        assert!(
            verify_api_storage_capability(
                &new_wire,
                &keys,
                "filebelt-worker-io",
                ApiStorageCapabilityUse::Download,
                120
            )
            .is_ok()
        );
    }

    #[test]
    fn mount_read_is_separate_and_read_only() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let wire = sign_mount_storage_read_capability(&mount_claims(), 3, &pair).unwrap();
        let keys = MountStorageKeyset::parse(&format!(
            "filebelt-capability-keyset-v2\npurpose=mount-storage\n3:{}\n",
            URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
        ))
        .unwrap();
        assert_eq!(
            verify_mount_storage_read_capability(&wire, &keys, "filebelt-worker-io", 110)
                .unwrap()
                .generation,
            3
        );
        let mut write = mount_claims();
        write.operation = MountCapabilityOperation::Write as i32;
        assert_eq!(
            sign_mount_storage_read_capability(&write, 3, &pair),
            Err(CapabilityError::InvalidClaims)
        );
    }
}

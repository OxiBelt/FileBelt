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
const MOUNT_CAPABILITY_CLAIMS_DIGEST_DOMAIN: &[u8] =
    b"filebelt.storage.mount-capability-claims-digest.v1\0";

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

/// The closed set of mount-storage `fbcap2` operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountStorageCapabilityUse {
    Read,
    WriteData,
    Deallocate,
    Allocate,
    SeekData,
    SeekHole,
    Flush,
    Finalize,
    Abort,
    DeleteStaging,
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

impl MountStorageCapabilityUse {
    /// Returns the exact Protobuf operation bound by this use.
    #[must_use]
    pub const fn operation(self) -> MountCapabilityOperation {
        match self {
            Self::Read => MountCapabilityOperation::Read,
            Self::WriteData => MountCapabilityOperation::WriteData,
            Self::Deallocate => MountCapabilityOperation::Deallocate,
            Self::Allocate => MountCapabilityOperation::Allocate,
            Self::SeekData => MountCapabilityOperation::SeekData,
            Self::SeekHole => MountCapabilityOperation::SeekHole,
            Self::Flush => MountCapabilityOperation::Flush,
            Self::Finalize => MountCapabilityOperation::Finalize,
            Self::Abort => MountCapabilityOperation::Abort,
            Self::DeleteStaging => MountCapabilityOperation::DeleteStaging,
        }
    }

    const fn requires_version(self) -> bool {
        matches!(
            self,
            Self::Read
                | Self::WriteData
                | Self::Deallocate
                | Self::Allocate
                | Self::SeekData
                | Self::SeekHole
                | Self::Flush
                | Self::Finalize
        )
    }

    const fn requires_write_session(self) -> bool {
        !matches!(self, Self::Read)
    }

    const fn requires_range(self) -> bool {
        matches!(
            self,
            Self::Read
                | Self::WriteData
                | Self::Deallocate
                | Self::Allocate
                | Self::SeekData
                | Self::SeekHole
        )
    }

    const fn requires_single_offset(self) -> bool {
        matches!(self, Self::SeekData | Self::SeekHole)
    }

    const fn requires_content_digest(self) -> bool {
        matches!(self, Self::WriteData)
    }
}

/// Computes the stable identity stored with an I/O completion receipt.
///
/// The digest covers every signed claim field. A duplicate nonce or
/// capability identifier with any substituted operation, range, fence, or
/// WriteData body digest therefore cannot retrieve another request's result.
#[must_use]
pub fn mount_capability_claims_digest(claims: &MountCapabilityClaims) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MOUNT_CAPABILITY_CLAIMS_DIGEST_DOMAIN);
    hasher.update(&claims.encode_to_vec());
    *hasher.finalize().as_bytes()
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

/// Signs one operation-specific mount-storage capability.
pub fn sign_mount_storage_capability(
    claims: &MountCapabilityClaims,
    purpose: MountStorageCapabilityUse,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> Result<String, CapabilityError> {
    if claims.operation != purpose.operation() as i32 || generation == 0 {
        return Err(CapabilityError::InvalidClaims);
    }
    validate_mount_claims(
        claims,
        &claims.audience,
        purpose,
        claims.issued_at_unix_seconds,
    )?;
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

/// Verifies one operation-specific capability with a mount-storage keyset.
pub fn verify_mount_storage_capability(
    wire: &str,
    keys: &MountStorageKeyset,
    expected_audience: &str,
    purpose: MountStorageCapabilityUse,
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
    validate_mount_claims(&claims, expected_audience, purpose, now_unix_seconds)?;
    Ok(Verified {
        claims,
        generation: signed.key_generation,
    })
}

/// Signs a mount-storage read capability.
///
/// This compatibility wrapper preserves the existing read-only caller API.
pub fn sign_mount_storage_read_capability(
    claims: &MountCapabilityClaims,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> Result<String, CapabilityError> {
    sign_mount_storage_capability(
        claims,
        MountStorageCapabilityUse::Read,
        generation,
        key_pair,
    )
}

/// Verifies a mount-storage read capability with a mount-storage keyset.
///
/// This compatibility wrapper preserves the existing read-only caller API.
pub fn verify_mount_storage_read_capability(
    wire: &str,
    keys: &MountStorageKeyset,
    expected_audience: &str,
    now_unix_seconds: i64,
) -> Result<Verified<MountCapabilityClaims>, CapabilityError> {
    verify_mount_storage_capability(
        wire,
        keys,
        expected_audience,
        MountStorageCapabilityUse::Read,
        now_unix_seconds,
    )
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
    purpose: MountStorageCapabilityUse,
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
    ] {
        validate_non_nil_uuid(identifier)?;
    }
    if claims.audience.is_empty() || claims.audience != expected_audience {
        return Err(CapabilityError::WrongAudience);
    }
    if claims.operation != purpose.operation() as i32 {
        return Err(CapabilityError::WrongOperation);
    }
    if purpose.requires_version() {
        validate_non_nil_uuid(&claims.version_id)?;
    } else if !claims.version_id.is_empty() {
        return Err(CapabilityError::InvalidClaims);
    }
    if purpose.requires_write_session() {
        validate_non_nil_uuid(&claims.write_session_id)?;
    } else if !claims.write_session_id.is_empty() {
        return Err(CapabilityError::InvalidClaims);
    }
    if purpose.requires_range() {
        if claims.range_end < claims.range_start
            || claims
                .range_end
                .checked_sub(claims.range_start)
                .and_then(|difference| difference.checked_add(1))
                .is_none()
        {
            return Err(CapabilityError::InvalidClaims);
        }
        if purpose.requires_single_offset() && claims.range_start != claims.range_end {
            return Err(CapabilityError::InvalidClaims);
        }
    } else if claims.range_start != 0 || claims.range_end != 0 {
        return Err(CapabilityError::InvalidClaims);
    }
    if (purpose.requires_content_digest() && claims.content_blake3.len() != 32)
        || (!purpose.requires_content_digest() && !claims.content_blake3.is_empty())
    {
        return Err(CapabilityError::InvalidClaims);
    }
    validate_lifetime(
        claims.issued_at_unix_seconds,
        claims.expires_at_unix_seconds,
        MAX_MOUNT_CAPABILITY_LIFETIME_SECONDS,
        now_unix_seconds,
    )?;
    if !(16..=64).contains(&claims.nonce.len())
        || claims.credential_generation == 0
        || claims.authorization_generation == 0
        || claims.membership_generation == 0
        || claims.drive_acl_generation == 0
        || claims.namespace_generation == 0
        || claims.resource_acl_generation == 0
        || claims.gateway_epoch == 0
        || claims.fencing_token == 0
    {
        return Err(CapabilityError::InvalidClaims);
    }
    Ok(())
}

fn validate_non_nil_uuid(value: &str) -> Result<Uuid, CapabilityError> {
    let identifier = Uuid::parse_str(value).map_err(|_| CapabilityError::InvalidClaims)?;
    if identifier.is_nil() {
        return Err(CapabilityError::InvalidClaims);
    }
    Ok(identifier)
}

fn validate_lifetime(
    issued: i64,
    expires: i64,
    maximum: i64,
    now: i64,
) -> Result<(), CapabilityError> {
    if expires < issued
        || expires
            .checked_sub(issued)
            .is_none_or(|lifetime| lifetime > maximum)
    {
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
    fn mount_keyset(pair: &Ed25519KeyPair, generation: u32) -> MountStorageKeyset {
        MountStorageKeyset::parse(&format!(
            "filebelt-capability-keyset-v2\npurpose=mount-storage\n{generation}:{}\n",
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
    const MOUNT_USES: [MountStorageCapabilityUse; 10] = [
        MountStorageCapabilityUse::Read,
        MountStorageCapabilityUse::WriteData,
        MountStorageCapabilityUse::Deallocate,
        MountStorageCapabilityUse::Allocate,
        MountStorageCapabilityUse::SeekData,
        MountStorageCapabilityUse::SeekHole,
        MountStorageCapabilityUse::Flush,
        MountStorageCapabilityUse::Finalize,
        MountStorageCapabilityUse::Abort,
        MountStorageCapabilityUse::DeleteStaging,
    ];

    fn mount_claims(purpose: MountStorageCapabilityUse) -> MountCapabilityClaims {
        MountCapabilityClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: "filebelt-worker-io".into(),
            operation: purpose.operation() as i32,
            tenant_id: Uuid::new_v4().to_string(),
            principal_id: Uuid::new_v4().to_string(),
            mount_session_id: Uuid::new_v4().to_string(),
            credential_id: Uuid::new_v4().to_string(),
            drive_id: Uuid::new_v4().to_string(),
            resource_id: Uuid::new_v4().to_string(),
            version_id: if purpose.requires_version() {
                Uuid::new_v4().to_string()
            } else {
                String::new()
            },
            write_session_id: if purpose.requires_write_session() {
                Uuid::new_v4().to_string()
            } else {
                String::new()
            },
            range_start: 0,
            range_end: if purpose.requires_range() && !purpose.requires_single_offset() {
                4095
            } else {
                0
            },
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
            content_blake3: if purpose.requires_content_digest() {
                vec![13; 32]
            } else {
                Vec::new()
            },
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
    fn every_mount_operation_round_trips_and_read_wrappers_remain_compatible() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let keys = mount_keyset(&pair, 3);
        for purpose in MOUNT_USES {
            let claims = mount_claims(purpose);
            let wire = sign_mount_storage_capability(&claims, purpose, 3, &pair).unwrap();
            assert_eq!(
                verify_mount_storage_capability(&wire, &keys, "filebelt-worker-io", purpose, 110,)
                    .unwrap(),
                Verified {
                    claims,
                    generation: 3,
                }
            );
        }

        let read = mount_claims(MountStorageCapabilityUse::Read);
        let generic =
            sign_mount_storage_capability(&read, MountStorageCapabilityUse::Read, 3, &pair)
                .unwrap();
        assert_eq!(
            sign_mount_storage_read_capability(&read, 3, &pair).unwrap(),
            generic
        );
        assert_eq!(
            verify_mount_storage_read_capability(&generic, &keys, "filebelt-worker-io", 110,)
                .unwrap()
                .claims,
            read
        );
    }

    #[test]
    fn every_cross_operation_substitution_is_rejected() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let keys = mount_keyset(&pair, 3);
        for signed_purpose in MOUNT_USES {
            let claims = mount_claims(signed_purpose);
            let wire = sign_mount_storage_capability(&claims, signed_purpose, 3, &pair).unwrap();
            for expected_purpose in MOUNT_USES {
                let result = verify_mount_storage_capability(
                    &wire,
                    &keys,
                    "filebelt-worker-io",
                    expected_purpose,
                    110,
                );
                if signed_purpose == expected_purpose {
                    assert!(result.is_ok());
                } else {
                    assert_eq!(result, Err(CapabilityError::WrongOperation));
                }
            }

            let different_purpose = MOUNT_USES
                .into_iter()
                .find(|purpose| *purpose != signed_purpose)
                .unwrap();
            assert_eq!(
                sign_mount_storage_capability(&claims, different_purpose, 3, &pair),
                Err(CapabilityError::InvalidClaims)
            );
        }
    }

    #[test]
    fn mount_operation_fields_are_required_or_forbidden_exactly() {
        let pair = Ed25519KeyPair::generate().unwrap();
        for purpose in MOUNT_USES {
            let valid = mount_claims(purpose);

            let mut version = valid.clone();
            if purpose.requires_version() {
                version.version_id.clear();
                assert_eq!(
                    sign_mount_storage_capability(&version, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims)
                );
                version.version_id = "not-a-uuid".into();
                assert_eq!(
                    sign_mount_storage_capability(&version, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims)
                );
                version.version_id = Uuid::nil().to_string();
            } else {
                version.version_id = Uuid::new_v4().to_string();
            }
            assert_eq!(
                sign_mount_storage_capability(&version, purpose, 3, &pair),
                Err(CapabilityError::InvalidClaims)
            );

            let mut write_session = valid.clone();
            if purpose.requires_write_session() {
                write_session.write_session_id.clear();
                assert_eq!(
                    sign_mount_storage_capability(&write_session, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims)
                );
                write_session.write_session_id = "not-a-uuid".into();
                assert_eq!(
                    sign_mount_storage_capability(&write_session, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims)
                );
                write_session.write_session_id = Uuid::nil().to_string();
            } else {
                write_session.write_session_id = Uuid::new_v4().to_string();
            }
            assert_eq!(
                sign_mount_storage_capability(&write_session, purpose, 3, &pair),
                Err(CapabilityError::InvalidClaims)
            );

            let mut range = valid.clone();
            if purpose.requires_range() {
                range.range_start = 9;
                range.range_end = 8;
                assert_eq!(
                    sign_mount_storage_capability(&range, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims)
                );
                range.range_start = 0;
                range.range_end = u64::MAX;
                assert_eq!(
                    sign_mount_storage_capability(&range, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims)
                );
                range.range_start = 42;
                range.range_end = 42;
                assert!(sign_mount_storage_capability(&range, purpose, 3, &pair).is_ok());
                if purpose.requires_single_offset() {
                    range.range_end = 43;
                    assert_eq!(
                        sign_mount_storage_capability(&range, purpose, 3, &pair),
                        Err(CapabilityError::InvalidClaims)
                    );
                }
            } else {
                range.range_end = 1;
                assert_eq!(
                    sign_mount_storage_capability(&range, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims)
                );
            }

            let mut content_digest = valid.clone();
            if purpose.requires_content_digest() {
                content_digest.content_blake3.clear();
                assert_eq!(
                    sign_mount_storage_capability(&content_digest, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims)
                );
                content_digest.content_blake3 = vec![5; 31];
            } else {
                content_digest.content_blake3 = vec![5; 32];
            }
            assert_eq!(
                sign_mount_storage_capability(&content_digest, purpose, 3, &pair),
                Err(CapabilityError::InvalidClaims)
            );
        }
    }

    #[test]
    fn mount_claims_receipt_digest_covers_body_digest_and_every_signed_field() {
        let claims = mount_claims(MountStorageCapabilityUse::WriteData);
        let baseline = mount_capability_claims_digest(&claims);
        let mut changed = claims.clone();
        changed.content_blake3[0] ^= 1;
        assert_ne!(baseline, mount_capability_claims_digest(&changed));
        changed = claims.clone();
        changed.range_end += 1;
        assert_ne!(baseline, mount_capability_claims_digest(&changed));
        changed = claims.clone();
        changed.gateway_epoch += 1;
        assert_ne!(baseline, mount_capability_claims_digest(&changed));
        changed = claims;
        changed.operation = MountCapabilityOperation::Allocate as i32;
        assert_ne!(baseline, mount_capability_claims_digest(&changed));
    }

    #[test]
    fn legacy_unsigned_mount_write_operation_has_no_accepted_use() {
        assert!(
            MOUNT_USES
                .into_iter()
                .all(|purpose| purpose.operation() as i32 != 2)
        );
    }

    #[test]
    fn mount_capabilities_require_every_common_uuid_for_every_operation() {
        let pair = Ed25519KeyPair::generate().unwrap();
        for purpose in MOUNT_USES {
            for invalid in ["not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
                for field in 0..8 {
                    let mut claims = mount_claims(purpose);
                    match field {
                        0 => claims.capability_id = invalid.to_owned(),
                        1 => claims.tenant_id = invalid.to_owned(),
                        2 => claims.principal_id = invalid.to_owned(),
                        3 => claims.mount_session_id = invalid.to_owned(),
                        4 => claims.credential_id = invalid.to_owned(),
                        5 => claims.drive_id = invalid.to_owned(),
                        6 => claims.resource_id = invalid.to_owned(),
                        7 => claims.grant_id = invalid.to_owned(),
                        _ => unreachable!(),
                    }
                    assert_eq!(
                        sign_mount_storage_capability(&claims, purpose, 3, &pair),
                        Err(CapabilityError::InvalidClaims),
                        "purpose={purpose:?} field={field} invalid={invalid}",
                    );
                }
            }
        }
    }

    #[test]
    fn mount_capabilities_require_every_generation_and_fence() {
        let pair = Ed25519KeyPair::generate().unwrap();
        for purpose in MOUNT_USES {
            for field in 0..8 {
                let mut claims = mount_claims(purpose);
                match field {
                    0 => claims.credential_generation = 0,
                    1 => claims.authorization_generation = 0,
                    2 => claims.membership_generation = 0,
                    3 => claims.drive_acl_generation = 0,
                    4 => claims.namespace_generation = 0,
                    5 => claims.resource_acl_generation = 0,
                    6 => claims.gateway_epoch = 0,
                    7 => claims.fencing_token = 0,
                    _ => unreachable!(),
                }
                assert_eq!(
                    sign_mount_storage_capability(&claims, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims),
                    "purpose={purpose:?} field={field}",
                );
            }
        }
    }

    #[test]
    fn mount_nonce_and_lifetime_bounds_are_enforced() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let keys = mount_keyset(&pair, 3);
        for purpose in MOUNT_USES {
            for length in [15, 65] {
                let mut claims = mount_claims(purpose);
                claims.nonce = vec![1; length];
                assert_eq!(
                    sign_mount_storage_capability(&claims, purpose, 3, &pair),
                    Err(CapabilityError::InvalidClaims)
                );
            }
            for length in [16, 64] {
                let mut claims = mount_claims(purpose);
                claims.nonce = vec![1; length];
                assert!(sign_mount_storage_capability(&claims, purpose, 3, &pair).is_ok());
            }

            let mut too_long = mount_claims(purpose);
            too_long.expires_at_unix_seconds =
                too_long.issued_at_unix_seconds + MAX_MOUNT_CAPABILITY_LIFETIME_SECONDS + 1;
            assert_eq!(
                sign_mount_storage_capability(&too_long, purpose, 3, &pair),
                Err(CapabilityError::LifetimeTooLong)
            );
            let mut reversed = mount_claims(purpose);
            reversed.expires_at_unix_seconds = reversed.issued_at_unix_seconds - 1;
            assert_eq!(
                sign_mount_storage_capability(&reversed, purpose, 3, &pair),
                Err(CapabilityError::LifetimeTooLong)
            );
            let mut overflowing = mount_claims(purpose);
            overflowing.issued_at_unix_seconds = i64::MIN;
            overflowing.expires_at_unix_seconds = i64::MAX;
            assert_eq!(
                sign_mount_storage_capability(&overflowing, purpose, 3, &pair),
                Err(CapabilityError::LifetimeTooLong)
            );

            let claims = mount_claims(purpose);
            let wire = sign_mount_storage_capability(&claims, purpose, 3, &pair).unwrap();
            assert_eq!(
                verify_mount_storage_capability(
                    &wire,
                    &keys,
                    "filebelt-worker-io",
                    purpose,
                    claims.issued_at_unix_seconds - 1,
                ),
                Err(CapabilityError::Expired)
            );
            assert_eq!(
                verify_mount_storage_capability(
                    &wire,
                    &keys,
                    "filebelt-worker-io",
                    purpose,
                    claims.expires_at_unix_seconds,
                ),
                Err(CapabilityError::Expired)
            );
        }
    }

    #[test]
    fn mount_generation_rotation_overlap_verifies_exact_generations() {
        let old = Ed25519KeyPair::generate().unwrap();
        let new = Ed25519KeyPair::generate().unwrap();
        let old_claims = mount_claims(MountStorageCapabilityUse::Read);
        let new_claims = mount_claims(MountStorageCapabilityUse::WriteData);
        let old_wire =
            sign_mount_storage_capability(&old_claims, MountStorageCapabilityUse::Read, 3, &old)
                .unwrap();
        let new_wire = sign_mount_storage_capability(
            &new_claims,
            MountStorageCapabilityUse::WriteData,
            4,
            &new,
        )
        .unwrap();
        let keys = MountStorageKeyset::parse(&format!(
            "filebelt-capability-keyset-v2\npurpose=mount-storage\n3:{}\n4:{}\n",
            URL_SAFE_NO_PAD.encode(old.public_key().as_ref()),
            URL_SAFE_NO_PAD.encode(new.public_key().as_ref()),
        ))
        .unwrap();
        assert_eq!(
            verify_mount_storage_capability(
                &old_wire,
                &keys,
                "filebelt-worker-io",
                MountStorageCapabilityUse::Read,
                110,
            )
            .unwrap()
            .generation,
            3
        );
        assert_eq!(
            verify_mount_storage_capability(
                &new_wire,
                &keys,
                "filebelt-worker-io",
                MountStorageCapabilityUse::WriteData,
                110,
            )
            .unwrap()
            .generation,
            4
        );
    }

    #[test]
    fn mount_prefix_purpose_domain_signature_audience_and_generation_are_bound() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let claims = mount_claims(MountStorageCapabilityUse::Read);
        let wire =
            sign_mount_storage_capability(&claims, MountStorageCapabilityUse::Read, 3, &pair)
                .unwrap();
        let keys = mount_keyset(&pair, 3);
        assert_eq!(
            verify_mount_storage_capability(
                wire.replacen("fbcap2.", "fbcap1.", 1).as_str(),
                &keys,
                "filebelt-worker-io",
                MountStorageCapabilityUse::Read,
                110,
            ),
            Err(CapabilityError::InvalidEncoding)
        );
        for malformed in ["fbcap2.%", "fbcap2.AA"] {
            assert_eq!(
                verify_mount_storage_capability(
                    malformed,
                    &keys,
                    "filebelt-worker-io",
                    MountStorageCapabilityUse::Read,
                    110,
                ),
                Err(CapabilityError::InvalidEncoding)
            );
        }
        assert_eq!(
            verify_mount_storage_capability(
                &wire,
                &keys,
                "another-audience",
                MountStorageCapabilityUse::Read,
                110,
            ),
            Err(CapabilityError::WrongAudience)
        );
        assert_eq!(
            sign_mount_storage_capability(&claims, MountStorageCapabilityUse::Read, 0, &pair,),
            Err(CapabilityError::InvalidClaims)
        );
        assert_eq!(
            verify_mount_storage_capability(
                &wire,
                &mount_keyset(&pair, 4),
                "filebelt-worker-io",
                MountStorageCapabilityUse::Read,
                110,
            ),
            Err(CapabilityError::UnknownKey)
        );
        assert!(matches!(
            MountStorageKeyset::parse(&format!(
                "filebelt-capability-keyset-v2\npurpose=api-storage\n3:{}\n",
                URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
            )),
            Err(KeysetError::InvalidEncoding)
        ));

        let claims_bytes = claims.encode_to_vec();
        let wrong_domain_input = [CAPABILITY_SIGNATURE_DOMAIN, claims_bytes.as_slice()].concat();
        let wrong_domain = SignedMountCapability {
            key_generation: 3,
            claims: claims_bytes,
            signature: pair.sign(&wrong_domain_input).as_ref().to_vec(),
        };
        let wrong_domain_wire = format!(
            "fbcap2.{}",
            URL_SAFE_NO_PAD.encode(wrong_domain.encode_to_vec())
        );
        assert_eq!(
            verify_mount_storage_capability(
                &wrong_domain_wire,
                &keys,
                "filebelt-worker-io",
                MountStorageCapabilityUse::Read,
                110,
            ),
            Err(CapabilityError::InvalidSignature)
        );

        let encoded = wire.strip_prefix("fbcap2.").unwrap();
        let mut signed =
            SignedMountCapability::decode(URL_SAFE_NO_PAD.decode(encoded).unwrap().as_slice())
                .unwrap();
        let mut changed_claims = MountCapabilityClaims::decode(signed.claims.as_slice()).unwrap();
        changed_claims.drive_id = Uuid::new_v4().to_string();
        signed.claims = changed_claims.encode_to_vec();
        let changed_claims_wire =
            format!("fbcap2.{}", URL_SAFE_NO_PAD.encode(signed.encode_to_vec()));
        assert_eq!(
            verify_mount_storage_capability(
                &changed_claims_wire,
                &keys,
                "filebelt-worker-io",
                MountStorageCapabilityUse::Read,
                110,
            ),
            Err(CapabilityError::InvalidSignature)
        );

        let mut signed =
            SignedMountCapability::decode(URL_SAFE_NO_PAD.decode(encoded).unwrap().as_slice())
                .unwrap();
        signed.signature[0] ^= 1;
        let tampered = format!("fbcap2.{}", URL_SAFE_NO_PAD.encode(signed.encode_to_vec()));
        assert_eq!(
            verify_mount_storage_capability(
                &tampered,
                &keys,
                "filebelt-worker-io",
                MountStorageCapabilityUse::Read,
                110,
            ),
            Err(CapabilityError::InvalidSignature)
        );
    }
}

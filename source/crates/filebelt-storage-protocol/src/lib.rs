// SPDX-License-Identifier: Apache-2.0

//! Capability-limited storage protocol and AWS-LC Ed25519 envelope.

#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use prost::Message;
use thiserror::Error;
use uuid::Uuid;

/// Maximum admission lifetime for a freshly issued data-plane capability.
pub const MAX_CAPABILITY_LIFETIME_SECONDS: i64 = 60;
const CAPABILITY_SIGNATURE_DOMAIN: &[u8] = b"filebelt.storage.capability.v1\0";

mod generated {
    include!("../../../../protocol/generated/rust/filebelt/storage/v1/filebelt.storage.v1.rs");
}

pub use generated::{CapabilityClaims, CapabilityOperation, SignedCapability};

/// Public verification key indexed by rotation generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationKey {
    pub generation: u32,
    pub public_key: Vec<u8>,
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

impl CapabilityClaims {
    pub fn validate_at(
        &self,
        expected_audience: &str,
        expected_operation: CapabilityOperation,
        now_unix_seconds: i64,
    ) -> Result<(), CapabilityError> {
        Uuid::parse_str(&self.capability_id).map_err(|_| CapabilityError::InvalidClaims)?;
        Uuid::parse_str(&self.tenant_id).map_err(|_| CapabilityError::InvalidClaims)?;
        Uuid::parse_str(&self.principal_id).map_err(|_| CapabilityError::InvalidClaims)?;
        Uuid::parse_str(&self.grant_id).map_err(|_| CapabilityError::InvalidClaims)?;
        if self.audience != expected_audience {
            return Err(CapabilityError::WrongAudience);
        }
        if self.operation != expected_operation as i32 {
            return Err(CapabilityError::WrongOperation);
        }
        if self.expires_at_unix_seconds < self.issued_at_unix_seconds
            || self.expires_at_unix_seconds - self.issued_at_unix_seconds
                > MAX_CAPABILITY_LIFETIME_SECONDS
        {
            return Err(CapabilityError::LifetimeTooLong);
        }
        if now_unix_seconds < self.issued_at_unix_seconds
            || now_unix_seconds >= self.expires_at_unix_seconds
        {
            return Err(CapabilityError::Expired);
        }
        if self.nonce.len() < 16 || self.nonce.len() > 64 {
            return Err(CapabilityError::InvalidClaims);
        }
        if self.range_end < self.range_start {
            return Err(CapabilityError::InvalidClaims);
        }
        if self.resource_acl_generation == 0
            || self.drive_acl_generation == 0
            || self.membership_generation == 0
            || self.namespace_generation == 0
        {
            return Err(CapabilityError::InvalidClaims);
        }
        Ok(())
    }
}

pub fn sign_capability(
    claims: &CapabilityClaims,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> String {
    let claims_bytes = claims.encode_to_vec();
    let signing_input = [CAPABILITY_SIGNATURE_DOMAIN, claims_bytes.as_slice()].concat();
    let signed = SignedCapability {
        key_generation: generation,
        signature: key_pair.sign(&signing_input).as_ref().to_vec(),
        claims: claims_bytes,
    };
    format!("fbcap1.{}", URL_SAFE_NO_PAD.encode(signed.encode_to_vec()))
}

pub fn verify_capability(
    wire: &str,
    keys: &[VerificationKey],
    expected_audience: &str,
    expected_operation: CapabilityOperation,
    now_unix_seconds: i64,
) -> Result<CapabilityClaims, CapabilityError> {
    let encoded = wire
        .strip_prefix("fbcap1.")
        .ok_or(CapabilityError::InvalidEncoding)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CapabilityError::InvalidEncoding)?;
    let signed =
        SignedCapability::decode(bytes.as_slice()).map_err(|_| CapabilityError::InvalidEncoding)?;
    let key = keys
        .iter()
        .find(|key| key.generation == signed.key_generation)
        .ok_or(CapabilityError::UnknownKey)?;
    let signing_input = [CAPABILITY_SIGNATURE_DOMAIN, signed.claims.as_slice()].concat();
    UnparsedPublicKey::new(&ED25519, &key.public_key)
        .verify(&signing_input, &signed.signature)
        .map_err(|_| CapabilityError::InvalidSignature)?;
    let claims = CapabilityClaims::decode(signed.claims.as_slice())
        .map_err(|_| CapabilityError::InvalidClaims)?;
    claims.validate_at(expected_audience, expected_operation, now_unix_seconds)?;
    Ok(claims)
}

pub fn unix_time_now() -> Result<i64, CapabilityError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CapabilityError::InvalidClaims)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| CapabilityError::InvalidClaims)
}

/// Create a lookup map suitable for long-lived worker state.
pub fn verification_key_map(keys: &[VerificationKey]) -> BTreeMap<u32, Vec<u8>> {
    keys.iter()
        .map(|key| (key.generation, key.public_key.clone()))
        .collect()
}

pub fn public_key(key_pair: &Ed25519KeyPair, generation: u32) -> VerificationKey {
    VerificationKey {
        generation,
        public_key: key_pair.public_key().as_ref().to_vec(),
    }
}

pub fn parse_verification_keyset(
    source: &str,
    required_generation: u32,
) -> Result<Vec<VerificationKey>, CapabilityError> {
    let mut lines = source.lines();
    if lines.next() != Some("filebelt-capability-keyset-v1") {
        return Err(CapabilityError::InvalidEncoding);
    }
    let mut keys = Vec::new();
    for line in lines {
        let (generation, encoded) = line
            .split_once(':')
            .ok_or(CapabilityError::InvalidEncoding)?;
        let generation = generation
            .parse::<u32>()
            .map_err(|_| CapabilityError::InvalidEncoding)?;
        let public_key = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CapabilityError::InvalidEncoding)?;
        if generation == 0
            || public_key.len() != 32
            || keys
                .iter()
                .any(|key: &VerificationKey| key.generation == generation)
        {
            return Err(CapabilityError::InvalidEncoding);
        }
        keys.push(VerificationKey {
            generation,
            public_key,
        });
    }
    if !keys.iter().any(|key| key.generation == required_generation) {
        return Err(CapabilityError::UnknownKey);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> CapabilityClaims {
        CapabilityClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: "filebelt-worker-io".into(),
            operation: CapabilityOperation::UploadPart as i32,
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

    #[test]
    fn round_trip_and_reject_wrong_audience() {
        let pair = Ed25519KeyPair::generate().expect("generate key");
        let wire = sign_capability(&claims(), 4, &pair);
        let keys = [public_key(&pair, 4)];
        assert!(
            verify_capability(
                &wire,
                &keys,
                "filebelt-worker-io",
                CapabilityOperation::UploadPart,
                120,
            )
            .is_ok()
        );
        assert_eq!(
            verify_capability(
                &wire,
                &keys,
                "filebelt-api",
                CapabilityOperation::UploadPart,
                120,
            ),
            Err(CapabilityError::WrongAudience),
        );
    }

    #[test]
    fn rejects_expired_and_tampered_capability() {
        let pair = Ed25519KeyPair::generate().expect("generate key");
        let mut wire = sign_capability(&claims(), 2, &pair);
        let keys = [public_key(&pair, 2)];
        assert_eq!(
            verify_capability(
                &wire,
                &keys,
                "filebelt-worker-io",
                CapabilityOperation::UploadPart,
                160,
            ),
            Err(CapabilityError::Expired),
        );
        wire.push('a');
        assert!(
            verify_capability(
                &wire,
                &keys,
                "filebelt-worker-io",
                CapabilityOperation::UploadPart,
                120,
            )
            .is_err()
        );
    }

    #[test]
    fn parses_bounded_versioned_keysets() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
        let keys =
            parse_verification_keyset(&format!("filebelt-capability-keyset-v1\n2:{encoded}\n"), 2)
                .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].generation, 2);
        assert_eq!(
            parse_verification_keyset(&format!("filebelt-capability-keyset-v1\n2:{encoded}\n"), 1,),
            Err(CapabilityError::UnknownKey)
        );
    }
}

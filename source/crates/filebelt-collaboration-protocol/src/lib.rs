// SPDX-License-Identifier: Apache-2.0

//! Stable collaboration frames and one-use join-grant signatures.

#![deny(unsafe_code)]

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use prost::Message as _;
use thiserror::Error;
use uuid::Uuid;

const GRANT_SIGNATURE_DOMAIN: &[u8] = b"filebelt.collaboration.grant.v1\0";
const GRANT_DIGEST_DOMAIN: &[u8] = b"filebelt.collaboration.grant-digest.v1\0";
/// Domain separator for the normalized Markdown source digests retained as
/// MCP provenance evidence. Callers must validate UTF-8 and normalize line
/// endings before hashing; source bytes themselves are never persisted here.
pub const NORMALIZED_MARKDOWN_SOURCE_DIGEST_DOMAIN: &[u8] =
    b"filebelt.markdown.normalized-source.v1\0";
pub const MAX_GRANT_LIFETIME_SECONDS: i64 = 60;
// One UpdateGroup carries up to 2 MiB of Yjs bytes plus bounded protobuf
// framing for sixteen chunk messages and identifiers.
pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024 + 64 * 1024;
pub const PROTOCOL_VERSION: u32 = 1;

mod generated {
    include!(
        "../../../../protocol/generated/rust/filebelt/collaboration/v1/filebelt.collaboration.v1.rs"
    );
}

pub use generated::{
    Acknowledgement, Authenticate, Awareness, Checkpoint, CheckpointRequest, CheckpointState,
    CollaborationCodec, CollaborationError, CollaborationErrorCode, CollaborationFrame,
    CollaborationGrantClaims, Freeze, FreezeReason, Heartbeat, PresenceMode, PresenceState,
    SignedCollaborationGrant, SyncChunk, SyncRequest, UpdateChunk, UpdateGroup,
    collaboration_frame,
};

#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub generation: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("collaboration grant encoding is invalid")]
    InvalidEncoding,
    #[error("collaboration grant signature is invalid")]
    InvalidSignature,
    #[error("collaboration grant key generation is unknown")]
    UnknownKey,
    #[error("collaboration grant claims are invalid")]
    InvalidClaims,
    #[error("collaboration grant is expired or not yet valid")]
    Expired,
    #[error("collaboration grant lifetime exceeds 60 seconds")]
    LifetimeTooLong,
}

impl CollaborationGrantClaims {
    pub fn validate_at(&self, now_unix_seconds: i64) -> Result<(), GrantError> {
        for value in [
            &self.grant_id,
            &self.tenant_id,
            &self.room_id,
            &self.drive_id,
            &self.node_id,
            &self.base_version_id,
            &self.principal_id,
            &self.session_id,
            &self.client_id,
        ] {
            Uuid::parse_str(value).map_err(|_| GrantError::InvalidClaims)?;
        }
        if self.room_epoch == 0
            || self.resource_acl_generation == 0
            || self.drive_acl_generation == 0
            || self.membership_generation == 0
            || self.namespace_generation == 0
            || !matches!(
                PresenceMode::try_from(self.presence_mode),
                Ok(PresenceMode::Pseudonym | PresenceMode::DisplayName)
            )
            || self.presence_label.is_empty()
            || self.presence_label.len() > 120
            || self.presence_label.chars().any(char::is_control)
            || self.nonce.len() < 16
            || self.nonce.len() > 64
            || !self.bootstrap_download_capability.starts_with("fbcap1.")
        {
            return Err(GrantError::InvalidClaims);
        }
        if self.expires_at_unix_seconds < self.issued_at_unix_seconds
            || self.expires_at_unix_seconds - self.issued_at_unix_seconds
                > MAX_GRANT_LIFETIME_SECONDS
        {
            return Err(GrantError::LifetimeTooLong);
        }
        if now_unix_seconds < self.issued_at_unix_seconds
            || now_unix_seconds >= self.expires_at_unix_seconds
        {
            return Err(GrantError::Expired);
        }
        Ok(())
    }
}

#[must_use]
pub fn sign_grant(
    claims: &CollaborationGrantClaims,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> String {
    let claims_bytes = claims.encode_to_vec();
    let signing_input = [GRANT_SIGNATURE_DOMAIN, claims_bytes.as_slice()].concat();
    let signed = SignedCollaborationGrant {
        key_generation: generation,
        claims: claims_bytes,
        signature: key_pair.sign(&signing_input).as_ref().to_vec(),
    };
    format!(
        "fbcollab1.{}",
        URL_SAFE_NO_PAD.encode(signed.encode_to_vec())
    )
}

pub fn verify_grant(
    wire: &str,
    keys: &[VerificationKey],
    now_unix_seconds: i64,
) -> Result<CollaborationGrantClaims, GrantError> {
    let encoded = wire
        .strip_prefix("fbcollab1.")
        .ok_or(GrantError::InvalidEncoding)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| GrantError::InvalidEncoding)?;
    let signed = SignedCollaborationGrant::decode(bytes.as_slice())
        .map_err(|_| GrantError::InvalidEncoding)?;
    let key = keys
        .iter()
        .find(|key| key.generation == signed.key_generation)
        .ok_or(GrantError::UnknownKey)?;
    let signing_input = [GRANT_SIGNATURE_DOMAIN, signed.claims.as_slice()].concat();
    UnparsedPublicKey::new(&ED25519, &key.public_key)
        .verify(&signing_input, &signed.signature)
        .map_err(|_| GrantError::InvalidSignature)?;
    let claims = CollaborationGrantClaims::decode(signed.claims.as_slice())
        .map_err(|_| GrantError::InvalidClaims)?;
    claims.validate_at(now_unix_seconds)?;
    Ok(claims)
}

/// Stable database lookup digest for a signed, already high-entropy grant.
/// The signature remains the authenticity boundary; this digest only avoids
/// persisting the bearer value itself.
#[must_use]
pub fn grant_digest(wire: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(GRANT_DIGEST_DOMAIN);
    hasher.update(wire.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Returns the domain-separated digest of already normalized Markdown source.
#[must_use]
pub fn normalized_markdown_source_digest(source: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NORMALIZED_MARKDOWN_SOURCE_DIGEST_DOMAIN);
    hasher.update(source);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair as _;

    fn claims() -> CollaborationGrantClaims {
        CollaborationGrantClaims {
            grant_id: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            room_id: Uuid::new_v4().to_string(),
            room_epoch: 1,
            drive_id: Uuid::new_v4().to_string(),
            node_id: Uuid::new_v4().to_string(),
            base_version_id: Uuid::new_v4().to_string(),
            principal_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            client_id: Uuid::new_v4().to_string(),
            presence_mode: PresenceMode::Pseudonym as i32,
            presence_label: "Editor 7".into(),
            resource_acl_generation: 1,
            drive_acl_generation: 1,
            membership_generation: 1,
            namespace_generation: 1,
            can_checkpoint: true,
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 160,
            nonce: vec![7; 32],
            bootstrap_download_capability: "fbcap1.test".into(),
        }
    }

    #[test]
    fn signed_grant_round_trips_and_expires() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let expected = claims();
        let wire = sign_grant(&expected, 3, &pair);
        let keys = [VerificationKey {
            generation: 3,
            public_key: pair.public_key().as_ref().to_vec(),
        }];
        assert_eq!(verify_grant(&wire, &keys, 120).unwrap(), expected);
        assert_eq!(verify_grant(&wire, &keys, 160), Err(GrantError::Expired));
    }

    #[test]
    fn wrong_generation_and_tampering_fail_closed() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let mut wire = sign_grant(&claims(), 3, &pair);
        assert_eq!(verify_grant(&wire, &[], 120), Err(GrantError::UnknownKey));
        wire.push('x');
        let keys = [VerificationKey {
            generation: 3,
            public_key: pair.public_key().as_ref().to_vec(),
        }];
        assert!(verify_grant(&wire, &keys, 120).is_err());
    }

    #[test]
    fn grant_digest_is_domain_separated_and_stable() {
        assert_eq!(
            grant_digest("fbcollab1.test"),
            grant_digest("fbcollab1.test")
        );
        assert_ne!(
            grant_digest("fbcollab1.test"),
            *blake3::hash(b"fbcollab1.test").as_bytes()
        );
    }

    #[test]
    fn normalized_markdown_source_digest_is_domain_separated_and_stable() {
        assert_eq!(
            normalized_markdown_source_digest(b"# Source\n"),
            normalized_markdown_source_digest(b"# Source\n")
        );
        assert_ne!(
            normalized_markdown_source_digest(b"# Source\n"),
            *blake3::hash(b"# Source\n").as_bytes()
        );
    }
}

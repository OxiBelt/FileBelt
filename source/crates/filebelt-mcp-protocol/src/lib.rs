// SPDX-License-Identifier: Apache-2.0

//! Signed, versioned internal MCP mediation protocol.

#![deny(unsafe_code)]

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use prost::Message;
use thiserror::Error;
use uuid::Uuid;

const DELEGATION_DOMAIN: &[u8] = b"filebelt.mcp.delegation.v1\0";
pub const MAX_DELEGATION_LIFETIME_SECONDS: i64 = 120;
pub const MAX_FRAME_BYTES: usize = 4_194_304;
pub const RUNNER_RELAY_PROTOCOL_VERSION: &str = "filebelt.mcp.runner.v1";
pub const MAX_RUNNER_RELAY_PAYLOAD_BYTES: usize = 65_536;
pub const MAX_RUNNER_RELAY_MESSAGE_BYTES: usize = 69_632;

mod generated {
    include!("../../../../protocol/generated/rust/filebelt/mcp/v1/filebelt.mcp.v1.rs");
}

pub use generated::{
    AttachmentClaim, AttachmentDisclosure, AttachmentEncoding, AttachmentFieldClaim,
    CreateRunnerLeaseRequest, CreateRunnerLeaseResponse, DelegationClaims,
    DeleteRunnerLeaseRequest, DeleteRunnerLeaseResponse, InvocationFrame, InvocationFrameKind,
    InvocationRequest, McpOperation, McpPrimitive, RunnerLeaseClaims, RunnerRelayFrame,
    RunnerRelayFrameKind, RunnerRelayHello, SignedDelegation,
};

#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub generation: u32,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("MCP delegation encoding is invalid")]
    InvalidEncoding,
    #[error("MCP delegation signature is invalid")]
    InvalidSignature,
    #[error("MCP delegation key generation is unknown")]
    UnknownKey,
    #[error("MCP delegation claims are invalid")]
    InvalidClaims,
    #[error("MCP delegation audience does not match")]
    WrongAudience,
    #[error("MCP delegation operation does not match")]
    WrongOperation,
    #[error("MCP delegation is expired or not yet valid")]
    Expired,
    #[error("MCP delegation lifetime exceeds the maximum")]
    LifetimeTooLong,
    #[error("MCP protocol frame exceeds the maximum")]
    FrameTooLarge,
    #[error("MCP runner relay message is invalid")]
    InvalidRunnerRelay,
}

impl DelegationClaims {
    pub fn validate_at(
        &self,
        expected_audience: &str,
        expected_operation: McpOperation,
        now_unix_seconds: i64,
    ) -> Result<(), ProtocolError> {
        for identifier in [
            &self.capability_id,
            &self.tenant_id,
            &self.principal_id,
            &self.registration_id,
        ] {
            Uuid::parse_str(identifier).map_err(|_| ProtocolError::InvalidClaims)?;
        }
        if !self.session_id.is_empty() {
            Uuid::parse_str(&self.session_id).map_err(|_| ProtocolError::InvalidClaims)?;
        }
        if !self.service_grant_id.is_empty() {
            Uuid::parse_str(&self.service_grant_id).map_err(|_| ProtocolError::InvalidClaims)?;
        }
        if self.audience != expected_audience {
            return Err(ProtocolError::WrongAudience);
        }
        if self.operation != expected_operation as i32 {
            return Err(ProtocolError::WrongOperation);
        }
        if self.expires_at_unix_seconds < self.issued_at_unix_seconds
            || self.expires_at_unix_seconds - self.issued_at_unix_seconds
                > MAX_DELEGATION_LIFETIME_SECONDS
        {
            return Err(ProtocolError::LifetimeTooLong);
        }
        if now_unix_seconds < self.issued_at_unix_seconds
            || now_unix_seconds >= self.expires_at_unix_seconds
        {
            return Err(ProtocolError::Expired);
        }
        if self.application_id.is_empty()
            || self.application_id.len() > 128
            || self.capability_fingerprint.len() != 32
            || self.arguments_digest.len() != 32
            || !(16..=64).contains(&self.nonce.len())
            || self.policy_generation == 0
            || self.membership_generation == 0
            || self.attachments.len() > 4
            || self
                .attachments
                .iter()
                .any(|claim| claim.validate().is_err())
        {
            return Err(ProtocolError::InvalidClaims);
        }
        Ok(())
    }
}

impl AttachmentClaim {
    fn validate(&self) -> Result<(), ProtocolError> {
        for identifier in [
            &self.drive_id,
            &self.node_id,
            &self.version_id,
            &self.data_grant_id,
        ] {
            Uuid::parse_str(identifier).map_err(|_| ProtocolError::InvalidClaims)?;
        }
        if self.fields.is_empty()
            || self.fields.len() > 4
            || self.fields.iter().any(|field| field.validate().is_err())
            || self.maximum_raw_bytes == 0
            || self.maximum_raw_bytes > 16_777_216
            || self.size_bytes > self.maximum_raw_bytes
            || self.drive_acl_generation == 0
            || self.resource_acl_generation == 0
            || self.membership_generation == 0
            || self.namespace_generation == 0
            || self.download_path.len() > 128
            || !self.download_path.starts_with("/io/v1/downloads/")
            || self.download_path[17..].parse::<Uuid>().is_err()
            || !self.authorization.starts_with("fbcap1.")
            || self.authorization.len() > 4_096
            || self.basename.is_empty()
            || self.basename.len() > 255
            || self.media_type.is_empty()
            || self.media_type.len() > 255
        {
            return Err(ProtocolError::InvalidClaims);
        }
        Ok(())
    }
}

impl AttachmentFieldClaim {
    fn validate(&self) -> Result<(), ProtocolError> {
        let disclosure = AttachmentDisclosure::try_from(self.disclosure)
            .map_err(|_| ProtocolError::InvalidClaims)?;
        let encoding = AttachmentEncoding::try_from(self.encoding)
            .map_err(|_| ProtocolError::InvalidClaims)?;
        if disclosure == AttachmentDisclosure::Unspecified
            || encoding == AttachmentEncoding::Unspecified
            || !valid_json_pointer(&self.target_json_pointer)
            || (matches!(disclosure, AttachmentDisclosure::Size)
                && encoding != AttachmentEncoding::Decimal)
            || (!matches!(disclosure, AttachmentDisclosure::Size)
                && encoding == AttachmentEncoding::Decimal)
            || (matches!(disclosure, AttachmentDisclosure::Content)
                && !matches!(
                    encoding,
                    AttachmentEncoding::Utf8 | AttachmentEncoding::Base64
                ))
        {
            return Err(ProtocolError::InvalidClaims);
        }
        Ok(())
    }
}

fn valid_json_pointer(value: &str) -> bool {
    !value.is_empty()
        && value.starts_with('/')
        && value.len() <= 512
        && !value.split('/').skip(1).any(|token| {
            token.as_bytes().windows(1).any(|byte| byte == b"~") && invalid_tilde(token)
        })
}

fn invalid_tilde(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b'~'
            && bytes
                .get(index + 1)
                .is_none_or(|next| !matches!(*next, b'0' | b'1'))
    })
}

pub fn sign_delegation(
    claims: &DelegationClaims,
    generation: u32,
    key_pair: &Ed25519KeyPair,
) -> String {
    let claims_bytes = claims.encode_to_vec();
    let input = [DELEGATION_DOMAIN, claims_bytes.as_slice()].concat();
    let envelope = SignedDelegation {
        key_generation: generation,
        claims: claims_bytes,
        signature: key_pair.sign(&input).as_ref().to_vec(),
    };
    format!(
        "fbmcp1.{}",
        URL_SAFE_NO_PAD.encode(envelope.encode_to_vec())
    )
}

pub fn verify_delegation(
    wire: &str,
    keys: &[VerificationKey],
    expected_audience: &str,
    expected_operation: McpOperation,
    now_unix_seconds: i64,
) -> Result<DelegationClaims, ProtocolError> {
    let encoded = wire
        .strip_prefix("fbmcp1.")
        .ok_or(ProtocolError::InvalidEncoding)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidEncoding)?;
    let envelope =
        SignedDelegation::decode(bytes.as_slice()).map_err(|_| ProtocolError::InvalidEncoding)?;
    let key = keys
        .iter()
        .find(|key| key.generation == envelope.key_generation)
        .ok_or(ProtocolError::UnknownKey)?;
    let input = [DELEGATION_DOMAIN, envelope.claims.as_slice()].concat();
    UnparsedPublicKey::new(&ED25519, &key.public_key)
        .verify(&input, &envelope.signature)
        .map_err(|_| ProtocolError::InvalidSignature)?;
    let claims = DelegationClaims::decode(envelope.claims.as_slice())
        .map_err(|_| ProtocolError::InvalidClaims)?;
    claims.validate_at(expected_audience, expected_operation, now_unix_seconds)?;
    Ok(claims)
}

pub fn encode_frame(frame: &InvocationFrame) -> Result<Vec<u8>, ProtocolError> {
    let bytes = frame.encode_length_delimited_to_vec();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(bytes)
}

pub fn decode_frame(bytes: &[u8]) -> Result<InvocationFrame, ProtocolError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    InvocationFrame::decode_length_delimited(bytes).map_err(|_| ProtocolError::InvalidEncoding)
}

pub fn decode_frames(mut bytes: &[u8]) -> Result<Vec<InvocationFrame>, ProtocolError> {
    if bytes.len() > MAX_FRAME_BYTES.saturating_mul(4) {
        return Err(ProtocolError::FrameTooLarge);
    }
    let mut frames = Vec::new();
    while !bytes.is_empty() {
        if frames.len() >= 128 {
            return Err(ProtocolError::InvalidEncoding);
        }
        let before = bytes.len();
        let frame = InvocationFrame::decode_length_delimited(&mut bytes)
            .map_err(|_| ProtocolError::InvalidEncoding)?;
        if before == bytes.len() || frame.encoded_len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge);
        }
        frames.push(frame);
    }
    Ok(frames)
}

pub fn encode_runner_hello(hello: &RunnerRelayHello) -> Result<Vec<u8>, ProtocolError> {
    validate_runner_hello(hello)?;
    encode_runner_message(hello)
}

pub fn decode_runner_hello(bytes: &[u8]) -> Result<RunnerRelayHello, ProtocolError> {
    let hello = decode_runner_message(bytes)?;
    validate_runner_hello(&hello)?;
    Ok(hello)
}

pub fn encode_runner_relay_frame(frame: &RunnerRelayFrame) -> Result<Vec<u8>, ProtocolError> {
    validate_runner_relay_frame(frame)?;
    encode_runner_message(frame)
}

pub fn decode_runner_relay_frame(bytes: &[u8]) -> Result<RunnerRelayFrame, ProtocolError> {
    let frame = decode_runner_message(bytes)?;
    validate_runner_relay_frame(&frame)?;
    Ok(frame)
}

fn encode_runner_message(message: &impl Message) -> Result<Vec<u8>, ProtocolError> {
    if message.encoded_len() > MAX_RUNNER_RELAY_MESSAGE_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(message.encode_to_vec())
}

fn decode_runner_message<M: Message + Default>(bytes: &[u8]) -> Result<M, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_RUNNER_RELAY_MESSAGE_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    M::decode(bytes).map_err(|_| ProtocolError::InvalidEncoding)
}

fn validate_runner_hello(hello: &RunnerRelayHello) -> Result<(), ProtocolError> {
    if hello.protocol_version != RUNNER_RELAY_PROTOCOL_VERSION
        || Uuid::parse_str(&hello.invocation_id).is_err()
        || !(32..=4096).contains(&hello.bootstrap_token.len())
    {
        return Err(ProtocolError::InvalidRunnerRelay);
    }
    Ok(())
}

fn validate_runner_relay_frame(frame: &RunnerRelayFrame) -> Result<(), ProtocolError> {
    if Uuid::parse_str(&frame.invocation_id).is_err() || frame.sequence == 0 {
        return Err(ProtocolError::InvalidRunnerRelay);
    }
    let kind = RunnerRelayFrameKind::try_from(frame.kind)
        .map_err(|_| ProtocolError::InvalidRunnerRelay)?;
    let valid = match kind {
        RunnerRelayFrameKind::Data => {
            !frame.payload.is_empty()
                && frame.payload.len() <= MAX_RUNNER_RELAY_PAYLOAD_BYTES
                && frame.code.is_empty()
                && !frame.terminal
        }
        RunnerRelayFrameKind::Close => {
            frame.payload.is_empty() && frame.code.is_empty() && frame.terminal
        }
        RunnerRelayFrameKind::Error => {
            frame.payload.is_empty()
                && !frame.code.is_empty()
                && frame.code.len() <= 128
                && frame
                    .code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.')
                && frame.terminal
        }
        RunnerRelayFrameKind::Unspecified => false,
    };
    if !valid {
        return Err(ProtocolError::InvalidRunnerRelay);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair as _;

    fn claims() -> DelegationClaims {
        DelegationClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: "filebelt-mcp-broker".into(),
            operation: McpOperation::Invoke as i32,
            tenant_id: Uuid::new_v4().to_string(),
            principal_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            application_id: "filebelt.settings.mcp-test".into(),
            registration_id: Uuid::new_v4().to_string(),
            capability_fingerprint: vec![3; 32],
            arguments_digest: vec![4; 32],
            attachments: Vec::new(),
            policy_generation: 1,
            membership_generation: 1,
            nonce: vec![5; 32],
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 220,
            service_grant_id: String::new(),
        }
    }

    #[test]
    fn delegation_round_trip_is_audience_bound() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let wire = sign_delegation(&claims(), 2, &pair);
        let keys = [VerificationKey {
            generation: 2,
            public_key: pair.public_key().as_ref().to_vec(),
        }];
        assert!(
            verify_delegation(
                &wire,
                &keys,
                "filebelt-mcp-broker",
                McpOperation::Invoke,
                110
            )
            .is_ok()
        );
        assert_eq!(
            verify_delegation(
                &wire,
                &keys,
                "filebelt-controller",
                McpOperation::Invoke,
                110
            ),
            Err(ProtocolError::WrongAudience),
        );
    }

    #[test]
    fn frame_limit_is_fail_closed() {
        let frame = InvocationFrame {
            request_id: Uuid::new_v4().to_string(),
            sequence: 1,
            kind: InvocationFrameKind::Json as i32,
            payload: vec![0; MAX_FRAME_BYTES],
            code: String::new(),
            terminal: false,
        };
        assert_eq!(encode_frame(&frame), Err(ProtocolError::FrameTooLarge));
    }

    #[test]
    fn attachment_claim_binds_grant_capability_and_fields() {
        let mut claims = claims();
        claims.attachments.push(AttachmentClaim {
            drive_id: Uuid::new_v4().to_string(),
            node_id: Uuid::new_v4().to_string(),
            version_id: Uuid::new_v4().to_string(),
            data_grant_id: Uuid::new_v4().to_string(),
            fields: vec![AttachmentFieldClaim {
                disclosure: AttachmentDisclosure::Content as i32,
                target_json_pointer: "/document".into(),
                encoding: AttachmentEncoding::Utf8 as i32,
            }],
            maximum_raw_bytes: 1_048_576,
            drive_acl_generation: 1,
            resource_acl_generation: 1,
            membership_generation: 1,
            namespace_generation: 1,
            download_path: format!("/io/v1/downloads/{}", Uuid::new_v4()),
            authorization: "fbcap1.signed".into(),
            basename: "document.txt".into(),
            media_type: "text/plain".into(),
            size_bytes: 8,
        });
        assert!(
            claims
                .validate_at("filebelt-mcp-broker", McpOperation::Invoke, 110)
                .is_ok()
        );
        claims.attachments[0].data_grant_id = "not-a-uuid".into();
        assert_eq!(
            claims.validate_at("filebelt-mcp-broker", McpOperation::Invoke, 110),
            Err(ProtocolError::InvalidClaims)
        );
    }

    #[test]
    fn runner_relay_requires_exact_version_identity_and_terminal_shape() {
        let invocation_id = Uuid::new_v4().to_string();
        let hello = RunnerRelayHello {
            protocol_version: RUNNER_RELAY_PROTOCOL_VERSION.into(),
            invocation_id: invocation_id.clone(),
            bootstrap_token: vec![7; 32],
        };
        let encoded = encode_runner_hello(&hello).expect("encode relay hello");
        assert_eq!(
            decode_runner_hello(&encoded).expect("decode relay hello"),
            hello
        );

        let data = RunnerRelayFrame {
            invocation_id,
            sequence: 1,
            kind: RunnerRelayFrameKind::Data as i32,
            payload: b"{}\n".to_vec(),
            code: String::new(),
            terminal: false,
        };
        let encoded = encode_runner_relay_frame(&data).expect("encode data frame");
        assert_eq!(
            decode_runner_relay_frame(&encoded).expect("decode data frame"),
            data
        );

        let mut invalid = data;
        invalid.terminal = true;
        assert_eq!(
            encode_runner_relay_frame(&invalid),
            Err(ProtocolError::InvalidRunnerRelay)
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Capability-limited persistence through the FileBelt I/O role.

use std::sync::Arc;

use aws_lc_rs::signature::Ed25519KeyPair;
use filebelt_collaboration_protocol::CollaborationGrantClaims;
use filebelt_database::collaboration::{
    CollaborationAuthorizationContext, CollaborationAuthorizationGenerations,
    CollaborationObjectRecord, CollaborationUpdateChunkInput,
};
use filebelt_database::{Database, DatabaseError};
use filebelt_storage_protocol::{
    CapabilityClaims, CapabilityOperation, VerificationKey, sign_capability, unix_time_now,
    verify_capability,
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, StatusCode};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{ApplyReceipt, MAX_MARKDOWN_SOURCE_BYTES};

const CAPABILITY_AUDIENCE: &str = "filebelt-worker-io";

#[derive(Debug, Error)]
pub enum IoClientError {
    #[error("the collaboration context is invalid")]
    InvalidContext,
    #[error("the I/O capability is invalid")]
    InvalidCapability,
    #[error("the I/O service rejected collaboration persistence")]
    Rejected,
    #[error("the I/O service is unavailable")]
    Unavailable,
    #[error("the collaboration source exceeds the editor limit")]
    SourceTooLarge,
    #[error("authoritative collaboration persistence failed: {0}")]
    Database(#[from] DatabaseError),
}

#[derive(Clone)]
pub struct CollaborationIoClient {
    http: Client,
    io_url: Url,
    signer: Arc<Ed25519KeyPair>,
    signing_generation: u32,
    verification_keys: Arc<Vec<VerificationKey>>,
}

pub(crate) struct PersistUpdateGroupInput<'a> {
    pub claims: &'a CollaborationGrantClaims,
    pub chunks: &'a [Vec<u8>],
    pub receipt: &'a ApplyReceipt,
    pub client_update_id: Uuid,
    pub mcp_invocation_id: Option<Uuid>,
    pub expected_base_sequence: i64,
}

impl CollaborationIoClient {
    #[must_use]
    pub fn new(
        http: Client,
        io_url: Url,
        signer: Arc<Ed25519KeyPair>,
        signing_generation: u32,
        verification_keys: Arc<Vec<VerificationKey>>,
    ) -> Self {
        Self {
            http,
            io_url,
            signer,
            signing_generation,
            verification_keys,
        }
    }

    pub async fn download_bootstrap(
        &self,
        collaboration: &CollaborationGrantClaims,
    ) -> Result<Vec<u8>, IoClientError> {
        let now = unix_time_now().map_err(|_| IoClientError::InvalidCapability)?;
        let capability = verify_capability(
            &collaboration.bootstrap_download_capability,
            &self.verification_keys,
            CAPABILITY_AUDIENCE,
            CapabilityOperation::Download,
            now,
        )
        .map_err(|_| IoClientError::InvalidCapability)?;
        if capability.tenant_id != collaboration.tenant_id
            || capability.principal_id != collaboration.principal_id
            || capability.session_id != collaboration.session_id
            || capability.resource_id != collaboration.node_id
            || capability.resource_acl_generation != collaboration.resource_acl_generation
            || capability.drive_acl_generation != collaboration.drive_acl_generation
            || capability.membership_generation != collaboration.membership_generation
            || capability.namespace_generation != collaboration.namespace_generation
        {
            return Err(IoClientError::InvalidCapability);
        }
        let grant_id = parse_uuid(&capability.grant_id)?;
        let url = self
            .io_url
            .join(&format!("io/v1/downloads/{grant_id}"))
            .map_err(|_| IoClientError::InvalidContext)?;
        let response = self
            .http
            .get(url)
            .header(AUTHORIZATION, &collaboration.bootstrap_download_capability)
            .send()
            .await
            .map_err(|_| IoClientError::Unavailable)?;
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_MARKDOWN_SOURCE_BYTES as u64)
        {
            return Err(IoClientError::SourceTooLarge);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| IoClientError::Unavailable)?;
        if bytes.len() > MAX_MARKDOWN_SOURCE_BYTES {
            return Err(IoClientError::SourceTooLarge);
        }
        Ok(bytes.to_vec())
    }

    pub(crate) async fn persist_update_group(
        &self,
        database: &Database,
        input: PersistUpdateGroupInput<'_>,
    ) -> Result<(Uuid, i64, i64), IoClientError> {
        let PersistUpdateGroupInput {
            claims,
            chunks,
            receipt,
            client_update_id,
            mcp_invocation_id,
            expected_base_sequence,
        } = input;
        let tenant_id = parse_uuid(&claims.tenant_id)?;
        let room_id = parse_uuid(&claims.room_id)?;
        let drive_id = parse_uuid(&claims.drive_id)?;
        let client_id = parse_uuid(&claims.client_id)?;
        let epoch = i64::try_from(claims.room_epoch).map_err(|_| IoClientError::InvalidContext)?;
        let room = database
            .collaboration_room(tenant_id, drive_id, parse_uuid(&claims.node_id)?)
            .await?
            .ok_or(IoClientError::InvalidContext)?;
        if room.room_id != room_id || room.epoch != epoch || room.state != "active" {
            return Err(IoClientError::InvalidContext);
        }
        let total = chunks.iter().try_fold(0_i64, |size, chunk| {
            size.checked_add(i64::try_from(chunk.len()).ok()?)
        });
        let total = total.ok_or(IoClientError::InvalidContext)?;
        let object = database
            .collaboration_reserve_object(
                tenant_id,
                room_id,
                epoch,
                drive_id,
                "update_group",
                total,
                room.fencing_token,
            )
            .await?;
        let body = chunks.concat();
        if let Err(error) = self.write_and_finalize(claims, &object, body).await {
            let _ = database
                .collaboration_abandon_object(tenant_id, object.id)
                .await;
            return Err(error);
        }
        let mut offset = 0_i64;
        let mut manifest_chunks = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            let size = i32::try_from(chunk.len()).map_err(|_| IoClientError::InvalidContext)?;
            manifest_chunks.push(CollaborationUpdateChunkInput {
                chunk_index: i32::try_from(index).map_err(|_| IoClientError::InvalidContext)?,
                object_offset: offset,
                size_bytes: size,
                blake3: blake3::hash(chunk).as_bytes().to_vec(),
            });
            offset = offset
                .checked_add(i64::from(size))
                .ok_or(IoClientError::InvalidContext)?;
        }
        let persisted = database
            .collaboration_persist_update_group(
                tenant_id,
                room_id,
                epoch,
                room.fencing_token,
                expected_base_sequence,
                client_id,
                client_update_id,
                authorization_context(claims)?,
                mcp_invocation_id,
                &receipt.source_before_digest,
                &receipt.source_after_digest,
                object.id,
                &manifest_chunks,
                &receipt.state_vector,
                &receipt.state_digest,
            )
            .await;
        let (durable_object_id, first, last) = match persisted {
            Ok(result) => result,
            Err(error) => {
                let _ = database
                    .collaboration_abandon_object(tenant_id, object.id)
                    .await;
                return Err(error.into());
            }
        };
        Ok((durable_object_id, first, last))
    }

    pub async fn read_object(
        &self,
        claims: &CollaborationGrantClaims,
        object: &CollaborationObjectRecord,
    ) -> Result<Vec<u8>, IoClientError> {
        let size = object.size_bytes.ok_or(IoClientError::InvalidContext)?;
        let capability = self.issue_capability(
            claims,
            object,
            CapabilityOperation::ReadCollaborationObject,
            u64::try_from(size).map_err(|_| IoClientError::InvalidContext)?,
        )?;
        let url = self.object_url(object.id, false)?;
        let response = self
            .http
            .get(url)
            .header(AUTHORIZATION, capability)
            .send()
            .await
            .map_err(|_| IoClientError::Unavailable)?;
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| IoClientError::Unavailable)?;
        if !object_bytes_match(object, &bytes) {
            return Err(IoClientError::Rejected);
        }
        Ok(bytes.to_vec())
    }

    pub async fn persist_snapshot(
        &self,
        database: &Database,
        claims: &CollaborationGrantClaims,
        snapshot: Vec<u8>,
        covered_sequence: i64,
        state_vector: &[u8],
    ) -> Result<Uuid, IoClientError> {
        let tenant_id = parse_uuid(&claims.tenant_id)?;
        let room_id = parse_uuid(&claims.room_id)?;
        let drive_id = parse_uuid(&claims.drive_id)?;
        let epoch = i64::try_from(claims.room_epoch).map_err(|_| IoClientError::InvalidContext)?;
        let room = database
            .collaboration_room(tenant_id, drive_id, parse_uuid(&claims.node_id)?)
            .await?
            .ok_or(IoClientError::InvalidContext)?;
        if room.room_id != room_id || room.epoch != epoch || room.state != "active" {
            return Err(IoClientError::InvalidContext);
        }
        let reserved = i64::try_from(snapshot.len()).map_err(|_| IoClientError::InvalidContext)?;
        let object = database
            .collaboration_reserve_object(
                tenant_id,
                room_id,
                epoch,
                drive_id,
                "snapshot",
                reserved,
                room.fencing_token,
            )
            .await?;
        if let Err(error) = self.write_and_finalize(claims, &object, snapshot).await {
            let _ = database
                .collaboration_abandon_object(tenant_id, object.id)
                .await;
            return Err(error);
        }
        let committed = database
            .collaboration_commit_snapshot(
                tenant_id,
                room_id,
                epoch,
                room.fencing_token,
                authorization_context(claims)?,
                object.id,
                covered_sequence,
                state_vector,
            )
            .await;
        match committed {
            Ok(snapshot_id) => Ok(snapshot_id),
            Err(error) => {
                let _ = database
                    .collaboration_abandon_object(tenant_id, object.id)
                    .await;
                Err(error.into())
            }
        }
    }

    async fn write_and_finalize(
        &self,
        claims: &CollaborationGrantClaims,
        object: &CollaborationObjectRecord,
        body: Vec<u8>,
    ) -> Result<(), IoClientError> {
        let size = u64::try_from(body.len()).map_err(|_| IoClientError::InvalidContext)?;
        let write = self.issue_capability(
            claims,
            object,
            CapabilityOperation::WriteCollaborationObject,
            size,
        )?;
        let write_response = self
            .http
            .put(self.object_url(object.id, false)?)
            .header(AUTHORIZATION, write)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|_| IoClientError::Unavailable)?;
        if !write_response.status().is_success() {
            return Err(status_error(write_response.status()));
        }
        let finalize = self.issue_capability(
            claims,
            object,
            CapabilityOperation::FinalizeCollaborationObject,
            size,
        )?;
        let finalize_response = self
            .http
            .post(self.object_url(object.id, true)?)
            .header(AUTHORIZATION, finalize)
            .send()
            .await
            .map_err(|_| IoClientError::Unavailable)?;
        if !finalize_response.status().is_success() {
            return Err(status_error(finalize_response.status()));
        }
        Ok(())
    }

    fn issue_capability(
        &self,
        collaboration: &CollaborationGrantClaims,
        object: &CollaborationObjectRecord,
        operation: CapabilityOperation,
        size: u64,
    ) -> Result<String, IoClientError> {
        let now = unix_time_now().map_err(|_| IoClientError::InvalidCapability)?;
        let claims = CapabilityClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: CAPABILITY_AUDIENCE.into(),
            operation: operation as i32,
            tenant_id: collaboration.tenant_id.clone(),
            principal_id: collaboration.principal_id.clone(),
            session_id: collaboration.session_id.clone(),
            resource_id: collaboration.node_id.clone(),
            upload_id: object.room_id.to_string(),
            payload_id: object.payload_id.to_string(),
            part_number: 0,
            range_start: 0,
            range_end: size.saturating_sub(1),
            resource_acl_generation: collaboration.resource_acl_generation,
            membership_generation: collaboration.membership_generation,
            namespace_generation: collaboration.namespace_generation,
            fencing_token: u64::try_from(object.fencing_token)
                .map_err(|_| IoClientError::InvalidContext)?,
            nonce: random_nonce()?,
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now + 60,
            drive_acl_generation: collaboration.drive_acl_generation,
            grant_id: object.id.to_string(),
        };
        Ok(sign_capability(
            &claims,
            self.signing_generation,
            &self.signer,
        ))
    }

    fn object_url(&self, object_id: Uuid, finalize: bool) -> Result<Url, IoClientError> {
        self.io_url
            .join(&format!(
                "io/v1/collaboration/{object_id}{}",
                if finalize { "/finalize" } else { "" }
            ))
            .map_err(|_| IoClientError::InvalidContext)
    }
}

fn random_nonce() -> Result<Vec<u8>, IoClientError> {
    let mut nonce = vec![0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| IoClientError::Unavailable)?;
    Ok(nonce)
}

fn parse_uuid(value: &str) -> Result<Uuid, IoClientError> {
    Uuid::parse_str(value).map_err(|_| IoClientError::InvalidContext)
}

fn authorization_context(
    claims: &CollaborationGrantClaims,
) -> Result<CollaborationAuthorizationContext, IoClientError> {
    Ok(CollaborationAuthorizationContext {
        principal_id: parse_uuid(&claims.principal_id)?,
        session_id: parse_uuid(&claims.session_id)?,
        drive_id: parse_uuid(&claims.drive_id)?,
        node_id: parse_uuid(&claims.node_id)?,
        generations: CollaborationAuthorizationGenerations {
            membership: i64::try_from(claims.membership_generation)
                .map_err(|_| IoClientError::InvalidContext)?,
            drive_acl: i64::try_from(claims.drive_acl_generation)
                .map_err(|_| IoClientError::InvalidContext)?,
            namespace: i64::try_from(claims.namespace_generation)
                .map_err(|_| IoClientError::InvalidContext)?,
            resource_acl: i64::try_from(claims.resource_acl_generation)
                .map_err(|_| IoClientError::InvalidContext)?,
        },
    })
}

fn status_error(status: StatusCode) -> IoClientError {
    if status.is_server_error() {
        IoClientError::Unavailable
    } else {
        IoClientError::Rejected
    }
}

fn object_bytes_match(object: &CollaborationObjectRecord, bytes: &[u8]) -> bool {
    let Some(size) = object.size_bytes else {
        return false;
    };
    i64::try_from(bytes.len()).ok() == Some(size)
        && object.blake3.as_deref() == Some(blake3::hash(bytes).as_bytes().as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> CollaborationObjectRecord {
        CollaborationObjectRecord {
            id: Uuid::new_v4(),
            room_id: Uuid::new_v4(),
            epoch: 1,
            drive_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
            fencing_token: 1,
            payload_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
            payload_locator: Uuid::new_v4(),
            purpose: "snapshot".into(),
            state: "durable".into(),
            reserved_bytes: 3,
            size_bytes: Some(3),
            blake3: blake3::hash(b"one").as_bytes().to_vec().into(),
        }
    }

    #[test]
    fn read_object_requires_the_manifest_digest() {
        assert!(object_bytes_match(&object(), b"one"));
        assert!(!object_bytes_match(&object(), b"two"));
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Transactional idempotency for MCP authority-creating writes.

use serde_json::Value;
use uuid::Uuid;

use super::invocation::{NewMcpApprovalRule, insert_approval_rule};
use super::operations::{NewMcpServiceGrant, insert_service_grant};
use super::{Database, DatabaseError, NewMcpDataGrant, insert_data_grant};
use crate::IdempotencyRecord;
use crate::idempotency::{IdempotencyInput, IdempotencyReservation, finalize, reserve};

#[derive(Clone, Debug)]
pub struct McpIdempotency<'a> {
    pub principal_id: Uuid,
    pub route: &'a str,
    pub key: &'a str,
    pub request_fingerprint: &'a [u8; 32],
    pub response_status: i32,
    pub response_body: &'a Value,
}

#[derive(Clone, Debug)]
pub enum McpIdempotentWrite {
    Created(IdempotencyRecord),
    Replayed(IdempotencyRecord),
    KeyReused,
}

impl Database {
    pub async fn mcp_create_approval_rule_idempotent(
        &self,
        input: &NewMcpApprovalRule<'_>,
        idempotency: &McpIdempotency<'_>,
    ) -> Result<McpIdempotentWrite, DatabaseError> {
        if idempotency.principal_id != input.principal_id
            || !(100..=599).contains(&idempotency.response_status)
            || !(1..=3_600).contains(&input.lifetime_seconds)
            || !matches!(
                input.primitive,
                "resource_read" | "prompt_get" | "tool_call"
            )
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let reservation = idempotency.reservation_input();
        match reserve(&mut transaction, input.tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                insert_approval_rule(&mut transaction, input).await?;
                let record = finalize(
                    &mut transaction,
                    input.tenant_id,
                    &reservation,
                    idempotency.response_status,
                    idempotency.response_body,
                )
                .await?;
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Created(record))
            }
        }
    }

    pub async fn mcp_create_data_grant_idempotent(
        &self,
        input: &NewMcpDataGrant,
        idempotency: &McpIdempotency<'_>,
    ) -> Result<McpIdempotentWrite, DatabaseError> {
        if idempotency.principal_id != input.principal_id
            || !(100..=599).contains(&idempotency.response_status)
            || !(1..=2_592_000).contains(&input.lifetime_seconds)
            || !(input.allow_metadata || input.allow_content)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let reservation = idempotency.reservation_input();
        match reserve(&mut transaction, input.tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                insert_data_grant(&mut transaction, input).await?;
                let record = finalize(
                    &mut transaction,
                    input.tenant_id,
                    &reservation,
                    idempotency.response_status,
                    idempotency.response_body,
                )
                .await?;
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Created(record))
            }
        }
    }

    pub async fn mcp_create_service_grant_idempotent(
        &self,
        input: &NewMcpServiceGrant<'_>,
        idempotency: &McpIdempotency<'_>,
    ) -> Result<McpIdempotentWrite, DatabaseError> {
        if idempotency.principal_id != input.created_by
            || !(100..=599).contains(&idempotency.response_status)
            || !(1..=2_592_000).contains(&input.lifetime_seconds)
            || !matches!(
                input.primitive,
                "resource_read" | "prompt_get" | "tool_call"
            )
            || !input.constraints.is_object()
            || !input.quota.is_object()
            || !(1..=600).contains(&input.max_invocations_per_hour)
            || input.data_grant_ids.len() > 64
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let reservation = idempotency.reservation_input();
        match reserve(&mut transaction, input.tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                insert_service_grant(&mut transaction, input).await?;
                let record = finalize(
                    &mut transaction,
                    input.tenant_id,
                    &reservation,
                    idempotency.response_status,
                    idempotency.response_body,
                )
                .await?;
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Created(record))
            }
        }
    }
}

impl McpIdempotency<'_> {
    fn reservation_input(&self) -> IdempotencyInput<'_> {
        IdempotencyInput {
            principal_id: self.principal_id,
            route: self.route,
            key: self.key,
            request_fingerprint: self.request_fingerprint,
            legacy_request_fingerprint: None,
        }
    }
}

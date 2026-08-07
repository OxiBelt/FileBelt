// SPDX-License-Identifier: Apache-2.0

//! Transactional idempotency for MCP authority-creating writes.

use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::invocation::{NewMcpApprovalRule, insert_approval_rule};
use super::operations::{NewMcpServiceGrant, insert_service_grant};
use super::{Database, DatabaseError, NewMcpDataGrant, insert_data_grant};
use crate::IdempotencyRecord;

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
            || !(1..=3_600).contains(&input.lifetime_seconds)
            || !matches!(
                input.primitive,
                "resource_read" | "prompt_get" | "tool_call"
            )
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        match reserve(&mut transaction, input.tenant_id, idempotency).await? {
            Reservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Replayed(record))
            }
            Reservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::KeyReused)
            }
            Reservation::Created(record) => {
                insert_approval_rule(&mut transaction, input).await?;
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
            || !(1..=2_592_000).contains(&input.lifetime_seconds)
            || !(input.allow_metadata || input.allow_content)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        match reserve(&mut transaction, input.tenant_id, idempotency).await? {
            Reservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Replayed(record))
            }
            Reservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::KeyReused)
            }
            Reservation::Created(record) => {
                insert_data_grant(&mut transaction, input).await?;
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
        match reserve(&mut transaction, input.tenant_id, idempotency).await? {
            Reservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Replayed(record))
            }
            Reservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::KeyReused)
            }
            Reservation::Created(record) => {
                insert_service_grant(&mut transaction, input).await?;
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Created(record))
            }
        }
    }
}

enum Reservation {
    Created(IdempotencyRecord),
    Replay(IdempotencyRecord),
    KeyReused,
}

async fn reserve(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    input: &McpIdempotency<'_>,
) -> Result<Reservation, DatabaseError> {
    if input.route.is_empty()
        || input.route.len() > 255
        || input.key.is_empty()
        || input.key.len() > 128
        || !input.key.bytes().all(|byte| byte.is_ascii_graphic())
        || !(100..=599).contains(&input.response_status)
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    sqlx::query("DELETE FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key=$4 AND expires_at<=statement_timestamp()")
        .bind(tenant_id)
        .bind(input.principal_id)
        .bind(input.route)
        .bind(input.key)
        .execute(&mut **transaction)
        .await?;
    let inserted = sqlx::query("INSERT INTO public.idempotency_records (tenant_id,principal_id,route,key,request_fingerprint,response_status,response_body) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
        .bind(tenant_id)
        .bind(input.principal_id)
        .bind(input.route)
        .bind(input.key)
        .bind(input.request_fingerprint.as_slice())
        .bind(input.response_status)
        .bind(input.response_body)
        .execute(&mut **transaction)
        .await?
        .rows_affected()
        == 1;
    let row = sqlx::query("SELECT request_fingerprint,response_status,response_body FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key=$4 FOR UPDATE")
        .bind(tenant_id)
        .bind(input.principal_id)
        .bind(input.route)
        .bind(input.key)
        .fetch_one(&mut **transaction)
        .await?;
    let record = IdempotencyRecord {
        request_fingerprint: row.get("request_fingerprint"),
        response_status: row.get("response_status"),
        response_body: row.get("response_body"),
    };
    if record.request_fingerprint.as_slice() != input.request_fingerprint {
        return Ok(Reservation::KeyReused);
    }
    if inserted {
        Ok(Reservation::Created(record))
    } else {
        Ok(Reservation::Replay(record))
    }
}

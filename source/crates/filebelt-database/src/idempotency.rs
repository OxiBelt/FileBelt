// SPDX-License-Identifier: Apache-2.0

//! Transaction-local reservation and finalization for authority-creating writes.

use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{DatabaseError, IdempotencyRecord};

pub(crate) struct IdempotencyInput<'a> {
    pub principal_id: Uuid,
    pub route: &'a str,
    pub key: &'a str,
    pub request_fingerprint: &'a [u8; 32],
    /// One exact pre-contract-change fingerprint accepted only when replaying
    /// an existing unexpired receipt. New and expired reservations always
    /// persist `request_fingerprint`.
    pub legacy_request_fingerprint: Option<&'a [u8; 32]>,
}

pub(crate) enum IdempotencyReservation {
    Created,
    Replay(IdempotencyRecord),
    KeyReused,
}

pub(crate) async fn reserve(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    input: &IdempotencyInput<'_>,
) -> Result<IdempotencyReservation, DatabaseError> {
    if input.route.is_empty()
        || input.route.len() > 255
        || input.key.is_empty()
        || input.key.len() > 128
        || !input.key.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let inserted = sqlx::query("INSERT INTO public.idempotency_records (tenant_id,principal_id,route,key,request_fingerprint,response_status,response_body) VALUES ($1,$2,$3,$4,$5,102,$6) ON CONFLICT DO NOTHING")
        .bind(tenant_id)
        .bind(input.principal_id)
        .bind(input.route)
        .bind(input.key)
        .bind(input.request_fingerprint.as_slice())
        .bind(json!(null))
        .execute(&mut **transaction)
        .await?
        .rows_affected()
        == 1;
    let row = sqlx::query("SELECT request_fingerprint,response_status,response_body,expires_at<=clock_timestamp() AS expired FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key=$4 FOR UPDATE")
        .bind(tenant_id)
        .bind(input.principal_id)
        .bind(input.route)
        .bind(input.key)
        .fetch_one(&mut **transaction)
        .await?;
    if row.get::<bool, _>("expired") {
        sqlx::query("UPDATE public.idempotency_records SET request_fingerprint=$5,response_status=102,response_body=$6,created_at=clock_timestamp(),expires_at=clock_timestamp()+interval '24 hours' WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key=$4")
            .bind(tenant_id)
            .bind(input.principal_id)
            .bind(input.route)
            .bind(input.key)
            .bind(input.request_fingerprint.as_slice())
            .bind(json!(null))
            .execute(&mut **transaction)
            .await?;
        return Ok(IdempotencyReservation::Created);
    }
    let record = idempotency_record_from_row(&row);
    let current_matches = record.request_fingerprint.as_slice() == input.request_fingerprint;
    let legacy_matches = input
        .legacy_request_fingerprint
        .is_some_and(|legacy| record.request_fingerprint.as_slice() == legacy);
    if !current_matches && !legacy_matches {
        return Ok(IdempotencyReservation::KeyReused);
    }
    if inserted {
        Ok(IdempotencyReservation::Created)
    } else {
        Ok(IdempotencyReservation::Replay(record))
    }
}

pub(crate) async fn finalize(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    input: &IdempotencyInput<'_>,
    response_status: i32,
    response_body: &Value,
) -> Result<IdempotencyRecord, DatabaseError> {
    if !(100..=599).contains(&response_status) {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let row = sqlx::query("UPDATE public.idempotency_records SET response_status=$6,response_body=$7 WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key=$4 AND request_fingerprint=$5 RETURNING request_fingerprint,response_status,response_body")
        .bind(tenant_id)
        .bind(input.principal_id)
        .bind(input.route)
        .bind(input.key)
        .bind(input.request_fingerprint.as_slice())
        .bind(response_status)
        .bind(response_body)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(DatabaseError::Conflict)?;
    Ok(idempotency_record_from_row(&row))
}

fn idempotency_record_from_row(row: &sqlx::postgres::PgRow) -> IdempotencyRecord {
    IdempotencyRecord {
        request_fingerprint: row.get("request_fingerprint"),
        response_status: row.get("response_status"),
        response_body: row.get("response_body"),
    }
}

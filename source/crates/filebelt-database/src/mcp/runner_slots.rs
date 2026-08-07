// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-authoritative runner admission and deletion reconciliation.

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::{Database, DatabaseError};

#[derive(Clone, Copy, Debug)]
pub struct NewMcpRunnerSlotReservation {
    pub tenant_id: Uuid,
    pub invocation_id: Uuid,
    pub principal_id: Uuid,
    pub tenant_limit: i64,
    pub principal_limit: i64,
    pub lease_seconds: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpRunnerSlotReservation {
    pub tenant_id: Uuid,
    pub invocation_id: Uuid,
    pub principal_id: Uuid,
    pub lease_expires_at: String,
    pub created_at: String,
    pub released: bool,
}

impl Database {
    pub async fn mcp_reserve_runner_slot(
        &self,
        input: NewMcpRunnerSlotReservation,
    ) -> Result<McpRunnerSlotReservation, DatabaseError> {
        validate_limits(
            input.tenant_limit,
            input.principal_limit,
            input.lease_seconds,
        )?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO filebelt_mcp.runner_slot_admission (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(input.tenant_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SELECT tenant_id FROM filebelt_mcp.runner_slot_admission WHERE tenant_id=$1 FOR UPDATE")
            .bind(input.tenant_id)
            .fetch_one(&mut *transaction)
            .await?;
        if let Some(row) = sqlx::query("SELECT tenant_id,invocation_id,principal_id,lease_expires_at::text AS lease_expires_at,created_at::text AS created_at,released_at IS NOT NULL AS released FROM filebelt_mcp.runner_slot_reservations WHERE tenant_id=$1 AND invocation_id=$2")
            .bind(input.tenant_id)
            .bind(input.invocation_id)
            .fetch_optional(&mut *transaction)
            .await?
        {
            let reservation = reservation_from_row(&row);
            if reservation.principal_id != input.principal_id || reservation.released {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit().await?;
            return Ok(reservation);
        }
        let row = sqlx::query("SELECT count(*)::bigint AS tenant_used,count(*) FILTER (WHERE principal_id=$2)::bigint AS principal_used FROM filebelt_mcp.runner_slot_reservations WHERE tenant_id=$1 AND released_at IS NULL")
            .bind(input.tenant_id)
            .bind(input.principal_id)
            .fetch_one(&mut *transaction)
            .await?;
        if row.get::<i64, _>("tenant_used") >= input.tenant_limit
            || row.get::<i64, _>("principal_used") >= input.principal_limit
        {
            return Err(DatabaseError::AdmissionLimited);
        }
        let row = sqlx::query("INSERT INTO filebelt_mcp.runner_slot_reservations (tenant_id,invocation_id,principal_id,lease_expires_at) VALUES ($1,$2,$3,statement_timestamp()+make_interval(secs=>$4)) RETURNING tenant_id,invocation_id,principal_id,lease_expires_at::text AS lease_expires_at,created_at::text AS created_at,false AS released")
            .bind(input.tenant_id)
            .bind(input.invocation_id)
            .bind(input.principal_id)
            .bind(input.lease_seconds)
            .fetch_one(&mut *transaction)
            .await?;
        let reservation = reservation_from_row(&row);
        transaction.commit().await?;
        Ok(reservation)
    }

    pub async fn mcp_renew_runner_slot(
        &self,
        tenant_id: Uuid,
        invocation_id: Uuid,
        principal_id: Uuid,
        lease_seconds: i64,
    ) -> Result<(), DatabaseError> {
        validate_limits(1, 1, lease_seconds)?;
        let affected = sqlx::query("UPDATE filebelt_mcp.runner_slot_reservations SET lease_expires_at=statement_timestamp()+make_interval(secs=>$4),updated_at=clock_timestamp() WHERE tenant_id=$1 AND invocation_id=$2 AND principal_id=$3 AND released_at IS NULL")
            .bind(tenant_id)
            .bind(invocation_id)
            .bind(principal_id)
            .bind(lease_seconds)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(DatabaseError::NotFound)
        }
    }

    pub async fn mcp_expired_runner_slots(
        &self,
        limit: i64,
    ) -> Result<Vec<McpRunnerSlotReservation>, DatabaseError> {
        if !(1..=200).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        Ok(sqlx::query("SELECT tenant_id,invocation_id,principal_id,lease_expires_at::text AS lease_expires_at,created_at::text AS created_at,false AS released FROM filebelt_mcp.runner_slot_reservations WHERE released_at IS NULL AND lease_expires_at<=clock_timestamp() ORDER BY lease_expires_at,tenant_id,invocation_id LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(reservation_from_row)
            .collect())
    }

    pub async fn mcp_release_runner_slot_after_confirmed_delete(
        &self,
        tenant_id: Uuid,
        invocation_id: Uuid,
        principal_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let affected = sqlx::query("UPDATE filebelt_mcp.runner_slot_reservations SET released_at=COALESCE(released_at,clock_timestamp()),updated_at=clock_timestamp() WHERE tenant_id=$1 AND invocation_id=$2 AND principal_id=$3")
            .bind(tenant_id)
            .bind(invocation_id)
            .bind(principal_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(DatabaseError::NotFound)
        }
    }
}

fn validate_limits(tenant: i64, principal: i64, lease: i64) -> Result<(), DatabaseError> {
    if !(1..=10_000).contains(&tenant)
        || !(1..=10_000).contains(&principal)
        || principal > tenant
        || !(1..=900).contains(&lease)
    {
        Err(DatabaseError::InvalidPersistedValue)
    } else {
        Ok(())
    }
}

fn reservation_from_row(row: &sqlx::postgres::PgRow) -> McpRunnerSlotReservation {
    McpRunnerSlotReservation {
        tenant_id: row.get("tenant_id"),
        invocation_id: row.get("invocation_id"),
        principal_id: row.get("principal_id"),
        lease_expires_at: row.get("lease_expires_at"),
        created_at: row.get("created_at"),
        released: row.get("released"),
    }
}

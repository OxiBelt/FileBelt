// SPDX-License-Identifier: Apache-2.0

//! Bounded, resumable security cutovers for descendant direct shares.

use filebelt_database::Database;
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

pub async fn descendant_shares_status(
    database: &Database,
    tenant_slug: &str,
    operation_id: Uuid,
) -> Result<String, String> {
    let tenant_id = tenant_id(database, tenant_slug).await?;
    let value: Value =
        sqlx::query_scalar("SELECT filebelt_security.descendant_shares_status($1,$2)")
            .bind(tenant_id)
            .bind(operation_id)
            .fetch_one(database.pool())
            .await
            .map_err(|error| error.to_string())?;
    pretty(value)
}

pub async fn repair_descendant_shares(
    database: &Database,
    tenant_slug: &str,
    operation_id: Uuid,
    confirm_tenant: &str,
    actor_principal_id: Uuid,
    batch_size: u32,
) -> Result<String, String> {
    require_confirmation(tenant_slug, confirm_tenant)?;
    if !(1..=1_000).contains(&batch_size) {
        return Err("security repair batch size must be between 1 and 1000".into());
    }
    let tenant_id = tenant_id(database, tenant_slug).await?;
    let mut batch_count = 0_u64;
    let mut selected = 0_u64;
    let final_batch = loop {
        let mut transaction = database
            .pool()
            .begin()
            .await
            .map_err(|error| error.to_string())?;
        bind_source_revision(&mut transaction).await?;
        let value: Value =
            sqlx::query_scalar("SELECT filebelt_security.repair_descendant_shares($1,$2,$3,$4,$5)")
                .bind(tenant_id)
                .bind(operation_id)
                .bind(confirm_tenant)
                .bind(actor_principal_id)
                .bind(i32::try_from(batch_size).map_err(|_| "security repair batch is invalid")?)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|error| error.to_string())?;
        transaction
            .commit()
            .await
            .map_err(|error| error.to_string())?;
        batch_count += 1;
        let batch_selected = value
            .get("selected")
            .and_then(Value::as_u64)
            .ok_or_else(|| "security repair result is missing selected".to_owned())?;
        selected = selected.saturating_add(batch_selected);
        let remaining = value
            .get("remaining")
            .and_then(Value::as_u64)
            .ok_or_else(|| "security repair result is missing remaining".to_owned())?;
        if remaining == 0 {
            break value;
        }
        if batch_selected == 0 {
            return Err(
                "security repair made no progress; retry the same operation after concurrent row locks clear"
                    .into(),
            );
        }
    };
    pretty(json!({
        "schema": "filebelt.security.descendant_shares.repair.v1",
        "tenant_id": tenant_id,
        "operation_id": operation_id,
        "batches": batch_count,
        "selected": selected,
        "result": final_batch,
    }))
}

pub async fn verify_descendant_shares(
    database: &Database,
    tenant_slug: &str,
    operation_id: Uuid,
    confirm_tenant: &str,
    actor_principal_id: Uuid,
) -> Result<String, String> {
    require_confirmation(tenant_slug, confirm_tenant)?;
    let tenant_id = tenant_id(database, tenant_slug).await?;
    let mut transaction = database
        .pool()
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    bind_source_revision(&mut transaction).await?;
    let value: Value =
        sqlx::query_scalar("SELECT filebelt_security.verify_descendant_shares($1,$2,$3,$4)")
            .bind(tenant_id)
            .bind(operation_id)
            .bind(confirm_tenant)
            .bind(actor_principal_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    pretty(value)
}

pub async fn activate_descendant_shares(
    database: &Database,
    tenant_slug: &str,
    operation_id: Uuid,
    confirm_tenant: &str,
    actor_principal_id: Uuid,
) -> Result<String, String> {
    require_confirmation(tenant_slug, confirm_tenant)?;
    let tenant_id = tenant_id(database, tenant_slug).await?;
    let mut transaction = database
        .pool()
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    bind_source_revision(&mut transaction).await?;
    let value: Value =
        sqlx::query_scalar("SELECT filebelt_security.activate_descendant_shares($1,$2,$3,$4)")
            .bind(tenant_id)
            .bind(operation_id)
            .bind(confirm_tenant)
            .bind(actor_principal_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    pretty(value)
}

async fn bind_source_revision(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), String> {
    sqlx::query_scalar::<_, String>("SELECT set_config('filebelt.source_revision',$1,true)")
        .bind(filebelt_build_identity::CURRENT.revision)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn tenant_id(database: &Database, tenant_slug: &str) -> Result<Uuid, String> {
    sqlx::query("SELECT id FROM tenants WHERE slug=$1")
        .bind(tenant_slug)
        .fetch_optional(database.pool())
        .await
        .map_err(|error| error.to_string())?
        .map(|row| row.get("id"))
        .ok_or_else(|| "configured tenant was not found".to_owned())
}

fn require_confirmation(tenant_slug: &str, confirm_tenant: &str) -> Result<(), String> {
    if tenant_slug == confirm_tenant {
        Ok(())
    } else {
        Err("--confirm-tenant must exactly match the configured tenant slug".into())
    }
}

fn pretty(value: Value) -> Result<String, String> {
    serde_json::to_string_pretty(&value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_confirmation_is_exact() {
        assert!(require_confirmation("acme", "acme").is_ok());
        assert!(require_confirmation("acme", "ACME").is_err());
        assert!(require_confirmation("acme", " acme").is_err());
    }
}

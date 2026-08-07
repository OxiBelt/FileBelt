// SPDX-License-Identifier: Apache-2.0

//! Idempotent operator orchestration for durable payload scrub jobs.

use filebelt_database::Database;
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

const START_SCHEMA: &str = "filebelt.storage.scrub.start.v1";
const STATUS_SCHEMA: &str = "filebelt.storage.scrub.status.v1";

pub async fn start(
    database: &Database,
    tenant_slug: &str,
    backend_id: Uuid,
    run_id: Uuid,
    payload_id: Option<Uuid>,
    confirm_tenant: Option<&str>,
    batch_size: u32,
) -> Result<String, String> {
    if !(1..=10_000).contains(&batch_size) {
        return Err("scrub batch size must be between 1 and 10000".into());
    }
    match (payload_id, confirm_tenant) {
        (Some(_), Some(_)) => {
            return Err("targeted scrub must not include --confirm-tenant".into());
        }
        (None, Some(confirmation)) if confirmation == tenant_slug => {}
        (None, _) => {
            return Err(
                "full scrub requires --confirm-tenant exactly matching the configured tenant slug"
                    .into(),
            );
        }
        (Some(_), None) => {}
    }

    let mut transaction = database
        .pool()
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    let tenant_id = tenant_id(&mut transaction, tenant_slug).await?;
    let payloads = if let Some(payload_id) = payload_id {
        let row = sqlx::query("SELECT id FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND id=$3 AND state IN ('referenced','finalized') FOR UPDATE")
            .bind(tenant_id)
            .bind(backend_id)
            .bind(payload_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "target payload is not eligible for scrub".to_owned())?;
        vec![row.get::<Uuid, _>("id")]
    } else {
        sqlx::query("SELECT payload.id FROM payload_objects AS payload WHERE payload.tenant_id=$1 AND payload.backend_id=$2 AND payload.state IN ('referenced','finalized') AND NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.tenant_id=payload.tenant_id AND jobs.kind='payload_scrub' AND jobs.aggregate_id=payload.id AND jobs.payload->>'scrub_run_id'=$3) ORDER BY payload.id FOR UPDATE OF payload SKIP LOCKED LIMIT $4")
            .bind(tenant_id)
            .bind(backend_id)
            .bind(run_id.to_string())
            .bind(i64::from(batch_size))
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get::<Uuid, _>("id"))
            .collect()
    };
    let mut inserted = 0_u64;
    for payload_id in &payloads {
        inserted += sqlx::query("INSERT INTO jobs (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) VALUES ($1,$2,'payload_scrub','queued',40,$3,$4,$5) ON CONFLICT (tenant_id,kind,idempotency_key) DO NOTHING")
            .bind(tenant_id)
            .bind(Uuid::new_v4())
            .bind(payload_id)
            .bind(idempotency_key(run_id, *payload_id))
            .bind(json!({"payload_id": payload_id, "scrub_run_id": run_id}))
            .execute(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?
            .rows_affected();
    }
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM payload_objects AS payload WHERE payload.tenant_id=$1 AND payload.backend_id=$2 AND payload.state IN ('referenced','finalized') AND NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.tenant_id=payload.tenant_id AND jobs.kind='payload_scrub' AND jobs.aggregate_id=payload.id AND jobs.payload->>'scrub_run_id'=$3)")
        .bind(tenant_id)
        .bind(backend_id)
        .bind(run_id.to_string())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&json!({
        "schema": START_SCHEMA,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "payload_id": payload_id,
        "jobs_selected": payloads.len(),
        "jobs_inserted": inserted,
        "eligible_payloads_not_queued": remaining,
    }))
    .map_err(|error| error.to_string())
}

pub async fn status(
    database: &Database,
    tenant_slug: &str,
    backend_id: Uuid,
    run_id: Uuid,
    payload_id: Option<Uuid>,
) -> Result<String, String> {
    let status = status_value(database, tenant_slug, backend_id, run_id, payload_id).await?;
    serde_json::to_string_pretty(&status).map_err(|error| error.to_string())
}

pub async fn verify(
    database: &Database,
    tenant_slug: &str,
    backend_id: Uuid,
    run_id: Uuid,
    payload_id: Option<Uuid>,
) -> Result<String, String> {
    let status = status_value(database, tenant_slug, backend_id, run_id, payload_id).await?;
    let field = |name: &str| {
        status
            .get(name)
            .and_then(Value::as_i64)
            .ok_or_else(|| format!("scrub status field {name} is invalid"))
    };
    let jobs = field("jobs")?;
    let complete = field("complete")?;
    let verified = field("verified")?;
    let missing = field("eligible_payloads_without_job")?;
    let quarantined = field("quarantined_payloads")?;
    if (payload_id.is_some() && jobs != 1)
        || missing != 0
        || complete != jobs
        || verified != jobs
        || quarantined != 0
    {
        return Err(format!(
            "scrub run is not verified: {}",
            serde_json::to_string(&status).map_err(|error| error.to_string())?
        ));
    }
    serde_json::to_string_pretty(&json!({
        "schema": "filebelt.storage.scrub.verification.v1",
        "status": "verified",
        "run": status,
    }))
    .map_err(|error| error.to_string())
}

async fn status_value(
    database: &Database,
    tenant_slug: &str,
    backend_id: Uuid,
    run_id: Uuid,
    payload_id: Option<Uuid>,
) -> Result<Value, String> {
    let mut transaction = database
        .pool()
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    let tenant_id = tenant_id(&mut transaction, tenant_slug).await?;
    if let Some(payload_id) = payload_id {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND id=$3)")
            .bind(tenant_id)
            .bind(backend_id)
            .bind(payload_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?;
        if !exists {
            return Err("target payload was not found".into());
        }
    }
    let row = sqlx::query("SELECT count(*) AS jobs,count(*) FILTER (WHERE state='queued') AS queued,count(*) FILTER (WHERE state='running') AS running,count(*) FILTER (WHERE state='retry_wait') AS retry_wait,count(*) FILTER (WHERE state='terminal') AS terminal,count(*) FILTER (WHERE state='operator_blocked') AS operator_blocked,count(*) FILTER (WHERE state='complete') AS complete,count(*) FILTER (WHERE state='complete' AND EXISTS (SELECT 1 FROM job_attempts WHERE job_attempts.tenant_id=jobs.tenant_id AND job_attempts.job_id=jobs.id AND job_attempts.outcome='payload_verified')) AS verified FROM jobs WHERE tenant_id=$1 AND kind='payload_scrub' AND payload->>'scrub_run_id'=$2 AND ($3::uuid IS NULL OR aggregate_id=$3)")
        .bind(tenant_id)
        .bind(run_id.to_string())
        .bind(payload_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    let eligible: i64 = sqlx::query_scalar("SELECT count(*) FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND state IN ('referenced','finalized','quarantining','quarantined') AND ($3::uuid IS NULL OR id=$3)")
        .bind(tenant_id)
        .bind(backend_id)
        .bind(payload_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    let missing: i64 = sqlx::query_scalar("SELECT count(*) FROM payload_objects AS payload WHERE payload.tenant_id=$1 AND payload.backend_id=$2 AND payload.state IN ('referenced','finalized','quarantining','quarantined') AND ($4::uuid IS NULL OR payload.id=$4) AND NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.tenant_id=payload.tenant_id AND jobs.kind='payload_scrub' AND jobs.aggregate_id=payload.id AND jobs.payload->>'scrub_run_id'=$3)")
        .bind(tenant_id)
        .bind(backend_id)
        .bind(run_id.to_string())
        .bind(payload_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    let quarantined: i64 = sqlx::query_scalar("SELECT count(*) FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND state IN ('quarantining','quarantined') AND ($3::uuid IS NULL OR id=$3)")
        .bind(tenant_id)
        .bind(backend_id)
        .bind(payload_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    let status = json!({
        "schema": STATUS_SCHEMA,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "payload_id": payload_id,
        "eligible_payloads": eligible,
        "eligible_payloads_without_job": missing,
        "quarantined_payloads": quarantined,
        "jobs": row.get::<i64, _>("jobs"),
        "queued": row.get::<i64, _>("queued"),
        "running": row.get::<i64, _>("running"),
        "retry_wait": row.get::<i64, _>("retry_wait"),
        "terminal": row.get::<i64, _>("terminal"),
        "operator_blocked": row.get::<i64, _>("operator_blocked"),
        "complete": row.get::<i64, _>("complete"),
        "verified": row.get::<i64, _>("verified"),
    });
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    Ok(status)
}

async fn tenant_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_slug: &str,
) -> Result<Uuid, String> {
    sqlx::query("SELECT id FROM tenants WHERE slug=$1")
        .bind(tenant_slug)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| error.to_string())?
        .map(|row| row.get("id"))
        .ok_or_else(|| "configured tenant was not found".to_owned())
}

fn idempotency_key(run_id: Uuid, payload_id: Uuid) -> String {
    format!("operator-scrub:{run_id}:{payload_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_idempotency_key_binds_run_and_payload() {
        let run = Uuid::parse_str("0198d1e4-bf39-7f65-9029-11eedf35de88").expect("run UUID");
        let payload =
            Uuid::parse_str("0198d1e4-c573-71a2-b8bb-f0c4d57a17bc").expect("payload UUID");
        assert_eq!(
            idempotency_key(run, payload),
            "operator-scrub:0198d1e4-bf39-7f65-9029-11eedf35de88:0198d1e4-c573-71a2-b8bb-f0c4d57a17bc"
        );
    }
}

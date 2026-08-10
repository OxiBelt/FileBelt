// SPDX-License-Identifier: Apache-2.0

//! Audited, fail-closed Phase 8 compatibility and activation controls.

use filebelt_database::Database;
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

const CONFIG_VERSION: i32 = 7;
const SCHEMA_MAX: i32 = 9;
const REQUIRED_ROLES: &[&str] = &[
    "filebelt-api",
    "filebelt-worker-io",
    "filebelt-worker-maintenance",
    "filebelt-collaboration",
    "filebelt-media-controller",
    "filebelt-vfs",
    "filebelt-tools",
];

pub async fn advertise(
    database: &Database,
    tenant_slug: &str,
    role: &str,
    instance_id: Uuid,
    source_revision: &str,
    compatible: bool,
) -> Result<String, String> {
    if !REQUIRED_ROLES.contains(&role) {
        return Err("role is not in the Phase 8 compatibility set".into());
    }
    if !(7..=64).contains(&source_revision.len())
        || !source_revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("source revision must be 7 through 64 hexadecimal characters".into());
    }
    let tenant_id = database
        .tenant_by_slug(tenant_slug)
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query("SELECT filebelt_phase8.advertise_role($1,$2,$3,$4,$5,$6,$7)")
        .bind(tenant_id)
        .bind(role)
        .bind(instance_id)
        .bind(source_revision.to_ascii_lowercase())
        .bind(CONFIG_VERSION)
        .bind(SCHEMA_MAX)
        .bind(compatible)
        .execute(database.pool())
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&json!({
        "schema": "filebelt.phase8.compatibility.v1",
        "tenant_id": tenant_id,
        "role": role,
        "instance_id": instance_id,
        "source_revision": source_revision.to_ascii_lowercase(),
        "config_version": CONFIG_VERSION,
        "schema_max": SCHEMA_MAX,
        "compatible": compatible,
    }))
    .map_err(|error| error.to_string())
}

pub async fn status(database: &Database, tenant_slug: &str) -> Result<String, String> {
    let tenant_id = database
        .tenant_by_slug(tenant_slug)
        .await
        .map_err(|error| error.to_string())?;
    let state = sqlx::query("SELECT state,generation,activated_at::text AS activated_at,disabled_at::text AS disabled_at FROM filebelt_phase8.activation_state WHERE tenant_id=$1")
        .bind(tenant_id)
        .fetch_optional(database.pool())
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Phase 8 activation state is absent; apply current migrations".to_owned())?;
    let advertisements = sqlx::query("SELECT DISTINCT ON (role) role,instance_id,source_revision,config_version,schema_max,compatible,advertised_at::text AS advertised_at,(advertised_at>=clock_timestamp()-interval '5 minutes') AS fresh FROM filebelt_phase8.role_compatibility WHERE tenant_id=$1 ORDER BY role,advertised_at DESC,instance_id")
        .bind(tenant_id)
        .fetch_all(database.pool())
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|row| json!({
            "role": row.get::<String,_>("role"),
            "instance_id": row.get::<Uuid,_>("instance_id"),
            "source_revision": row.get::<String,_>("source_revision"),
            "config_version": row.get::<i32,_>("config_version"),
            "schema_max": row.get::<i32,_>("schema_max"),
            "compatible": row.get::<bool,_>("compatible"),
            "advertised_at": row.get::<String,_>("advertised_at"),
            "fresh": row.get::<bool,_>("fresh"),
        }))
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&json!({
        "schema": "filebelt.phase8.activation.v1",
        "tenant_id": tenant_id,
        "state": state.get::<String,_>("state"),
        "generation": state.get::<i64,_>("generation"),
        "activated_at": state.get::<Option<String>,_>("activated_at"),
        "disabled_at": state.get::<Option<String>,_>("disabled_at"),
        "required_roles": REQUIRED_ROLES,
        "latest_advertisements": advertisements,
    }))
    .map_err(|error| error.to_string())
}

pub async fn activate(
    database: &Database,
    tenant_slug: &str,
    actor_principal_id: Uuid,
) -> Result<String, String> {
    let tenant_id = database
        .tenant_by_slug(tenant_slug)
        .await
        .map_err(|error| error.to_string())?;
    let mut transaction = database
        .pool()
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    lock_activation(&mut transaction, tenant_id).await?;
    require_tenant_admin(&mut transaction, tenant_id, actor_principal_id).await?;
    let current = sqlx::query("SELECT state,generation FROM filebelt_phase8.activation_state WHERE tenant_id=$1 FOR UPDATE")
        .bind(tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Phase 8 activation state is absent; apply current migrations".to_owned())?;
    let previous_state = current.get::<String, _>("state");
    if previous_state == "active" {
        return Err("Phase 8 is already active".into());
    }
    let generation = current
        .get::<i64, _>("generation")
        .checked_add(1)
        .ok_or_else(|| "activation generation overflow".to_owned())?;
    let roles = compatible_roles(&mut transaction, tenant_id).await?;

    sqlx::query("DELETE FROM filebelt_phase8.managed_traversal WHERE tenant_id=$1")
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query(
        "INSERT INTO filebelt_phase8.managed_traversal (tenant_id,drive_id,ancestor_id,principal_id,source_acl_entry_id,activation_generation) \
         SELECT DISTINCT acl.tenant_id,acl.drive_id,path.ancestor_id,acl.principal_id,acl.id,$2 \
         FROM acl_entries acl \
         JOIN node_ancestry covered ON covered.tenant_id=acl.tenant_id AND covered.drive_id=acl.drive_id AND covered.ancestor_id=acl.resource_id \
           AND ((covered.depth=0 AND acl.inheritance IN ('self','self_and_descendants')) OR (covered.depth>0 AND acl.inheritance IN ('descendants','self_and_descendants'))) \
         JOIN node_ancestry path ON path.tenant_id=covered.tenant_id AND path.drive_id=covered.drive_id AND path.descendant_id=covered.descendant_id AND path.depth>0 \
         WHERE acl.tenant_id=$1 AND acl.effect='allow'",
    )
    .bind(tenant_id)
    .bind(generation)
    .execute(&mut *transaction)
    .await
    .map_err(|error| error.to_string())?;
    sqlx::query("DELETE FROM filebelt_phase8.managed_group_memberships WHERE tenant_id=$1")
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query("INSERT INTO filebelt_phase8.managed_group_memberships (tenant_id,group_id,user_principal_id,source_membership_generation,activation_generation) SELECT membership.tenant_id,membership.group_id,membership.user_principal_id,membership.generation,$2 FROM group_memberships membership WHERE membership.tenant_id=$1 AND EXISTS (SELECT 1 FROM filebelt_mount.nfs_principal_mappings mapping WHERE mapping.tenant_id=membership.tenant_id AND mapping.principal_id=membership.user_principal_id AND mapping.revoked_at IS NULL)")
        .bind(tenant_id)
        .bind(generation)
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;

    sqlx::query("UPDATE filebelt_phase8.activation_state SET state='active',generation=$2,activated_by=$3,activated_at=clock_timestamp(),disabled_by=NULL,disabled_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1")
        .bind(tenant_id).bind(generation).bind(actor_principal_id)
        .execute(&mut *transaction).await.map_err(|error| error.to_string())?;
    record_event(
        &mut transaction,
        tenant_id,
        actor_principal_id,
        &previous_state,
        "active",
        generation,
        &roles,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    Ok(json!({"state":"active","tenant_id":tenant_id,"generation":generation,"compatible_roles":roles}).to_string())
}

pub async fn deactivate(
    database: &Database,
    tenant_slug: &str,
    actor_principal_id: Uuid,
) -> Result<String, String> {
    let tenant_id = database
        .tenant_by_slug(tenant_slug)
        .await
        .map_err(|error| error.to_string())?;
    let mut transaction = database
        .pool()
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    lock_activation(&mut transaction, tenant_id).await?;
    require_tenant_admin(&mut transaction, tenant_id, actor_principal_id).await?;
    let current = sqlx::query("SELECT state,generation FROM filebelt_phase8.activation_state WHERE tenant_id=$1 FOR UPDATE")
        .bind(tenant_id).fetch_optional(&mut *transaction).await.map_err(|error| error.to_string())?
        .ok_or_else(|| "Phase 8 activation state is absent; apply current migrations".to_owned())?;
    let previous_state = current.get::<String, _>("state");
    if previous_state != "active" {
        return Err("Phase 8 is not active".into());
    }
    let generation = current
        .get::<i64, _>("generation")
        .checked_add(1)
        .ok_or_else(|| "activation generation overflow".to_owned())?;
    sqlx::query("UPDATE filebelt_phase8.activation_state SET state='disabled',generation=$2,disabled_by=$3,disabled_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1")
        .bind(tenant_id).bind(generation).bind(actor_principal_id).execute(&mut *transaction).await.map_err(|error| error.to_string())?;
    record_event(
        &mut transaction,
        tenant_id,
        actor_principal_id,
        &previous_state,
        "disabled",
        generation,
        &json!([]),
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    Ok(json!({"state":"disabled","tenant_id":tenant_id,"generation":generation}).to_string())
}

async fn lock_activation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
) -> Result<(), String> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('filebelt-phase8:' || $1::text,0))")
        .bind(tenant_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn require_tenant_admin(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    actor: Uuid,
) -> Result<(), String> {
    let authorized: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users u JOIN external_identities e ON e.tenant_id=u.tenant_id AND e.user_id=u.id AND e.disabled_at IS NULL JOIN tenant_admin_bindings b ON b.tenant_id=e.tenant_id AND b.issuer=e.issuer AND b.subject=e.subject WHERE u.tenant_id=$1 AND u.principal_id=$2 AND u.status='active')")
        .bind(tenant_id).bind(actor).fetch_one(&mut **transaction).await.map_err(|error| error.to_string())?;
    if !authorized {
        return Err("actor is not an active tenant administrator".into());
    }
    Ok(())
}

async fn compatible_roles(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
) -> Result<Value, String> {
    let rows = sqlx::query("SELECT DISTINCT ON (role) role,instance_id,source_revision,config_version,schema_max,compatible FROM filebelt_phase8.role_compatibility WHERE tenant_id=$1 AND role=ANY($2) ORDER BY role,advertised_at DESC,instance_id")
        .bind(tenant_id).bind(REQUIRED_ROLES).fetch_all(&mut **transaction).await.map_err(|error| error.to_string())?;
    if rows.len() != REQUIRED_ROLES.len() {
        return Err("not every required role has advertised Phase 8 compatibility".into());
    }
    let mut revision: Option<String> = None;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let role = row.get::<String, _>("role");
        let candidate = row.get::<String, _>("source_revision");
        if !row.get::<bool, _>("compatible")
            || row.get::<i32, _>("config_version") != CONFIG_VERSION
            || row.get::<i32, _>("schema_max") < SCHEMA_MAX
        {
            return Err(format!(
                "role {role} advertised an incompatible Phase 8 contract"
            ));
        }
        if let Some(expected) = &revision {
            if expected != &candidate {
                return Err("required roles do not advertise one source revision".into());
            }
        } else {
            revision = Some(candidate.clone());
        }
        result.push(json!({"role":role,"instance_id":row.get::<Uuid,_>("instance_id"),"source_revision":candidate}));
    }
    let fresh: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT DISTINCT ON (role) role,advertised_at FROM filebelt_phase8.role_compatibility WHERE tenant_id=$1 AND role=ANY($2) ORDER BY role,advertised_at DESC,instance_id) latest WHERE advertised_at>=clock_timestamp()-interval '5 minutes'")
        .bind(tenant_id).bind(REQUIRED_ROLES).fetch_one(&mut **transaction).await.map_err(|error| error.to_string())?;
    if fresh != REQUIRED_ROLES.len() as i64 {
        return Err("one or more required compatibility advertisements are stale".into());
    }
    Ok(Value::Array(result))
}

async fn record_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    actor: Uuid,
    previous: &str,
    next: &str,
    generation: i64,
    roles: &Value,
) -> Result<(), String> {
    let event_id = Uuid::new_v4();
    sqlx::query("INSERT INTO filebelt_phase8.activation_events (tenant_id,id,actor_principal_id,previous_state,new_state,generation,compatible_roles) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(tenant_id).bind(event_id).bind(actor).bind(previous).bind(next).bind(generation).bind(roles).execute(&mut **transaction).await.map_err(|error| error.to_string())?;
    sqlx::query("INSERT INTO audit_events (tenant_id,id,actor_principal_id,action,outcome,reason_code,privacy_visible,details) VALUES ($1,$2,$3,'phase8.activation','allowed',$4,false,$5)")
        .bind(tenant_id).bind(event_id).bind(actor).bind(if next=="active" {"phase8_activated"} else {"phase8_disabled"}).bind(json!({"previous_state":previous,"new_state":next,"generation":generation,"compatible_roles":roles})).execute(&mut **transaction).await.map_err(|error| error.to_string())?;
    Ok(())
}

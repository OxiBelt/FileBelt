// SPDX-License-Identifier: Apache-2.0

//! Audited, fail-closed Phase 8 compatibility and activation controls.

use std::collections::BTreeSet;
use std::path::Path;

use filebelt_database::Database;
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

const PHASE8_CONFIG_VERSION: i32 = filebelt_control_protocol::CONFIG_VERSION as i32;
const SCHEMA_MAX: i32 = 9;
const QUALIFICATION_SCHEMA: &str = "filebelt.phase8.qualification.v2";
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
    qualification_evidence: &Path,
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
    validate_qualification_evidence(
        qualification_evidence,
        role,
        instance_id,
        source_revision,
        compatible,
    )?;
    let tenant_id = database
        .tenant_by_slug(tenant_slug)
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query("SELECT filebelt_phase8.advertise_role($1,$2,$3,$4,$5,$6,$7)")
        .bind(tenant_id)
        .bind(role)
        .bind(instance_id)
        .bind(source_revision.to_ascii_lowercase())
        .bind(PHASE8_CONFIG_VERSION)
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
        "config_version": PHASE8_CONFIG_VERSION,
        "schema_max": SCHEMA_MAX,
        "compatible": compatible,
    }))
    .map_err(|error| error.to_string())
}

fn validate_qualification_evidence(
    path: &Path,
    role: &str,
    instance_id: Uuid,
    source_revision: &str,
    compatible: bool,
) -> Result<(), String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read Phase 8 qualification evidence: {error}"))?;
    let evidence: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Phase 8 qualification evidence is not valid JSON: {error}"))?;
    let object = evidence
        .as_object()
        .ok_or_else(|| "Phase 8 qualification evidence must be an object".to_owned())?;
    if object.get("schema").and_then(Value::as_str) != Some(QUALIFICATION_SCHEMA) {
        return Err(format!(
            "Phase 8 qualification evidence schema must be {QUALIFICATION_SCHEMA}"
        ));
    }
    if object.get("configurationVersion").and_then(Value::as_i64)
        != Some(i64::from(PHASE8_CONFIG_VERSION))
    {
        return Err(format!(
            "Phase 8 qualification evidence configurationVersion must be {PHASE8_CONFIG_VERSION}"
        ));
    }
    let normalized_revision = source_revision.to_ascii_lowercase();
    if object.get("sourceRevision").and_then(Value::as_str) != Some(normalized_revision.as_str()) {
        return Err("Phase 8 qualification evidence sourceRevision does not match".into());
    }
    let roles = object
        .get("roles")
        .and_then(Value::as_array)
        .ok_or_else(|| "Phase 8 qualification evidence roles must be an array".to_owned())?;
    let mut observed = BTreeSet::new();
    let mut selected = None;
    for result in roles {
        let result = result
            .as_object()
            .ok_or_else(|| "Phase 8 qualification role result must be an object".to_owned())?;
        let result_role = nonempty_string(result.get("role"), "role")?;
        if !REQUIRED_ROLES.contains(&result_role) || !observed.insert(result_role) {
            return Err("Phase 8 qualification evidence has an unknown or duplicate role".into());
        }
        if result_role == role {
            selected = Some(result);
        }
    }
    if observed.len() != REQUIRED_ROLES.len()
        || REQUIRED_ROLES
            .iter()
            .any(|required| !observed.contains(required))
    {
        return Err("Phase 8 qualification evidence does not cover every required role".into());
    }
    let result = selected.ok_or_else(|| {
        "Phase 8 qualification evidence does not contain the requested role".to_owned()
    })?;
    if nonempty_string(result.get("sourceRevision"), "role sourceRevision")? != normalized_revision
    {
        return Err("Phase 8 role evidence sourceRevision does not match".into());
    }
    if nonempty_string(result.get("instanceId"), "role instanceId")? != instance_id.to_string() {
        return Err("Phase 8 role evidence instanceId does not match".into());
    }
    nonempty_string(result.get("endpoint"), "role endpoint")?;
    validate_cleanup(result.get("cleanup"))?;
    let status = nonempty_string(result.get("status"), "role status")?;
    if compatible {
        if status != "passed" {
            return Err("compatible Phase 8 advertisement requires passed role evidence".into());
        }
        validate_assertion(result.get("successAssertion"), "successAssertion")?;
        validate_assertion(result.get("failureAssertion"), "failureAssertion")?;
        let samples = result
            .get("samplesMilliseconds")
            .and_then(Value::as_array)
            .ok_or_else(|| "passed Phase 8 role evidence requires latency samples".to_owned())?;
        if samples.is_empty()
            || samples.iter().any(|sample| {
                sample
                    .as_f64()
                    .is_none_or(|milliseconds| !milliseconds.is_finite() || milliseconds <= 0.0)
            })
        {
            return Err("passed Phase 8 role evidence requires positive latency samples".into());
        }
    } else {
        if status != "failed" && status != "skipped" {
            return Err(
                "incompatible Phase 8 advertisement requires failed or skipped evidence".into(),
            );
        }
        if status == "skipped" {
            nonempty_string(result.get("prerequisite"), "role prerequisite")?;
        } else {
            nonempty_string(result.get("failure"), "role failure")?;
        }
    }
    Ok(())
}

fn nonempty_string<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("Phase 8 qualification evidence {field} must be nonempty"))
}

fn validate_assertion(value: Option<&Value>, field: &str) -> Result<(), String> {
    let assertion = value
        .and_then(Value::as_object)
        .ok_or_else(|| format!("Phase 8 role evidence {field} must be an object"))?;
    nonempty_string(assertion.get("expected"), &format!("{field}.expected"))?;
    nonempty_string(assertion.get("observed"), &format!("{field}.observed"))?;
    if assertion.get("passed").and_then(Value::as_bool) != Some(true) {
        return Err(format!("Phase 8 role evidence {field}.passed must be true"));
    }
    Ok(())
}

fn validate_cleanup(value: Option<&Value>) -> Result<(), String> {
    let cleanup = value
        .and_then(Value::as_object)
        .ok_or_else(|| "Phase 8 role evidence cleanup must be an object".to_owned())?;
    let status = nonempty_string(cleanup.get("status"), "cleanup.status")?;
    if status != "passed" && status != "not_required" {
        return Err("Phase 8 role evidence cleanup.status is invalid".into());
    }
    nonempty_string(cleanup.get("detail"), "cleanup.detail")?;
    Ok(())
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
           AND (covered.depth=0 OR (covered.depth=1 AND acl.inheritance IN ('children','descendants','self_and_descendants')) OR (covered.depth>1 AND acl.inheritance IN ('descendants','self_and_descendants'))) \
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
            || row.get::<i32, _>("config_version") != PHASE8_CONFIG_VERSION
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use serde_json::json;
    use uuid::Uuid;

    use super::{
        PHASE8_CONFIG_VERSION, QUALIFICATION_SCHEMA, REQUIRED_ROLES,
        validate_qualification_evidence,
    };

    #[test]
    fn compatibility_advertisement_tracks_the_runtime_config_version() {
        assert_eq!(
            PHASE8_CONFIG_VERSION,
            filebelt_control_protocol::CONFIG_VERSION as i32
        );
        assert_eq!(PHASE8_CONFIG_VERSION, 9);
    }

    #[test]
    fn compatible_advertisement_requires_executed_role_evidence() {
        let instance_id = Uuid::new_v4();
        let revision = "a".repeat(40);
        let roles = REQUIRED_ROLES
            .iter()
            .map(|role| {
                json!({
                    "role": role,
                    "status": "passed",
                    "sourceRevision": revision,
                    "instanceId": instance_id,
                    "endpoint": format!("local://{role}"),
                    "samplesMilliseconds": [1.0],
                    "successAssertion": {"expected": "success", "observed": "success", "passed": true},
                    "failureAssertion": {"expected": "rejected", "observed": "rejected", "passed": true},
                    "cleanup": {"status": "not_required", "detail": "read-only assertion"},
                })
            })
            .collect::<Vec<_>>();
        let mut file = tempfile::NamedTempFile::new().expect("temporary evidence");
        serde_json::to_writer(
            &mut file,
            &json!({
                "schema": QUALIFICATION_SCHEMA,
                "configurationVersion": PHASE8_CONFIG_VERSION,
                "sourceRevision": revision,
                "roles": roles,
            }),
        )
        .expect("write evidence");
        file.flush().expect("flush evidence");

        assert!(
            validate_qualification_evidence(
                file.path(),
                "filebelt-api",
                instance_id,
                &revision,
                true,
            )
            .is_ok()
        );
        let error = validate_qualification_evidence(
            file.path(),
            "filebelt-api",
            Uuid::new_v4(),
            &revision,
            true,
        )
        .expect_err("mismatched instance must fail");
        assert!(error.contains("instanceId does not match"));
    }

    #[test]
    fn skipped_role_can_only_advertise_incompatible_with_a_prerequisite() {
        let instance_id = Uuid::new_v4();
        let revision = "b".repeat(40);
        let roles = REQUIRED_ROLES
            .iter()
            .map(|role| {
                if *role == "filebelt-media-controller" {
                    json!({
                        "role": role,
                        "status": "skipped",
                        "sourceRevision": revision,
                        "instanceId": instance_id,
                        "endpoint": "media-controller://dispatch",
                        "prerequisite": "scoped I/O transfer and reconciled Job callbacks",
                        "cleanup": {"status": "not_required", "detail": "no workload started"},
                    })
                } else {
                    json!({
                        "role": role,
                        "status": "failed",
                        "sourceRevision": revision,
                        "instanceId": instance_id,
                        "endpoint": format!("local://{role}"),
                        "failure": "not exercised by this focused fixture",
                        "cleanup": {"status": "not_required", "detail": "no workload started"},
                    })
                }
            })
            .collect::<Vec<_>>();
        let mut file = tempfile::NamedTempFile::new().expect("temporary evidence");
        serde_json::to_writer(
            &mut file,
            &json!({
                "schema": QUALIFICATION_SCHEMA,
                "configurationVersion": PHASE8_CONFIG_VERSION,
                "sourceRevision": revision,
                "roles": roles,
            }),
        )
        .expect("write evidence");
        file.flush().expect("flush evidence");

        assert!(
            validate_qualification_evidence(
                file.path(),
                "filebelt-media-controller",
                instance_id,
                &revision,
                false,
            )
            .is_ok()
        );
        let error = validate_qualification_evidence(
            file.path(),
            "filebelt-media-controller",
            instance_id,
            &revision,
            true,
        )
        .expect_err("skipped evidence cannot advertise compatibility");
        assert!(error.contains("requires passed role evidence"));
    }
}

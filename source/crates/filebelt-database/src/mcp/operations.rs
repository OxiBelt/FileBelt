// SPDX-License-Identifier: Apache-2.0

//! MCP administrative, invocation, and abuse-control persistence operations.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{Database, DatabaseError};

#[derive(Clone, Debug)]
pub struct NewMcpManagedTemplate<'a> {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub display_name: &'a str,
    pub description: &'a str,
    pub transport: &'a str,
    pub endpoint_uri: Option<&'a str>,
    pub trust_profile: Option<&'a str>,
    pub catalog_entry: Option<&'a str>,
    pub policy: &'a Value,
    pub created_by: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpManagedTemplateRecord {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub display_name: String,
    pub description: String,
    pub transport: String,
    pub endpoint_uri: Option<String>,
    pub trust_profile: Option<String>,
    pub catalog_entry: Option<String>,
    pub enabled: bool,
    pub policy: Value,
    pub revision: i64,
    pub revocation_generation: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub struct NewMcpServicePrincipal<'a> {
    pub tenant_id: Uuid,
    pub service_id: Uuid,
    pub principal_id: Uuid,
    pub display_name: &'a str,
    pub identity_binding_id: Uuid,
    pub spiffe_uri: &'a str,
    pub created_by: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServicePrincipalRecord {
    pub tenant_id: Uuid,
    pub service_id: Uuid,
    pub principal_id: Uuid,
    pub display_name: String,
    pub spiffe_uri: String,
    pub status: String,
    pub revocation_generation: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub struct NewMcpServiceGrant<'a> {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub service_id: Uuid,
    pub expected_service_generation: i64,
    pub registration_id: Uuid,
    pub capability_fingerprint: &'a [u8; 32],
    pub primitive: &'a str,
    pub capability_name: &'a str,
    pub constraints: &'a Value,
    pub application_id: &'a str,
    pub quota: &'a Value,
    pub data_grant_ids: &'a [Uuid],
    pub max_invocations_per_hour: i32,
    pub created_by: Uuid,
    pub lifetime_seconds: i64,
}

impl Database {
    pub async fn mcp_create_managed_template(
        &self,
        input: &NewMcpManagedTemplate<'_>,
    ) -> Result<McpManagedTemplateRecord, DatabaseError> {
        if input.display_name.is_empty()
            || input.description.len() > 1000
            || !matches!(input.transport, "streamable_http" | "stdio_catalog")
            || !input.policy.is_object()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query("INSERT INTO filebelt_mcp.managed_templates (tenant_id,id,display_name,description,transport,endpoint_uri,trust_profile,catalog_entry,policy,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *,created_at::text AS created_at_text,updated_at::text AS updated_at_text")
            .bind(input.tenant_id)
            .bind(input.id)
            .bind(input.display_name)
            .bind(input.description)
            .bind(input.transport)
            .bind(input.endpoint_uri)
            .bind(input.trust_profile)
            .bind(input.catalog_entry)
            .bind(input.policy)
            .bind(input.created_by)
            .fetch_one(&self.pool)
            .await?;
        Ok(template_from_row(&row))
    }

    pub async fn mcp_managed_templates(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<McpManagedTemplateRecord>, DatabaseError> {
        Ok(sqlx::query("SELECT *,created_at::text AS created_at_text,updated_at::text AS updated_at_text FROM filebelt_mcp.managed_templates WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY display_name,id")
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(template_from_row)
            .collect())
    }

    pub async fn mcp_assign_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        subject_principal_id: Uuid,
        subject_kind: &str,
        created_by: Uuid,
    ) -> Result<(), DatabaseError> {
        if !matches!(subject_kind, "user" | "group" | "service") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query("INSERT INTO filebelt_mcp.template_assignments (tenant_id,template_id,subject_principal_id,subject_kind,created_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,template_id,subject_principal_id) DO UPDATE SET subject_kind=EXCLUDED.subject_kind,created_by=EXCLUDED.created_by,created_at=clock_timestamp(),revoked_at=NULL")
            .bind(tenant_id)
            .bind(template_id)
            .bind(subject_principal_id)
            .bind(subject_kind)
            .bind(created_by)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mcp_create_service_principal(
        &self,
        input: &NewMcpServicePrincipal<'_>,
    ) -> Result<McpServicePrincipalRecord, DatabaseError> {
        if input.display_name.is_empty()
            || input.display_name.len() > 255
            || !valid_spiffe_uri(input.spiffe_uri)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO public.principals (tenant_id,id,kind) VALUES ($1,$2,'service')")
            .bind(input.tenant_id)
            .bind(input.principal_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO filebelt_mcp.service_principals (tenant_id,id,principal_id,display_name,created_by) VALUES ($1,$2,$3,$4,$5)")
            .bind(input.tenant_id)
            .bind(input.service_id)
            .bind(input.principal_id)
            .bind(input.display_name)
            .bind(input.created_by)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO filebelt_mcp.service_identity_bindings (tenant_id,id,service_id,spiffe_uri) VALUES ($1,$2,$3,$4)")
            .bind(input.tenant_id)
            .bind(input.identity_binding_id)
            .bind(input.service_id)
            .bind(input.spiffe_uri)
            .execute(&mut *transaction)
            .await?;
        let row = service_row(&mut transaction, input.tenant_id, input.service_id).await?;
        transaction.commit().await?;
        Ok(service_from_row(&row))
    }

    pub async fn mcp_bind_service_identity(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        service_id: Uuid,
        spiffe_uri: &str,
    ) -> Result<(), DatabaseError> {
        if !valid_spiffe_uri(spiffe_uri) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query("INSERT INTO filebelt_mcp.service_identity_bindings (tenant_id,id,service_id,spiffe_uri) VALUES ($1,$2,$3,$4)")
            .bind(tenant_id)
            .bind(id)
            .bind(service_id)
            .bind(spiffe_uri)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mcp_replace_service_identity(
        &self,
        tenant_id: Uuid,
        service_id: Uuid,
        binding_id: Uuid,
        spiffe_uri: &str,
    ) -> Result<McpServicePrincipalRecord, DatabaseError> {
        if !valid_spiffe_uri(spiffe_uri) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("UPDATE filebelt_mcp.service_identity_bindings SET revoked_at=COALESCE(revoked_at,clock_timestamp()),generation=generation+1 WHERE tenant_id=$1 AND service_id=$2 AND revoked_at IS NULL")
            .bind(tenant_id)
            .bind(service_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO filebelt_mcp.service_identity_bindings (tenant_id,id,service_id,spiffe_uri) VALUES ($1,$2,$3,$4)")
            .bind(tenant_id)
            .bind(binding_id)
            .bind(service_id)
            .bind(spiffe_uri)
            .execute(&mut *transaction)
            .await?;
        let affected = sqlx::query("UPDATE filebelt_mcp.service_principals SET revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status<>'deleted'")
            .bind(tenant_id)
            .bind(service_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        if affected != 1 {
            return Err(DatabaseError::NotFound);
        }
        let row = service_row(&mut transaction, tenant_id, service_id).await?;
        transaction.commit().await?;
        Ok(service_from_row(&row))
    }

    pub async fn mcp_create_service_grant(
        &self,
        input: &NewMcpServiceGrant<'_>,
    ) -> Result<(), DatabaseError> {
        if !(1..=2_592_000).contains(&input.lifetime_seconds)
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
        insert_service_grant(&mut transaction, input).await?;
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mcp_review_capability(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
        snapshot_id: Uuid,
        fingerprint: &[u8; 32],
        reviewer_principal_id: Uuid,
        decision: &str,
        constraints: &Value,
    ) -> Result<(), DatabaseError> {
        if !matches!(decision, "approved" | "denied") || !constraints.is_object() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let affected = sqlx::query("INSERT INTO filebelt_mcp.capability_reviews (tenant_id,registration_id,snapshot_id,capability_fingerprint,reviewer_principal_id,decision,constraints) SELECT $1,$2,$3,$4,$5,$6,$7 FROM filebelt_mcp.capability_snapshots s JOIN filebelt_mcp.registrations r ON r.tenant_id=s.tenant_id AND r.id=s.registration_id AND r.credential_generation=s.credential_generation WHERE s.tenant_id=$1 AND s.id=$3 AND s.registration_id=$2 AND s.superseded_at IS NULL ON CONFLICT (tenant_id,snapshot_id,capability_fingerprint) DO UPDATE SET reviewer_principal_id=EXCLUDED.reviewer_principal_id,decision=EXCLUDED.decision,constraints=EXCLUDED.constraints,reviewed_at=clock_timestamp(),revoked_at=NULL")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(snapshot_id)
            .bind(fingerprint.as_slice())
            .bind(reviewer_principal_id)
            .bind(decision)
            .bind(constraints)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(DatabaseError::StaleGeneration)
        }
    }
}

pub(super) async fn insert_service_grant(
    transaction: &mut Transaction<'_, Postgres>,
    input: &NewMcpServiceGrant<'_>,
) -> Result<(), DatabaseError> {
    let created = sqlx::query("INSERT INTO filebelt_mcp.service_invocation_grants (tenant_id,id,service_id,registration_id,capability_fingerprint,primitive,capability_name,constraints,application_id,quota,max_invocations_per_hour,created_by,created_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,statement_timestamp(),statement_timestamp()+make_interval(secs=>$13) FROM filebelt_mcp.service_principals s JOIN filebelt_mcp.registrations r ON r.tenant_id=s.tenant_id AND r.owner_principal_id=s.principal_id AND r.id=$4 WHERE s.tenant_id=$1 AND s.id=$3 AND s.status='active' AND s.revocation_generation=$14 AND r.revoked_at IS NULL AND r.deleted_at IS NULL")
        .bind(input.tenant_id)
        .bind(input.id)
        .bind(input.service_id)
        .bind(input.registration_id)
        .bind(input.capability_fingerprint.as_slice())
        .bind(input.primitive)
        .bind(input.capability_name)
        .bind(input.constraints)
        .bind(input.application_id)
        .bind(input.quota)
        .bind(input.max_invocations_per_hour)
        .bind(input.created_by)
        .bind(input.lifetime_seconds)
        .bind(input.expected_service_generation)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
    if created != 1 {
        return Err(DatabaseError::NotFound);
    }
    for data_grant_id in input.data_grant_ids {
        let inserted = sqlx::query("INSERT INTO filebelt_mcp.service_grant_data_grants (tenant_id,service_grant_id,data_grant_id) SELECT $1,$2,g.id FROM filebelt_mcp.data_grants g JOIN filebelt_mcp.service_invocation_grants sg ON sg.tenant_id=g.tenant_id AND sg.id=$2 AND sg.registration_id=g.registration_id JOIN filebelt_mcp.service_principals s ON s.tenant_id=g.tenant_id AND s.id=$4 AND s.principal_id=g.principal_id WHERE g.tenant_id=$1 AND g.id=$3 AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp()")
            .bind(input.tenant_id)
            .bind(input.id)
            .bind(data_grant_id)
            .bind(input.service_id)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        if inserted != 1 {
            return Err(DatabaseError::NotFound);
        }
    }
    Ok(())
}

pub(super) fn template_from_row(row: &sqlx::postgres::PgRow) -> McpManagedTemplateRecord {
    McpManagedTemplateRecord {
        tenant_id: row.get("tenant_id"),
        id: row.get("id"),
        display_name: row.get("display_name"),
        description: row.get("description"),
        transport: row.get("transport"),
        endpoint_uri: row.get("endpoint_uri"),
        trust_profile: row.get("trust_profile"),
        catalog_entry: row.get("catalog_entry"),
        enabled: row.get("enabled"),
        policy: row.get("policy"),
        revision: row.get("revision"),
        revocation_generation: row.get("revocation_generation"),
        created_at: row.get("created_at_text"),
        updated_at: row.get("updated_at_text"),
    }
}

pub(super) fn valid_spiffe_uri(value: &str) -> bool {
    value.starts_with("spiffe://") && value.len() <= 2048 && !value.chars().any(char::is_whitespace)
}

pub(super) async fn service_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    service_id: Uuid,
) -> Result<sqlx::postgres::PgRow, DatabaseError> {
    sqlx::query("SELECT s.*,b.spiffe_uri,s.created_at::text AS created_at_text,s.updated_at::text AS updated_at_text FROM filebelt_mcp.service_principals s JOIN filebelt_mcp.service_identity_bindings b ON b.tenant_id=s.tenant_id AND b.service_id=s.id AND b.revoked_at IS NULL WHERE s.tenant_id=$1 AND s.id=$2")
        .bind(tenant_id)
        .bind(service_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(DatabaseError::from)
}

pub(super) fn service_from_row(row: &sqlx::postgres::PgRow) -> McpServicePrincipalRecord {
    McpServicePrincipalRecord {
        tenant_id: row.get("tenant_id"),
        service_id: row.get("id"),
        principal_id: row.get("principal_id"),
        display_name: row.get("display_name"),
        spiffe_uri: row.get("spiffe_uri"),
        status: row.get("status"),
        revocation_generation: row.get("revocation_generation"),
        created_at: row.get("created_at_text"),
        updated_at: row.get("updated_at_text"),
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Read/update/revoke operations for MCP administration and invocation policy.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{
    Database, DatabaseError, McpManagedTemplateRecord, McpRegistrationRecord,
    McpServicePrincipalRecord, registration_from_row,
};

#[derive(Clone, Debug)]
pub struct RegistrationConfigurationUpdate<'a> {
    pub tenant_id: Uuid,
    pub registration_id: Uuid,
    pub owner_principal_id: Uuid,
    pub expected_revision: i64,
    pub display_name: &'a str,
    pub description: &'a str,
    pub endpoint_uri: Option<&'a str>,
    pub trust_profile: Option<&'a str>,
    pub catalog_entry: Option<&'a str>,
    pub policy: &'a Value,
}

#[derive(Clone, Debug)]
pub struct TemplateConfigurationUpdate<'a> {
    pub tenant_id: Uuid,
    pub template_id: Uuid,
    pub expected_revision: i64,
    pub display_name: &'a str,
    pub description: &'a str,
    pub endpoint_uri: Option<&'a str>,
    pub trust_profile: Option<&'a str>,
    pub catalog_entry: Option<&'a str>,
    pub policy: &'a Value,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpCapabilitySnapshotRecord {
    pub id: Uuid,
    pub registration_id: Uuid,
    pub credential_generation: i64,
    pub fingerprint: Vec<u8>,
    pub protocol_version: String,
    pub document: Value,
    pub discovered_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpCapabilityRecord {
    pub primitive: String,
    pub name: String,
    pub fingerprint: Vec<u8>,
    pub read_only_hint: Option<bool>,
    pub descriptor: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpCapabilityReviewRecord {
    pub snapshot_id: Uuid,
    pub capability_fingerprint: Vec<u8>,
    pub reviewer_principal_id: Uuid,
    pub decision: String,
    pub constraints: Value,
    pub reviewed_at: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpApprovalRuleRecord {
    pub id: Uuid,
    pub registration_id: Uuid,
    pub application_id: String,
    pub primitive: String,
    pub capability_name: String,
    pub capability_fingerprint: Vec<u8>,
    pub argument_digest: Vec<u8>,
    pub attachment_digest: Vec<u8>,
    pub single_use: bool,
    pub consumed: bool,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpDataGrantRecord {
    pub id: Uuid,
    pub principal_id: Uuid,
    pub registration_id: Uuid,
    pub drive_id: Uuid,
    pub resource_id: Uuid,
    pub version_id: Uuid,
    pub allow_metadata: bool,
    pub allow_content: bool,
    pub acl_generation: i64,
    pub namespace_generation: i64,
    pub registration_generation: i64,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServiceGrantRecord {
    pub id: Uuid,
    pub service_id: Uuid,
    pub registration_id: Uuid,
    pub capability_fingerprint: Vec<u8>,
    pub primitive: String,
    pub capability_name: String,
    pub constraints: Value,
    pub application_id: String,
    pub quota: Value,
    pub data_grant_ids: Vec<Uuid>,
    pub max_invocations_per_hour: i32,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpAdminBlockRuleRecord {
    pub id: Uuid,
    pub scope: String,
    pub matcher: String,
    pub reason_code: String,
    pub enabled: bool,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpTemplateAssignmentRecord {
    pub template_id: Uuid,
    pub principal_id: Uuid,
    pub principal_kind: String,
    pub created_at: String,
}

impl Database {
    pub async fn mcp_registration_by_id(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        let row = sqlx::query("SELECT *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL")
            .bind(tenant_id)
            .bind(registration_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        registration_from_row(&row)
    }

    pub async fn mcp_delete_registration(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
        expected_revision: i64,
        tombstone_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query("UPDATE filebelt_mcp.registrations SET enabled=false,revoked_at=COALESCE(revoked_at,clock_timestamp()),deleted_at=clock_timestamp(),revocation_generation=revocation_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL RETURNING owner_principal_id,revocation_generation")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(expected_revision)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        sqlx::query("INSERT INTO filebelt_mcp.deletion_tombstones (tenant_id,id,object_kind,object_id,owner_principal_id,revocation_generation,remote_revocation_deadline) VALUES ($1,$2,'registration',$3,$4,$5,clock_timestamp()+interval '15 minutes')")
            .bind(tenant_id)
            .bind(tombstone_id)
            .bind(registration_id)
            .bind(row.get::<Uuid, _>("owner_principal_id"))
            .bind(row.get::<i64, _>("revocation_generation"))
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mcp_current_capability_snapshot(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
    ) -> Result<McpCapabilitySnapshotRecord, DatabaseError> {
        let row = sqlx::query("SELECT s.id,s.registration_id,s.credential_generation,s.fingerprint,s.protocol_version,s.document,s.discovered_at::text AS discovered_at FROM filebelt_mcp.capability_snapshots s JOIN filebelt_mcp.registrations r ON r.tenant_id=s.tenant_id AND r.id=s.registration_id AND r.credential_generation=s.credential_generation WHERE s.tenant_id=$1 AND s.registration_id=$2 AND s.superseded_at IS NULL")
            .bind(tenant_id)
            .bind(registration_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(snapshot_from_row(&row))
    }

    pub async fn mcp_capability_reviews(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
    ) -> Result<Vec<McpCapabilityReviewRecord>, DatabaseError> {
        Ok(sqlx::query("SELECT cr.snapshot_id,cr.capability_fingerprint,cr.reviewer_principal_id,cr.decision,cr.constraints,cr.reviewed_at::text AS reviewed_at,cr.revoked_at IS NOT NULL AS revoked FROM filebelt_mcp.capability_reviews cr JOIN filebelt_mcp.capability_snapshots s ON s.tenant_id=cr.tenant_id AND s.id=cr.snapshot_id AND s.registration_id=cr.registration_id JOIN filebelt_mcp.registrations r ON r.tenant_id=s.tenant_id AND r.id=s.registration_id AND r.credential_generation=s.credential_generation WHERE cr.tenant_id=$1 AND cr.registration_id=$2 AND s.superseded_at IS NULL ORDER BY cr.reviewed_at,cr.capability_fingerprint")
            .bind(tenant_id)
            .bind(registration_id)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(review_from_row)
            .collect())
    }

    pub async fn mcp_capability_by_fingerprint(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
        fingerprint: &[u8; 32],
    ) -> Result<McpCapabilityRecord, DatabaseError> {
        let row = sqlx::query("SELECT c.primitive,c.name,c.fingerprint,c.read_only_hint,c.descriptor FROM filebelt_mcp.capabilities c JOIN filebelt_mcp.capability_snapshots s ON s.tenant_id=c.tenant_id AND s.id=c.snapshot_id JOIN filebelt_mcp.registrations r ON r.tenant_id=s.tenant_id AND r.id=s.registration_id AND r.credential_generation=s.credential_generation WHERE c.tenant_id=$1 AND s.registration_id=$2 AND c.fingerprint=$3 AND s.superseded_at IS NULL")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(fingerprint.as_slice())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(McpCapabilityRecord {
            primitive: row.get("primitive"),
            name: row.get("name"),
            fingerprint: row.get("fingerprint"),
            read_only_hint: row.get("read_only_hint"),
            descriptor: row.get("descriptor"),
        })
    }

    pub async fn mcp_approval_rules(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        registration_id: Option<Uuid>,
    ) -> Result<Vec<McpApprovalRuleRecord>, DatabaseError> {
        Ok(sqlx::query("SELECT id,registration_id,application_id,primitive,capability_name,capability_fingerprint,argument_digest,attachment_digest,single_use,consumed_at IS NOT NULL AS consumed,created_at::text AS created_at,expires_at::text AS expires_at,revoked_at IS NOT NULL AS revoked FROM filebelt_mcp.approval_rules WHERE tenant_id=$1 AND principal_id=$2 AND ($3::uuid IS NULL OR registration_id=$3) ORDER BY created_at DESC,id LIMIT 200")
            .bind(tenant_id)
            .bind(principal_id)
            .bind(registration_id)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(approval_from_row)
            .collect())
    }

    pub async fn mcp_revoke_approval_rule(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        approval_id: Uuid,
    ) -> Result<(), DatabaseError> {
        update_one(sqlx::query("UPDATE filebelt_mcp.approval_rules SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND principal_id=$2 AND id=$3")
            .bind(tenant_id).bind(principal_id).bind(approval_id).execute(&self.pool).await?.rows_affected())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mcp_consume_matching_approval(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
        principal_id: Uuid,
        session_id: Option<Uuid>,
        application_id: &str,
        primitive: &str,
        capability_name: &str,
        capability_fingerprint: &[u8; 32],
        argument_digest: &[u8; 32],
        attachment_digest: &[u8; 32],
    ) -> Result<Uuid, DatabaseError> {
        if !matches!(primitive, "resource_read" | "prompt_get" | "tool_call") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar("WITH candidate AS (SELECT id FROM filebelt_mcp.approval_rules WHERE tenant_id=$1 AND registration_id=$2 AND principal_id=$3 AND session_id IS NOT DISTINCT FROM $4 AND application_id=$5 AND primitive=$6 AND capability_name=$7 AND capability_fingerprint=$8 AND argument_digest=$9 AND attachment_digest=$10 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at>clock_timestamp() ORDER BY expires_at,id LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE filebelt_mcp.approval_rules a SET consumed_at=CASE WHEN a.single_use THEN clock_timestamp() ELSE a.consumed_at END FROM candidate c WHERE a.tenant_id=$1 AND a.id=c.id RETURNING a.id")
            .bind(tenant_id).bind(registration_id).bind(principal_id).bind(session_id)
            .bind(application_id).bind(primitive).bind(capability_name)
            .bind(capability_fingerprint.as_slice()).bind(argument_digest.as_slice())
            .bind(attachment_digest.as_slice()).fetch_optional(&self.pool).await?
            .ok_or(DatabaseError::NotFound)
    }

    pub async fn mcp_data_grants(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
    ) -> Result<Vec<McpDataGrantRecord>, DatabaseError> {
        Ok(sqlx::query("SELECT id,principal_id,registration_id,drive_id,resource_id,version_id,allow_metadata,allow_content,acl_generation,namespace_generation,registration_generation,created_at::text AS created_at,expires_at::text AS expires_at,revoked_at IS NOT NULL AS revoked FROM filebelt_mcp.data_grants WHERE tenant_id=$1 AND principal_id=$2 AND drive_id=$3 AND resource_id=$4 ORDER BY created_at DESC,id LIMIT 200")
            .bind(tenant_id).bind(principal_id).bind(drive_id).bind(resource_id)
            .fetch_all(&self.pool).await?.iter().map(data_grant_from_row).collect())
    }

    pub async fn mcp_node_data_grants(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
    ) -> Result<Vec<McpDataGrantRecord>, DatabaseError> {
        Ok(sqlx::query("SELECT id,principal_id,registration_id,drive_id,resource_id,version_id,allow_metadata,allow_content,acl_generation,namespace_generation,registration_generation,created_at::text AS created_at,expires_at::text AS expires_at,revoked_at IS NOT NULL AS revoked FROM filebelt_mcp.data_grants WHERE tenant_id=$1 AND drive_id=$2 AND resource_id=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY created_at DESC,id LIMIT 200")
            .bind(tenant_id).bind(drive_id).bind(resource_id)
            .fetch_all(&self.pool).await?.iter().map(data_grant_from_row).collect())
    }

    pub async fn mcp_revoke_data_grant(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        grant_id: Uuid,
    ) -> Result<(), DatabaseError> {
        update_one(sqlx::query("UPDATE filebelt_mcp.data_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND principal_id=$2 AND drive_id=$3 AND resource_id=$4 AND id=$5")
            .bind(tenant_id).bind(principal_id).bind(drive_id).bind(resource_id)
            .bind(grant_id).execute(&self.pool).await?.rows_affected())
    }

    pub async fn mcp_managed_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<McpManagedTemplateRecord, DatabaseError> {
        let row = sqlx::query("SELECT *,created_at::text AS created_at_text,updated_at::text AS updated_at_text FROM filebelt_mcp.managed_templates WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL")
            .bind(tenant_id).bind(template_id).fetch_optional(&self.pool).await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(template_from_row(&row))
    }

    pub async fn mcp_update_managed_template(
        &self,
        input: &TemplateConfigurationUpdate<'_>,
    ) -> Result<McpManagedTemplateRecord, DatabaseError> {
        if input.display_name.is_empty()
            || input.description.len() > 1000
            || !input.policy.is_object()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query("UPDATE filebelt_mcp.managed_templates SET display_name=$4,description=$5,endpoint_uri=$6,trust_profile=$7,catalog_entry=$8,policy=$9,enabled=$10,revision=revision+1,revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL RETURNING *,created_at::text AS created_at_text,updated_at::text AS updated_at_text")
            .bind(input.tenant_id).bind(input.template_id).bind(input.expected_revision)
            .bind(input.display_name).bind(input.description).bind(input.endpoint_uri).bind(input.trust_profile)
            .bind(input.catalog_entry).bind(input.policy).bind(input.enabled)
            .fetch_optional(&self.pool).await?.ok_or(DatabaseError::Conflict)?;
        Ok(template_from_row(&row))
    }

    pub async fn mcp_delete_managed_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        expected_revision: i64,
    ) -> Result<(), DatabaseError> {
        update_one(sqlx::query("UPDATE filebelt_mcp.managed_templates SET enabled=false,deleted_at=clock_timestamp(),revision=revision+1,revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL")
            .bind(tenant_id).bind(template_id).bind(expected_revision).execute(&self.pool).await?.rows_affected())
    }

    pub async fn mcp_revoke_template_assignment(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        subject_principal_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let affected = sqlx::query("UPDATE filebelt_mcp.template_assignments SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND template_id=$2 AND subject_principal_id=$3")
            .bind(tenant_id).bind(template_id).bind(subject_principal_id)
            .execute(&mut *transaction).await?.rows_affected();
        if affected != 1 {
            return Err(DatabaseError::NotFound);
        }
        sqlx::query("UPDATE filebelt_mcp.registrations SET enabled=false,revocation_generation=revocation_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND template_id=$2 AND owner_principal_id=$3 AND deleted_at IS NULL")
            .bind(tenant_id).bind(template_id).bind(subject_principal_id)
            .execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mcp_template_assignments(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<McpTemplateAssignmentRecord>, DatabaseError> {
        Ok(sqlx::query("SELECT template_id,subject_principal_id AS principal_id,subject_kind AS principal_kind,created_at::text AS created_at FROM filebelt_mcp.template_assignments WHERE tenant_id=$1 AND template_id=$2 AND revoked_at IS NULL ORDER BY created_at,subject_principal_id")
            .bind(tenant_id).bind(template_id).fetch_all(&self.pool).await?
            .iter().map(|row| McpTemplateAssignmentRecord { template_id: row.get("template_id"), principal_id: row.get("principal_id"), principal_kind: row.get("principal_kind"), created_at: row.get("created_at") }).collect())
    }

    pub async fn mcp_template_assignment_count(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i64, DatabaseError> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM filebelt_mcp.template_assignments WHERE tenant_id=$1 AND template_id=$2 AND revoked_at IS NULL")
            .bind(tenant_id).bind(template_id).fetch_one(&self.pool).await?)
    }

    pub async fn mcp_service_principals(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<McpServicePrincipalRecord>, DatabaseError> {
        Ok(sqlx::query("SELECT s.*,b.spiffe_uri,s.created_at::text AS created_at_text,s.updated_at::text AS updated_at_text FROM filebelt_mcp.service_principals s JOIN filebelt_mcp.service_identity_bindings b ON b.tenant_id=s.tenant_id AND b.service_id=s.id AND b.revoked_at IS NULL WHERE s.tenant_id=$1 AND s.status<>'deleted' ORDER BY s.display_name,s.id")
            .bind(tenant_id).fetch_all(&self.pool).await?.iter().map(service_from_row).collect())
    }

    pub async fn mcp_service_principal(
        &self,
        tenant_id: Uuid,
        service_id: Uuid,
    ) -> Result<McpServicePrincipalRecord, DatabaseError> {
        let row = sqlx::query("SELECT s.*,b.spiffe_uri,s.created_at::text AS created_at_text,s.updated_at::text AS updated_at_text FROM filebelt_mcp.service_principals s JOIN filebelt_mcp.service_identity_bindings b ON b.tenant_id=s.tenant_id AND b.service_id=s.id AND b.revoked_at IS NULL WHERE s.tenant_id=$1 AND s.id=$2 AND s.status<>'deleted'")
            .bind(tenant_id).bind(service_id).fetch_optional(&self.pool).await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(service_from_row(&row))
    }

    pub async fn mcp_update_service_principal(
        &self,
        tenant_id: Uuid,
        service_id: Uuid,
        display_name: &str,
        status: &str,
    ) -> Result<McpServicePrincipalRecord, DatabaseError> {
        if display_name.is_empty() || !matches!(status, "active" | "suspended") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let updated = sqlx::query("UPDATE filebelt_mcp.service_principals SET display_name=$3,status=$4,revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status<>'deleted'")
            .bind(tenant_id).bind(service_id).bind(display_name).bind(status)
            .execute(&self.pool).await?.rows_affected();
        if updated != 1 {
            return Err(DatabaseError::NotFound);
        }
        let row = sqlx::query("SELECT s.*,b.spiffe_uri,s.created_at::text AS created_at_text,s.updated_at::text AS updated_at_text FROM filebelt_mcp.service_principals s JOIN filebelt_mcp.service_identity_bindings b ON b.tenant_id=s.tenant_id AND b.service_id=s.id AND b.revoked_at IS NULL WHERE s.tenant_id=$1 AND s.id=$2 AND s.status<>'deleted'")
            .bind(tenant_id).bind(service_id).fetch_one(&self.pool).await?;
        Ok(service_from_row(&row))
    }

    pub async fn mcp_delete_service_principal(
        &self,
        tenant_id: Uuid,
        service_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("UPDATE filebelt_mcp.service_identity_bindings SET revoked_at=COALESCE(revoked_at,clock_timestamp()),generation=generation+1 WHERE tenant_id=$1 AND service_id=$2 AND revoked_at IS NULL")
            .bind(tenant_id).bind(service_id).execute(&mut *transaction).await?;
        let affected = sqlx::query("UPDATE filebelt_mcp.service_principals SET status='deleted',deleted_at=clock_timestamp(),revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status<>'deleted'")
            .bind(tenant_id).bind(service_id).execute(&mut *transaction).await?.rows_affected();
        if affected != 1 {
            return Err(DatabaseError::NotFound);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mcp_service_grants(
        &self,
        tenant_id: Uuid,
        service_id: Uuid,
    ) -> Result<Vec<McpServiceGrantRecord>, DatabaseError> {
        Ok(sqlx::query("SELECT g.id,g.service_id,g.registration_id,g.capability_fingerprint,g.primitive,g.capability_name,g.constraints,g.application_id,g.quota,g.max_invocations_per_hour,g.created_at::text AS created_at,g.expires_at::text AS expires_at,g.revoked_at IS NOT NULL AS revoked,COALESCE(array_agg(d.data_grant_id) FILTER (WHERE d.data_grant_id IS NOT NULL),'{}'::uuid[]) AS data_grant_ids FROM filebelt_mcp.service_invocation_grants g LEFT JOIN filebelt_mcp.service_grant_data_grants d ON d.tenant_id=g.tenant_id AND d.service_grant_id=g.id WHERE g.tenant_id=$1 AND g.service_id=$2 GROUP BY g.tenant_id,g.id ORDER BY g.created_at DESC,g.id LIMIT 200")
            .bind(tenant_id).bind(service_id).fetch_all(&self.pool).await?
            .iter().map(service_grant_from_row).collect())
    }

    pub async fn mcp_revoke_service_grant(
        &self,
        tenant_id: Uuid,
        service_id: Uuid,
        grant_id: Uuid,
    ) -> Result<(), DatabaseError> {
        update_one(sqlx::query("UPDATE filebelt_mcp.service_invocation_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND service_id=$2 AND id=$3")
            .bind(tenant_id).bind(service_id).bind(grant_id).execute(&self.pool).await?.rows_affected())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mcp_create_admin_block_rule(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        scope: &str,
        matcher: &str,
        reason_code: &str,
        created_by: Uuid,
    ) -> Result<McpAdminBlockRuleRecord, DatabaseError> {
        validate_block_rule(scope, matcher, reason_code)?;
        let mut transaction = self.pool.begin().await?;
        advance_admin_block_policy(&mut transaction, tenant_id).await?;
        let row = sqlx::query("INSERT INTO filebelt_mcp.admin_block_rules (tenant_id,id,scope,matcher,reason_code,created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,scope,matcher,reason_code,enabled,revision,created_at::text AS created_at,updated_at::text AS updated_at")
            .bind(tenant_id).bind(id).bind(scope).bind(matcher).bind(reason_code).bind(created_by)
            .fetch_one(&mut *transaction).await?;
        let record = block_rule_from_row(&row);
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn mcp_admin_block_rules(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<McpAdminBlockRuleRecord>, DatabaseError> {
        Ok(sqlx::query("SELECT id,scope,matcher,reason_code,enabled,revision,created_at::text AS created_at,updated_at::text AS updated_at FROM filebelt_mcp.admin_block_rules WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY scope,matcher,id")
            .bind(tenant_id).fetch_all(&self.pool).await?.iter().map(block_rule_from_row).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mcp_update_admin_block_rule(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_revision: i64,
        matcher: &str,
        reason_code: &str,
        enabled: bool,
    ) -> Result<McpAdminBlockRuleRecord, DatabaseError> {
        if matcher.is_empty() || reason_code.is_empty() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        advance_admin_block_policy(&mut transaction, tenant_id).await?;
        let row = sqlx::query("UPDATE filebelt_mcp.admin_block_rules SET matcher=$4,reason_code=$5,enabled=$6,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL RETURNING id,scope,matcher,reason_code,enabled,revision,created_at::text AS created_at,updated_at::text AS updated_at")
            .bind(tenant_id).bind(id).bind(expected_revision).bind(matcher).bind(reason_code).bind(enabled)
            .fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::Conflict)?;
        let record = block_rule_from_row(&row);
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn mcp_delete_admin_block_rule(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_revision: i64,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        advance_admin_block_policy(&mut transaction, tenant_id).await?;
        update_one(sqlx::query("UPDATE filebelt_mcp.admin_block_rules SET enabled=false,deleted_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL")
            .bind(tenant_id).bind(id).bind(expected_revision).execute(&mut *transaction).await?.rows_affected())?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mcp_delete_admin_block_rule_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        advance_admin_block_policy(&mut transaction, tenant_id).await?;
        update_one(sqlx::query("UPDATE filebelt_mcp.admin_block_rules SET enabled=false,deleted_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL")
            .bind(tenant_id).bind(id).execute(&mut *transaction).await?.rows_affected())?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mcp_cancel_invocation(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        invocation_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let state: String = sqlx::query_scalar("SELECT state FROM filebelt_mcp.invocations WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 FOR UPDATE")
            .bind(tenant_id)
            .bind(principal_id)
            .bind(invocation_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        if state == "cancelled" {
            transaction.commit().await?;
            return Ok(());
        }
        if !matches!(state.as_str(), "pending" | "running") {
            return Err(DatabaseError::Conflict);
        }
        sqlx::query("UPDATE filebelt_mcp.invocations SET state='cancelled',reason_code='mcp.cancelled_by_principal',finished_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND id=$3")
            .bind(tenant_id)
            .bind(principal_id)
            .bind(invocation_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}

pub(super) async fn advance_admin_block_policy(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
) -> Result<(), DatabaseError> {
    sqlx::query("INSERT INTO filebelt_mcp.policy_generations (tenant_id,admin_block_generation) VALUES ($1,2) ON CONFLICT (tenant_id) DO UPDATE SET admin_block_generation=filebelt_mcp.policy_generations.admin_block_generation+1,updated_at=clock_timestamp()")
        .bind(tenant_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("UPDATE filebelt_mcp.invocations SET state='cancelled',finished_at=clock_timestamp(),reason_code='mcp.admin_block_changed' WHERE tenant_id=$1 AND state IN ('pending','running')")
        .bind(tenant_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn update_one(affected: u64) -> Result<(), DatabaseError> {
    if affected == 1 {
        Ok(())
    } else {
        Err(DatabaseError::NotFound)
    }
}

pub(super) fn validate_block_rule(
    scope: &str,
    matcher: &str,
    reason: &str,
) -> Result<(), DatabaseError> {
    if !matches!(
        scope,
        "origin" | "trust_profile" | "catalog_entry" | "registration" | "capability"
    ) || matcher.is_empty()
        || matcher.len() > 2048
        || reason.is_empty()
    {
        Err(DatabaseError::InvalidPersistedValue)
    } else {
        Ok(())
    }
}

fn snapshot_from_row(row: &sqlx::postgres::PgRow) -> McpCapabilitySnapshotRecord {
    McpCapabilitySnapshotRecord {
        id: row.get("id"),
        registration_id: row.get("registration_id"),
        credential_generation: row.get("credential_generation"),
        fingerprint: row.get("fingerprint"),
        protocol_version: row.get("protocol_version"),
        document: row.get("document"),
        discovered_at: row.get("discovered_at"),
    }
}
fn review_from_row(row: &sqlx::postgres::PgRow) -> McpCapabilityReviewRecord {
    McpCapabilityReviewRecord {
        snapshot_id: row.get("snapshot_id"),
        capability_fingerprint: row.get("capability_fingerprint"),
        reviewer_principal_id: row.get("reviewer_principal_id"),
        decision: row.get("decision"),
        constraints: row.get("constraints"),
        reviewed_at: row.get("reviewed_at"),
        revoked: row.get("revoked"),
    }
}
fn approval_from_row(row: &sqlx::postgres::PgRow) -> McpApprovalRuleRecord {
    McpApprovalRuleRecord {
        id: row.get("id"),
        registration_id: row.get("registration_id"),
        application_id: row.get("application_id"),
        primitive: row.get("primitive"),
        capability_name: row.get("capability_name"),
        capability_fingerprint: row.get("capability_fingerprint"),
        argument_digest: row.get("argument_digest"),
        attachment_digest: row.get("attachment_digest"),
        single_use: row.get("single_use"),
        consumed: row.get("consumed"),
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
        revoked: row.get("revoked"),
    }
}
fn data_grant_from_row(row: &sqlx::postgres::PgRow) -> McpDataGrantRecord {
    McpDataGrantRecord {
        id: row.get("id"),
        principal_id: row.get("principal_id"),
        registration_id: row.get("registration_id"),
        drive_id: row.get("drive_id"),
        resource_id: row.get("resource_id"),
        version_id: row.get("version_id"),
        allow_metadata: row.get("allow_metadata"),
        allow_content: row.get("allow_content"),
        acl_generation: row.get("acl_generation"),
        namespace_generation: row.get("namespace_generation"),
        registration_generation: row.get("registration_generation"),
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
        revoked: row.get("revoked"),
    }
}
fn service_grant_from_row(row: &sqlx::postgres::PgRow) -> McpServiceGrantRecord {
    McpServiceGrantRecord {
        id: row.get("id"),
        service_id: row.get("service_id"),
        registration_id: row.get("registration_id"),
        capability_fingerprint: row.get("capability_fingerprint"),
        primitive: row.get("primitive"),
        capability_name: row.get("capability_name"),
        constraints: row.get("constraints"),
        application_id: row.get("application_id"),
        quota: row.get("quota"),
        data_grant_ids: row.get("data_grant_ids"),
        max_invocations_per_hour: row.get("max_invocations_per_hour"),
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
        revoked: row.get("revoked"),
    }
}
pub(super) fn block_rule_from_row(row: &sqlx::postgres::PgRow) -> McpAdminBlockRuleRecord {
    McpAdminBlockRuleRecord {
        id: row.get("id"),
        scope: row.get("scope"),
        matcher: row.get("matcher"),
        reason_code: row.get("reason_code"),
        enabled: row.get("enabled"),
        revision: row.get("revision"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn template_from_row(row: &sqlx::postgres::PgRow) -> McpManagedTemplateRecord {
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
fn service_from_row(row: &sqlx::postgres::PgRow) -> McpServicePrincipalRecord {
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

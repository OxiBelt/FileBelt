// SPDX-License-Identifier: Apache-2.0

//! Least-privilege PostgreSQL repository for MCP policy and encrypted secrets.

use filebelt_mcp_policy::{
    AuthenticationState, CapabilityState, QuarantineState, RegistrationPolicyState, ValidationState,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{Database, DatabaseError};

mod idempotency;
mod invocation;
mod management;
mod operations;
mod runner_slots;
pub use idempotency::{McpIdempotency, McpIdempotentWrite};
pub use invocation::{
    McpActivityRecord, McpInvocationIntentApprovalContext, McpOAuthAttemptSecret, McpRateDecision,
    McpRevocationGenerations, NewMcpApprovalRule, NewMcpInvocation, NewMcpOAuthAttempt,
};
pub use management::{
    McpAdminBlockRuleRecord, McpApprovalRuleRecord, McpCapabilityRecord, McpCapabilityReviewRecord,
    McpCapabilitySnapshotRecord, McpDataGrantRecord, McpServiceGrantRecord,
    McpTemplateAssignmentRecord, RegistrationConfigurationUpdate, TemplateConfigurationUpdate,
};
pub use operations::{
    McpManagedTemplateRecord, McpServicePrincipalRecord, NewMcpManagedTemplate, NewMcpServiceGrant,
    NewMcpServicePrincipal,
};
pub use runner_slots::{McpRunnerSlotReservation, NewMcpRunnerSlotReservation};

#[derive(Clone, Debug)]
pub struct NewMcpRegistration<'a> {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub owner_principal_id: Uuid,
    pub owner_kind: &'a str,
    pub source_kind: &'a str,
    pub template_id: Option<Uuid>,
    pub display_name: &'a str,
    pub description: &'a str,
    pub transport: &'a str,
    pub endpoint_uri: Option<&'a str>,
    pub trust_profile: Option<&'a str>,
    pub catalog_entry: Option<&'a str>,
    pub policy: &'a Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpRegistrationRecord {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub owner_principal_id: Uuid,
    pub owner_kind: String,
    pub source_kind: String,
    pub template_id: Option<Uuid>,
    pub display_name: String,
    pub description: String,
    pub transport: String,
    pub endpoint_uri: Option<String>,
    pub trust_profile: Option<String>,
    pub catalog_entry: Option<String>,
    pub state: RegistrationPolicyState,
    pub policy: Value,
    pub revision: i64,
    pub revocation_generation: i64,
    pub credential_generation: i64,
    pub credential_kind: String,
    pub protocol_version: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub struct NewCapabilitySnapshot<'a> {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub registration_id: Uuid,
    pub credential_generation: i64,
    pub fingerprint: &'a [u8; 32],
    pub protocol_version: &'a str,
    pub document: &'a Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpSecretEnvelope {
    pub tenant_id: Uuid,
    pub registration_id: Uuid,
    pub owner_principal_id: Uuid,
    pub issuer: String,
    pub secret_kind: String,
    pub credential_generation: i64,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: Vec<u8>,
    pub kek_generation: i32,
    pub aad_version: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpCredentialMetadata {
    pub registration_id: Uuid,
    pub owner_principal_id: Uuid,
    pub issuer: String,
    pub secret_kind: String,
    pub credential_generation: i64,
    pub kek_generation: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpAttachmentMetadata {
    pub basename: String,
    pub media_type: String,
}

#[derive(Clone, Debug)]
pub struct NewMcpDataGrant {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub principal_id: Uuid,
    pub registration_id: Uuid,
    pub drive_id: Uuid,
    pub resource_id: Uuid,
    pub version_id: Uuid,
    pub allow_metadata: bool,
    pub allow_content: bool,
    pub drive_acl_generation: i64,
    pub acl_generation: i64,
    pub namespace_generation: i64,
    pub created_by: Uuid,
    pub lifetime_seconds: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpAuthoritySnapshot {
    pub principal_generation: i64,
    pub registration_generation: i64,
    pub drive_acl_generation: i64,
    pub acl_generation: i64,
    pub namespace_generation: i64,
    pub allow_metadata: bool,
    pub allow_content: bool,
}

impl Database {
    pub async fn mcp_create_registration(
        &self,
        input: &NewMcpRegistration<'_>,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        if !matches!(input.owner_kind, "user" | "service")
            || !matches!(input.source_kind, "personal" | "managed")
            || !matches!(input.transport, "streamable_http" | "stdio_catalog")
            || input.display_name.is_empty()
            || input.display_name.len() > 255
            || input.description.len() > 1000
            || !input.policy.is_object()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "INSERT INTO filebelt_mcp.registrations (tenant_id,id,owner_principal_id,owner_kind,source_kind,template_id,display_name,description,transport,endpoint_uri,trust_profile,catalog_entry,policy) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text",
        )
        .bind(input.tenant_id)
        .bind(input.id)
        .bind(input.owner_principal_id)
        .bind(input.owner_kind)
        .bind(input.source_kind)
        .bind(input.template_id)
        .bind(input.display_name)
        .bind(input.description)
        .bind(input.transport)
        .bind(input.endpoint_uri)
        .bind(input.trust_profile)
        .bind(input.catalog_entry)
        .bind(input.policy)
        .fetch_one(&self.pool)
        .await?;
        registration_from_row(&row)
    }

    pub async fn mcp_registration(
        &self,
        tenant_id: Uuid,
        owner_principal_id: Uuid,
        registration_id: Uuid,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        let row = sqlx::query("SELECT *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND owner_principal_id=$2 AND id=$3 AND deleted_at IS NULL")
            .bind(tenant_id)
            .bind(owner_principal_id)
            .bind(registration_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        registration_from_row(&row)
    }

    pub async fn mcp_list_registrations(
        &self,
        tenant_id: Uuid,
        owner_principal_id: Uuid,
        limit: i64,
    ) -> Result<Vec<McpRegistrationRecord>, DatabaseError> {
        if !(1..=200).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query("SELECT *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND owner_principal_id=$2 AND deleted_at IS NULL ORDER BY updated_at DESC,id LIMIT $3")
            .bind(tenant_id)
            .bind(owner_principal_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(registration_from_row)
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mcp_update_registration_state(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
        expected_revision: i64,
        state: RegistrationPolicyState,
        protocol_version: Option<&str>,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        if state.enabled {
            state
                .can_enable()
                .map_err(|_| DatabaseError::InvalidPersistedValue)?;
        }
        let row = sqlx::query("UPDATE filebelt_mcp.registrations SET validation_state=$4,authentication_state=$5,capability_state=$6,quarantine_state=$7,enabled=$8,protocol_version=$9,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL RETURNING *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(expected_revision)
            .bind(validation_text(state.validation))
            .bind(authentication_text(state.authentication))
            .bind(capability_text(state.capabilities))
            .bind(quarantine_text(state.quarantine))
            .bind(state.enabled)
            .bind(protocol_version)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        registration_from_row(&row)
    }

    pub async fn mcp_revoke_registration(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
        expected_revision: i64,
    ) -> Result<i64, DatabaseError> {
        sqlx::query_scalar("UPDATE filebelt_mcp.registrations SET enabled=false,revoked_at=COALESCE(revoked_at,clock_timestamp()),revocation_generation=revocation_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL RETURNING revocation_generation")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(expected_revision)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::Conflict)
    }

    pub async fn mcp_store_capability_snapshot(
        &self,
        input: &NewCapabilitySnapshot<'_>,
    ) -> Result<bool, DatabaseError> {
        if !input.document.is_object() || input.protocol_version.is_empty() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let credential_generation: i64 = sqlx::query_scalar("SELECT credential_generation FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL AND deleted_at IS NULL FOR UPDATE")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        if credential_generation != input.credential_generation {
            return Err(DatabaseError::StaleGeneration);
        }
        let current = sqlx::query("SELECT fingerprint,credential_generation FROM filebelt_mcp.capability_snapshots WHERE tenant_id=$1 AND registration_id=$2 AND superseded_at IS NULL FOR UPDATE")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .fetch_optional(&mut *transaction)
            .await?;
        if current.as_ref().is_some_and(|row| {
            row.get::<i64, _>("credential_generation") == input.credential_generation
                && row.get::<Vec<u8>, _>("fingerprint").as_slice() == input.fingerprint
        }) {
            transaction.commit().await?;
            return Ok(false);
        }
        sqlx::query("UPDATE filebelt_mcp.capability_snapshots SET superseded_at=clock_timestamp() WHERE tenant_id=$1 AND registration_id=$2 AND superseded_at IS NULL")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO filebelt_mcp.capability_snapshots (tenant_id,id,registration_id,credential_generation,fingerprint,protocol_version,document) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(input.tenant_id)
            .bind(input.id)
            .bind(input.registration_id)
            .bind(input.credential_generation)
            .bind(input.fingerprint.as_slice())
            .bind(input.protocol_version)
            .bind(input.document)
            .execute(&mut *transaction)
            .await?;
        for (primitive, values) in [
            ("tool_call", "tools"),
            ("resource_read", "resources"),
            ("prompt_get", "prompts"),
        ] {
            let descriptors = input
                .document
                .get(values)
                .and_then(|value| value.get(values))
                .and_then(Value::as_array)
                .ok_or(DatabaseError::InvalidPersistedValue)?;
            for descriptor in descriptors {
                let name = descriptor
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty() && name.len() <= 255)
                    .ok_or(DatabaseError::InvalidPersistedValue)?;
                let read_only_hint = descriptor
                    .pointer("/annotations/readOnlyHint")
                    .and_then(Value::as_bool);
                if primitive == "tool_call" && read_only_hint != Some(true) {
                    return Err(DatabaseError::InvalidPersistedValue);
                }
                let fingerprint =
                    filebelt_mcp_policy::policy_json_digest(b"capability", descriptor)
                        .map_err(|_| DatabaseError::InvalidPersistedValue)?;
                sqlx::query("INSERT INTO filebelt_mcp.capabilities (tenant_id,snapshot_id,fingerprint,primitive,name,read_only_hint,descriptor) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                    .bind(input.tenant_id)
                    .bind(input.id)
                    .bind(fingerprint.as_slice())
                    .bind(primitive)
                    .bind(name)
                    .bind(read_only_hint)
                    .bind(descriptor)
                    .execute(&mut *transaction)
                    .await?;
            }
        }
        let state = if current.is_some() {
            "drifted"
        } else {
            "pending_review"
        };
        sqlx::query("UPDATE filebelt_mcp.registrations SET capability_state=$3,enabled=false,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .bind(state)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn mcp_replace_registration_secret(
        &self,
        envelope: &McpSecretEnvelope,
    ) -> Result<McpCredentialMetadata, DatabaseError> {
        validate_secret_envelope(envelope)?;
        let mut transaction = self.pool.begin().await?;
        let current_generation: i64 = sqlx::query_scalar("SELECT credential_generation FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND revoked_at IS NULL AND deleted_at IS NULL FOR UPDATE")
            .bind(envelope.tenant_id)
            .bind(envelope.registration_id)
            .bind(envelope.owner_principal_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        if current_generation.checked_add(1) != Some(envelope.credential_generation) {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query("DELETE FROM filebelt_mcp.oauth_attempts WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3")
            .bind(envelope.tenant_id)
            .bind(envelope.registration_id)
            .bind(envelope.owner_principal_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM filebelt_mcp_vault.secret_envelopes WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3")
            .bind(envelope.tenant_id)
            .bind(envelope.registration_id)
            .bind(envelope.owner_principal_id)
            .execute(&mut *transaction)
            .await?;
        let row = sqlx::query("INSERT INTO filebelt_mcp_vault.secret_envelopes (tenant_id,registration_id,owner_principal_id,issuer,secret_kind,credential_generation,ciphertext,nonce,wrapped_dek,wrap_nonce,kek_generation,aad_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (tenant_id,registration_id,owner_principal_id,issuer,secret_kind) DO UPDATE SET credential_generation=EXCLUDED.credential_generation,ciphertext=EXCLUDED.ciphertext,nonce=EXCLUDED.nonce,wrapped_dek=EXCLUDED.wrapped_dek,wrap_nonce=EXCLUDED.wrap_nonce,kek_generation=EXCLUDED.kek_generation,aad_version=EXCLUDED.aad_version,updated_at=clock_timestamp(),deleted_at=NULL WHERE filebelt_mcp_vault.secret_envelopes.credential_generation < EXCLUDED.credential_generation RETURNING registration_id,owner_principal_id,issuer,secret_kind,credential_generation,kek_generation,created_at::text AS created_at,updated_at::text AS updated_at")
            .bind(envelope.tenant_id)
            .bind(envelope.registration_id)
            .bind(envelope.owner_principal_id)
            .bind(&envelope.issuer)
            .bind(&envelope.secret_kind)
            .bind(envelope.credential_generation)
            .bind(&envelope.ciphertext)
            .bind(&envelope.nonce)
            .bind(&envelope.wrapped_dek)
            .bind(&envelope.wrap_nonce)
            .bind(envelope.kek_generation)
            .bind(envelope.aad_version)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::StaleGeneration)?;
        let public_kind = match envelope.secret_kind.as_str() {
            "oauth_client" | "oauth_access" | "oauth_refresh" => "oauth",
            kind => kind,
        };
        let advanced = sqlx::query("UPDATE filebelt_mcp.registrations SET enabled=false,authentication_state='authorized',capability_state='undiscovered',protocol_version=NULL,credential_generation=$4,credential_kind=$5,revocation_generation=revocation_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND credential_generation=$4-1")
            .bind(envelope.tenant_id)
            .bind(envelope.registration_id)
            .bind(envelope.owner_principal_id)
            .bind(envelope.credential_generation)
            .bind(public_kind)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        if advanced != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        let metadata = credential_metadata_from_row(&row);
        transaction.commit().await?;
        Ok(metadata)
    }

    pub async fn mcp_secret_envelope(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
        owner_principal_id: Uuid,
        issuer: &str,
        secret_kind: &str,
    ) -> Result<McpSecretEnvelope, DatabaseError> {
        let row = sqlx::query("SELECT * FROM filebelt_mcp_vault.secret_envelopes WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3 AND issuer=$4 AND secret_kind=$5 AND deleted_at IS NULL")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(owner_principal_id)
            .bind(issuer)
            .bind(secret_kind)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(secret_from_row(&row))
    }

    pub async fn mcp_secret_metadata(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
        owner_principal_id: Uuid,
    ) -> Result<Vec<McpCredentialMetadata>, DatabaseError> {
        Ok(sqlx::query("SELECT registration_id,owner_principal_id,issuer,secret_kind,credential_generation,kek_generation,created_at::text AS created_at,updated_at::text AS updated_at FROM filebelt_mcp_vault.secret_envelopes WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3 AND deleted_at IS NULL ORDER BY issuer,secret_kind")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(owner_principal_id)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(credential_metadata_from_row)
            .collect())
    }

    pub async fn mcp_replace_registration_configuration_and_erase(
        &self,
        input: &RegistrationConfigurationUpdate<'_>,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        if input.display_name.is_empty()
            || input.display_name.len() > 255
            || input.description.len() > 1000
            || !input.policy.is_object()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT filebelt_mcp.replace_registration_configuration_and_erase($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .bind(input.owner_principal_id)
            .bind(input.expected_revision)
            .bind(input.display_name)
            .bind(input.description)
            .bind(input.endpoint_uri)
            .bind(input.trust_profile)
            .bind(input.catalog_entry)
            .bind(input.policy)
            .execute(&mut *transaction)
            .await?;
        let row = sqlx::query("SELECT *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND deleted_at IS NULL")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .bind(input.owner_principal_id)
            .fetch_one(&mut *transaction)
            .await?;
        let registration = registration_from_row(&row)?;
        transaction.commit().await?;
        Ok(registration)
    }

    pub async fn mcp_cryptographically_erase_registration_at_revision(
        &self,
        tenant_id: Uuid,
        registration_id: Uuid,
        owner_principal_id: Uuid,
        expected_revision: i64,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query_scalar::<_, i64>("SELECT credential_generation FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND revision=$4 AND deleted_at IS NULL FOR UPDATE")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(owner_principal_id)
            .bind(expected_revision)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        sqlx::query("DELETE FROM filebelt_mcp.oauth_attempts WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(owner_principal_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM filebelt_mcp_vault.secret_envelopes WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(owner_principal_id)
            .execute(&mut *transaction)
            .await?;
        let row = sqlx::query("UPDATE filebelt_mcp.registrations SET enabled=false,authentication_state='required',capability_state='undiscovered',protocol_version=NULL,credential_kind='none',revocation_generation=revocation_generation+1,credential_generation=credential_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND revision=$4 RETURNING *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text")
            .bind(tenant_id)
            .bind(registration_id)
            .bind(owner_principal_id)
            .bind(expected_revision)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        let registration = registration_from_row(&row)?;
        transaction.commit().await?;
        Ok(registration)
    }

    pub async fn mcp_create_data_grant(
        &self,
        input: &NewMcpDataGrant,
    ) -> Result<(), DatabaseError> {
        if !(1..=2_592_000).contains(&input.lifetime_seconds)
            || !(input.allow_metadata || input.allow_content)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        insert_data_grant(&mut transaction, input).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mcp_authority_snapshot(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        registration_id: Uuid,
        data_grant_id: Uuid,
    ) -> Result<McpAuthoritySnapshot, DatabaseError> {
        let row = sqlx::query("SELECT p.generation AS principal_generation,r.revocation_generation,d.acl_generation AS drive_acl_generation,n.acl_generation,n.namespace_generation,g.drive_acl_generation AS granted_drive_acl_generation,g.acl_generation AS granted_acl_generation,g.namespace_generation AS granted_namespace_generation,g.allow_metadata,g.allow_content FROM filebelt_mcp.data_grants g JOIN filebelt_mcp.registrations r ON r.tenant_id=g.tenant_id AND r.id=g.registration_id JOIN public.principals p ON p.tenant_id=g.tenant_id AND p.id=g.principal_id JOIN public.drives d ON d.tenant_id=g.tenant_id AND d.id=g.drive_id JOIN public.nodes n ON n.tenant_id=g.tenant_id AND n.drive_id=g.drive_id AND n.id=g.resource_id JOIN public.file_versions v ON v.tenant_id=g.tenant_id AND v.node_id=g.resource_id AND v.id=g.version_id WHERE g.tenant_id=$1 AND g.principal_id=$2 AND g.registration_id=$3 AND g.id=$4 AND g.registration_generation=r.revocation_generation AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp() AND r.enabled AND r.revoked_at IS NULL AND r.deleted_at IS NULL AND p.disabled_at IS NULL")
            .bind(tenant_id)
            .bind(principal_id)
            .bind(registration_id)
            .bind(data_grant_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        let granted_drive_acl: Option<i64> = row.get("granted_drive_acl_generation");
        let snapshot = McpAuthoritySnapshot {
            principal_generation: row.get("principal_generation"),
            registration_generation: row.get("revocation_generation"),
            drive_acl_generation: row.get("drive_acl_generation"),
            acl_generation: row.get("acl_generation"),
            namespace_generation: row.get("namespace_generation"),
            allow_metadata: row.get("allow_metadata"),
            allow_content: row.get("allow_content"),
        };
        let granted_acl: i64 = row.get("granted_acl_generation");
        let granted_namespace: i64 = row.get("granted_namespace_generation");
        if granted_drive_acl != Some(snapshot.drive_acl_generation)
            || snapshot.acl_generation != granted_acl
            || snapshot.namespace_generation != granted_namespace
        {
            return Err(DatabaseError::StaleGeneration);
        }
        Ok(snapshot)
    }

    pub async fn mcp_attachment_metadata(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        version_id: Uuid,
    ) -> Result<McpAttachmentMetadata, DatabaseError> {
        let row = sqlx::query("SELECT n.display_name,v.media_type FROM public.nodes n JOIN public.file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id AND v.id=$4 WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3 AND n.kind='file' AND n.trash_root_id IS NULL")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(resource_id)
            .bind(version_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(McpAttachmentMetadata {
            basename: row.get("display_name"),
            media_type: row
                .get::<Option<String>, _>("media_type")
                .unwrap_or_else(|| "application/octet-stream".to_owned()),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mcp_record_invocation_attachment(
        &self,
        tenant_id: Uuid,
        invocation_id: Uuid,
        ordinal: i32,
        version_id: Uuid,
        sent_content: bool,
        sent_basename: bool,
        sent_media_type: bool,
        sent_size: bool,
        bytes_sent: i64,
    ) -> Result<(), DatabaseError> {
        if !(0..=3).contains(&ordinal) || bytes_sent < 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query("INSERT INTO filebelt_mcp.invocation_attachments (tenant_id,invocation_id,ordinal,version_id,sent_content,sent_basename,sent_media_type,sent_size,bytes_sent) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(tenant_id)
            .bind(invocation_id)
            .bind(ordinal)
            .bind(version_id)
            .bind(sent_content)
            .bind(sent_basename)
            .bind(sent_media_type)
            .bind(sent_size)
            .bind(bytes_sent)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

async fn lock_data_grant_version(
    transaction: &mut Transaction<'_, Postgres>,
    input: &NewMcpDataGrant,
) -> Result<(), DatabaseError> {
    if input.drive_acl_generation <= 0
        || input.acl_generation <= 0
        || input.namespace_generation <= 0
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let row = sqlx::query("SELECT d.acl_generation AS drive_acl_generation,n.acl_generation,n.namespace_generation FROM public.nodes n JOIN public.drives d ON d.tenant_id=n.tenant_id AND d.id=n.drive_id JOIN public.file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id AND v.id=$4 WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3 FOR SHARE OF d,n,v")
        .bind(input.tenant_id)
        .bind(input.drive_id)
        .bind(input.resource_id)
        .bind(input.version_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
    if row.get::<i64, _>("drive_acl_generation") != input.drive_acl_generation
        || row.get::<i64, _>("acl_generation") != input.acl_generation
        || row.get::<i64, _>("namespace_generation") != input.namespace_generation
    {
        return Err(DatabaseError::StaleGeneration);
    }
    Ok(())
}

pub(super) async fn insert_data_grant(
    transaction: &mut Transaction<'_, Postgres>,
    input: &NewMcpDataGrant,
) -> Result<(), DatabaseError> {
    let registration_generation: i64 = sqlx::query_scalar("SELECT revocation_generation FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND revoked_at IS NULL AND deleted_at IS NULL FOR SHARE")
        .bind(input.tenant_id)
        .bind(input.registration_id)
        .bind(input.principal_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
    lock_data_grant_version(transaction, input).await?;
    sqlx::query("INSERT INTO filebelt_mcp.data_grants (tenant_id,id,principal_id,registration_id,drive_id,resource_id,version_id,allow_metadata,allow_content,drive_acl_generation,acl_generation,namespace_generation,registration_generation,created_by,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,statement_timestamp(),statement_timestamp()+make_interval(secs=>$15))")
        .bind(input.tenant_id)
        .bind(input.id)
        .bind(input.principal_id)
        .bind(input.registration_id)
        .bind(input.drive_id)
        .bind(input.resource_id)
        .bind(input.version_id)
        .bind(input.allow_metadata)
        .bind(input.allow_content)
        .bind(input.drive_acl_generation)
        .bind(input.acl_generation)
        .bind(input.namespace_generation)
        .bind(registration_generation)
        .bind(input.created_by)
        .bind(input.lifetime_seconds)
        .execute(&mut **transaction)
        .await
        .map_err(crate::map_security_admission)?;
    Ok(())
}

fn registration_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<McpRegistrationRecord, DatabaseError> {
    Ok(McpRegistrationRecord {
        tenant_id: row.get("tenant_id"),
        id: row.get("id"),
        owner_principal_id: row.get("owner_principal_id"),
        owner_kind: row.get("owner_kind"),
        source_kind: row.get("source_kind"),
        template_id: row.get("template_id"),
        display_name: row.get("display_name"),
        description: row.get("description"),
        transport: row.get("transport"),
        endpoint_uri: row.get("endpoint_uri"),
        trust_profile: row.get("trust_profile"),
        catalog_entry: row.get("catalog_entry"),
        state: RegistrationPolicyState {
            validation: validation_state(row.get::<String, _>("validation_state").as_str())?,
            authentication: authentication_state(
                row.get::<String, _>("authentication_state").as_str(),
            )?,
            capabilities: capability_state(row.get::<String, _>("capability_state").as_str())?,
            quarantine: quarantine_state(row.get::<String, _>("quarantine_state").as_str())?,
            enabled: row.get("enabled"),
            revoked: row.get("is_revoked"),
        },
        policy: row.get("policy"),
        revision: row.get("revision"),
        revocation_generation: row.get("revocation_generation"),
        credential_generation: row.get("credential_generation"),
        credential_kind: row.get("credential_kind"),
        protocol_version: row.get("protocol_version"),
        created_at: row.get("created_at_text"),
        updated_at: row.get("updated_at_text"),
    })
}

fn secret_from_row(row: &sqlx::postgres::PgRow) -> McpSecretEnvelope {
    McpSecretEnvelope {
        tenant_id: row.get("tenant_id"),
        registration_id: row.get("registration_id"),
        owner_principal_id: row.get("owner_principal_id"),
        issuer: row.get("issuer"),
        secret_kind: row.get("secret_kind"),
        credential_generation: row.get("credential_generation"),
        ciphertext: row.get("ciphertext"),
        nonce: row.get("nonce"),
        wrapped_dek: row.get("wrapped_dek"),
        wrap_nonce: row.get("wrap_nonce"),
        kek_generation: row.get("kek_generation"),
        aad_version: row.get("aad_version"),
    }
}

fn credential_metadata_from_row(row: &sqlx::postgres::PgRow) -> McpCredentialMetadata {
    McpCredentialMetadata {
        registration_id: row.get("registration_id"),
        owner_principal_id: row.get("owner_principal_id"),
        issuer: row.get("issuer"),
        secret_kind: row.get("secret_kind"),
        credential_generation: row.get("credential_generation"),
        kek_generation: row.get("kek_generation"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn validate_secret_envelope(envelope: &McpSecretEnvelope) -> Result<(), DatabaseError> {
    if envelope.nonce.len() != 12
        || envelope.wrap_nonce.len() != 12
        || envelope.ciphertext.is_empty()
        || envelope.wrapped_dek.is_empty()
        || envelope.credential_generation <= 0
        || envelope.kek_generation <= 0
        || envelope.aad_version != 1
        || envelope.issuer.len() > 2048
        || !matches!(
            envelope.secret_kind.as_str(),
            "oauth_client" | "oauth_access" | "oauth_refresh" | "bearer" | "api_key"
        )
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn validation_text(state: ValidationState) -> &'static str {
    match state {
        ValidationState::NeverTested => "never_tested",
        ValidationState::Valid => "valid",
        ValidationState::Invalid => "invalid",
    }
}

fn validation_state(value: &str) -> Result<ValidationState, DatabaseError> {
    match value {
        "never_tested" => Ok(ValidationState::NeverTested),
        "valid" => Ok(ValidationState::Valid),
        "invalid" => Ok(ValidationState::Invalid),
        _ => Err(DatabaseError::InvalidPersistedValue),
    }
}

fn authentication_text(state: AuthenticationState) -> &'static str {
    match state {
        AuthenticationState::NoneRequired => "none_required",
        AuthenticationState::Required => "required",
        AuthenticationState::Authorized => "authorized",
        AuthenticationState::Failed => "failed",
    }
}

fn authentication_state(value: &str) -> Result<AuthenticationState, DatabaseError> {
    match value {
        "none_required" => Ok(AuthenticationState::NoneRequired),
        "required" => Ok(AuthenticationState::Required),
        "authorized" => Ok(AuthenticationState::Authorized),
        "failed" => Ok(AuthenticationState::Failed),
        _ => Err(DatabaseError::InvalidPersistedValue),
    }
}

fn capability_text(state: CapabilityState) -> &'static str {
    match state {
        CapabilityState::Undiscovered => "undiscovered",
        CapabilityState::PendingReview => "pending_review",
        CapabilityState::Approved => "approved",
        CapabilityState::Drifted => "drifted",
    }
}

fn capability_state(value: &str) -> Result<CapabilityState, DatabaseError> {
    match value {
        "undiscovered" => Ok(CapabilityState::Undiscovered),
        "pending_review" => Ok(CapabilityState::PendingReview),
        "approved" => Ok(CapabilityState::Approved),
        "drifted" => Ok(CapabilityState::Drifted),
        _ => Err(DatabaseError::InvalidPersistedValue),
    }
}

fn quarantine_text(state: QuarantineState) -> &'static str {
    match state {
        QuarantineState::Clear => "clear",
        QuarantineState::Quarantined => "quarantined",
    }
}

fn quarantine_state(value: &str) -> Result<QuarantineState, DatabaseError> {
    match value {
        "clear" => Ok(QuarantineState::Clear),
        "quarantined" => Ok(QuarantineState::Quarantined),
        _ => Err(DatabaseError::InvalidPersistedValue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_policy_state_is_closed() {
        assert_eq!(
            validation_state("valid").expect("state"),
            ValidationState::Valid
        );
        assert!(validation_state("future").is_err());
        assert!(authentication_state("future").is_err());
        assert!(capability_state("future").is_err());
        assert!(quarantine_state("future").is_err());
    }

    #[test]
    fn database_queries_never_persist_arguments_or_results() {
        let source = include_str!("mcp.rs");
        let production = source.split("#[cfg(test)]").next().expect("source prefix");
        assert!(!production.contains("argument_json"));
        assert!(!production.contains("result_json"));
        assert!(!production.contains("stderr_text"));
    }

    #[test]
    fn data_grant_queries_bind_drive_acl_generation() {
        let source = include_str!("mcp.rs");
        let production = source.split("#[cfg(test)]").next().expect("source prefix");
        for required in [
            "pub drive_acl_generation: i64",
            "g.drive_acl_generation AS granted_drive_acl_generation",
            "JOIN public.drives d",
            "FOR SHARE OF d,n,v",
            "granted_drive_acl != Some(snapshot.drive_acl_generation)",
            "row.get::<i64, _>(\"drive_acl_generation\") != input.drive_acl_generation",
            "drive_acl_generation,acl_generation,namespace_generation",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
    }
}

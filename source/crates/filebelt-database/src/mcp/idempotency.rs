// SPDX-License-Identifier: Apache-2.0

//! Transactional idempotency for MCP authority-creating writes.

use filebelt_mcp_policy::RegistrationPolicyState;
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::invocation::{NewMcpApprovalRule, insert_approval_rule};
use super::management::{
    McpAdminBlockRuleRecord, McpCapabilityReviewRecord, McpCapabilitySnapshotRecord,
    TemplateConfigurationUpdate, advance_admin_block_policy, block_rule_from_row,
    validate_block_rule,
};
use super::operations::{
    McpManagedTemplateRecord, McpServicePrincipalRecord, NewMcpManagedTemplate, NewMcpServiceGrant,
    NewMcpServicePrincipal, insert_service_grant, service_from_row, service_row, template_from_row,
    valid_spiffe_uri,
};
use super::{
    Database, DatabaseError, McpRegistrationRecord, NewCapabilitySnapshot, NewMcpDataGrant,
    NewMcpRegistration, authentication_text, capability_text, insert_data_grant, quarantine_text,
    registration_from_row, validation_text,
};
use crate::IdempotencyRecord;
use crate::idempotency::{IdempotencyInput, IdempotencyReservation, finalize, reserve};

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

#[derive(Clone, Debug)]
pub struct McpMutationIdempotency<'a> {
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub route: &'a str,
    pub key: &'a str,
    pub request_fingerprint: &'a [u8; 32],
    pub legacy_request_fingerprint: Option<&'a [u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct McpCapabilityDecision<'a> {
    pub fingerprint: &'a [u8; 32],
    pub decision: &'a str,
    pub constraints: &'a Value,
}

#[derive(Debug)]
pub enum McpMutationStart {
    Started(McpMutationTransaction),
    Replayed(IdempotencyRecord),
    KeyReused,
}

#[derive(Debug)]
pub struct McpMutationTransaction {
    transaction: Transaction<'static, Postgres>,
    tenant_id: Uuid,
    principal_id: Uuid,
    route: String,
    key: String,
    request_fingerprint: [u8; 32],
}

impl Database {
    pub async fn mcp_begin_mutation(
        &self,
        idempotency: &McpMutationIdempotency<'_>,
    ) -> Result<McpMutationStart, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let reservation = IdempotencyInput {
            principal_id: idempotency.principal_id,
            route: idempotency.route,
            key: idempotency.key,
            request_fingerprint: idempotency.request_fingerprint,
            legacy_request_fingerprint: idempotency.legacy_request_fingerprint,
        };
        match reserve(&mut transaction, idempotency.tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpMutationStart::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpMutationStart::KeyReused)
            }
            IdempotencyReservation::Created => {
                Ok(McpMutationStart::Started(McpMutationTransaction {
                    transaction,
                    tenant_id: idempotency.tenant_id,
                    principal_id: idempotency.principal_id,
                    route: idempotency.route.to_owned(),
                    key: idempotency.key.to_owned(),
                    request_fingerprint: *idempotency.request_fingerprint,
                }))
            }
        }
    }

    pub async fn mcp_create_approval_rule_idempotent(
        &self,
        input: &NewMcpApprovalRule<'_>,
        idempotency: &McpIdempotency<'_>,
    ) -> Result<McpIdempotentWrite, DatabaseError> {
        if idempotency.principal_id != input.principal_id
            || !(100..=599).contains(&idempotency.response_status)
            || !(1..=3_600).contains(&input.lifetime_seconds)
            || !matches!(
                input.primitive,
                "resource_read" | "prompt_get" | "tool_call"
            )
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let reservation = idempotency.reservation_input();
        match reserve(&mut transaction, input.tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                insert_approval_rule(&mut transaction, input).await?;
                let record = finalize(
                    &mut transaction,
                    input.tenant_id,
                    &reservation,
                    idempotency.response_status,
                    idempotency.response_body,
                )
                .await?;
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
            || !(100..=599).contains(&idempotency.response_status)
            || !(1..=2_592_000).contains(&input.lifetime_seconds)
            || !(input.allow_metadata || input.allow_content)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let reservation = idempotency.reservation_input();
        match reserve(&mut transaction, input.tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                insert_data_grant(&mut transaction, input).await?;
                let record = finalize(
                    &mut transaction,
                    input.tenant_id,
                    &reservation,
                    idempotency.response_status,
                    idempotency.response_body,
                )
                .await?;
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
            || !(100..=599).contains(&idempotency.response_status)
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
        let reservation = idempotency.reservation_input();
        match reserve(&mut transaction, input.tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(McpIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                insert_service_grant(&mut transaction, input).await?;
                let record = finalize(
                    &mut transaction,
                    input.tenant_id,
                    &reservation,
                    idempotency.response_status,
                    idempotency.response_body,
                )
                .await?;
                transaction.commit().await?;
                Ok(McpIdempotentWrite::Created(record))
            }
        }
    }
}

impl McpMutationTransaction {
    pub async fn mark_broker_operation_applied(
        &mut self,
        operation_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let affected = sqlx::query("UPDATE filebelt_mcp.broker_operation_receipts SET api_completed_at=COALESCE(api_completed_at,clock_timestamp()) WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3 AND result IS NOT NULL")
            .bind(self.tenant_id)
            .bind(self.principal_id)
            .bind(operation_id)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        one_row(affected)
    }

    pub async fn create_registration(
        &mut self,
        input: &NewMcpRegistration<'_>,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        self.ensure_tenant(input.tenant_id)?;
        if input.owner_principal_id != self.principal_id
            || !matches!(input.owner_kind, "user" | "service")
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
        .fetch_one(&mut *self.transaction)
        .await?;
        registration_from_row(&row)
    }

    pub async fn update_registration_state(
        &mut self,
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
        let row = sqlx::query("UPDATE filebelt_mcp.registrations SET validation_state=$5,authentication_state=$6,capability_state=$7,quarantine_state=$8,enabled=$9,protocol_version=$10,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND owner_principal_id=$2 AND id=$3 AND revision=$4 AND deleted_at IS NULL RETURNING *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text")
            .bind(self.tenant_id)
            .bind(self.principal_id)
            .bind(registration_id)
            .bind(expected_revision)
            .bind(validation_text(state.validation))
            .bind(authentication_text(state.authentication))
            .bind(capability_text(state.capabilities))
            .bind(quarantine_text(state.quarantine))
            .bind(state.enabled)
            .bind(protocol_version)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        registration_from_row(&row)
    }

    pub async fn revoke_registration(
        &mut self,
        registration_id: Uuid,
        expected_revision: i64,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        let row = sqlx::query("UPDATE filebelt_mcp.registrations SET enabled=false,revoked_at=COALESCE(revoked_at,clock_timestamp()),revocation_generation=revocation_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND owner_principal_id=$2 AND id=$3 AND revision=$4 AND deleted_at IS NULL RETURNING *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text")
            .bind(self.tenant_id)
            .bind(self.principal_id)
            .bind(registration_id)
            .bind(expected_revision)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        registration_from_row(&row)
    }

    pub async fn delete_registration(
        &mut self,
        registration_id: Uuid,
        expected_revision: i64,
        tombstone_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let row = sqlx::query("UPDATE filebelt_mcp.registrations SET enabled=false,revoked_at=COALESCE(revoked_at,clock_timestamp()),deleted_at=clock_timestamp(),revocation_generation=revocation_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND owner_principal_id=$2 AND id=$3 AND revision=$4 AND deleted_at IS NULL RETURNING owner_principal_id,revocation_generation")
            .bind(self.tenant_id)
            .bind(self.principal_id)
            .bind(registration_id)
            .bind(expected_revision)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        sqlx::query("INSERT INTO filebelt_mcp.deletion_tombstones (tenant_id,id,object_kind,object_id,owner_principal_id,revocation_generation,remote_revocation_deadline) VALUES ($1,$2,'registration',$3,$4,$5,clock_timestamp()+interval '15 minutes')")
            .bind(self.tenant_id)
            .bind(tombstone_id)
            .bind(registration_id)
            .bind(row.get::<Uuid, _>("owner_principal_id"))
            .bind(row.get::<i64, _>("revocation_generation"))
            .execute(&mut *self.transaction)
            .await?;
        Ok(())
    }

    pub async fn store_capability_snapshot(
        &mut self,
        input: &NewCapabilitySnapshot<'_>,
        expected_revision: i64,
    ) -> Result<McpCapabilitySnapshotRecord, DatabaseError> {
        self.ensure_tenant(input.tenant_id)?;
        if !input.document.is_object() || input.protocol_version.is_empty() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let credential_generation: i64 = sqlx::query_scalar("SELECT credential_generation FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND owner_principal_id=$2 AND id=$3 AND revision=$4 AND revoked_at IS NULL AND deleted_at IS NULL FOR UPDATE")
            .bind(input.tenant_id)
            .bind(self.principal_id)
            .bind(input.registration_id)
            .bind(expected_revision)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        if credential_generation != input.credential_generation {
            return Err(DatabaseError::StaleGeneration);
        }
        let current = sqlx::query("SELECT id,registration_id,credential_generation,fingerprint,protocol_version,document,discovered_at::text AS discovered_at FROM filebelt_mcp.capability_snapshots WHERE tenant_id=$1 AND registration_id=$2 AND superseded_at IS NULL FOR UPDATE")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .fetch_optional(&mut *self.transaction)
            .await?;
        if let Some(row) = current.as_ref()
            && row.get::<Vec<u8>, _>("fingerprint").as_slice() == input.fingerprint
            && row.get::<i64, _>("credential_generation") == input.credential_generation
        {
            return Ok(McpCapabilitySnapshotRecord {
                id: row.get("id"),
                registration_id: row.get("registration_id"),
                credential_generation: row.get("credential_generation"),
                fingerprint: row.get("fingerprint"),
                protocol_version: row.get("protocol_version"),
                document: row.get("document"),
                discovered_at: row.get("discovered_at"),
            });
        }
        sqlx::query("UPDATE filebelt_mcp.capability_snapshots SET superseded_at=clock_timestamp() WHERE tenant_id=$1 AND registration_id=$2 AND superseded_at IS NULL")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .execute(&mut *self.transaction)
            .await?;
        let discovered_at: String = sqlx::query_scalar("INSERT INTO filebelt_mcp.capability_snapshots (tenant_id,id,registration_id,credential_generation,fingerprint,protocol_version,document) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING discovered_at::text")
            .bind(input.tenant_id)
            .bind(input.id)
            .bind(input.registration_id)
            .bind(input.credential_generation)
            .bind(input.fingerprint.as_slice())
            .bind(input.protocol_version)
            .bind(input.document)
            .fetch_one(&mut *self.transaction)
            .await?;
        for (primitive, values) in [
            ("tool_call", input.document.pointer("/tools/tools")),
            (
                "resource_read",
                input.document.pointer("/resources/resources"),
            ),
            ("prompt_get", input.document.pointer("/prompts/prompts")),
        ] {
            for descriptor in values.and_then(Value::as_array).into_iter().flatten() {
                let name = descriptor
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(DatabaseError::InvalidPersistedValue)?;
                let read_only_hint = descriptor
                    .pointer("/annotations/readOnlyHint")
                    .and_then(Value::as_bool);
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
                    .execute(&mut *self.transaction)
                    .await?;
            }
        }
        let capability_state = if current.is_some() {
            "drifted"
        } else {
            "pending_review"
        };
        let updated = sqlx::query("UPDATE filebelt_mcp.registrations SET capability_state=$5,enabled=false,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND owner_principal_id=$2 AND id=$3 AND revision=$4")
            .bind(input.tenant_id)
            .bind(self.principal_id)
            .bind(input.registration_id)
            .bind(expected_revision)
            .bind(capability_state)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        if updated != 1 {
            return Err(DatabaseError::Conflict);
        }
        Ok(McpCapabilitySnapshotRecord {
            id: input.id,
            registration_id: input.registration_id,
            credential_generation: input.credential_generation,
            fingerprint: input.fingerprint.to_vec(),
            protocol_version: input.protocol_version.to_owned(),
            document: input.document.clone(),
            discovered_at,
        })
    }

    pub async fn revoke_approval(&mut self, approval_id: Uuid) -> Result<(), DatabaseError> {
        let affected = sqlx::query("UPDATE filebelt_mcp.approval_rules SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND principal_id=$2 AND id=$3")
            .bind(self.tenant_id)
            .bind(self.principal_id)
            .bind(approval_id)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        one_row(affected)
    }

    pub async fn review_capabilities(
        &mut self,
        registration_id: Uuid,
        expected_revision: i64,
        snapshot_id: Uuid,
        decisions: &[McpCapabilityDecision<'_>],
        state: RegistrationPolicyState,
        protocol_version: Option<&str>,
    ) -> Result<(McpRegistrationRecord, Vec<McpCapabilityReviewRecord>), DatabaseError> {
        if decisions.is_empty()
            || decisions.iter().any(|decision| {
                !matches!(decision.decision, "approved" | "denied")
                    || !decision.constraints.is_object()
            })
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        for decision in decisions {
            let affected = sqlx::query("INSERT INTO filebelt_mcp.capability_reviews (tenant_id,registration_id,snapshot_id,capability_fingerprint,reviewer_principal_id,decision,constraints) SELECT $1,$2,$3,$4,$5,$6,$7 FROM filebelt_mcp.capability_snapshots s JOIN filebelt_mcp.registrations r ON r.tenant_id=s.tenant_id AND r.id=s.registration_id AND r.credential_generation=s.credential_generation WHERE s.tenant_id=$1 AND s.id=$3 AND s.registration_id=$2 AND s.superseded_at IS NULL AND r.owner_principal_id=$5 ON CONFLICT (tenant_id,snapshot_id,capability_fingerprint) DO UPDATE SET reviewer_principal_id=EXCLUDED.reviewer_principal_id,decision=EXCLUDED.decision,constraints=EXCLUDED.constraints,reviewed_at=clock_timestamp(),revoked_at=NULL")
                .bind(self.tenant_id)
                .bind(registration_id)
                .bind(snapshot_id)
                .bind(decision.fingerprint.as_slice())
                .bind(self.principal_id)
                .bind(decision.decision)
                .bind(decision.constraints)
                .execute(&mut *self.transaction)
                .await?
                .rows_affected();
            if affected != 1 {
                return Err(DatabaseError::StaleGeneration);
            }
        }
        let updated = self
            .update_registration_state(registration_id, expected_revision, state, protocol_version)
            .await?;
        let reviews = sqlx::query("SELECT snapshot_id,capability_fingerprint,reviewer_principal_id,decision,constraints,reviewed_at::text AS reviewed_at,revoked_at IS NOT NULL AS revoked FROM filebelt_mcp.capability_reviews WHERE tenant_id=$1 AND registration_id=$2 AND snapshot_id=$3 ORDER BY capability_fingerprint")
            .bind(self.tenant_id)
            .bind(registration_id)
            .bind(snapshot_id)
            .fetch_all(&mut *self.transaction)
            .await?
            .iter()
            .map(|row| McpCapabilityReviewRecord {
                snapshot_id: row.get("snapshot_id"),
                capability_fingerprint: row.get("capability_fingerprint"),
                reviewer_principal_id: row.get("reviewer_principal_id"),
                decision: row.get("decision"),
                constraints: row.get("constraints"),
                reviewed_at: row.get("reviewed_at"),
                revoked: row.get("revoked"),
            })
            .collect();
        Ok((updated, reviews))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_invocation_intent(
        &mut self,
        id: Uuid,
        registration_id: Uuid,
        session_id: Uuid,
        application_id: &str,
        primitive: &str,
        capability_fingerprint: &[u8; 32],
        argument_digest: &[u8; 32],
        attachment_digest: &[u8; 32],
        request_digest: &[u8; 32],
    ) -> Result<i64, DatabaseError> {
        if !matches!(primitive, "resource_read" | "prompt_get" | "tool_call") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar("INSERT INTO filebelt_mcp.invocation_intents (tenant_id,id,registration_id,principal_id,session_id,application_id,primitive,capability_fingerprint,argument_digest,attachment_digest,request_digest,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,statement_timestamp(),statement_timestamp()+interval '5 minutes') RETURNING extract(epoch FROM expires_at)::bigint")
            .bind(self.tenant_id)
            .bind(id)
            .bind(registration_id)
            .bind(self.principal_id)
            .bind(session_id)
            .bind(application_id)
            .bind(primitive)
            .bind(capability_fingerprint.as_slice())
            .bind(argument_digest.as_slice())
            .bind(attachment_digest.as_slice())
            .bind(request_digest.as_slice())
            .fetch_one(&mut *self.transaction)
            .await
            .map_err(Into::into)
    }

    pub async fn cancel_invocation(&mut self, invocation_id: Uuid) -> Result<(), DatabaseError> {
        let state: String = sqlx::query_scalar("SELECT state FROM filebelt_mcp.invocations WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 FOR UPDATE")
            .bind(self.tenant_id)
            .bind(self.principal_id)
            .bind(invocation_id)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        if state == "cancelled" {
            return Ok(());
        }
        if !matches!(state.as_str(), "pending" | "running") {
            return Err(DatabaseError::Conflict);
        }
        sqlx::query("UPDATE filebelt_mcp.invocations SET state='cancelled',reason_code='mcp.cancelled_by_principal',finished_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND id=$3")
            .bind(self.tenant_id)
            .bind(self.principal_id)
            .bind(invocation_id)
            .execute(&mut *self.transaction)
            .await?;
        Ok(())
    }

    pub async fn revoke_data_grant(
        &mut self,
        drive_id: Uuid,
        resource_id: Uuid,
        grant_id: Uuid,
        namespace_generation: i64,
        acl_generation: i64,
    ) -> Result<(), DatabaseError> {
        let affected = sqlx::query("UPDATE filebelt_mcp.data_grants g SET revoked_at=COALESCE(g.revoked_at,clock_timestamp()) WHERE g.tenant_id=$1 AND g.principal_id=$2 AND g.drive_id=$3 AND g.resource_id=$4 AND g.id=$5 AND EXISTS (SELECT 1 FROM public.nodes n WHERE n.tenant_id=g.tenant_id AND n.drive_id=g.drive_id AND n.id=g.resource_id AND n.namespace_generation=$6 AND n.acl_generation=$7)")
            .bind(self.tenant_id)
            .bind(self.principal_id)
            .bind(drive_id)
            .bind(resource_id)
            .bind(grant_id)
            .bind(namespace_generation)
            .bind(acl_generation)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        one_row(affected)
    }

    pub async fn create_managed_template(
        &mut self,
        input: &NewMcpManagedTemplate<'_>,
    ) -> Result<McpManagedTemplateRecord, DatabaseError> {
        self.ensure_tenant(input.tenant_id)?;
        if input.created_by != self.principal_id
            || input.display_name.is_empty()
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
            .fetch_one(&mut *self.transaction)
            .await?;
        Ok(template_from_row(&row))
    }

    pub async fn update_managed_template(
        &mut self,
        input: &TemplateConfigurationUpdate<'_>,
    ) -> Result<McpManagedTemplateRecord, DatabaseError> {
        self.ensure_tenant(input.tenant_id)?;
        if input.display_name.is_empty()
            || input.description.len() > 1000
            || !input.policy.is_object()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query("UPDATE filebelt_mcp.managed_templates SET display_name=$4,description=$5,endpoint_uri=$6,trust_profile=$7,catalog_entry=$8,policy=$9,enabled=$10,revision=revision+1,revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL RETURNING *,created_at::text AS created_at_text,updated_at::text AS updated_at_text")
            .bind(input.tenant_id)
            .bind(input.template_id)
            .bind(input.expected_revision)
            .bind(input.display_name)
            .bind(input.description)
            .bind(input.endpoint_uri)
            .bind(input.trust_profile)
            .bind(input.catalog_entry)
            .bind(input.policy)
            .bind(input.enabled)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        Ok(template_from_row(&row))
    }

    pub async fn delete_managed_template(
        &mut self,
        template_id: Uuid,
        expected_revision: i64,
    ) -> Result<(), DatabaseError> {
        let affected = sqlx::query("UPDATE filebelt_mcp.managed_templates SET enabled=false,deleted_at=clock_timestamp(),revision=revision+1,revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL")
            .bind(self.tenant_id)
            .bind(template_id)
            .bind(expected_revision)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        one_row(affected)
    }

    pub async fn assign_template(
        &mut self,
        template_id: Uuid,
        subject_principal_id: Uuid,
        subject_kind: &str,
        expected_template_revision: i64,
    ) -> Result<i64, DatabaseError> {
        if !matches!(subject_kind, "user" | "group" | "service") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar("INSERT INTO filebelt_mcp.template_assignments (tenant_id,template_id,subject_principal_id,subject_kind,created_by) SELECT $1,$2,$3,$4,$5 FROM filebelt_mcp.managed_templates t WHERE t.tenant_id=$1 AND t.id=$2 AND t.revision=$6 AND t.deleted_at IS NULL ON CONFLICT (tenant_id,template_id,subject_principal_id) DO UPDATE SET subject_kind=EXCLUDED.subject_kind,created_by=EXCLUDED.created_by,created_at=clock_timestamp(),revoked_at=NULL RETURNING extract(epoch FROM created_at)::bigint")
            .bind(self.tenant_id)
            .bind(template_id)
            .bind(subject_principal_id)
            .bind(subject_kind)
            .bind(self.principal_id)
            .bind(expected_template_revision)
            .fetch_optional(&mut *self.transaction)
            .await
            .map_err(DatabaseError::from)?
            .ok_or(DatabaseError::Conflict)
    }

    pub async fn revoke_template_assignment(
        &mut self,
        template_id: Uuid,
        subject_principal_id: Uuid,
        expected_template_revision: i64,
    ) -> Result<(), DatabaseError> {
        sqlx::query_scalar::<_, i32>("SELECT 1 FROM filebelt_mcp.managed_templates WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL FOR SHARE")
            .bind(self.tenant_id)
            .bind(template_id)
            .bind(expected_template_revision)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        let affected = sqlx::query("UPDATE filebelt_mcp.template_assignments SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND template_id=$2 AND subject_principal_id=$3")
            .bind(self.tenant_id)
            .bind(template_id)
            .bind(subject_principal_id)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        one_row(affected)?;
        sqlx::query("UPDATE filebelt_mcp.registrations SET enabled=false,revocation_generation=revocation_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND template_id=$2 AND owner_principal_id=$3 AND deleted_at IS NULL")
            .bind(self.tenant_id)
            .bind(template_id)
            .bind(subject_principal_id)
            .execute(&mut *self.transaction)
            .await?;
        Ok(())
    }

    pub async fn template_assignment_count(
        &mut self,
        template_id: Uuid,
    ) -> Result<i64, DatabaseError> {
        sqlx::query_scalar("SELECT count(*) FROM filebelt_mcp.template_assignments WHERE tenant_id=$1 AND template_id=$2 AND revoked_at IS NULL")
            .bind(self.tenant_id)
            .bind(template_id)
            .fetch_one(&mut *self.transaction)
            .await
            .map_err(Into::into)
    }

    pub async fn create_service_principal(
        &mut self,
        input: &NewMcpServicePrincipal<'_>,
    ) -> Result<McpServicePrincipalRecord, DatabaseError> {
        self.ensure_tenant(input.tenant_id)?;
        if input.created_by != self.principal_id
            || input.display_name.is_empty()
            || input.display_name.len() > 255
            || !valid_spiffe_uri(input.spiffe_uri)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query("INSERT INTO public.principals (tenant_id,id,kind) VALUES ($1,$2,'service')")
            .bind(input.tenant_id)
            .bind(input.principal_id)
            .execute(&mut *self.transaction)
            .await?;
        sqlx::query("INSERT INTO filebelt_mcp.service_principals (tenant_id,id,principal_id,display_name,created_by) VALUES ($1,$2,$3,$4,$5)")
            .bind(input.tenant_id)
            .bind(input.service_id)
            .bind(input.principal_id)
            .bind(input.display_name)
            .bind(input.created_by)
            .execute(&mut *self.transaction)
            .await?;
        sqlx::query("INSERT INTO filebelt_mcp.service_identity_bindings (tenant_id,id,service_id,spiffe_uri) VALUES ($1,$2,$3,$4)")
            .bind(input.tenant_id)
            .bind(input.identity_binding_id)
            .bind(input.service_id)
            .bind(input.spiffe_uri)
            .execute(&mut *self.transaction)
            .await?;
        let row = service_row(&mut self.transaction, input.tenant_id, input.service_id).await?;
        Ok(service_from_row(&row))
    }

    pub async fn update_service_principal(
        &mut self,
        service_id: Uuid,
        expected_generation: i64,
        display_name: &str,
        status: &str,
        replacement_identity: Option<(Uuid, &str)>,
    ) -> Result<McpServicePrincipalRecord, DatabaseError> {
        if display_name.is_empty()
            || !matches!(status, "active" | "suspended")
            || replacement_identity.is_some_and(|(_, uri)| !valid_spiffe_uri(uri))
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let affected = sqlx::query("UPDATE filebelt_mcp.service_principals SET display_name=$4,status=$5,revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revocation_generation=$3 AND status<>'deleted'")
            .bind(self.tenant_id)
            .bind(service_id)
            .bind(expected_generation)
            .bind(display_name)
            .bind(status)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        if affected != 1 {
            return Err(DatabaseError::Conflict);
        }
        if let Some((binding_id, spiffe_uri)) = replacement_identity {
            sqlx::query("UPDATE filebelt_mcp.service_identity_bindings SET revoked_at=COALESCE(revoked_at,clock_timestamp()),generation=generation+1 WHERE tenant_id=$1 AND service_id=$2 AND revoked_at IS NULL")
                .bind(self.tenant_id)
                .bind(service_id)
                .execute(&mut *self.transaction)
                .await?;
            sqlx::query("INSERT INTO filebelt_mcp.service_identity_bindings (tenant_id,id,service_id,spiffe_uri) VALUES ($1,$2,$3,$4)")
                .bind(self.tenant_id)
                .bind(binding_id)
                .bind(service_id)
                .bind(spiffe_uri)
                .execute(&mut *self.transaction)
                .await?;
            one_row(sqlx::query("UPDATE filebelt_mcp.service_principals SET revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status<>'deleted'")
                .bind(self.tenant_id)
                .bind(service_id)
                .execute(&mut *self.transaction)
                .await?
                .rows_affected())?;
        }
        let row = service_row(&mut self.transaction, self.tenant_id, service_id).await?;
        Ok(service_from_row(&row))
    }

    pub async fn delete_service_principal(
        &mut self,
        service_id: Uuid,
        expected_generation: i64,
    ) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE filebelt_mcp.service_identity_bindings SET revoked_at=COALESCE(revoked_at,clock_timestamp()),generation=generation+1 WHERE tenant_id=$1 AND service_id=$2 AND revoked_at IS NULL")
            .bind(self.tenant_id)
            .bind(service_id)
            .execute(&mut *self.transaction)
            .await?;
        let affected = sqlx::query("UPDATE filebelt_mcp.service_principals SET status='deleted',deleted_at=clock_timestamp(),revocation_generation=revocation_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revocation_generation=$3 AND status<>'deleted'")
            .bind(self.tenant_id)
            .bind(service_id)
            .bind(expected_generation)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        one_row(affected)
    }

    pub async fn revoke_service_grant(
        &mut self,
        service_id: Uuid,
        grant_id: Uuid,
        expected_service_generation: i64,
    ) -> Result<(), DatabaseError> {
        let affected = sqlx::query("UPDATE filebelt_mcp.service_invocation_grants g SET revoked_at=COALESCE(g.revoked_at,clock_timestamp()) WHERE g.tenant_id=$1 AND g.service_id=$2 AND g.id=$3 AND EXISTS (SELECT 1 FROM filebelt_mcp.service_principals s WHERE s.tenant_id=g.tenant_id AND s.id=g.service_id AND s.revocation_generation=$4 AND s.status<>'deleted')")
            .bind(self.tenant_id)
            .bind(service_id)
            .bind(grant_id)
            .bind(expected_service_generation)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        one_row(affected)
    }

    pub async fn create_admin_block_rule(
        &mut self,
        id: Uuid,
        scope: &str,
        matcher: &str,
        reason_code: &str,
    ) -> Result<McpAdminBlockRuleRecord, DatabaseError> {
        validate_block_rule(scope, matcher, reason_code)?;
        advance_admin_block_policy(&mut self.transaction, self.tenant_id).await?;
        let row = sqlx::query("INSERT INTO filebelt_mcp.admin_block_rules (tenant_id,id,scope,matcher,reason_code,created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,scope,matcher,reason_code,enabled,revision,created_at::text AS created_at,updated_at::text AS updated_at")
            .bind(self.tenant_id)
            .bind(id)
            .bind(scope)
            .bind(matcher)
            .bind(reason_code)
            .bind(self.principal_id)
            .fetch_one(&mut *self.transaction)
            .await?;
        Ok(block_rule_from_row(&row))
    }

    pub async fn delete_admin_block_rule(
        &mut self,
        id: Uuid,
        expected_revision: i64,
    ) -> Result<(), DatabaseError> {
        advance_admin_block_policy(&mut self.transaction, self.tenant_id).await?;
        let affected = sqlx::query("UPDATE filebelt_mcp.admin_block_rules SET enabled=false,deleted_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL")
            .bind(self.tenant_id)
            .bind(id)
            .bind(expected_revision)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        one_row(affected)
    }

    pub async fn finalize(
        mut self,
        response_status: i32,
        response_body: &Value,
    ) -> Result<McpIdempotentWrite, DatabaseError> {
        let reservation = IdempotencyInput {
            principal_id: self.principal_id,
            route: &self.route,
            key: &self.key,
            request_fingerprint: &self.request_fingerprint,
            legacy_request_fingerprint: None,
        };
        let record = finalize(
            &mut self.transaction,
            self.tenant_id,
            &reservation,
            response_status,
            response_body,
        )
        .await?;
        self.transaction.commit().await?;
        Ok(McpIdempotentWrite::Created(record))
    }

    fn ensure_tenant(&self, tenant_id: Uuid) -> Result<(), DatabaseError> {
        if tenant_id == self.tenant_id {
            Ok(())
        } else {
            Err(DatabaseError::InvalidPersistedValue)
        }
    }
}

fn one_row(affected: u64) -> Result<(), DatabaseError> {
    if affected == 1 {
        Ok(())
    } else {
        Err(DatabaseError::NotFound)
    }
}

impl McpIdempotency<'_> {
    fn reservation_input(&self) -> IdempotencyInput<'_> {
        IdempotencyInput {
            principal_id: self.principal_id,
            route: self.route,
            key: self.key,
            request_fingerprint: self.request_fingerprint,
            legacy_request_fingerprint: None,
        }
    }
}

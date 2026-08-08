// SPDX-License-Identifier: Apache-2.0

//! MCP approvals, OAuth state, invocation, and abuse-control persistence.

use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{Database, DatabaseError};

#[derive(Clone, Debug)]
pub struct NewMcpApprovalRule<'a> {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub registration_id: Uuid,
    pub principal_id: Uuid,
    pub intent_id: Uuid,
    pub session_id: Option<Uuid>,
    pub application_id: &'a str,
    pub primitive: &'a str,
    pub capability_name: &'a str,
    pub capability_fingerprint: &'a [u8; 32],
    pub argument_digest: &'a [u8; 32],
    pub attachment_digest: &'a [u8; 32],
    pub single_use: bool,
    pub lifetime_seconds: i64,
}

#[derive(Clone, Debug)]
pub struct NewMcpOAuthAttempt<'a> {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub registration_id: Uuid,
    pub owner_principal_id: Uuid,
    pub credential_generation: i64,
    pub session_id: Uuid,
    pub state_digest: &'a [u8],
    pub issuer: &'a str,
    pub redirect_path: &'a str,
    pub ciphertext: &'a [u8],
    pub nonce: &'a [u8; 12],
    pub wrapped_dek: &'a [u8],
    pub wrap_nonce: &'a [u8; 12],
    pub kek_generation: i32,
}

#[derive(Clone, Debug)]
pub struct McpOAuthAttemptSecret {
    pub registration_id: Uuid,
    pub owner_principal_id: Uuid,
    pub issuer: String,
    pub redirect_path: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: Vec<u8>,
    pub kek_generation: i32,
}

#[derive(Clone, Debug)]
pub struct McpInvocationIntentApprovalContext {
    pub registration_id: Uuid,
    pub application_id: String,
    pub primitive: String,
    pub capability_fingerprint: Vec<u8>,
    pub argument_digest: Vec<u8>,
    pub attachment_digest: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NewMcpInvocation<'a> {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub registration_id: Uuid,
    pub principal_id: Uuid,
    pub application_id: &'a str,
    pub primitive: &'a str,
    pub capability_fingerprint: &'a [u8; 32],
    pub approval_id: Option<Uuid>,
    pub registration_generation: i64,
    pub authority_generation: i64,
    pub admin_block_generation: i64,
    pub request_bytes: i64,
    /// Provenance evidence for a Markdown semantic proposal. These are only
    /// normalized-source digests and immutable identifiers, never Markdown.
    pub semantic_node_id: Option<Uuid>,
    pub semantic_base_version_id: Option<Uuid>,
    pub semantic_input_digest: Option<&'a [u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpActivityRecord {
    pub id: Uuid,
    pub registration_id: Uuid,
    pub principal_id: Uuid,
    pub application_id: String,
    pub primitive: String,
    pub capability_fingerprint: Vec<u8>,
    pub attachment_version_ids: Vec<Uuid>,
    pub approval_id: Option<Uuid>,
    pub state: String,
    pub request_bytes: i64,
    pub response_bytes: i64,
    pub reason_code: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub duration_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpRateDecision {
    pub allowed: bool,
    pub used: i64,
    pub limit: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpRevocationGenerations {
    pub principal: i64,
    pub registration: i64,
    pub credential: i64,
    pub admin_block: i64,
}

impl Database {
    pub async fn mcp_create_approval_rule(
        &self,
        input: &NewMcpApprovalRule<'_>,
    ) -> Result<(), DatabaseError> {
        if !(1..=3_600).contains(&input.lifetime_seconds)
            || !matches!(
                input.primitive,
                "resource_read" | "prompt_get" | "tool_call"
            )
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        insert_approval_rule(&mut transaction, input).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mcp_begin_oauth_attempt(
        &self,
        input: &NewMcpOAuthAttempt<'_>,
    ) -> Result<(), DatabaseError> {
        if input.state_digest.len() != 32
            || input.ciphertext.is_empty()
            || input.wrapped_dek.is_empty()
            || input.kek_generation <= 0
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query_scalar::<_, i64>("SELECT credential_generation FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND credential_generation=$4 AND revoked_at IS NULL AND deleted_at IS NULL FOR SHARE")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .bind(input.owner_principal_id)
            .bind(input.credential_generation)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        sqlx::query("INSERT INTO filebelt_mcp.oauth_attempts (tenant_id,id,registration_id,owner_principal_id,session_id,state_digest,credential_generation,issuer,redirect_path,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,statement_timestamp(),statement_timestamp()+interval '10 minutes')")
            .bind(input.tenant_id).bind(input.id).bind(input.registration_id)
            .bind(input.owner_principal_id).bind(input.session_id).bind(input.state_digest)
            .bind(input.credential_generation).bind(input.issuer).bind(input.redirect_path)
            .execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO filebelt_mcp_vault.oauth_attempt_secrets (tenant_id,attempt_id,registration_id,owner_principal_id,ciphertext,nonce,wrapped_dek,wrap_nonce,kek_generation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(input.tenant_id).bind(input.id).bind(input.registration_id)
            .bind(input.owner_principal_id).bind(input.ciphertext).bind(input.nonce.as_slice())
            .bind(input.wrapped_dek).bind(input.wrap_nonce.as_slice()).bind(input.kek_generation)
            .execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mcp_consume_oauth_attempt(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        state_digest: &[u8],
    ) -> Result<McpOAuthAttemptSecret, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query("UPDATE filebelt_mcp.oauth_attempts o SET consumed_at=clock_timestamp() FROM filebelt_mcp.registrations r WHERE o.tenant_id=$1 AND o.session_id=$2 AND o.state_digest=$3 AND o.consumed_at IS NULL AND o.expires_at>clock_timestamp() AND r.tenant_id=o.tenant_id AND r.id=o.registration_id AND r.owner_principal_id=o.owner_principal_id AND r.credential_generation=o.credential_generation AND r.revoked_at IS NULL AND r.deleted_at IS NULL RETURNING o.id,o.registration_id,o.owner_principal_id,o.issuer,o.redirect_path")
            .bind(tenant_id).bind(session_id).bind(state_digest)
            .fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::NotFound)?;
        let attempt_id: Uuid = row.get("id");
        let secret = sqlx::query("SELECT ciphertext,nonce,wrapped_dek,wrap_nonce,kek_generation FROM filebelt_mcp_vault.oauth_attempt_secrets WHERE tenant_id=$1 AND attempt_id=$2")
            .bind(tenant_id).bind(attempt_id).fetch_one(&mut *transaction).await?;
        sqlx::query("DELETE FROM filebelt_mcp_vault.oauth_attempt_secrets WHERE tenant_id=$1 AND attempt_id=$2")
            .bind(tenant_id).bind(attempt_id).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(McpOAuthAttemptSecret {
            registration_id: row.get("registration_id"),
            owner_principal_id: row.get("owner_principal_id"),
            issuer: row.get("issuer"),
            redirect_path: row.get("redirect_path"),
            ciphertext: secret.get("ciphertext"),
            nonce: secret.get("nonce"),
            wrapped_dek: secret.get("wrapped_dek"),
            wrap_nonce: secret.get("wrap_nonce"),
            kek_generation: secret.get("kek_generation"),
        })
    }

    pub async fn mcp_oauth_attempt_registration(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        state_digest: &[u8; 32],
    ) -> Result<Uuid, DatabaseError> {
        sqlx::query_scalar("SELECT o.registration_id FROM filebelt_mcp.oauth_attempts o JOIN filebelt_mcp.registrations r ON r.tenant_id=o.tenant_id AND r.id=o.registration_id AND r.owner_principal_id=o.owner_principal_id AND r.credential_generation=o.credential_generation WHERE o.tenant_id=$1 AND o.session_id=$2 AND o.state_digest=$3 AND o.consumed_at IS NULL AND o.expires_at>clock_timestamp() AND r.revoked_at IS NULL AND r.deleted_at IS NULL")
            .bind(tenant_id)
            .bind(session_id)
            .bind(state_digest.as_slice())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mcp_create_invocation_intent(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        registration_id: Uuid,
        principal_id: Uuid,
        session_id: Uuid,
        application_id: &str,
        primitive: &str,
        capability_fingerprint: &[u8; 32],
        argument_digest: &[u8; 32],
        attachment_digest: &[u8; 32],
        request_digest: &[u8; 32],
    ) -> Result<(), DatabaseError> {
        if !matches!(primitive, "resource_read" | "prompt_get" | "tool_call") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query("INSERT INTO filebelt_mcp.invocation_intents (tenant_id,id,registration_id,principal_id,session_id,application_id,primitive,capability_fingerprint,argument_digest,attachment_digest,request_digest,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,statement_timestamp(),statement_timestamp()+interval '5 minutes')")
            .bind(tenant_id).bind(id).bind(registration_id).bind(principal_id)
            .bind(session_id).bind(application_id).bind(primitive)
            .bind(capability_fingerprint.as_slice()).bind(argument_digest.as_slice())
            .bind(attachment_digest.as_slice()).bind(request_digest.as_slice())
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn mcp_invocation_intent_for_approval(
        &self,
        tenant_id: Uuid,
        intent_id: Uuid,
        principal_id: Uuid,
        session_id: Uuid,
    ) -> Result<McpInvocationIntentApprovalContext, DatabaseError> {
        let row = sqlx::query("SELECT registration_id,application_id,primitive,capability_fingerprint,argument_digest,attachment_digest FROM filebelt_mcp.invocation_intents WHERE tenant_id=$1 AND id=$2 AND principal_id=$3 AND session_id=$4 AND consumed_at IS NULL AND expires_at>clock_timestamp()")
            .bind(tenant_id).bind(intent_id).bind(principal_id).bind(session_id)
            .fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(McpInvocationIntentApprovalContext {
            registration_id: row.get("registration_id"),
            application_id: row.get("application_id"),
            primitive: row.get("primitive"),
            capability_fingerprint: row.get("capability_fingerprint"),
            argument_digest: row.get("argument_digest"),
            attachment_digest: row.get("attachment_digest"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mcp_consume_invocation_intent(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        principal_id: Uuid,
        session_id: Uuid,
        application_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<Uuid, DatabaseError> {
        sqlx::query_scalar("UPDATE filebelt_mcp.invocation_intents SET consumed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND principal_id=$3 AND session_id=$4 AND application_id=$5 AND request_digest=$6 AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING registration_id")
            .bind(tenant_id).bind(id).bind(principal_id).bind(session_id)
            .bind(application_id).bind(request_digest.as_slice())
            .fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)
    }

    pub async fn mcp_start_invocation(
        &self,
        input: &NewMcpInvocation<'_>,
    ) -> Result<(), DatabaseError> {
        let semantic_context_is_complete = matches!(
            (
                input.semantic_node_id,
                input.semantic_base_version_id,
                input.semantic_input_digest,
            ),
            (None, None, None) | (Some(_), Some(_), Some(_))
        );
        if input.request_bytes < 0
            || !matches!(
                input.primitive,
                "resource_read" | "prompt_get" | "tool_call"
            )
            || !semantic_context_is_complete
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO filebelt_mcp.policy_generations (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(input.tenant_id)
            .execute(&mut *transaction)
            .await?;
        let block_generation: i64 = sqlx::query_scalar("SELECT admin_block_generation FROM filebelt_mcp.policy_generations WHERE tenant_id=$1 FOR SHARE")
            .bind(input.tenant_id)
            .fetch_one(&mut *transaction)
            .await?;
        if block_generation != input.admin_block_generation {
            return Err(DatabaseError::StaleGeneration);
        }
        let inserted = sqlx::query("INSERT INTO filebelt_mcp.invocations (tenant_id,id,registration_id,principal_id,application_id,primitive,capability_fingerprint,approval_id,registration_generation,authority_generation,admin_block_generation,state,request_bytes,semantic_node_id,semantic_base_version_id,semantic_input_digest,started_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'running',$12,$13,$14,$15,clock_timestamp() FROM filebelt_mcp.registrations r JOIN public.principals p ON p.tenant_id=r.tenant_id AND p.id=$4 WHERE r.tenant_id=$1 AND r.id=$3 AND r.enabled AND r.revocation_generation=$9 AND r.revoked_at IS NULL AND r.deleted_at IS NULL AND p.generation=$10 AND p.disabled_at IS NULL")
            .bind(input.tenant_id).bind(input.id).bind(input.registration_id)
            .bind(input.principal_id).bind(input.application_id).bind(input.primitive)
            .bind(input.capability_fingerprint.as_slice()).bind(input.approval_id)
            .bind(input.registration_generation).bind(input.authority_generation)
            .bind(input.admin_block_generation).bind(input.request_bytes)
            .bind(input.semantic_node_id).bind(input.semantic_base_version_id)
            .bind(input.semantic_input_digest.map(AsRef::as_ref))
            .execute(&mut *transaction).await?.rows_affected();
        if inserted != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mcp_finish_invocation(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        state: &str,
        response_bytes: i64,
        reason_code: Option<&str>,
        semantic_output_digest: Option<&[u8; 32]>,
    ) -> Result<(), DatabaseError> {
        if response_bytes < 0
            || !matches!(
                state,
                "succeeded" | "denied" | "failed" | "cancelled" | "interrupted"
            )
            || semantic_output_digest.is_some() && state != "succeeded"
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let affected = sqlx::query("UPDATE filebelt_mcp.invocations SET state=$3,response_bytes=$4,reason_code=$5,semantic_output_digest=$6,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state IN ('pending','running')")
            .bind(tenant_id).bind(id).bind(state).bind(response_bytes).bind(reason_code)
            .bind(semantic_output_digest.map(AsRef::as_ref))
            .execute(&self.pool).await?.rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(DatabaseError::Conflict)
        }
    }

    /// Resolves a Markdown proposal's target only when its claimed immutable
    /// base version belongs to that exact live file node. Authorization stays
    /// in the API layer; this method deliberately returns no source bytes.
    pub async fn mcp_markdown_context_drive(
        &self,
        tenant_id: Uuid,
        node_id: Uuid,
        base_version_id: Uuid,
    ) -> Result<Uuid, DatabaseError> {
        sqlx::query_scalar(
            "SELECT n.drive_id FROM public.nodes n JOIN public.file_versions v \
             ON v.tenant_id=n.tenant_id AND v.node_id=n.id \
             WHERE n.tenant_id=$1 AND n.id=$2 AND n.kind='file' \
               AND n.trash_root_id IS NULL AND v.id=$3",
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(base_version_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DatabaseError::NotFound)
    }

    pub async fn mcp_activity(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        limit: i64,
    ) -> Result<Vec<McpActivityRecord>, DatabaseError> {
        if !(1..=200).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        Ok(sqlx::query("SELECT i.id,i.registration_id,i.principal_id,i.application_id,i.primitive,i.capability_fingerprint,i.approval_id,i.state,i.request_bytes,i.response_bytes,i.reason_code,i.created_at::text AS created_at,i.finished_at::text AS finished_at,COALESCE((SELECT array_agg(a.version_id ORDER BY a.ordinal) FROM filebelt_mcp.invocation_attachments a WHERE a.tenant_id=i.tenant_id AND a.invocation_id=i.id),ARRAY[]::uuid[]) AS attachment_version_ids,COALESCE((EXTRACT(EPOCH FROM (i.finished_at-i.started_at))*1000)::bigint,0) AS duration_ms FROM filebelt_mcp.invocations i WHERE i.tenant_id=$1 AND i.principal_id=$2 ORDER BY i.created_at DESC,i.id LIMIT $3")
            .bind(tenant_id).bind(principal_id).bind(limit).fetch_all(&self.pool).await?
            .iter().map(activity_from_row).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mcp_take_rate_limit(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        bucket: &str,
        window_epoch_seconds: i64,
        window_seconds: i64,
        cost: i64,
        limit: i64,
    ) -> Result<McpRateDecision, DatabaseError> {
        if bucket.is_empty() || window_seconds <= 0 || cost <= 0 || limit <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let used: i64 = sqlx::query_scalar("INSERT INTO filebelt_mcp.rate_buckets (tenant_id,principal_id,bucket,window_started_at,used,limit_value,expires_at) VALUES ($1,$2,$3,to_timestamp($4),$5,$6,to_timestamp($4)+make_interval(secs=>$7)) ON CONFLICT (tenant_id,principal_id,bucket,window_started_at) DO UPDATE SET used=filebelt_mcp.rate_buckets.used+EXCLUDED.used,limit_value=EXCLUDED.limit_value,expires_at=EXCLUDED.expires_at RETURNING used")
            .bind(tenant_id).bind(principal_id).bind(bucket).bind(window_epoch_seconds)
            .bind(cost).bind(limit).bind(window_seconds).fetch_one(&self.pool).await?;
        Ok(McpRateDecision {
            allowed: used <= limit,
            used,
            limit,
        })
    }

    pub async fn mcp_revocation_generations(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        registration_id: Uuid,
    ) -> Result<McpRevocationGenerations, DatabaseError> {
        sqlx::query("INSERT INTO filebelt_mcp.policy_generations (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        let row = sqlx::query("SELECT p.generation AS principal,r.revocation_generation AS registration,r.credential_generation AS credential,g.admin_block_generation FROM public.principals p JOIN filebelt_mcp.registrations r ON r.tenant_id=p.tenant_id AND r.id=$3 JOIN filebelt_mcp.policy_generations g ON g.tenant_id=r.tenant_id WHERE p.tenant_id=$1 AND p.id=$2 AND p.disabled_at IS NULL AND r.revoked_at IS NULL AND r.deleted_at IS NULL")
            .bind(tenant_id).bind(principal_id).bind(registration_id)
            .fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(McpRevocationGenerations {
            principal: row.get("principal"),
            registration: row.get("registration"),
            credential: row.get("credential"),
            admin_block: row.get("admin_block_generation"),
        })
    }

    pub async fn mcp_invocation_is_active(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        invocation_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM filebelt_mcp.invocations WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 AND state IN ('pending','running'))")
            .bind(tenant_id)
            .bind(principal_id)
            .bind(invocation_id)
            .fetch_one(&self.pool)
            .await?)
    }
}

pub(super) async fn insert_approval_rule(
    transaction: &mut Transaction<'_, Postgres>,
    input: &NewMcpApprovalRule<'_>,
) -> Result<(), DatabaseError> {
    sqlx::query("INSERT INTO filebelt_mcp.approval_rules (tenant_id,id,registration_id,principal_id,intent_id,session_id,application_id,primitive,capability_name,capability_fingerprint,argument_digest,attachment_digest,single_use,created_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,statement_timestamp(),statement_timestamp()+make_interval(secs=>$14) FROM filebelt_mcp.invocation_intents i WHERE i.tenant_id=$1 AND i.id=$5 AND i.registration_id=$3 AND i.principal_id=$4 AND i.consumed_at IS NULL AND i.expires_at>clock_timestamp()")
        .bind(input.tenant_id)
        .bind(input.id)
        .bind(input.registration_id)
        .bind(input.principal_id)
        .bind(input.intent_id)
        .bind(input.session_id)
        .bind(input.application_id)
        .bind(input.primitive)
        .bind(input.capability_name)
        .bind(input.capability_fingerprint.as_slice())
        .bind(input.argument_digest.as_slice())
        .bind(input.attachment_digest.as_slice())
        .bind(input.single_use)
        .bind(input.lifetime_seconds)
        .execute(&mut **transaction)
        .await?
        .rows_affected()
        .eq(&1)
        .then_some(())
        .ok_or(DatabaseError::NotFound)
}

fn activity_from_row(row: &sqlx::postgres::PgRow) -> McpActivityRecord {
    McpActivityRecord {
        id: row.get("id"),
        registration_id: row.get("registration_id"),
        principal_id: row.get("principal_id"),
        application_id: row.get("application_id"),
        primitive: row.get("primitive"),
        capability_fingerprint: row.get("capability_fingerprint"),
        attachment_version_ids: row.get("attachment_version_ids"),
        approval_id: row.get("approval_id"),
        state: row.get("state"),
        request_bytes: row.get("request_bytes"),
        response_bytes: row.get("response_bytes"),
        reason_code: row.get("reason_code"),
        created_at: row.get("created_at"),
        finished_at: row.get("finished_at"),
        duration_ms: row.get("duration_ms"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn activity_record_contains_only_safe_metadata() {
        let source = include_str!("invocation.rs");
        let production = source.split("#[cfg(test)]").next().expect("source prefix");
        for prohibited in [
            "arguments: Value",
            "result: Value",
            "filename: String",
            "stderr: String",
        ] {
            assert!(!production.contains(prohibited));
        }
    }

    #[test]
    fn semantic_provenance_persists_context_and_digests_but_not_markdown() {
        let source = include_str!("invocation.rs");
        let production = source.split("#[cfg(test)]").next().expect("source prefix");
        for required in [
            "semantic_node_id",
            "semantic_base_version_id",
            "semantic_input_digest",
            "semantic_output_digest",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
        assert!(!production.contains("semantic_markdown: String"));
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Broker-owned durable replay for management operations and safe probes.

use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::invocation::NewMcpOAuthAttempt;
use super::management::RegistrationConfigurationUpdate;
use super::{
    Database, DatabaseError, McpCredentialMetadata, McpRegistrationRecord, McpSecretEnvelope,
    credential_metadata_from_row, registration_from_row, validate_secret_envelope,
};

#[derive(Clone, Debug)]
pub struct McpBrokerOperationIdempotency<'a> {
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub registration_id: Uuid,
    pub operation: &'a str,
    pub operation_id: Uuid,
    pub request_fingerprint: &'a [u8; 32],
}

#[derive(Debug)]
pub enum McpBrokerOperationStart {
    Started(McpBrokerOperationTransaction),
    Replayed(Value),
    KeyReused,
}

#[derive(Debug)]
pub struct McpBrokerOperationTransaction {
    transaction: Transaction<'static, Postgres>,
    tenant_id: Uuid,
    principal_id: Uuid,
    registration_id: Uuid,
    operation: String,
    operation_id: Uuid,
    request_fingerprint: [u8; 32],
}

impl Database {
    pub async fn mcp_begin_broker_operation(
        &self,
        input: &McpBrokerOperationIdempotency<'_>,
    ) -> Result<McpBrokerOperationStart, DatabaseError> {
        validate_operation(input.operation)?;
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query("INSERT INTO filebelt_mcp.broker_operation_receipts (tenant_id,principal_id,registration_id,operation,operation_id,request_fingerprint) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
            .bind(input.tenant_id)
            .bind(input.principal_id)
            .bind(input.registration_id)
            .bind(input.operation)
            .bind(input.operation_id)
            .bind(input.request_fingerprint.as_slice())
            .execute(&mut *transaction)
            .await?
            .rows_affected()
            == 1;
        let row = sqlx::query("SELECT registration_id,operation,request_fingerprint,result,api_completed_at IS NOT NULL AS api_completed,expires_at<=clock_timestamp() AS expired FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3 FOR UPDATE")
            .bind(input.tenant_id)
            .bind(input.principal_id)
            .bind(input.operation_id)
            .fetch_one(&mut *transaction)
            .await?;
        if row.get::<bool, _>("expired") && row.get::<bool, _>("api_completed") {
            sqlx::query("UPDATE filebelt_mcp.broker_operation_receipts SET registration_id=$4,operation=$5,request_fingerprint=$6,result=NULL,api_completed_at=NULL,created_at=clock_timestamp(),expires_at=clock_timestamp()+interval '24 hours' WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3")
                .bind(input.tenant_id)
                .bind(input.principal_id)
                .bind(input.operation_id)
                .bind(input.registration_id)
                .bind(input.operation)
                .bind(input.request_fingerprint.as_slice())
                .execute(&mut *transaction)
                .await?;
            return Ok(McpBrokerOperationStart::Started(
                McpBrokerOperationTransaction::new(transaction, input),
            ));
        }
        if row.get::<Uuid, _>("registration_id") != input.registration_id
            || row.get::<String, _>("operation") != input.operation
            || row.get::<Vec<u8>, _>("request_fingerprint").as_slice() != input.request_fingerprint
        {
            transaction.commit().await?;
            return Ok(McpBrokerOperationStart::KeyReused);
        }
        if inserted {
            return Ok(McpBrokerOperationStart::Started(
                McpBrokerOperationTransaction::new(transaction, input),
            ));
        }
        let result: Option<Value> = row.get("result");
        let result = result.ok_or(DatabaseError::Conflict)?;
        transaction.commit().await?;
        Ok(McpBrokerOperationStart::Replayed(result))
    }

    pub async fn purge_mcp_broker_operation_receipts(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<u64, DatabaseError> {
        if !(1..=1_000).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let removed = sqlx::query("DELETE FROM filebelt_mcp.broker_operation_receipts WHERE ctid IN (SELECT ctid FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND result IS NOT NULL AND api_completed_at IS NOT NULL AND expires_at<=clock_timestamp() ORDER BY expires_at,operation_id LIMIT $2 FOR UPDATE SKIP LOCKED)")
            .bind(tenant_id)
            .bind(limit)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(removed)
    }
}

impl McpBrokerOperationTransaction {
    fn new(
        transaction: Transaction<'static, Postgres>,
        input: &McpBrokerOperationIdempotency<'_>,
    ) -> Self {
        Self {
            transaction,
            tenant_id: input.tenant_id,
            principal_id: input.principal_id,
            registration_id: input.registration_id,
            operation: input.operation.to_owned(),
            operation_id: input.operation_id,
            request_fingerprint: *input.request_fingerprint,
        }
    }

    pub async fn configure_registration(
        &mut self,
        input: &RegistrationConfigurationUpdate<'_>,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        self.ensure_registration(
            input.tenant_id,
            input.owner_principal_id,
            input.registration_id,
        )?;
        if self.operation != "registration_configure"
            || input.display_name.is_empty()
            || input.display_name.len() > 255
            || input.description.len() > 1000
            || !input.policy.is_object()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
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
            .execute(&mut *self.transaction)
            .await?;
        let row = sqlx::query("SELECT *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND deleted_at IS NULL")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .bind(input.owner_principal_id)
            .fetch_one(&mut *self.transaction)
            .await?;
        registration_from_row(&row)
    }

    pub async fn replace_registration_secret(
        &mut self,
        envelope: &McpSecretEnvelope,
    ) -> Result<McpCredentialMetadata, DatabaseError> {
        self.ensure_registration(
            envelope.tenant_id,
            envelope.owner_principal_id,
            envelope.registration_id,
        )?;
        if self.operation != "credential_replace" {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        validate_secret_envelope(envelope)?;
        let current_generation: i64 = sqlx::query_scalar("SELECT credential_generation FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND revoked_at IS NULL AND deleted_at IS NULL FOR UPDATE")
            .bind(envelope.tenant_id)
            .bind(envelope.registration_id)
            .bind(envelope.owner_principal_id)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        if current_generation.checked_add(1) != Some(envelope.credential_generation) {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query("DELETE FROM filebelt_mcp.oauth_attempts WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3")
            .bind(envelope.tenant_id)
            .bind(envelope.registration_id)
            .bind(envelope.owner_principal_id)
            .execute(&mut *self.transaction)
            .await?;
        sqlx::query("DELETE FROM filebelt_mcp_vault.secret_envelopes WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3")
            .bind(envelope.tenant_id)
            .bind(envelope.registration_id)
            .bind(envelope.owner_principal_id)
            .execute(&mut *self.transaction)
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
            .fetch_optional(&mut *self.transaction)
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
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        if advanced != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        Ok(credential_metadata_from_row(&row))
    }

    pub async fn erase_registration_at_revision(
        &mut self,
        expected_revision: i64,
    ) -> Result<McpRegistrationRecord, DatabaseError> {
        if self.operation != "credential_erase" {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar::<_, i64>("SELECT credential_generation FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND revision=$4 AND deleted_at IS NULL FOR UPDATE")
            .bind(self.tenant_id)
            .bind(self.registration_id)
            .bind(self.principal_id)
            .bind(expected_revision)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::Conflict)?;
        sqlx::query("DELETE FROM filebelt_mcp.oauth_attempts WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3")
            .bind(self.tenant_id)
            .bind(self.registration_id)
            .bind(self.principal_id)
            .execute(&mut *self.transaction)
            .await?;
        sqlx::query("DELETE FROM filebelt_mcp_vault.secret_envelopes WHERE tenant_id=$1 AND registration_id=$2 AND owner_principal_id=$3")
            .bind(self.tenant_id)
            .bind(self.registration_id)
            .bind(self.principal_id)
            .execute(&mut *self.transaction)
            .await?;
        let row = sqlx::query("UPDATE filebelt_mcp.registrations SET enabled=false,authentication_state='required',capability_state='undiscovered',protocol_version=NULL,credential_kind='none',revocation_generation=revocation_generation+1,credential_generation=credential_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND revision=$4 RETURNING *,revoked_at IS NOT NULL AS is_revoked,created_at::text AS created_at_text,updated_at::text AS updated_at_text")
            .bind(self.tenant_id)
            .bind(self.registration_id)
            .bind(self.principal_id)
            .bind(expected_revision)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        registration_from_row(&row)
    }

    pub async fn begin_oauth_attempt(
        &mut self,
        input: &NewMcpOAuthAttempt<'_>,
    ) -> Result<i64, DatabaseError> {
        self.ensure_registration(
            input.tenant_id,
            input.owner_principal_id,
            input.registration_id,
        )?;
        if self.operation != "oauth_begin"
            || input.state_digest.len() != 32
            || input.ciphertext.is_empty()
            || input.wrapped_dek.is_empty()
            || input.kek_generation <= 0
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar::<_, i64>("SELECT credential_generation FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND credential_generation=$4 AND revoked_at IS NULL AND deleted_at IS NULL FOR SHARE")
            .bind(input.tenant_id)
            .bind(input.registration_id)
            .bind(input.owner_principal_id)
            .bind(input.credential_generation)
            .fetch_optional(&mut *self.transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        let expires_at: i64 = sqlx::query_scalar("INSERT INTO filebelt_mcp.oauth_attempts (tenant_id,id,registration_id,owner_principal_id,session_id,state_digest,credential_generation,issuer,redirect_path,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,statement_timestamp(),statement_timestamp()+interval '10 minutes') RETURNING extract(epoch FROM expires_at)::bigint")
            .bind(input.tenant_id)
            .bind(input.id)
            .bind(input.registration_id)
            .bind(input.owner_principal_id)
            .bind(input.session_id)
            .bind(input.state_digest)
            .bind(input.credential_generation)
            .bind(input.issuer)
            .bind(input.redirect_path)
            .fetch_one(&mut *self.transaction)
            .await?;
        sqlx::query("INSERT INTO filebelt_mcp_vault.oauth_attempt_secrets (tenant_id,attempt_id,registration_id,owner_principal_id,ciphertext,nonce,wrapped_dek,wrap_nonce,kek_generation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(input.tenant_id)
            .bind(input.id)
            .bind(input.registration_id)
            .bind(input.owner_principal_id)
            .bind(input.ciphertext)
            .bind(input.nonce.as_slice())
            .bind(input.wrapped_dek)
            .bind(input.wrap_nonce.as_slice())
            .bind(input.kek_generation)
            .execute(&mut *self.transaction)
            .await?;
        Ok(expires_at)
    }

    pub async fn finalize(mut self, result: &Value) -> Result<(), DatabaseError> {
        validate_safe_result(
            &self.operation,
            self.tenant_id,
            self.principal_id,
            self.registration_id,
            result,
        )?;
        let updated = sqlx::query("UPDATE filebelt_mcp.broker_operation_receipts SET result=$7 WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3 AND registration_id=$4 AND operation=$5 AND request_fingerprint=$6 AND result IS NULL")
            .bind(self.tenant_id)
            .bind(self.principal_id)
            .bind(self.operation_id)
            .bind(self.registration_id)
            .bind(&self.operation)
            .bind(self.request_fingerprint.as_slice())
            .bind(result)
            .execute(&mut *self.transaction)
            .await?
            .rows_affected();
        if updated != 1 {
            return Err(DatabaseError::Conflict);
        }
        self.transaction.commit().await?;
        Ok(())
    }

    fn ensure_registration(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        registration_id: Uuid,
    ) -> Result<(), DatabaseError> {
        if self.tenant_id == tenant_id
            && self.principal_id == principal_id
            && self.registration_id == registration_id
        {
            Ok(())
        } else {
            Err(DatabaseError::InvalidPersistedValue)
        }
    }
}

fn validate_operation(operation: &str) -> Result<(), DatabaseError> {
    if matches!(
        operation,
        "registration_configure"
            | "credential_replace"
            | "credential_erase"
            | "oauth_begin"
            | "test"
            | "discover"
    ) {
        Ok(())
    } else {
        Err(DatabaseError::InvalidPersistedValue)
    }
}

fn validate_safe_result(
    operation: &str,
    tenant_id: Uuid,
    principal_id: Uuid,
    registration_id: Uuid,
    result: &Value,
) -> Result<(), DatabaseError> {
    let object = result
        .as_object()
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    match operation {
        "registration_configure" | "credential_erase" => {
            let registration: McpRegistrationRecord = serde_json::from_value(result.clone())
                .map_err(|_| DatabaseError::InvalidPersistedValue)?;
            if registration.tenant_id != tenant_id
                || registration.owner_principal_id != principal_id
                || registration.id != registration_id
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
        }
        "credential_replace" => {
            if object.len() != 2
                || object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "revision" | "credential_generation"))
                || object
                    .values()
                    .any(|value| value.as_i64().is_none_or(|value| value <= 0))
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
        }
        "oauth_begin" => {
            if object.len() != 5
                || object.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "issuer"
                            | "authorization_endpoint"
                            | "client_id"
                            | "resource"
                            | "expires_at"
                    )
                })
                || object.get("expires_at").and_then(Value::as_i64).is_none()
                || ["issuer", "authorization_endpoint", "client_id", "resource"]
                    .iter()
                    .any(|key| {
                        object
                            .get(*key)
                            .and_then(Value::as_str)
                            .is_none_or(|value| value.is_empty() || value.len() > 4_096)
                    })
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
        }
        "test" => {
            if object.len() != 3
                || object.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "protocol_version" | "checked_at" | "duration_ms"
                    )
                })
                || object
                    .get("protocol_version")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.is_empty() || value.len() > 64)
                || object.get("checked_at").and_then(Value::as_i64).is_none()
                || object
                    .get("duration_ms")
                    .and_then(Value::as_u64)
                    .is_none_or(|value| value > 120_000)
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
        }
        "discover" => {
            if object.len() != 2
                || object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "protocol_version" | "document"))
                || object
                    .get("protocol_version")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.is_empty() || value.len() > 64)
                || object
                    .get("document")
                    .is_none_or(|value| !value.is_object())
                || serde_json::to_vec(result)
                    .map_err(|_| DatabaseError::InvalidPersistedValue)?
                    .len()
                    > 16 * 1_024 * 1_024
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
        }
        _ => return Err(DatabaseError::InvalidPersistedValue),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn oauth_receipts_reject_bearer_material() {
        let id = Uuid::new_v4();
        for forbidden in ["state", "verifier", "authorization_url", "access_token"] {
            let mut result = json!({
                "issuer": "https://issuer.example",
                "authorization_endpoint": "https://issuer.example/authorize",
                "client_id": "client",
                "resource": "https://mcp.example/rpc",
                "expires_at": 1_800_000_000_i64,
            });
            result
                .as_object_mut()
                .unwrap()
                .insert(forbidden.into(), Value::String("secret".into()));
            assert!(validate_safe_result("oauth_begin", id, id, id, &result).is_err());
        }
    }

    #[test]
    fn operation_results_are_exactly_typed() {
        let id = Uuid::new_v4();
        assert!(
            validate_safe_result(
                "credential_replace",
                id,
                id,
                id,
                &json!({"revision":2,"credential_generation":2}),
            )
            .is_ok()
        );
        assert!(
            validate_safe_result(
                "credential_replace",
                id,
                id,
                id,
                &json!({"revision":2,"credential_generation":2,"secret":"no"}),
            )
            .is_err()
        );
        assert!(
            validate_safe_result(
                "test",
                id,
                id,
                id,
                &json!({
                    "protocol_version":"2026-07-28",
                    "checked_at":1_800_000_000_i64,
                    "duration_ms":12,
                }),
            )
            .is_ok()
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Authoritative mount credential, device, gateway, and session mechanics.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row as _;
use uuid::Uuid;

use super::{Database, DatabaseError, insert_audit, insert_outbox, map_conflict};

#[derive(Clone, Debug)]
pub struct MountSecretEnvelopeInput<'a> {
    pub ciphertext: &'a [u8],
    pub nonce: &'a [u8; 12],
    pub wrapped_dek: &'a [u8],
    pub wrap_nonce: &'a [u8; 12],
    pub kek_generation: i32,
    pub aad_digest: &'a [u8; 32],
    pub aad_version: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountCredentialRecord {
    pub id: Uuid,
    pub principal_id: Uuid,
    pub protocol: String,
    pub username: String,
    pub verifier_kind: String,
    pub credential_generation: i64,
    pub authorization_generation: i64,
    pub read_only: bool,
    pub allowed_drive_ids: Vec<Uuid>,
    pub bound_device_id: Option<Uuid>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MountAuthenticationMaterial {
    pub credential: MountCredentialRecord,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: [u8; 12],
    pub kek_generation: i32,
    pub aad_digest: [u8; 32],
    pub aad_version: i32,
}

#[derive(Clone, Debug)]
pub struct MountSessionFence {
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub user_principal_id: Uuid,
    pub credential_id: Uuid,
    pub protocol: String,
    pub credential_generation: i64,
    pub authorization_generation: i64,
    pub membership_generation: i64,
    pub gateway_epoch: i64,
    pub read_only: bool,
    pub allowed_drive_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountDeviceRecord {
    pub id: Uuid,
    pub principal_id: Uuid,
    pub headscale_node_id: String,
    pub display_name: String,
    pub tailnet_addresses: Vec<String>,
    pub node_tags: Vec<String>,
    pub capability_version: String,
    pub ownership_generation: i64,
    pub observed_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MountDeviceObservation {
    pub principal_id: Uuid,
    pub headscale_node_id: String,
    pub issuer: String,
    pub subject: String,
    pub display_name: String,
    pub addresses: Vec<String>,
    pub tags: Vec<String>,
    pub capability_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountSessionSummary {
    pub id: Uuid,
    pub protocol: String,
    pub gateway_id: String,
    pub source_address: String,
    pub state: String,
    pub created_at: String,
    pub last_activity_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    pub close_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MountHandleRecord {
    pub id: Uuid,
    pub session_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub version_id: Option<Uuid>,
    pub access_actions: Vec<String>,
    pub credential_generation: i64,
    pub authorization_generation: i64,
    pub membership_generation: i64,
    pub drive_acl_generation: i64,
    pub namespace_generation: i64,
    pub resource_acl_generation: i64,
    pub gateway_epoch: i64,
}

#[derive(Clone, Debug)]
pub struct MountReadCapabilityFence {
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub mount_session_id: Uuid,
    pub credential_id: Uuid,
    pub handle_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub version_id: Uuid,
    pub credential_generation: i64,
    pub authorization_generation: i64,
    pub membership_generation: i64,
    pub drive_acl_generation: i64,
    pub namespace_generation: i64,
    pub resource_acl_generation: i64,
    pub gateway_epoch: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountPolicyRecord {
    pub protocol: String,
    pub enabled: bool,
    pub read_only: bool,
    pub allowed_drive_ids: Vec<Uuid>,
    pub authorization_generation: i64,
    pub revision: i64,
    pub updated_at: String,
}

/// One explicit Kerberos-to-FileBelt projection used by the NFS gateway.
/// Numeric POSIX projections remain compatibility metadata; callers must still
/// evaluate the current Virtual ACL before every filesystem operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NfsPrincipalMapping {
    pub kerberos_principal: String,
    pub principal_id: Uuid,
    pub credential_id: Uuid,
    pub projected_uid: i64,
    pub projected_gid: i64,
    pub generation: i64,
}

#[derive(Clone, Debug)]
pub struct UpsertNfsPrincipalMappingInput<'a> {
    pub tenant_id: Uuid,
    pub actor_principal_id: Uuid,
    pub principal_id: Uuid,
    pub kerberos_principal: &'a str,
    pub projected_uid: i64,
    pub projected_gid: i64,
    pub allowed_drive_ids: &'a [Uuid],
    pub expected_generation: Option<i64>,
}

impl Database {
    /// Lists active NFS identity projections for tenant-administrator review.
    pub async fn list_nfs_principal_mappings(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<NfsPrincipalMapping>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT kerberos_principal,principal_id,credential_id,projected_uid,projected_gid,generation \
             FROM filebelt_mount.nfs_principal_mappings WHERE tenant_id=$1 AND revoked_at IS NULL \
             ORDER BY kerberos_principal,principal_id",
        )
        .bind(tenant_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .iter()
            .map(|row| NfsPrincipalMapping {
                kerberos_principal: row.get("kerberos_principal"),
                principal_id: row.get("principal_id"),
                credential_id: row.get("credential_id"),
                projected_uid: row.get("projected_uid"),
                projected_gid: row.get("projected_gid"),
                generation: row.get("generation"),
            })
            .collect())
    }

    /// Creates or generation-fences an explicit Kerberos identity projection.
    /// No keytab, password verifier, or AUTH_SYS identity is persisted here.
    pub async fn upsert_nfs_principal_mapping(
        &self,
        input: &UpsertNfsPrincipalMappingInput<'_>,
    ) -> Result<NfsPrincipalMapping, DatabaseError> {
        if input.kerberos_principal.is_empty()
            || input.kerberos_principal.len() > 512
            || input
                .kerberos_principal
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
            || !input.kerberos_principal.contains('@')
            || input.projected_uid <= 0
            || input.projected_gid <= 0
            || input.allowed_drive_ids.is_empty()
            || input.allowed_drive_ids.len() > 256
            || input.expected_generation.is_some_and(|value| value <= 0)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let target_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM principals p JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.id \
             WHERE p.tenant_id=$1 AND p.id=$2 AND p.kind='user' AND p.disabled_at IS NULL AND u.status='active')",
        )
        .bind(input.tenant_id)
        .bind(input.principal_id)
        .fetch_one(&mut *transaction)
        .await?;
        let drive_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM drives WHERE tenant_id=$1 AND id=ANY($2)")
                .bind(input.tenant_id)
                .bind(input.allowed_drive_ids)
                .fetch_one(&mut *transaction)
                .await?;
        if !target_exists || drive_count != input.allowed_drive_ids.len() as i64 {
            return Err(DatabaseError::NotFound);
        }

        let existing = sqlx::query(
            "SELECT principal_id,credential_id,generation FROM filebelt_mount.nfs_principal_mappings \
             WHERE tenant_id=$1 AND kerberos_principal=$2 FOR UPDATE",
        )
        .bind(input.tenant_id)
        .bind(input.kerberos_principal)
        .fetch_optional(&mut *transaction)
        .await?;
        let credential_id;
        let generation;
        if let Some(row) = existing {
            if row.get::<Uuid, _>("principal_id") != input.principal_id
                || input.expected_generation != Some(row.get::<i64, _>("generation"))
            {
                return Err(DatabaseError::Conflict);
            }
            credential_id = row.get("credential_id");
            generation = sqlx::query_scalar(
                "UPDATE filebelt_mount.nfs_principal_mappings SET projected_uid=$3,projected_gid=$4,generation=generation+1,revoked_at=NULL,updated_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND kerberos_principal=$2 RETURNING generation",
            )
            .bind(input.tenant_id)
            .bind(input.kerberos_principal)
            .bind(input.projected_uid)
            .bind(input.projected_gid)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_conflict)?;
            sqlx::query(
                "UPDATE filebelt_mount.credentials SET allowed_drive_ids=$3,credential_generation=credential_generation+1,authorization_generation=authorization_generation+1,revoked_at=NULL,expires_at=clock_timestamp()+interval '365 days' \
                 WHERE tenant_id=$1 AND id=$2 AND principal_id=$4 AND protocol='nfs'",
            )
            .bind(input.tenant_id)
            .bind(credential_id)
            .bind(input.allowed_drive_ids)
            .bind(input.principal_id)
            .execute(&mut *transaction)
            .await?;
        } else {
            if input.expected_generation.is_some() {
                return Err(DatabaseError::Conflict);
            }
            credential_id = Uuid::new_v4();
            generation = 1;
            sqlx::query(
                "INSERT INTO filebelt_mount.credentials (tenant_id,id,principal_id,protocol,username,verifier_kind,read_only,allowed_drive_ids,expires_at) \
                 VALUES ($1,$2,$3,'nfs',$4,'kerberos_principal',false,$5,clock_timestamp()+interval '365 days')",
            )
            .bind(input.tenant_id)
            .bind(credential_id)
            .bind(input.principal_id)
            .bind(credential_id.to_string())
            .bind(input.allowed_drive_ids)
            .execute(&mut *transaction)
            .await
            .map_err(map_conflict)?;
            sqlx::query(
                "INSERT INTO filebelt_mount.nfs_principal_mappings (tenant_id,kerberos_principal,principal_id,credential_id,projected_uid,projected_gid) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(input.tenant_id)
            .bind(input.kerberos_principal)
            .bind(input.principal_id)
            .bind(credential_id)
            .bind(input.projected_uid)
            .bind(input.projected_gid)
            .execute(&mut *transaction)
            .await
            .map_err(map_conflict)?;
        }
        sqlx::query(
            "INSERT INTO filebelt_mount.policies (tenant_id,principal_id,protocol,enabled,read_only,allowed_drive_ids) \
             VALUES ($1,$2,'nfs',true,false,$3) ON CONFLICT (tenant_id,principal_id,protocol) DO UPDATE SET \
             enabled=true,read_only=false,allowed_drive_ids=EXCLUDED.allowed_drive_ids,authorization_generation=filebelt_mount.policies.authorization_generation+1,revision=filebelt_mount.policies.revision+1,updated_at=clock_timestamp()",
        )
        .bind(input.tenant_id)
        .bind(input.principal_id)
        .bind(input.allowed_drive_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE filebelt_mount.sessions SET state='closed',close_reason='nfs_mapping_changed',last_activity_at=clock_timestamp() WHERE tenant_id=$1 AND user_principal_id=$2 AND protocol='nfs' AND state='active'")
            .bind(input.tenant_id).bind(input.principal_id).execute(&mut *transaction).await?;
        insert_audit(
            &mut transaction,
            input.tenant_id,
            Some(input.actor_principal_id),
            Some(input.principal_id),
            Some(credential_id),
            "mount.nfs.mapping.update",
            "allowed",
            "tenant_admin_mapping",
            false,
            json!({"kerberos_principal":input.kerberos_principal,"projected_uid":input.projected_uid,"projected_gid":input.projected_gid,"generation":generation}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            input.tenant_id,
            "filebelt.v1.mount.nfs.mapping.changed",
            "nfs_mapping",
            credential_id,
            generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(NfsPrincipalMapping {
            kerberos_principal: input.kerberos_principal.to_owned(),
            principal_id: input.principal_id,
            credential_id,
            projected_uid: input.projected_uid,
            projected_gid: input.projected_gid,
            generation,
        })
    }

    pub async fn revoke_nfs_principal_mapping(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        credential_id: Uuid,
        expected_generation: i64,
    ) -> Result<(), DatabaseError> {
        if expected_generation <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query("UPDATE filebelt_mount.nfs_principal_mappings SET revoked_at=clock_timestamp(),generation=generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND credential_id=$2 AND generation=$3 AND revoked_at IS NULL RETURNING principal_id,credential_id,kerberos_principal,generation")
            .bind(tenant_id).bind(credential_id).bind(expected_generation).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::Conflict)?;
        let principal_id: Uuid = row.get("principal_id");
        let credential_id: Uuid = row.get("credential_id");
        let kerberos_principal: String = row.get("kerberos_principal");
        let generation: i64 = row.get("generation");
        sqlx::query("UPDATE filebelt_mount.credentials SET revoked_at=clock_timestamp(),credential_generation=credential_generation+1,authorization_generation=authorization_generation+1 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL")
            .bind(tenant_id).bind(credential_id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE filebelt_mount.policies SET enabled=false,authorization_generation=authorization_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'")
            .bind(tenant_id).bind(principal_id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE filebelt_mount.sessions SET state='closed',close_reason='nfs_mapping_revoked',last_activity_at=clock_timestamp() WHERE tenant_id=$1 AND user_principal_id=$2 AND protocol='nfs' AND state='active'")
            .bind(tenant_id).bind(principal_id).execute(&mut *transaction).await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            Some(principal_id),
            Some(credential_id),
            "mount.nfs.mapping.revoke",
            "allowed",
            "tenant_admin_mapping",
            false,
            json!({"kerberos_principal":kerberos_principal,"generation":generation}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.nfs.mapping.changed",
            "nfs_mapping",
            credential_id,
            generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mount_authentication_throttled(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        principal_key: &[u8; 32],
        source_key: &[u8; 32],
    ) -> Result<bool, DatabaseError> {
        if !matches!(protocol, "smb" | "ftps") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.authentication_throttles \
             WHERE tenant_id=$1 AND protocol=$2 AND principal_key=$3 AND source_key=$4 \
               AND expires_at>clock_timestamp() AND delay_until>clock_timestamp())",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(principal_key.as_slice())
        .bind(source_key.as_slice())
        .fetch_one(self.pool())
        .await
        .map_err(DatabaseError::from)
    }

    pub async fn record_mount_authentication_failure(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        principal_key: &[u8; 32],
        source_key: &[u8; 32],
    ) -> Result<(), DatabaseError> {
        if !matches!(protocol, "smb" | "ftps") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query(
            "INSERT INTO filebelt_mount.authentication_throttles \
             (tenant_id,protocol,principal_key,source_key,failures,delay_until,expires_at) \
             VALUES ($1,$2,$3,$4,1,clock_timestamp()+interval '2 seconds',\
               clock_timestamp()+interval '1 hour') \
             ON CONFLICT (tenant_id,protocol,principal_key,source_key) DO UPDATE SET \
               failures=LEAST(filebelt_mount.authentication_throttles.failures+1,1024),\
               delay_until=clock_timestamp()+make_interval(secs=>LEAST(300,\
                 power(2,LEAST(filebelt_mount.authentication_throttles.failures+1,8))::integer)),\
               expires_at=clock_timestamp()+interval '1 hour',updated_at=clock_timestamp()",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(principal_key.as_slice())
        .bind(source_key.as_slice())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn clear_mount_authentication_failures(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        principal_key: &[u8; 32],
        source_key: &[u8; 32],
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            "DELETE FROM filebelt_mount.authentication_throttles \
             WHERE tenant_id=$1 AND protocol=$2 AND principal_key=$3 AND source_key=$4",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(principal_key.as_slice())
        .bind(source_key.as_slice())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn list_mount_policies(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<MountPolicyRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT protocol,enabled,read_only,allowed_drive_ids,authorization_generation,\
             revision,updated_at::text FROM filebelt_mount.policies \
             WHERE tenant_id=$1 AND principal_id=$2 ORDER BY protocol",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(mount_policy_from_row).collect())
    }

    pub async fn upsert_mount_policy(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        protocol: &str,
        enabled: bool,
        read_only: bool,
        allowed_drive_ids: &[Uuid],
    ) -> Result<MountPolicyRecord, DatabaseError> {
        if !matches!(protocol, "smb" | "ftps" | "nfs") || allowed_drive_ids.len() > 256 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "INSERT INTO filebelt_mount.policies \
             (tenant_id,principal_id,protocol,enabled,read_only,allowed_drive_ids) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,principal_id,protocol) \
             DO UPDATE SET enabled=EXCLUDED.enabled,read_only=EXCLUDED.read_only,\
               allowed_drive_ids=EXCLUDED.allowed_drive_ids,\
               authorization_generation=filebelt_mount.policies.authorization_generation+1,\
               revision=filebelt_mount.policies.revision+1,updated_at=clock_timestamp() \
             RETURNING protocol,enabled,read_only,allowed_drive_ids,authorization_generation,\
               revision,updated_at::text",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(protocol)
        .bind(enabled)
        .bind(read_only)
        .bind(allowed_drive_ids)
        .fetch_one(&mut *transaction)
        .await?;
        let policy = mount_policy_from_row(&row);
        let revoked = sqlx::query(
            "UPDATE filebelt_mount.credentials SET revoked_at=clock_timestamp(),\
             credential_generation=credential_generation+1,\
             authorization_generation=authorization_generation+1 \
             WHERE tenant_id=$1 AND principal_id=$2 AND protocol=$3 AND revoked_at IS NULL \
             RETURNING id,credential_generation",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(protocol)
        .fetch_all(&mut *transaction)
        .await?;
        for credential in &revoked {
            sqlx::query(
                "INSERT INTO filebelt_mount.deletion_tombstones \
                 (tenant_id,id,object_kind,object_id,principal_id,protocol,reason_code,generation) \
                 VALUES ($1,$2,'credential',$3,$4,$5,'policy_changed',$6)",
            )
            .bind(tenant_id)
            .bind(Uuid::new_v4())
            .bind(credential.get::<Uuid, _>("id"))
            .bind(principal_id)
            .bind(protocol)
            .bind(credential.get::<i64, _>("credential_generation"))
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE filebelt_mount.sessions SET state='revoked',closed_at=clock_timestamp(),\
             close_reason='policy_changed' WHERE tenant_id=$1 AND user_principal_id=$2 \
             AND protocol=$3 AND state IN ('active','draining')",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(protocol)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(principal_id),
            Some(principal_id),
            None,
            "mount.policy.update",
            "allowed",
            "self_service_policy",
            false,
            json!({"protocol":protocol,"enabled":enabled,"read_only":read_only,"revoked_credentials":revoked.len()}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.policy.changed",
            "mount_policy",
            principal_id,
            policy.authorization_generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(policy)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_mount_credential(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        credential_id: Uuid,
        protocol: &str,
        username: &str,
        verifier_kind: &str,
        read_only: bool,
        allowed_drive_ids: &[Uuid],
        bound_device_id: Option<Uuid>,
        expires_at: &str,
        envelope: &MountSecretEnvelopeInput<'_>,
    ) -> Result<MountCredentialRecord, DatabaseError> {
        if !matches!(
            (protocol, verifier_kind),
            ("smb", "ntlm_verifier") | ("ftps", "hmac_sha256")
        ) || !(16..=96).contains(&username.len())
            || allowed_drive_ids.len() > 256
            || envelope.kek_generation <= 0
            || envelope.aad_version != 1
            || envelope.wrapped_dek.len() != 48
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let policy = sqlx::query(
            "SELECT enabled,read_only,allowed_drive_ids FROM filebelt_mount.policies \
             WHERE tenant_id=$1 AND principal_id=$2 AND protocol=$3 FOR SHARE",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(protocol)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        if !policy.get::<bool, _>("enabled")
            || !read_only && policy.get::<bool, _>("read_only")
            || !allowed_drive_ids.iter().all(|drive| {
                policy
                    .get::<Vec<Uuid>, _>("allowed_drive_ids")
                    .contains(drive)
            })
        {
            return Err(DatabaseError::Conflict);
        }
        if let Some(device_id) = bound_device_id {
            let current: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM filebelt_mount.headscale_devices \
                 WHERE tenant_id=$1 AND id=$2 AND principal_id=$3 AND revoked_at IS NULL \
                 AND observed_at>clock_timestamp()-interval '5 minutes')",
            )
            .bind(tenant_id)
            .bind(device_id)
            .bind(principal_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !current {
                return Err(DatabaseError::Conflict);
            }
        }
        let id = credential_id;
        sqlx::query(
            "INSERT INTO filebelt_mount.credentials \
             (tenant_id,id,principal_id,protocol,username,verifier_kind,read_only,allowed_drive_ids,bound_device_id,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz)",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(principal_id)
        .bind(protocol)
        .bind(username)
        .bind(verifier_kind)
        .bind(read_only)
        .bind(allowed_drive_ids)
        .bind(bound_device_id)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_conflict)?;
        sqlx::query(
            "INSERT INTO filebelt_mount_vault.secret_envelopes \
             (tenant_id,credential_id,owner_principal_id,credential_generation,namespace,secret_kind,\
              ciphertext,nonce,wrapped_dek,wrap_nonce,kek_generation,aad_digest,aad_version) \
             VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(principal_id)
        .bind(protocol)
        .bind(verifier_kind)
        .bind(envelope.ciphertext)
        .bind(envelope.nonce.as_slice())
        .bind(envelope.wrapped_dek)
        .bind(envelope.wrap_nonce.as_slice())
        .bind(envelope.kek_generation)
        .bind(envelope.aad_digest.as_slice())
        .bind(envelope.aad_version)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(principal_id),
            Some(principal_id),
            Some(id),
            "mount.credential.create",
            "allowed",
            "mount_policy_allowed",
            false,
            json!({"protocol":protocol,"read_only":read_only,"device_bound":bound_device_id.is_some()}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.credential.changed",
            "mount_credential",
            id,
            1,
        )
        .await?;
        transaction.commit().await?;
        self.mount_credential(tenant_id, principal_id, id).await
    }

    pub async fn mount_credential(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        credential_id: Uuid,
    ) -> Result<MountCredentialRecord, DatabaseError> {
        let row = sqlx::query(
            "SELECT id,principal_id,protocol,username,verifier_kind,credential_generation,\
             authorization_generation,read_only,allowed_drive_ids,bound_device_id,\
             created_at::text,last_used_at::text,expires_at::text,revoked_at::text \
             FROM filebelt_mount.credentials WHERE tenant_id=$1 AND principal_id=$2 AND id=$3",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(credential_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(mount_credential_from_row(&row))
    }

    pub async fn list_mount_credentials(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<MountCredentialRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT id,principal_id,protocol,username,verifier_kind,credential_generation,\
             authorization_generation,read_only,allowed_drive_ids,bound_device_id,\
             created_at::text,last_used_at::text,expires_at::text,revoked_at::text \
             FROM filebelt_mount.credentials WHERE tenant_id=$1 AND principal_id=$2 \
             ORDER BY created_at DESC,id",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(mount_credential_from_row).collect())
    }

    pub async fn revoke_mount_credential(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        credential_id: Uuid,
        reason_code: &str,
    ) -> Result<(), DatabaseError> {
        if reason_code.is_empty() || reason_code.len() > 128 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "UPDATE filebelt_mount.credentials SET revoked_at=clock_timestamp(),\
             credential_generation=credential_generation+1,authorization_generation=authorization_generation+1 \
             WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 AND revoked_at IS NULL \
             RETURNING protocol,credential_generation",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(credential_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let generation: i64 = row.get("credential_generation");
        sqlx::query(
            "UPDATE filebelt_mount.sessions SET state='revoked',closed_at=clock_timestamp(),\
             close_reason=$4 WHERE tenant_id=$1 AND credential_id=$2 AND user_principal_id=$3 \
             AND state IN ('active','draining')",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .bind(principal_id)
        .bind(reason_code)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO filebelt_mount.deletion_tombstones \
             (tenant_id,id,object_kind,object_id,principal_id,protocol,reason_code,generation) \
             VALUES ($1,$2,'credential',$3,$4,$5,$6,$7)",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind(credential_id)
        .bind(principal_id)
        .bind(row.get::<String, _>("protocol"))
        .bind(reason_code)
        .bind(generation)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(principal_id),
            Some(principal_id),
            Some(credential_id),
            "mount.credential.revoke",
            "allowed",
            reason_code,
            false,
            json!({}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.credential.changed",
            "mount_credential",
            credential_id,
            generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mount_authentication_material(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        username: &str,
        device_id: Option<Uuid>,
    ) -> Result<MountAuthenticationMaterial, DatabaseError> {
        let row = sqlx::query(
            "SELECT c.id,c.principal_id,c.protocol,c.username,c.verifier_kind,c.credential_generation,\
             c.authorization_generation,c.read_only,c.allowed_drive_ids,c.bound_device_id,\
             c.created_at::text,c.last_used_at::text,c.expires_at::text,c.revoked_at::text,\
             e.ciphertext,e.nonce,e.wrapped_dek,e.wrap_nonce,e.kek_generation,e.aad_digest,e.aad_version \
             FROM filebelt_mount.credentials c \
             JOIN filebelt_mount.policies policy ON policy.tenant_id=c.tenant_id \
               AND policy.principal_id=c.principal_id AND policy.protocol=c.protocol \
             JOIN principals p ON p.tenant_id=c.tenant_id AND p.id=c.principal_id \
             JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.id \
             JOIN filebelt_mount_vault.secret_envelopes e \
               ON e.tenant_id=c.tenant_id AND e.credential_id=c.id \
             WHERE c.tenant_id=$1 AND c.protocol=$2 AND c.username=$3 \
               AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp() \
               AND policy.enabled AND p.disabled_at IS NULL AND u.status='active' \
               AND (c.bound_device_id IS NULL OR c.bound_device_id=$4) \
               AND (c.bound_device_id IS NULL OR EXISTS (SELECT 1 FROM filebelt_mount.headscale_devices d \
                 WHERE d.tenant_id=c.tenant_id AND d.id=c.bound_device_id AND d.principal_id=c.principal_id \
                   AND d.revoked_at IS NULL AND d.observed_at>clock_timestamp()-interval '5 minutes'))",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(username)
        .bind(device_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(MountAuthenticationMaterial {
            credential: mount_credential_from_row(&row),
            ciphertext: row.get("ciphertext"),
            nonce: array_12(row.get::<Vec<u8>, _>("nonce"))?,
            wrapped_dek: row.get("wrapped_dek"),
            wrap_nonce: array_12(row.get::<Vec<u8>, _>("wrap_nonce"))?,
            kek_generation: row.get("kek_generation"),
            aad_digest: array_32(row.get::<Vec<u8>, _>("aad_digest"))?,
            aad_version: row.get("aad_version"),
        })
    }

    /// Resolves only an already-provisioned RPCSEC_GSS identity. This method
    /// never accepts AUTH_SYS values, reads a vault envelope, or turns a UID,
    /// GID, or host identity into authority.
    pub async fn nfs_principal_mapping(
        &self,
        tenant_id: Uuid,
        kerberos_principal: &str,
    ) -> Result<NfsPrincipalMapping, DatabaseError> {
        if kerberos_principal.is_empty() || kerberos_principal.len() > 512 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "SELECT mapping.kerberos_principal,mapping.principal_id,mapping.credential_id,\
             mapping.projected_uid,mapping.projected_gid,mapping.generation \
             FROM filebelt_mount.nfs_principal_mappings mapping \
             JOIN filebelt_mount.credentials credential \
               ON credential.tenant_id=mapping.tenant_id AND credential.id=mapping.credential_id \
             JOIN filebelt_mount.policies policy \
               ON policy.tenant_id=credential.tenant_id AND policy.principal_id=credential.principal_id \
                 AND policy.protocol='nfs' \
             JOIN principals principal \
               ON principal.tenant_id=mapping.tenant_id AND principal.id=mapping.principal_id \
             WHERE mapping.tenant_id=$1 AND mapping.kerberos_principal=$2 \
               AND mapping.revoked_at IS NULL AND credential.protocol='nfs' \
               AND credential.verifier_kind='kerberos_principal' AND credential.revoked_at IS NULL \
               AND credential.expires_at>clock_timestamp() AND policy.enabled \
               AND principal.disabled_at IS NULL",
        )
        .bind(tenant_id)
        .bind(kerberos_principal)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(NfsPrincipalMapping {
            kerberos_principal: row.get("kerberos_principal"),
            principal_id: row.get("principal_id"),
            credential_id: row.get("credential_id"),
            projected_uid: row.get("projected_uid"),
            projected_gid: row.get("projected_gid"),
            generation: row.get("generation"),
        })
    }

    /// Atomically consumes one NFSv4 slot/sequence receipt. Repeating a slot
    /// sequence with a different digest is a conflict; replay caches therefore
    /// cannot be reconstructed from adapter memory after restart.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_nfs_replay_receipt(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        slot_id: i32,
        sequence_id: i64,
        request_digest: &[u8; 32],
        response_digest: &[u8; 32],
        gateway_epoch: i64,
    ) -> Result<(), DatabaseError> {
        if client_id.is_empty()
            || client_id.len() > 255
            || !(0..=1023).contains(&slot_id)
            || sequence_id <= 0
            || gateway_epoch <= 0
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let inserted = sqlx::query(
            "INSERT INTO filebelt_mount.nfs_replay_receipts \
             (tenant_id,client_id,slot_id,sequence_id,request_digest,response_digest,gateway_epoch,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '90 seconds') \
             ON CONFLICT (tenant_id,client_id,slot_id,sequence_id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(slot_id)
        .bind(sequence_id)
        .bind(request_digest.as_slice())
        .bind(response_digest.as_slice())
        .bind(gateway_epoch)
        .execute(self.pool())
        .await?;
        if inserted.rows_affected() == 1 {
            return Ok(());
        }
        let existing = sqlx::query(
            "SELECT request_digest,response_digest,gateway_epoch FROM filebelt_mount.nfs_replay_receipts \
             WHERE tenant_id=$1 AND client_id=$2 AND slot_id=$3 AND sequence_id=$4 \
               AND expires_at>clock_timestamp()",
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(slot_id)
        .bind(sequence_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let same = existing.get::<Vec<u8>, _>("request_digest") == request_digest
            && existing.get::<Vec<u8>, _>("response_digest") == response_digest
            && existing.get::<i64, _>("gateway_epoch") == gateway_epoch;
        if same {
            Ok(())
        } else {
            Err(DatabaseError::Conflict)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_mount_session(
        &self,
        tenant_id: Uuid,
        credential_id: Uuid,
        device_id: Option<Uuid>,
        protocol: &str,
        gateway_id: &str,
        gateway_epoch: i64,
        source_address: &str,
    ) -> Result<MountSessionFence, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let credential = sqlx::query(
            "SELECT c.principal_id,c.credential_generation,c.authorization_generation,\
             c.read_only,c.allowed_drive_ids,p.generation AS membership_generation \
             FROM filebelt_mount.credentials c JOIN principals p \
               ON p.tenant_id=c.tenant_id AND p.id=c.principal_id \
             JOIN filebelt_mount.policies policy ON policy.tenant_id=c.tenant_id \
               AND policy.principal_id=c.principal_id AND policy.protocol=c.protocol \
             WHERE c.tenant_id=$1 AND c.id=$2 AND c.protocol=$3 AND c.revoked_at IS NULL \
               AND c.expires_at>clock_timestamp() AND policy.enabled AND p.disabled_at IS NULL \
               AND (c.bound_device_id IS NULL OR c.bound_device_id=$4) FOR SHARE OF c,p,policy",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .bind(protocol)
        .bind(device_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let gateway: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.gateway_epochs \
             WHERE tenant_id=$1 AND protocol=$2 AND gateway_id=$3 AND epoch=$4 \
               AND NOT draining AND lease_expires_at>clock_timestamp())",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(gateway_id)
        .bind(gateway_epoch)
        .fetch_one(&mut *transaction)
        .await?;
        if !gateway {
            return Err(DatabaseError::StaleGeneration);
        }
        let session_id = Uuid::new_v4();
        let session_principal_id = Uuid::new_v4();
        let user_principal_id: Uuid = credential.get("principal_id");
        sqlx::query("INSERT INTO principals (tenant_id,id,kind) VALUES ($1,$2,'mount_session')")
            .bind(tenant_id)
            .bind(session_principal_id)
            .execute(&mut *transaction)
            .await?;
        let absolute_hours = if protocol == "smb" { 12 } else { 4 };
        sqlx::query(
            "INSERT INTO filebelt_mount.sessions \
             (tenant_id,id,session_principal_id,user_principal_id,credential_id,device_id,protocol,\
              gateway_id,gateway_epoch,source_address,credential_generation,authorization_generation,\
              membership_generation,idle_expires_at,absolute_expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::inet,$11,$12,$13,\
              clock_timestamp()+interval '15 minutes',clock_timestamp()+make_interval(hours=>$14))",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(session_principal_id)
        .bind(user_principal_id)
        .bind(credential_id)
        .bind(device_id)
        .bind(protocol)
        .bind(gateway_id)
        .bind(gateway_epoch)
        .bind(source_address)
        .bind(credential.get::<i64, _>("credential_generation"))
        .bind(credential.get::<i64, _>("authorization_generation"))
        .bind(credential.get::<i64, _>("membership_generation"))
        .bind(absolute_hours)
        .execute(&mut *transaction)
        .await
        .map_err(map_conflict)?;
        sqlx::query(
            "UPDATE filebelt_mount.credentials SET last_used_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(user_principal_id),
            Some(session_principal_id),
            Some(session_id),
            "mount.session.start",
            "allowed",
            "credential_verified",
            false,
            json!({"protocol":protocol,"device_bound":device_id.is_some()}),
        )
        .await?;
        transaction.commit().await?;
        Ok(MountSessionFence {
            tenant_id,
            session_id,
            user_principal_id,
            credential_id,
            protocol: protocol.to_owned(),
            credential_generation: credential.get("credential_generation"),
            authorization_generation: credential.get("authorization_generation"),
            membership_generation: credential.get("membership_generation"),
            gateway_epoch,
            read_only: credential.get("read_only"),
            allowed_drive_ids: credential.get("allowed_drive_ids"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn admit_mount_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        protocol: &str,
        gateway_id: &str,
        gateway_epoch: i64,
        credential_generation: i64,
        authorization_generation: i64,
    ) -> Result<MountSessionFence, DatabaseError> {
        let row = sqlx::query(
            "UPDATE filebelt_mount.sessions s SET last_activity_at=clock_timestamp(),\
             idle_expires_at=LEAST(s.absolute_expires_at,clock_timestamp()+interval '15 minutes') \
             FROM filebelt_mount.credentials c,principals p,filebelt_mount.gateway_epochs gateway,\
                  filebelt_mount.policies policy \
             WHERE s.tenant_id=$1 AND s.id=$2 AND s.protocol=$3 AND s.gateway_id=$4 \
               AND s.gateway_epoch=$5 AND s.credential_generation=$6 \
               AND s.authorization_generation=$7 AND s.state='active' \
               AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() \
               AND c.tenant_id=s.tenant_id AND c.id=s.credential_id AND c.revoked_at IS NULL \
               AND c.expires_at>clock_timestamp() AND c.credential_generation=$6 \
               AND c.authorization_generation=$7 \
               AND (c.bound_device_id IS NULL OR EXISTS (SELECT 1 \
                 FROM filebelt_mount.headscale_devices device \
                 WHERE device.tenant_id=c.tenant_id AND device.id=c.bound_device_id \
                   AND device.principal_id=s.user_principal_id AND device.revoked_at IS NULL \
                   AND device.observed_at>clock_timestamp()-interval '5 minutes')) \
               AND p.tenant_id=s.tenant_id AND p.id=s.user_principal_id \
               AND p.disabled_at IS NULL AND p.generation=s.membership_generation \
               AND policy.tenant_id=s.tenant_id AND policy.principal_id=s.user_principal_id \
               AND policy.protocol=s.protocol AND policy.enabled \
               AND gateway.tenant_id=s.tenant_id AND gateway.protocol=s.protocol \
               AND gateway.gateway_id=s.gateway_id AND gateway.epoch=s.gateway_epoch \
               AND NOT gateway.draining AND gateway.lease_expires_at>clock_timestamp() \
             RETURNING s.user_principal_id,s.credential_id,s.protocol,s.credential_generation,\
               s.authorization_generation,s.membership_generation,s.gateway_epoch,\
               c.read_only,c.allowed_drive_ids",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(protocol)
        .bind(gateway_id)
        .bind(gateway_epoch)
        .bind(credential_generation)
        .bind(authorization_generation)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        Ok(MountSessionFence {
            tenant_id,
            session_id,
            user_principal_id: row.get("user_principal_id"),
            credential_id: row.get("credential_id"),
            protocol: row.get("protocol"),
            credential_generation: row.get("credential_generation"),
            authorization_generation: row.get("authorization_generation"),
            membership_generation: row.get("membership_generation"),
            gateway_epoch: row.get("gateway_epoch"),
            read_only: row.get("read_only"),
            allowed_drive_ids: row.get("allowed_drive_ids"),
        })
    }

    pub async fn end_mount_session(
        &self,
        fence: &MountSessionFence,
        reason_code: &str,
    ) -> Result<(), DatabaseError> {
        if reason_code.is_empty() || reason_code.len() > 64 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let changed = sqlx::query(
            "UPDATE filebelt_mount.sessions SET state='closed',closed_at=clock_timestamp(),close_reason=$3 \
             WHERE tenant_id=$1 AND id=$2 AND state='active'",
        )
        .bind(fence.tenant_id)
        .bind(fence.session_id)
        .bind(reason_code)
        .execute(&mut *transaction)
        .await?;
        if changed.rows_affected() != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        insert_audit(
            &mut transaction,
            fence.tenant_id,
            Some(fence.user_principal_id),
            None,
            Some(fence.session_id),
            "mount.session.end",
            "allowed",
            reason_code,
            false,
            json!({"protocol":fence.protocol}),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open_mount_handle(
        &self,
        fence: &MountSessionFence,
        drive_id: Uuid,
        node_id: Uuid,
        expected_version_id: Option<Uuid>,
        access_actions: &[String],
        share_read: bool,
        share_write: bool,
        share_delete: bool,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<MountHandleRecord, DatabaseError> {
        if access_actions.is_empty()
            || access_actions.len() > 19
            || !access_actions.iter().all(|action| {
                matches!(
                    action.as_str(),
                    "READ_METADATA" | "READ_CONTENT" | "MANAGE_LOCK"
                )
            })
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let node = sqlx::query(
            "SELECT n.head_version_id,n.kind,n.namespace_generation,n.acl_generation,\
             d.acl_generation AS drive_acl_generation FROM nodes n JOIN drives d \
             ON d.tenant_id=n.tenant_id AND d.id=n.drive_id \
             WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3 \
               AND n.kind='file' AND n.trash_root_id IS NULL FOR SHARE OF n,d",
        )
        .bind(fence.tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let version_id: Option<Uuid> = node.get("head_version_id");
        if version_id.is_none()
            || expected_version_id.is_some_and(|expected| Some(expected) != version_id)
            || node.get::<i64, _>("drive_acl_generation") != drive_acl_generation
            || node.get::<i64, _>("namespace_generation") != namespace_generation
            || node.get::<i64, _>("acl_generation") != resource_acl_generation
        {
            return Err(DatabaseError::StaleGeneration);
        }
        let wants_read = access_actions.iter().any(|action| action == "READ_CONTENT");
        let wants_write = access_actions
            .iter()
            .any(|action| action == "WRITE_CONTENT");
        let wants_delete = access_actions.iter().any(|action| action == "DELETE");
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.handles h \
             WHERE h.tenant_id=$1 AND h.drive_id=$2 AND h.node_id=$3 \
               AND h.closed_at IS NULL AND h.expires_at>clock_timestamp() AND (\
                 ($4 AND NOT h.share_read) OR ('READ_CONTENT'=ANY(h.access_actions) AND NOT $5) OR \
                 ($6 AND NOT h.share_write) OR ('WRITE_CONTENT'=ANY(h.access_actions) AND NOT $7) OR \
                 ($8 AND NOT h.share_delete) OR ('DELETE'=ANY(h.access_actions) AND NOT $9)))",
        )
        .bind(fence.tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(wants_read)
        .bind(share_read)
        .bind(wants_write)
        .bind(share_write)
        .bind(wants_delete)
        .bind(share_delete)
        .fetch_one(&mut *transaction)
        .await?;
        if conflict {
            return Err(DatabaseError::Conflict);
        }
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO filebelt_mount.handles \
             (tenant_id,id,session_id,drive_id,node_id,version_id,access_actions,\
              share_read,share_write,share_delete,credential_generation,authorization_generation,\
              membership_generation,drive_acl_generation,namespace_generation,\
              resource_acl_generation,gateway_epoch,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
               clock_timestamp()+interval '15 minutes')",
        )
        .bind(fence.tenant_id)
        .bind(id)
        .bind(fence.session_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(version_id)
        .bind(access_actions)
        .bind(share_read)
        .bind(share_write)
        .bind(share_delete)
        .bind(fence.credential_generation)
        .bind(fence.authorization_generation)
        .bind(fence.membership_generation)
        .bind(drive_acl_generation)
        .bind(namespace_generation)
        .bind(resource_acl_generation)
        .bind(fence.gateway_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(map_conflict)?;
        insert_audit(
            &mut transaction,
            fence.tenant_id,
            Some(fence.user_principal_id),
            None,
            Some(node_id),
            "mount.handle.open",
            "allowed",
            "virtual_acl_allowed",
            false,
            json!({"handle_id":id,"protocol":fence.protocol,"write":wants_write}),
        )
        .await?;
        transaction.commit().await?;
        Ok(MountHandleRecord {
            id,
            session_id: fence.session_id,
            drive_id,
            node_id,
            version_id,
            access_actions: access_actions.to_vec(),
            credential_generation: fence.credential_generation,
            authorization_generation: fence.authorization_generation,
            membership_generation: fence.membership_generation,
            drive_acl_generation,
            namespace_generation,
            resource_acl_generation,
            gateway_epoch: fence.gateway_epoch,
        })
    }

    pub async fn admit_mount_handle(
        &self,
        fence: &MountSessionFence,
        handle_id: Uuid,
        required_action: &str,
    ) -> Result<MountHandleRecord, DatabaseError> {
        if !matches!(
            required_action,
            "READ_METADATA" | "READ_CONTENT" | "MANAGE_LOCK"
        ) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "UPDATE filebelt_mount.handles h SET expires_at=clock_timestamp()+interval '15 minutes' \
             FROM filebelt_mount.sessions s,filebelt_mount.credentials c,principals p,drives d,nodes n,\
                  filebelt_mount.policies policy,filebelt_mount.gateway_epochs gateway \
             WHERE h.tenant_id=$1 AND h.id=$2 AND h.session_id=$3 AND h.closed_at IS NULL \
               AND h.expires_at>clock_timestamp() AND $4=ANY(h.access_actions) \
               AND h.credential_generation=$5 AND h.authorization_generation=$6 \
               AND h.membership_generation=$7 AND h.gateway_epoch=$8 \
               AND s.tenant_id=h.tenant_id AND s.id=h.session_id AND s.state='active' \
               AND s.credential_generation=h.credential_generation \
               AND s.authorization_generation=h.authorization_generation \
               AND s.membership_generation=h.membership_generation AND s.gateway_epoch=h.gateway_epoch \
               AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() \
               AND c.tenant_id=s.tenant_id AND c.id=s.credential_id AND c.revoked_at IS NULL \
               AND c.expires_at>clock_timestamp() AND c.credential_generation=h.credential_generation \
               AND c.authorization_generation=h.authorization_generation \
               AND p.tenant_id=s.tenant_id AND p.id=s.user_principal_id AND p.disabled_at IS NULL \
               AND p.generation=h.membership_generation \
               AND d.tenant_id=h.tenant_id AND d.id=h.drive_id AND d.acl_generation=h.drive_acl_generation \
               AND n.tenant_id=h.tenant_id AND n.drive_id=h.drive_id AND n.id=h.node_id \
               AND n.namespace_generation=h.namespace_generation AND n.acl_generation=h.resource_acl_generation \
               AND policy.tenant_id=s.tenant_id AND policy.principal_id=s.user_principal_id \
               AND policy.protocol=s.protocol AND policy.enabled \
               AND gateway.tenant_id=s.tenant_id AND gateway.protocol=s.protocol \
               AND gateway.gateway_id=s.gateway_id AND gateway.epoch=h.gateway_epoch \
               AND NOT gateway.draining AND gateway.lease_expires_at>clock_timestamp() \
             RETURNING h.id,h.session_id,h.drive_id,h.node_id,h.version_id,h.access_actions,\
               h.credential_generation,h.authorization_generation,h.membership_generation,\
               h.drive_acl_generation,h.namespace_generation,h.resource_acl_generation,h.gateway_epoch",
        )
        .bind(fence.tenant_id)
        .bind(handle_id)
        .bind(fence.session_id)
        .bind(required_action)
        .bind(fence.credential_generation)
        .bind(fence.authorization_generation)
        .bind(fence.membership_generation)
        .bind(fence.gateway_epoch)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        Ok(mount_handle_from_row(&row))
    }

    pub async fn admit_mount_read_capability(
        &self,
        capability: &MountReadCapabilityFence,
    ) -> Result<MountHandleRecord, DatabaseError> {
        let row = sqlx::query(
            "SELECT h.id,h.session_id,h.drive_id,h.node_id,h.version_id,h.access_actions,\
               h.credential_generation,h.authorization_generation,h.membership_generation,\
               h.drive_acl_generation,h.namespace_generation,h.resource_acl_generation,h.gateway_epoch \
             FROM filebelt_mount.handles h \
             JOIN filebelt_mount.sessions s ON s.tenant_id=h.tenant_id AND s.id=h.session_id \
             JOIN filebelt_mount.credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id \
             JOIN principals p ON p.tenant_id=s.tenant_id AND p.id=s.user_principal_id \
             JOIN drives d ON d.tenant_id=h.tenant_id AND d.id=h.drive_id \
             JOIN nodes n ON n.tenant_id=h.tenant_id AND n.drive_id=h.drive_id AND n.id=h.node_id \
             JOIN filebelt_mount.policies policy ON policy.tenant_id=s.tenant_id \
               AND policy.principal_id=s.user_principal_id AND policy.protocol=s.protocol \
             JOIN filebelt_mount.gateway_epochs gateway ON gateway.tenant_id=s.tenant_id \
               AND gateway.protocol=s.protocol AND gateway.gateway_id=s.gateway_id \
             WHERE h.tenant_id=$1 AND h.id=$2 AND h.session_id=$3 AND s.credential_id=$4 \
               AND s.user_principal_id=$5 AND h.drive_id=$6 AND h.node_id=$7 AND h.version_id=$8 \
               AND h.closed_at IS NULL AND h.expires_at>clock_timestamp() \
               AND 'READ_CONTENT'=ANY(h.access_actions) AND s.state='active' \
               AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() \
               AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp() \
               AND h.drive_id=ANY(c.allowed_drive_ids) \
               AND (c.bound_device_id IS NULL OR EXISTS (SELECT 1 \
                 FROM filebelt_mount.headscale_devices device \
                 WHERE device.tenant_id=c.tenant_id AND device.id=c.bound_device_id \
                   AND device.principal_id=s.user_principal_id AND device.revoked_at IS NULL \
                   AND device.observed_at>clock_timestamp()-interval '5 minutes')) \
               AND p.disabled_at IS NULL AND policy.enabled AND h.drive_id=ANY(policy.allowed_drive_ids) \
               AND gateway.epoch=$15 AND NOT gateway.draining \
               AND gateway.lease_expires_at>clock_timestamp() \
               AND h.credential_generation=$9 AND c.credential_generation=$9 \
               AND s.credential_generation=$9 AND h.authorization_generation=$10 \
               AND c.authorization_generation=$10 AND s.authorization_generation=$10 \
               AND h.membership_generation=$11 AND s.membership_generation=$11 AND p.generation=$11 \
               AND h.drive_acl_generation=$12 AND d.acl_generation=$12 \
               AND h.namespace_generation=$13 AND n.namespace_generation=$13 \
               AND h.resource_acl_generation=$14 AND n.acl_generation=$14 \
               AND h.gateway_epoch=$15 AND s.gateway_epoch=$15",
        )
        .bind(capability.tenant_id)
        .bind(capability.handle_id)
        .bind(capability.mount_session_id)
        .bind(capability.credential_id)
        .bind(capability.principal_id)
        .bind(capability.drive_id)
        .bind(capability.node_id)
        .bind(capability.version_id)
        .bind(capability.credential_generation)
        .bind(capability.authorization_generation)
        .bind(capability.membership_generation)
        .bind(capability.drive_acl_generation)
        .bind(capability.namespace_generation)
        .bind(capability.resource_acl_generation)
        .bind(capability.gateway_epoch)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        Ok(mount_handle_from_row(&row))
    }

    pub async fn close_mount_handle(
        &self,
        fence: &MountSessionFence,
        handle_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let closed = sqlx::query(
            "UPDATE filebelt_mount.handles SET closed_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND session_id=$3 AND closed_at IS NULL",
        )
        .bind(fence.tenant_id)
        .bind(handle_id)
        .bind(fence.session_id)
        .execute(&mut *transaction)
        .await?;
        if closed.rows_affected() != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query(
            "UPDATE filebelt_mount.byte_locks SET released_at=clock_timestamp() \
             WHERE tenant_id=$1 AND handle_id=$2 AND released_at IS NULL",
        )
        .bind(fence.tenant_id)
        .bind(handle_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn acquire_mount_byte_lock(
        &self,
        fence: &MountSessionFence,
        handle: &MountHandleRecord,
        owner_key: &str,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<Uuid, DatabaseError> {
        if owner_key.is_empty() || owner_key.len() > 255 || length == 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let offset = i64::try_from(offset).map_err(|_| DatabaseError::InvalidPersistedValue)?;
        let length = i64::try_from(length).map_err(|_| DatabaseError::InvalidPersistedValue)?;
        let end = offset
            .checked_add(length)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let mut transaction = self.pool().begin().await?;
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.byte_locks \
             WHERE tenant_id=$1 AND drive_id=$2 AND node_id=$3 AND released_at IS NULL \
               AND expires_at>clock_timestamp() AND offset_bytes<$4 \
               AND offset_bytes+length_bytes>$5 AND (exclusive OR $6))",
        )
        .bind(fence.tenant_id)
        .bind(handle.drive_id)
        .bind(handle.node_id)
        .bind(end)
        .bind(offset)
        .bind(exclusive)
        .fetch_one(&mut *transaction)
        .await?;
        if conflict {
            return Err(DatabaseError::Conflict);
        }
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO filebelt_mount.byte_locks \
             (tenant_id,id,handle_id,drive_id,node_id,owner_key,offset_bytes,length_bytes,\
              exclusive,gateway_epoch,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp()+interval '30 seconds')",
        )
        .bind(fence.tenant_id)
        .bind(id)
        .bind(handle.id)
        .bind(handle.drive_id)
        .bind(handle.node_id)
        .bind(owner_key)
        .bind(offset)
        .bind(length)
        .bind(exclusive)
        .bind(fence.gateway_epoch)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(id)
    }

    pub async fn release_mount_byte_lock(
        &self,
        fence: &MountSessionFence,
        handle_id: Uuid,
        lock_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let changed = sqlx::query(
            "UPDATE filebelt_mount.byte_locks SET released_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND handle_id=$3 AND gateway_epoch=$4 \
               AND released_at IS NULL",
        )
        .bind(fence.tenant_id)
        .bind(lock_id)
        .bind(handle_id)
        .bind(fence.gateway_epoch)
        .execute(self.pool())
        .await?;
        if changed.rows_affected() != 1 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }

    pub async fn claim_mount_gateway_epoch(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        shard_key: &str,
        gateway_id: &str,
    ) -> Result<i64, DatabaseError> {
        let row = sqlx::query(
            "INSERT INTO filebelt_mount.gateway_epochs \
             (tenant_id,protocol,shard_key,gateway_id,epoch,lease_expires_at) \
             VALUES ($1,$2,$3,$4,1,clock_timestamp()+interval '20 seconds') \
             ON CONFLICT (tenant_id,protocol,shard_key) DO UPDATE SET \
               gateway_id=EXCLUDED.gateway_id,\
               epoch=CASE WHEN filebelt_mount.gateway_epochs.gateway_id=EXCLUDED.gateway_id \
                 THEN filebelt_mount.gateway_epochs.epoch ELSE filebelt_mount.gateway_epochs.epoch+1 END,\
               draining=false,lease_expires_at=EXCLUDED.lease_expires_at,updated_at=clock_timestamp() \
             WHERE filebelt_mount.gateway_epochs.gateway_id=EXCLUDED.gateway_id \
                OR filebelt_mount.gateway_epochs.lease_expires_at<=clock_timestamp() \
             RETURNING epoch",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(shard_key)
        .bind(gateway_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::AdmissionLimited)?;
        Ok(row.get("epoch"))
    }

    pub async fn list_mount_devices(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<MountDeviceRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT id,principal_id,headscale_node_id,display_name,\
             ARRAY(SELECT value::text FROM unnest(tailnet_addresses) value) AS tailnet_addresses,\
             node_tags,capability_version,ownership_generation,observed_at::text,revoked_at::text \
             FROM filebelt_mount.headscale_devices WHERE tenant_id=$1 AND principal_id=$2 \
             ORDER BY revoked_at NULLS FIRST,display_name,id",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(mount_device_from_row).collect())
    }

    pub async fn list_mount_sessions(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<MountSessionSummary>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT id,protocol,gateway_id,host(source_address) AS source_address,state,\
             created_at::text,last_activity_at::text,idle_expires_at::text,\
             absolute_expires_at::text,close_reason FROM filebelt_mount.sessions \
             WHERE tenant_id=$1 AND user_principal_id=$2 ORDER BY created_at DESC,id LIMIT 200",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .iter()
            .map(|row| MountSessionSummary {
                id: row.get("id"),
                protocol: row.get("protocol"),
                gateway_id: row.get("gateway_id"),
                source_address: row.get("source_address"),
                state: row.get("state"),
                created_at: row.get("created_at"),
                last_activity_at: row.get("last_activity_at"),
                idle_expires_at: row.get("idle_expires_at"),
                absolute_expires_at: row.get("absolute_expires_at"),
                close_reason: row.get("close_reason"),
            })
            .collect())
    }

    pub async fn mount_principal_for_external_identity(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<Uuid>, DatabaseError> {
        sqlx::query_scalar(
            "SELECT u.principal_id FROM external_identities identity JOIN users u \
             ON u.tenant_id=identity.tenant_id AND u.id=identity.user_id JOIN principals p \
             ON p.tenant_id=u.tenant_id AND p.id=u.principal_id \
             WHERE identity.tenant_id=$1 AND identity.issuer=$2 AND identity.subject=$3 \
               AND identity.disabled_at IS NULL AND u.status='active' AND p.disabled_at IS NULL",
        )
        .bind(tenant_id)
        .bind(issuer)
        .bind(subject)
        .fetch_optional(self.pool())
        .await
        .map_err(DatabaseError::from)
    }

    pub async fn replace_mount_devices(
        &self,
        tenant_id: Uuid,
        observations: &[MountDeviceObservation],
    ) -> Result<(), DatabaseError> {
        if observations.len() > 10_000
            || observations.iter().any(|observation| {
                observation.headscale_node_id.is_empty()
                    || observation.headscale_node_id.len() > 255
                    || observation.addresses.is_empty()
                    || observation.addresses.len() > 16
                    || observation.tags.len() > 32
                    || observation.capability_version.is_empty()
            })
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        for observation in observations {
            sqlx::query(
                "INSERT INTO filebelt_mount.headscale_devices \
                 (tenant_id,id,principal_id,headscale_node_id,oidc_issuer,oidc_subject,display_name,\
                  tailnet_addresses,node_tags,capability_version,observed_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8::inet[],$9,$10,clock_timestamp()) \
                 ON CONFLICT (tenant_id,headscale_node_id) DO UPDATE SET \
                   principal_id=EXCLUDED.principal_id,oidc_issuer=EXCLUDED.oidc_issuer,\
                   oidc_subject=EXCLUDED.oidc_subject,display_name=EXCLUDED.display_name,\
                   tailnet_addresses=EXCLUDED.tailnet_addresses,node_tags=EXCLUDED.node_tags,\
                   capability_version=EXCLUDED.capability_version,\
                   ownership_generation=CASE \
                     WHEN filebelt_mount.headscale_devices.principal_id=EXCLUDED.principal_id \
                     THEN filebelt_mount.headscale_devices.ownership_generation \
                     ELSE filebelt_mount.headscale_devices.ownership_generation+1 END,\
                   observed_at=clock_timestamp(),revoked_at=NULL",
            )
            .bind(tenant_id)
            .bind(Uuid::new_v4())
            .bind(observation.principal_id)
            .bind(&observation.headscale_node_id)
            .bind(&observation.issuer)
            .bind(&observation.subject)
            .bind(&observation.display_name)
            .bind(&observation.addresses)
            .bind(&observation.tags)
            .bind(&observation.capability_version)
            .execute(&mut *transaction)
            .await?;
        }
        let observed = observations
            .iter()
            .map(|observation| observation.headscale_node_id.clone())
            .collect::<Vec<_>>();
        sqlx::query(
            "UPDATE filebelt_mount.headscale_devices SET revoked_at=clock_timestamp(),\
             ownership_generation=ownership_generation+1 \
             WHERE tenant_id=$1 AND revoked_at IS NULL AND NOT (headscale_node_id=ANY($2))",
        )
        .bind(tenant_id)
        .bind(&observed)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}

fn mount_credential_from_row(row: &sqlx::postgres::PgRow) -> MountCredentialRecord {
    MountCredentialRecord {
        id: row.get("id"),
        principal_id: row.get("principal_id"),
        protocol: row.get("protocol"),
        username: row.get("username"),
        verifier_kind: row.get("verifier_kind"),
        credential_generation: row.get("credential_generation"),
        authorization_generation: row.get("authorization_generation"),
        read_only: row.get("read_only"),
        allowed_drive_ids: row.get("allowed_drive_ids"),
        bound_device_id: row.get("bound_device_id"),
        created_at: row.get("created_at"),
        last_used_at: row.get("last_used_at"),
        expires_at: row.get("expires_at"),
        revoked_at: row.get("revoked_at"),
    }
}

fn mount_policy_from_row(row: &sqlx::postgres::PgRow) -> MountPolicyRecord {
    MountPolicyRecord {
        protocol: row.get("protocol"),
        enabled: row.get("enabled"),
        read_only: row.get("read_only"),
        allowed_drive_ids: row.get("allowed_drive_ids"),
        authorization_generation: row.get("authorization_generation"),
        revision: row.get("revision"),
        updated_at: row.get("updated_at"),
    }
}

fn mount_device_from_row(row: &sqlx::postgres::PgRow) -> MountDeviceRecord {
    MountDeviceRecord {
        id: row.get("id"),
        principal_id: row.get("principal_id"),
        headscale_node_id: row.get("headscale_node_id"),
        display_name: row.get("display_name"),
        tailnet_addresses: row.get("tailnet_addresses"),
        node_tags: row.get("node_tags"),
        capability_version: row.get("capability_version"),
        ownership_generation: row.get("ownership_generation"),
        observed_at: row.get("observed_at"),
        revoked_at: row.get("revoked_at"),
    }
}

fn mount_handle_from_row(row: &sqlx::postgres::PgRow) -> MountHandleRecord {
    MountHandleRecord {
        id: row.get("id"),
        session_id: row.get("session_id"),
        drive_id: row.get("drive_id"),
        node_id: row.get("node_id"),
        version_id: row.get("version_id"),
        access_actions: row.get("access_actions"),
        credential_generation: row.get("credential_generation"),
        authorization_generation: row.get("authorization_generation"),
        membership_generation: row.get("membership_generation"),
        drive_acl_generation: row.get("drive_acl_generation"),
        namespace_generation: row.get("namespace_generation"),
        resource_acl_generation: row.get("resource_acl_generation"),
        gateway_epoch: row.get("gateway_epoch"),
    }
}

fn array_12(value: Vec<u8>) -> Result<[u8; 12], DatabaseError> {
    value
        .try_into()
        .map_err(|_| DatabaseError::InvalidPersistedValue)
}

fn array_32(value: Vec<u8>) -> Result<[u8; 32], DatabaseError> {
    value
        .try_into()
        .map_err(|_| DatabaseError::InvalidPersistedValue)
}

#[cfg(test)]
mod tests {
    #[test]
    fn source_keeps_secret_queries_inside_the_mount_module() {
        let source = include_str!("mount.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("filebelt_mount_vault.secret_envelopes"));
        assert!(production.contains("policy.enabled"));
        assert!(production.contains("gateway.lease_expires_at>clock_timestamp()"));
        assert!(!production.contains("payload_locator"));
    }
}

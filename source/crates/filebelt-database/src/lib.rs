// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL persistence mechanics for FileBelt Phase 2.

#![deny(unsafe_code)]

pub mod collaboration;
pub mod document;
pub mod mcp;
pub mod media;
pub mod mount;

mod idempotency;

use std::collections::{BTreeMap, BTreeSet};

use filebelt_domain::Action;
use filebelt_events_protocol::EventEnvelope;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations/postgres");

pub const PRIVATE_DRIVE_QUOTA_BYTES: i64 = 1_099_511_627_776;
pub const SHARED_DRIVE_QUOTA_BYTES: i64 = 10_995_116_277_760;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("database operation failed: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("requested object was not found")]
    NotFound,
    #[error("request conflicts with current state")]
    Conflict,
    #[error("drive quota is exhausted")]
    QuotaExceeded,
    #[error("storage backend is unavailable or below its write threshold")]
    StorageUnavailable,
    #[error("request admission limit is exhausted")]
    AdmissionLimited,
    #[error("descendant-share admission is temporarily blocked")]
    SecurityAdmissionBlocked,
    #[error("a stale generation or fencing token was supplied")]
    StaleGeneration,
    #[error("persisted value is outside the supported domain")]
    InvalidPersistedValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub principal_id: Uuid,
    pub private_drive_id: Uuid,
    pub private_root_id: Uuid,
    pub tenant_admin: bool,
    pub suspended: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub principal_id: Uuid,
    pub tenant_admin: bool,
    pub reauthenticated_recently: bool,
    pub csrf_digest: Vec<u8>,
    pub display_name: String,
    pub verified_email: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: Uuid,
    pub created_at: String,
    pub last_seen_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    pub revoked: bool,
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub request_fingerprint: Vec<u8>,
    pub response_status: i32,
    pub response_body: Value,
}

#[derive(Clone, Debug)]
pub struct OidcAttemptRecord {
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_path: String,
    pub session_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DriveRecord {
    pub id: Uuid,
    pub owner_principal_id: Uuid,
    pub kind: String,
    pub display_name: String,
    pub root_id: Uuid,
    pub namespace_generation: i64,
    pub acl_generation: i64,
    pub quota_bytes: i64,
    pub used_physical_bytes: i64,
    pub reserved_bytes: i64,
    pub owner_display_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: Uuid,
    pub drive_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub kind: String,
    pub display_name: String,
    pub name_key: String,
    pub head_version_id: Option<Uuid>,
    pub namespace_generation: i64,
    pub acl_generation: i64,
    pub trashed: bool,
    pub updated_at: String,
    pub size_bytes: Option<i64>,
    pub version_ordinal: Option<i64>,
    pub head_media_type: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileVersionRecord {
    pub id: Uuid,
    pub node_id: Uuid,
    pub ordinal: i64,
    pub size_bytes: i64,
    pub created_by: Uuid,
    pub restored_from_version_id: Option<Uuid>,
    pub created_at: String,
    pub current: bool,
    pub media_type: Option<String>,
    pub origin_kind: String,
    pub source_version_id: Option<Uuid>,
    pub creator_display_name: Option<String>,
    pub mcp_assisted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectShareRecord {
    pub principal_id: Uuid,
    pub display_name: String,
    pub verified_email: String,
    pub preset: String,
    pub inheritance: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvancedAclEntryRecord {
    pub principal_id: Uuid,
    pub principal_kind: String,
    pub display_name: String,
    pub verified_email: Option<String>,
    pub action: String,
    pub effect: String,
    pub inheritance: String,
    pub source: String,
}

#[derive(Clone, Copy, Debug)]
pub struct AdvancedAclEntryInput<'a> {
    pub action: &'a str,
    pub effect: &'a str,
    pub inheritance: &'a str,
}

#[derive(Clone, Debug)]
pub struct AdvancedAclReplacementPreflight {
    pub target_principal_id: Uuid,
    pub actions: BTreeSet<Action>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AclInputRow {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub principal_id: Uuid,
    pub action: String,
    pub effect: String,
    pub inheritance: String,
    pub depth: i32,
    pub direct: bool,
    pub generation: i64,
    pub created_by: Uuid,
    pub direct_share_id: Option<Uuid>,
    pub direct_share_active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInputRow {
    pub group_id: Uuid,
    pub principal_id: Uuid,
    pub role: String,
    pub generation: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationPrincipalFact {
    pub principal_id: Uuid,
    pub groups: Vec<GroupInputRow>,
    pub entries: Vec<AclInputRow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationSnapshot {
    pub tenant_id: Uuid,
    pub drive_id: Uuid,
    pub resource_id: Uuid,
    pub owner_principal_id: Uuid,
    pub owner_kind: String,
    pub owner_group_id: Option<Uuid>,
    pub actor_principal_id: Uuid,
    pub actor_groups: Vec<GroupInputRow>,
    pub entries: Vec<AclInputRow>,
    pub creator_facts: Vec<AuthorizationPrincipalFact>,
    pub membership_generation: i64,
    pub drive_acl_generation: i64,
    /// Namespace generation of the drive containing `resource_id`.
    pub namespace_generation: i64,
    /// Namespace generation of the exact node identified by `resource_id`.
    pub resource_namespace_generation: i64,
    pub resource_acl_generation: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadRecord {
    pub tenant_id: Uuid,
    pub upload_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Option<Uuid>,
    pub parent_id: Uuid,
    pub owner_principal_id: Uuid,
    pub payload_id: Uuid,
    pub backend_id: Uuid,
    pub payload_locator: Uuid,
    pub expected_head_version_id: Option<Uuid>,
    pub target_display_name: String,
    pub target_name_key: String,
    pub declared_size_bytes: i64,
    pub chunk_size_bytes: i32,
    pub part_count: i32,
    pub fencing_token: i64,
    pub state: String,
    pub declared_media_type: Option<String>,
    pub collaboration_checkpoint_id: Option<Uuid>,
    pub import_intent_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadPartRecord {
    pub part_number: i32,
    pub locator: Uuid,
    pub state: String,
    pub size_bytes: i32,
    pub blake3: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadRecord {
    pub tenant_id: Uuid,
    pub payload_id: Uuid,
    pub drive_id: Uuid,
    pub backend_id: Uuid,
    pub locator: Uuid,
    pub layout: String,
    pub state: String,
    pub size_bytes: i64,
    pub blake3: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobRecord {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub kind: String,
    pub payload: Value,
    pub attempt: i32,
    pub fencing_token: i64,
}

impl Database {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, DatabaseError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), DatabaseError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub async fn health(&self) -> Result<(), DatabaseError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn phase8_is_active(&self, tenant_id: Uuid) -> Result<bool, DatabaseError> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_phase8.activation_state WHERE tenant_id=$1 AND state='active')",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn bootstrap_tenant(
        &self,
        slug: &str,
        backend_id: Uuid,
        admin_bindings: &[(String, String)],
    ) -> Result<Uuid, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let tenant_id = sqlx::query("SELECT id FROM tenants WHERE slug = $1 FOR UPDATE")
            .bind(slug)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| row.get("id"))
            .unwrap_or_else(Uuid::new_v4);
        sqlx::query("INSERT INTO tenants (id,slug) VALUES ($1,$2) ON CONFLICT (slug) DO NOTHING")
            .bind(tenant_id)
            .bind(slug)
            .execute(&mut *transaction)
            .await?;
        let existing_backend: Option<Uuid> = sqlx::query(
            "SELECT id FROM storage_backends WHERE tenant_id=$1 AND kind='posix' FOR UPDATE",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *transaction)
        .await?
        .map(|row| row.get("id"));
        if existing_backend.is_some_and(|existing| existing != backend_id) {
            return Err(DatabaseError::Conflict);
        }
        sqlx::query("INSERT INTO storage_backends (tenant_id,id) VALUES ($1,$2) ON CONFLICT (tenant_id,kind) DO NOTHING")
            .bind(tenant_id).bind(backend_id).execute(&mut *transaction).await?;
        for (issuer, subject) in admin_bindings {
            sqlx::query(
                "INSERT INTO tenant_admin_bindings (tenant_id,issuer,subject) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
            )
            .bind(tenant_id)
            .bind(issuer)
            .bind(subject)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(tenant_id)
    }

    pub async fn tenant_by_slug(&self, slug: &str) -> Result<Uuid, DatabaseError> {
        sqlx::query("SELECT id FROM tenants WHERE slug = $1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?
            .map(|row| row.get("id"))
            .ok_or(DatabaseError::NotFound)
    }

    pub async fn report_storage_capacity(
        &self,
        tenant_id: Uuid,
        backend_id: Uuid,
        total_bytes: i64,
        free_bytes: i64,
        ready: bool,
    ) -> Result<(), DatabaseError> {
        if total_bytes <= 0 || free_bytes < 0 || free_bytes > total_bytes {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let updated=sqlx::query("UPDATE storage_backends SET capacity_total_bytes=$3,capacity_free_bytes=$4,capacity_checked_at=clock_timestamp(),storage_ready=$5 WHERE tenant_id=$1 AND id=$2 AND kind='posix'")
            .bind(tenant_id).bind(backend_id).bind(total_bytes).bind(free_bytes).bind(ready).execute(&self.pool).await?.rows_affected();
        if updated != 1 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }

    pub async fn mark_storage_unready(
        &self,
        tenant_id: Uuid,
        backend_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let updated=sqlx::query("UPDATE storage_backends SET storage_ready=false,capacity_checked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND kind='posix'")
            .bind(tenant_id).bind(backend_id).execute(&self.pool).await?.rows_affected();
        if updated != 1 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }

    pub async fn link_oidc_identity(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        subject: &str,
        display_name: &str,
        verified_email: Option<&str>,
        claims: &Value,
    ) -> Result<IdentityRecord, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        if let Some(row) = sqlx::query(
            "SELECT ei.user_id,u.principal_id,u.status FROM external_identities ei JOIN users u ON u.tenant_id=ei.tenant_id AND u.id=ei.user_id WHERE ei.tenant_id=$1 AND ei.issuer=$2 AND ei.subject=$3 FOR UPDATE OF ei,u",
        )
        .bind(tenant_id)
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let user_id: Uuid = row.get("user_id");
            let principal_id: Uuid = row.get("principal_id");
            let status: String = row.get("status");
            sqlx::query("UPDATE external_identities SET last_seen_at=clock_timestamp(),claims_snapshot=$4 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3")
                .bind(tenant_id).bind(issuer).bind(subject).bind(claims)
                .execute(&mut *transaction).await?;
            if let Some(email) = verified_email {
                sqlx::query("UPDATE users SET display_name=$3,verified_email=$4,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                    .bind(tenant_id).bind(user_id).bind(display_name).bind(email)
                    .execute(&mut *transaction).await?;
            }
            let (drive_id, root_id) = private_drive_for_user(&mut transaction, tenant_id, principal_id).await?;
            let tenant_admin = is_admin(&mut transaction, tenant_id, issuer, subject).await?;
            transaction.commit().await?;
            return Ok(IdentityRecord { tenant_id, user_id, principal_id, private_drive_id: drive_id, private_root_id: root_id, tenant_admin, suspended: status == "suspended" });
        }

        let user_id = Uuid::new_v4();
        let principal_id = Uuid::new_v4();
        let identity_id = Uuid::new_v4();
        let drive_id = Uuid::new_v4();
        let root_id = Uuid::new_v4();
        sqlx::query("INSERT INTO principals (tenant_id,id,kind) VALUES ($1,$2,'user')")
            .bind(tenant_id)
            .bind(principal_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO users (tenant_id,id,principal_id,display_name,verified_email) VALUES ($1,$2,$3,$4,$5)")
            .bind(tenant_id).bind(user_id).bind(principal_id).bind(display_name).bind(verified_email)
            .execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO external_identities (tenant_id,id,user_id,issuer,subject,claims_snapshot) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(tenant_id).bind(identity_id).bind(user_id).bind(issuer).bind(subject).bind(claims)
            .execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO user_preferences (tenant_id,user_id) VALUES ($1,$2)")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO drives (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) VALUES ($1,$2,$3,'private','My Drive',$4)")
            .bind(tenant_id).bind(drive_id).bind(principal_id).bind(PRIVATE_DRIVE_QUOTA_BYTES)
            .execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO nodes (tenant_id,drive_id,id,parent_id,kind,display_name,name_key,owner_principal_id) VALUES ($1,$2,$3,NULL,'directory','','',$4)")
            .bind(tenant_id).bind(drive_id).bind(root_id).bind(principal_id).execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO node_ancestry (tenant_id,drive_id,ancestor_id,descendant_id,depth) VALUES ($1,$2,$3,$3,0)")
            .bind(tenant_id).bind(drive_id).bind(root_id).execute(&mut *transaction).await?;
        let tenant_admin = is_admin(&mut transaction, tenant_id, issuer, subject).await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(principal_id),
            Some(principal_id),
            Some(root_id),
            "identity.link",
            "allowed",
            "oidc_identity_created",
            false,
            json!({}),
        )
        .await?;
        transaction.commit().await?;
        Ok(IdentityRecord {
            tenant_id,
            user_id,
            principal_id,
            private_drive_id: drive_id,
            private_root_id: root_id,
            tenant_admin,
            suspended: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_session(
        &self,
        identity: &IdentityRecord,
        key_generation: i32,
        token_digest: &[u8],
        csrf_digest: &[u8],
        idle_seconds: i64,
        absolute_seconds: i64,
        user_agent: Option<&str>,
    ) -> Result<Uuid, DatabaseError> {
        let id = Uuid::new_v4();
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO api_sessions (tenant_id,id,user_id,principal_id,token_key_generation,token_digest,csrf_digest,idle_expires_at,absolute_expires_at,user_agent) VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+make_interval(secs=>$8),clock_timestamp()+make_interval(secs=>$9),$10)")
            .bind(identity.tenant_id).bind(id).bind(identity.user_id).bind(identity.principal_id)
            .bind(key_generation).bind(token_digest).bind(csrf_digest).bind(idle_seconds).bind(absolute_seconds).bind(user_agent)
            .execute(&mut *transaction).await?;
        insert_audit(
            &mut transaction,
            identity.tenant_id,
            Some(identity.principal_id),
            Some(identity.principal_id),
            None,
            "session.create",
            "allowed",
            "oidc_authenticated",
            true,
            json!({"session_id":id}),
        )
        .await?;
        transaction.commit().await?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_oidc_attempt(
        &self,
        tenant_id: Uuid,
        state_digest: &[u8],
        nonce_digest: &[u8],
        pkce_digest: &[u8],
        nonce: &str,
        pkce_verifier: &str,
        return_path: &str,
        session_id: Option<Uuid>,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE")
            .bind(tenant_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        sqlx::query("DELETE FROM oidc_login_attempts WHERE tenant_id=$1 AND (expires_at<=clock_timestamp() OR consumed_at IS NOT NULL)")
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await?;
        let active: i64 =
            sqlx::query("SELECT count(*) FROM oidc_login_attempts WHERE tenant_id=$1")
                .bind(tenant_id)
                .fetch_one(&mut *transaction)
                .await?
                .get(0);
        if active >= 4096 {
            return Err(DatabaseError::AdmissionLimited);
        }
        sqlx::query("INSERT INTO oidc_login_attempts (tenant_id,id,state_digest,nonce_digest,pkce_verifier_digest,nonce_secret,pkce_verifier_secret,return_path,session_id,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '10 minutes')")
            .bind(tenant_id).bind(Uuid::new_v4()).bind(state_digest).bind(nonce_digest).bind(pkce_digest).bind(nonce).bind(pkce_verifier).bind(return_path).bind(session_id).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn consume_oidc_attempt(
        &self,
        tenant_id: Uuid,
        state_digest: &[u8],
    ) -> Result<OidcAttemptRecord, DatabaseError> {
        let row=sqlx::query("WITH selected AS (SELECT id,nonce_secret,pkce_verifier_secret,return_path,session_id FROM oidc_login_attempts WHERE tenant_id=$1 AND state_digest=$2 AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE), consumed AS (UPDATE oidc_login_attempts a SET consumed_at=clock_timestamp(),nonce_secret='',pkce_verifier_secret='' FROM selected s WHERE a.tenant_id=$1 AND a.id=s.id RETURNING a.id) SELECT s.nonce_secret,s.pkce_verifier_secret,s.return_path,s.session_id FROM selected s JOIN consumed c USING (id)")
            .bind(tenant_id).bind(state_digest).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(OidcAttemptRecord {
            nonce: row.get("nonce_secret"),
            pkce_verifier: row.get("pkce_verifier_secret"),
            return_path: row.get("return_path"),
            session_id: row.get("session_id"),
        })
    }

    pub async fn resolve_session(
        &self,
        tenant_id: Uuid,
        key_generation: i32,
        token_digest: &[u8],
        idle_seconds: i64,
    ) -> Result<SessionRecord, DatabaseError> {
        let row = sqlx::query("UPDATE api_sessions s SET last_seen_at=clock_timestamp(),idle_expires_at=LEAST(s.absolute_expires_at,clock_timestamp()+make_interval(secs=>$4)) FROM users u WHERE s.tenant_id=$1 AND s.token_key_generation=$2 AND s.token_digest=$3 AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() AND u.tenant_id=s.tenant_id AND u.id=s.user_id AND u.status='active' RETURNING s.id,s.user_id,s.principal_id,s.csrf_digest,u.display_name,u.verified_email,(s.reauthenticated_at>clock_timestamp()-interval '10 minutes') AS fresh")
            .bind(tenant_id).bind(key_generation).bind(token_digest).bind(idle_seconds)
            .fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        let principal_id: Uuid = row.get("principal_id");
        let tenant_admin: bool = sqlx::query("SELECT EXISTS (SELECT 1 FROM external_identities ei JOIN tenant_admin_bindings a ON a.tenant_id=ei.tenant_id AND a.issuer=ei.issuer AND a.subject=ei.subject JOIN users u ON u.tenant_id=ei.tenant_id AND u.id=ei.user_id WHERE ei.tenant_id=$1 AND u.principal_id=$2)")
            .bind(tenant_id).bind(principal_id).fetch_one(&self.pool).await?.get(0);
        Ok(SessionRecord {
            tenant_id,
            session_id: row.get("id"),
            user_id: row.get("user_id"),
            principal_id,
            tenant_admin,
            reauthenticated_recently: row.get("fresh"),
            csrf_digest: row.get("csrf_digest"),
            display_name: row.get("display_name"),
            verified_email: row.get("verified_email"),
        })
    }

    pub async fn revoke_session(
        &self,
        tenant_id: Uuid,
        actor: Uuid,
        session_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let target = sqlx::query("UPDATE api_sessions SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL RETURNING principal_id")
            .bind(tenant_id).bind(session_id).fetch_optional(&mut *transaction).await?;
        let Some(target) = target else {
            return Ok(false);
        };
        let target: Uuid = target.get("principal_id");
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor),
            Some(target),
            None,
            "session.revoke",
            "allowed",
            "session_revoked",
            true,
            json!({"session_id":session_id}),
        )
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn list_sessions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<SessionSummary>, DatabaseError> {
        let rows = sqlx::query("SELECT id,created_at::text,last_seen_at::text,idle_expires_at::text,absolute_expires_at::text,(revoked_at IS NOT NULL) AS revoked,user_agent FROM api_sessions WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at DESC")
            .bind(tenant_id)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| SessionSummary {
                session_id: row.get("id"),
                created_at: row.get("created_at"),
                last_seen_at: row.get("last_seen_at"),
                idle_expires_at: row.get("idle_expires_at"),
                absolute_expires_at: row.get("absolute_expires_at"),
                revoked: row.get("revoked"),
                user_agent: row.get("user_agent"),
            })
            .collect())
    }

    pub async fn revoke_all_sessions(
        &self,
        tenant_id: Uuid,
        actor: Uuid,
        user_id: Uuid,
        except_session_id: Option<Uuid>,
    ) -> Result<u64, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let rows = sqlx::query("UPDATE api_sessions SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL AND ($3::uuid IS NULL OR id<>$3) RETURNING id")
            .bind(tenant_id)
            .bind(user_id)
            .bind(except_session_id)
            .fetch_all(&mut *transaction)
            .await?;
        if !rows.is_empty() {
            insert_audit(
                &mut transaction,
                tenant_id,
                Some(actor),
                Some(actor),
                None,
                "session.revoke_all",
                "allowed",
                "all_sessions_revoked",
                true,
                json!({
                    "except_session_id":except_session_id,
                    "revoked_session_ids":rows.iter().map(|row| row.get::<Uuid,_>("id")).collect::<Vec<_>>(),
                }),
            )
            .await?;
        }
        transaction.commit().await?;
        u64::try_from(rows.len()).map_err(|_| DatabaseError::InvalidPersistedValue)
    }

    pub async fn idempotency_record(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        route: &str,
        key: &str,
    ) -> Result<Option<IdempotencyRecord>, DatabaseError> {
        let row = sqlx::query("SELECT request_fingerprint,response_status,response_body FROM idempotency_records WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key=$4 AND expires_at>clock_timestamp()")
            .bind(tenant_id)
            .bind(principal_id)
            .bind(route)
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| IdempotencyRecord {
            request_fingerprint: row.get("request_fingerprint"),
            response_status: row.get("response_status"),
            response_body: row.get("response_body"),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn store_idempotency_response(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        route: &str,
        key: &str,
        request_fingerprint: &[u8],
        response_status: i32,
        response_body: &Value,
    ) -> Result<IdempotencyRecord, DatabaseError> {
        let row = sqlx::query("WITH inserted AS (INSERT INTO idempotency_records (tenant_id,principal_id,route,key,request_fingerprint,response_status,response_body) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING request_fingerprint,response_status,response_body) SELECT request_fingerprint,response_status,response_body FROM inserted UNION ALL SELECT request_fingerprint,response_status,response_body FROM idempotency_records WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key=$4 LIMIT 1")
            .bind(tenant_id)
            .bind(principal_id)
            .bind(route)
            .bind(key)
            .bind(request_fingerprint)
            .bind(response_status)
            .bind(response_body)
            .fetch_one(&self.pool)
            .await?;
        Ok(IdempotencyRecord {
            request_fingerprint: row.get("request_fingerprint"),
            response_status: row.get("response_status"),
            response_body: row.get("response_body"),
        })
    }

    pub async fn list_drives(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<DriveRecord>, DatabaseError> {
        let rows = sqlx::query("SELECT d.*,n.id AS root_id,COALESCE(u.display_name,g.display_name,d.owner_principal_id::text) AS owner_display_name FROM drives d JOIN nodes n ON n.tenant_id=d.tenant_id AND n.drive_id=d.id AND n.parent_id IS NULL LEFT JOIN users u ON u.tenant_id=d.tenant_id AND u.principal_id=d.owner_principal_id LEFT JOIN groups g ON g.tenant_id=d.tenant_id AND g.principal_id=d.owner_principal_id WHERE d.tenant_id=$1 AND (d.owner_principal_id=$2 OR d.owner_principal_id IN (SELECT g.principal_id FROM group_memberships m JOIN groups g ON g.tenant_id=m.tenant_id AND g.id=m.group_id WHERE m.tenant_id=$1 AND m.user_principal_id=$2) OR EXISTS (SELECT 1 FROM acl_entries a WHERE a.tenant_id=d.tenant_id AND a.drive_id=d.id AND a.effect='allow' AND a.action='READ_METADATA' AND (a.principal_id=$2 OR a.principal_id IN (SELECT g.principal_id FROM group_memberships m JOIN groups g ON g.tenant_id=m.tenant_id AND g.id=m.group_id WHERE m.tenant_id=$1 AND m.user_principal_id=$2)))) ORDER BY d.kind,d.display_name")
            .bind(tenant_id).bind(principal_id).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| DriveRecord {
                id: row.get("id"),
                owner_principal_id: row.get("owner_principal_id"),
                kind: row.get("kind"),
                display_name: row.get("display_name"),
                root_id: row.get("root_id"),
                namespace_generation: row.get("namespace_generation"),
                acl_generation: row.get("acl_generation"),
                quota_bytes: row.get("quota_bytes"),
                used_physical_bytes: row.get("used_physical_bytes"),
                reserved_bytes: row.get("reserved_bytes"),
                owner_display_name: row.get("owner_display_name"),
            })
            .collect())
    }

    pub async fn node(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
    ) -> Result<NodeRecord, DatabaseError> {
        let row = sqlx::query("SELECT n.*,n.updated_at::text AS updated_at_text,v.size_bytes,v.ordinal AS version_ordinal,v.media_type AS head_media_type FROM nodes n LEFT JOIN file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id AND v.id=n.head_version_id WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(node_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(node_from_row(&row))
    }

    pub async fn list_children(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        parent_id: Uuid,
    ) -> Result<Vec<NodeRecord>, DatabaseError> {
        let rows = sqlx::query("SELECT n.*,n.updated_at::text AS updated_at_text,v.size_bytes,v.ordinal AS version_ordinal,v.media_type AS head_media_type FROM nodes n LEFT JOIN file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id AND v.id=n.head_version_id WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.parent_id=$3 AND n.trash_root_id IS NULL ORDER BY n.kind DESC,n.name_key,n.id")
            .bind(tenant_id).bind(drive_id).bind(parent_id).fetch_all(&self.pool).await?;
        Ok(rows.iter().map(node_from_row).collect())
    }

    pub async fn list_trashed_nodes(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
    ) -> Result<Vec<NodeRecord>, DatabaseError> {
        let rows = sqlx::query("SELECT n.*,n.updated_at::text AS updated_at_text,v.size_bytes,v.ordinal AS version_ordinal,v.media_type AS head_media_type FROM nodes n LEFT JOIN file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id AND v.id=n.head_version_id WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.trash_root_id=n.id ORDER BY n.kind DESC,n.name_key,n.id")
            .bind(tenant_id)
            .bind(drive_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(node_from_row).collect())
    }

    pub async fn list_shared_nodes(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<NodeRecord>, DatabaseError> {
        let rows = sqlx::query("SELECT DISTINCT n.*,n.updated_at::text AS updated_at_text,v.size_bytes,v.ordinal AS version_ordinal,v.media_type AS head_media_type FROM nodes n JOIN node_ancestry na ON na.tenant_id=n.tenant_id AND na.drive_id=n.drive_id AND na.descendant_id=n.id JOIN acl_entries a ON a.tenant_id=na.tenant_id AND a.drive_id=na.drive_id AND a.resource_id=na.ancestor_id LEFT JOIN file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id AND v.id=n.head_version_id WHERE n.tenant_id=$1 AND n.trash_root_id IS NULL AND a.effect='allow' AND a.action='READ_METADATA' AND (a.principal_id=$2 OR a.principal_id IN (SELECT g.principal_id FROM group_memberships m JOIN groups g ON g.tenant_id=m.tenant_id AND g.id=m.group_id WHERE m.tenant_id=$1 AND m.user_principal_id=$2)) AND ((na.depth=0 AND a.inheritance IN ('self','self_and_descendants')) OR (na.depth>0 AND a.inheritance IN ('descendants','self_and_descendants'))) ORDER BY n.kind DESC,n.name_key,n.id")
            .bind(tenant_id)
            .bind(principal_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(node_from_row).collect())
    }

    pub async fn list_file_versions(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
    ) -> Result<Vec<FileVersionRecord>, DatabaseError> {
        let rows = sqlx::query("SELECT v.id,v.node_id,v.ordinal,v.size_bytes,v.created_by,v.restored_from_version_id,v.created_at::text,(n.head_version_id=v.id) AS current,v.media_type,v.origin_kind,v.source_version_id,v.creator_display_name,v.mcp_assisted FROM nodes n JOIN file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3 AND n.kind='file' ORDER BY v.ordinal DESC,v.id")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(node_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(file_version_from_row).collect())
    }

    pub async fn list_direct_shares(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
    ) -> Result<Vec<DirectShareRecord>, DatabaseError> {
        let rows = sqlx::query("SELECT s.target_principal_id,u.display_name,u.verified_email,s.preset,s.inheritance,s.created_at::text FROM direct_shares s JOIN nodes n ON n.tenant_id=s.tenant_id AND n.drive_id=s.drive_id AND n.id=s.resource_id JOIN users u ON u.tenant_id=s.tenant_id AND u.principal_id=s.target_principal_id WHERE s.tenant_id=$1 AND s.drive_id=$2 AND s.resource_id=$3 AND s.revoked_at IS NULL ORDER BY lower(u.verified_email),s.id")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(resource_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .iter()
            .map(|row| DirectShareRecord {
                principal_id: row.get("target_principal_id"),
                display_name: row.get("display_name"),
                verified_email: row.get("verified_email"),
                preset: row.get("preset"),
                inheritance: row.get("inheritance"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    pub async fn list_advanced_acl_entries(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
    ) -> Result<Vec<AdvancedAclEntryRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT a.principal_id,p.kind AS principal_kind, \
                    COALESCE(u.display_name,g.display_name,a.principal_id::text) AS display_name, \
                    u.verified_email,a.action,a.effect,a.inheritance, \
                    CASE WHEN a.direct_share_id IS NULL THEN 'advanced' ELSE 'share' END AS source \
             FROM acl_entries a \
             JOIN principals p ON p.tenant_id=a.tenant_id AND p.id=a.principal_id \
             LEFT JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.id \
             LEFT JOIN groups g ON g.tenant_id=p.tenant_id AND g.principal_id=p.id \
             WHERE a.tenant_id=$1 AND a.drive_id=$2 AND a.resource_id=$3 \
             ORDER BY p.kind,lower(COALESCE(u.display_name,g.display_name,a.principal_id::text)), \
                      a.principal_id,a.action,a.inheritance,a.effect",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(resource_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|row| AdvancedAclEntryRecord {
                principal_id: row.get("principal_id"),
                principal_kind: row.get("principal_kind"),
                display_name: row.get("display_name"),
                verified_email: row.get("verified_email"),
                action: row.get("action"),
                effect: row.get("effect"),
                inheritance: row.get("inheritance"),
                source: row.get("source"),
            })
            .collect())
    }

    pub async fn preflight_advanced_acl_replacement(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        target_kind: &str,
        verified_email: Option<&str>,
        group_id: Option<Uuid>,
    ) -> Result<AdvancedAclReplacementPreflight, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let target_principal_id = resolve_advanced_acl_target(
            &mut transaction,
            tenant_id,
            target_kind,
            verified_email,
            group_id,
        )
        .await?;
        let actions = advanced_acl_actions_for_target(
            &mut transaction,
            tenant_id,
            drive_id,
            resource_id,
            target_principal_id,
        )
        .await?;
        transaction.commit().await?;
        Ok(AdvancedAclReplacementPreflight {
            target_principal_id,
            actions,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn replace_advanced_acl_entries(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        target_kind: &str,
        verified_email: Option<&str>,
        group_id: Option<Uuid>,
        expected_target_principal_id: Uuid,
        entries: &[AdvancedAclEntryInput<'_>],
        covered_actions: &BTreeSet<Action>,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<(Uuid, i64), DatabaseError> {
        if entries.len() > Action::ALL.len()
            || entries.iter().any(|entry| {
                !Action::ALL
                    .iter()
                    .any(|action| action.as_str() == entry.action)
                    || !matches!(entry.effect, "allow" | "deny")
                    || !matches!(
                        entry.inheritance,
                        "self" | "descendants" | "self_and_descendants"
                    )
            })
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let submitted_actions = advanced_acl_actions(entries)?;
        if !replacement_actions_are_covered(covered_actions, &submitted_actions, &BTreeSet::new()) {
            return Err(DatabaseError::StaleGeneration);
        }
        let mut transaction = self.pool.begin().await?;
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            session_id,
            drive_id,
            resource_id,
            [
                membership_generation,
                drive_acl_generation,
                namespace_generation,
                resource_acl_generation,
            ],
        )
        .await?;
        let target_principal_id = resolve_advanced_acl_target(
            &mut transaction,
            tenant_id,
            target_kind,
            verified_email,
            group_id,
        )
        .await
        .map_err(stale_advanced_acl_target_drift)?;
        require_exact_advanced_acl_target(expected_target_principal_id, target_principal_id)?;
        let current_actions = advanced_acl_actions_for_target(
            &mut transaction,
            tenant_id,
            drive_id,
            resource_id,
            target_principal_id,
        )
        .await?;
        if !replacement_actions_are_covered(covered_actions, &submitted_actions, &current_actions) {
            return Err(DatabaseError::StaleGeneration);
        }
        let owner_principal_id: Uuid = sqlx::query_scalar(
            "SELECT owner_principal_id FROM drives WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        if target_principal_id == owner_principal_id {
            return Err(DatabaseError::Conflict);
        }
        sqlx::query(
            "DELETE FROM acl_entries WHERE tenant_id=$1 AND drive_id=$2 AND resource_id=$3 \
             AND principal_id=$4 AND direct_share_id IS NULL",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(resource_id)
        .bind(target_principal_id)
        .execute(&mut *transaction)
        .await?;
        for entry in entries {
            sqlx::query(
                "INSERT INTO acl_entries \
                 (tenant_id,drive_id,resource_id,id,principal_id,action,effect,inheritance,created_by,generation) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,1)",
            )
            .bind(tenant_id)
            .bind(drive_id)
            .bind(resource_id)
            .bind(Uuid::new_v4())
            .bind(target_principal_id)
            .bind(entry.action)
            .bind(entry.effect)
            .bind(entry.inheritance)
            .bind(actor_principal_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_conflict)?;
        }
        let generation: i64 = sqlx::query_scalar(
            "SELECT acl_generation FROM nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(resource_id)
        .fetch_one(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            Some(target_principal_id),
            Some(resource_id),
            "acl.replace",
            "allowed",
            "manage_acl_allowed",
            true,
            json!({"entry_count":entries.len(),"target_kind":target_kind}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.acl.changed",
            "node",
            resource_id,
            generation,
        )
        .await?;
        transaction.commit().await?;
        Ok((target_principal_id, generation))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn restore_file_version(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
        source_version_id: Uuid,
        expected_head_version_id: Option<Uuid>,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<FileVersionRecord, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            session_id,
            drive_id,
            node_id,
            [
                membership_generation,
                drive_acl_generation,
                namespace_generation,
                resource_acl_generation,
            ],
        )
        .await?;
        let source = sqlx::query("SELECT v.payload_id,v.size_bytes,v.blake3,v.media_type,n.head_version_id FROM nodes n JOIN file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3 AND n.kind='file' AND n.trash_root_id IS NULL AND v.id=$4 FOR UPDATE OF n")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(node_id)
            .bind(source_version_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        if source.get::<Option<Uuid>, _>("head_version_id") != expected_head_version_id {
            return Err(DatabaseError::StaleGeneration);
        }
        let ordinal: i64 = sqlx::query("SELECT COALESCE(max(ordinal),0)+1 FROM file_versions WHERE tenant_id=$1 AND node_id=$2")
            .bind(tenant_id)
            .bind(node_id)
            .fetch_one(&mut *transaction)
            .await?
            .get(0);
        let id = Uuid::new_v4();
        let created = sqlx::query("INSERT INTO file_versions (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,media_type,created_by,restored_from_version_id,origin_kind,source_version_id,creator_display_name) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'restore',$10,u.display_name FROM api_sessions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id WHERE s.tenant_id=$1 AND s.id=$11 RETURNING created_at::text,creator_display_name")
            .bind(tenant_id)
            .bind(node_id)
            .bind(id)
            .bind(ordinal)
            .bind(source.get::<Uuid, _>("payload_id"))
            .bind(source.get::<i64, _>("size_bytes"))
            .bind(source.get::<Vec<u8>, _>("blake3"))
            .bind(source.get::<Option<String>, _>("media_type"))
            .bind(actor_principal_id)
            .bind(source_version_id)
            .bind(session_id)
            .fetch_one(&mut *transaction)
            .await?;
        let created_at: String = created.get("created_at");
        let creator_display_name: Option<String> = created.get("creator_display_name");
        sqlx::query("UPDATE nodes SET head_version_id=$4,updated_at=clock_timestamp() WHERE tenant_id=$1 AND drive_id=$2 AND id=$3")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(node_id)
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE filebelt_collaboration.epochs e SET state='frozen', \
             freeze_reason='external_head',fencing_token=fencing_token+1 \
             FROM filebelt_collaboration.rooms r \
             WHERE r.tenant_id=$1 AND r.drive_id=$2 AND r.node_id=$3 \
               AND e.tenant_id=r.tenant_id AND e.room_id=r.id AND e.state='active'",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            None,
            Some(node_id),
            "version.restore",
            "allowed",
            "create_version_allowed",
            false,
            json!({"source_version_id":source_version_id,"version_id":id}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.version.created",
            "node",
            node_id,
            ordinal,
        )
        .await?;
        transaction.commit().await?;
        Ok(FileVersionRecord {
            id,
            node_id,
            ordinal,
            size_bytes: source.get("size_bytes"),
            created_by: actor_principal_id,
            restored_from_version_id: Some(source_version_id),
            created_at,
            current: true,
            media_type: source.get("media_type"),
            origin_kind: "restore".into(),
            source_version_id: Some(source_version_id),
            creator_display_name,
            mcp_assisted: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_direct_share(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        verified_email: &str,
        preset: &str,
        inheritance: &str,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<DirectShareRecord, DatabaseError> {
        let actions = share_preset_actions(preset)?;
        if !matches!(inheritance, "self" | "self_and_descendants") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let normalized_email = verified_email.trim().to_lowercase();
        if normalized_email.is_empty() || normalized_email.len() > 320 {
            return Err(DatabaseError::NotFound);
        }
        let mut transaction = self.pool.begin().await?;
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            session_id,
            drive_id,
            resource_id,
            [
                membership_generation,
                drive_acl_generation,
                namespace_generation,
                resource_acl_generation,
            ],
        )
        .await?;
        let target = sqlx::query("SELECT u.principal_id,u.display_name,u.verified_email FROM users u JOIN principals p ON p.tenant_id=u.tenant_id AND p.id=u.principal_id WHERE u.tenant_id=$1 AND lower(u.verified_email)=$2 AND u.status='active' AND p.disabled_at IS NULL FOR SHARE OF u,p")
            .bind(tenant_id)
            .bind(&normalized_email)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        let target_principal_id: Uuid = target.get("principal_id");
        if target_principal_id == actor_principal_id {
            return Err(DatabaseError::Conflict);
        }
        let share_id = Uuid::new_v4();
        let created_at: String = sqlx::query("INSERT INTO direct_shares (tenant_id,id,drive_id,resource_id,target_principal_id,preset,inheritance,created_by,authorization_model_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1) RETURNING created_at::text")
            .bind(tenant_id)
            .bind(share_id)
            .bind(drive_id)
            .bind(resource_id)
            .bind(target_principal_id)
            .bind(preset)
            .bind(inheritance)
            .bind(actor_principal_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_security_admission)?
            .get(0);
        for action in actions {
            sqlx::query("INSERT INTO acl_entries (tenant_id,drive_id,resource_id,id,principal_id,action,effect,inheritance,created_by,generation,direct_share_id) VALUES ($1,$2,$3,$4,$5,$6,'allow',$7,$8,1,$9)")
                .bind(tenant_id)
                .bind(drive_id)
                .bind(resource_id)
                .bind(Uuid::new_v4())
                .bind(target_principal_id)
                .bind(action)
                .bind(inheritance)
                .bind(actor_principal_id)
                .bind(share_id)
                .execute(&mut *transaction)
                .await
                .map_err(map_conflict)?;
        }
        let generation: i64 = sqlx::query(
            "SELECT acl_generation FROM nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(resource_id)
        .fetch_one(&mut *transaction)
        .await?
        .get(0);
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            Some(target_principal_id),
            Some(resource_id),
            "share.create",
            "allowed",
            "share_allowed",
            true,
            json!({"preset":preset,"inheritance":inheritance}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.acl.changed",
            "node",
            resource_id,
            generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(DirectShareRecord {
            principal_id: target_principal_id,
            display_name: target.get("display_name"),
            verified_email: target.get("verified_email"),
            preset: preset.into(),
            inheritance: inheritance.into(),
            created_at,
        })
    }

    pub async fn descendant_share_admission_open(
        &self,
        tenant_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        sqlx::query_scalar("SELECT filebelt_security.descendant_share_admission_open($1)")
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await
            .map_err(map_security_admission)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn revoke_direct_share(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        target_principal_id: Uuid,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            session_id,
            drive_id,
            resource_id,
            [
                membership_generation,
                drive_acl_generation,
                namespace_generation,
                resource_acl_generation,
            ],
        )
        .await?;
        let share_id: Uuid = sqlx::query("SELECT id FROM direct_shares WHERE tenant_id=$1 AND drive_id=$2 AND resource_id=$3 AND target_principal_id=$4 AND revoked_at IS NULL FOR UPDATE")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(resource_id)
            .bind(target_principal_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?
            .get(0);
        sqlx::query("DELETE FROM acl_entries WHERE tenant_id=$1 AND direct_share_id=$2")
            .bind(tenant_id)
            .bind(share_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE direct_shares SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(share_id)
        .execute(&mut *transaction)
        .await?;
        let generation: i64 = sqlx::query(
            "SELECT acl_generation FROM nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(resource_id)
        .fetch_one(&mut *transaction)
        .await?
        .get(0);
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            Some(target_principal_id),
            Some(resource_id),
            "share.revoke",
            "allowed",
            "share_allowed",
            true,
            json!({}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.acl.changed",
            "node",
            resource_id,
            generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn trash_node(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        expected_namespace_generation: i64,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<NodeRecord, DatabaseError> {
        self.set_node_trash_state(
            tenant_id,
            actor_principal_id,
            session_id,
            drive_id,
            resource_id,
            expected_namespace_generation,
            [
                membership_generation,
                drive_acl_generation,
                namespace_generation,
                resource_acl_generation,
            ],
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn restore_node(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        expected_namespace_generation: i64,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<NodeRecord, DatabaseError> {
        self.set_node_trash_state(
            tenant_id,
            actor_principal_id,
            session_id,
            drive_id,
            resource_id,
            expected_namespace_generation,
            [
                membership_generation,
                drive_acl_generation,
                namespace_generation,
                resource_acl_generation,
            ],
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn set_node_trash_state(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        expected_namespace_generation: i64,
        generations: [i64; 4],
        trash: bool,
    ) -> Result<NodeRecord, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            session_id,
            drive_id,
            resource_id,
            generations,
        )
        .await?;
        let node = sqlx::query("SELECT n.parent_id,n.display_name,n.name_key,n.namespace_generation,n.trash_root_id,d.trash_retention_days FROM nodes n JOIN drives d ON d.tenant_id=n.tenant_id AND d.id=n.drive_id WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3 FOR UPDATE OF n")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(resource_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        if node.get::<i64, _>("namespace_generation") != expected_namespace_generation
            || node.get::<Option<Uuid>, _>("parent_id").is_none()
            || (trash && node.get::<Option<Uuid>, _>("trash_root_id").is_some())
            || (!trash && node.get::<Option<Uuid>, _>("trash_root_id") != Some(resource_id))
        {
            return Err(DatabaseError::StaleGeneration);
        }
        if trash {
            sqlx::query("UPDATE nodes n SET trash_root_id=$4,trashed_original_parent_id=CASE WHEN n.id=$4 THEN n.parent_id ELSE n.trashed_original_parent_id END,trashed_original_name=CASE WHEN n.id=$4 THEN n.display_name ELSE n.trashed_original_name END,trashed_original_name_key=CASE WHEN n.id=$4 THEN n.name_key ELSE n.trashed_original_name_key END,purge_after=clock_timestamp()+make_interval(days=>$5),namespace_generation=CASE WHEN n.id=$4 THEN n.namespace_generation+1 ELSE n.namespace_generation END,updated_at=clock_timestamp() WHERE n.tenant_id=$1 AND n.drive_id=$2 AND EXISTS (SELECT 1 FROM node_ancestry a WHERE a.tenant_id=$1 AND a.drive_id=$2 AND a.ancestor_id=$3 AND a.descendant_id=n.id) AND n.trash_root_id IS NULL")
                .bind(tenant_id)
                .bind(drive_id)
                .bind(resource_id)
                .bind(resource_id)
                .bind(node.get::<i32, _>("trash_retention_days"))
                .execute(&mut *transaction)
                .await?;
        } else {
            let parent_id: Uuid = node.get("parent_id");
            let parent_live: bool = sqlx::query("SELECT EXISTS (SELECT 1 FROM nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 AND trash_root_id IS NULL)")
                .bind(tenant_id)
                .bind(drive_id)
                .bind(parent_id)
                .fetch_one(&mut *transaction)
                .await?
                .get(0);
            if !parent_live {
                return Err(DatabaseError::Conflict);
            }
            sqlx::query("UPDATE nodes n SET trash_root_id=NULL,trashed_original_parent_id=CASE WHEN n.id=$4 THEN NULL ELSE n.trashed_original_parent_id END,trashed_original_name=CASE WHEN n.id=$4 THEN NULL ELSE n.trashed_original_name END,trashed_original_name_key=CASE WHEN n.id=$4 THEN NULL ELSE n.trashed_original_name_key END,purge_after=NULL,namespace_generation=CASE WHEN n.id=$4 THEN n.namespace_generation+1 ELSE n.namespace_generation END,updated_at=clock_timestamp() WHERE n.tenant_id=$1 AND n.drive_id=$2 AND EXISTS (SELECT 1 FROM node_ancestry a WHERE a.tenant_id=$1 AND a.drive_id=$2 AND a.ancestor_id=$3 AND a.descendant_id=n.id) AND n.trash_root_id=$4")
                .bind(tenant_id)
                .bind(drive_id)
                .bind(resource_id)
                .bind(resource_id)
                .execute(&mut *transaction)
                .await
                .map_err(map_conflict)?;
        }
        let drive_generation: i64 = sqlx::query("UPDATE drives SET namespace_generation=namespace_generation+1 WHERE tenant_id=$1 AND id=$2 RETURNING namespace_generation")
            .bind(tenant_id)
            .bind(drive_id)
            .fetch_one(&mut *transaction)
            .await?
            .get(0);
        let action = if trash { "node.trash" } else { "node.restore" };
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            None,
            Some(resource_id),
            action,
            "allowed",
            if trash {
                "delete_allowed"
            } else {
                "restore_allowed"
            },
            false,
            json!({}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.namespace.changed",
            "node",
            resource_id,
            drive_generation,
        )
        .await?;
        transaction.commit().await?;
        self.node(tenant_id, drive_id, resource_id).await
    }

    pub async fn authorization_snapshot(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
    ) -> Result<AuthorizationSnapshot, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await?;
        let resource = sqlx::query("SELECT d.owner_principal_id,p.kind AS owner_kind,g.id AS owner_group_id,d.acl_generation AS drive_acl_generation,d.namespace_generation,n.namespace_generation AS resource_namespace_generation,n.acl_generation AS resource_acl_generation,actor.generation AS membership_generation FROM drives d JOIN principals p ON p.tenant_id=d.tenant_id AND p.id=d.owner_principal_id LEFT JOIN groups g ON g.tenant_id=p.tenant_id AND g.principal_id=p.id JOIN nodes n ON n.tenant_id=d.tenant_id AND n.drive_id=d.id JOIN principals actor ON actor.tenant_id=d.tenant_id AND actor.id=$4 AND actor.disabled_at IS NULL WHERE d.tenant_id=$1 AND d.id=$2 AND n.id=$3")
            .bind(tenant_id).bind(drive_id).bind(resource_id).bind(actor_principal_id).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::NotFound)?;
        let groups = sqlx::query("SELECT g.id AS group_id,g.principal_id,m.role,m.generation FROM group_memberships m JOIN groups g ON g.tenant_id=m.tenant_id AND g.id=m.group_id WHERE m.tenant_id=$1 AND m.user_principal_id=$2")
            .bind(tenant_id).bind(actor_principal_id).fetch_all(&mut *transaction).await?;
        let membership_generation = resource.get("membership_generation");
        let actor_groups: Vec<GroupInputRow> = groups
            .iter()
            .map(|row| GroupInputRow {
                group_id: row.get("group_id"),
                principal_id: row.get("principal_id"),
                role: row.get("role"),
                generation: row.get("generation"),
            })
            .collect();
        let graph_principals: Vec<Uuid> = sqlx::query_scalar("WITH RECURSIVE graph_principals(principal_id) AS ( \
                SELECT $4::uuid \
                UNION \
                SELECT a.created_by \
                FROM graph_principals graph \
                JOIN principals current_principal ON current_principal.tenant_id=$1 AND current_principal.id=graph.principal_id AND current_principal.disabled_at IS NULL \
                LEFT JOIN users current_user_record ON current_user_record.tenant_id=current_principal.tenant_id AND current_user_record.principal_id=current_principal.id \
                LEFT JOIN group_memberships membership ON membership.tenant_id=$1 AND membership.user_principal_id=graph.principal_id \
                LEFT JOIN groups local_group ON local_group.tenant_id=membership.tenant_id AND local_group.id=membership.group_id \
                JOIN node_ancestry ancestry ON ancestry.tenant_id=$1 AND ancestry.drive_id=$2 AND ancestry.descendant_id=$3 \
                JOIN acl_entries a ON a.tenant_id=ancestry.tenant_id AND a.drive_id=ancestry.drive_id AND a.resource_id=ancestry.ancestor_id \
                JOIN direct_shares share ON share.tenant_id=a.tenant_id AND share.id=a.direct_share_id AND share.revoked_at IS NULL \
                WHERE (current_user_record.id IS NULL OR current_user_record.status='active') \
                  AND (a.principal_id=graph.principal_id OR a.principal_id=local_group.principal_id) \
                  AND a.effect='allow' AND a.inheritance='self_and_descendants' \
            ) \
            SELECT graph.principal_id \
            FROM graph_principals graph \
            JOIN principals p ON p.tenant_id=$1 AND p.id=graph.principal_id AND p.disabled_at IS NULL \
            LEFT JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.id \
            WHERE u.id IS NULL OR u.status='active'")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(resource_id)
            .bind(actor_principal_id)
            .fetch_all(&mut *transaction)
            .await?;
        if graph_principals.is_empty() {
            return Err(DatabaseError::NotFound);
        }
        let fact_groups = sqlx::query("SELECT m.user_principal_id,g.id AS group_id,g.principal_id,m.role,m.generation FROM group_memberships m JOIN groups g ON g.tenant_id=m.tenant_id AND g.id=m.group_id WHERE m.tenant_id=$1 AND m.user_principal_id=ANY($2)")
            .bind(tenant_id)
            .bind(&graph_principals)
            .fetch_all(&mut *transaction)
            .await?;
        let fact_entries = sqlx::query("WITH subjects AS ( \
                SELECT actor_principal_id,actor_principal_id AS acl_principal_id FROM unnest($3::uuid[]) actor(actor_principal_id) \
                UNION \
                SELECT membership.user_principal_id,local_group.principal_id \
                FROM group_memberships membership \
                JOIN groups local_group ON local_group.tenant_id=membership.tenant_id AND local_group.id=membership.group_id \
                WHERE membership.tenant_id=$1 AND membership.user_principal_id=ANY($3) \
            ) \
            SELECT subjects.actor_principal_id,a.id,a.resource_id,a.principal_id,a.action,a.effect,a.inheritance,a.generation,a.created_by,a.direct_share_id,EXISTS (SELECT 1 FROM direct_shares share WHERE share.tenant_id=a.tenant_id AND share.id=a.direct_share_id AND share.revoked_at IS NULL) AS direct_share_active,ancestry.depth,(a.resource_id=$4) AS direct \
            FROM subjects \
            JOIN node_ancestry ancestry ON ancestry.tenant_id=$1 AND ancestry.drive_id=$2 AND ancestry.descendant_id=$4 \
            JOIN acl_entries a ON a.tenant_id=ancestry.tenant_id AND a.drive_id=ancestry.drive_id AND a.resource_id=ancestry.ancestor_id AND a.principal_id=subjects.acl_principal_id \
              AND (a.resource_id=$4 \
                OR (ancestry.depth=1 AND a.inheritance IN ('children','descendants','self_and_descendants')) \
                OR (ancestry.depth>1 AND a.inheritance IN ('descendants','self_and_descendants')))")
            .bind(tenant_id)
            .bind(drive_id)
            .bind(&graph_principals)
            .bind(resource_id)
            .fetch_all(&mut *transaction)
            .await?;
        let mut creator_facts: BTreeMap<Uuid, AuthorizationPrincipalFact> = graph_principals
            .iter()
            .copied()
            .map(|principal_id| {
                (
                    principal_id,
                    AuthorizationPrincipalFact {
                        principal_id,
                        groups: Vec::new(),
                        entries: Vec::new(),
                    },
                )
            })
            .collect();
        for row in fact_groups {
            let principal_id: Uuid = row.get("user_principal_id");
            if let Some(facts) = creator_facts.get_mut(&principal_id) {
                facts.groups.push(GroupInputRow {
                    group_id: row.get("group_id"),
                    principal_id: row.get("principal_id"),
                    role: row.get("role"),
                    generation: row.get("generation"),
                });
            }
        }
        for row in fact_entries {
            let principal_id: Uuid = row.get("actor_principal_id");
            if let Some(facts) = creator_facts.get_mut(&principal_id) {
                facts.entries.push(AclInputRow {
                    id: row.get("id"),
                    resource_id: row.get("resource_id"),
                    principal_id: row.get("principal_id"),
                    action: row.get("action"),
                    effect: row.get("effect"),
                    inheritance: row.get("inheritance"),
                    depth: row.get("depth"),
                    direct: row.get("direct"),
                    generation: row.get("generation"),
                    created_by: row.get("created_by"),
                    direct_share_id: row.get("direct_share_id"),
                    direct_share_active: row.get("direct_share_active"),
                });
            }
        }
        let entries = creator_facts
            .get(&actor_principal_id)
            .map(|facts| facts.entries.clone())
            .ok_or(DatabaseError::NotFound)?;
        let snapshot = AuthorizationSnapshot {
            tenant_id,
            drive_id,
            resource_id,
            owner_principal_id: resource.get("owner_principal_id"),
            owner_kind: resource.get("owner_kind"),
            owner_group_id: resource.get("owner_group_id"),
            actor_principal_id,
            actor_groups,
            entries,
            creator_facts: creator_facts.into_values().collect(),
            membership_generation,
            drive_acl_generation: resource.get("drive_acl_generation"),
            namespace_generation: resource.get("namespace_generation"),
            resource_namespace_generation: resource.get("resource_namespace_generation"),
            resource_acl_generation: resource.get("resource_acl_generation"),
        };
        transaction.commit().await?;
        Ok(snapshot)
    }

    pub async fn publish_authorization_generations(
        &self,
        snapshot: &AuthorizationSnapshot,
        session_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let current=sqlx::query("SELECT p.generation AS membership_generation,d.acl_generation AS drive_acl_generation,d.namespace_generation,n.acl_generation AS resource_acl_generation,LEAST(s.idle_expires_at,s.absolute_expires_at)::text AS session_expires_at FROM api_sessions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id JOIN principals p ON p.tenant_id=s.tenant_id AND p.id=s.principal_id JOIN drives d ON d.tenant_id=s.tenant_id JOIN nodes n ON n.tenant_id=d.tenant_id AND n.drive_id=d.id WHERE s.tenant_id=$1 AND s.id=$2 AND s.principal_id=$3 AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() AND u.status='active' AND p.disabled_at IS NULL AND d.id=$4 AND n.id=$5 FOR SHARE OF s,u,p,d,n")
            .bind(snapshot.tenant_id).bind(session_id).bind(snapshot.actor_principal_id).bind(snapshot.drive_id).bind(snapshot.resource_id).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::StaleGeneration)?;
        if current.get::<i64, _>("membership_generation") != snapshot.membership_generation
            || current.get::<i64, _>("drive_acl_generation") != snapshot.drive_acl_generation
            || current.get::<i64, _>("namespace_generation") != snapshot.namespace_generation
            || current.get::<i64, _>("resource_acl_generation") != snapshot.resource_acl_generation
        {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query("INSERT INTO authorization_generations (tenant_id,session_id,principal_id,drive_id,resource_id,membership_generation,drive_acl_generation,namespace_generation,resource_acl_generation,session_expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz) ON CONFLICT (tenant_id,session_id,principal_id,resource_id) DO UPDATE SET drive_id=EXCLUDED.drive_id,membership_generation=EXCLUDED.membership_generation,drive_acl_generation=EXCLUDED.drive_acl_generation,namespace_generation=EXCLUDED.namespace_generation,resource_acl_generation=EXCLUDED.resource_acl_generation,session_expires_at=EXCLUDED.session_expires_at,updated_at=clock_timestamp()")
            .bind(snapshot.tenant_id)
            .bind(session_id)
            .bind(snapshot.actor_principal_id)
            .bind(snapshot.drive_id)
            .bind(snapshot.resource_id)
            .bind(snapshot.membership_generation)
            .bind(snapshot.drive_acl_generation)
            .bind(snapshot.namespace_generation)
            .bind(snapshot.resource_acl_generation)
            .bind(current.get::<String,_>("session_expires_at"))
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_directory(
        &self,
        tenant_id: Uuid,
        actor: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        parent_id: Uuid,
        display_name: &str,
        name_key: &str,
        expected_generation: i64,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<NodeRecord, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor,
            session_id,
            drive_id,
            parent_id,
            [
                membership_generation,
                drive_acl_generation,
                namespace_generation,
                resource_acl_generation,
            ],
        )
        .await?;
        let generation: i64 = sqlx::query("SELECT namespace_generation FROM nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 FOR UPDATE")
            .bind(tenant_id).bind(drive_id).bind(parent_id).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::NotFound)?.get(0);
        if generation != expected_generation {
            return Err(DatabaseError::StaleGeneration);
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO nodes (tenant_id,drive_id,id,parent_id,kind,display_name,name_key,owner_principal_id) VALUES ($1,$2,$3,$4,'directory',$5,$6,$7)")
            .bind(tenant_id).bind(drive_id).bind(id).bind(parent_id).bind(display_name).bind(name_key).bind(actor).execute(&mut *transaction).await.map_err(map_conflict)?;
        sqlx::query("INSERT INTO node_ancestry (tenant_id,drive_id,ancestor_id,descendant_id,depth) SELECT tenant_id,drive_id,ancestor_id,$4,depth+1 FROM node_ancestry WHERE tenant_id=$1 AND drive_id=$2 AND descendant_id=$3 UNION ALL SELECT $1,$2,$4,$4,0")
            .bind(tenant_id).bind(drive_id).bind(parent_id).bind(id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE nodes SET namespace_generation=namespace_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND drive_id=$2 AND id=$3")
            .bind(tenant_id).bind(drive_id).bind(parent_id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE drives SET namespace_generation=namespace_generation+1 WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id).bind(drive_id).execute(&mut *transaction).await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor),
            None,
            Some(id),
            "node.create",
            "allowed",
            "create_child_allowed",
            false,
            json!({"parent_id":parent_id}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.namespace.changed",
            "node",
            id,
            generation + 1,
        )
        .await?;
        transaction.commit().await?;
        self.node(tenant_id, drive_id, id).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn begin_upload(
        &self,
        tenant_id: Uuid,
        actor: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        parent_id: Uuid,
        node_id: Option<Uuid>,
        expected_parent_generation: Option<i64>,
        expected_head: Option<Uuid>,
        display_name: &str,
        name_key: &str,
        declared_size: i64,
        chunk_size: i32,
        part_count: i32,
        layout: &str,
        declared_media_type: Option<&str>,
        collaboration_checkpoint_id: Option<Uuid>,
        import_intent_id: Option<Uuid>,
        ttl_seconds: i64,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<UploadRecord, DatabaseError> {
        validate_upload_expectation_shape(node_id, expected_parent_generation, expected_head)?;
        if !matches!(layout, "whole" | "chunked")
            || (layout == "whole" && part_count != 1)
            || (layout == "chunked" && part_count < 2)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        if collaboration_checkpoint_id.is_some() && import_intent_id.is_some()
            || collaboration_checkpoint_id.is_some() && node_id.is_none()
            || import_intent_id.is_some() && node_id.is_some()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let authorization_resource_id = node_id.unwrap_or(parent_id);
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor,
            session_id,
            drive_id,
            authorization_resource_id,
            [
                membership_generation,
                drive_acl_generation,
                namespace_generation,
                resource_acl_generation,
            ],
        )
        .await?;
        if let Some(existing) = node_id {
            let node = sqlx::query("SELECT parent_id,kind,head_version_id,trash_root_id FROM nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 FOR UPDATE")
                .bind(tenant_id)
                .bind(drive_id)
                .bind(existing)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(DatabaseError::StaleGeneration)?;
            if node.get::<Option<Uuid>, _>("parent_id") != Some(parent_id)
                || node.get::<String, _>("kind") != "file"
                || node.get::<Option<Uuid>, _>("head_version_id") != expected_head
                || node.get::<Option<Uuid>, _>("trash_root_id").is_some()
            {
                return Err(DatabaseError::StaleGeneration);
            }
        }
        if let Some(expected_parent_generation) = expected_parent_generation {
            let parent = sqlx::query("SELECT kind,namespace_generation FROM nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 FOR UPDATE")
                .bind(tenant_id)
                .bind(drive_id)
                .bind(parent_id)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(DatabaseError::StaleGeneration)?;
            if parent.get::<String, _>("kind") != "directory"
                || parent.get::<i64, _>("namespace_generation") != expected_parent_generation
            {
                return Err(DatabaseError::StaleGeneration);
            }
        }
        if let Some(checkpoint_id) = collaboration_checkpoint_id {
            sqlx::query(
                "SELECT 1 FROM filebelt_collaboration.checkpoints WHERE tenant_id=$1 AND id=$2 \
                 AND node_id=$3 AND base_version_id=$4 AND created_by=$5 AND state='prepared' \
                 AND expires_at>clock_timestamp() FOR UPDATE",
            )
            .bind(tenant_id)
            .bind(checkpoint_id)
            .bind(node_id.ok_or(DatabaseError::InvalidPersistedValue)?)
            .bind(expected_head.ok_or(DatabaseError::InvalidPersistedValue)?)
            .bind(actor)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::StaleGeneration)?;
        }
        if let Some(intent_id) = import_intent_id {
            let intent = sqlx::query(
                "SELECT source_node_id,target_parent_id,target_display_name,target_name_key,principal_id,session_id, \
                        source_membership_generation,source_drive_acl_generation,source_namespace_generation,source_resource_acl_generation, \
                        target_membership_generation,target_drive_acl_generation,target_namespace_generation,target_resource_acl_generation \
                 FROM filebelt_collaboration.import_intents WHERE tenant_id=$1 AND id=$2 \
                   AND drive_id=$3 AND state='active' AND expires_at>clock_timestamp() FOR UPDATE",
            )
            .bind(tenant_id)
            .bind(intent_id)
            .bind(drive_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::StaleGeneration)?;
            if intent.get::<Uuid, _>("target_parent_id") != parent_id
                || intent.get::<String, _>("target_display_name") != display_name
                || intent.get::<String, _>("target_name_key") != name_key
                || intent.get::<Uuid, _>("principal_id") != actor
                || intent.get::<Uuid, _>("session_id") != session_id
                || intent.get::<i64, _>("target_membership_generation") != membership_generation
                || intent.get::<i64, _>("target_drive_acl_generation") != drive_acl_generation
                || intent.get::<i64, _>("target_namespace_generation") != namespace_generation
                || intent.get::<i64, _>("target_resource_acl_generation") != resource_acl_generation
                || declared_media_type != Some("text/markdown")
            {
                return Err(DatabaseError::StaleGeneration);
            }
            lock_authorization_fence(
                &mut transaction,
                tenant_id,
                actor,
                session_id,
                drive_id,
                intent.get("source_node_id"),
                [
                    intent.get("source_membership_generation"),
                    intent.get("source_drive_acl_generation"),
                    intent.get("source_namespace_generation"),
                    intent.get("source_resource_acl_generation"),
                ],
            )
            .await?;
        }
        let backend_id: Uuid = sqlx::query(
            "SELECT id FROM storage_backends WHERE tenant_id=$1 AND kind='posix' FOR UPDATE",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StorageUnavailable)?
        .get(0);
        let reserved = sqlx::query("UPDATE drives SET reserved_bytes=reserved_bytes+$3 WHERE tenant_id=$1 AND id=$2 AND used_physical_bytes+reserved_bytes+$3<=quota_bytes RETURNING namespace_generation")
            .bind(tenant_id).bind(drive_id).bind(declared_size).fetch_optional(&mut *transaction).await?;
        if reserved.is_none() {
            return Err(DatabaseError::QuotaExceeded);
        }
        sqlx::query("SELECT 1 FROM storage_backends b WHERE b.tenant_id=$1 AND b.id=$2 AND b.storage_ready AND b.capacity_checked_at>clock_timestamp()-interval '2 minutes' AND b.capacity_free_bytes-(SELECT COALESCE(sum(d.reserved_bytes),0) FROM drives d WHERE d.tenant_id=$1)>=10737418240 AND (b.capacity_free_bytes-(SELECT COALESCE(sum(d.reserved_bytes),0) FROM drives d WHERE d.tenant_id=$1))::numeric>=b.capacity_total_bytes::numeric*0.05")
            .bind(tenant_id).bind(backend_id).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::StorageUnavailable)?;
        let upload_id = Uuid::new_v4();
        let payload_id = Uuid::new_v4();
        let locator = Uuid::new_v4();
        sqlx::query("INSERT INTO payload_objects (tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes) VALUES ($1,$2,$3,$4,$5,$6,'staging',$7)")
            .bind(tenant_id).bind(payload_id).bind(drive_id).bind(backend_id).bind(locator).bind(layout).bind(declared_size).execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO upload_sessions (tenant_id,id,drive_id,node_id,parent_id,owner_principal_id,payload_id,expected_head_version_id,target_display_name,target_name_key,declared_size_bytes,chunk_size_bytes,part_count,declared_media_type,collaboration_checkpoint_id,import_intent_id,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'open',clock_timestamp()+make_interval(secs=>$17))")
            .bind(tenant_id).bind(upload_id).bind(drive_id).bind(node_id).bind(parent_id).bind(actor).bind(payload_id).bind(expected_head).bind(display_name).bind(name_key).bind(declared_size).bind(chunk_size).bind(part_count).bind(declared_media_type).bind(collaboration_checkpoint_id).bind(import_intent_id).bind(ttl_seconds).execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO quota_reservations (tenant_id,id,drive_id,upload_id,bytes,state,expires_at) VALUES ($1,$2,$3,$4,$5,'active',clock_timestamp()+make_interval(secs=>$6))")
            .bind(tenant_id).bind(Uuid::new_v4()).bind(drive_id).bind(upload_id).bind(declared_size).bind(ttl_seconds).execute(&mut *transaction).await?;
        for part in 0..part_count {
            sqlx::query("INSERT INTO upload_parts (tenant_id,upload_id,part_number,state,size_bytes,locator) VALUES ($1,$2,$3,'allocated',0,$4)")
                .bind(tenant_id).bind(upload_id).bind(part).bind(Uuid::new_v4()).execute(&mut *transaction).await?;
        }
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor),
            None,
            node_id,
            "upload.begin",
            "allowed",
            "write_content_allowed",
            false,
            json!({"upload_id":upload_id,"bytes":declared_size}),
        )
        .await?;
        transaction.commit().await?;
        Ok(UploadRecord {
            tenant_id,
            upload_id,
            drive_id,
            node_id,
            parent_id,
            owner_principal_id: actor,
            payload_id,
            backend_id,
            payload_locator: locator,
            expected_head_version_id: expected_head,
            target_display_name: display_name.into(),
            target_name_key: name_key.into(),
            declared_size_bytes: declared_size,
            chunk_size_bytes: chunk_size,
            part_count,
            fencing_token: 1,
            state: "open".into(),
            declared_media_type: declared_media_type.map(str::to_owned),
            collaboration_checkpoint_id,
            import_intent_id,
        })
    }

    pub async fn upload(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
    ) -> Result<UploadRecord, DatabaseError> {
        let row = sqlx::query("SELECT u.*,p.backend_id,p.locator AS payload_locator FROM upload_sessions u JOIN payload_objects p ON p.tenant_id=u.tenant_id AND p.id=u.payload_id WHERE u.tenant_id=$1 AND u.id=$2")
            .bind(tenant_id).bind(upload_id).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(upload_from_row(&row))
    }

    pub async fn upload_owned_by(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
        owner_principal_id: Uuid,
    ) -> Result<UploadRecord, DatabaseError> {
        let row = sqlx::query("SELECT u.*,p.backend_id,p.locator AS payload_locator FROM upload_sessions u JOIN payload_objects p ON p.tenant_id=u.tenant_id AND p.id=u.payload_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.owner_principal_id=$3")
            .bind(tenant_id)
            .bind(upload_id)
            .bind(owner_principal_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(upload_from_row(&row))
    }

    pub async fn upload_for_payload(
        &self,
        tenant_id: Uuid,
        payload_id: Uuid,
    ) -> Result<UploadRecord, DatabaseError> {
        let row = sqlx::query("SELECT u.*,p.backend_id,p.locator AS payload_locator FROM upload_sessions u JOIN payload_objects p ON p.tenant_id=u.tenant_id AND p.id=u.payload_id WHERE u.tenant_id=$1 AND u.payload_id=$2")
            .bind(tenant_id)
            .bind(payload_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(upload_from_row(&row))
    }

    pub async fn upload_part(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
        part: i32,
    ) -> Result<UploadPartRecord, DatabaseError> {
        let row=sqlx::query("SELECT part_number,locator,state,size_bytes,blake3 FROM upload_parts WHERE tenant_id=$1 AND upload_id=$2 AND part_number=$3")
            .bind(tenant_id).bind(upload_id).bind(part).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(UploadPartRecord {
            part_number: row.get("part_number"),
            locator: row.get("locator"),
            state: row.get("state"),
            size_bytes: row.get("size_bytes"),
            blake3: row.get("blake3"),
        })
    }

    pub async fn upload_parts(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
    ) -> Result<Vec<UploadPartRecord>, DatabaseError> {
        let rows=sqlx::query("SELECT part_number,locator,state,size_bytes,blake3 FROM upload_parts WHERE tenant_id=$1 AND upload_id=$2 ORDER BY part_number")
            .bind(tenant_id).bind(upload_id).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| UploadPartRecord {
                part_number: row.get("part_number"),
                locator: row.get("locator"),
                state: row.get("state"),
                size_bytes: row.get("size_bytes"),
                blake3: row.get("blake3"),
            })
            .collect())
    }

    pub async fn uploads_needing_staging_cleanup(
        &self,
        tenant_id: Uuid,
        backend_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        let rows = sqlx::query("SELECT u.id FROM upload_sessions u JOIN payload_objects p ON p.tenant_id=u.tenant_id AND p.id=u.payload_id WHERE u.tenant_id=$1 AND p.backend_id=$2 AND u.state IN ('finalized','committed') AND u.staging_cleaned_at IS NULL AND EXISTS (SELECT 1 FROM upload_parts part WHERE part.tenant_id=u.tenant_id AND part.upload_id=u.id AND part.state='durable') ORDER BY u.created_at LIMIT $3")
            .bind(tenant_id)
            .bind(backend_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|row| row.get("id")).collect())
    }

    pub async fn mark_upload_staging_cleaned(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let updated = sqlx::query("UPDATE upload_sessions SET staging_cleaned_at=COALESCE(staging_cleaned_at,clock_timestamp()) WHERE tenant_id=$1 AND id=$2 AND state IN ('finalized','committed')")
            .bind(tenant_id)
            .bind(upload_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if updated != 1 {
            return Err(DatabaseError::Conflict);
        }
        Ok(())
    }

    pub async fn consume_capability_nonce(
        &self,
        tenant_id: Uuid,
        nonce_digest: &[u8],
        operation: &str,
        expires_at_unix: i64,
    ) -> Result<(), DatabaseError> {
        let inserted=sqlx::query("INSERT INTO capability_nonces (tenant_id,nonce_digest,operation,expires_at,consumed_at) VALUES ($1,$2,$3,to_timestamp($4),clock_timestamp()) ON CONFLICT DO NOTHING")
            .bind(tenant_id).bind(nonce_digest).bind(operation).bind(expires_at_unix as f64).execute(&self.pool).await?.rows_affected();
        if inserted != 1 {
            return Err(DatabaseError::Conflict);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn authorization_generations_match(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        principal_id: Uuid,
        drive_id: Uuid,
        resource_id: Uuid,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<bool, DatabaseError> {
        let row=sqlx::query("SELECT membership_generation,drive_acl_generation,namespace_generation,resource_acl_generation FROM authorization_generations WHERE tenant_id=$1 AND session_id=$2 AND principal_id=$3 AND drive_id=$4 AND resource_id=$5 AND session_expires_at>clock_timestamp()")
            .bind(tenant_id).bind(session_id).bind(principal_id).bind(drive_id).bind(resource_id).fetch_optional(&self.pool).await?;
        Ok(row.is_some_and(|row| {
            row.get::<i64, _>("drive_acl_generation") == drive_acl_generation
                && row.get::<i64, _>("namespace_generation") == namespace_generation
                && row.get::<i64, _>("resource_acl_generation") == resource_acl_generation
                && row.get::<i64, _>("membership_generation") == membership_generation
        }))
    }

    pub async fn mark_part_durable(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
        part: i32,
        fencing_token: i64,
        size: i32,
        digest: &[u8],
    ) -> Result<(), DatabaseError> {
        let updated=sqlx::query("UPDATE upload_parts p SET state='durable',size_bytes=$5,blake3=$6,durable_at=clock_timestamp() FROM upload_sessions u WHERE p.tenant_id=$1 AND p.upload_id=$2 AND p.part_number=$3 AND u.tenant_id=p.tenant_id AND u.id=p.upload_id AND u.state='open' AND u.fencing_token=$4")
            .bind(tenant_id).bind(upload_id).bind(part).bind(fencing_token).bind(size).bind(digest).execute(&self.pool).await?.rows_affected();
        if updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        Ok(())
    }

    pub async fn mark_upload_finalized(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
        fencing_token: i64,
        finalization_owner: Uuid,
        digest: &[u8],
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row=sqlx::query("UPDATE upload_sessions SET state='finalized',finalization_owner=NULL,finalization_lease_expires_at=NULL WHERE tenant_id=$1 AND id=$2 AND state='finalizing' AND fencing_token=$3 AND finalization_owner=$4 RETURNING payload_id,declared_size_bytes")
            .bind(tenant_id).bind(upload_id).bind(fencing_token).bind(finalization_owner).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::StaleGeneration)?;
        let payload_id: Uuid = row.get("payload_id");
        let size: i64 = row.get("declared_size_bytes");
        let updated = sqlx::query("UPDATE payload_objects SET state='finalized',blake3=$3,size_bytes=$4,finalized_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='finalizing'")
            .bind(tenant_id).bind(payload_id).bind(digest).bind(size).execute(&mut *transaction).await?.rows_affected();
        if updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn claim_upload_finalization(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
        fencing_token: i64,
        finalization_owner: Uuid,
        lease_seconds: i64,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query("UPDATE upload_sessions SET state='finalizing',finalization_owner=$4,finalization_lease_expires_at=clock_timestamp()+make_interval(secs=>$5) WHERE tenant_id=$1 AND id=$2 AND state='open' AND fencing_token=$3 AND expires_at>clock_timestamp() AND (SELECT count(*) FROM upload_parts WHERE tenant_id=$1 AND upload_id=$2 AND state='durable')=part_count RETURNING payload_id")
            .bind(tenant_id).bind(upload_id).bind(fencing_token).bind(finalization_owner).bind(lease_seconds)
            .fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::Conflict)?;
        let payload_id: Uuid = row.get("payload_id");
        let updated = sqlx::query("UPDATE payload_objects SET state='finalizing' WHERE tenant_id=$1 AND id=$2 AND state='staging'")
            .bind(tenant_id).bind(payload_id).execute(&mut *transaction).await?.rows_affected();
        if updated != 1 {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn heartbeat_upload_finalization(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
        fencing_token: i64,
        finalization_owner: Uuid,
        lease_seconds: i64,
    ) -> Result<(), DatabaseError> {
        let updated = sqlx::query("UPDATE upload_sessions SET finalization_lease_expires_at=clock_timestamp()+make_interval(secs=>$5) WHERE tenant_id=$1 AND id=$2 AND state='finalizing' AND fencing_token=$3 AND finalization_owner=$4")
            .bind(tenant_id).bind(upload_id).bind(fencing_token).bind(finalization_owner).bind(lease_seconds)
            .execute(&self.pool).await?.rows_affected();
        if updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        Ok(())
    }

    pub async fn abort_upload_finalization(
        &self,
        tenant_id: Uuid,
        upload_id: Uuid,
        fencing_token: i64,
        finalization_owner: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query("UPDATE upload_sessions SET state='open',fencing_token=fencing_token+1,finalization_owner=NULL,finalization_lease_expires_at=NULL WHERE tenant_id=$1 AND id=$2 AND state='finalizing' AND fencing_token=$3 AND finalization_owner=$4 RETURNING payload_id")
            .bind(tenant_id).bind(upload_id).bind(fencing_token).bind(finalization_owner)
            .fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::StaleGeneration)?;
        let payload_id: Uuid = row.get("payload_id");
        let updated = sqlx::query("UPDATE payload_objects SET state='staging' WHERE tenant_id=$1 AND id=$2 AND state='finalizing'")
            .bind(tenant_id).bind(payload_id).execute(&mut *transaction).await?.rows_affected();
        if updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn reopen_expired_upload_finalizations(
        &self,
        tenant_id: Uuid,
    ) -> Result<u64, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let rows = sqlx::query("UPDATE upload_sessions SET state='open',fencing_token=fencing_token+1,finalization_owner=NULL,finalization_lease_expires_at=NULL WHERE tenant_id=$1 AND state='finalizing' AND finalization_lease_expires_at<=clock_timestamp() RETURNING payload_id")
            .bind(tenant_id).fetch_all(&mut *transaction).await?;
        for row in &rows {
            let updated = sqlx::query("UPDATE payload_objects SET state='staging' WHERE tenant_id=$1 AND id=$2 AND state='finalizing'")
                .bind(tenant_id).bind(row.get::<Uuid,_>("payload_id")).execute(&mut *transaction).await?.rows_affected();
            if updated != 1 {
                return Err(DatabaseError::StaleGeneration);
            }
        }
        transaction.commit().await?;
        u64::try_from(rows.len()).map_err(|_| DatabaseError::InvalidPersistedValue)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_upload(
        &self,
        tenant_id: Uuid,
        actor: Uuid,
        session_id: Uuid,
        upload_id: Uuid,
        expected_fencing_token: i64,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<(Uuid, Uuid), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row=sqlx::query("SELECT u.*,p.blake3 FROM upload_sessions u JOIN payload_objects p ON p.tenant_id=u.tenant_id AND p.id=u.payload_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.owner_principal_id=$3 AND u.fencing_token=$4 AND u.state='finalized' AND p.state='finalized' FOR UPDATE OF u,p")
            .bind(tenant_id).bind(upload_id).bind(actor).bind(expected_fencing_token).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::StaleGeneration)?;
        let drive_id: Uuid = row.get("drive_id");
        let parent_id: Uuid = row.get("parent_id");
        let authorization_resource_id: Uuid =
            row.get::<Option<Uuid>, _>("node_id").unwrap_or(parent_id);
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor,
            session_id,
            drive_id,
            authorization_resource_id,
            [
                membership_generation,
                drive_acl_generation,
                namespace_generation,
                resource_acl_generation,
            ],
        )
        .await?;
        let mut node_id: Option<Uuid> = row.get("node_id");
        let expected: Option<Uuid> = row.get("expected_head_version_id");
        if let Some(existing) = node_id {
            let current:Option<Uuid>=sqlx::query("SELECT head_version_id FROM nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 FOR UPDATE")
                .bind(tenant_id).bind(drive_id).bind(existing).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::NotFound)?.get(0);
            if current != expected {
                return Err(DatabaseError::Conflict);
            }
        } else {
            let created = Uuid::new_v4();
            let parent: Uuid = row.get("parent_id");
            sqlx::query("INSERT INTO nodes (tenant_id,drive_id,id,parent_id,kind,display_name,name_key,owner_principal_id) VALUES ($1,$2,$3,$4,'file',$5,$6,$7)")
                .bind(tenant_id).bind(drive_id).bind(created).bind(parent).bind(row.get::<String,_>("target_display_name")).bind(row.get::<String,_>("target_name_key")).bind(actor).execute(&mut *transaction).await.map_err(map_conflict)?;
            sqlx::query("INSERT INTO node_ancestry (tenant_id,drive_id,ancestor_id,descendant_id,depth) SELECT tenant_id,drive_id,ancestor_id,$4,depth+1 FROM node_ancestry WHERE tenant_id=$1 AND drive_id=$2 AND descendant_id=$3 UNION ALL SELECT $1,$2,$4,$4,0")
                .bind(tenant_id).bind(drive_id).bind(parent).bind(created).execute(&mut *transaction).await?;
            node_id = Some(created);
        }
        let node_id = node_id.ok_or(DatabaseError::InvalidPersistedValue)?;
        let version_id = Uuid::new_v4();
        let ordinal:i64=sqlx::query("SELECT COALESCE(max(ordinal),0)+1 FROM file_versions WHERE tenant_id=$1 AND node_id=$2")
            .bind(tenant_id).bind(node_id).fetch_one(&mut *transaction).await?.get(0);
        let payload_id: Uuid = row.get("payload_id");
        let size: i64 = row.get("declared_size_bytes");
        let digest: Vec<u8> = row.get("blake3");
        let declared_media_type: Option<String> = row.get("declared_media_type");
        let checkpoint_id: Option<Uuid> = row.get("collaboration_checkpoint_id");
        let import_intent_id: Option<Uuid> = row.get("import_intent_id");
        let (origin_kind, source_version_id, mcp_assisted) = if let Some(checkpoint_id) =
            checkpoint_id
        {
            let checkpoint = sqlx::query(
                "SELECT base_version_id,source_size_bytes,source_blake3,mcp_assisted \
                 FROM filebelt_collaboration.checkpoints WHERE tenant_id=$1 AND id=$2 \
                   AND node_id=$3 AND created_by=$4 AND state='prepared' \
                   AND expires_at>clock_timestamp() FOR UPDATE",
            )
            .bind(tenant_id)
            .bind(checkpoint_id)
            .bind(node_id)
            .bind(actor)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::StaleGeneration)?;
            if checkpoint.get::<Uuid, _>("base_version_id")
                != expected.ok_or(DatabaseError::StaleGeneration)?
                || checkpoint.get::<i64, _>("source_size_bytes") != size
                || checkpoint.get::<Vec<u8>, _>("source_blake3") != digest
                || declared_media_type.as_deref() != Some("text/markdown")
            {
                return Err(DatabaseError::Conflict);
            }
            (
                "collaboration_checkpoint",
                Some(checkpoint.get("base_version_id")),
                checkpoint.get("mcp_assisted"),
            )
        } else if let Some(import_intent_id) = import_intent_id {
            let intent = sqlx::query(
                    "SELECT source_node_id,source_version_id,source_membership_generation, \
                            source_drive_acl_generation,source_namespace_generation,source_resource_acl_generation \
                     FROM filebelt_collaboration.import_intents \
                 WHERE tenant_id=$1 AND id=$2 AND principal_id=$3 AND session_id=$4 \
                   AND state='active' AND expires_at>clock_timestamp() FOR UPDATE",
                )
                .bind(tenant_id)
                .bind(import_intent_id)
                .bind(actor)
                .bind(session_id)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(DatabaseError::StaleGeneration)?;
            if declared_media_type.as_deref() != Some("text/markdown") {
                return Err(DatabaseError::Conflict);
            }
            lock_authorization_fence(
                &mut transaction,
                tenant_id,
                actor,
                session_id,
                drive_id,
                intent.get("source_node_id"),
                [
                    intent.get("source_membership_generation"),
                    intent.get("source_drive_acl_generation"),
                    intent.get("source_namespace_generation"),
                    intent.get("source_resource_acl_generation"),
                ],
            )
            .await?;
            ("import", Some(intent.get("source_version_id")), false)
        } else if row.get::<Option<Uuid>, _>("node_id").is_some()
            && declared_media_type.as_deref() == Some("text/markdown")
        {
            ("markdown_save", expected, false)
        } else {
            ("upload", None, false)
        };
        let creator_display_name: String = sqlx::query_scalar(
            "SELECT u.display_name FROM api_sessions s JOIN users u \
             ON u.tenant_id=s.tenant_id AND u.id=s.user_id \
             WHERE s.tenant_id=$1 AND s.id=$2 AND s.principal_id=$3",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(actor)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query("INSERT INTO file_versions (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,media_type,created_by,origin_kind,source_version_id,creator_display_name,mcp_assisted) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(tenant_id).bind(node_id).bind(version_id).bind(ordinal).bind(payload_id).bind(size).bind(&digest).bind(&declared_media_type).bind(actor).bind(origin_kind).bind(source_version_id).bind(&creator_display_name).bind(mcp_assisted).execute(&mut *transaction).await?;
        sqlx::query("UPDATE nodes SET head_version_id=$4,namespace_generation=namespace_generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND drive_id=$2 AND id=$3")
            .bind(tenant_id).bind(drive_id).bind(node_id).bind(version_id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE payload_objects SET state='referenced',referenced_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id).bind(payload_id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE upload_sessions SET state='committed' WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(upload_id)
            .execute(&mut *transaction)
            .await?;
        if let Some(checkpoint_id) = checkpoint_id {
            let checkpoint_updated = sqlx::query(
                "UPDATE filebelt_collaboration.checkpoints SET state='committed', \
                 committed_version_id=$3,consumed_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND id=$2 AND state='prepared'",
            )
            .bind(tenant_id)
            .bind(checkpoint_id)
            .bind(version_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let epoch_updated = sqlx::query(
                "UPDATE filebelt_collaboration.epochs e SET state='closed',dirty=false, \
                 closed_at=clock_timestamp(),fencing_token=fencing_token+1 \
                 FROM filebelt_collaboration.checkpoints c \
                 WHERE c.tenant_id=$1 AND c.id=$2 AND e.tenant_id=c.tenant_id \
                   AND e.room_id=c.room_id AND e.epoch=c.epoch AND e.state='active'",
            )
            .bind(tenant_id)
            .bind(checkpoint_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if checkpoint_updated != 1 || epoch_updated != 1 {
                return Err(DatabaseError::Conflict);
            }
        } else {
            sqlx::query(
                "UPDATE filebelt_collaboration.epochs e SET state='frozen', \
                 freeze_reason='external_head',fencing_token=fencing_token+1 \
                 FROM filebelt_collaboration.rooms r \
                 WHERE r.tenant_id=$1 AND r.drive_id=$2 AND r.node_id=$3 \
                   AND e.tenant_id=r.tenant_id AND e.room_id=r.id AND e.state='active'",
            )
            .bind(tenant_id)
            .bind(drive_id)
            .bind(node_id)
            .execute(&mut *transaction)
            .await?;
        }
        if let Some(import_intent_id) = import_intent_id {
            let consumed = sqlx::query(
                "UPDATE filebelt_collaboration.import_intents SET state='consumed', \
                 consumed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 \
                   AND principal_id=$3 AND session_id=$4 AND state='active'",
            )
            .bind(tenant_id)
            .bind(import_intent_id)
            .bind(actor)
            .bind(session_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if consumed != 1 {
                return Err(DatabaseError::Conflict);
            }
        }
        sqlx::query(
            "UPDATE quota_reservations SET state='committed' WHERE tenant_id=$1 AND upload_id=$2",
        )
        .bind(tenant_id)
        .bind(upload_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE drives SET reserved_bytes=reserved_bytes-$3,used_physical_bytes=used_physical_bytes+$3,namespace_generation=namespace_generation+1 WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id).bind(drive_id).bind(size).execute(&mut *transaction).await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor),
            None,
            Some(node_id),
            "version.commit",
            "allowed",
            "create_version_allowed",
            false,
            json!({"version_id":version_id}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.namespace.changed",
            "node",
            node_id,
            ordinal,
        )
        .await?;
        transaction.commit().await?;
        Ok((node_id, version_id))
    }

    pub async fn payload_for_node(
        &self,
        tenant_id: Uuid,
        node_id: Uuid,
        version_id: Option<Uuid>,
    ) -> Result<PayloadRecord, DatabaseError> {
        let row=sqlx::query("SELECT p.tenant_id,p.id AS payload_id,p.drive_id,p.backend_id,p.locator,p.layout,p.state,p.size_bytes,p.blake3 FROM file_versions v JOIN nodes n ON n.tenant_id=v.tenant_id AND n.id=v.node_id JOIN payload_objects p ON p.tenant_id=v.tenant_id AND p.id=v.payload_id WHERE v.tenant_id=$1 AND v.node_id=$2 AND v.id=COALESCE($3,n.head_version_id) AND p.state='referenced'")
            .bind(tenant_id).bind(node_id).bind(version_id).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(PayloadRecord {
            tenant_id: row.get("tenant_id"),
            payload_id: row.get("payload_id"),
            drive_id: row.get("drive_id"),
            backend_id: row.get("backend_id"),
            locator: row.get("locator"),
            layout: row.get("layout"),
            state: row.get("state"),
            size_bytes: row.get("size_bytes"),
            blake3: row.get("blake3"),
        })
    }

    pub async fn payload(
        &self,
        tenant_id: Uuid,
        payload_id: Uuid,
    ) -> Result<PayloadRecord, DatabaseError> {
        let row=sqlx::query("SELECT tenant_id,id AS payload_id,drive_id,backend_id,locator,layout,state,size_bytes,blake3 FROM payload_objects WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id).bind(payload_id).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(PayloadRecord {
            tenant_id: row.get("tenant_id"),
            payload_id: row.get("payload_id"),
            drive_id: row.get("drive_id"),
            backend_id: row.get("backend_id"),
            locator: row.get("locator"),
            layout: row.get("layout"),
            state: row.get("state"),
            size_bytes: row.get("size_bytes"),
            blake3: row.get("blake3"),
        })
    }

    /// Complete physical deletion of a finalized upload that never committed.
    ///
    /// The payload terminal state, upload fence, reservation state, and drive
    /// accounting move together so a retry cannot release the same bytes twice.
    pub async fn complete_orphan_payload_deletion(
        &self,
        tenant_id: Uuid,
        payload_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT u.id AS upload_id,u.drive_id,u.declared_size_bytes \
             FROM payload_objects p \
             JOIN upload_sessions u ON u.tenant_id=p.tenant_id AND u.payload_id=p.id \
             JOIN quota_reservations q ON q.tenant_id=u.tenant_id AND q.upload_id=u.id \
             WHERE p.tenant_id=$1 AND p.id=$2 AND p.state='deleting' \
               AND u.state='finalized' AND q.state='active' \
             FOR UPDATE OF p,u,q",
        )
        .bind(tenant_id)
        .bind(payload_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let upload_id: Uuid = row.get("upload_id");
        let drive_id: Uuid = row.get("drive_id");
        let bytes: i64 = row.get("declared_size_bytes");

        let payload_updated = sqlx::query(
            "UPDATE payload_objects SET state='deleted' \
             WHERE tenant_id=$1 AND id=$2 AND state='deleting'",
        )
        .bind(tenant_id)
        .bind(payload_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let upload_updated = sqlx::query(
            "UPDATE upload_sessions \
             SET state='expired',fencing_token=fencing_token+1,staging_cleaned_at=NULL \
             WHERE tenant_id=$1 AND id=$2 AND state='finalized'",
        )
        .bind(tenant_id)
        .bind(upload_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let reservation_updated = sqlx::query(
            "UPDATE quota_reservations SET state='released' \
             WHERE tenant_id=$1 AND upload_id=$2 AND state='active'",
        )
        .bind(tenant_id)
        .bind(upload_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let drive_updated = sqlx::query(
            "UPDATE drives SET reserved_bytes=reserved_bytes-$3 \
             WHERE tenant_id=$1 AND id=$2 AND reserved_bytes>=$3",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(bytes)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if payload_updated != 1
            || upload_updated != 1
            || reservation_updated != 1
            || drive_updated != 1
        {
            return Err(DatabaseError::StaleGeneration);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn expire_uploads(&self, tenant_id: Uuid) -> Result<u64, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let rows=sqlx::query("UPDATE upload_sessions SET state='expired',fencing_token=fencing_token+1 WHERE tenant_id=$1 AND state='open' AND expires_at<=clock_timestamp() RETURNING tenant_id,id,drive_id,declared_size_bytes")
            .bind(tenant_id).fetch_all(&mut *tx).await?;
        for row in &rows {
            let tenant_id: Uuid = row.get("tenant_id");
            let upload_id: Uuid = row.get("id");
            let drive_id: Uuid = row.get("drive_id");
            let bytes: i64 = row.get("declared_size_bytes");
            sqlx::query("UPDATE quota_reservations SET state='released' WHERE tenant_id=$1 AND upload_id=$2 AND state='active'").bind(tenant_id).bind(upload_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE drives SET reserved_bytes=GREATEST(0,reserved_bytes-$3) WHERE tenant_id=$1 AND id=$2").bind(tenant_id).bind(drive_id).bind(bytes).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO jobs (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) VALUES ($1,$2,'upload_reconcile','queued',50,$3,$4,$5) ON CONFLICT DO NOTHING")
                .bind(tenant_id).bind(Uuid::new_v4()).bind(upload_id).bind(format!("expire:{upload_id}")).bind(json!({"upload_id":upload_id})).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(rows.len() as u64)
    }

    pub async fn complete_job(&self, job: &JobRecord, outcome: &str) -> Result<(), DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let result=sqlx::query("UPDATE jobs SET state='complete',lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='running' AND fencing_token=$3")
            .bind(job.tenant_id).bind(job.id).bind(job.fencing_token).execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query("UPDATE job_attempts SET finished_at=clock_timestamp(),outcome=$4 WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3")
            .bind(job.tenant_id).bind(job.id).bind(job.attempt).bind(outcome).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn fail_job(
        &self,
        job: &JobRecord,
        error_code: &str,
        retryable: bool,
    ) -> Result<(), DatabaseError> {
        let state = if retryable && job.attempt < 8 {
            "retry_wait"
        } else {
            "terminal"
        };
        let delay_seconds =
            i64::from(1_i32.checked_shl(job.attempt.min(8) as u32).unwrap_or(256)).min(300);
        let mut tx = self.pool.begin().await?;
        let result=sqlx::query("UPDATE jobs SET state=$4,last_error_code=$5,available_at=clock_timestamp()+make_interval(secs=>random()*$6::double precision),lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='running' AND fencing_token=$3")
            .bind(job.tenant_id).bind(job.id).bind(job.fencing_token).bind(state).bind(error_code).bind(delay_seconds).execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query("UPDATE job_attempts SET finished_at=clock_timestamp(),outcome=$4 WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND finished_at IS NULL")
            .bind(job.tenant_id).bind(job.id).bind(job.attempt).bind(error_code).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn pending_outbox(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, Uuid, String, Vec<u8>)>, DatabaseError> {
        let rows=sqlx::query("SELECT tenant_id,id,topic,payload FROM outbox_events WHERE tenant_id=$1 AND published_at IS NULL AND next_attempt_at<=clock_timestamp() ORDER BY occurred_at LIMIT $2").bind(tenant_id).bind(limit).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get("tenant_id"),
                    row.get("id"),
                    row.get("topic"),
                    row.get("payload"),
                )
            })
            .collect())
    }

    pub async fn mark_outbox_published(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            "UPDATE outbox_events SET published_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(event_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_outbox_retry(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE outbox_events SET publish_attempts=publish_attempts+1,next_attempt_at=clock_timestamp()+interval '5 seconds' WHERE tenant_id=$1 AND id=$2").bind(tenant_id).bind(event_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn claim_job(
        &self,
        tenant_id: Uuid,
        worker_id: Uuid,
        lease_seconds: i64,
    ) -> Result<Option<JobRecord>, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE job_attempts a SET finished_at=clock_timestamp(),outcome='lease_expired' FROM jobs j WHERE a.tenant_id=$1 AND j.tenant_id=$1 AND a.tenant_id=j.tenant_id AND a.job_id=j.id AND a.finished_at IS NULL AND j.state='running' AND j.lease_expires_at<=clock_timestamp() AND j.attempt_count>=8")
            .bind(tenant_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE jobs SET state='terminal',last_error_code='lease_attempts_exhausted',lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND state='running' AND lease_expires_at<=clock_timestamp() AND attempt_count>=8")
            .bind(tenant_id).execute(&mut *tx).await?;
        let row=sqlx::query("SELECT tenant_id,id,state,attempt_count FROM jobs WHERE tenant_id=$1 AND ((state IN ('queued','retry_wait') AND available_at<=clock_timestamp()) OR (state='running' AND lease_expires_at<=clock_timestamp() AND attempt_count<8)) ORDER BY priority,available_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1")
            .bind(tenant_id).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let id: Uuid = row.get("id");
        if row.get::<String, _>("state") == "running" {
            sqlx::query("UPDATE job_attempts SET finished_at=clock_timestamp(),outcome='lease_expired' WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND finished_at IS NULL")
                .bind(tenant_id).bind(id).bind(row.get::<i32,_>("attempt_count")).execute(&mut *tx).await?;
        }
        let claimed=sqlx::query("UPDATE jobs SET state='running',lease_owner=$3,lease_expires_at=clock_timestamp()+make_interval(secs=>$4),fencing_token=fencing_token+1,attempt_count=attempt_count+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING kind,payload,attempt_count,fencing_token")
            .bind(tenant_id).bind(id).bind(worker_id).bind(lease_seconds).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO job_attempts (tenant_id,job_id,attempt,worker_id,fencing_token) VALUES ($1,$2,$3,$4,$5)")
            .bind(tenant_id).bind(id).bind(claimed.get::<i32,_>("attempt_count")).bind(worker_id).bind(claimed.get::<i64,_>("fencing_token")).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(JobRecord {
            tenant_id,
            id,
            kind: claimed.get("kind"),
            payload: claimed.get("payload"),
            attempt: claimed.get("attempt_count"),
            fencing_token: claimed.get("fencing_token"),
        }))
    }
}

fn validate_upload_expectation_shape(
    node_id: Option<Uuid>,
    expected_parent_generation: Option<i64>,
    expected_head: Option<Uuid>,
) -> Result<(), DatabaseError> {
    if expected_parent_generation.is_some_and(|generation| generation <= 0)
        || (node_id.is_none() && (expected_parent_generation.is_none() || expected_head.is_some()))
        || (node_id.is_some() && expected_head.is_none())
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

async fn resolve_advanced_acl_target(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    target_kind: &str,
    verified_email: Option<&str>,
    group_id: Option<Uuid>,
) -> Result<Uuid, DatabaseError> {
    match target_kind {
        "user" => {
            let email = verified_email
                .map(str::trim)
                .filter(|email| !email.is_empty() && email.len() <= 320)
                .ok_or(DatabaseError::InvalidPersistedValue)?;
            sqlx::query_scalar(
                "SELECT u.principal_id FROM users u \
                 JOIN principals p ON p.tenant_id=u.tenant_id AND p.id=u.principal_id \
                 WHERE u.tenant_id=$1 AND lower(u.verified_email)=lower($2) \
                   AND u.status='active' AND p.disabled_at IS NULL FOR SHARE OF u,p",
            )
            .bind(tenant_id)
            .bind(email)
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(DatabaseError::NotFound)
        }
        "group" => {
            let id = group_id.ok_or(DatabaseError::InvalidPersistedValue)?;
            sqlx::query_scalar(
                "SELECT g.principal_id FROM groups g \
                 JOIN principals p ON p.tenant_id=g.tenant_id AND p.id=g.principal_id \
                 WHERE g.tenant_id=$1 AND g.id=$2 AND p.disabled_at IS NULL \
                 FOR SHARE OF g,p",
            )
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(DatabaseError::NotFound)
        }
        _ => Err(DatabaseError::InvalidPersistedValue),
    }
}

async fn advanced_acl_actions_for_target(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    target_principal_id: Uuid,
) -> Result<BTreeSet<Action>, DatabaseError> {
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM acl_entries WHERE tenant_id=$1 AND drive_id=$2 AND resource_id=$3 \
         AND principal_id=$4 AND direct_share_id IS NULL FOR SHARE",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(resource_id)
    .bind(target_principal_id)
    .fetch_all(&mut **transaction)
    .await?;
    actions
        .into_iter()
        .map(|action| advanced_acl_action(&action))
        .collect()
}

fn advanced_acl_actions(
    entries: &[AdvancedAclEntryInput<'_>],
) -> Result<BTreeSet<Action>, DatabaseError> {
    entries
        .iter()
        .map(|entry| advanced_acl_action(entry.action))
        .collect()
}

fn advanced_acl_action(value: &str) -> Result<Action, DatabaseError> {
    Action::ALL
        .into_iter()
        .find(|action| action.as_str() == value)
        .ok_or(DatabaseError::InvalidPersistedValue)
}

fn replacement_actions_are_covered(
    covered_actions: &BTreeSet<Action>,
    submitted_actions: &BTreeSet<Action>,
    current_actions: &BTreeSet<Action>,
) -> bool {
    covered_actions.contains(&Action::ManageAcl)
        && submitted_actions
            .union(current_actions)
            .all(|action| covered_actions.contains(action))
}

fn require_exact_advanced_acl_target(
    expected_target_principal_id: Uuid,
    target_principal_id: Uuid,
) -> Result<(), DatabaseError> {
    if expected_target_principal_id == target_principal_id {
        Ok(())
    } else {
        Err(DatabaseError::StaleGeneration)
    }
}

fn stale_advanced_acl_target_drift(error: DatabaseError) -> DatabaseError {
    match error {
        DatabaseError::NotFound => DatabaseError::StaleGeneration,
        error => error,
    }
}

#[allow(clippy::too_many_arguments)]
async fn lock_authorization_fence(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    session_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    expected: [i64; 4],
) -> Result<(), DatabaseError> {
    let current = sqlx::query("SELECT p.generation AS membership_generation,d.acl_generation AS drive_acl_generation,d.namespace_generation,n.acl_generation AS resource_acl_generation FROM api_sessions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id JOIN principals p ON p.tenant_id=s.tenant_id AND p.id=s.principal_id JOIN drives d ON d.tenant_id=s.tenant_id JOIN nodes n ON n.tenant_id=d.tenant_id AND n.drive_id=d.id WHERE s.tenant_id=$1 AND s.id=$2 AND s.principal_id=$3 AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() AND u.status='active' AND p.disabled_at IS NULL AND d.id=$4 AND n.id=$5 FOR UPDATE OF s,u,p,d,n")
        .bind(tenant_id)
        .bind(session_id)
        .bind(actor_principal_id)
        .bind(drive_id)
        .bind(resource_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
    let actual: [i64; 4] = [
        current.get("membership_generation"),
        current.get("drive_acl_generation"),
        current.get("namespace_generation"),
        current.get("resource_acl_generation"),
    ];
    if actual != expected {
        return Err(DatabaseError::StaleGeneration);
    }
    Ok(())
}

/// Fence a collaboration manifest against the exact session and Virtual ACL
/// projection without giving the collaboration role mutation rights on policy
/// rows. `FOR SHARE` conflicts with the authorization-changing updates that
/// advance the corresponding generation.
async fn lock_collaboration_authorization_fence(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    session_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    expected: [i64; 4],
) -> Result<(), DatabaseError> {
    let current = sqlx::query("SELECT p.generation AS membership_generation,d.acl_generation AS drive_acl_generation,d.namespace_generation,n.acl_generation AS resource_acl_generation FROM api_sessions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id JOIN principals p ON p.tenant_id=s.tenant_id AND p.id=s.principal_id JOIN drives d ON d.tenant_id=s.tenant_id JOIN nodes n ON n.tenant_id=d.tenant_id AND n.drive_id=d.id WHERE s.tenant_id=$1 AND s.id=$2 AND s.principal_id=$3 AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() AND u.status='active' AND p.disabled_at IS NULL AND d.id=$4 AND n.id=$5 FOR SHARE OF s,u,p,d,n")
        .bind(tenant_id)
        .bind(session_id)
        .bind(actor_principal_id)
        .bind(drive_id)
        .bind(resource_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
    let actual: [i64; 4] = [
        current.get("membership_generation"),
        current.get("drive_acl_generation"),
        current.get("namespace_generation"),
        current.get("resource_acl_generation"),
    ];
    if actual != expected {
        return Err(DatabaseError::StaleGeneration);
    }
    Ok(())
}

fn share_preset_actions(preset: &str) -> Result<&'static [&'static str], DatabaseError> {
    const VIEWER: &[&str] = &[
        "READ_METADATA",
        "LIST_CHILDREN",
        "READ_CONTENT",
        "USE_EXTERNAL_EDITOR",
    ];
    const CONTRIBUTOR: &[&str] = &[
        "READ_METADATA",
        "LIST_CHILDREN",
        "READ_CONTENT",
        "CREATE_CHILD",
        "WRITE_CONTENT",
        "CREATE_VERSION",
        "RENAME",
        "MOVE",
        "DELETE",
        "RESTORE",
        "SET_ATTRIBUTES",
        "USE_EXTERNAL_EDITOR",
        "COMMENT",
        "REVIEW",
    ];
    const MANAGER: &[&str] = &[
        "READ_METADATA",
        "LIST_CHILDREN",
        "READ_CONTENT",
        "CREATE_CHILD",
        "WRITE_CONTENT",
        "CREATE_VERSION",
        "RENAME",
        "MOVE",
        "DELETE",
        "RESTORE",
        "SET_ATTRIBUTES",
        "SHARE",
        "MANAGE_ACL",
        "USE_EXTERNAL_EDITOR",
        "COMMENT",
        "REVIEW",
    ];
    match preset {
        "viewer" => Ok(VIEWER),
        "contributor" => Ok(CONTRIBUTOR),
        "manager" => Ok(MANAGER),
        _ => Err(DatabaseError::InvalidPersistedValue),
    }
}

fn file_version_from_row(row: &sqlx::postgres::PgRow) -> FileVersionRecord {
    FileVersionRecord {
        id: row.get("id"),
        node_id: row.get("node_id"),
        ordinal: row.get("ordinal"),
        size_bytes: row.get("size_bytes"),
        created_by: row.get("created_by"),
        restored_from_version_id: row.get("restored_from_version_id"),
        created_at: row.get("created_at"),
        current: row.get("current"),
        media_type: row.get("media_type"),
        origin_kind: row.get("origin_kind"),
        source_version_id: row.get("source_version_id"),
        creator_display_name: row.get("creator_display_name"),
        mcp_assisted: row.get("mcp_assisted"),
    }
}

fn node_from_row(row: &sqlx::postgres::PgRow) -> NodeRecord {
    NodeRecord {
        id: row.get("id"),
        drive_id: row.get("drive_id"),
        parent_id: row.get("parent_id"),
        kind: row.get("kind"),
        display_name: row.get("display_name"),
        name_key: row.get("name_key"),
        head_version_id: row.get("head_version_id"),
        namespace_generation: row.get("namespace_generation"),
        acl_generation: row.get("acl_generation"),
        trashed: row.get::<Option<Uuid>, _>("trash_root_id").is_some(),
        updated_at: row.get("updated_at_text"),
        size_bytes: row.get("size_bytes"),
        version_ordinal: row.get("version_ordinal"),
        head_media_type: row.get("head_media_type"),
    }
}
fn upload_from_row(row: &sqlx::postgres::PgRow) -> UploadRecord {
    UploadRecord {
        tenant_id: row.get("tenant_id"),
        upload_id: row.get("id"),
        drive_id: row.get("drive_id"),
        node_id: row.get("node_id"),
        parent_id: row.get("parent_id"),
        owner_principal_id: row.get("owner_principal_id"),
        payload_id: row.get("payload_id"),
        backend_id: row.get("backend_id"),
        payload_locator: row.get("payload_locator"),
        expected_head_version_id: row.get("expected_head_version_id"),
        target_display_name: row.get("target_display_name"),
        target_name_key: row.get("target_name_key"),
        declared_size_bytes: row.get("declared_size_bytes"),
        chunk_size_bytes: row.get("chunk_size_bytes"),
        part_count: row.get("part_count"),
        fencing_token: row.get("fencing_token"),
        state: row.get("state"),
        declared_media_type: row.get("declared_media_type"),
        collaboration_checkpoint_id: row.get("collaboration_checkpoint_id"),
        import_intent_id: row.get("import_intent_id"),
    }
}
fn map_conflict(error: sqlx::Error) -> DatabaseError {
    if matches!(&error,sqlx::Error::Database(db) if db.is_unique_violation()) {
        DatabaseError::Conflict
    } else {
        DatabaseError::Sql(error)
    }
}

fn map_security_admission(error: sqlx::Error) -> DatabaseError {
    if matches!(&error, sqlx::Error::Database(db) if db.code().as_deref() == Some("FB001")) {
        DatabaseError::SecurityAdmissionBlocked
    } else {
        map_conflict(error)
    }
}
async fn is_admin(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    issuer: &str,
    subject: &str,
) -> Result<bool, DatabaseError> {
    Ok(sqlx::query("SELECT EXISTS (SELECT 1 FROM tenant_admin_bindings WHERE tenant_id=$1 AND issuer=$2 AND subject=$3)").bind(tenant_id).bind(issuer).bind(subject).fetch_one(&mut **tx).await?.get(0))
}
async fn private_drive_for_user(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    principal_id: Uuid,
) -> Result<(Uuid, Uuid), DatabaseError> {
    let row=sqlx::query("SELECT d.id,n.id AS root_id FROM drives d JOIN nodes n ON n.tenant_id=d.tenant_id AND n.drive_id=d.id AND n.parent_id IS NULL WHERE d.tenant_id=$1 AND d.owner_principal_id=$2 AND d.kind='private'").bind(tenant_id).bind(principal_id).fetch_optional(&mut **tx).await?.ok_or(DatabaseError::NotFound)?;
    Ok((row.get("id"), row.get("root_id")))
}
#[allow(clippy::too_many_arguments)]
async fn insert_audit(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor: Option<Uuid>,
    target: Option<Uuid>,
    resource: Option<Uuid>,
    action: &str,
    outcome: &str,
    reason: &str,
    privacy: bool,
    details: Value,
) -> Result<Uuid, DatabaseError> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO audit_events (tenant_id,id,actor_principal_id,target_principal_id,resource_id,action,outcome,reason_code,privacy_visible,details) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(tenant_id).bind(id).bind(actor).bind(target).bind(resource).bind(action).bind(outcome).bind(reason).bind(privacy).bind(details).execute(&mut **tx).await?;
    Ok(id)
}
async fn insert_outbox(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    topic: &str,
    aggregate_type: &str,
    aggregate_id: Uuid,
    generation: i64,
) -> Result<Uuid, DatabaseError> {
    let id = Uuid::new_v4();
    let occurred_at: i64 = sqlx::query("SELECT extract(epoch from clock_timestamp())::bigint")
        .fetch_one(&mut **tx)
        .await?
        .get(0);
    let unsigned_generation =
        u64::try_from(generation).map_err(|_| DatabaseError::InvalidPersistedValue)?;
    let payload = EventEnvelope {
        event_id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        aggregate_type: aggregate_type.into(),
        aggregate_id: aggregate_id.to_string(),
        aggregate_generation: unsigned_generation,
        event_type: topic.into(),
        occurred_at_unix_seconds: occurred_at,
        payload: Vec::new(),
    }
    .encode_to_vec();
    sqlx::query("INSERT INTO outbox_events (tenant_id,id,topic,aggregate_type,aggregate_id,aggregate_generation,partition_key,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)").bind(tenant_id).bind(id).bind(topic).bind(aggregate_type).bind(aggregate_id).bind(generation).bind(format!("{tenant_id}:{aggregate_id}")).bind(payload).execute(&mut **tx).await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn quota_defaults_are_tiered() {
        assert_eq!(SHARED_DRIVE_QUOTA_BYTES, PRIVATE_DRIVE_QUOTA_BYTES * 10);
    }

    #[test]
    fn upload_expectations_distinguish_new_files_from_new_versions() {
        let node_id = Uuid::new_v4();
        let head_id = Uuid::new_v4();

        assert!(validate_upload_expectation_shape(None, Some(1), None).is_ok());
        assert!(validate_upload_expectation_shape(Some(node_id), None, Some(head_id)).is_ok());
        assert!(validate_upload_expectation_shape(Some(node_id), Some(1), Some(head_id)).is_ok());

        assert!(validate_upload_expectation_shape(None, None, None).is_err());
        assert!(validate_upload_expectation_shape(None, Some(0), None).is_err());
        assert!(validate_upload_expectation_shape(None, Some(1), Some(head_id)).is_err());
        assert!(validate_upload_expectation_shape(Some(node_id), None, None).is_err());
    }

    #[test]
    fn upload_mutations_are_transactionally_authorization_fenced() {
        let source = include_str!("lib.rs");
        let begin_upload = source
            .split_once("pub async fn begin_upload")
            .expect("begin_upload exists")
            .1
            .split_once("pub async fn upload(")
            .expect("upload follows begin_upload")
            .0;
        assert!(begin_upload.contains("lock_authorization_fence("));
        assert!(begin_upload.contains("expected_parent_generation"));
        assert!(begin_upload.contains("expected_head"));

        let commit_upload = source
            .split_once("pub async fn commit_upload")
            .expect("commit_upload exists")
            .1
            .split_once("pub async fn payload_for_node")
            .expect("payload_for_node follows commit_upload")
            .0;
        assert!(commit_upload.contains("lock_authorization_fence("));
        assert!(commit_upload.contains("expected_fencing_token"));
        assert!(commit_upload.contains("u.owner_principal_id=$3"));
        assert!(commit_upload.contains("u.fencing_token=$4"));
    }

    #[test]
    fn directory_mutation_is_transactionally_authorization_fenced() {
        let source = include_str!("lib.rs");
        let create_directory = source
            .split_once("pub async fn create_directory")
            .expect("create_directory exists")
            .1
            .split_once("pub async fn begin_upload")
            .expect("begin_upload follows create_directory")
            .0;
        assert!(create_directory.contains("session_id: Uuid"));
        assert!(create_directory.contains("lock_authorization_fence("));
        assert!(create_directory.contains("expected_generation"));
    }

    #[test]
    fn advanced_acl_replacement_is_fenced_and_preserves_share_rows() {
        let source = include_str!("lib.rs");
        let replacement = source
            .split_once("pub async fn replace_advanced_acl_entries")
            .expect("advanced ACL replacement exists")
            .1
            .split_once("pub async fn restore_file_version")
            .expect("restore follows ACL replacement")
            .0;
        assert!(replacement.contains("lock_authorization_fence("));
        assert!(replacement.contains("direct_share_id IS NULL"));
        assert!(replacement.contains("target_principal_id == owner_principal_id"));
        assert!(replacement.contains("filebelt.v1.acl.changed"));
        assert!(replacement.contains("require_exact_advanced_acl_target"));
        assert!(replacement.contains("replacement_actions_are_covered"));
    }

    #[test]
    fn advanced_acl_replacement_coverage_requires_submitted_and_deleted_actions() {
        let submitted_actions = [Action::Export].into_iter().collect();
        let current_actions = [Action::ReadContent].into_iter().collect();
        let mut covered_actions: BTreeSet<_> =
            [Action::ManageAcl, Action::Export].into_iter().collect();

        assert!(!replacement_actions_are_covered(
            &covered_actions,
            &submitted_actions,
            &current_actions,
        ));

        covered_actions.insert(Action::ReadContent);
        assert!(replacement_actions_are_covered(
            &covered_actions,
            &submitted_actions,
            &current_actions,
        ));

        assert!(!replacement_actions_are_covered(
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        ));
        assert!(replacement_actions_are_covered(
            &[Action::ManageAcl].into_iter().collect(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        ));
    }

    #[test]
    fn advanced_acl_replacement_requires_the_preflight_target() {
        let expected = Uuid::new_v4();

        assert!(require_exact_advanced_acl_target(expected, expected).is_ok());
        assert!(matches!(
            require_exact_advanced_acl_target(expected, Uuid::new_v4()),
            Err(DatabaseError::StaleGeneration)
        ));
    }

    #[test]
    fn collaboration_fence_uses_shared_locks_without_policy_mutation_privileges() {
        let source = include_str!("lib.rs");
        let fence = source
            .split_once("async fn lock_collaboration_authorization_fence")
            .expect("collaboration fence exists")
            .1
            .split_once("fn share_preset_actions")
            .expect("share presets follow fences")
            .0;
        assert!(fence.contains("FOR SHARE OF s,u,p,d,n"));
        assert!(fence.contains("u.status='active'"));
        assert!(!fence.contains("FOR UPDATE"));
    }

    #[test]
    fn oidc_attempts_are_reclaimed_and_admission_bounded() {
        let source = include_str!("lib.rs");
        let create_attempt = source
            .split_once("pub async fn create_oidc_attempt")
            .expect("create_oidc_attempt exists")
            .1
            .split_once("pub async fn consume_oidc_attempt")
            .expect("consume_oidc_attempt follows create_oidc_attempt")
            .0;
        assert!(create_attempt.contains("DELETE FROM oidc_login_attempts"));
        assert!(create_attempt.contains("active >= 4096"));
        assert!(create_attempt.contains("FOR UPDATE"));
    }

    #[test]
    fn authorization_snapshots_collect_recursive_share_creator_facts_atomically() {
        let source = include_str!("lib.rs");
        let snapshot = source
            .split_once("pub async fn authorization_snapshot")
            .expect("authorization snapshot exists")
            .1
            .split_once("pub async fn publish_authorization_generations")
            .expect("generation publication follows snapshot")
            .0;
        assert!(snapshot.contains("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"));
        assert!(snapshot.contains("WITH RECURSIVE graph_principals"));
        assert!(snapshot.contains("share.revoked_at IS NULL"));
        assert!(snapshot.contains("a.inheritance='self_and_descendants'"));
        assert!(snapshot.contains("ancestry.depth=1 AND a.inheritance IN"));
        assert!(snapshot.contains("ancestry.depth>1 AND a.inheritance IN"));
        assert!(snapshot.contains("AS direct_share_active"));
        assert!(snapshot.contains("creator_facts: creator_facts.into_values().collect()"));
        assert!(snapshot.contains("transaction.commit().await?"));
    }

    #[test]
    fn descendant_share_admission_maps_the_database_guard_code() {
        let source = include_str!("lib.rs");
        assert!(source.contains("descendant_share_admission_open($1)"));
        assert!(source.contains("Some(\"FB001\")"));
        assert!(source.contains("DatabaseError::SecurityAdmissionBlocked"));
    }

    #[test]
    fn session_lifecycle_writes_append_audit_events() {
        let source = include_str!("lib.rs");
        for (start, end, action) in [
            (
                "pub async fn create_session",
                "pub async fn create_oidc_attempt",
                "session.create",
            ),
            (
                "pub async fn revoke_session",
                "pub async fn list_sessions",
                "session.revoke",
            ),
            (
                "pub async fn revoke_all_sessions",
                "pub async fn idempotency_record",
                "session.revoke_all",
            ),
        ] {
            let method = source
                .split_once(start)
                .expect("session lifecycle method exists")
                .1
                .split_once(end)
                .expect("following method exists")
                .0;
            assert!(method.contains("insert_audit("));
            assert!(method.contains(action));
            assert!(method.contains("transaction.commit().await?"));
        }
    }

    #[test]
    fn backend_capacity_reservations_lock_before_drive_updates() {
        let source = include_str!("lib.rs");
        let begin_upload = source
            .split_once("pub async fn begin_upload")
            .expect("begin_upload exists")
            .1
            .split_once("pub async fn upload(")
            .expect("upload follows begin_upload")
            .0;
        let backend_lock = begin_upload
            .find("storage_backends WHERE tenant_id=$1 AND kind='posix' FOR UPDATE")
            .expect("shared backend lock exists");
        let drive_reservation = begin_upload
            .find("UPDATE drives SET reserved_bytes")
            .expect("drive reservation exists");
        assert!(backend_lock < drive_reservation);
    }

    #[test]
    fn direct_uploads_cannot_claim_mcp_provenance() {
        let source = include_str!("lib.rs");
        let begin_upload = source
            .split_once("pub async fn begin_upload")
            .expect("begin upload exists")
            .1
            .split_once("pub async fn upload(")
            .expect("upload follows begin upload")
            .0;
        assert!(!begin_upload.contains("mcp_invocation_id"));

        let commit = source
            .split_once("pub async fn commit_upload")
            .expect("commit exists")
            .1
            .split_once("pub async fn payload_for_node")
            .expect("payload lookup follows commit")
            .0;
        assert!(!commit.contains("mcp_invocation_id"));
    }

    #[test]
    fn upload_finalization_is_leased_fenced_and_recoverable() {
        let source = include_str!("lib.rs");
        let claim = source
            .split_once("pub async fn claim_upload_finalization")
            .expect("claim method exists")
            .1
            .split_once("pub async fn heartbeat_upload_finalization")
            .expect("heartbeat follows claim")
            .0;
        assert!(claim.contains("state='open'"));
        assert!(claim.contains("SET state='finalizing'"));
        assert!(claim.contains("finalization_owner=$4"));

        let completion = source
            .split_once("pub async fn mark_upload_finalized")
            .expect("completion method exists")
            .1
            .split_once("pub async fn claim_upload_finalization")
            .expect("claim follows completion")
            .0;
        assert!(completion.contains("state='finalizing'"));
        assert!(completion.contains("finalization_owner=$4"));

        let recovery = source
            .split_once("pub async fn reopen_expired_upload_finalizations")
            .expect("recovery method exists")
            .1
            .split_once("pub async fn commit_upload")
            .expect("commit follows recovery")
            .0;
        assert!(recovery.contains("fencing_token=fencing_token+1"));
        assert!(recovery.contains("finalization_lease_expires_at<=clock_timestamp()"));

        let migration = include_str!("../../../migrations/postgres/000001_phase2_core.sql");
        assert!(migration.contains("uploads_finalization_lease_index"));
        assert!(migration.contains("finalization_owner IS NOT NULL"));
    }

    #[test]
    fn disabled_principals_cannot_refresh_authorization_projections() {
        let source = include_str!("lib.rs");
        let snapshot = source
            .split_once("pub async fn authorization_snapshot")
            .expect("authorization_snapshot exists")
            .1
            .split_once("pub async fn publish_authorization_generations")
            .expect("publish_authorization_generations follows authorization_snapshot")
            .0;
        assert!(snapshot.contains("actor.id=$4 AND actor.disabled_at IS NULL"));

        let publish = source
            .split_once("pub async fn publish_authorization_generations")
            .expect("publish_authorization_generations exists")
            .1
            .split_once("pub async fn create_directory")
            .expect("create_directory follows publish_authorization_generations")
            .0;
        assert!(publish.contains("u.status='active' AND p.disabled_at IS NULL"));

        let migration = include_str!("../../../migrations/postgres/000001_phase2_core.sql");
        assert!(migration.contains("invalidate_principal_capability_projection"));
        assert!(migration.contains("AFTER UPDATE OF disabled_at ON principals"));
        assert!(migration.contains("OLD.disabled_at IS DISTINCT FROM NEW.disabled_at"));
    }
}

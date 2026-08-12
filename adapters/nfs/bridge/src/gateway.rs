// SPDX-License-Identifier: LGPL-3.0-or-later

//! NFS gateway admission, GSS-bound session fencing, and export lifecycle.

use crate::config::BridgeConfig;
use crate::control::{ControlError, ExportInstaller};
use crate::ipc::{BRIDGE_UID, IPC_GID, socket_has_expected_metadata};
use crate::vfs::{VfsClient, VfsClientError};
use filebelt_vfs_protocol::vfs_request::Operation;
use filebelt_vfs_protocol::{
    GatewayDrainRequest, GatewayHelloRequest, GatewayReconcileRequest, MountProtocol,
    NFS_AUTHORITY_SCHEMA_REVISION, NFS_CONFIG_FORMAT, NFS_GATEWAY_LEASE_SECONDS,
    NfsAuthenticateRequest, NfsGatewayCompatibility, NfsGatewayFeature, PROTOCOL_VERSION, VfsError,
    VfsRequest, VfsResponse, canonical_nfs_request_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

const STATE_FORMAT: u32 = 1;
const MAX_STATE_BYTES: u64 = 16_384;
const MAX_SESSIONS: usize = 4_096;
const LEASE_REFRESH_AFTER: Duration = Duration::from_secs(20);
const LEASE_DURATION: Duration = Duration::from_secs(NFS_GATEWAY_LEASE_SECONDS as u64);

pub trait VfsExecutor {
    fn execute(&self, request: &VfsRequest) -> Result<VfsResponse, VfsClientError>;

    fn execute_lifecycle(&self, request: &VfsRequest) -> Result<VfsResponse, VfsClientError> {
        self.execute(request)
    }
}

impl VfsExecutor for VfsClient {
    fn execute(&self, request: &VfsRequest) -> Result<VfsResponse, VfsClientError> {
        self.execute(request)
    }

    fn execute_lifecycle(&self, request: &VfsRequest) -> Result<VfsResponse, VfsClientError> {
        self.execute_lifecycle(request)
    }
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("gateway bootstrap or lease renewal failed")]
    Bootstrap,
    #[error("FSAL export application failed")]
    Export,
    #[error("gateway request is invalid or unauthenticated")]
    Request,
    #[error("gateway state is unavailable")]
    State,
    #[error("VFS transport failed")]
    Vfs,
}

#[derive(Clone, Debug)]
struct SessionFence {
    session_id: String,
    credential_generation: u64,
    authorization_generation: u64,
    expires_at_unix_seconds: i64,
    nfs_client_id: Option<String>,
    nfs_session_id: Option<String>,
    projection: filebelt_vfs_protocol::NfsSessionProjection,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayStateFile {
    format: u32,
    boot_id: String,
    tenant_id: String,
    gateway_epoch: u64,
    feature_generation: u64,
    export_generation: u64,
    lease_expires_at_unix_seconds: i64,
    draining: bool,
}

#[derive(Clone, Debug)]
struct AdmittedState {
    tenant_id: Uuid,
    gateway_epoch: u64,
    feature_generation: u64,
    export_generation: u64,
    refresh_at: Instant,
    lease_expires_at: Instant,
}

impl AdmittedState {
    fn fence(&self) -> RenewalFence {
        RenewalFence {
            tenant_id: self.tenant_id,
            gateway_epoch: self.gateway_epoch,
            feature_generation: self.feature_generation,
            export_generation: self.export_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewalFence {
    tenant_id: Uuid,
    gateway_epoch: u64,
    feature_generation: u64,
    export_generation: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct RenewalCandidate {
    fence: RenewalFence,
}

#[derive(Clone, Debug)]
pub struct RenewalOffer {
    fence: RenewalFence,
    exports: Vec<filebelt_vfs_protocol::NfsExportManifestEntry>,
}

impl RenewalOffer {
    #[must_use]
    pub fn fence(&self) -> RenewalFence {
        self.fence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingRenewal {
    expected: RenewalFence,
    candidate: RenewalFence,
}

#[derive(Clone)]
pub struct GatewayMaintenance<E, I> {
    config: BridgeConfig,
    executor: E,
    installer: I,
    boot_id: Uuid,
}

pub struct Gateway<E, I> {
    config: BridgeConfig,
    executor: E,
    installer: I,
    boot_id: Uuid,
    admitted: Option<AdmittedState>,
    pending_renewal: Option<PendingRenewal>,
    sessions: BTreeMap<[u8; 32], SessionFence>,
}

impl<E: VfsExecutor, I: ExportInstaller> Gateway<E, I> {
    #[must_use]
    pub fn new(config: BridgeConfig, executor: E, installer: I) -> Self {
        Self {
            config,
            executor,
            installer,
            boot_id: Uuid::new_v4(),
            admitted: None,
            pending_renewal: None,
            sessions: BTreeMap::new(),
        }
    }

    pub fn bootstrap(&mut self) -> Result<(), GatewayError> {
        let offer = fetch_offer(&self.config, &self.executor, self.boot_id)?;
        let candidate = apply_offer(&self.executor, &self.installer, self.boot_id, &offer)?;
        self.apply_renewal(None, candidate)
    }

    #[must_use]
    pub fn renewal_fence(&self) -> Option<RenewalFence> {
        self.admitted
            .as_ref()
            .filter(|state| state.refresh_at <= Instant::now())
            .map(AdmittedState::fence)
    }

    pub fn apply_renewal(
        &mut self,
        expected: Option<RenewalFence>,
        candidate: RenewalCandidate,
    ) -> Result<(), GatewayError> {
        let valid_attempt = match expected {
            None => self.admitted.is_none() && self.pending_renewal.is_none(),
            Some(previous) if previous == candidate.fence => {
                self.admitted.as_ref().map(AdmittedState::fence) == Some(previous)
                    && self.pending_renewal.is_none()
                    && self.disk_state_matches(previous, true)
            }
            Some(previous) => {
                self.admitted.is_none()
                    && self.pending_renewal
                        == Some(PendingRenewal {
                            expected: previous,
                            candidate: candidate.fence,
                        })
                    && self.disk_state_matches(previous, false)
            }
        };
        if !valid_attempt {
            return Err(GatewayError::State);
        }
        let preserve_sessions = renewal_preserves_sessions(expected, candidate.fence);
        if !preserve_sessions {
            self.sessions.clear();
        }
        let now = Instant::now();
        let admitted = AdmittedState {
            tenant_id: candidate.fence.tenant_id,
            gateway_epoch: candidate.fence.gateway_epoch,
            feature_generation: candidate.fence.feature_generation,
            export_generation: candidate.fence.export_generation,
            refresh_at: now + LEASE_REFRESH_AFTER,
            lease_expires_at: now + LEASE_DURATION,
        };
        self.write_state(&admitted, false)?;
        self.admitted = Some(admitted);
        self.pending_renewal = None;
        Ok(())
    }

    /// Fence a changed authority set before the worker mutates the local FSAL.
    /// Returns false when a newer renewal/expiry already superseded this work.
    pub fn prepare_renewal(
        &mut self,
        expected: RenewalFence,
        candidate: RenewalFence,
    ) -> Result<bool, GatewayError> {
        if self.admitted.as_ref().map(AdmittedState::fence) != Some(expected) {
            return Ok(false);
        }
        if !self.disk_state_matches(expected, true) {
            self.admitted = None;
            self.sessions.clear();
            return Err(GatewayError::State);
        }
        if candidate == expected {
            return Ok(true);
        }
        self.admitted = None;
        self.sessions.clear();
        self.pending_renewal = Some(PendingRenewal {
            expected,
            candidate,
        });
        /* Persist unready only after memory admission has already been
         * revoked. A write failure therefore cannot restore service. */
        expire_state(&self.config.state_file, self.boot_id)?;
        Ok(true)
    }

    pub fn fail_renewal(&mut self, expected: RenewalFence) {
        if self
            .pending_renewal
            .is_some_and(|pending| pending.expected == expected)
        {
            self.pending_renewal = None;
            self.admitted = None;
            self.sessions.clear();
            return;
        }
        let expired = self.admitted.as_ref().is_some_and(|state| {
            state.fence() == expected && state.lease_expires_at <= Instant::now()
        });
        if expired {
            self.admitted = None;
            self.sessions.clear();
            let _ = expire_state(&self.config.state_file, self.boot_id);
        }
    }

    pub fn handle(&mut self, mut request: VfsRequest) -> VfsResponse {
        let request_id = Uuid::new_v4();
        request.request_id = request_id.to_string();
        match self.handle_inner(request) {
            Ok(response) => response,
            Err(error) => VfsResponse::failure(request_id, error, "nfs_gateway_rejected"),
        }
    }

    fn handle_inner(&mut self, mut request: VfsRequest) -> Result<VfsResponse, VfsError> {
        if self.ensure_admitted().is_err() {
            return Err(VfsError::Unavailable);
        }
        let admitted_fence = self.admitted.as_ref().ok_or(VfsError::Unavailable)?.fence();
        if !self.disk_state_matches(admitted_fence, true) {
            self.admitted = None;
            self.sessions.clear();
            return Err(VfsError::Unavailable);
        }
        if request.protocol_version != PROTOCOL_VERSION
            || request.protocol != MountProtocol::Nfs as i32
            || !request.tenant_id.is_empty()
            || !request.gateway_id.is_empty()
            || request.gateway_epoch != 0
            || !request.session_id.is_empty()
            || request.credential_generation != 0
            || request.authorization_generation != 0
        {
            return Err(VfsError::InvalidRequest);
        }
        let admitted = self.admitted.as_ref().ok_or(VfsError::Unavailable)?;
        request.tenant_id = admitted.tenant_id.to_string();
        request.gateway_id = self.boot_id.to_string();
        request.gateway_epoch = admitted.gateway_epoch;

        // Recovery authority is bridge-owned. The C callback can select only
        // the persisted state identifier; it cannot forge another NFS client
        // or a stale/current gateway epoch.
        if let (Some(context), Some(Operation::Reclaim(reclaim))) =
            (request.nfs_context.as_ref(), request.operation.as_mut())
        {
            reclaim.client_id.clone_from(&context.client_id);
            reclaim.gateway_epoch = admitted.gateway_epoch;
        }

        match request.operation.as_ref() {
            Some(Operation::NfsAuthenticate(authenticate)) => {
                if request.nfs_context.is_some()
                    || !valid_principal_for_realm(
                        &authenticate.kerberos_principal,
                        &self.config.kerberos_realm,
                    )
                    || authenticate.context_expires_at_unix_seconds <= unix_seconds()
                {
                    return Err(VfsError::Unauthenticated);
                }
                let binding: [u8; 32] = authenticate
                    .gss_binding_digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| VfsError::Unauthenticated)?;
                request.validate().map_err(|_| VfsError::InvalidRequest)?;
                let response = self
                    .executor
                    .execute(&request)
                    .map_err(|_| VfsError::Unavailable)?;
                if response.error == VfsError::Ok as i32 {
                    self.admit_session(binding, authenticate, &response)
                        .map_err(|_| VfsError::Unauthenticated)?;
                }
                Ok(response)
            }
            Some(
                Operation::GatewayHello(_)
                | Operation::GatewayDrain(_)
                | Operation::GatewayReconcile(_)
                | Operation::Authenticate(_),
            )
            | None => Err(VfsError::InvalidRequest),
            Some(_) => {
                let binding: [u8; 32] = request
                    .nfs_context
                    .as_ref()
                    .ok_or(VfsError::Unauthenticated)?
                    .gss_binding_digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| VfsError::Unauthenticated)?;
                self.remove_expired_sessions();
                let session = self
                    .sessions
                    .get(&binding)
                    .ok_or(VfsError::Unauthenticated)?;
                let context = request.nfs_context.as_ref().expect("checked NFS context");
                if session.nfs_client_id.as_deref() != Some(context.client_id.as_str())
                    || session.nfs_session_id.as_deref() != Some(context.nfs_session_id.as_str())
                {
                    return Err(VfsError::Unauthenticated);
                }
                request.session_id.clone_from(&session.session_id);
                request.credential_generation = session.credential_generation;
                request.authorization_generation = session.authorization_generation;
                request
                    .nfs_context
                    .as_mut()
                    .expect("checked NFS context")
                    .request_digest
                    .clear();
                if operation_is_mutation(request.operation.as_ref().expect("checked operation")) {
                    let digest = canonical_nfs_request_digest(&request);
                    request
                        .nfs_context
                        .as_mut()
                        .expect("checked NFS context")
                        .request_digest = digest.to_vec();
                }
                request.validate().map_err(|_| VfsError::InvalidRequest)?;
                let response = self
                    .executor
                    .execute(&request)
                    .map_err(|_| VfsError::Unavailable)?;
                if matches!(
                    VfsError::try_from(response.error),
                    Ok(VfsError::Unauthenticated | VfsError::StaleGeneration)
                ) {
                    self.sessions.remove(&binding);
                }
                Ok(response)
            }
        }
    }

    fn ensure_admitted(&mut self) -> Result<(), GatewayError> {
        if self
            .admitted
            .as_ref()
            .is_some_and(|state| state.lease_expires_at > Instant::now())
        {
            return Ok(());
        }
        self.admitted = None;
        self.sessions.clear();
        Err(GatewayError::Bootstrap)
    }

    fn admit_session(
        &mut self,
        binding: [u8; 32],
        authenticate: &NfsAuthenticateRequest,
        response: &VfsResponse,
    ) -> Result<(), GatewayError> {
        let projection = response
            .nfs_session_projection
            .as_ref()
            .ok_or(GatewayError::Request)?;
        let expires_at = projection
            .absolute_expires_at_unix_seconds
            .min(authenticate.context_expires_at_unix_seconds);
        if expires_at <= unix_seconds()
            || Uuid::parse_str(&response.session_id).is_err()
            || response.credential_generation == 0
            || response.authorization_generation == 0
            || self
                .admitted
                .as_ref()
                .is_none_or(|state| projection.feature_generation != state.feature_generation)
        {
            return Err(GatewayError::Request);
        }
        self.remove_expired_sessions();
        if self.sessions.len() >= MAX_SESSIONS && !self.sessions.contains_key(&binding) {
            return Err(GatewayError::Request);
        }
        self.sessions.insert(
            binding,
            SessionFence {
                session_id: response.session_id.clone(),
                credential_generation: response.credential_generation,
                authorization_generation: response.authorization_generation,
                expires_at_unix_seconds: expires_at,
                nfs_client_id: None,
                nfs_session_id: None,
                projection: projection.clone(),
            },
        );
        Ok(())
    }

    pub(crate) fn bind_fsal_session(
        &mut self,
        binding: [u8; 32],
        client_id: &str,
        nfs_session_id: &str,
    ) -> Result<(), GatewayError> {
        self.remove_expired_sessions();
        let session = self
            .sessions
            .get_mut(&binding)
            .ok_or(GatewayError::Request)?;
        match (&session.nfs_client_id, &session.nfs_session_id) {
            (None, None) => {
                session.nfs_client_id = Some(client_id.to_owned());
                session.nfs_session_id = Some(nfs_session_id.to_owned());
                Ok(())
            }
            (Some(expected_client), Some(expected_session))
                if expected_client == client_id && expected_session == nfs_session_id =>
            {
                Ok(())
            }
            _ => Err(GatewayError::Request),
        }
    }

    pub(crate) fn fsal_projection(
        &mut self,
        binding: [u8; 32],
        client_id: &str,
        nfs_session_id: &str,
    ) -> Option<filebelt_vfs_protocol::NfsSessionProjection> {
        self.remove_expired_sessions();
        self.sessions.get(&binding).and_then(|session| {
            (session.nfs_client_id.as_deref() == Some(client_id)
                && session.nfs_session_id.as_deref() == Some(nfs_session_id))
            .then(|| session.projection.clone())
        })
    }

    fn remove_expired_sessions(&mut self) {
        let now = unix_seconds();
        self.sessions
            .retain(|_, session| session.expires_at_unix_seconds > now);
    }

    fn disk_state_matches(&self, fence: RenewalFence, require_live_lease: bool) -> bool {
        read_state(&self.config.state_file).is_ok_and(|state| {
            state.boot_id == self.boot_id.to_string()
                && state.tenant_id == fence.tenant_id.to_string()
                && state.gateway_epoch == fence.gateway_epoch
                && state.feature_generation == fence.feature_generation
                && state.export_generation == fence.export_generation
                && !state.draining
                && (!require_live_lease || state.lease_expires_at_unix_seconds > unix_seconds())
        })
    }

    fn write_state(&self, admitted: &AdmittedState, draining: bool) -> Result<(), GatewayError> {
        let state = GatewayStateFile {
            format: STATE_FORMAT,
            boot_id: self.boot_id.to_string(),
            tenant_id: admitted.tenant_id.to_string(),
            gateway_epoch: admitted.gateway_epoch,
            feature_generation: admitted.feature_generation,
            export_generation: admitted.export_generation,
            lease_expires_at_unix_seconds: unix_seconds() + i64::from(NFS_GATEWAY_LEASE_SECONDS),
            draining,
        };
        write_state(&self.config.state_file, &state)
    }
}

fn renewal_preserves_sessions(expected: Option<RenewalFence>, candidate: RenewalFence) -> bool {
    expected == Some(candidate)
}

impl<E, I> Gateway<E, I>
where
    E: VfsExecutor + Clone,
    I: ExportInstaller + Clone,
{
    #[must_use]
    pub fn maintenance_worker(&self) -> GatewayMaintenance<E, I> {
        GatewayMaintenance {
            config: self.config.clone(),
            executor: self.executor.clone(),
            installer: self.installer.clone(),
            boot_id: self.boot_id,
        }
    }
}

impl<E: VfsExecutor, I: ExportInstaller> GatewayMaintenance<E, I> {
    pub fn offer(&self) -> Result<RenewalOffer, GatewayError> {
        fetch_offer(&self.config, &self.executor, self.boot_id)
    }

    pub fn apply(&self, offer: &RenewalOffer) -> Result<RenewalCandidate, GatewayError> {
        apply_offer(&self.executor, &self.installer, self.boot_id, offer)
    }
}

fn fetch_offer<E: VfsExecutor>(
    config: &BridgeConfig,
    executor: &E,
    boot_id: Uuid,
) -> Result<RenewalOffer, GatewayError> {
    let hello = hello_request(config, boot_id);
    let response = executor
        .execute_lifecycle(&hello)
        .map_err(|_| GatewayError::Vfs)?;
    if response.error != VfsError::Ok as i32 || response.gateway_epoch == 0 {
        return Err(GatewayError::Bootstrap);
    }
    let manifest = response
        .nfs_gateway_hello
        .as_ref()
        .ok_or(GatewayError::Bootstrap)?;
    let tenant_id = Uuid::parse_str(&manifest.tenant_id).map_err(|_| GatewayError::Bootstrap)?;
    Ok(RenewalOffer {
        fence: RenewalFence {
            tenant_id,
            gateway_epoch: response.gateway_epoch,
            feature_generation: manifest.feature_generation,
            export_generation: manifest.export_generation,
        },
        exports: manifest.active_exports.clone(),
    })
}

fn apply_offer<E: VfsExecutor, I: ExportInstaller>(
    executor: &E,
    installer: &I,
    boot_id: Uuid,
    offer: &RenewalOffer,
) -> Result<RenewalCandidate, GatewayError> {
    let (digest, applied_exports) = installer
        .apply_and_read_back(
            boot_id,
            offer.fence.feature_generation,
            offer.fence.export_generation,
            offer.fence.tenant_id,
            &offer.exports,
        )
        .map_err(|_: ControlError| GatewayError::Export)?;
    let reconcile = VfsRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        tenant_id: offer.fence.tenant_id.to_string(),
        protocol: MountProtocol::Nfs as i32,
        gateway_id: boot_id.to_string(),
        gateway_epoch: offer.fence.gateway_epoch,
        session_id: String::new(),
        credential_generation: 0,
        authorization_generation: 0,
        nfs_context: None,
        operation: Some(Operation::GatewayReconcile(GatewayReconcileRequest {
            boot_id: boot_id.to_string(),
            feature_generation: offer.fence.feature_generation,
            export_generation: offer.fence.export_generation,
            manifest_digest: digest.to_vec(),
            applied_exports,
        })),
    };
    reconcile.validate().map_err(|_| GatewayError::Bootstrap)?;
    let acknowledged = executor
        .execute_lifecycle(&reconcile)
        .map_err(|_| GatewayError::Vfs)?;
    if acknowledged.error != VfsError::Ok as i32 {
        return Err(GatewayError::Bootstrap);
    }
    Ok(RenewalCandidate { fence: offer.fence })
}

fn hello_request(config: &BridgeConfig, boot_id: Uuid) -> VfsRequest {
    let features = [
        NfsGatewayFeature::RpcsecGssPrivacy,
        NfsGatewayFeature::PersistentHandles,
        NfsGatewayFeature::Nfs4Acl,
        NfsGatewayFeature::SparseFiles,
        NfsGatewayFeature::Xattr,
        NfsGatewayFeature::Symlink,
    ]
    .into_iter()
    .map(|feature| feature as i32)
    .collect();
    VfsRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        tenant_id: String::new(),
        protocol: MountProtocol::Nfs as i32,
        gateway_id: boot_id.to_string(),
        gateway_epoch: 0,
        session_id: String::new(),
        credential_generation: 0,
        authorization_generation: 0,
        nfs_context: None,
        operation: Some(Operation::GatewayHello(GatewayHelloRequest {
            shard_key: String::new(),
            tenant_slug: config.tenant_slug.clone(),
            boot_id: boot_id.to_string(),
            nfs_compatibility: Some(NfsGatewayCompatibility {
                minimum_protocol_version: PROTOCOL_VERSION,
                maximum_protocol_version: PROTOCOL_VERSION,
                features,
                release_revision: config.release_revision.clone(),
                config_format: NFS_CONFIG_FORMAT,
                authority_schema_revision: NFS_AUTHORITY_SCHEMA_REVISION,
            }),
        })),
    }
}

pub fn drain<E: VfsExecutor, I: ExportInstaller>(
    config: &BridgeConfig,
    executor: &E,
    installer: &I,
) -> Result<(), GatewayError> {
    let mut state = read_state(&config.state_file)?;
    if state.draining {
        return Ok(());
    }
    state.draining = true;
    write_state(&config.state_file, &state)?;
    let boot_id = Uuid::parse_str(&state.boot_id).map_err(|_| GatewayError::State)?;
    let local_result = installer.drain(boot_id);
    let request = VfsRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        tenant_id: state.tenant_id.clone(),
        protocol: MountProtocol::Nfs as i32,
        gateway_id: state.boot_id.clone(),
        gateway_epoch: state.gateway_epoch,
        session_id: String::new(),
        credential_generation: 0,
        authorization_generation: 0,
        nfs_context: None,
        operation: Some(Operation::GatewayDrain(GatewayDrainRequest {
            boot_id: state.boot_id,
        })),
    };
    request.validate().map_err(|_| GatewayError::State)?;
    let response = executor.execute(&request).map_err(|_| GatewayError::Vfs)?;
    if response.error != VfsError::Ok as i32 {
        return Err(GatewayError::Vfs);
    }
    local_result.map_err(|_| GatewayError::Export)?;
    Ok(())
}

pub fn healthy(config: &BridgeConfig) -> bool {
    let Ok(state) = read_state(&config.state_file) else {
        return false;
    };
    state.format == STATE_FORMAT
        && !state.draining
        && state.lease_expires_at_unix_seconds > unix_seconds()
        && Uuid::parse_str(&state.boot_id).is_ok()
        && Uuid::parse_str(&state.tenant_id).is_ok()
        && state.gateway_epoch > 0
        && state.feature_generation > 0
        && state.export_generation > 0
        && socket_has_expected_metadata(&config.ipc_socket, BRIDGE_UID, IPC_GID)
}

pub(super) fn operation_is_mutation(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Open(_)
            | Operation::Write(_)
            | Operation::Flush(_)
            | Operation::Commit(_)
            | Operation::Close(_)
            | Operation::Create(_)
            | Operation::Mkdir(_)
            | Operation::Rename(_)
            | Operation::Remove(_)
            | Operation::SetAttributes(_)
            | Operation::Lock(_)
            | Operation::Unlock(_)
            | Operation::LeaseAcknowledge(_)
            | Operation::EndSession(_)
            | Operation::SetXattr(_)
            | Operation::RemoveXattr(_)
            | Operation::Symlink(_)
            | Operation::SparseWrite(_)
            | Operation::Reclaim(_)
            | Operation::OpenUnlinked(_)
            | Operation::SetAcl(_)
    ) || matches!(
        operation,
        Operation::SparseControl(request)
            if matches!(
                filebelt_vfs_protocol::SparseControlKind::try_from(request.kind),
                Ok(filebelt_vfs_protocol::SparseControlKind::Allocate
                    | filebelt_vfs_protocol::SparseControlKind::Deallocate)
            )
    )
}

fn valid_principal_for_realm(principal: &str, expected_realm: &str) -> bool {
    if principal.is_empty() || principal.len() > 512 {
        return false;
    }
    let mut components = principal.split('@');
    let user = components.next().unwrap_or_default();
    let realm = components.next().unwrap_or_default();
    !user.is_empty()
        && !user.eq_ignore_ascii_case("root")
        && realm == expected_realm
        && components.next().is_none()
        && user
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\' | b'@'))
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

fn read_state(path: &Path) -> Result<GatewayStateFile, GatewayError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| GatewayError::State)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(GatewayError::State);
    }
    let file = File::open(path).map_err(|_| GatewayError::State)?;
    let mut encoded = Vec::new();
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| GatewayError::State)?;
    if encoded.len() > MAX_STATE_BYTES as usize {
        return Err(GatewayError::State);
    }
    let state: GatewayStateFile = toml::from_slice(&encoded).map_err(|_| GatewayError::State)?;
    if state.format != STATE_FORMAT {
        return Err(GatewayError::State);
    }
    Ok(state)
}

fn expire_state(path: &Path, boot_id: Uuid) -> Result<(), GatewayError> {
    let mut state = read_state(path)?;
    if state.boot_id != boot_id.to_string() || state.draining {
        return Err(GatewayError::State);
    }
    state.lease_expires_at_unix_seconds = 0;
    write_state(path, &state)
}

fn write_state(path: &Path, state: &GatewayStateFile) -> Result<(), GatewayError> {
    let temporary = path.with_extension("state.new");
    let parent = path.parent().ok_or(GatewayError::State)?;
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(&temporary).map_err(|_| GatewayError::State)?;
            sync_directory(parent)?;
        }
        Ok(_) => return Err(GatewayError::State),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(GatewayError::State),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| GatewayError::State)?;
    let encoded = toml::to_string(state).map_err(|_| GatewayError::State)?;
    file.write_all(encoded.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| GatewayError::State)?;
    fs::rename(&temporary, path).map_err(|_| GatewayError::State)?;
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), GatewayError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| GatewayError::State)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CONFIG_FORMAT, ClientTlsConfig};
    use crate::wire::{FsalAuthentication, FsalCall};
    use filebelt_vfs_protocol::{CloseRequest, NfsSessionProjection, RpcsecGssProtection};
    use prost::Message;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingExecutor(Arc<Mutex<Vec<VfsRequest>>>);

    impl VfsExecutor for RecordingExecutor {
        fn execute(&self, request: &VfsRequest) -> Result<VfsResponse, VfsClientError> {
            self.0.lock().unwrap().push(request.clone());
            let request_id = Uuid::parse_str(&request.request_id).unwrap();
            if matches!(request.operation, Some(Operation::NfsAuthenticate(_))) {
                Ok(VfsResponse {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: request.request_id.clone(),
                    error: VfsError::Ok as i32,
                    session_id: Uuid::from_u128(90).to_string(),
                    credential_generation: 3,
                    authorization_generation: 4,
                    nfs_session_projection: Some(NfsSessionProjection {
                        posix_name: "alice".into(),
                        primary_group_name: "users".into(),
                        projected_uid: 1001,
                        projected_gid: 1002,
                        mapping_generation: 2,
                        feature_generation: 5,
                        absolute_expires_at_unix_seconds: unix_seconds() + 300,
                        allowed_export_ids: vec![7],
                    }),
                    ..VfsResponse::default()
                })
            } else {
                Ok(VfsResponse {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: request_id.to_string(),
                    error: VfsError::Ok as i32,
                    ..VfsResponse::default()
                })
            }
        }
    }

    #[derive(Clone)]
    struct UnusedInstaller;

    impl ExportInstaller for UnusedInstaller {
        fn apply_and_read_back(
            &self,
            _boot_id: Uuid,
            _feature_generation: u64,
            _export_generation: u64,
            _tenant_id: Uuid,
            _exports: &[filebelt_vfs_protocol::NfsExportManifestEntry],
        ) -> Result<([u8; 32], Vec<filebelt_vfs_protocol::NfsAppliedExport>), ControlError>
        {
            Err(ControlError::Rejected)
        }

        fn drain(&self, _boot_id: Uuid) -> Result<(), ControlError> {
            Err(ControlError::Rejected)
        }
    }

    fn config() -> BridgeConfig {
        let state_directory =
            std::env::temp_dir().join(format!("filebelt-nfs-gateway-{}", Uuid::new_v4()));
        fs::create_dir(&state_directory).expect("create state test directory");
        fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))
            .expect("protect state test directory");
        BridgeConfig {
            format: CONFIG_FORMAT,
            tenant_slug: "tenant-one".into(),
            kerberos_realm: "EXAMPLE.COM".into(),
            release_revision: "952fb93373a6".into(),
            vfs_url: "https://filebelt-vfs/internal/v1/vfs/execute".into(),
            ipc_socket: "/run/filebelt-nfs/bridge.sock".into(),
            ganesha_control_socket: "/run/filebelt-nfs/ganesha-control.sock".into(),
            state_file: state_directory.join("gateway.state"),
            tls: ClientTlsConfig {
                certificate_chain_file: "/run/secrets/nfs-bridge-vfs-client-tls/tls.crt".into(),
                private_key_file: "/run/secrets/nfs-bridge-vfs-client-tls/tls.key".into(),
                server_ca_file: "/run/secrets/nfs-bridge-vfs-client-tls/server-ca.crt".into(),
            },
        }
    }

    fn admitted_gateway(
        executor: RecordingExecutor,
    ) -> Gateway<RecordingExecutor, UnusedInstaller> {
        let mut gateway = Gateway::new(config(), executor, UnusedInstaller);
        gateway.admitted = Some(AdmittedState {
            tenant_id: Uuid::from_u128(10),
            gateway_epoch: 9,
            feature_generation: 5,
            export_generation: 6,
            refresh_at: Instant::now() + Duration::from_secs(300),
            lease_expires_at: Instant::now() + Duration::from_secs(300),
        });
        gateway
            .write_state(gateway.admitted.as_ref().unwrap(), false)
            .expect("write admitted state");
        gateway
    }

    fn cleanup_gateway<E, I>(gateway: &Gateway<E, I>) {
        let state = gateway.config.state_file.clone();
        let temporary = state.with_extension("state.new");
        let parent = state.parent().unwrap().to_owned();
        let _ = fs::remove_file(temporary);
        let _ = fs::remove_file(state);
        let _ = fs::remove_dir(parent);
    }

    fn authenticate(binding: u8) -> VfsRequest {
        VfsRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: String::new(),
            tenant_id: String::new(),
            protocol: MountProtocol::Nfs as i32,
            gateway_id: String::new(),
            gateway_epoch: 0,
            session_id: String::new(),
            credential_generation: 0,
            authorization_generation: 0,
            nfs_context: None,
            operation: Some(Operation::NfsAuthenticate(NfsAuthenticateRequest {
                kerberos_principal: "alice@EXAMPLE.COM".into(),
                gss_binding_digest: vec![binding; 32],
                source_address: "192.0.2.10".into(),
                protection: RpcsecGssProtection::Privacy as i32,
                context_expires_at_unix_seconds: unix_seconds() + 300,
            })),
        }
    }

    fn close(binding: u8) -> VfsRequest {
        VfsRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: String::new(),
            tenant_id: String::new(),
            protocol: MountProtocol::Nfs as i32,
            gateway_id: String::new(),
            gateway_epoch: 0,
            session_id: String::new(),
            credential_generation: 0,
            authorization_generation: 0,
            nfs_context: Some(filebelt_vfs_protocol::NfsRequestContext {
                gss_binding_digest: vec![binding; 32],
                client_id: "0000000000000007".into(),
                nfs_session_id: "01010101010101010101010101010101".into(),
                slot_id: 2,
                sequence_id: 3,
                operation_index: 4,
                request_digest: vec![99; 32],
            }),
            operation: Some(Operation::Close(CloseRequest {
                handle_id: Uuid::from_u128(20).to_string(),
            })),
        }
    }

    #[test]
    fn exact_realm_and_single_component_are_required() {
        assert!(valid_principal_for_realm(
            "alice@EXAMPLE.COM",
            "EXAMPLE.COM"
        ));
        for invalid in [
            "alice@example.com",
            "alice/admin@EXAMPLE.COM",
            "alice\\@EXAMPLE.COM",
            "alice smith@EXAMPLE.COM",
            "root@EXAMPLE.COM",
            "alice@OTHER.COM",
            "alice@@EXAMPLE.COM",
        ] {
            assert!(
                !valid_principal_for_realm(invalid, "EXAMPLE.COM"),
                "{invalid}"
            );
        }
    }

    #[test]
    fn mutation_digest_binds_operation_and_replay_coordinates() {
        let mut first = VfsRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::from_u128(1).to_string(),
            tenant_id: Uuid::from_u128(2).to_string(),
            protocol: MountProtocol::Nfs as i32,
            gateway_id: Uuid::from_u128(3).to_string(),
            gateway_epoch: 1,
            session_id: Uuid::from_u128(4).to_string(),
            credential_generation: 1,
            authorization_generation: 1,
            nfs_context: Some(filebelt_vfs_protocol::NfsRequestContext {
                gss_binding_digest: vec![7; 32],
                client_id: "client-1".into(),
                nfs_session_id: "session-1".into(),
                slot_id: 1,
                sequence_id: 1,
                operation_index: 1,
                request_digest: vec![],
            }),
            operation: Some(Operation::Close(filebelt_vfs_protocol::CloseRequest {
                handle_id: Uuid::from_u128(5).to_string(),
            })),
        };
        let baseline = canonical_nfs_request_digest(&first);
        first.request_id = Uuid::from_u128(99).to_string();
        assert_eq!(baseline, canonical_nfs_request_digest(&first));
        first.nfs_context.as_mut().unwrap().sequence_id += 1;
        assert_ne!(baseline, canonical_nfs_request_digest(&first));
        first.nfs_context.as_mut().unwrap().sequence_id -= 1;
        first.nfs_context.as_mut().unwrap().request_digest = vec![9; 32];
        assert_eq!(baseline, canonical_nfs_request_digest(&first));

        let fixed = VfsRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::from_u128(22).to_string(),
            tenant_id: Uuid::from_u128(23).to_string(),
            protocol: MountProtocol::Nfs as i32,
            gateway_id: "nfs-gateway-0".into(),
            gateway_epoch: 7,
            session_id: Uuid::from_u128(24).to_string(),
            credential_generation: 3,
            authorization_generation: 5,
            nfs_context: Some(filebelt_vfs_protocol::NfsRequestContext {
                gss_binding_digest: vec![7; 32],
                client_id: "nfs-client-1".into(),
                nfs_session_id: "nfs-session-1".into(),
                slot_id: 1_023,
                sequence_id: 9,
                operation_index: 63,
                request_digest: vec![9; 32],
            }),
            operation: Some(Operation::Close(CloseRequest {
                handle_id: Uuid::from_u128(21).to_string(),
            })),
        };
        assert_eq!(
            canonical_nfs_request_digest(&fixed),
            [
                0x00, 0x21, 0x3d, 0x0b, 0x6c, 0xc1, 0x74, 0x8c, 0x7e, 0xb5, 0xc9, 0x84, 0x7c, 0x69,
                0xcb, 0x03, 0xb3, 0xa3, 0x5f, 0xd0, 0x4e, 0x2d, 0x91, 0x1b, 0x4b, 0x73, 0x7b, 0x78,
                0x25, 0x02, 0x5c, 0x70,
            ]
        );
    }

    #[test]
    fn bridge_owns_envelope_session_and_mutation_digest() {
        let executor = RecordingExecutor::default();
        let records = Arc::clone(&executor.0);
        let mut gateway = admitted_gateway(executor);
        assert_eq!(gateway.handle(authenticate(7)).error, VfsError::Ok as i32);
        gateway
            .bind_fsal_session(
                [7; 32],
                "0000000000000007",
                "01010101010101010101010101010101",
            )
            .expect("bind authenticated NFS session");
        assert_eq!(gateway.handle(close(7)).error, VfsError::Ok as i32);

        let records = records.lock().unwrap();
        assert_eq!(records.len(), 2);
        let authenticate = &records[0];
        assert_eq!(authenticate.tenant_id, Uuid::from_u128(10).to_string());
        assert_eq!(authenticate.gateway_id, gateway.boot_id.to_string());
        assert_eq!(authenticate.gateway_epoch, 9);
        let close = &records[1];
        assert_eq!(close.session_id, Uuid::from_u128(90).to_string());
        assert_eq!(close.credential_generation, 3);
        assert_eq!(close.authorization_generation, 4);
        assert_eq!(close.nfs_context.as_ref().unwrap().request_digest.len(), 32);
        assert_ne!(
            close.nfs_context.as_ref().unwrap().request_digest,
            vec![99; 32]
        );
        close
            .validate()
            .expect("bridge-created request must validate");
        drop(records);
        cleanup_gateway(&gateway);
    }

    #[test]
    fn wrong_realm_expired_context_and_unknown_binding_fail_before_vfs() {
        let executor = RecordingExecutor::default();
        let records = Arc::clone(&executor.0);
        let mut gateway = admitted_gateway(executor);
        let mut wrong_realm = authenticate(8);
        let Some(Operation::NfsAuthenticate(auth)) = wrong_realm.operation.as_mut() else {
            panic!("auth operation");
        };
        auth.kerberos_principal = "alice@OTHER.COM".into();
        assert_eq!(
            gateway.handle(wrong_realm).error,
            VfsError::Unauthenticated as i32
        );
        assert_eq!(
            gateway.handle(close(8)).error,
            VfsError::Unauthenticated as i32
        );
        let mut expired = authenticate(9);
        let Some(Operation::NfsAuthenticate(auth)) = expired.operation.as_mut() else {
            panic!("auth operation");
        };
        auth.context_expires_at_unix_seconds = unix_seconds();
        assert_eq!(
            gateway.handle(expired).error,
            VfsError::Unauthenticated as i32
        );
        assert!(records.lock().unwrap().is_empty());
        cleanup_gateway(&gateway);
    }

    #[test]
    fn projection_cache_is_bound_to_exact_nfs_session_and_expiry() {
        let executor = RecordingExecutor::default();
        let records = Arc::clone(&executor.0);
        let mut gateway = admitted_gateway(executor);
        assert_eq!(gateway.handle(authenticate(7)).error, VfsError::Ok as i32);
        gateway
            .bind_fsal_session(
                [7; 32],
                "0000000000000007",
                "01010101010101010101010101010101",
            )
            .expect("bind exact session");
        let projection = gateway
            .fsal_projection(
                [7; 32],
                "0000000000000007",
                "01010101010101010101010101010101",
            )
            .expect("bound projection");
        assert_eq!(projection.mapping_generation, 2);
        assert_eq!(projection.feature_generation, 5);
        assert_eq!(projection.allowed_export_ids, [7]);
        assert!(
            gateway
                .fsal_projection(
                    [7; 32],
                    "0000000000000008",
                    "01010101010101010101010101010101",
                )
                .is_none()
        );
        assert!(
            gateway
                .fsal_projection(
                    [7; 32],
                    "0000000000000007",
                    "02020202020202020202020202020202",
                )
                .is_none()
        );

        gateway
            .sessions
            .get_mut(&[7; 32])
            .expect("cached session")
            .expires_at_unix_seconds = unix_seconds();
        assert!(
            gateway
                .fsal_projection(
                    [7; 32],
                    "0000000000000007",
                    "01010101010101010101010101010101",
                )
                .is_none()
        );
        assert!(gateway.sessions.is_empty());
        assert_eq!(records.lock().unwrap().len(), 1);
        cleanup_gateway(&gateway);
    }

    #[test]
    fn trusted_bridge_adds_mutation_digest_for_canonical_fsal_call() {
        let executor = RecordingExecutor::default();
        let records = Arc::clone(&executor.0);
        let mut gateway = admitted_gateway(executor);
        let call = FsalCall {
            format: 1,
            authentication: Some(FsalAuthentication {
                kerberos_principal: "alice@EXAMPLE.COM".into(),
                gss_binding_digest: vec![7; 32],
                source_address: "192.0.2.10".into(),
                context_expires_at_unix_seconds: unix_seconds() + 300,
                client_id: "0000000000000007".into(),
                nfs_session_id: "01010101010101010101010101010101".into(),
                slot_id: 2,
                sequence_id: 3,
                operation_index: 4,
            }),
            operation_tag: 28,
            operation: CloseRequest {
                handle_id: Uuid::from_u128(20).to_string(),
            }
            .encode_to_vec(),
        };
        let response = crate::wire::execute(&mut gateway, &call.encode_to_vec());
        let vfs_response = VfsResponse::decode(response.vfs_response.as_slice()).unwrap();
        assert_eq!(vfs_response.error, VfsError::Ok as i32);
        let projection = response.projection.expect("bound POSIX projection");
        assert_eq!(projection.posix_name, "alice");
        assert_eq!(projection.projected_uid, 1001);
        let recorded = records.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(matches!(
            recorded[0].operation,
            Some(Operation::NfsAuthenticate(_))
        ));
        let context = recorded[1].nfs_context.as_ref().expect("NFS context");
        assert_eq!(context.request_digest.len(), 32);
        recorded[1]
            .validate()
            .expect("trusted bridge mutation must validate");
        drop(recorded);

        let reclaim = FsalCall {
            operation_tag: 49,
            operation: filebelt_vfs_protocol::ReclaimRequest {
                client_id: String::new(),
                state_id: Uuid::from_u128(21).to_string(),
                gateway_epoch: 0,
            }
            .encode_to_vec(),
            ..call
        };
        let reclaimed = crate::wire::execute(&mut gateway, &reclaim.encode_to_vec());
        assert!(reclaimed.projection.is_some());
        let records = records.lock().unwrap();
        let Some(Operation::Reclaim(reclaim)) = records.last().unwrap().operation.as_ref() else {
            panic!("trusted reclaim");
        };
        assert_eq!(reclaim.client_id, "0000000000000007");
        assert_eq!(reclaim.gateway_epoch, 9);
        drop(records);
        cleanup_gateway(&gateway);
    }

    #[test]
    fn renewal_retries_until_deadline_and_preserves_only_exact_fence() {
        let executor = RecordingExecutor::default();
        let mut gateway = admitted_gateway(executor);
        assert_eq!(gateway.handle(authenticate(7)).error, VfsError::Ok as i32);
        let fence = gateway.admitted.as_ref().unwrap().fence();
        gateway.fail_renewal(fence);
        assert!(gateway.admitted.is_some());
        assert_eq!(gateway.sessions.len(), 1);

        assert!(renewal_preserves_sessions(Some(fence), fence));
        let changed = RenewalFence {
            export_generation: fence.export_generation + 1,
            ..fence
        };
        assert!(!renewal_preserves_sessions(Some(fence), changed));
        assert!(!renewal_preserves_sessions(None, fence));

        gateway.admitted.as_mut().unwrap().lease_expires_at = Instant::now();
        gateway.fail_renewal(fence);
        assert!(gateway.admitted.is_none());
        assert!(gateway.sessions.is_empty());
        cleanup_gateway(&gateway);
    }

    #[test]
    fn changed_manifest_reconcile_failure_stays_unready() {
        let executor = RecordingExecutor::default();
        let mut gateway = admitted_gateway(executor);
        assert_eq!(gateway.handle(authenticate(7)).error, VfsError::Ok as i32);
        let fence = gateway.admitted.as_ref().unwrap().fence();
        let changed = RenewalFence {
            export_generation: fence.export_generation + 1,
            ..fence
        };
        assert!(
            gateway
                .prepare_renewal(fence, changed)
                .expect("invalidate changed fence")
        );
        assert!(gateway.admitted.is_none());
        assert!(gateway.sessions.is_empty());

        // Represents local apply/readback followed by reconcile transport
        // failure: fail_renewal must not restore the old live authority.
        gateway.fail_renewal(fence);
        assert!(gateway.admitted.is_none());
        assert_eq!(gateway.handle(close(7)).error, VfsError::Unavailable as i32);
        cleanup_gateway(&gateway);
    }

    #[test]
    fn missing_or_corrupt_state_revokes_memory_admission() {
        let mut removed = admitted_gateway(RecordingExecutor::default());
        assert_eq!(removed.handle(authenticate(7)).error, VfsError::Ok as i32);
        fs::remove_file(&removed.config.state_file).expect("remove state");
        assert_eq!(removed.handle(close(7)).error, VfsError::Unavailable as i32);
        assert!(removed.admitted.is_none());
        assert!(removed.sessions.is_empty());
        cleanup_gateway(&removed);

        let mut corrupt = admitted_gateway(RecordingExecutor::default());
        assert_eq!(corrupt.handle(authenticate(7)).error, VfsError::Ok as i32);
        fs::write(&corrupt.config.state_file, b"not valid toml\n").expect("corrupt state");
        fs::set_permissions(
            &corrupt.config.state_file,
            fs::Permissions::from_mode(0o600),
        )
        .expect("retain protected mode");
        assert_eq!(corrupt.handle(close(7)).error, VfsError::Unavailable as i32);
        assert!(corrupt.admitted.is_none());
        assert!(corrupt.sessions.is_empty());
        cleanup_gateway(&corrupt);
    }
}

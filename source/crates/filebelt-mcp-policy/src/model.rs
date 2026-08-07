// SPDX-License-Identifier: Apache-2.0

//! Registration and capability state independent of transports and storage.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationState {
    NeverTested,
    Valid,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationState {
    NoneRequired,
    Required,
    Authorized,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Undiscovered,
    PendingReview,
    Approved,
    Drifted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineState {
    Clear,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistrationPolicyState {
    pub validation: ValidationState,
    pub authentication: AuthenticationState,
    pub capabilities: CapabilityState,
    pub quarantine: QuarantineState,
    pub enabled: bool,
    pub revoked: bool,
}

impl Default for RegistrationPolicyState {
    fn default() -> Self {
        Self {
            validation: ValidationState::NeverTested,
            authentication: AuthenticationState::Required,
            capabilities: CapabilityState::Undiscovered,
            quarantine: QuarantineState::Clear,
            enabled: false,
            revoked: false,
        }
    }
}

impl RegistrationPolicyState {
    pub fn can_enable(self) -> Result<(), RegistrationStateError> {
        if self.revoked {
            return Err(RegistrationStateError::Revoked);
        }
        if self.quarantine == QuarantineState::Quarantined {
            return Err(RegistrationStateError::Quarantined);
        }
        if self.validation != ValidationState::Valid {
            return Err(RegistrationStateError::NotValidated);
        }
        if !matches!(
            self.authentication,
            AuthenticationState::NoneRequired | AuthenticationState::Authorized
        ) {
            return Err(RegistrationStateError::NotAuthorized);
        }
        if self.capabilities != CapabilityState::Approved {
            return Err(RegistrationStateError::CapabilitiesNotApproved);
        }
        Ok(())
    }

    pub fn enable(&mut self) -> Result<(), RegistrationStateError> {
        self.can_enable()?;
        self.enabled = true;
        Ok(())
    }

    pub fn mark_capability_drift(&mut self) {
        self.capabilities = CapabilityState::Drifted;
        self.enabled = false;
    }

    pub fn quarantine(&mut self) {
        self.quarantine = QuarantineState::Quarantined;
        self.enabled = false;
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        self.enabled = false;
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RegistrationStateError {
    #[error("mcp.policy.registration_revoked")]
    Revoked,
    #[error("mcp.policy.registration_quarantined")]
    Quarantined,
    #[error("mcp.policy.registration_not_validated")]
    NotValidated,
    #[error("mcp.policy.registration_not_authorized")]
    NotAuthorized,
    #[error("mcp.policy.capabilities_not_approved")]
    CapabilitiesNotApproved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityPrimitive {
    ResourceRead,
    PromptGet,
    ToolCall,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDescriptor {
    pub primitive: CapabilityPrimitive,
    pub name: String,
    pub fingerprint: [u8; 32],
    pub read_only_hint: Option<bool>,
}

impl CapabilityDescriptor {
    pub fn reviewable(&self) -> bool {
        !self.name.is_empty()
            && self.name.len() <= 255
            && (self.primitive != CapabilityPrimitive::ToolCall
                || self.read_only_hint == Some(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> RegistrationPolicyState {
        RegistrationPolicyState {
            validation: ValidationState::Valid,
            authentication: AuthenticationState::Authorized,
            capabilities: CapabilityState::Approved,
            ..RegistrationPolicyState::default()
        }
    }

    #[test]
    fn enabling_requires_all_independent_gates() {
        let mut state = RegistrationPolicyState::default();
        assert_eq!(state.enable(), Err(RegistrationStateError::NotValidated));
        state.validation = ValidationState::Valid;
        assert_eq!(state.enable(), Err(RegistrationStateError::NotAuthorized));
        state.authentication = AuthenticationState::Authorized;
        assert_eq!(
            state.enable(),
            Err(RegistrationStateError::CapabilitiesNotApproved)
        );
        state.capabilities = CapabilityState::Approved;
        assert_eq!(state.enable(), Ok(()));
        assert!(state.enabled);
    }

    #[test]
    fn drift_quarantine_and_revocation_fail_closed() {
        let mut state = ready();
        state.enable().expect("ready state");
        state.mark_capability_drift();
        assert!(!state.enabled);
        let mut state = ready();
        state.quarantine();
        assert_eq!(state.enable(), Err(RegistrationStateError::Quarantined));
        let mut state = ready();
        state.revoke();
        assert_eq!(state.enable(), Err(RegistrationStateError::Revoked));
    }

    #[test]
    fn tools_require_an_explicit_read_only_hint() {
        let descriptor = CapabilityDescriptor {
            primitive: CapabilityPrimitive::ToolCall,
            name: "lookup".into(),
            fingerprint: [7; 32],
            read_only_hint: None,
        };
        assert!(!descriptor.reviewable());
        assert!(
            CapabilityDescriptor {
                read_only_hint: Some(true),
                ..descriptor
            }
            .reviewable()
        );
    }
}

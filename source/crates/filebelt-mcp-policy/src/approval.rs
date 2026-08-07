// SPDX-License-Identifier: Apache-2.0

//! Exact approval binding for outbound MCP invocations.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::CapabilityPrimitive;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentBinding {
    pub version_id: Uuid,
    pub content: bool,
    pub basename: bool,
    pub media_type: bool,
    pub size: bool,
    pub target_pointer: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationBinding {
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub registration_id: Uuid,
    pub application_id: String,
    pub session_id: Option<Uuid>,
    pub primitive: CapabilityPrimitive,
    pub capability_name: String,
    pub capability_fingerprint: [u8; 32],
    pub argument_digest: [u8; 32],
    pub attachments: Vec<AttachmentBinding>,
    pub now_epoch_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub registration_id: Uuid,
    pub application_id: String,
    pub session_id: Option<Uuid>,
    pub primitive: CapabilityPrimitive,
    pub capability_name: String,
    pub capability_fingerprint: [u8; 32],
    pub argument_digest: [u8; 32],
    pub attachments: Vec<AttachmentBinding>,
    pub expires_at_epoch_seconds: i64,
    pub single_use: bool,
    pub consumed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Allow,
    Deny(ApprovalError),
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ApprovalError {
    #[error("mcp.policy.approval_expired")]
    Expired,
    #[error("mcp.policy.approval_consumed")]
    Consumed,
    #[error("mcp.policy.approval_binding_mismatch")]
    BindingMismatch,
}

impl ApprovalBinding {
    pub fn evaluate(&self, invocation: &InvocationBinding) -> ApprovalDecision {
        if self.expires_at_epoch_seconds <= invocation.now_epoch_seconds {
            return ApprovalDecision::Deny(ApprovalError::Expired);
        }
        if self.single_use && self.consumed {
            return ApprovalDecision::Deny(ApprovalError::Consumed);
        }
        let matches = self.tenant_id == invocation.tenant_id
            && self.principal_id == invocation.principal_id
            && self.registration_id == invocation.registration_id
            && self.application_id == invocation.application_id
            && self.session_id == invocation.session_id
            && self.primitive == invocation.primitive
            && self.capability_name == invocation.capability_name
            && self.capability_fingerprint == invocation.capability_fingerprint
            && self.argument_digest == invocation.argument_digest
            && self.attachments == invocation.attachments;
        if matches {
            ApprovalDecision::Allow
        } else {
            ApprovalDecision::Deny(ApprovalError::BindingMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> (ApprovalBinding, InvocationBinding) {
        let registration_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let principal_id = Uuid::new_v4();
        let session_id = Some(Uuid::new_v4());
        let attachment = AttachmentBinding {
            version_id: Uuid::new_v4(),
            content: true,
            basename: false,
            media_type: true,
            size: false,
            target_pointer: "/input".into(),
        };
        (
            ApprovalBinding {
                tenant_id,
                principal_id,
                registration_id,
                application_id: "web".into(),
                session_id,
                primitive: CapabilityPrimitive::ResourceRead,
                capability_name: "read".into(),
                capability_fingerprint: [1; 32],
                argument_digest: [2; 32],
                attachments: vec![attachment.clone()],
                expires_at_epoch_seconds: 200,
                single_use: true,
                consumed: false,
            },
            InvocationBinding {
                tenant_id,
                principal_id,
                registration_id,
                application_id: "web".into(),
                session_id,
                primitive: CapabilityPrimitive::ResourceRead,
                capability_name: "read".into(),
                capability_fingerprint: [1; 32],
                argument_digest: [2; 32],
                attachments: vec![attachment],
                now_epoch_seconds: 100,
            },
        )
    }

    #[test]
    fn exact_binding_allows() {
        let (approval, invocation) = binding();
        assert_eq!(approval.evaluate(&invocation), ApprovalDecision::Allow);
    }

    #[test]
    fn every_mutable_input_is_bound() {
        let (approval, mut invocation) = binding();
        invocation.attachments[0].target_pointer = "/other".into();
        assert_eq!(
            approval.evaluate(&invocation),
            ApprovalDecision::Deny(ApprovalError::BindingMismatch)
        );
        let (approval, mut invocation) = binding();
        invocation.principal_id = Uuid::new_v4();
        assert_eq!(
            approval.evaluate(&invocation),
            ApprovalDecision::Deny(ApprovalError::BindingMismatch)
        );
    }

    #[test]
    fn expired_and_consumed_approvals_deny() {
        let (mut approval, mut invocation) = binding();
        invocation.now_epoch_seconds = 200;
        assert_eq!(
            approval.evaluate(&invocation),
            ApprovalDecision::Deny(ApprovalError::Expired)
        );
        invocation.now_epoch_seconds = 100;
        approval.consumed = true;
        assert_eq!(
            approval.evaluate(&invocation),
            ApprovalDecision::Deny(ApprovalError::Consumed)
        );
    }
}

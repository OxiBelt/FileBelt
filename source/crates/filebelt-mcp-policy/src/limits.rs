// SPDX-License-Identifier: Apache-2.0

//! Compiled safety ceilings for administrator and user-configurable policy.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLimits {
    pub attachment_count: u32,
    pub attachment_item_bytes: u64,
    pub attachment_raw_bytes: u64,
    pub attachment_wire_bytes: u64,
    pub message_bytes: u64,
    pub result_bytes: u64,
    pub registrations_per_principal: u32,
    pub invocation_concurrency_per_principal: u32,
    pub invocation_concurrency_per_registration: u32,
    pub saved_approval_seconds: u32,
    pub data_grant_seconds: u32,
}

impl PolicyLimits {
    pub const fn within(self, ceiling: Self) -> bool {
        self.attachment_count <= ceiling.attachment_count
            && self.attachment_item_bytes <= ceiling.attachment_item_bytes
            && self.attachment_raw_bytes <= ceiling.attachment_raw_bytes
            && self.attachment_wire_bytes <= ceiling.attachment_wire_bytes
            && self.message_bytes <= ceiling.message_bytes
            && self.result_bytes <= ceiling.result_bytes
            && self.registrations_per_principal <= ceiling.registrations_per_principal
            && self.invocation_concurrency_per_principal
                <= ceiling.invocation_concurrency_per_principal
            && self.invocation_concurrency_per_registration
                <= ceiling.invocation_concurrency_per_registration
            && self.saved_approval_seconds <= ceiling.saved_approval_seconds
            && self.data_grant_seconds <= ceiling.data_grant_seconds
    }
}

pub const COMPILED_LIMITS: PolicyLimits = PolicyLimits {
    attachment_count: 4,
    attachment_item_bytes: 16 * 1_048_576,
    attachment_raw_bytes: 16 * 1_048_576,
    attachment_wire_bytes: 24 * 1_048_576,
    message_bytes: 1_048_576,
    result_bytes: 4 * 1_048_576,
    registrations_per_principal: 20,
    invocation_concurrency_per_principal: 4,
    invocation_concurrency_per_registration: 2,
    saved_approval_seconds: 3_600,
    data_grant_seconds: 30 * 24 * 60 * 60,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_cannot_exceed_compiled_ceiling() {
        assert!(COMPILED_LIMITS.within(COMPILED_LIMITS));
        let excessive = PolicyLimits {
            result_bytes: COMPILED_LIMITS.result_bytes + 1,
            ..COMPILED_LIMITS
        };
        assert!(!excessive.within(COMPILED_LIMITS));
    }
}

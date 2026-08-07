// SPDX-License-Identifier: Apache-2.0

//! Pure policy models for outbound Model Context Protocol access.

#![deny(unsafe_code)]

mod approval;
mod limits;
mod model;

pub use approval::{
    ApprovalBinding, ApprovalDecision, ApprovalError, AttachmentBinding, InvocationBinding,
};
pub use limits::{COMPILED_LIMITS, PolicyLimits};
pub use model::{
    AuthenticationState, CapabilityDescriptor, CapabilityPrimitive, CapabilityState,
    QuarantineState, RegistrationPolicyState, RegistrationStateError, ValidationState,
};

#[derive(Debug, thiserror::Error)]
pub enum PolicyJsonError {
    #[error("JSON contains an integer outside the interoperable I-JSON range")]
    UnsafeInteger,
    #[error("JSON canonicalization failed")]
    Serialization(#[from] serde_json::Error),
}

/// Encodes an I-JSON value using RFC 8785 canonicalization.
pub fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, PolicyJsonError> {
    validate_interoperable_numbers(value)?;
    Ok(serde_json_canonicalizer::to_vec(value)?)
}

/// Computes a domain-separated RFC 8785 digest over a bounded JSON value.
///
/// Callers must parse JSON with duplicate-key rejection before constructing the
/// value and enforce the applicable size/depth ceiling before calling this
/// function.
pub fn policy_json_digest(
    domain: &'static [u8],
    value: &serde_json::Value,
) -> Result<[u8; 32], PolicyJsonError> {
    let encoded = canonical_json(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"filebelt-mcp-policy-v1\0");
    hasher.update(domain);
    hasher.update(b"\0");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

fn validate_interoperable_numbers(value: &serde_json::Value) -> Result<(), PolicyJsonError> {
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    match value {
        serde_json::Value::Number(number) => {
            if number
                .as_i64()
                .is_some_and(|value| !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value))
                || number
                    .as_u64()
                    .is_some_and(|value| value > MAX_SAFE_INTEGER as u64)
            {
                return Err(PolicyJsonError::UnsafeInteger);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                validate_interoperable_numbers(value)?;
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                validate_interoperable_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn policy_digest_is_key_order_independent_and_domain_separated() {
        let first: serde_json::Value =
            serde_json::from_str(r#"{"b":2,"a":1}"#).expect("valid json");
        let second = json!({"a": 1, "b": 2});
        assert_eq!(
            policy_json_digest(b"arguments", &first).expect("digest"),
            policy_json_digest(b"arguments", &second).expect("digest")
        );
        assert_ne!(
            policy_json_digest(b"arguments", &first).expect("digest"),
            policy_json_digest(b"capability", &first).expect("digest")
        );
    }

    #[test]
    fn canonical_json_rejects_integers_that_collapse_in_binary64() {
        let first = json!(9_007_199_254_740_992_u64);
        let second = json!(9_007_199_254_740_993_u64);
        assert_eq!(
            serde_json_canonicalizer::to_vec(&first).expect("legacy canonical form"),
            serde_json_canonicalizer::to_vec(&second).expect("legacy canonical form")
        );
        assert!(matches!(
            canonical_json(&first),
            Err(PolicyJsonError::UnsafeInteger)
        ));
        assert!(canonical_json(&json!(9_007_199_254_740_991_u64)).is_ok());
        assert!(canonical_json(&json!(-9_007_199_254_740_991_i64)).is_ok());
    }
}

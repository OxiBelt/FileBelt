// SPDX-License-Identifier: Apache-2.0

//! MCP-specific facade over the shared domain-separated secret vault.

#![deny(unsafe_code)]

use std::path::Path;

use filebelt_secret_vault as vault;
use uuid::Uuid;
use zeroize::Zeroizing;

pub use vault::{SecretEnvelope, VaultError};

#[derive(Debug)]
pub struct Keyring(vault::Keyring);

#[derive(Clone, Debug)]
pub struct SecretContext<'a> {
    pub tenant_id: Uuid,
    pub registration_id: Uuid,
    pub owner_principal_id: Uuid,
    pub issuer: &'a str,
    pub secret_kind: &'a str,
    pub credential_generation: i64,
}

impl Keyring {
    pub fn load(path: &Path) -> Result<Self, VaultError> {
        vault::Keyring::load(path, vault::VaultProfile::mcp()).map(Self)
    }

    pub fn encrypt(
        &self,
        generation: u32,
        context: &SecretContext<'_>,
        plaintext: &[u8],
    ) -> Result<SecretEnvelope, VaultError> {
        self.0
            .encrypt(generation, &generic_context(context), plaintext)
    }

    pub fn decrypt(
        &self,
        context: &SecretContext<'_>,
        envelope: &SecretEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.0.decrypt(&generic_context(context), envelope)
    }
}

fn generic_context<'a>(context: &'a SecretContext<'a>) -> vault::SecretContext<'a> {
    vault::SecretContext {
        tenant_id: context.tenant_id,
        secret_id: context.registration_id,
        owner_principal_id: context.owner_principal_id,
        namespace: context.issuer,
        secret_kind: context.secret_kind,
        credential_generation: context.credential_generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_preserves_the_existing_context_shape() {
        let context = SecretContext {
            tenant_id: Uuid::nil(),
            registration_id: Uuid::max(),
            owner_principal_id: Uuid::from_u128(1),
            issuer: "https://mcp.example.test/",
            secret_kind: "bearer",
            credential_generation: 3,
        };
        let generic = generic_context(&context);
        assert_eq!(generic.secret_id, context.registration_id);
        assert_eq!(generic.namespace, context.issuer);
    }
}

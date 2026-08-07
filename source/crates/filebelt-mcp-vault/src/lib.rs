// SPDX-License-Identifier: Apache-2.0

//! Envelope encryption for per-principal MCP credentials.

#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const FORMAT: &str = "filebelt.mcp-keyring.v1";
const AAD_DOMAIN: &[u8] = b"filebelt.mcp.secret-envelope.v1\0";
const WRAP_DOMAIN: &[u8] = b"filebelt.mcp.dek-wrap.v1\0";
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("MCP keyring cannot be read")]
    Read,
    #[error("MCP keyring is invalid")]
    InvalidKeyring,
    #[error("MCP key generation is unavailable")]
    UnknownGeneration,
    #[error("MCP secret context is invalid")]
    InvalidContext,
    #[error("MCP secret envelope is invalid")]
    InvalidEnvelope,
    #[error("MCP cryptographic operation failed")]
    Crypto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringDocument {
    format: String,
    keys: Vec<KeyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDocument {
    generation: u32,
    key_base64: String,
}

#[derive(Debug)]
pub struct Keyring {
    keys: BTreeMap<u32, Zeroizing<Vec<u8>>>,
}

#[derive(Clone, Debug)]
pub struct SecretContext<'a> {
    pub tenant_id: Uuid,
    pub registration_id: Uuid,
    pub owner_principal_id: Uuid,
    pub issuer: &'a str,
    pub secret_kind: &'a str,
    pub credential_generation: i64,
}

#[derive(Clone, Debug)]
pub struct SecretEnvelope {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_BYTES],
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: [u8; NONCE_BYTES],
    pub kek_generation: u32,
    pub aad_version: u32,
}

impl Keyring {
    pub fn load(path: &Path) -> Result<Self, VaultError> {
        let bytes = std::fs::read(path).map_err(|_| VaultError::Read)?;
        let document: KeyringDocument =
            serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidKeyring)?;
        if document.format != FORMAT || document.keys.is_empty() || document.keys.len() > 32 {
            return Err(VaultError::InvalidKeyring);
        }
        let mut keys = BTreeMap::new();
        for item in document.keys {
            if item.generation == 0 || keys.contains_key(&item.generation) {
                return Err(VaultError::InvalidKeyring);
            }
            let decoded = STANDARD
                .decode(item.key_base64)
                .map_err(|_| VaultError::InvalidKeyring)?;
            if decoded.len() != KEY_BYTES {
                return Err(VaultError::InvalidKeyring);
            }
            keys.insert(item.generation, Zeroizing::new(decoded));
        }
        Ok(Self { keys })
    }

    pub fn encrypt(
        &self,
        generation: u32,
        context: &SecretContext<'_>,
        plaintext: &[u8],
    ) -> Result<SecretEnvelope, VaultError> {
        validate_context(context, plaintext.len())?;
        let kek = self
            .keys
            .get(&generation)
            .ok_or(VaultError::UnknownGeneration)?;
        let mut dek = Zeroizing::new([0_u8; KEY_BYTES]);
        let mut nonce = [0_u8; NONCE_BYTES];
        let mut wrap_nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(dek.as_mut()).map_err(|_| VaultError::Crypto)?;
        getrandom::fill(&mut nonce).map_err(|_| VaultError::Crypto)?;
        getrandom::fill(&mut wrap_nonce).map_err(|_| VaultError::Crypto)?;

        let aad = aad(context)?;
        let mut ciphertext = plaintext.to_vec();
        key(dek.as_ref())?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| VaultError::Crypto)?;
        let mut wrapped_dek = dek.as_ref().to_vec();
        key(kek.as_ref())?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(wrap_nonce),
                Aad::from(wrap_aad(&aad, generation).as_slice()),
                &mut wrapped_dek,
            )
            .map_err(|_| VaultError::Crypto)?;
        Ok(SecretEnvelope {
            ciphertext,
            nonce,
            wrapped_dek,
            wrap_nonce,
            kek_generation: generation,
            aad_version: 1,
        })
    }

    pub fn decrypt(
        &self,
        context: &SecretContext<'_>,
        envelope: &SecretEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        validate_context(context, envelope.ciphertext.len().saturating_sub(TAG_BYTES))?;
        if envelope.aad_version != 1
            || envelope.ciphertext.len() <= TAG_BYTES
            || envelope.wrapped_dek.len() != KEY_BYTES + TAG_BYTES
        {
            return Err(VaultError::InvalidEnvelope);
        }
        let kek = self
            .keys
            .get(&envelope.kek_generation)
            .ok_or(VaultError::UnknownGeneration)?;
        let aad = aad(context)?;
        let mut dek = Zeroizing::new(envelope.wrapped_dek.clone());
        let opened_dek = key(kek.as_ref())?
            .open_in_place(
                Nonce::assume_unique_for_key(envelope.wrap_nonce),
                Aad::from(wrap_aad(&aad, envelope.kek_generation).as_slice()),
                dek.as_mut(),
            )
            .map_err(|_| VaultError::InvalidEnvelope)?;
        if opened_dek.len() != KEY_BYTES {
            return Err(VaultError::InvalidEnvelope);
        }
        let content_key = key(opened_dek)?;
        let mut plaintext = Zeroizing::new(envelope.ciphertext.clone());
        let length = content_key
            .open_in_place(
                Nonce::assume_unique_for_key(envelope.nonce),
                Aad::from(aad.as_slice()),
                plaintext.as_mut(),
            )
            .map_err(|_| VaultError::InvalidEnvelope)?
            .len();
        plaintext.truncate(length);
        Ok(plaintext)
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

fn validate_context(context: &SecretContext<'_>, plaintext_len: usize) -> Result<(), VaultError> {
    if context.issuer.is_empty()
        || context.issuer.len() > 2_048
        || context.secret_kind.is_empty()
        || context.secret_kind.len() > 64
        || context.credential_generation <= 0
        || plaintext_len == 0
        || plaintext_len > 8_192
    {
        return Err(VaultError::InvalidContext);
    }
    Ok(())
}

fn aad(context: &SecretContext<'_>) -> Result<Vec<u8>, VaultError> {
    validate_context(context, 1)?;
    let mut value = Vec::with_capacity(256);
    value.extend_from_slice(AAD_DOMAIN);
    let credential_generation = context.credential_generation.to_string();
    for part in [
        context.tenant_id.as_bytes().as_slice(),
        context.registration_id.as_bytes().as_slice(),
        context.owner_principal_id.as_bytes().as_slice(),
        context.issuer.as_bytes(),
        context.secret_kind.as_bytes(),
        credential_generation.as_bytes(),
    ] {
        value.extend_from_slice(&(part.len() as u32).to_be_bytes());
        value.extend_from_slice(part);
    }
    Ok(value)
}

fn wrap_aad(aad: &[u8], generation: u32) -> Vec<u8> {
    [WRAP_DOMAIN, &generation.to_be_bytes(), aad].concat()
}

fn key(bytes: &[u8]) -> Result<LessSafeKey, VaultError> {
    UnboundKey::new(&AES_256_GCM, bytes)
        .map(LessSafeKey::new)
        .map_err(|_| VaultError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyring() -> Keyring {
        Keyring {
            keys: BTreeMap::from([(7, Zeroizing::new(vec![9; 32]))]),
        }
    }

    fn context<'a>() -> SecretContext<'a> {
        SecretContext {
            tenant_id: Uuid::new_v4(),
            registration_id: Uuid::new_v4(),
            owner_principal_id: Uuid::new_v4(),
            issuer: "https://mcp.example.test/",
            secret_kind: "bearer",
            credential_generation: 3,
        }
    }

    #[test]
    fn envelope_is_context_bound() {
        let keyring = keyring();
        let context = context();
        let envelope = keyring.encrypt(7, &context, b"private-token").unwrap();
        assert_eq!(
            keyring.decrypt(&context, &envelope).unwrap().as_slice(),
            b"private-token"
        );
        let mut changed = context.clone();
        changed.registration_id = Uuid::new_v4();
        assert!(keyring.decrypt(&changed, &envelope).is_err());
    }

    #[test]
    fn keyring_format_is_strict() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.json");
        std::fs::write(
            &path,
            r#"{"format":"filebelt.mcp-keyring.v1","keys":[{"generation":4,"key_base64":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}]}"#,
        )
        .unwrap();
        assert!(Keyring::load(&path).is_ok());
    }
}

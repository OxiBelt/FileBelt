// SPDX-License-Identifier: Apache-2.0

//! Opaque NFS file-handle encoding. The adapter never receives a Core path or
//! payload locator: the handle binds only authoritative tenant, export, node,
//! and independent staleness generations that VFS revalidates in PostgreSQL.

#![allow(dead_code)]

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

const FORMAT: u8 = 2;
const KEYSET_FORMAT: &str = "filebelt-nfs-handle-keyset-v1";
const TAG_BYTES: usize = 32;
const BODY_BYTES: usize = 1 + 4 + 16 + 8 + 16 + 8 + 8 + 8;
pub const HANDLE_BYTES: usize = BODY_BYTES + TAG_BYTES;

/// Accepts only the canonical single-component user principal selected by the
/// deployment. Service/instance principals, enterprise aliases, escapes,
/// cross-realm names, and the root account never reach mapping lookup.
pub fn validate_authenticated_principal<'a>(
    principal: &'a str,
    expected_realm: &str,
) -> Result<&'a str, NfsPrincipalError> {
    if principal.is_empty() || principal.len() > 512 {
        return Err(NfsPrincipalError::Invalid);
    }
    let mut components = principal.split('@');
    let user = components.next().unwrap_or_default();
    let realm = components.next().unwrap_or_default();
    if user.is_empty()
        || user.eq_ignore_ascii_case("root")
        || realm != expected_realm
        || components.next().is_some()
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\' | b'@'))
    {
        return Err(NfsPrincipalError::Invalid);
    }
    Ok(user)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NfsPrincipalError {
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NfsHandleScope {
    pub tenant_id: Uuid,
    pub export_id: u64,
    pub node_id: Uuid,
    pub export_generation: u64,
    pub node_generation: u64,
    pub restore_generation: u64,
}

struct NfsHandleKeyMaterial {
    generation: u32,
    material: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Copy)]
pub struct NfsHandleKey<'a> {
    generation: u32,
    material: &'a [u8; 32],
}

pub struct NfsHandleKeyring {
    current: NfsHandleKeyMaterial,
    previous: Option<NfsHandleKeyMaterial>,
}

impl NfsHandleKeyring {
    pub fn load(path: &Path, expected_current_generation: u32) -> Result<Self> {
        let source = Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("cannot read NFS handle keyset {}", path.display()))?,
        );
        parse_keyring(&source, expected_current_generation)
    }

    pub fn current(&self) -> NfsHandleKey<'_> {
        NfsHandleKey {
            generation: self.current.generation,
            material: &self.current.material,
        }
    }

    pub fn previous(&self) -> Option<NfsHandleKey<'_>> {
        self.previous.as_ref().map(|key| NfsHandleKey {
            generation: key.generation,
            material: &key.material,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NfsHandleError {
    Malformed,
    Stale,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysetDocument {
    format: String,
    current: KeyDocument,
    previous: Option<KeyDocument>,
}

impl Drop for KeysetDocument {
    fn drop(&mut self) {
        self.current.key.zeroize();
        if let Some(previous) = self.previous.as_mut() {
            previous.key.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDocument {
    generation: u32,
    key: String,
}

fn parse_keyring(source: &str, expected_current_generation: u32) -> Result<NfsHandleKeyring> {
    let mut document: KeysetDocument =
        serde_json::from_str(source).context("NFS handle keyset is not strict JSON")?;
    if document.format != KEYSET_FORMAT
        || expected_current_generation == 0
        || document.current.generation != expected_current_generation
    {
        bail!("NFS handle keyset format or current generation is invalid");
    }
    let current = NfsHandleKeyMaterial {
        generation: document.current.generation,
        material: decode_key(&mut document.current.key)?,
    };
    let previous = if let Some(previous) = document.previous.as_mut() {
        if previous.generation == 0 || previous.generation >= current.generation {
            previous.key.zeroize();
            bail!("NFS previous handle key generation is invalid");
        }
        let material = decode_key(&mut previous.key)?;
        if verify_slices_are_equal(current.material.as_ref(), material.as_ref()).is_ok() {
            bail!("NFS current and previous handle keys must differ");
        }
        Some(NfsHandleKeyMaterial {
            generation: previous.generation,
            material,
        })
    } else {
        None
    };
    Ok(NfsHandleKeyring { current, previous })
}

fn decode_key(value: &mut String) -> Result<Zeroizing<[u8; 32]>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .context("NFS handle key is not unpadded base64url")
        .and_then(|decoded| {
            <[u8; 32]>::try_from(decoded.as_slice())
                .context("NFS handle key must contain exactly 32 bytes")
        });
    value.zeroize();
    decoded.map(Zeroizing::new)
}

pub fn issue_handle(scope: NfsHandleScope, key: NfsHandleKey<'_>) -> [u8; HANDLE_BYTES] {
    let mut handle = [0_u8; HANDLE_BYTES];
    handle[0] = FORMAT;
    handle[1..5].copy_from_slice(&key.generation.to_be_bytes());
    handle[5..21].copy_from_slice(&scope.tenant_id.into_bytes());
    handle[21..29].copy_from_slice(&scope.export_id.to_be_bytes());
    handle[29..45].copy_from_slice(&scope.node_id.into_bytes());
    handle[45..53].copy_from_slice(&scope.export_generation.to_be_bytes());
    handle[53..61].copy_from_slice(&scope.node_generation.to_be_bytes());
    handle[61..69].copy_from_slice(&scope.restore_generation.to_be_bytes());
    let authentication_tag = tag(key.material, &handle[..BODY_BYTES]);
    handle[BODY_BYTES..].copy_from_slice(&authentication_tag);
    handle
}

/// Validates only current or immediately previous key material. The caller
/// then compares every decoded generation with authoritative PostgreSQL state.
pub fn validate_handle(
    handle: &[u8],
    keyring: &NfsHandleKeyring,
) -> Result<NfsHandleScope, NfsHandleError> {
    if handle.len() != HANDLE_BYTES || handle[0] != FORMAT {
        return Err(NfsHandleError::Malformed);
    }
    let key_generation = u32::from_be_bytes(
        handle[1..5]
            .try_into()
            .map_err(|_| NfsHandleError::Malformed)?,
    );
    let key = if key_generation == keyring.current.generation {
        keyring.current()
    } else if keyring
        .previous
        .as_ref()
        .is_some_and(|candidate| candidate.generation == key_generation)
    {
        keyring.previous().ok_or(NfsHandleError::Stale)?
    } else {
        return Err(NfsHandleError::Stale);
    };
    let authentication_tag = tag(key.material, &handle[..BODY_BYTES]);
    if verify_slices_are_equal(&authentication_tag, &handle[BODY_BYTES..]).is_err() {
        return Err(NfsHandleError::Malformed);
    }

    let tenant_id = Uuid::from_slice(&handle[5..21]).map_err(|_| NfsHandleError::Malformed)?;
    let export_id = u64::from_be_bytes(
        handle[21..29]
            .try_into()
            .map_err(|_| NfsHandleError::Malformed)?,
    );
    let node_id = Uuid::from_slice(&handle[29..45]).map_err(|_| NfsHandleError::Malformed)?;
    let export_generation = u64::from_be_bytes(
        handle[45..53]
            .try_into()
            .map_err(|_| NfsHandleError::Malformed)?,
    );
    let node_generation = u64::from_be_bytes(
        handle[53..61]
            .try_into()
            .map_err(|_| NfsHandleError::Malformed)?,
    );
    let restore_generation = u64::from_be_bytes(
        handle[61..69]
            .try_into()
            .map_err(|_| NfsHandleError::Malformed)?,
    );
    if tenant_id.is_nil()
        || node_id.is_nil()
        || export_id == 0
        || export_generation == 0
        || node_generation == 0
        || restore_generation == 0
    {
        return Err(NfsHandleError::Stale);
    }
    Ok(NfsHandleScope {
        tenant_id,
        export_id,
        node_id,
        export_generation,
        node_generation,
        restore_generation,
    })
}

fn tag(key: &[u8; 32], body: &[u8]) -> [u8; TAG_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"filebelt.nfs.filehandle.v2\0");
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::{
        HANDLE_BYTES, NfsHandleError, NfsHandleScope, NfsPrincipalError, issue_handle,
        parse_keyring, validate_authenticated_principal, validate_handle,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use uuid::Uuid;

    fn keyring(current_generation: u32, current: u8, previous: Option<(u32, u8)>) -> String {
        let previous = previous.map_or_else(
            || "null".to_owned(),
            |(generation, byte)| {
                format!(
                    r#"{{"generation":{generation},"key":"{}"}}"#,
                    URL_SAFE_NO_PAD.encode([byte; 32])
                )
            },
        );
        format!(
            r#"{{"format":"filebelt-nfs-handle-keyset-v1","current":{{"generation":{current_generation},"key":"{}"}},"previous":{previous}}}"#,
            URL_SAFE_NO_PAD.encode([current; 32])
        )
    }

    fn scope() -> NfsHandleScope {
        NfsHandleScope {
            tenant_id: Uuid::new_v4(),
            export_id: 17,
            node_id: Uuid::new_v4(),
            export_generation: 3,
            node_generation: 5,
            restore_generation: 7,
        }
    }

    #[test]
    fn opaque_handle_round_trips_for_current_or_previous_key_only() {
        assert!(HANDLE_BYTES <= 128);
        let old = parse_keyring(&keyring(2, 2, None), 2).unwrap();
        let expected = scope();
        let handle = issue_handle(expected, old.current());
        let rotated = parse_keyring(&keyring(3, 3, Some((2, 2))), 3).unwrap();
        assert_eq!(validate_handle(&handle, &rotated), Ok(expected));
        let without_previous = parse_keyring(&keyring(3, 3, None), 3).unwrap();
        assert_eq!(
            validate_handle(&handle, &without_previous),
            Err(NfsHandleError::Stale)
        );
    }

    #[test]
    fn opaque_handle_binds_every_authoritative_scope_field() {
        let keyring = parse_keyring(&keyring(1, 7, None), 1).unwrap();
        let expected = scope();
        let handle = issue_handle(expected, keyring.current());
        assert_eq!(validate_handle(&handle, &keyring), Ok(expected));

        for index in [5, 21, 29, 45, 53, 61] {
            let mut tampered = handle;
            tampered[index] ^= 1;
            assert_eq!(
                validate_handle(&tampered, &keyring),
                Err(NfsHandleError::Malformed)
            );
        }
    }

    #[test]
    fn keyset_parser_rejects_generation_and_material_reuse() {
        assert!(parse_keyring(&keyring(2, 2, None), 3).is_err());
        assert!(parse_keyring(&keyring(2, 2, Some((2, 1))), 2).is_err());
        assert!(parse_keyring(&keyring(2, 2, Some((1, 2))), 2).is_err());
        assert!(parse_keyring(&keyring(0, 2, None), 0).is_err());
    }

    #[test]
    fn keyset_parser_is_strict_and_bounded() {
        let unknown = keyring(1, 1, None).replace(
            r#""format":"filebelt-nfs-handle-keyset-v1""#,
            r#""format":"filebelt-nfs-handle-keyset-v1","extra":true"#,
        );
        assert!(parse_keyring(&unknown, 1).is_err());
        let short = keyring(1, 1, None).replace(
            &URL_SAFE_NO_PAD.encode([1; 32]),
            &URL_SAFE_NO_PAD.encode([1; 31]),
        );
        assert!(parse_keyring(&short, 1).is_err());
    }

    #[test]
    fn authenticated_principal_is_exactly_one_non_root_user_in_the_configured_realm() {
        assert_eq!(
            validate_authenticated_principal("alice@EXAMPLE.TEST", "EXAMPLE.TEST"),
            Ok("alice")
        );
        for invalid in [
            "root@EXAMPLE.TEST",
            "nfs/server@EXAMPLE.TEST",
            "alice/admin@EXAMPLE.TEST",
            "alice\\@example.test@EXAMPLE.TEST",
            "alice@OTHER.TEST",
            "alice@@EXAMPLE.TEST",
            "alice smith@EXAMPLE.TEST",
        ] {
            assert_eq!(
                validate_authenticated_principal(invalid, "EXAMPLE.TEST"),
                Err(NfsPrincipalError::Invalid)
            );
        }
    }
}

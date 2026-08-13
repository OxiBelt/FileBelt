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
use filebelt_vfs_protocol::NfsExportManifestEntry;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

const FORMAT: u8 = 2;
const KEYSET_FORMAT: &str = "filebelt-nfs-handle-keyset-v1";
const TAG_BYTES: usize = 32;
const BODY_BYTES: usize = 1 + 4 + 16 + 8 + 16 + 8 + 8 + 8;
pub const HANDLE_BYTES: usize = BODY_BYTES + TAG_BYTES;
const _: () = assert!(HANDLE_BYTES <= filebelt_vfs_protocol::MAX_PERSISTENT_HANDLE_BYTES);

/// Computes the stable digest acknowledged for one root handle after the
/// gateway has installed and read back its export.
#[must_use]
pub fn root_handle_digest(handle: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"filebelt.nfs.root-handle.v1\0");
    hash_length_prefixed(&mut hasher, handle);
    *hasher.finalize().as_bytes()
}

/// Computes the canonical desired-manifest digest. Entries must already be in
/// strictly increasing export-ID order; the protocol validator and PostgreSQL
/// authority enforce that ordering independently.
#[must_use]
pub fn manifest_digest(
    tenant_id: Uuid,
    feature_generation: u64,
    export_generation: u64,
    exports: &[NfsExportManifestEntry],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"filebelt.nfs.export-manifest.v1\0");
    hasher.update(tenant_id.as_bytes());
    hasher.update(&feature_generation.to_be_bytes());
    hasher.update(&export_generation.to_be_bytes());
    hasher.update(
        &u32::try_from(exports.len())
            .expect("validated NFS manifest entry count is bounded")
            .to_be_bytes(),
    );
    for export in exports {
        hasher.update(&export.export_id.to_be_bytes());
        hash_length_prefixed(&mut hasher, export.drive_id.as_bytes());
        hasher.update(&export.generation.to_be_bytes());
        hasher.update(&[u8::from(export.read_only)]);
        hash_length_prefixed(&mut hasher, export.export_path.as_bytes());
        hash_length_prefixed(&mut hasher, &export.root_handle);
    }
    *hasher.finalize().as_bytes()
}

fn hash_length_prefixed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(
        &u32::try_from(value.len())
            .expect("validated NFS manifest field is bounded")
            .to_be_bytes(),
    );
    hasher.update(value);
}

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

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_exercise(input: &[u8]) {
    use filebelt_vfs_protocol::{VfsRequest, canonical_nfs_request_digest};
    use prost::Message as _;

    let mut padded = [0_u8; 112];
    let copied = input.len().min(padded.len());
    padded[..copied].copy_from_slice(&input[..copied]);

    let mut tenant_bytes = [0_u8; 16];
    tenant_bytes.copy_from_slice(&padded[..16]);
    tenant_bytes[15] |= 1;
    let mut node_bytes = [0_u8; 16];
    node_bytes.copy_from_slice(&padded[16..32]);
    node_bytes[15] |= 1;
    let key_material: [u8; 32] = padded[32..64]
        .try_into()
        .expect("the fuzz key slice has a fixed length");
    let nonzero = |offset: usize| {
        u64::from_be_bytes(
            padded[offset..offset + 8]
                .try_into()
                .expect("the fuzz integer slice has a fixed length"),
        ) | 1
    };
    let scope = NfsHandleScope {
        tenant_id: Uuid::from_bytes(tenant_bytes),
        export_id: nonzero(64),
        node_id: Uuid::from_bytes(node_bytes),
        export_generation: nonzero(72),
        node_generation: nonzero(80),
        restore_generation: nonzero(88),
    };
    let keyring = NfsHandleKeyring {
        current: NfsHandleKeyMaterial {
            generation: 1,
            material: Zeroizing::new(key_material),
        },
        previous: None,
    };
    let issued = issue_handle(scope, keyring.current());
    assert_eq!(validate_handle(&issued, &keyring), Ok(scope));
    let mut tampered = issued;
    tampered[HANDLE_BYTES - 1] ^= 1;
    assert_eq!(
        validate_handle(&tampered, &keyring),
        Err(NfsHandleError::Malformed)
    );

    let realm = std::str::from_utf8(&padded[96..104]).unwrap_or_default();
    let principal = std::str::from_utf8(input).unwrap_or_default();
    let _ = validate_authenticated_principal(principal, realm);
    let _ = root_handle_digest(input);

    if let Ok(request) = VfsRequest::decode(input) {
        let first = canonical_nfs_request_digest(&request);
        assert_eq!(first, canonical_nfs_request_digest(&request));
        let _ = request.validate();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HANDLE_BYTES, NfsHandleError, NfsHandleScope, NfsPrincipalError, issue_handle,
        manifest_digest, parse_keyring, root_handle_digest, validate_authenticated_principal,
        validate_handle,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use filebelt_vfs_protocol::NfsExportManifestEntry;
    use uuid::Uuid;

    fn manifest_entry(export_id: u64, generation: u64, handle: u8) -> NfsExportManifestEntry {
        let drive_id = Uuid::from_u128(u128::from(export_id) + 100);
        NfsExportManifestEntry {
            export_id,
            drive_id: drive_id.to_string(),
            export_path: format!("/filebelt/{drive_id}"),
            generation,
            root_handle: vec![handle; HANDLE_BYTES],
            read_only: false,
        }
    }

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

    #[test]
    fn reconciliation_digests_bind_order_generations_and_root_handles() {
        let tenant_id = Uuid::from_u128(9);
        let first = manifest_entry(7, 3, 1);
        let second = manifest_entry(11, 4, 2);
        let baseline = manifest_digest(tenant_id, 5, 6, &[first.clone(), second.clone()]);
        assert_eq!(
            baseline,
            [
                0x61, 0x49, 0xf3, 0x5f, 0x85, 0xdd, 0x9b, 0xe4, 0x56, 0x74, 0xc9, 0x27, 0xf0, 0x6e,
                0x5b, 0xba, 0x7e, 0x34, 0xb7, 0x5e, 0x6b, 0x96, 0xa4, 0x13, 0x18, 0xc4, 0xc4, 0x1c,
                0x3a, 0xc2, 0x90, 0x67,
            ],
            "the VFS and adapter must share one canonical manifest encoding"
        );
        assert_eq!(
            root_handle_digest(&first.root_handle),
            [
                0xb9, 0xc5, 0x0a, 0xc8, 0xbc, 0xb3, 0x22, 0x61, 0x7c, 0xfb, 0x23, 0xd5, 0x29, 0xf2,
                0xbb, 0xd8, 0xf1, 0x40, 0x3e, 0xab, 0x60, 0x0f, 0x0b, 0xb0, 0xad, 0x46, 0xeb, 0x61,
                0x04, 0x52, 0x4f, 0x83,
            ],
            "the VFS and adapter must share one canonical root-handle encoding"
        );
        assert_ne!(
            baseline,
            manifest_digest(tenant_id, 5, 7, &[first.clone(), second.clone()])
        );
        assert_ne!(
            baseline,
            manifest_digest(tenant_id, 5, 6, &[second, first.clone()])
        );
        assert_ne!(
            root_handle_digest(&first.root_handle),
            root_handle_digest(&[9])
        );
    }
}

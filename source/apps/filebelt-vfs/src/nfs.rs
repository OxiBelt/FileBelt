// SPDX-License-Identifier: Apache-2.0

//! Opaque NFS file-handle encoding. The adapter never receives a Core path or
//! payload locator: the handle binds only the logical export, node, and
//! generation that VFS revalidates against PostgreSQL before use.

#![allow(dead_code)]

use uuid::Uuid;

const FORMAT: u8 = 1;
const TAG_BYTES: usize = 32;
const BODY_BYTES: usize = 1 + 4 + 16 + 16 + 8;
pub const HANDLE_BYTES: usize = BODY_BYTES + TAG_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NfsHandleScope {
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub generation: u64,
}

#[derive(Clone, Copy)]
pub struct NfsHandleKey {
    pub generation: u32,
    pub material: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NfsHandleError {
    Malformed,
    Stale,
}

pub fn issue_handle(scope: NfsHandleScope, key: NfsHandleKey) -> [u8; HANDLE_BYTES] {
    let mut handle = [0_u8; HANDLE_BYTES];
    handle[0] = FORMAT;
    handle[1..5].copy_from_slice(&key.generation.to_be_bytes());
    handle[5..21].copy_from_slice(&scope.drive_id.into_bytes());
    handle[21..37].copy_from_slice(&scope.node_id.into_bytes());
    handle[37..45].copy_from_slice(&scope.generation.to_be_bytes());
    let authentication_tag = tag(&key.material, &handle[..BODY_BYTES]);
    handle[BODY_BYTES..].copy_from_slice(&authentication_tag);
    handle
}

/// Validates only current or immediately previous key material. The caller
/// then compares the decoded scope with its authoritative export/node state.
pub fn validate_handle(
    handle: &[u8],
    current: NfsHandleKey,
    previous: Option<NfsHandleKey>,
) -> Result<NfsHandleScope, NfsHandleError> {
    if handle.len() != HANDLE_BYTES || handle[0] != FORMAT {
        return Err(NfsHandleError::Malformed);
    }
    let key_generation = u32::from_be_bytes(
        handle[1..5]
            .try_into()
            .map_err(|_| NfsHandleError::Malformed)?,
    );
    let key = if key_generation == current.generation {
        current
    } else if previous.is_some_and(|candidate| candidate.generation == key_generation) {
        previous.expect("checked previous handle key")
    } else {
        return Err(NfsHandleError::Stale);
    };
    if tag(&key.material, &handle[..BODY_BYTES]) != handle[BODY_BYTES..] {
        return Err(NfsHandleError::Malformed);
    }
    let drive_id = Uuid::from_slice(&handle[5..21]).map_err(|_| NfsHandleError::Malformed)?;
    let node_id = Uuid::from_slice(&handle[21..37]).map_err(|_| NfsHandleError::Malformed)?;
    let generation = u64::from_be_bytes(
        handle[37..45]
            .try_into()
            .map_err(|_| NfsHandleError::Malformed)?,
    );
    if generation == 0 {
        return Err(NfsHandleError::Stale);
    }
    Ok(NfsHandleScope {
        drive_id,
        node_id,
        generation,
    })
}

fn tag(key: &[u8; 32], body: &[u8]) -> [u8; TAG_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"filebelt.nfs.filehandle.v1\0");
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::{NfsHandleError, NfsHandleKey, NfsHandleScope, issue_handle, validate_handle};
    use uuid::Uuid;

    fn key(generation: u32, byte: u8) -> NfsHandleKey {
        NfsHandleKey {
            generation,
            material: [byte; 32],
        }
    }

    #[test]
    fn opaque_handle_round_trips_for_current_or_previous_key_only() {
        let scope = NfsHandleScope {
            drive_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
            generation: 7,
        };
        let handle = issue_handle(scope, key(2, 2));
        assert_eq!(
            validate_handle(&handle, key(3, 3), Some(key(2, 2))),
            Ok(scope)
        );
        assert_eq!(
            validate_handle(&handle, key(3, 3), None),
            Err(NfsHandleError::Stale)
        );
    }

    #[test]
    fn opaque_handle_rejects_tampering() {
        let scope = NfsHandleScope {
            drive_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
            generation: 1,
        };
        let mut handle = issue_handle(scope, key(1, 7));
        handle[21] ^= 1;
        assert_eq!(
            validate_handle(&handle, key(1, 7), None),
            Err(NfsHandleError::Malformed)
        );
    }
}

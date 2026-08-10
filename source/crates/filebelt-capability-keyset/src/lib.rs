// SPDX-License-Identifier: Apache-2.0

//! Strict, purpose-bound Ed25519 capability verification keysets.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;

const FORMAT: &str = "filebelt-capability-keyset-v2";
const MAX_KEYSET_TEXT_BYTES: usize = 1_024;

/// The closed list of capability-key purposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPurpose {
    ApiStorage,
    ApiCollaborationGrant,
    ApiMcpDelegation,
    CollaborationStorage,
    DocumentStorage,
    MountStorage,
    MediaStorage,
}

impl KeyPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiStorage => "api-storage",
            Self::ApiCollaborationGrant => "api-collaboration-grant",
            Self::ApiMcpDelegation => "api-mcp-delegation",
            Self::CollaborationStorage => "collaboration-storage",
            Self::DocumentStorage => "document-storage",
            Self::MountStorage => "mount-storage",
            Self::MediaStorage => "media-storage",
        }
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for KeyPurpose {
    type Err = KeysetError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "api-storage" => Ok(Self::ApiStorage),
            "api-collaboration-grant" => Ok(Self::ApiCollaborationGrant),
            "api-mcp-delegation" => Ok(Self::ApiMcpDelegation),
            "collaboration-storage" => Ok(Self::CollaborationStorage),
            "document-storage" => Ok(Self::DocumentStorage),
            "mount-storage" => Ok(Self::MountStorage),
            "media-storage" => Ok(Self::MediaStorage),
            _ => Err(KeysetError::InvalidEncoding),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum KeysetError {
    #[error("capability keyset encoding is invalid")]
    InvalidEncoding,
    #[error("capability key generation is unknown")]
    UnknownKey,
    #[error("capability signature is invalid")]
    InvalidSignature,
}

#[derive(Clone, Debug)]
struct Keyset {
    keys: BTreeMap<u32, [u8; 32]>,
}

impl Keyset {
    fn parse(source: &str, purpose: &str) -> Result<Self, KeysetError> {
        if source.is_empty() || source.len() > MAX_KEYSET_TEXT_BYTES || !source.is_ascii() {
            return Err(KeysetError::InvalidEncoding);
        }
        let canonical = source
            .strip_suffix('\n')
            .filter(|text| !text.ends_with('\n'))
            .ok_or(KeysetError::InvalidEncoding)?;
        let lines: Vec<_> = canonical.split('\n').collect();
        if !(3..=4).contains(&lines.len())
            || lines[0] != FORMAT
            || lines[1] != format!("purpose={purpose}")
        {
            return Err(KeysetError::InvalidEncoding);
        }

        let mut keys = BTreeMap::new();
        for line in &lines[2..] {
            let (generation_text, encoded) =
                line.split_once(':').ok_or(KeysetError::InvalidEncoding)?;
            if generation_text.is_empty()
                || !generation_text.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(KeysetError::InvalidEncoding);
            }
            let generation = generation_text
                .parse::<u32>()
                .map_err(|_| KeysetError::InvalidEncoding)?;
            if generation == 0 || generation.to_string() != generation_text {
                return Err(KeysetError::InvalidEncoding);
            }
            let decoded = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| KeysetError::InvalidEncoding)?;
            let public_key: [u8; 32] = decoded
                .try_into()
                .map_err(|_| KeysetError::InvalidEncoding)?;
            if keys.contains_key(&generation) || keys.values().any(|key| key == &public_key) {
                return Err(KeysetError::InvalidEncoding);
            }
            keys.insert(generation, public_key);
        }
        Ok(Self { keys })
    }

    fn verify(&self, generation: u32, message: &[u8], signature: &[u8]) -> Result<(), KeysetError> {
        let key = self.keys.get(&generation).ok_or(KeysetError::UnknownKey)?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(message, signature)
            .map_err(|_| KeysetError::InvalidSignature)
    }
}

/// Encodes a canonical version 2 keyset with exactly one trailing newline.
pub fn encode_keyset(
    purpose: KeyPurpose,
    entries: &[(u32, [u8; 32])],
) -> Result<String, KeysetError> {
    if !(1..=2).contains(&entries.len()) {
        return Err(KeysetError::InvalidEncoding);
    }
    let mut keyset = Keyset {
        keys: BTreeMap::new(),
    };
    for (generation, public_key) in entries {
        if *generation == 0
            || keyset.keys.contains_key(generation)
            || keyset.keys.values().any(|key| key == public_key)
        {
            return Err(KeysetError::InvalidEncoding);
        }
        keyset.keys.insert(*generation, *public_key);
    }
    let mut output = format!("{FORMAT}\npurpose={purpose}\n");
    for (generation, public_key) in keyset.keys {
        output.push_str(&generation.to_string());
        output.push(':');
        output.push_str(&URL_SAFE_NO_PAD.encode(public_key));
        output.push('\n');
    }
    Ok(output)
}

/// Returns whether every supplied public key byte string is unique.
///
/// Runtimes that load more than one purpose use this at startup so a copied
/// private key cannot collapse the purpose boundary even when each individual
/// keyset has the correct purpose label.
pub fn public_key_material_is_disjoint(keys: impl IntoIterator<Item = [u8; 32]>) -> bool {
    let mut observed = BTreeSet::new();
    keys.into_iter().all(|key| observed.insert(key))
}

macro_rules! typed_keyset {
    ($name:ident, $purpose:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name(Keyset);

        impl $name {
            /// Parses exactly one purpose-bound, version 2 verification keyset.
            pub fn parse(source: &str) -> Result<Self, KeysetError> {
                Keyset::parse(source, $purpose.as_str()).map(Self)
            }

            #[must_use]
            pub const fn purpose() -> KeyPurpose {
                $purpose
            }

            #[must_use]
            pub fn len(&self) -> usize {
                self.0.keys.len()
            }

            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.0.keys.is_empty()
            }

            #[must_use]
            pub fn contains_generation(&self, generation: u32) -> bool {
                self.0.keys.contains_key(&generation)
            }

            #[must_use]
            pub fn public_key(&self, generation: u32) -> Option<&[u8; 32]> {
                self.0.keys.get(&generation)
            }

            pub fn entries(&self) -> impl ExactSizeIterator<Item = (u32, &[u8; 32])> {
                self.0
                    .keys
                    .iter()
                    .map(|(generation, key)| (*generation, key))
            }

            pub fn verify(
                &self,
                generation: u32,
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), KeysetError> {
                self.0.verify(generation, message, signature)
            }
        }
    };
}

typed_keyset!(ApiStorageKeyset, KeyPurpose::ApiStorage);
typed_keyset!(
    ApiCollaborationGrantKeyset,
    KeyPurpose::ApiCollaborationGrant
);
typed_keyset!(ApiMcpDelegationKeyset, KeyPurpose::ApiMcpDelegation);
typed_keyset!(CollaborationStorageKeyset, KeyPurpose::CollaborationStorage);
typed_keyset!(DocumentStorageKeyset, KeyPurpose::DocumentStorage);
typed_keyset!(MountStorageKeyset, KeyPurpose::MountStorage);
typed_keyset!(MediaStorageKeyset, KeyPurpose::MediaStorage);

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> String {
        URL_SAFE_NO_PAD.encode([byte; 32])
    }

    fn source(purpose: &str, records: &str) -> String {
        format!("{FORMAT}\npurpose={purpose}\n{records}\n")
    }

    #[test]
    fn accepts_one_or_two_canonical_records_for_exact_purpose() {
        let one = source("api-storage", &format!("1:{}", key(1)));
        assert!(ApiStorageKeyset::parse(&one).is_ok());
        let two = source("api-storage", &format!("1:{}\n2:{}", key(1), key(2)));
        assert!(ApiStorageKeyset::parse(&two).is_ok());
        assert!(ApiCollaborationGrantKeyset::parse(&two).is_err());
    }

    #[test]
    fn rejects_legacy_blank_unknown_duplicate_and_malformed_records() {
        let valid = source("api-storage", &format!("1:{}", key(1)));
        for invalid in [
            valid.replace(FORMAT, "filebelt-capability-keyset-v1"),
            valid.replace("purpose=api-storage", "purpose=unknown"),
            valid.trim_end().to_owned(),
            format!("{valid}\n"),
            source("api-storage", ""),
            source("api-storage", &format!("0:{}", key(1))),
            source("api-storage", &format!("01:{}", key(1))),
            source("api-storage", &format!("1:{}\n1:{}", key(1), key(2))),
            source("api-storage", &format!("1:{}\n2:{}", key(1), key(1))),
            source(
                "api-storage",
                &format!("1:{}\n2:{}\n3:{}", key(1), key(2), key(3)),
            ),
            source("api-storage", "1:not-base64"),
            source(
                "api-storage",
                &format!("1:{}", URL_SAFE_NO_PAD.encode([1; 31])),
            ),
        ] {
            assert!(matches!(
                ApiStorageKeyset::parse(&invalid),
                Err(KeysetError::InvalidEncoding)
            ));
        }
    }

    #[test]
    fn rejects_oversized_keyset() {
        let oversized = "x".repeat(MAX_KEYSET_TEXT_BYTES + 1);
        assert!(matches!(
            ApiStorageKeyset::parse(&oversized),
            Err(KeysetError::InvalidEncoding)
        ));
    }

    #[test]
    fn detects_public_key_reuse_across_purpose_sets() {
        assert!(public_key_material_is_disjoint([[1; 32], [2; 32]]));
        assert!(!public_key_material_is_disjoint([[1; 32], [1; 32]]));
    }
}

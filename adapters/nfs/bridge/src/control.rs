// SPDX-License-Identifier: LGPL-3.0-or-later

//! Versioned adapter-local control protocol for atomic FSAL export install.

use crate::ipc::SeqPacket;
use filebelt_vfs_protocol::{NfsAppliedExport, NfsExportManifestEntry};
use prost::Message;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

const CONTROL_FORMAT: u32 = 1;

#[derive(Clone, PartialEq, Message)]
struct ApplyManifestRequest {
    #[prost(uint32, tag = "1")]
    format: u32,
    #[prost(string, tag = "2")]
    request_id: String,
    #[prost(string, tag = "3")]
    boot_id: String,
    #[prost(uint64, tag = "4")]
    feature_generation: u64,
    #[prost(uint64, tag = "5")]
    export_generation: u64,
    #[prost(bytes = "vec", tag = "6")]
    manifest_digest: Vec<u8>,
    #[prost(message, repeated, tag = "7")]
    exports: Vec<ControlExport>,
    #[prost(bool, tag = "8")]
    drain: bool,
}

#[derive(Clone, PartialEq, Message)]
struct ControlExport {
    #[prost(uint64, tag = "1")]
    export_id: u64,
    #[prost(string, tag = "2")]
    drive_id: String,
    #[prost(string, tag = "3")]
    export_path: String,
    #[prost(uint64, tag = "4")]
    generation: u64,
    #[prost(bytes = "vec", tag = "5")]
    root_handle: Vec<u8>,
    #[prost(bool, tag = "6")]
    read_only: bool,
}

#[derive(Clone, PartialEq, Message)]
struct ApplyManifestResponse {
    #[prost(uint32, tag = "1")]
    format: u32,
    #[prost(string, tag = "2")]
    request_id: String,
    #[prost(bool, tag = "3")]
    applied: bool,
    #[prost(message, repeated, tag = "4")]
    exports: Vec<ControlAppliedExport>,
}

#[derive(Clone, PartialEq, Message)]
struct ControlAppliedExport {
    #[prost(uint64, tag = "1")]
    export_id: u64,
    #[prost(uint64, tag = "2")]
    generation: u64,
    #[prost(bytes = "vec", tag = "3")]
    root_handle: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct GaneshaControlClient {
    socket: PathBuf,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ControlError {
    #[error("Ganesha control channel is unavailable")]
    Unavailable,
    #[error("Ganesha rejected or misreported the export manifest")]
    Rejected,
}

pub trait ExportInstaller {
    fn apply_and_read_back(
        &self,
        boot_id: Uuid,
        feature_generation: u64,
        export_generation: u64,
        tenant_id: Uuid,
        exports: &[NfsExportManifestEntry],
    ) -> Result<([u8; 32], Vec<NfsAppliedExport>), ControlError>;

    fn drain(&self, boot_id: Uuid) -> Result<(), ControlError>;
}

impl GaneshaControlClient {
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_owned(),
        }
    }
}

impl ExportInstaller for GaneshaControlClient {
    fn apply_and_read_back(
        &self,
        boot_id: Uuid,
        feature_generation: u64,
        export_generation: u64,
        tenant_id: Uuid,
        exports: &[NfsExportManifestEntry],
    ) -> Result<([u8; 32], Vec<NfsAppliedExport>), ControlError> {
        let digest = manifest_digest(tenant_id, feature_generation, export_generation, exports);
        let request_id = Uuid::new_v4();
        let request = ApplyManifestRequest {
            format: CONTROL_FORMAT,
            request_id: request_id.to_string(),
            boot_id: boot_id.to_string(),
            feature_generation,
            export_generation,
            manifest_digest: digest.to_vec(),
            exports: exports
                .iter()
                .map(|export| ControlExport {
                    export_id: export.export_id,
                    drive_id: export.drive_id.clone(),
                    export_path: export.export_path.clone(),
                    generation: export.generation,
                    root_handle: export.root_handle.clone(),
                    read_only: export.read_only,
                })
                .collect(),
            drain: false,
        };
        let response = self.exchange(&request)?;
        let applied = response
            .exports
            .into_iter()
            .map(|export| NfsAppliedExport {
                export_id: export.export_id,
                generation: export.generation,
                root_handle_digest: root_handle_digest(&export.root_handle).to_vec(),
            })
            .collect::<Vec<_>>();
        if response.format != CONTROL_FORMAT
            || response.request_id != request_id.to_string()
            || !response.applied
            || !applied_matches(exports, &applied)
        {
            return Err(ControlError::Rejected);
        }
        Ok((digest, applied))
    }

    fn drain(&self, boot_id: Uuid) -> Result<(), ControlError> {
        let request_id = Uuid::new_v4();
        let request = ApplyManifestRequest {
            format: CONTROL_FORMAT,
            request_id: request_id.to_string(),
            boot_id: boot_id.to_string(),
            feature_generation: 0,
            export_generation: 0,
            manifest_digest: Vec::new(),
            exports: Vec::new(),
            drain: true,
        };
        let response = self.exchange(&request)?;
        if response.format != CONTROL_FORMAT
            || response.request_id != request_id.to_string()
            || !response.applied
            || !response.exports.is_empty()
        {
            return Err(ControlError::Rejected);
        }
        Ok(())
    }
}

impl GaneshaControlClient {
    fn exchange(
        &self,
        request: &ApplyManifestRequest,
    ) -> Result<ApplyManifestResponse, ControlError> {
        let payload = request.encode_to_vec();
        let mut delay = Duration::from_millis(25);
        for attempt in 0..5 {
            let response = SeqPacket::connect(&self.socket).and_then(|packet| {
                packet.send(&payload)?;
                packet.receive()
            });
            if let Ok(response) = response {
                return decode_response_exact(&response);
            }
            if attempt != 4 {
                thread::sleep(delay);
                delay = delay.saturating_mul(2);
            }
        }
        Err(ControlError::Unavailable)
    }
}

fn decode_response_exact(encoded: &[u8]) -> Result<ApplyManifestResponse, ControlError> {
    let decoded = ApplyManifestResponse::decode(encoded).map_err(|_| ControlError::Rejected)?;
    if decoded.encode_to_vec() != encoded {
        return Err(ControlError::Rejected);
    }
    Ok(decoded)
}

#[must_use]
pub fn root_handle_digest(handle: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"filebelt.nfs.root-handle.v1\0");
    hash_length_prefixed(&mut hasher, handle);
    *hasher.finalize().as_bytes()
}

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
    let count = u32::try_from(exports.len()).expect("validated manifest is bounded");
    hasher.update(&count.to_be_bytes());
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
    let length = u32::try_from(value.len()).expect("validated field is bounded");
    hasher.update(&length.to_be_bytes());
    hasher.update(value);
}

fn applied_matches(exports: &[NfsExportManifestEntry], applied: &[NfsAppliedExport]) -> bool {
    exports.len() == applied.len()
        && exports.iter().zip(applied).all(|(expected, actual)| {
            expected.export_id == actual.export_id
                && expected.generation == actual.generation
                && root_handle_digest(&expected.root_handle) == actual.root_handle_digest.as_slice()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(export_id: u64, generation: u64, handle: &[u8]) -> NfsExportManifestEntry {
        let drive_id = Uuid::from_u128(u128::from(export_id) + 100);
        NfsExportManifestEntry {
            export_id,
            drive_id: drive_id.to_string(),
            export_path: format!("/filebelt/{drive_id}"),
            generation,
            root_handle: handle.to_vec(),
            read_only: export_id.is_multiple_of(2),
        }
    }

    #[test]
    fn digest_binds_tenant_generations_order_and_complete_entry() {
        let tenant = Uuid::from_u128(9);
        let first = export(7, 3, &[1; 101]);
        let second = export(11, 4, &[2; 101]);
        let baseline = manifest_digest(tenant, 5, 6, &[first.clone(), second.clone()]);
        assert_eq!(
            baseline,
            [
                0x61, 0x49, 0xf3, 0x5f, 0x85, 0xdd, 0x9b, 0xe4, 0x56, 0x74, 0xc9, 0x27, 0xf0, 0x6e,
                0x5b, 0xba, 0x7e, 0x34, 0xb7, 0x5e, 0x6b, 0x96, 0xa4, 0x13, 0x18, 0xc4, 0xc4, 0x1c,
                0x3a, 0xc2, 0x90, 0x67,
            ]
        );
        assert_eq!(
            root_handle_digest(&[1; 101]),
            [
                0xb9, 0xc5, 0x0a, 0xc8, 0xbc, 0xb3, 0x22, 0x61, 0x7c, 0xfb, 0x23, 0xd5, 0x29, 0xf2,
                0xbb, 0xd8, 0xf1, 0x40, 0x3e, 0xab, 0x60, 0x0f, 0x0b, 0xb0, 0xad, 0x46, 0xeb, 0x61,
                0x04, 0x52, 0x4f, 0x83,
            ]
        );
        assert_eq!(
            baseline,
            manifest_digest(tenant, 5, 6, &[first.clone(), second.clone()])
        );
        assert_ne!(
            baseline,
            manifest_digest(tenant, 5, 7, &[first.clone(), second.clone()])
        );
        assert_ne!(baseline, manifest_digest(tenant, 5, 6, &[second, first]));
    }

    #[test]
    fn control_response_rejects_unknown_or_noncanonical_wire_data() {
        let response = ApplyManifestResponse {
            format: CONTROL_FORMAT,
            request_id: Uuid::from_u128(7).to_string(),
            applied: true,
            exports: Vec::new(),
        };
        let canonical = response.encode_to_vec();
        assert!(decode_response_exact(&canonical).is_ok());

        let mut unknown = canonical.clone();
        unknown.extend_from_slice(&[0x28, 0x01]);
        assert_eq!(decode_response_exact(&unknown), Err(ControlError::Rejected));

        let mut overlong = vec![0x08, 0x81, 0x00];
        overlong.extend_from_slice(&canonical[2..]);
        assert_eq!(
            decode_response_exact(&overlong),
            Err(ControlError::Rejected)
        );
    }

    #[test]
    fn readback_must_match_every_root_digest() {
        let expected = vec![export(7, 3, &[1; 101])];
        assert!(applied_matches(
            &expected,
            &[NfsAppliedExport {
                export_id: 7,
                generation: 3,
                root_handle_digest: root_handle_digest(&[1; 101]).to_vec(),
            }]
        ));
        assert!(!applied_matches(
            &expected,
            &[NfsAppliedExport {
                export_id: 7,
                generation: 3,
                root_handle_digest: root_handle_digest(&[2; 101]).to_vec(),
            }]
        ));
    }
}

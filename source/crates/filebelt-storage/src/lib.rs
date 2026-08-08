// SPDX-License-Identifier: Apache-2.0

//! UUID-only POSIX storage mechanics shared by FileBelt storage workers.

#![deny(unsafe_code)]

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write as _};
use std::os::unix::fs::symlink;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use filebelt_database::{PayloadRecord, UploadPartRecord, UploadRecord};
use thiserror::Error;
use uuid::Uuid;

mod cow;

pub use cow::{CowChunkDigest, CowManifest, CowWriteResult};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

#[derive(Clone, Debug)]
pub struct StorageLayout {
    root: PathBuf,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("storage object has an unsafe type or mode")]
    UnsafeObject,
    #[error("stored bytes do not match their durable metadata")]
    CorruptObject,
    #[error("stored bytes do not satisfy the declared content profile")]
    InvalidContent,
    #[error("storage operation is inconsistent with persisted state")]
    StateConflict,
    #[error("blocking storage task failed")]
    Join,
}

#[derive(Clone, Debug)]
pub struct FinalizedObject {
    pub digest: [u8; 32],
    pub size: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TemporaryCleanupReport {
    pub writing_removed: u64,
    pub finalizing_removed: u64,
}

impl TemporaryCleanupReport {
    #[must_use]
    pub const fn total_removed(&self) -> u64 {
        self.writing_removed + self.finalizing_removed
    }
}

impl StorageLayout {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn probe(&self) -> Result<(), StorageError> {
        let layout = self.clone();
        tokio::task::spawn_blocking(move || layout.probe_blocking())
            .await
            .map_err(|_| StorageError::Join)?
    }

    fn probe_blocking(&self) -> Result<(), StorageError> {
        self.prepare()?;
        let probe_id = Uuid::new_v4();
        let directory = self.shard_directory("staging", probe_id)?;
        let source = directory.join(format!("{probe_id}.probe"));
        let linked = directory.join(format!("{probe_id}.linked"));
        let destination = directory.join(format!("{probe_id}.renamed"));
        let symbolic = directory.join(format!("{probe_id}.symlink"));
        let mut file = create_new_file(&source)?;
        file.write_all(b"filebelt-storage-probe-v1")?;
        file.sync_all()?;
        fs::hard_link(&source, &linked)?;
        verify_regular_file(&linked)?;
        fs::remove_file(&linked)?;
        fs::rename(&source, &destination)?;
        sync_directory(&directory)?;
        verify_regular_file(&destination)?;
        symlink(&destination, &symbolic)?;
        if !matches!(
            verify_regular_file(&symbolic),
            Err(StorageError::UnsafeObject)
        ) {
            return Err(StorageError::UnsafeObject);
        }
        fs::remove_file(&symbolic)?;
        fs::remove_file(&destination)?;
        sync_directory(&directory)?;
        Ok(())
    }

    pub fn prepare(&self) -> Result<(), StorageError> {
        create_secure_directory(&self.root)?;
        for name in ["whole", "chunks", "staging", "quarantine"] {
            let child = self.root.join(name);
            create_secure_directory(&child)?;
            verify_same_owner(&child, &self.root)?;
        }
        Ok(())
    }

    pub fn staging_part_path(&self, locator: Uuid) -> Result<PathBuf, StorageError> {
        Ok(self
            .shard_directory("staging", locator)?
            .join(format!("{locator}.part")))
    }

    pub fn staging_temporary_path(
        &self,
        locator: Uuid,
        operation_id: Uuid,
    ) -> Result<PathBuf, StorageError> {
        Ok(self
            .shard_directory("staging", locator)?
            .join(format!("{locator}.{operation_id}.writing")))
    }

    pub fn payload_path(&self, payload: &PayloadRecord) -> Result<PathBuf, StorageError> {
        let area = match payload.layout.as_str() {
            "whole" => "whole",
            "chunked" => "chunks",
            _ => return Err(StorageError::StateConflict),
        };
        Ok(self
            .shard_directory(area, payload.locator)?
            .join(payload.locator.to_string()))
    }

    pub fn publish_staging_part(
        &self,
        temporary: &Path,
        locator: Uuid,
        expected_size: u64,
        expected_digest: &[u8; 32],
    ) -> Result<PathBuf, StorageError> {
        verify_regular_file(temporary)?;
        let destination = self.staging_part_path(locator)?;
        match fs::hard_link(temporary, &destination) {
            Ok(()) => sync_directory(parent(&destination)?)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                verify_file(&destination, expected_size, expected_digest)?;
            }
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(temporary)?;
        sync_directory(parent(&destination)?)?;
        verify_file(&destination, expected_size, expected_digest)?;
        Ok(destination)
    }

    pub fn finalize(
        &self,
        upload: &UploadRecord,
        payload: &PayloadRecord,
        parts: &[UploadPartRecord],
        operation_id: Uuid,
    ) -> Result<FinalizedObject, StorageError> {
        validate_manifest(upload, payload, parts)?;
        let final_path = self.payload_path(payload)?;
        if final_path.exists() {
            return self.verify_finalized(upload, payload, parts);
        }

        match payload.layout.as_str() {
            "whole" => {
                let source = self.staging_part_path(parts[0].locator)?;
                verify_part(&source, &parts[0])?;
                match fs::hard_link(&source, &final_path) {
                    Ok(()) => sync_directory(parent(&final_path)?)?,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            "chunked" => {
                let final_parent = parent(&final_path)?;
                let temporary =
                    final_parent.join(format!(".{}.{}.finalizing", payload.locator, operation_id));
                create_secure_directory(&temporary)?;
                verify_same_owner(&temporary, final_parent)?;
                for part in parts {
                    let source = self.staging_part_path(part.locator)?;
                    verify_part(&source, part)?;
                    fs::hard_link(&source, temporary.join(part_file_name(part.part_number)))?;
                }
                sync_directory(&temporary)?;
                match fs::rename(&temporary, &final_path) {
                    Ok(()) => sync_directory(final_parent)?,
                    Err(error) if final_path.exists() => {
                        remove_empty_or_operation_directory(&temporary)?;
                        let _ = error;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            _ => return Err(StorageError::StateConflict),
        }
        self.verify_finalized(upload, payload, parts)
    }

    pub fn verify_finalized(
        &self,
        upload: &UploadRecord,
        payload: &PayloadRecord,
        parts: &[UploadPartRecord],
    ) -> Result<FinalizedObject, StorageError> {
        validate_manifest(upload, payload, parts)?;
        let final_path = self.payload_path(payload)?;
        let mut hasher = blake3::Hasher::new();
        let mut size = 0_u64;
        match payload.layout.as_str() {
            "whole" => hash_file(&final_path, &mut hasher, &mut size)?,
            "chunked" => {
                verify_directory(&final_path)?;
                verify_same_owner(&final_path, parent(&final_path)?)?;
                for part in parts {
                    let path = final_path.join(part_file_name(part.part_number));
                    verify_part(&path, part)?;
                    hash_file(&path, &mut hasher, &mut size)?;
                }
            }
            _ => return Err(StorageError::StateConflict),
        }
        if size
            != u64::try_from(upload.declared_size_bytes).map_err(|_| StorageError::StateConflict)?
        {
            return Err(StorageError::CorruptObject);
        }
        if upload.declared_media_type.as_deref() == Some("text/markdown") {
            validate_markdown_payload(&final_path, payload, parts)?;
        }
        Ok(FinalizedObject {
            digest: *hasher.finalize().as_bytes(),
            size,
        })
    }

    pub fn verified_download_segments(
        &self,
        upload: &UploadRecord,
        payload: &PayloadRecord,
        parts: &[UploadPartRecord],
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<DownloadSegment>, StorageError> {
        validate_manifest(upload, payload, parts)?;
        let final_path = self.payload_path(payload)?;
        if payload.size_bytes == 0 {
            verify_part(&final_path, &parts[0])?;
            return Ok(Vec::new());
        }
        let size = u64::try_from(payload.size_bytes).map_err(|_| StorageError::StateConflict)?;
        if start > end_inclusive || end_inclusive >= size {
            return Err(StorageError::StateConflict);
        }
        if payload.layout == "whole" {
            verify_part(&final_path, &parts[0])?;
            return Ok(vec![DownloadSegment {
                path: final_path,
                offset: start,
                length: end_inclusive - start + 1,
            }]);
        }
        verify_directory(&final_path)?;
        let mut logical_offset = 0_u64;
        let mut result = Vec::new();
        for part in parts {
            let part_size =
                u64::try_from(part.size_bytes).map_err(|_| StorageError::StateConflict)?;
            let part_end = logical_offset.saturating_add(part_size);
            let overlap_start = start.max(logical_offset);
            let overlap_end_exclusive = end_inclusive.saturating_add(1).min(part_end);
            if overlap_start < overlap_end_exclusive {
                let path = final_path.join(part_file_name(part.part_number));
                verify_part(&path, part)?;
                result.push(DownloadSegment {
                    path,
                    offset: overlap_start - logical_offset,
                    length: overlap_end_exclusive - overlap_start,
                });
            }
            logical_offset = part_end;
        }
        if result.iter().map(|segment| segment.length).sum::<u64>() != end_inclusive - start + 1 {
            return Err(StorageError::CorruptObject);
        }
        Ok(result)
    }

    /// Publish one already-fsynced staging part as a whole payload object.
    /// This is used for collaboration update groups and snapshots, whose
    /// authoritative manifest is separate from the upload-session tables.
    pub fn finalize_whole_object(
        &self,
        payload: &PayloadRecord,
        expected_size: u64,
        expected_digest: &[u8; 32],
    ) -> Result<FinalizedObject, StorageError> {
        if payload.layout != "whole" {
            return Err(StorageError::StateConflict);
        }
        let source = self.staging_part_path(payload.locator)?;
        verify_file(&source, expected_size, expected_digest)?;
        let destination = self.payload_path(payload)?;
        match fs::hard_link(&source, &destination) {
            Ok(()) => sync_directory(parent(&destination)?)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                verify_file(&destination, expected_size, expected_digest)?;
            }
            Err(error) => return Err(error.into()),
        }
        verify_file(&destination, expected_size, expected_digest)?;
        Ok(FinalizedObject {
            digest: *expected_digest,
            size: expected_size,
        })
    }

    pub fn verify_staging_object(
        &self,
        locator: Uuid,
        expected_size: u64,
    ) -> Result<FinalizedObject, StorageError> {
        let path = self.staging_part_path(locator)?;
        verify_regular_file(&path)?;
        let mut hasher = blake3::Hasher::new();
        let mut size = 0_u64;
        hash_file(&path, &mut hasher, &mut size)?;
        if size != expected_size {
            return Err(StorageError::CorruptObject);
        }
        Ok(FinalizedObject {
            digest: *hasher.finalize().as_bytes(),
            size,
        })
    }

    pub fn verified_whole_object_segment(
        &self,
        payload: &PayloadRecord,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<DownloadSegment>, StorageError> {
        if payload.layout != "whole" {
            return Err(StorageError::StateConflict);
        }
        let size = u64::try_from(payload.size_bytes).map_err(|_| StorageError::StateConflict)?;
        let digest: [u8; 32] = payload
            .blake3
            .as_deref()
            .ok_or(StorageError::StateConflict)?
            .try_into()
            .map_err(|_| StorageError::StateConflict)?;
        let path = self.payload_path(payload)?;
        verify_file(&path, size, &digest)?;
        if size == 0 {
            return Ok(Vec::new());
        }
        if start > end_inclusive || end_inclusive >= size {
            return Err(StorageError::StateConflict);
        }
        Ok(vec![DownloadSegment {
            path,
            offset: start,
            length: end_inclusive - start + 1,
        }])
    }

    pub fn remove_staging_locator(&self, locator: Uuid) -> Result<(), StorageError> {
        let path = self.staging_part_path(locator)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                verify_regular_file(&path)?;
                fs::remove_file(&path)?;
                sync_directory(parent(&path)?)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub fn remove_staging_parts(&self, parts: &[UploadPartRecord]) -> Result<(), StorageError> {
        for part in parts {
            let path = self.staging_part_path(part.locator)?;
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    verify_regular_file(&path)?;
                    fs::remove_file(&path)?;
                    sync_directory(parent(&path)?)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub fn delete_payload(&self, payload: &PayloadRecord) -> Result<(), StorageError> {
        let path = self.payload_path(payload)?;
        match payload.layout.as_str() {
            "whole" => match fs::symlink_metadata(&path) {
                Ok(_) => {
                    verify_regular_file(&path)?;
                    fs::remove_file(&path)?;
                    sync_directory(parent(&path)?)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
            "chunked" => match fs::symlink_metadata(&path) {
                Ok(_) => {
                    verify_directory(&path)?;
                    for entry in fs::read_dir(&path)? {
                        let entry = entry?;
                        verify_regular_file(&entry.path())?;
                        fs::remove_file(entry.path())?;
                    }
                    fs::remove_dir(&path)?;
                    sync_directory(parent(&path)?)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
            _ => return Err(StorageError::StateConflict),
        }
        Ok(())
    }

    pub fn quarantine_payload(&self, payload: &PayloadRecord) -> Result<PathBuf, StorageError> {
        self.quarantine_payload_with_after_move(payload, || Ok(()))
    }

    fn quarantine_payload_with_after_move<F>(
        &self,
        payload: &PayloadRecord,
        after_move: F,
    ) -> Result<PathBuf, StorageError>
    where
        F: FnOnce() -> Result<(), StorageError>,
    {
        let source = self.payload_path(payload)?;
        let destination = self
            .shard_directory("quarantine", payload.locator)?
            .join(payload.locator.to_string());

        match (path_kind(&source)?, path_kind(&destination)?) {
            (PathKind::Missing, PathKind::Present) => {
                verify_payload_container(&destination, payload)?;
                sync_directory(parent(&source)?)?;
                sync_directory(parent(&destination)?)?;
                return Ok(destination);
            }
            (PathKind::Present, PathKind::Missing) => {
                verify_payload_container(&source, payload)?;
            }
            (PathKind::Missing, PathKind::Missing) => return Ok(destination),
            (PathKind::Present, PathKind::Present) => {
                return Err(StorageError::StateConflict);
            }
        }

        match fs::rename(&source, &destination) {
            Ok(()) => after_move()?,
            Err(error) => {
                if error.kind() != io::ErrorKind::NotFound
                    || path_kind(&source)? != PathKind::Missing
                    || path_kind(&destination)? != PathKind::Present
                {
                    return Err(error.into());
                }
                verify_payload_container(&destination, payload)?;
            }
        }
        sync_directory(parent(&source)?)?;
        sync_directory(parent(&destination)?)?;
        verify_payload_container(&destination, payload)?;
        Ok(destination)
    }

    pub fn cleanup_operation_temporaries(
        &self,
        minimum_age: Duration,
        max_removals: usize,
    ) -> Result<TemporaryCleanupReport, StorageError> {
        self.cleanup_operation_temporaries_at(SystemTime::now(), minimum_age, max_removals)
    }

    fn cleanup_operation_temporaries_at(
        &self,
        now: SystemTime,
        minimum_age: Duration,
        max_removals: usize,
    ) -> Result<TemporaryCleanupReport, StorageError> {
        self.prepare()?;
        let mut report = TemporaryCleanupReport::default();
        if max_removals == 0 {
            return Ok(report);
        }
        self.cleanup_sharded_area("staging", now, minimum_age, max_removals, &mut report)?;
        if usize::try_from(report.total_removed()).unwrap_or(usize::MAX) < max_removals {
            self.cleanup_sharded_area("chunks", now, minimum_age, max_removals, &mut report)?;
        }
        Ok(report)
    }

    fn cleanup_sharded_area(
        &self,
        area: &str,
        now: SystemTime,
        minimum_age: Duration,
        max_removals: usize,
        report: &mut TemporaryCleanupReport,
    ) -> Result<(), StorageError> {
        let area_path = self.root.join(area);
        verify_directory(&area_path)?;
        verify_same_owner(&area_path, &self.root)?;
        for first in fs::read_dir(&area_path)? {
            let first = first?;
            if !is_shard_name(&first.file_name()) {
                return Err(StorageError::UnsafeObject);
            }
            let first_path = first.path();
            verify_directory(&first_path)?;
            verify_same_owner(&first_path, &area_path)?;
            for second in fs::read_dir(&first_path)? {
                let second = second?;
                if !is_shard_name(&second.file_name()) {
                    return Err(StorageError::UnsafeObject);
                }
                let second_path = second.path();
                verify_directory(&second_path)?;
                verify_same_owner(&second_path, &first_path)?;
                for entry in fs::read_dir(&second_path)? {
                    if usize::try_from(report.total_removed()).unwrap_or(usize::MAX) >= max_removals
                    {
                        return Ok(());
                    }
                    let entry = entry?;
                    let name = entry
                        .file_name()
                        .into_string()
                        .map_err(|_| StorageError::UnsafeObject)?;
                    let path = entry.path();
                    let kind = if area == "staging" && is_writing_temporary(&name) {
                        Some(TemporaryKind::Writing)
                    } else if area == "chunks" && is_finalizing_temporary(&name) {
                        Some(TemporaryKind::Finalizing)
                    } else {
                        None
                    };
                    let Some(kind) = kind else {
                        continue;
                    };
                    let metadata = fs::symlink_metadata(&path)?;
                    if now.duration_since(metadata.modified()?).unwrap_or_default() < minimum_age {
                        continue;
                    }
                    match kind {
                        TemporaryKind::Writing => {
                            verify_regular_file(&path)?;
                            fs::remove_file(&path)?;
                            sync_directory(&second_path)?;
                            report.writing_removed += 1;
                        }
                        TemporaryKind::Finalizing => {
                            remove_empty_or_operation_directory(&path)?;
                            sync_directory(&second_path)?;
                            report.finalizing_removed += 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn shard_directory(&self, area: &str, locator: Uuid) -> Result<PathBuf, StorageError> {
        let hexadecimal = locator.simple().to_string();
        let first = &hexadecimal[0..2];
        let second = &hexadecimal[2..4];
        let area = self.root.join(area);
        create_secure_directory(&area)?;
        verify_same_owner(&area, &self.root)?;
        let first = area.join(first);
        create_secure_directory(&first)?;
        verify_same_owner(&first, &area)?;
        let second = first.join(second);
        create_secure_directory(&second)?;
        verify_same_owner(&second, &first)?;
        Ok(second)
    }
}

fn validate_markdown_payload(
    final_path: &Path,
    payload: &PayloadRecord,
    parts: &[UploadPartRecord],
) -> Result<(), StorageError> {
    let capacity = usize::try_from(payload.size_bytes).map_err(|_| StorageError::InvalidContent)?;
    if capacity > 2_097_152 {
        return Err(StorageError::InvalidContent);
    }
    let mut bytes = Vec::with_capacity(capacity);
    match payload.layout.as_str() {
        "whole" => {
            File::open(final_path)?.read_to_end(&mut bytes)?;
        }
        "chunked" => {
            for part in parts {
                File::open(final_path.join(part_file_name(part.part_number)))?
                    .read_to_end(&mut bytes)?;
            }
        }
        _ => return Err(StorageError::StateConflict),
    };
    let content = bytes
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(bytes.as_slice());
    if content.contains(&0) || std::str::from_utf8(content).is_err() {
        return Err(StorageError::InvalidContent);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathKind {
    Missing,
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TemporaryKind {
    Writing,
    Finalizing,
}

fn path_kind(path: &Path) -> Result<PathKind, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(PathKind::Present),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(PathKind::Missing),
        Err(error) => Err(error.into()),
    }
}

fn verify_payload_container(path: &Path, payload: &PayloadRecord) -> Result<(), StorageError> {
    match payload.layout.as_str() {
        "whole" => verify_regular_file(path),
        "chunked" => {
            verify_directory(path)?;
            verify_same_owner(path, parent(path)?)
        }
        _ => Err(StorageError::StateConflict),
    }
}

fn is_shard_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|value| {
        value.len() == 2
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_writing_temporary(name: &str) -> bool {
    let Some(without_suffix) = name.strip_suffix(".writing") else {
        return false;
    };
    let mut components = without_suffix.split('.');
    let Some(locator) = components.next() else {
        return false;
    };
    let Some(operation) = components.next() else {
        return false;
    };
    components.next().is_none() && is_canonical_uuid(locator) && is_canonical_uuid(operation)
}

fn is_finalizing_temporary(name: &str) -> bool {
    let Some(without_prefix) = name.strip_prefix('.') else {
        return false;
    };
    let Some(without_suffix) = without_prefix.strip_suffix(".finalizing") else {
        return false;
    };
    let components = without_suffix.split('.').collect::<Vec<_>>();
    matches!(components.as_slice(), [operation] if is_canonical_uuid(operation))
        || matches!(components.as_slice(), [locator, operation]
            if is_canonical_uuid(locator) && is_canonical_uuid(operation))
}

fn is_canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn is_part_file_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|value| {
        let Some(number) = value.strip_suffix(".part") else {
            return false;
        };
        number.len() == 8 && number.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[derive(Clone, Debug)]
pub struct DownloadSegment {
    pub path: PathBuf,
    pub offset: u64,
    pub length: u64,
}

pub fn create_new_file(path: &Path) -> Result<File, StorageError> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
    Ok(file)
}

fn validate_manifest(
    upload: &UploadRecord,
    payload: &PayloadRecord,
    parts: &[UploadPartRecord],
) -> Result<(), StorageError> {
    if upload.tenant_id != payload.tenant_id
        || upload.drive_id != payload.drive_id
        || upload.backend_id != payload.backend_id
        || upload.payload_id != payload.payload_id
        || upload.payload_locator != payload.locator
        || parts.len()
            != usize::try_from(upload.part_count).map_err(|_| StorageError::StateConflict)?
        || parts.iter().any(|part| {
            part.state != "durable" || part.blake3.as_ref().is_none_or(|digest| digest.len() != 32)
        })
        || (payload.layout == "whole" && parts.len() != 1)
        || (payload.layout == "chunked" && parts.len() < 2)
        || parts
            .iter()
            .enumerate()
            .any(|(index, part)| usize::try_from(part.part_number).ok() != Some(index))
    {
        return Err(StorageError::StateConflict);
    }
    Ok(())
}

fn verify_part(path: &Path, part: &UploadPartRecord) -> Result<(), StorageError> {
    let expected_digest: [u8; 32] = part
        .blake3
        .as_deref()
        .ok_or(StorageError::StateConflict)?
        .try_into()
        .map_err(|_| StorageError::StateConflict)?;
    verify_file(
        path,
        u64::try_from(part.size_bytes).map_err(|_| StorageError::StateConflict)?,
        &expected_digest,
    )
}

fn verify_file(
    path: &Path,
    expected_size: u64,
    expected_digest: &[u8; 32],
) -> Result<(), StorageError> {
    verify_regular_file(path)?;
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() != expected_size {
        return Err(StorageError::CorruptObject);
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if hasher.finalize().as_bytes() != expected_digest {
        return Err(StorageError::CorruptObject);
    }
    Ok(())
}

fn hash_file(
    path: &Path,
    hasher: &mut blake3::Hasher,
    total: &mut u64,
) -> Result<(), StorageError> {
    verify_regular_file(path)?;
    let mut file = File::open(path)?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        *total = total
            .checked_add(read as u64)
            .ok_or(StorageError::StateConflict)?;
    }
    Ok(())
}

fn create_secure_directory(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))?;
            verify_directory(path)?;
            sync_directory(path)?;
            if let Some(parent) = path.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn verify_directory(path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o777 != DIRECTORY_MODE {
        return Err(StorageError::UnsafeObject);
    }
    Ok(())
}

fn verify_regular_file(path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != FILE_MODE {
        return Err(StorageError::UnsafeObject);
    }
    verify_same_owner(path, parent(path)?)?;
    Ok(())
}

fn verify_same_owner(path: &Path, expected_owner_path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path)?;
    let expected = fs::symlink_metadata(expected_owner_path)?;
    if metadata.uid() != expected.uid() {
        return Err(StorageError::UnsafeObject);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), StorageError> {
    verify_directory(path)?;
    File::open(path)?.sync_all()?;
    Ok(())
}

fn parent(path: &Path) -> Result<&Path, StorageError> {
    path.parent().ok_or(StorageError::StateConflict)
}

fn part_file_name(part_number: i32) -> String {
    format!("{part_number:08}.part")
}

fn remove_empty_or_operation_directory(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    verify_directory(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !is_part_file_name(&entry.file_name()) {
            return Err(StorageError::UnsafeObject);
        }
        verify_regular_file(&entry.path())?;
        fs::remove_file(entry.path())?;
    }
    fs::remove_dir(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload(payload_id: Uuid, payload_locator: Uuid, size: i64, parts: i32) -> UploadRecord {
        UploadRecord {
            tenant_id: Uuid::new_v4(),
            upload_id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            node_id: None,
            parent_id: Uuid::new_v4(),
            owner_principal_id: Uuid::new_v4(),
            payload_id,
            backend_id: Uuid::new_v4(),
            payload_locator,
            expected_head_version_id: None,
            target_display_name: "ignored.txt".into(),
            target_name_key: "ignored.txt".into(),
            declared_size_bytes: size,
            chunk_size_bytes: 4,
            part_count: parts,
            fencing_token: 1,
            state: "open".into(),
            declared_media_type: None,
            collaboration_checkpoint_id: None,
            import_intent_id: None,
        }
    }

    fn payload(upload: &UploadRecord, layout: &str) -> PayloadRecord {
        PayloadRecord {
            tenant_id: upload.tenant_id,
            payload_id: upload.payload_id,
            backend_id: upload.backend_id,
            drive_id: upload.drive_id,
            locator: upload.payload_locator,
            layout: layout.into(),
            state: "staging".into(),
            size_bytes: upload.declared_size_bytes,
            blake3: None,
        }
    }

    fn stage(layout: &StorageLayout, part_number: i32, bytes: &[u8]) -> UploadPartRecord {
        let locator = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let temporary = layout
            .staging_temporary_path(locator, operation)
            .expect("temporary part path");
        let mut file = create_new_file(&temporary).expect("new part");
        file.write_all(bytes).expect("part bytes");
        file.sync_all().expect("durable part bytes");
        let digest = *blake3::hash(bytes).as_bytes();
        layout
            .publish_staging_part(&temporary, locator, bytes.len() as u64, &digest)
            .expect("publish staged part");
        UploadPartRecord {
            part_number,
            locator,
            state: "durable".into(),
            size_bytes: i32::try_from(bytes.len()).expect("small test part"),
            blake3: Some(digest.to_vec()),
        }
    }

    #[tokio::test]
    async fn probe_creates_only_fixed_storage_areas() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let root = temporary.path().join("payloads");
        let layout = StorageLayout::new(root.clone());
        layout.probe().await.expect("supported filesystem");
        for area in ["whole", "chunks", "staging", "quarantine"] {
            assert!(root.join(area).is_dir());
        }
    }

    #[test]
    fn locator_paths_do_not_include_logical_names() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let locator = Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").expect("uuid");
        let path = layout.staging_part_path(locator).expect("locator path");
        assert!(path.ends_with("aa/aa/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.part"));
    }

    #[test]
    fn whole_payload_is_published_and_verified_from_durable_part() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let upload = upload(Uuid::new_v4(), Uuid::new_v4(), 5, 1);
        let payload = payload(&upload, "whole");
        let parts = vec![stage(&layout, 0, b"hello")];
        let finalized = layout
            .finalize(&upload, &payload, &parts, Uuid::new_v4())
            .expect("finalize whole payload");
        assert_eq!(finalized.size, 5);
        assert_eq!(finalized.digest, *blake3::hash(b"hello").as_bytes());
        assert_eq!(
            layout
                .verified_download_segments(&upload, &payload, &parts, 1, 3)
                .expect("range")[0]
                .length,
            3
        );
    }

    #[test]
    fn chunked_payload_preserves_order_and_cross_part_ranges() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let upload = upload(Uuid::new_v4(), Uuid::new_v4(), 8, 2);
        let payload = payload(&upload, "chunked");
        let parts = vec![stage(&layout, 0, b"abcd"), stage(&layout, 1, b"efgh")];
        let finalized = layout
            .finalize(&upload, &payload, &parts, Uuid::new_v4())
            .expect("finalize chunked payload");
        assert_eq!(finalized.digest, *blake3::hash(b"abcdefgh").as_bytes());
        let segments = layout
            .verified_download_segments(&upload, &payload, &parts, 2, 5)
            .expect("cross-part range");
        assert_eq!(segments.len(), 2);
        assert_eq!(
            segments.iter().map(|segment| segment.length).sum::<u64>(),
            4
        );
    }

    #[test]
    fn range_verification_hashes_only_chunks_that_will_be_served() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let upload = upload(Uuid::new_v4(), Uuid::new_v4(), 8, 2);
        let payload = payload(&upload, "chunked");
        let parts = vec![stage(&layout, 0, b"abcd"), stage(&layout, 1, b"efgh")];
        layout
            .finalize(&upload, &payload, &parts, Uuid::new_v4())
            .expect("finalize chunked payload");
        let final_path = layout.payload_path(&payload).expect("payload path");
        std::fs::write(final_path.join(part_file_name(1)), b"bad!")
            .expect("corrupt unrelated chunk");

        let first = layout
            .verified_download_segments(&upload, &payload, &parts, 0, 0)
            .expect("unrelated corruption does not amplify a tiny range");
        assert_eq!(first.len(), 1);
        assert!(matches!(
            layout.verified_download_segments(&upload, &payload, &parts, 4, 4),
            Err(StorageError::CorruptObject)
        ));
    }

    #[test]
    fn whole_payload_rejects_multiple_parts() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let upload = upload(Uuid::new_v4(), Uuid::new_v4(), 8, 2);
        let payload = payload(&upload, "whole");
        let parts = vec![stage(&layout, 0, b"abcd"), stage(&layout, 1, b"efgh")];
        assert!(matches!(
            layout.finalize(&upload, &payload, &parts, Uuid::new_v4()),
            Err(StorageError::StateConflict)
        ));
    }

    #[test]
    fn symlinked_part_is_rejected() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let locator = Uuid::new_v4();
        let path = layout.staging_part_path(locator).expect("part path");
        symlink("/dev/null", &path).expect("test symlink");
        assert!(matches!(
            verify_regular_file(&path),
            Err(StorageError::UnsafeObject)
        ));
    }

    #[test]
    fn quarantine_reconciles_a_completed_filesystem_move() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let upload = upload(Uuid::new_v4(), Uuid::new_v4(), 5, 1);
        let payload = payload(&upload, "whole");
        let parts = vec![stage(&layout, 0, b"hello")];
        layout
            .finalize(&upload, &payload, &parts, Uuid::new_v4())
            .expect("finalize payload");

        assert!(matches!(
            layout.quarantine_payload_with_after_move(&payload, || Err(StorageError::Join)),
            Err(StorageError::Join)
        ));
        let first = layout
            .quarantine_payload(&payload)
            .expect("resume after post-move failpoint");
        let second = layout
            .quarantine_payload(&payload)
            .expect("resumed quarantine");

        assert_eq!(first, second);
        assert!(first.is_file());
        assert!(
            !layout
                .payload_path(&payload)
                .expect("payload path")
                .exists()
        );
    }

    #[test]
    fn quarantine_rejects_ambiguous_source_and_destination() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let upload = upload(Uuid::new_v4(), Uuid::new_v4(), 5, 1);
        let payload = payload(&upload, "whole");
        let parts = vec![stage(&layout, 0, b"hello")];
        layout
            .finalize(&upload, &payload, &parts, Uuid::new_v4())
            .expect("finalize payload");
        let destination = layout
            .quarantine_payload(&payload)
            .expect("initial quarantine");
        let source = layout.payload_path(&payload).expect("payload path");
        fs::hard_link(&destination, &source).expect("ambiguous duplicate");

        assert!(matches!(
            layout.quarantine_payload(&payload),
            Err(StorageError::StateConflict)
        ));
    }

    #[test]
    fn operation_temporary_cleanup_is_bounded_and_covers_both_areas() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let locator = Uuid::new_v4();
        let writing = layout
            .staging_temporary_path(locator, Uuid::new_v4())
            .expect("writing path");
        create_new_file(&writing).expect("writing temporary");
        let finalizing = layout
            .shard_directory("chunks", locator)
            .expect("chunk shard")
            .join(format!(".{locator}.{}.finalizing", Uuid::new_v4()));
        create_secure_directory(&finalizing).expect("finalizing temporary");
        create_new_file(&finalizing.join(part_file_name(0))).expect("linked chunk");

        let first = layout
            .cleanup_operation_temporaries(Duration::ZERO, 1)
            .expect("bounded cleanup");
        assert_eq!(first.writing_removed, 1);
        assert_eq!(first.finalizing_removed, 0);
        assert!(!writing.exists());
        assert!(finalizing.exists());

        let second = layout
            .cleanup_operation_temporaries(Duration::ZERO, 1)
            .expect("continued cleanup");
        assert_eq!(second.writing_removed, 0);
        assert_eq!(second.finalizing_removed, 1);
        assert!(!finalizing.exists());
    }

    #[test]
    fn operation_temporary_cleanup_never_follows_symlinks() {
        let temporary = tempfile::tempdir().expect("temporary storage root");
        let layout = StorageLayout::new(temporary.path().join("payloads"));
        layout.prepare().expect("prepare storage");
        let locator = Uuid::new_v4();
        let writing = layout
            .staging_temporary_path(locator, Uuid::new_v4())
            .expect("writing path");
        symlink("/dev/null", &writing).expect("test symlink");

        assert!(matches!(
            layout.cleanup_operation_temporaries(Duration::ZERO, 1),
            Err(StorageError::UnsafeObject)
        ));
        assert!(
            fs::symlink_metadata(writing)
                .expect("symlink remains")
                .file_type()
                .is_symlink()
        );
    }
}

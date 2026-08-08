// SPDX-License-Identifier: Apache-2.0

//! Copy-on-write staging for mount writes.

use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::PathBuf;

use filebelt_database::{PayloadRecord, UploadPartRecord};
use uuid::Uuid;

use super::{
    FinalizedObject, StorageError, StorageLayout, create_new_file, create_secure_directory, parent,
    path_kind, sync_directory, verify_directory, verify_file, verify_part, verify_regular_file,
    verify_same_owner,
};

const MIN_CHUNK_SIZE: u64 = 64 * 1024;
const MAX_CHUNK_SIZE: u64 = 64 * 1024 * 1024;
const MAX_CHUNK_COUNT: u64 = 100_000_000;
static ZERO_BUFFER: [u8; 64 * 1024] = [0; 64 * 1024];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CowWriteResult {
    pub logical_size: u64,
    pub reservation_delta: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CowChunkDigest {
    pub chunk_number: u64,
    pub size: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CowManifest {
    pub logical_size: u64,
    pub digest: [u8; 32],
    pub chunks: Vec<CowChunkDigest>,
}

impl StorageLayout {
    pub fn begin_cow_write(
        &self,
        write_session_id: Uuid,
        base_payload: Option<&PayloadRecord>,
        base_parts: &[UploadPartRecord],
    ) -> Result<(), StorageError> {
        self.prepare()?;
        let directory = self.cow_directory(write_session_id)?;
        if !matches!(path_kind(&directory)?, super::PathKind::Missing) {
            return Err(StorageError::StateConflict);
        }
        create_secure_directory(&directory)?;
        verify_same_owner(&directory, parent(&directory)?)?;
        if let Some(payload) = base_payload {
            let source = self.payload_path(payload)?;
            match payload.layout.as_str() {
                "whole" => {
                    let digest: [u8; 32] = payload
                        .blake3
                        .as_deref()
                        .ok_or(StorageError::CorruptObject)?
                        .try_into()
                        .map_err(|_| StorageError::CorruptObject)?;
                    verify_file(
                        &source,
                        u64::try_from(payload.size_bytes)
                            .map_err(|_| StorageError::StateConflict)?,
                        &digest,
                    )?;
                    fs::hard_link(source, directory.join(cow_chunk_name(0)))?;
                }
                "chunked" => {
                    verify_directory(&source)?;
                    for part in base_parts {
                        let part_number = u64::try_from(part.part_number)
                            .map_err(|_| StorageError::StateConflict)?;
                        let source_part = source.join(super::part_file_name(part.part_number));
                        verify_part(&source_part, part)?;
                        fs::hard_link(source_part, directory.join(cow_chunk_name(part_number)))?;
                    }
                }
                _ => return Err(StorageError::StateConflict),
            }
        } else if !base_parts.is_empty() {
            return Err(StorageError::StateConflict);
        }
        sync_directory(&directory)?;
        sync_directory(parent(&directory)?)?;
        Ok(())
    }

    pub fn write_cow_at(
        &self,
        write_session_id: Uuid,
        operation_id: Uuid,
        chunk_size: u64,
        current_logical_size: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<CowWriteResult, StorageError> {
        validate_chunk_size(chunk_size)?;
        let byte_count = u64::try_from(bytes.len()).map_err(|_| StorageError::StateConflict)?;
        let end = offset
            .checked_add(byte_count)
            .ok_or(StorageError::StateConflict)?;
        if offset > current_logical_size {
            self.write_cow_zero_range(
                write_session_id,
                operation_id,
                chunk_size,
                current_logical_size,
                offset - current_logical_size,
            )?;
        }
        self.write_cow_range(write_session_id, operation_id, chunk_size, offset, bytes)?;
        let logical_size = current_logical_size.max(end);
        Ok(CowWriteResult {
            logical_size,
            reservation_delta: logical_size.saturating_sub(current_logical_size),
        })
    }

    pub fn truncate_cow(
        &self,
        write_session_id: Uuid,
        operation_id: Uuid,
        chunk_size: u64,
        current_logical_size: u64,
        new_logical_size: u64,
    ) -> Result<CowWriteResult, StorageError> {
        validate_chunk_size(chunk_size)?;
        if new_logical_size > current_logical_size {
            self.write_cow_zero_range(
                write_session_id,
                operation_id,
                chunk_size,
                current_logical_size,
                new_logical_size - current_logical_size,
            )?;
        } else if new_logical_size < current_logical_size {
            let directory = self.cow_directory(write_session_id)?;
            verify_directory(&directory)?;
            let retained_chunks = new_logical_size.div_ceil(chunk_size);
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                let number = parse_cow_chunk_name(&entry.file_name())?;
                if number >= retained_chunks {
                    verify_regular_file(&entry.path())?;
                    fs::remove_file(entry.path())?;
                }
            }
            if new_logical_size > 0 {
                let final_number = (new_logical_size - 1) / chunk_size;
                let final_size = new_logical_size - final_number * chunk_size;
                self.replace_chunk(write_session_id, operation_id, final_number, |file| {
                    file.set_len(final_size)?;
                    Ok(())
                })?;
            }
            sync_directory(&directory)?;
        }
        Ok(CowWriteResult {
            logical_size: new_logical_size,
            reservation_delta: new_logical_size.saturating_sub(current_logical_size),
        })
    }

    pub fn cow_manifest(
        &self,
        write_session_id: Uuid,
        chunk_size: u64,
        logical_size: u64,
    ) -> Result<CowManifest, StorageError> {
        validate_chunk_size(chunk_size)?;
        let directory = self.cow_directory(write_session_id)?;
        verify_directory(&directory)?;
        let chunk_count = logical_size.div_ceil(chunk_size);
        if chunk_count > MAX_CHUNK_COUNT {
            return Err(StorageError::StateConflict);
        }
        let actual_count = fs::read_dir(&directory)?.count();
        if actual_count != usize::try_from(chunk_count).map_err(|_| StorageError::StateConflict)? {
            return Err(StorageError::CorruptObject);
        }
        let mut overall = blake3::Hasher::new();
        let mut chunks = Vec::with_capacity(actual_count);
        for chunk_number in 0..chunk_count {
            let path = directory.join(cow_chunk_name(chunk_number));
            verify_regular_file(&path)?;
            let expected_size = if chunk_number + 1 == chunk_count {
                logical_size - chunk_number * chunk_size
            } else {
                chunk_size
            };
            let mut file = File::open(&path)?;
            let mut chunk_hasher = blake3::Hasher::new();
            let mut size = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                let read_u64 = u64::try_from(read).map_err(|_| StorageError::StateConflict)?;
                size = size
                    .checked_add(read_u64)
                    .ok_or(StorageError::StateConflict)?;
                overall.update(&buffer[..read]);
                chunk_hasher.update(&buffer[..read]);
            }
            if size != expected_size {
                return Err(StorageError::CorruptObject);
            }
            chunks.push(CowChunkDigest {
                chunk_number,
                size,
                digest: *chunk_hasher.finalize().as_bytes(),
            });
        }
        Ok(CowManifest {
            logical_size,
            digest: *overall.finalize().as_bytes(),
            chunks,
        })
    }

    pub fn publish_cow(
        &self,
        write_session_id: Uuid,
        payload: &PayloadRecord,
        chunk_size: u64,
    ) -> Result<FinalizedObject, StorageError> {
        if payload.layout != "chunked" {
            return Err(StorageError::StateConflict);
        }
        let logical_size =
            u64::try_from(payload.size_bytes).map_err(|_| StorageError::StateConflict)?;
        let manifest = self.cow_manifest(write_session_id, chunk_size, logical_size)?;
        if payload.blake3.as_deref() != Some(manifest.digest.as_slice()) {
            return Err(StorageError::CorruptObject);
        }
        let source = self.cow_directory(write_session_id)?;
        let destination = self.payload_path(payload)?;
        if !matches!(path_kind(&destination)?, super::PathKind::Missing) {
            return Err(StorageError::StateConflict);
        }
        fs::rename(&source, &destination)?;
        sync_directory(parent(&source)?)?;
        sync_directory(parent(&destination)?)?;
        Ok(FinalizedObject {
            digest: manifest.digest,
            size: manifest.logical_size,
        })
    }

    pub fn abort_cow(&self, write_session_id: Uuid) -> Result<(), StorageError> {
        let directory = self.cow_directory(write_session_id)?;
        match path_kind(&directory)? {
            super::PathKind::Missing => return Ok(()),
            super::PathKind::Present => verify_directory(&directory)?,
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            parse_cow_entry_name(&entry.file_name())?;
            verify_regular_file(&entry.path())?;
            fs::remove_file(entry.path())?;
        }
        fs::remove_dir(&directory)?;
        sync_directory(parent(&directory)?)?;
        Ok(())
    }

    fn write_cow_range(
        &self,
        write_session_id: Uuid,
        operation_id: Uuid,
        chunk_size: u64,
        mut offset: u64,
        mut bytes: &[u8],
    ) -> Result<(), StorageError> {
        while !bytes.is_empty() {
            let chunk_number = offset / chunk_size;
            let within = offset % chunk_size;
            let remaining = chunk_size - within;
            let take = bytes
                .len()
                .min(usize::try_from(remaining).map_err(|_| StorageError::StateConflict)?);
            let segment = &bytes[..take];
            self.replace_chunk(write_session_id, operation_id, chunk_number, |file| {
                pad_file_to(file, within)?;
                file.seek(SeekFrom::Start(within))?;
                file.write_all(segment)?;
                Ok(())
            })?;
            offset = offset
                .checked_add(u64::try_from(take).map_err(|_| StorageError::StateConflict)?)
                .ok_or(StorageError::StateConflict)?;
            bytes = &bytes[take..];
        }
        Ok(())
    }

    fn write_cow_zero_range(
        &self,
        write_session_id: Uuid,
        operation_id: Uuid,
        chunk_size: u64,
        mut offset: u64,
        mut length: u64,
    ) -> Result<(), StorageError> {
        while length > 0 {
            let chunk_number = offset / chunk_size;
            let within = offset % chunk_size;
            let take = length.min(chunk_size - within);
            self.replace_chunk(write_session_id, operation_id, chunk_number, |file| {
                pad_file_to(file, within)?;
                file.seek(SeekFrom::Start(within))?;
                write_zeroes(file, take)?;
                Ok(())
            })?;
            offset = offset
                .checked_add(take)
                .ok_or(StorageError::StateConflict)?;
            length -= take;
        }
        Ok(())
    }

    fn replace_chunk<F>(
        &self,
        write_session_id: Uuid,
        operation_id: Uuid,
        chunk_number: u64,
        mutate: F,
    ) -> Result<(), StorageError>
    where
        F: FnOnce(&mut File) -> Result<(), StorageError>,
    {
        if chunk_number >= MAX_CHUNK_COUNT {
            return Err(StorageError::StateConflict);
        }
        let directory = self.cow_directory(write_session_id)?;
        verify_directory(&directory)?;
        let destination = directory.join(cow_chunk_name(chunk_number));
        let temporary = directory.join(format!(
            ".{}.{}.writing",
            cow_chunk_name(chunk_number),
            operation_id
        ));
        let mut file = match path_kind(&destination)? {
            super::PathKind::Present => {
                verify_regular_file(&destination)?;
                let mut source = File::open(&destination)?;
                let mut temporary_file = create_new_file(&temporary)?;
                std::io::copy(&mut source, &mut temporary_file)?;
                temporary_file
            }
            super::PathKind::Missing => create_new_file(&temporary)?,
        };
        mutate(&mut file)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &destination)?;
        sync_directory(&directory)?;
        Ok(())
    }

    fn cow_directory(&self, write_session_id: Uuid) -> Result<PathBuf, StorageError> {
        Ok(self
            .shard_directory("staging", write_session_id)?
            .join(format!("{write_session_id}.cow")))
    }
}

fn validate_chunk_size(chunk_size: u64) -> Result<(), StorageError> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) || !chunk_size.is_power_of_two() {
        return Err(StorageError::StateConflict);
    }
    Ok(())
}

fn cow_chunk_name(chunk_number: u64) -> String {
    format!("{chunk_number:08}.part")
}

fn parse_cow_chunk_name(name: &std::ffi::OsStr) -> Result<u64, StorageError> {
    let value = name.to_str().ok_or(StorageError::UnsafeObject)?;
    let digits = value
        .strip_suffix(".part")
        .filter(|digits| digits.len() == 8)
        .ok_or(StorageError::UnsafeObject)?;
    digits
        .parse::<u64>()
        .map_err(|_| StorageError::UnsafeObject)
}

fn parse_cow_entry_name(name: &std::ffi::OsStr) -> Result<u64, StorageError> {
    if let Ok(chunk_number) = parse_cow_chunk_name(name) {
        return Ok(chunk_number);
    }
    let value = name.to_str().ok_or(StorageError::UnsafeObject)?;
    let temporary = value
        .strip_prefix('.')
        .and_then(|value| value.strip_suffix(".writing"))
        .ok_or(StorageError::UnsafeObject)?;
    let (digits, operation_id) = temporary
        .split_once(".part.")
        .ok_or(StorageError::UnsafeObject)?;
    let chunk_number = parse_cow_chunk_name(std::ffi::OsStr::new(&format!("{digits}.part")))?;
    Uuid::parse_str(operation_id).map_err(|_| StorageError::UnsafeObject)?;
    Ok(chunk_number)
}

fn pad_file_to(file: &mut File, offset: u64) -> Result<(), StorageError> {
    let current = file.metadata()?.len();
    if current < offset {
        file.seek(SeekFrom::End(0))?;
        write_zeroes(file, offset - current)?;
    }
    Ok(())
}

fn write_zeroes(file: &mut File, mut length: u64) -> Result<(), StorageError> {
    while length > 0 {
        let take = length.min(ZERO_BUFFER.len() as u64);
        let take = usize::try_from(take).map_err(|_| StorageError::StateConflict)?;
        file.write_all(&ZERO_BUFFER[..take])?;
        length -= u64::try_from(take).map_err(|_| StorageError::StateConflict)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn dirty_hardlinks_are_copy_replaced_and_gaps_are_zero_filled() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, None, &[])
            .expect("begin COW write");
        let result = layout
            .write_cow_at(session, Uuid::new_v4(), 65_536, 0, 70_000, b"filebelt")
            .expect("write after gap");
        assert_eq!(result.logical_size, 70_008);
        assert_eq!(result.reservation_delta, 70_008);
        let manifest = layout
            .cow_manifest(session, 65_536, result.logical_size)
            .expect("manifest");
        assert_eq!(manifest.chunks.len(), 2);

        let directory = layout.cow_directory(session).expect("COW directory");
        let mut second = Vec::new();
        File::open(directory.join(cow_chunk_name(1)))
            .expect("second chunk")
            .read_to_end(&mut second)
            .expect("read second chunk");
        assert!(second[..4_464].iter().all(|byte| *byte == 0));
        assert_eq!(&second[4_464..], b"filebelt");
    }

    #[test]
    fn truncate_replaces_the_last_chunk_and_removes_later_chunks() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, None, &[])
            .expect("begin COW write");
        let original = vec![9_u8; 140_000];
        layout
            .write_cow_at(session, Uuid::new_v4(), 65_536, 0, 0, &original)
            .expect("initial write");
        layout
            .truncate_cow(session, Uuid::new_v4(), 65_536, 140_000, 70_000)
            .expect("truncate");
        let manifest = layout
            .cow_manifest(session, 65_536, 70_000)
            .expect("manifest");
        assert_eq!(manifest.chunks.len(), 2);
        assert_eq!(manifest.chunks[1].size, 4_464);
    }

    #[test]
    fn abort_removes_only_valid_chunks_and_crash_temporaries() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, None, &[])
            .expect("begin COW write");
        let directory = layout.cow_directory(session).expect("COW directory");
        let temporary =
            directory.join(format!(".{}.{}.writing", cow_chunk_name(0), Uuid::new_v4()));
        create_new_file(&temporary).expect("create crash temporary");

        layout.abort_cow(session).expect("abort COW write");
        assert!(matches!(
            path_kind(&directory).expect("inspect COW directory"),
            super::super::PathKind::Missing
        ));
    }
}

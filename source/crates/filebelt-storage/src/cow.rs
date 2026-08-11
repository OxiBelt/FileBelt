// SPDX-License-Identifier: Apache-2.0

//! Copy-on-write staging for mount writes.

use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use filebelt_database::PayloadRecord;
use rustix::fs::{
    FallocateFlags, FlockOperation, Mode, OFlags, SeekFrom as RustixSeekFrom, fallocate, flock,
    openat, seek,
};
use rustix::io::Errno;
use uuid::Uuid;

use super::{
    FinalizedObject, StorageError, StorageLayout, create_new_file, create_secure_directory, parent,
    path_kind, sync_directory, verify_directory, verify_file, verify_regular_file,
    verify_same_owner,
};

const MIN_CHUNK_SIZE: u64 = 64 * 1024;
const MAX_CHUNK_SIZE: u64 = 64 * 1024 * 1024;
const MAX_CHUNK_COUNT: u64 = 100_000_000;
const COW_LOCK_COORDINATOR: &str = ".cow-lock-coordinator";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CowBaseChunk {
    pub chunk_number: u64,
    pub size: u64,
    pub digest: [u8; 32],
}

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

#[derive(Debug)]
pub struct CowLockGuard {
    lock: Option<File>,
    lock_path: PathBuf,
    parent: PathBuf,
    remove_on_drop: bool,
}

impl CowLockGuard {
    /// Arms best-effort inode cleanup if an asynchronous acquisition is
    /// cancelled after the blocking flock has completed.
    pub fn arm_remove_on_drop(&mut self) {
        self.remove_on_drop = true;
    }

    /// Transfers the lock to code whose database lease determines whether
    /// terminal unlink is authorized.
    pub fn disarm_remove_on_drop(&mut self) {
        self.remove_on_drop = false;
    }

    fn remove_current_inode(&mut self) -> Result<(), StorageError> {
        let Some(lock) = self.lock.as_ref() else {
            return Ok(());
        };
        let parent_directory = File::open(&self.parent)?;
        let coordinator = open_cow_lock_file(&parent_directory, COW_LOCK_COORDINATOR)?;
        flock(&coordinator, FlockOperation::LockExclusive).map_err(storage_errno)?;
        let acquired = lock.metadata()?;
        let current = match fs::symlink_metadata(&self.lock_path) {
            Ok(current) => current,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                drop(self.lock.take());
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if !current.file_type().is_file()
            || current.permissions().mode() & 0o777 != 0o600
            || current.uid() != parent_directory.metadata()?.uid()
            || current.dev() != acquired.dev()
            || current.ino() != acquired.ino()
        {
            return Err(StorageError::UnsafeObject);
        }
        fs::remove_file(&self.lock_path)?;
        let sync_result = sync_directory(&self.parent);
        // Keep the old inode locked while the pathname removal becomes
        // durable and the shard coordinator excludes new openers.
        drop(self.lock.take());
        drop(coordinator);
        sync_result
    }
}

impl Drop for CowLockGuard {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = self.remove_current_inode();
        }
    }
}

impl StorageLayout {
    pub fn lock_cow(&self, write_session_id: Uuid) -> Result<CowLockGuard, StorageError> {
        self.prepare()?;
        let cow_parent = parent(&self.cow_directory(write_session_id)?)?.to_path_buf();
        let lock_name = format!(".{write_session_id}.cow.lock");
        let lock_path = cow_parent.join(&lock_name);
        loop {
            let parent_directory = File::open(&cow_parent)?;
            let coordinator = open_cow_lock_file(&parent_directory, COW_LOCK_COORDINATOR)?;
            flock(&coordinator, FlockOperation::LockExclusive).map_err(storage_errno)?;
            let lock = open_cow_lock_file(&parent_directory, &lock_name)?;
            drop(coordinator);

            flock(&lock, FlockOperation::LockExclusive).map_err(storage_errno)?;
            // A terminal cleanup may unlink a locked inode while an earlier
            // waiter still has it open. Recheck under the shard coordinator;
            // a stale waiter drops the old inode and retries the current path
            // instead of forming a split-lock domain.
            let coordinator = open_cow_lock_file(&parent_directory, COW_LOCK_COORDINATOR)?;
            flock(&coordinator, FlockOperation::LockExclusive).map_err(storage_errno)?;
            let current = fs::symlink_metadata(&lock_path);
            let acquired = lock.metadata()?;
            let parent_uid = parent_directory.metadata()?.uid();
            let current_matches = current.is_ok_and(|metadata| {
                metadata.file_type().is_file()
                    && metadata.permissions().mode() & 0o777 == 0o600
                    && metadata.uid() == parent_uid
                    && metadata.dev() == acquired.dev()
                    && metadata.ino() == acquired.ino()
            });
            drop(coordinator);
            if current_matches {
                return Ok(CowLockGuard {
                    lock: Some(lock),
                    lock_path,
                    parent: cow_parent,
                    remove_on_drop: false,
                });
            }
            drop(lock);
        }
    }

    /// Removes a terminal per-session lock without allowing old-inode waiters
    /// to overlap a newly created lock domain.
    pub fn remove_cow_lock(&self, mut guard: CowLockGuard) -> Result<(), StorageError> {
        guard.remove_current_inode()
    }

    pub fn with_cow_lock<T, F>(
        &self,
        write_session_id: Uuid,
        operation: F,
    ) -> Result<T, StorageError>
    where
        F: FnOnce() -> Result<T, StorageError>,
    {
        let _lock = self.lock_cow(write_session_id)?;
        operation()
    }

    pub async fn probe_sparse_files(&self) -> Result<(), StorageError> {
        let layout = self.clone();
        tokio::task::spawn_blocking(move || layout.probe_sparse_files_blocking())
            .await
            .map_err(|_| StorageError::Join)?
    }

    fn probe_sparse_files_blocking(&self) -> Result<(), StorageError> {
        let write_session_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        self.begin_cow_write(write_session_id, MIN_CHUNK_SIZE, None, &[])?;
        let result = (|| {
            self.write_cow_at(
                write_session_id,
                operation_id,
                MIN_CHUNK_SIZE,
                0,
                0,
                &vec![1; MIN_CHUNK_SIZE as usize],
            )?;
            if self.cow_next_data(write_session_id, MIN_CHUNK_SIZE, MIN_CHUNK_SIZE, 0)? != Some(0) {
                return Err(StorageError::UnsupportedFilesystem);
            }
            self.deallocate_cow_range(
                write_session_id,
                operation_id,
                MIN_CHUNK_SIZE,
                MIN_CHUNK_SIZE,
                0,
                MIN_CHUNK_SIZE,
            )?;
            if self
                .cow_next_data(write_session_id, MIN_CHUNK_SIZE, MIN_CHUNK_SIZE, 0)?
                .is_some()
                || self.cow_next_hole(write_session_id, MIN_CHUNK_SIZE, MIN_CHUNK_SIZE, 0)?
                    != Some(0)
            {
                return Err(StorageError::UnsupportedFilesystem);
            }
            self.allocate_cow_range(
                write_session_id,
                operation_id,
                MIN_CHUNK_SIZE,
                MIN_CHUNK_SIZE,
                0,
                MIN_CHUNK_SIZE,
            )?;
            if self.cow_chunk_allocated_bytes(write_session_id, 0)? == 0 {
                return Err(StorageError::UnsupportedFilesystem);
            }
            Ok(())
        })();
        let cleanup = self.abort_cow(write_session_id);
        result.and(cleanup)
    }

    pub fn begin_cow_write(
        &self,
        write_session_id: Uuid,
        chunk_size: u64,
        base_payload: Option<&PayloadRecord>,
        base_chunks: &[CowBaseChunk],
    ) -> Result<(), StorageError> {
        validate_chunk_size(chunk_size)?;
        self.prepare()?;
        let directory = self.cow_directory(write_session_id)?;
        self.recover_cow_under_lock(write_session_id)?;
        if !matches!(path_kind(&directory)?, super::PathKind::Missing) {
            return Err(StorageError::StateConflict);
        }
        let directory_parent = parent(&directory)?.to_path_buf();
        let temporary =
            directory_parent.join(format!(".{write_session_id}.cow.init.{}", Uuid::new_v4()));
        create_secure_directory(&temporary)?;
        verify_same_owner(&temporary, &directory_parent)?;
        let initialize = (|| {
            if let Some(payload) = base_payload {
                let source = self.payload_path(payload)?;
                let logical_size =
                    u64::try_from(payload.size_bytes).map_err(|_| StorageError::StateConflict)?;
                let digest: [u8; 32] = payload
                    .blake3
                    .as_deref()
                    .ok_or(StorageError::CorruptObject)?
                    .try_into()
                    .map_err(|_| StorageError::CorruptObject)?;
                match payload.layout.as_str() {
                    "whole" => {
                        verify_file(&source, logical_size, &digest)?;
                        split_whole_payload(&source, &temporary, chunk_size)?;
                    }
                    "chunked" => {
                        verify_directory(&source)?;
                        validate_base_chunks(base_chunks, chunk_size, logical_size)?;
                        for chunk in base_chunks {
                            let source_part = source.join(cow_chunk_name(chunk.chunk_number));
                            verify_file(&source_part, chunk.size, &chunk.digest)?;
                            fs::hard_link(
                                source_part,
                                temporary.join(cow_chunk_name(chunk.chunk_number)),
                            )?;
                        }
                    }
                    _ => return Err(StorageError::StateConflict),
                }
                sync_cow_files(&temporary)?;
                let manifest = self.cow_manifest_in(&temporary, chunk_size, logical_size)?;
                if manifest.logical_size != logical_size || manifest.digest != digest {
                    return Err(StorageError::CorruptObject);
                }
            } else if !base_chunks.is_empty() {
                return Err(StorageError::StateConflict);
            }
            Ok(())
        })();
        if let Err(error) = initialize {
            return match remove_cow_directory(&temporary) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup),
            };
        }
        sync_directory(&temporary)?;
        if let Err(error) = fs::rename(&temporary, &directory) {
            return match remove_cow_directory(&temporary) {
                Ok(()) => Err(error.into()),
                Err(cleanup) => Err(cleanup),
            };
        }
        sync_directory(&directory_parent)?;
        Ok(())
    }

    /// Removes only closed-shape initialization and chunk temporaries left by
    /// a crashed process. Callers must hold the per-session COW lock.
    pub fn recover_cow_under_lock(&self, write_session_id: Uuid) -> Result<(), StorageError> {
        self.prepare()?;
        let directory = self.cow_directory(write_session_id)?;
        let directory_parent = parent(&directory)?.to_path_buf();
        let initialization_prefix = format!(".{write_session_id}.cow.init.");
        let mut parent_changed = false;
        for entry in fs::read_dir(&directory_parent)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| StorageError::UnsafeObject)?;
            let Some(suffix) = name.strip_prefix(&initialization_prefix) else {
                continue;
            };
            let id = Uuid::parse_str(suffix).map_err(|_| StorageError::UnsafeObject)?;
            if id.to_string() != suffix {
                return Err(StorageError::UnsafeObject);
            }
            remove_interrupted_cow_directory(&entry.path())?;
            parent_changed = true;
        }
        if parent_changed {
            sync_directory(&directory_parent)?;
        }
        if matches!(path_kind(&directory)?, super::PathKind::Missing) {
            return Ok(());
        }
        verify_directory(&directory)?;
        let mut directory_changed = false;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if parse_cow_chunk_name(&entry.file_name()).is_ok() {
                verify_regular_file(&entry.path())?;
                continue;
            }
            parse_cow_writing_name(&entry.file_name())?;
            verify_interrupted_cow_file(&entry.path())?;
            fs::remove_file(entry.path())?;
            directory_changed = true;
        }
        if directory_changed {
            sync_directory(&directory)?;
        }
        // Also closes the rename-before-parent-fsync crash window for an
        // already visible final COW directory.
        sync_directory(&directory_parent)
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
            self.extend_cow_with_holes(
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
            self.extend_cow_with_holes(
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

    pub fn allocate_cow_range(
        &self,
        write_session_id: Uuid,
        operation_id: Uuid,
        chunk_size: u64,
        current_logical_size: u64,
        offset: u64,
        length: u64,
    ) -> Result<CowWriteResult, StorageError> {
        validate_chunk_size(chunk_size)?;
        let end = checked_nonempty_range_end(offset, length)?;
        if offset > current_logical_size {
            self.extend_cow_with_holes(
                write_session_id,
                operation_id,
                chunk_size,
                current_logical_size,
                offset - current_logical_size,
            )?;
        }
        self.for_each_cow_range(
            write_session_id,
            operation_id,
            chunk_size,
            offset,
            length,
            |file, within, take| {
                pad_file_to(
                    file,
                    within
                        .checked_add(take)
                        .ok_or(StorageError::StateConflict)?,
                )?;
                fallocate(file, FallocateFlags::empty(), within, take).map_err(storage_errno)?;
                Ok(())
            },
        )?;
        let logical_size = current_logical_size.max(end);
        Ok(CowWriteResult {
            logical_size,
            reservation_delta: logical_size.saturating_sub(current_logical_size),
        })
    }

    pub fn deallocate_cow_range(
        &self,
        write_session_id: Uuid,
        operation_id: Uuid,
        chunk_size: u64,
        current_logical_size: u64,
        offset: u64,
        length: u64,
    ) -> Result<CowWriteResult, StorageError> {
        validate_chunk_size(chunk_size)?;
        let requested_end = checked_nonempty_range_end(offset, length)?;
        let end = requested_end.min(current_logical_size);
        if offset < end {
            self.for_each_cow_range(
                write_session_id,
                operation_id,
                chunk_size,
                offset,
                end - offset,
                |file, within, take| {
                    fallocate(
                        file,
                        FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE,
                        within,
                        take,
                    )
                    .map_err(storage_errno)?;
                    Ok(())
                },
            )?;
        }
        Ok(CowWriteResult {
            logical_size: current_logical_size,
            reservation_delta: 0,
        })
    }

    pub fn cow_next_data(
        &self,
        write_session_id: Uuid,
        chunk_size: u64,
        logical_size: u64,
        offset: u64,
    ) -> Result<Option<u64>, StorageError> {
        self.cow_next_sparse_offset(
            write_session_id,
            chunk_size,
            logical_size,
            offset,
            SparseSeek::Data,
        )
    }

    pub fn cow_next_hole(
        &self,
        write_session_id: Uuid,
        chunk_size: u64,
        logical_size: u64,
        offset: u64,
    ) -> Result<Option<u64>, StorageError> {
        self.cow_next_sparse_offset(
            write_session_id,
            chunk_size,
            logical_size,
            offset,
            SparseSeek::Hole,
        )
    }

    pub fn sync_cow(&self, write_session_id: Uuid) -> Result<(), StorageError> {
        let directory = self.cow_directory(write_session_id)?;
        verify_directory(&directory)?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            parse_cow_chunk_name(&entry.file_name())?;
            verify_regular_file(&entry.path())?;
            File::open(entry.path())?.sync_all()?;
        }
        sync_directory(&directory)
    }

    pub fn cow_logical_size(
        &self,
        write_session_id: Uuid,
        chunk_size: u64,
    ) -> Result<u64, StorageError> {
        validate_chunk_size(chunk_size)?;
        let directory = self.cow_directory(write_session_id)?;
        verify_directory(&directory)?;
        let mut chunks = fs::read_dir(&directory)?
            .map(|entry| {
                let entry = entry?;
                let chunk_number = parse_cow_chunk_name(&entry.file_name())?;
                verify_regular_file(&entry.path())?;
                Ok((chunk_number, entry.metadata()?.len()))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        chunks.sort_unstable_by_key(|(chunk_number, _)| *chunk_number);
        let mut logical_size = 0_u64;
        for (index, (chunk_number, size)) in chunks.iter().copied().enumerate() {
            if chunk_number != u64::try_from(index).map_err(|_| StorageError::StateConflict)?
                || size == 0
                || size > chunk_size
                || (index + 1 < chunks.len() && size != chunk_size)
            {
                return Err(StorageError::CorruptObject);
            }
            logical_size = logical_size
                .checked_add(size)
                .ok_or(StorageError::StateConflict)?;
        }
        Ok(logical_size)
    }

    fn cow_chunk_allocated_bytes(
        &self,
        write_session_id: Uuid,
        chunk_number: u64,
    ) -> Result<u64, StorageError> {
        let path = self
            .cow_directory(write_session_id)?
            .join(cow_chunk_name(chunk_number));
        verify_regular_file(&path)?;
        fs::metadata(path)?
            .blocks()
            .checked_mul(512)
            .ok_or(StorageError::StateConflict)
    }

    pub fn cow_manifest(
        &self,
        write_session_id: Uuid,
        chunk_size: u64,
        logical_size: u64,
    ) -> Result<CowManifest, StorageError> {
        validate_chunk_size(chunk_size)?;
        let directory = self.cow_directory(write_session_id)?;
        self.cow_manifest_in(&directory, chunk_size, logical_size)
    }

    pub fn cow_staging_manifest(
        &self,
        write_session_id: Uuid,
        payload: &PayloadRecord,
        chunk_size: u64,
        logical_size: u64,
    ) -> Result<CowManifest, StorageError> {
        let source = self.cow_directory(write_session_id)?;
        let destination = self.payload_path(payload)?;
        match (path_kind(&source)?, path_kind(&destination)?) {
            (super::PathKind::Present, super::PathKind::Missing) => {
                self.cow_manifest_in(&source, chunk_size, logical_size)
            }
            (super::PathKind::Missing, super::PathKind::Present) => {
                self.cow_manifest_in(&destination, chunk_size, logical_size)
            }
            _ => Err(StorageError::StateConflict),
        }
    }

    fn cow_manifest_in(
        &self,
        directory: &std::path::Path,
        chunk_size: u64,
        logical_size: u64,
    ) -> Result<CowManifest, StorageError> {
        validate_chunk_size(chunk_size)?;
        verify_directory(directory)?;
        let chunk_count = logical_size.div_ceil(chunk_size);
        if chunk_count > MAX_CHUNK_COUNT {
            return Err(StorageError::StateConflict);
        }
        let actual_count = fs::read_dir(directory)?.count();
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
        expected: &CowManifest,
    ) -> Result<FinalizedObject, StorageError> {
        if payload.layout != "chunked" {
            return Err(StorageError::StateConflict);
        }
        let source = self.cow_directory(write_session_id)?;
        let destination = self.payload_path(payload)?;
        let manifest = match (path_kind(&source)?, path_kind(&destination)?) {
            (super::PathKind::Present, super::PathKind::Missing) => {
                let manifest = self.cow_manifest_in(&source, chunk_size, expected.logical_size)?;
                validate_cow_payload_evidence(payload, expected, &manifest)?;
                fs::rename(&source, &destination)?;
                sync_rename_parents(&source, &destination)?;
                manifest
            }
            (super::PathKind::Missing, super::PathKind::Present) => {
                let manifest =
                    self.cow_manifest_in(&destination, chunk_size, expected.logical_size)?;
                validate_cow_payload_evidence(payload, expected, &manifest)?;
                // A crash after rename but before either parent fsync leaves
                // this recovery shape. Retrying closes that durability gap.
                sync_rename_parents(&source, &destination)?;
                manifest
            }
            _ => return Err(StorageError::StateConflict),
        };
        Ok(FinalizedObject {
            digest: manifest.digest,
            size: manifest.logical_size,
        })
    }

    pub fn abort_cow(&self, write_session_id: Uuid) -> Result<(), StorageError> {
        self.recover_cow_under_lock(write_session_id)?;
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

    /// Idempotently removes both possible crash shapes of mount staging: the
    /// unpublished mutable COW source and the published payload destination.
    /// Callers must hold the per-session COW lock.
    pub fn delete_cow_staging(
        &self,
        write_session_id: Uuid,
        payload: &PayloadRecord,
    ) -> Result<(), StorageError> {
        self.abort_cow(write_session_id)?;
        self.delete_payload(payload)
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

    fn extend_cow_with_holes(
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
                pad_file_to(
                    file,
                    within
                        .checked_add(take)
                        .ok_or(StorageError::StateConflict)?,
                )?;
                Ok(())
            })?;
            offset = offset
                .checked_add(take)
                .ok_or(StorageError::StateConflict)?;
            length -= take;
        }
        Ok(())
    }

    fn for_each_cow_range<F>(
        &self,
        write_session_id: Uuid,
        operation_id: Uuid,
        chunk_size: u64,
        mut offset: u64,
        mut length: u64,
        mut operation: F,
    ) -> Result<(), StorageError>
    where
        F: FnMut(&mut File, u64, u64) -> Result<(), StorageError>,
    {
        while length > 0 {
            let chunk_number = offset / chunk_size;
            let within = offset % chunk_size;
            let take = length.min(chunk_size - within);
            self.replace_chunk(write_session_id, operation_id, chunk_number, |file| {
                operation(file, within, take)
            })?;
            offset = offset
                .checked_add(take)
                .ok_or(StorageError::StateConflict)?;
            length -= take;
        }
        Ok(())
    }

    fn cow_next_sparse_offset(
        &self,
        write_session_id: Uuid,
        chunk_size: u64,
        logical_size: u64,
        offset: u64,
        kind: SparseSeek,
    ) -> Result<Option<u64>, StorageError> {
        validate_chunk_size(chunk_size)?;
        if offset >= logical_size {
            return Ok((kind == SparseSeek::Hole && offset == logical_size).then_some(offset));
        }
        let directory = self.cow_directory(write_session_id)?;
        verify_directory(&directory)?;
        let mut chunk_number = offset / chunk_size;
        let mut within = offset % chunk_size;
        let chunk_count = logical_size.div_ceil(chunk_size);
        while chunk_number < chunk_count {
            let chunk_logical_size = if chunk_number + 1 == chunk_count {
                logical_size - chunk_number * chunk_size
            } else {
                chunk_size
            };
            let path = directory.join(cow_chunk_name(chunk_number));
            verify_regular_file(&path)?;
            let file = File::open(path)?;
            let result = match kind {
                SparseSeek::Data => seek(&file, RustixSeekFrom::Data(within)),
                SparseSeek::Hole => seek(&file, RustixSeekFrom::Hole(within)),
            };
            match result {
                Ok(found) if found < chunk_logical_size => {
                    return chunk_number
                        .checked_mul(chunk_size)
                        .and_then(|base| base.checked_add(found))
                        .map(Some)
                        .ok_or(StorageError::StateConflict);
                }
                Ok(_) | Err(Errno::NXIO) => {}
                Err(error) => return Err(storage_errno(error)),
            }
            chunk_number += 1;
            within = 0;
        }
        Ok((kind == SparseSeek::Hole).then_some(logical_size))
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
                let source = File::open(&destination)?;
                let mut temporary_file = create_new_file(&temporary)?;
                copy_sparse_file(&source, &mut temporary_file)?;
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

fn open_cow_lock_file(parent: &File, name: &str) -> Result<File, StorageError> {
    let lock = File::from(
        openat(
            parent,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(storage_errno)?,
    );
    let metadata = lock.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != parent.metadata()?.uid()
    {
        return Err(StorageError::UnsafeObject);
    }
    Ok(lock)
}

fn sync_cow_files(directory: &Path) -> Result<(), StorageError> {
    verify_directory(directory)?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        parse_cow_chunk_name(&entry.file_name())?;
        verify_regular_file(&entry.path())?;
        File::open(entry.path())?.sync_all()?;
    }
    Ok(())
}

fn remove_cow_directory(directory: &Path) -> Result<(), StorageError> {
    match path_kind(directory)? {
        super::PathKind::Missing => return Ok(()),
        super::PathKind::Present => verify_directory(directory)?,
    }
    verify_same_owner(directory, parent(directory)?)?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        parse_cow_chunk_name(&entry.file_name())?;
        verify_regular_file(&entry.path())?;
        fs::remove_file(entry.path())?;
    }
    fs::remove_dir(directory)?;
    sync_directory(parent(directory)?)
}

/// Removes a canonical, owner-only initialization crash shape. Creation asks
/// for 0700/0600 atomically, so the only accepted anomalies are permissions a
/// restrictive umask removed before the exact-mode repair. Broader modes,
/// symlinks, foreign owners, nested objects, and non-chunk names remain fatal.
fn remove_interrupted_cow_directory(directory: &Path) -> Result<(), StorageError> {
    match path_kind(directory)? {
        super::PathKind::Missing => return Ok(()),
        super::PathKind::Present => verify_interrupted_cow_directory(directory)?,
    }
    // Restore read/search permission only after the exact UUID name, type,
    // ownership, and non-broad mode checks selected this private artifact.
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        parse_cow_chunk_name(&entry.file_name())?;
        verify_interrupted_cow_file(&entry.path())?;
        fs::remove_file(entry.path())?;
    }
    fs::remove_dir(directory)?;
    sync_directory(parent(directory)?)
}

fn verify_interrupted_cow_directory(directory: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(directory)?;
    let mode = metadata.permissions().mode();
    if !metadata.file_type().is_dir()
        || mode & 0o7077 != 0
        || metadata.uid() != fs::symlink_metadata(parent(directory)?)?.uid()
    {
        return Err(StorageError::UnsafeObject);
    }
    Ok(())
}

fn verify_interrupted_cow_file(path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode();
    if !metadata.file_type().is_file()
        || mode & 0o7177 != 0
        || metadata.uid() != fs::symlink_metadata(parent(path)?)?.uid()
    {
        return Err(StorageError::UnsafeObject);
    }
    Ok(())
}

fn validate_chunk_size(chunk_size: u64) -> Result<(), StorageError> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) || !chunk_size.is_power_of_two() {
        return Err(StorageError::StateConflict);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SparseSeek {
    Data,
    Hole,
}

fn checked_nonempty_range_end(offset: u64, length: u64) -> Result<u64, StorageError> {
    if length == 0 {
        return Err(StorageError::StateConflict);
    }
    offset
        .checked_add(length)
        .ok_or(StorageError::StateConflict)
}

fn validate_base_chunks(
    chunks: &[CowBaseChunk],
    chunk_size: u64,
    logical_size: u64,
) -> Result<(), StorageError> {
    let expected_count = logical_size.div_ceil(chunk_size);
    if u64::try_from(chunks.len()).map_err(|_| StorageError::StateConflict)? != expected_count {
        return Err(StorageError::StateConflict);
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let chunk_number = u64::try_from(index).map_err(|_| StorageError::StateConflict)?;
        let expected_size = if chunk_number + 1 == expected_count {
            logical_size - chunk_number * chunk_size
        } else {
            chunk_size
        };
        if chunk.chunk_number != chunk_number || chunk.size != expected_size {
            return Err(StorageError::StateConflict);
        }
    }
    Ok(())
}

fn validate_cow_payload_evidence(
    payload: &PayloadRecord,
    expected: &CowManifest,
    manifest: &CowManifest,
) -> Result<(), StorageError> {
    // Mount staging rows do not gain their persisted digest and final size
    // until the following PostgreSQL transition. `expected` is therefore a
    // mandatory, caller-supplied manifest: absent provisional row evidence is
    // accepted only when the independently recomputed manifest matches it
    // exactly. Any evidence already present on the row must also agree.
    if manifest != expected
        || payload
            .blake3
            .as_deref()
            .is_some_and(|digest| digest != manifest.digest.as_slice())
        || match u64::try_from(payload.size_bytes) {
            Ok(0) => false,
            Ok(size) => size != expected.logical_size,
            Err(_) => true,
        }
    {
        return Err(StorageError::CorruptObject);
    }
    Ok(())
}

fn split_whole_payload(
    source: &std::path::Path,
    destination: &std::path::Path,
    chunk_size: u64,
) -> Result<(), StorageError> {
    let size = fs::metadata(source)?.len();
    if size == 0 {
        return Ok(());
    }
    if size <= chunk_size {
        fs::hard_link(source, destination.join(cow_chunk_name(0)))?;
        return Ok(());
    }
    let mut source = File::open(source)?;
    let mut chunk_number = 0_u64;
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    let mut created = Vec::new();
    let result = (|| {
        while remaining > 0 {
            let path = destination.join(cow_chunk_name(chunk_number));
            let mut chunk = create_new_file(&path)?;
            created.push(path);
            let mut chunk_remaining = remaining.min(chunk_size);
            while chunk_remaining > 0 {
                let take = usize::try_from(chunk_remaining.min(buffer.len() as u64))
                    .map_err(|_| StorageError::StateConflict)?;
                source.read_exact(&mut buffer[..take])?;
                chunk.write_all(&buffer[..take])?;
                chunk_remaining -= u64::try_from(take).map_err(|_| StorageError::StateConflict)?;
                remaining -= u64::try_from(take).map_err(|_| StorageError::StateConflict)?;
            }
            chunk.sync_all()?;
            chunk_number = chunk_number
                .checked_add(1)
                .ok_or(StorageError::StateConflict)?;
        }
        Ok(())
    })();
    if result.is_err() {
        for path in created.into_iter().rev() {
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        sync_directory(destination)?;
    }
    result
}

fn sync_rename_parents(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), StorageError> {
    let source_parent = parent(source)?;
    let destination_parent = parent(destination)?;
    sync_directory(source_parent)?;
    if source_parent != destination_parent {
        sync_directory(destination_parent)?;
    }
    Ok(())
}

fn copy_sparse_file(source: &File, destination: &mut File) -> Result<(), StorageError> {
    let size = source.metadata()?.len();
    destination.set_len(size)?;
    let mut cursor = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while cursor < size {
        let data = match seek(source, RustixSeekFrom::Data(cursor)) {
            Ok(data) if data < size => data,
            Ok(_) | Err(Errno::NXIO) => break,
            Err(error) => return Err(storage_errno(error)),
        };
        let hole = seek(source, RustixSeekFrom::Hole(data))
            .map_err(storage_errno)?
            .min(size);
        if hole <= data {
            return Err(StorageError::UnsupportedFilesystem);
        }
        let mut remaining = hole.checked_sub(data).ok_or(StorageError::CorruptObject)?;
        let mut source = source;
        source.seek(SeekFrom::Start(data))?;
        destination.seek(SeekFrom::Start(data))?;
        while remaining > 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| StorageError::StateConflict)?;
            source.read_exact(&mut buffer[..take])?;
            destination.write_all(&buffer[..take])?;
            remaining -= u64::try_from(take).map_err(|_| StorageError::StateConflict)?;
        }
        cursor = hole;
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
    parse_cow_writing_name(name)
}

fn parse_cow_writing_name(name: &std::ffi::OsStr) -> Result<u64, StorageError> {
    let value = name.to_str().ok_or(StorageError::UnsafeObject)?;
    let temporary = value
        .strip_prefix('.')
        .and_then(|value| value.strip_suffix(".writing"))
        .ok_or(StorageError::UnsafeObject)?;
    let (digits, operation_id) = temporary
        .split_once(".part.")
        .ok_or(StorageError::UnsafeObject)?;
    let chunk_number = parse_cow_chunk_name(std::ffi::OsStr::new(&format!("{digits}.part")))?;
    let parsed_operation_id =
        Uuid::parse_str(operation_id).map_err(|_| StorageError::UnsafeObject)?;
    if parsed_operation_id.to_string() != operation_id {
        return Err(StorageError::UnsafeObject);
    }
    Ok(chunk_number)
}

fn pad_file_to(file: &mut File, offset: u64) -> Result<(), StorageError> {
    let current = file.metadata()?.len();
    if current < offset {
        file.set_len(offset)?;
    }
    Ok(())
}

fn storage_errno(error: Errno) -> StorageError {
    if matches!(error, Errno::INVAL | Errno::NOTSUP) {
        StorageError::UnsupportedFilesystem
    } else {
        StorageError::Io(error.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn whole_payload(layout: &StorageLayout, bytes: &[u8]) -> PayloadRecord {
        let payload = PayloadRecord {
            tenant_id: Uuid::new_v4(),
            payload_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            locator: Uuid::new_v4(),
            layout: "whole".into(),
            state: "referenced".into(),
            size_bytes: i64::try_from(bytes.len()).expect("small test payload"),
            blake3: Some(blake3::hash(bytes).as_bytes().to_vec()),
        };
        let path = layout.payload_path(&payload).expect("whole payload path");
        let mut file = create_new_file(&path).expect("whole payload file");
        file.write_all(bytes).expect("whole payload bytes");
        file.sync_all().expect("durable whole payload");
        sync_directory(parent(&path).expect("whole payload parent"))
            .expect("durable whole payload directory");
        payload
    }

    fn staging_payload(layout: &StorageLayout, size: u64, digest: [u8; 32]) -> PayloadRecord {
        let payload = PayloadRecord {
            tenant_id: Uuid::new_v4(),
            payload_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            locator: Uuid::new_v4(),
            layout: "chunked".into(),
            state: "staging".into(),
            size_bytes: i64::try_from(size).expect("small test payload"),
            blake3: Some(digest.to_vec()),
        };
        assert!(
            matches!(
                path_kind(&layout.payload_path(&payload).expect("payload path")),
                Ok(super::super::PathKind::Missing)
            ),
            "staging payload must begin absent"
        );
        payload
    }

    #[test]
    fn dirty_hardlinks_are_copy_replaced_and_gaps_are_zero_filled() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, 65_536, None, &[])
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
            .begin_cow_write(session, 65_536, None, &[])
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
            .begin_cow_write(session, 65_536, None, &[])
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

    #[test]
    fn whole_payload_larger_than_chunk_size_is_split_exactly() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let bytes = (0..(65_536 * 2 + 17))
            .map(|index| u8::try_from(index % 251).expect("bounded byte"))
            .collect::<Vec<_>>();
        let base = whole_payload(&layout, &bytes);
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, 65_536, Some(&base), &[])
            .expect("begin COW from whole payload");

        let manifest = layout
            .cow_manifest(session, 65_536, bytes.len() as u64)
            .expect("split manifest");
        assert_eq!(
            manifest
                .chunks
                .iter()
                .map(|chunk| chunk.size)
                .collect::<Vec<_>>(),
            vec![65_536, 65_536, 17]
        );
        assert_eq!(manifest.digest, *blake3::hash(&bytes).as_bytes());
    }

    #[test]
    fn failed_multi_chunk_split_removes_every_created_chunk() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let bytes = vec![3_u8; 65_536 * 2 + 1];
        let base = whole_payload(&layout, &bytes);
        let source = layout.payload_path(&base).expect("base path");
        let destination = root.path().join("split");
        create_secure_directory(&destination).expect("split directory");
        let collision = destination.join(cow_chunk_name(1));
        create_new_file(&collision).expect("deterministic second-chunk collision");

        assert!(split_whole_payload(&source, &destination, 65_536).is_err());
        assert!(!destination.join(cow_chunk_name(0)).exists());
        assert!(collision.exists());
        fs::remove_file(collision).expect("remove collision");
        split_whole_payload(&source, &destination, 65_536).expect("retry split");
        assert!(destination.join(cow_chunk_name(0)).exists());
        assert!(destination.join(cow_chunk_name(1)).exists());
        assert!(destination.join(cow_chunk_name(2)).exists());
    }

    #[test]
    fn recovery_removes_only_well_formed_initialization_and_chunk_temporaries() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        let directory = layout.cow_directory(session).expect("COW directory");
        let parent = parent(&directory).expect("COW parent");
        let initialization = parent.join(format!(".{session}.cow.init.{}", Uuid::new_v4()));
        create_secure_directory(&initialization).expect("crashed initialization directory");
        let initialization_chunk = initialization.join(cow_chunk_name(0));
        create_new_file(&initialization_chunk).expect("partial initialization chunk");
        fs::set_permissions(&initialization_chunk, fs::Permissions::from_mode(0o400))
            .expect("simulate crash before file mode repair");
        fs::set_permissions(&initialization, fs::Permissions::from_mode(0o500))
            .expect("simulate crash before directory mode repair");

        layout
            .recover_cow_under_lock(session)
            .expect("recover initialization crash");
        assert!(!initialization.exists());

        layout
            .begin_cow_write(session, 65_536, None, &[])
            .expect("begin COW after recovery");
        let writing = directory.join(format!(".{}.{}.writing", cow_chunk_name(0), Uuid::new_v4()));
        create_new_file(&writing).expect("crashed chunk temporary");
        fs::set_permissions(&writing, fs::Permissions::from_mode(0o400))
            .expect("simulate crash before temporary mode repair");
        layout
            .recover_cow_under_lock(session)
            .expect("recover chunk crash");
        assert!(!writing.exists());

        let broad = directory.join(format!(".{}.{}.writing", cow_chunk_name(0), Uuid::new_v4()));
        create_new_file(&broad).expect("canonical broad-mode temporary");
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o644))
            .expect("simulate an unsafe broadened mode");
        assert!(matches!(
            layout.recover_cow_under_lock(session),
            Err(StorageError::UnsafeObject)
        ));
        assert!(broad.exists(), "broader crash shapes are never removed");
        fs::remove_file(broad).expect("remove rejected broad temporary");

        let noncanonical = directory.join(format!(
            ".{}.{}.writing",
            cow_chunk_name(0),
            "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
        ));
        create_new_file(&noncanonical).expect("noncanonical chunk temporary");
        assert!(matches!(
            layout.recover_cow_under_lock(session),
            Err(StorageError::UnsafeObject)
        ));
        assert!(noncanonical.exists(), "unsafe shapes are never removed");
        fs::remove_file(noncanonical).expect("remove rejected temporary");

        let malformed = parent.join(format!(".{session}.cow.init.not-a-uuid"));
        create_secure_directory(&malformed).expect("malformed initialization directory");
        assert!(matches!(
            layout.recover_cow_under_lock(session),
            Err(StorageError::UnsafeObject)
        ));
        assert!(malformed.exists(), "unsafe shapes are never removed");
    }

    #[test]
    fn maintenance_deletion_recovers_secure_mode_anomalous_temporaries() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, 65_536, None, &[])
            .expect("begin COW");
        let directory = layout.cow_directory(session).expect("COW directory");
        let writing = directory.join(format!(".{}.{}.writing", cow_chunk_name(0), Uuid::new_v4()));
        create_new_file(&writing).expect("crashed maintenance temporary");
        fs::set_permissions(&writing, fs::Permissions::from_mode(0o200))
            .expect("simulate killed writer before mode repair");
        let payload = PayloadRecord {
            tenant_id: Uuid::new_v4(),
            payload_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            locator: Uuid::new_v4(),
            layout: "chunked".into(),
            state: "abandoned".into(),
            size_bytes: 0,
            blake3: None,
        };

        layout
            .delete_cow_staging(session, &payload)
            .expect("maintenance cleanup accepts only the secure crash subset");
        assert!(!directory.exists());
        assert!(!layout.payload_path(&payload).unwrap().exists());
    }

    #[test]
    fn chunked_base_manifest_is_validated_before_atomic_initialization_publish() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let bytes = vec![0x5a; 65_536];
        let chunk_digest = *blake3::hash(&bytes).as_bytes();
        let payload = PayloadRecord {
            tenant_id: Uuid::new_v4(),
            payload_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            locator: Uuid::new_v4(),
            layout: "chunked".into(),
            state: "referenced".into(),
            size_bytes: 65_536,
            blake3: Some(vec![0x11; 32]),
        };
        let payload_path = layout.payload_path(&payload).expect("payload path");
        create_secure_directory(&payload_path).expect("chunked payload directory");
        let mut chunk =
            create_new_file(&payload_path.join(cow_chunk_name(0))).expect("chunked payload part");
        chunk.write_all(&bytes).expect("chunk bytes");
        chunk.sync_all().expect("sync chunk bytes");
        sync_directory(&payload_path).expect("sync chunk directory");
        let session = Uuid::new_v4();

        assert!(matches!(
            layout.begin_cow_write(
                session,
                65_536,
                Some(&payload),
                &[CowBaseChunk {
                    chunk_number: 0,
                    size: 65_536,
                    digest: chunk_digest,
                }],
            ),
            Err(StorageError::CorruptObject)
        ));
        assert!(!layout.cow_directory(session).unwrap().exists());
        let prefix = format!(".{session}.cow.init.");
        assert!(
            fs::read_dir(parent(&layout.cow_directory(session).unwrap()).unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&prefix)),
            "failed initialization leaves no retry-blocking temporary"
        );
    }

    #[test]
    fn sparse_allocate_deallocate_and_copy_preserve_holes() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        let operation = Uuid::new_v4();
        layout
            .begin_cow_write(session, 65_536, None, &[])
            .expect("begin sparse COW");
        layout
            .write_cow_at(session, operation, 65_536, 0, 0, &vec![1; 65_536])
            .expect("write data chunk");
        layout
            .deallocate_cow_range(session, operation, 65_536, 65_536, 16_384, 16_384)
            .expect("punch middle hole");
        assert_eq!(
            layout
                .cow_next_hole(session, 65_536, 65_536, 0)
                .expect("seek hole"),
            Some(16_384)
        );
        assert_eq!(
            layout
                .cow_next_data(session, 65_536, 65_536, 16_384)
                .expect("seek data after hole"),
            Some(32_768)
        );

        layout
            .write_cow_at(session, Uuid::new_v4(), 65_536, 65_536, 40_000, b"x")
            .expect("copy-replace after hole");
        assert_eq!(
            layout
                .cow_next_hole(session, 65_536, 65_536, 0)
                .expect("hole survives copy replacement"),
            Some(16_384)
        );
        layout
            .allocate_cow_range(session, Uuid::new_v4(), 65_536, 65_536, 16_384, 16_384)
            .expect("reallocate hole");
        assert!(
            layout
                .cow_chunk_allocated_bytes(session, 0)
                .expect("allocated chunk blocks")
                > 0
        );
    }

    #[test]
    fn sparse_ranges_reject_zero_length_and_overflow() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, 65_536, None, &[])
            .expect("begin COW");
        assert!(matches!(
            layout.allocate_cow_range(session, Uuid::new_v4(), 65_536, 0, 0, 0),
            Err(StorageError::StateConflict)
        ));
        assert!(matches!(
            layout.deallocate_cow_range(session, Uuid::new_v4(), 65_536, 0, u64::MAX, 2),
            Err(StorageError::StateConflict)
        ));
    }

    #[test]
    fn cow_lock_preserves_concurrent_disjoint_writes_in_one_chunk() {
        let root = TempDir::new().expect("temporary root");
        let layout = std::sync::Arc::new(StorageLayout::new(root.path().join("payload")));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, 65_536, None, &[])
            .expect("begin COW");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let threads = [(0_u64, b"left".as_slice()), (8_192, b"right".as_slice())]
            .into_iter()
            .map(|(offset, bytes)| {
                let layout = layout.clone();
                let barrier = barrier.clone();
                let bytes = bytes.to_vec();
                std::thread::spawn(move || {
                    barrier.wait();
                    layout
                        .with_cow_lock(session, || {
                            let current = layout.cow_logical_size(session, 65_536)?;
                            layout.write_cow_at(
                                session,
                                Uuid::new_v4(),
                                65_536,
                                current,
                                offset,
                                &bytes,
                            )?;
                            Ok(())
                        })
                        .expect("serialized write");
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for thread in threads {
            thread.join().expect("writer thread");
        }
        let directory = layout.cow_directory(session).expect("COW directory");
        let mut bytes = Vec::new();
        File::open(directory.join(cow_chunk_name(0)))
            .expect("COW chunk")
            .read_to_end(&mut bytes)
            .expect("COW bytes");
        assert_eq!(&bytes[..4], b"left");
        assert_eq!(&bytes[8_192..8_197], b"right");
    }

    #[test]
    fn cow_lock_isolated_per_session_even_within_one_storage_shard() {
        let root = TempDir::new().expect("temporary root");
        let layout = std::sync::Arc::new(StorageLayout::new(root.path().join("payload")));
        layout.prepare().expect("prepare storage");
        let first_session =
            Uuid::parse_str("aaaa0000-0000-4000-8000-000000000001").expect("first UUID");
        let second_session =
            Uuid::parse_str("aaaa0000-0000-4000-8000-000000000002").expect("second UUID");
        let first_lock = layout.lock_cow(first_session).expect("first session lock");
        let (acquired, receiver) = std::sync::mpsc::sync_channel(0);
        let second_layout = layout.clone();
        let second = std::thread::spawn(move || {
            let _second_lock = second_layout
                .lock_cow(second_session)
                .expect("second session lock");
            acquired.send(()).expect("signal distinct lock");
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("a distinct session must not share the shard lock");
        drop(first_lock);
        second.join().expect("second lock thread");
    }

    #[test]
    fn terminal_lock_removal_makes_old_inode_waiters_retry_the_new_domain() {
        let root = TempDir::new().expect("temporary root");
        let layout = std::sync::Arc::new(StorageLayout::new(root.path().join("payload")));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        let first = layout.lock_cow(session).expect("first lock");
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(0);
        let waiter_layout = layout.clone();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).expect("signal waiter start");
            let lock = waiter_layout
                .lock_cow(session)
                .expect("retry current inode");
            acquired_tx.send(lock).expect("return current lock");
        });
        started_rx.recv().expect("waiter started");
        std::thread::sleep(std::time::Duration::from_millis(50));
        layout
            .remove_cow_lock(first)
            .expect("remove terminal lock safely");
        let current = acquired_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("waiter retried current lock path");
        assert!(current.lock_path.exists());
        drop(current);
        waiter.join().expect("waiter thread");
    }

    #[test]
    fn cow_lock_child_exits_without_running_destructors() {
        let Ok(root) = std::env::var("FILEBELT_COW_LOCK_CRASH_ROOT") else {
            return;
        };
        let session = Uuid::parse_str(
            &std::env::var("FILEBELT_COW_LOCK_CRASH_SESSION").expect("child session"),
        )
        .expect("valid child session");
        let marker = std::env::var("FILEBELT_COW_LOCK_CRASH_MARKER").expect("child marker");
        let layout = StorageLayout::new(PathBuf::from(root));
        let _lock = layout.lock_cow(session).expect("child lock");
        fs::write(marker, b"locked").expect("child marker write");
        std::process::exit(97);
    }

    #[test]
    fn child_process_exit_releases_cow_flock() {
        let root = TempDir::new().expect("temporary root");
        let storage_root = root.path().join("payload");
        let layout = StorageLayout::new(storage_root.clone());
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        let marker = root.path().join("locked.marker");
        let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .arg("--exact")
            .arg("cow::tests::cow_lock_child_exits_without_running_destructors")
            .env("FILEBELT_COW_LOCK_CRASH_ROOT", &storage_root)
            .env("FILEBELT_COW_LOCK_CRASH_SESSION", session.to_string())
            .env("FILEBELT_COW_LOCK_CRASH_MARKER", &marker)
            .spawn()
            .expect("spawn lock child");
        for _ in 0..200 {
            if marker.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(marker.exists(), "child acquired the process-scoped flock");
        let status = child.wait().expect("wait for crashed child");
        assert_eq!(status.code(), Some(97));
        let _recovered = layout.lock_cow(session).expect("OS released child flock");
    }

    #[test]
    fn cow_lock_orders_flush_manifest_after_inflight_write() {
        let root = TempDir::new().expect("temporary root");
        let layout = std::sync::Arc::new(StorageLayout::new(root.path().join("payload")));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, 65_536, None, &[])
            .expect("begin COW");
        layout
            .write_cow_at(session, Uuid::new_v4(), 65_536, 0, 0, &[0; 8])
            .expect("initial bytes");
        let (locked, wait_for_release) = std::sync::mpsc::sync_channel(0);
        let writer_layout = layout.clone();
        let writer = std::thread::spawn(move || {
            writer_layout
                .with_cow_lock(session, || {
                    locked.send(()).expect("signal acquired lock");
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    writer_layout.write_cow_at(
                        session,
                        Uuid::new_v4(),
                        65_536,
                        8,
                        0,
                        b"filebelt",
                    )?;
                    Ok(())
                })
                .expect("write under lock");
        });
        wait_for_release.recv().expect("writer acquired lock");
        let manifest = layout
            .with_cow_lock(session, || layout.cow_manifest(session, 65_536, 8))
            .expect("manifest after write");
        writer.join().expect("writer thread");
        assert_eq!(manifest.digest, *blake3::hash(b"filebelt").as_bytes());
    }

    #[test]
    fn publish_mismatch_leaves_source_retryable_and_destination_absent() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, 65_536, None, &[])
            .expect("begin COW");
        let bytes = vec![9_u8; 65_537];
        layout
            .write_cow_at(session, Uuid::new_v4(), 65_536, 0, 0, &bytes)
            .expect("write COW bytes");
        let correct_digest = *blake3::hash(&bytes).as_bytes();
        let wrong = staging_payload(&layout, bytes.len() as u64, [1; 32]);
        let expected = layout
            .cow_manifest(session, 65_536, bytes.len() as u64)
            .expect("expected manifest");
        let source = layout.cow_directory(session).expect("COW source");
        let destination = layout.payload_path(&wrong).expect("payload destination");

        assert!(matches!(
            layout.publish_cow(session, &wrong, 65_536, &expected),
            Err(StorageError::CorruptObject)
        ));
        assert!(source.exists());
        assert!(!destination.exists());

        let mut correct = wrong;
        correct.blake3 = Some(correct_digest.to_vec());
        let finalized = layout
            .publish_cow(session, &correct, 65_536, &expected)
            .expect("retry publish");
        assert_eq!(finalized.digest, correct_digest);
        assert!(!source.exists());
        assert!(destination.exists());
        assert_eq!(
            layout
                .publish_cow(session, &correct, 65_536, &expected)
                .expect("idempotent publish retry"),
            finalized
        );
    }

    #[test]
    fn publish_requires_exact_manifest_when_staging_row_evidence_is_provisional() {
        let root = TempDir::new().expect("temporary root");
        let layout = StorageLayout::new(root.path().join("payload"));
        layout.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        layout
            .begin_cow_write(session, 65_536, None, &[])
            .expect("begin COW");
        let bytes = b"manifest authority";
        layout
            .write_cow_at(session, Uuid::new_v4(), 65_536, 0, 0, bytes)
            .expect("write COW bytes");
        let expected = layout
            .cow_manifest(session, 65_536, bytes.len() as u64)
            .expect("expected manifest");
        let mut wrong_expected = expected.clone();
        wrong_expected.digest = [0x44; 32];
        let mut provisional = staging_payload(&layout, 0, [0; 32]);
        provisional.blake3 = None;

        assert!(matches!(
            layout.publish_cow(session, &provisional, 65_536, &wrong_expected),
            Err(StorageError::CorruptObject)
        ));
        assert!(layout.cow_directory(session).unwrap().exists());
        assert!(!layout.payload_path(&provisional).unwrap().exists());

        let finalized = layout
            .publish_cow(session, &provisional, 65_536, &expected)
            .expect("explicit exact manifest publishes provisional row");
        assert_eq!(finalized.digest, expected.digest);
        assert_eq!(finalized.size, bytes.len() as u64);
    }

    #[test]
    fn delete_staging_is_idempotent_for_unpublished_published_both_and_neither() {
        for shape in ["unpublished", "published", "both", "neither"] {
            let root = TempDir::new().expect("temporary root");
            let layout = StorageLayout::new(root.path().join("payload"));
            layout.prepare().expect("prepare storage");
            let session = Uuid::new_v4();
            let bytes = b"staging cleanup";
            let payload =
                staging_payload(&layout, bytes.len() as u64, *blake3::hash(bytes).as_bytes());
            if shape != "neither" {
                layout
                    .begin_cow_write(session, 65_536, None, &[])
                    .expect("begin cleanup COW");
                layout
                    .write_cow_at(session, Uuid::new_v4(), 65_536, 0, 0, bytes)
                    .expect("write cleanup COW");
            }
            if shape == "published" {
                let manifest = layout
                    .cow_manifest(session, 65_536, bytes.len() as u64)
                    .expect("cleanup manifest");
                layout
                    .publish_cow(session, &payload, 65_536, &manifest)
                    .expect("publish cleanup payload");
            } else if shape == "both" {
                let destination = layout.payload_path(&payload).expect("payload destination");
                create_secure_directory(&destination).expect("published crash shape");
                let mut chunk = create_new_file(&destination.join(cow_chunk_name(0)))
                    .expect("published crash chunk");
                chunk.write_all(bytes).expect("published crash bytes");
                chunk.sync_all().expect("sync published crash bytes");
                sync_directory(&destination).expect("sync published crash directory");
            }

            layout
                .delete_cow_staging(session, &payload)
                .unwrap_or_else(|error| panic!("cleanup {shape}: {error}"));
            assert!(!layout.cow_directory(session).unwrap().exists());
            assert!(!layout.payload_path(&payload).unwrap().exists());
            layout
                .delete_cow_staging(session, &payload)
                .unwrap_or_else(|error| panic!("idempotent cleanup {shape}: {error}"));
        }
    }

    #[test]
    fn rename_parent_sync_handles_same_and_distinct_directories() {
        let root = TempDir::new().expect("temporary root");
        let left = root.path().join("left");
        let right = root.path().join("right");
        create_secure_directory(&left).expect("left directory");
        create_secure_directory(&right).expect("right directory");
        sync_rename_parents(&left.join("source"), &left.join("destination"))
            .expect("same parent sync");
        sync_rename_parents(&left.join("source"), &right.join("destination"))
            .expect("distinct parent sync");
    }
}

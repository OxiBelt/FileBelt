// SPDX-License-Identifier: Apache-2.0

//! Canonical bounds and tree validation for the private directory-repository
//! adapter protocol.
//!
//! The matching Protobuf source lives in
//! `protocol/directory_repository/v1/directory_repository.proto`. The committed
//! Rust bindings are produced only by the repository-pinned Buf generator.

#![deny(unsafe_code)]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

use filebelt_domain::{LogicalPath, NormalizedName};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_BLOB_BYTES: u64 = 100 * 1024 * 1024;
pub const MAX_PACK_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_PUSH_COMMITS: usize = 32;
pub const MAX_CHANGED_PATHS_PER_COMMIT: usize = 10_000;
pub const MAX_TREE_ENTRIES: usize = 100_000;
pub const MAX_REQUEST_ID_BYTES: usize = 64;
/// Private frames carry inspection metadata, never blob or pack bytes. Keeping
/// this cap well below the blob limit bounds Prost's pre-validation allocation.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

mod generated {
    include!(
        "../../../../protocol/generated/rust/filebelt/directory_repository/v1/filebelt.directory_repository.v1.rs"
    );
}

pub use generated::*;
pub use generated::{directory_repository_execute_request, directory_repository_execute_response};

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectFormat {
    Sha1,
    #[default]
    Sha256,
}

impl ObjectFormat {
    #[must_use]
    pub const fn oid_bytes(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectId {
    pub format: ObjectFormat,
    pub value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TreeMode {
    Directory,
    File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntry {
    pub path_components: Vec<String>,
    pub mode: TreeMode,
    pub object_id: ObjectId,
    pub object_size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    Upsert,
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeChange {
    pub path_components: Vec<String>,
    pub kind: ChangeKind,
    pub entry: Option<TreeEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationFence {
    pub tenant_id: Uuid,
    pub directory_root_id: Uuid,
    pub operation_id: Uuid,
    pub fencing_token: u64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("frame exceeds the configured limit")]
    FrameTooLarge,
    #[error("frame has an invalid length prefix")]
    FrameLength,
    #[error("frame cannot be encoded or decoded")]
    FrameCodec,
    #[error("frame I/O failed")]
    FrameIo,
    #[error("request ID is invalid")]
    RequestId,
    #[error("request or response is missing its required operation or result")]
    MissingOperation,
    #[error("operation fence is invalid")]
    Fence,
    #[error("object ID has the wrong format or length")]
    ObjectId,
    #[error("tree has too many entries")]
    TreeEntries,
    #[error("tree path is invalid")]
    Path,
    #[error("tree has a case-folding sibling collision")]
    PathCollision,
    #[error("tree paths are not in canonical order")]
    PathOrder,
    #[error("tree is missing a directory ancestor")]
    MissingAncestor,
    #[error("tree entry has an invalid mode or size")]
    TreeEntry,
    #[error(".git is prohibited in every casefolding")]
    GitDirectory,
    #[error(".filebeltkeep is invalid")]
    FileBeltKeep,
    #[error("too many changed paths")]
    ChangedPaths,
    #[error("tree change is invalid")]
    Change,
    #[error("commit chain is invalid")]
    CommitChain,
    #[error("pack exceeds its configured limit")]
    PackSize,
    #[error("request or response does not match the directory-repository contract")]
    Contract,
    #[error("response does not match its request")]
    ResponseMismatch,
}

pub fn validate_fence(fence: OperationFence) -> Result<(), ValidationError> {
    if fence.tenant_id.is_nil()
        || fence.directory_root_id.is_nil()
        || fence.operation_id.is_nil()
        || fence.fencing_token == 0
    {
        return Err(ValidationError::Fence);
    }
    Ok(())
}

pub fn validate_object_id(
    object_id: &ObjectId,
    expected_format: ObjectFormat,
) -> Result<(), ValidationError> {
    if object_id.format != expected_format
        || object_id.value.len() != expected_format.oid_bytes()
        || object_id.value.iter().all(|byte| *byte == 0)
    {
        return Err(ValidationError::ObjectId);
    }
    Ok(())
}

/// Validates the exact canonical flattened tree used for bounded inspection.
/// Entries must be ordered by their UTF-8 path-component vectors and must name
/// every directory ancestor explicitly.
pub fn validate_tree(
    entries: &[TreeEntry],
    expected_format: ObjectFormat,
) -> Result<(), ValidationError> {
    if entries.len() > MAX_TREE_ENTRIES {
        return Err(ValidationError::TreeEntries);
    }

    let mut modes = BTreeMap::new();
    let mut normalized_paths = Vec::with_capacity(entries.len());
    let mut prior: Option<&[String]> = None;
    for entry in entries {
        normalized_paths.push(validate_path(&entry.path_components)?);
        if prior.is_some_and(|path| path >= entry.path_components.as_slice()) {
            return Err(ValidationError::PathOrder);
        }
        prior = Some(&entry.path_components);
        validate_entry(entry, expected_format)?;
        modes.insert(entry.path_components.clone(), entry.mode);
    }
    validate_sibling_casefold_collisions(&normalized_paths)?;

    for entry in entries {
        for length in 1..entry.path_components.len() {
            if modes.get(&entry.path_components[..length]) != Some(&TreeMode::Directory) {
                return Err(ValidationError::MissingAncestor);
            }
        }
        if entry
            .path_components
            .last()
            .is_some_and(|component| component == ".filebeltkeep")
        {
            validate_filebeltkeep(entries, entry)?;
        }
    }
    Ok(())
}

pub fn validate_changes(
    changes: &[TreeChange],
    expected_format: ObjectFormat,
) -> Result<(), ValidationError> {
    if changes.len() > MAX_CHANGED_PATHS_PER_COMMIT {
        return Err(ValidationError::ChangedPaths);
    }
    let mut normalized_paths = Vec::with_capacity(changes.len());
    let mut prior: Option<&[String]> = None;
    for change in changes {
        normalized_paths.push(validate_path(&change.path_components)?);
        if prior.is_some_and(|path| path >= change.path_components.as_slice()) {
            return Err(ValidationError::PathOrder);
        }
        prior = Some(&change.path_components);
        match (change.kind, change.entry.as_ref()) {
            (ChangeKind::Delete, None) => {}
            (ChangeKind::Upsert, Some(entry))
                if entry.path_components == change.path_components =>
            {
                validate_entry(entry, expected_format)?;
            }
            _ => return Err(ValidationError::Change),
        }
    }
    validate_sibling_casefold_collisions(&normalized_paths)?;
    Ok(())
}

pub fn validate_commit_chain(
    commits: &[ObjectId],
    expected_format: ObjectFormat,
) -> Result<(), ValidationError> {
    if commits.is_empty() || commits.len() > MAX_PUSH_COMMITS {
        return Err(ValidationError::CommitChain);
    }
    for commit in commits {
        validate_object_id(commit, expected_format)?;
    }
    Ok(())
}

pub const fn validate_pack_size(pack_size_bytes: u64) -> Result<(), ValidationError> {
    if pack_size_bytes > MAX_PACK_BYTES {
        return Err(ValidationError::PackSize);
    }
    Ok(())
}

/// Encodes one bounded private Protobuf frame. This framing is transport-neutral
/// and does not create a listener or expose a Git wire protocol.
pub fn encode_frame<M: prost::Message>(message: &M) -> Result<Vec<u8>, ValidationError> {
    let body = message.encode_to_vec();
    if body.len() > MAX_FRAME_BYTES {
        return Err(ValidationError::FrameTooLarge);
    }
    let length = u32::try_from(body.len()).map_err(|_| ValidationError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decodes exactly one bounded private Protobuf frame.
pub fn decode_frame<M: prost::Message + Default>(frame: &[u8]) -> Result<M, ValidationError> {
    if frame.len() < 4 {
        return Err(ValidationError::FrameLength);
    }
    let length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| ValidationError::FrameLength)?,
    ) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ValidationError::FrameTooLarge);
    }
    if frame.len() != length + 4 {
        return Err(ValidationError::FrameLength);
    }
    M::decode(&frame[4..]).map_err(|_| ValidationError::FrameCodec)
}

pub fn read_frame<M: prost::Message + Default>(
    reader: &mut impl Read,
) -> Result<M, ValidationError> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| ValidationError::FrameIo)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ValidationError::FrameTooLarge);
    }
    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|_| ValidationError::FrameIo)?;
    M::decode(body.as_slice()).map_err(|_| ValidationError::FrameCodec)
}

pub fn write_frame<M: prost::Message>(
    writer: &mut impl Write,
    message: &M,
) -> Result<(), ValidationError> {
    let frame = encode_frame(message)?;
    writer
        .write_all(&frame)
        .map_err(|_| ValidationError::FrameIo)
}

/// Validates a generated private request before it reaches the isolated Git
/// executable. It deliberately has no transport side effect.
pub fn validate_request(
    request: &DirectoryRepositoryExecuteRequest,
) -> Result<(), ValidationError> {
    validate_request_id(&request.request_id)?;
    match request
        .operation
        .as_ref()
        .ok_or(ValidationError::MissingOperation)?
    {
        directory_repository_execute_request::Operation::Prepare(operation) => {
            let fence = wire_fence(operation.fence.as_ref())?;
            let object_format = wire_format(operation.object_format, false)?;
            validate_fence(fence)?;
            validate_optional_wire_object_id(operation.expected_head.as_ref(), object_format)?;
        }
        directory_repository_execute_request::Operation::Stage(operation) => {
            validate_fence(wire_fence(operation.fence.as_ref())?)?;
            let object_format = wire_format(operation.object_format, false)?;
            validate_wire_changes(&operation.changes, object_format)?;
        }
        directory_repository_execute_request::Operation::Verify(operation) => {
            validate_fence(wire_fence(operation.fence.as_ref())?)?;
            let object_format = wire_format(operation.object_format, false)?;
            if operation.entries.len() > MAX_TREE_ENTRIES {
                return Err(ValidationError::TreeEntries);
            }
            if operation.commits.is_empty() || operation.commits.len() > MAX_PUSH_COMMITS {
                return Err(ValidationError::CommitChain);
            }
            let entries = operation
                .entries
                .iter()
                .map(|entry| wire_tree_entry(entry, object_format))
                .collect::<Result<Vec<_>, _>>()?;
            let commits = operation
                .commits
                .iter()
                .map(|commit| wire_object_id(commit, object_format))
                .collect::<Result<Vec<_>, _>>()?;
            validate_tree(&entries, object_format)?;
            validate_commit_chain(&commits, object_format)?;
            validate_pack_size(operation.pack_size_bytes)?;
        }
        directory_repository_execute_request::Operation::Promote(operation) => {
            validate_fence(wire_fence(operation.fence.as_ref())?)?;
            if operation.commits.is_empty() || operation.commits.len() > MAX_PUSH_COMMITS {
                return Err(ValidationError::CommitChain);
            }
            let new_head = required_wire_object_id(operation.new_head.as_ref())?;
            validate_optional_wire_object_id(operation.expected_head.as_ref(), new_head.format)?;
            let commits = operation
                .commits
                .iter()
                .map(|commit| wire_object_id(commit, new_head.format))
                .collect::<Result<Vec<_>, _>>()?;
            validate_commit_chain(&commits, new_head.format)?;
        }
        directory_repository_execute_request::Operation::Rollback(operation) => {
            validate_fence(wire_fence(operation.fence.as_ref())?)?;
            let rollback_head = required_wire_object_id(operation.rollback_head.as_ref())?;
            validate_optional_wire_object_id(
                operation.expected_head.as_ref(),
                rollback_head.format,
            )?;
        }
        directory_repository_execute_request::Operation::Advertise(operation) => {
            validate_fence(wire_fence(operation.fence.as_ref())?)?;
            if operation.maximum_entries as usize > MAX_TREE_ENTRIES {
                return Err(ValidationError::TreeEntries);
            }
        }
        directory_repository_execute_request::Operation::Fsck(operation) => {
            validate_fence(wire_fence(operation.fence.as_ref())?)?;
        }
        directory_repository_execute_request::Operation::Gc(operation) => {
            validate_fence(wire_fence(operation.fence.as_ref())?)?;
            if operation.maximum_reclaim_bytes > MAX_PACK_BYTES {
                return Err(ValidationError::PackSize);
            }
        }
    }
    Ok(())
}

/// Validates that a generated response is a legal response to one generated
/// request. Error responses are admitted only when their code is explicit.
pub fn validate_response(
    request: &DirectoryRepositoryExecuteRequest,
    response: &DirectoryRepositoryExecuteResponse,
) -> Result<(), ValidationError> {
    validate_request(request)?;
    validate_request_id(&response.request_id)?;
    if response.request_id != request.request_id {
        return Err(ValidationError::ResponseMismatch);
    }
    let operation = request
        .operation
        .as_ref()
        .ok_or(ValidationError::MissingOperation)?;
    let result = response
        .result
        .as_ref()
        .ok_or(ValidationError::MissingOperation)?;
    if let directory_repository_execute_response::Result::Error(error) = result {
        return validate_error(error);
    }

    match (operation, result) {
        (
            directory_repository_execute_request::Operation::Verify(operation),
            directory_repository_execute_response::Result::TreeInspection(result),
        ) => {
            let object_format = wire_format(operation.object_format, false)?;
            if wire_format(result.object_format, false)? != object_format
                || result.commit_count != operation.commits.len() as u32
                || result.pack_size_bytes != operation.pack_size_bytes
                || result.entries != operation.entries
            {
                return Err(ValidationError::ResponseMismatch);
            }
            let entries = result
                .entries
                .iter()
                .map(|entry| wire_tree_entry(entry, object_format))
                .collect::<Result<Vec<_>, _>>()?;
            validate_tree(&entries, object_format)
        }
        (
            directory_repository_execute_request::Operation::Advertise(operation),
            directory_repository_execute_response::Result::Advertisement(result),
        ) => {
            let object_format = wire_format(result.object_format, false)?;
            if result.entry_count > operation.maximum_entries {
                return Err(ValidationError::ResponseMismatch);
            }
            validate_optional_wire_object_id(result.head.as_ref(), object_format)
        }
        (
            directory_repository_execute_request::Operation::Fsck(_),
            directory_repository_execute_response::Result::FsckResult(result),
        ) => {
            if result.checked_entries > MAX_TREE_ENTRIES as u64 {
                return Err(ValidationError::TreeEntries);
            }
            Ok(())
        }
        (
            directory_repository_execute_request::Operation::Gc(operation),
            directory_repository_execute_response::Result::GcResult(result),
        ) => {
            if result.reclaimed_bytes > operation.maximum_reclaim_bytes
                || result.remaining_pack_bytes > MAX_PACK_BYTES
            {
                return Err(ValidationError::ResponseMismatch);
            }
            Ok(())
        }
        (
            directory_repository_execute_request::Operation::Prepare(operation),
            directory_repository_execute_response::Result::Accepted(result),
        ) => validate_accepted(result, wire_format(operation.object_format, false)?),
        (
            directory_repository_execute_request::Operation::Stage(operation),
            directory_repository_execute_response::Result::Accepted(result),
        ) => validate_accepted(result, wire_format(operation.object_format, false)?),
        (
            directory_repository_execute_request::Operation::Promote(operation),
            directory_repository_execute_response::Result::Accepted(result),
        ) => validate_accepted_head(result, operation.new_head.as_ref()),
        (
            directory_repository_execute_request::Operation::Rollback(operation),
            directory_repository_execute_response::Result::Accepted(result),
        ) => validate_accepted_head(result, operation.rollback_head.as_ref()),
        _ => Err(ValidationError::ResponseMismatch),
    }
}

fn validate_request_id(value: &str) -> Result<(), ValidationError> {
    if value.len() > MAX_REQUEST_ID_BYTES || Uuid::parse_str(value).is_err() {
        return Err(ValidationError::RequestId);
    }
    Ok(())
}

fn wire_fence(value: Option<&DirectoryRepositoryFence>) -> Result<OperationFence, ValidationError> {
    let value = value.ok_or(ValidationError::Fence)?;
    Ok(OperationFence {
        tenant_id: Uuid::parse_str(&value.tenant_id).map_err(|_| ValidationError::Fence)?,
        directory_root_id: Uuid::parse_str(&value.directory_root_id)
            .map_err(|_| ValidationError::Fence)?,
        operation_id: Uuid::parse_str(&value.operation_id).map_err(|_| ValidationError::Fence)?,
        fencing_token: value.fencing_token,
    })
}

fn wire_format(value: i32, allow_default: bool) -> Result<ObjectFormat, ValidationError> {
    match GitObjectFormat::try_from(value).ok() {
        Some(GitObjectFormat::Sha1) => Ok(ObjectFormat::Sha1),
        Some(GitObjectFormat::Sha256) => Ok(ObjectFormat::Sha256),
        Some(GitObjectFormat::Unspecified) if allow_default => Ok(ObjectFormat::Sha256),
        _ => Err(ValidationError::ObjectId),
    }
}

fn wire_object_id(
    value: &GitObjectId,
    expected_format: ObjectFormat,
) -> Result<ObjectId, ValidationError> {
    let object_id = ObjectId {
        format: wire_format(value.format, false)?,
        value: value.value.clone(),
    };
    validate_object_id(&object_id, expected_format)?;
    Ok(object_id)
}

fn required_wire_object_id(value: Option<&GitObjectId>) -> Result<ObjectId, ValidationError> {
    let value = value.ok_or(ValidationError::ObjectId)?;
    let object_format = wire_format(value.format, false)?;
    wire_object_id(value, object_format)
}

fn validate_optional_wire_object_id(
    value: Option<&GitObjectId>,
    expected_format: ObjectFormat,
) -> Result<(), ValidationError> {
    if let Some(value) = value {
        wire_object_id(value, expected_format)?;
    }
    Ok(())
}

fn wire_tree_entry(
    value: &DirectoryRepositoryTreeEntry,
    expected_format: ObjectFormat,
) -> Result<TreeEntry, ValidationError> {
    let mode = match GitTreeMode::try_from(value.mode).ok() {
        Some(GitTreeMode::Directory) => TreeMode::Directory,
        Some(GitTreeMode::File) => TreeMode::File,
        _ => return Err(ValidationError::TreeEntry),
    };
    Ok(TreeEntry {
        path_components: value.path_components.clone(),
        mode,
        object_id: required_wire_object_id_with_format(value.object_id.as_ref(), expected_format)?,
        object_size_bytes: value.object_size_bytes,
    })
}

fn required_wire_object_id_with_format(
    value: Option<&GitObjectId>,
    expected_format: ObjectFormat,
) -> Result<ObjectId, ValidationError> {
    wire_object_id(value.ok_or(ValidationError::ObjectId)?, expected_format)
}

fn validate_wire_changes(
    changes: &[DirectoryRepositoryTreeChange],
    expected_format: ObjectFormat,
) -> Result<(), ValidationError> {
    if changes.len() > MAX_CHANGED_PATHS_PER_COMMIT {
        return Err(ValidationError::ChangedPaths);
    }
    let mut translated = Vec::with_capacity(changes.len());
    for change in changes {
        let kind = match DirectoryRepositoryChangeKind::try_from(change.kind).ok() {
            Some(DirectoryRepositoryChangeKind::Upsert) => ChangeKind::Upsert,
            Some(DirectoryRepositoryChangeKind::Delete) => ChangeKind::Delete,
            _ => return Err(ValidationError::Change),
        };
        let entry = match kind {
            ChangeKind::Delete => {
                if change.mode != GitTreeMode::Unspecified as i32
                    || change.object_id.is_some()
                    || change.object_size_bytes != 0
                {
                    return Err(ValidationError::Change);
                }
                None
            }
            ChangeKind::Upsert => {
                let object_id = required_wire_object_id_with_format(
                    change.object_id.as_ref(),
                    expected_format,
                )?;
                let mode = match GitTreeMode::try_from(change.mode).ok() {
                    Some(GitTreeMode::Directory) => TreeMode::Directory,
                    Some(GitTreeMode::File) => TreeMode::File,
                    _ => return Err(ValidationError::Change),
                };
                Some(TreeEntry {
                    path_components: change.path_components.clone(),
                    mode,
                    object_id,
                    object_size_bytes: change.object_size_bytes,
                })
            }
        };
        translated.push(TreeChange {
            path_components: change.path_components.clone(),
            kind,
            entry,
        });
    }
    validate_changes(&translated, expected_format)
}

fn validate_accepted(
    result: &DirectoryRepositoryAccepted,
    object_format: ObjectFormat,
) -> Result<(), ValidationError> {
    validate_optional_wire_object_id(result.head.as_ref(), object_format)?;
    validate_optional_wire_object_id(result.tree.as_ref(), object_format)
}

fn validate_accepted_head(
    result: &DirectoryRepositoryAccepted,
    expected_head: Option<&GitObjectId>,
) -> Result<(), ValidationError> {
    let expected_head = expected_head.ok_or(ValidationError::ObjectId)?;
    if result.head.as_ref() != Some(expected_head) {
        return Err(ValidationError::ResponseMismatch);
    }
    validate_accepted(result, wire_format(expected_head.format, false)?)
}

fn validate_error(error: &DirectoryRepositoryError) -> Result<(), ValidationError> {
    if !matches!(
        DirectoryRepositoryErrorCode::try_from(error.code).ok(),
        Some(
            DirectoryRepositoryErrorCode::InvalidRequest
                | DirectoryRepositoryErrorCode::NotFound
                | DirectoryRepositoryErrorCode::Conflict
                | DirectoryRepositoryErrorCode::ResourceExhausted
                | DirectoryRepositoryErrorCode::Unavailable
                | DirectoryRepositoryErrorCode::IntegrityFailure
                | DirectoryRepositoryErrorCode::Internal
        )
    ) || error.message.is_empty()
        || error.message.len() > 4_096
    {
        return Err(ValidationError::Contract);
    }
    Ok(())
}

fn validate_entry(entry: &TreeEntry, expected_format: ObjectFormat) -> Result<(), ValidationError> {
    validate_object_id(&entry.object_id, expected_format)?;
    match entry.mode {
        TreeMode::Directory if entry.object_size_bytes == 0 => Ok(()),
        TreeMode::File if entry.object_size_bytes <= MAX_BLOB_BYTES => Ok(()),
        _ => Err(ValidationError::TreeEntry),
    }
}

fn validate_path(path_components: &[String]) -> Result<Vec<NormalizedName>, ValidationError> {
    if path_components.is_empty() {
        return Err(ValidationError::Path);
    }
    let components = path_components
        .iter()
        .map(|component| {
            let normalized = NormalizedName::new(component).map_err(|_| ValidationError::Path)?;
            if normalized.display() != component {
                return Err(ValidationError::Path);
            }
            if normalized.comparison_key() == ".git" {
                return Err(ValidationError::GitDirectory);
            }
            Ok(normalized)
        })
        .collect::<Result<Vec<_>, _>>()?;
    LogicalPath::from_components(components.clone()).map_err(|_| ValidationError::Path)?;
    Ok(components)
}

fn validate_sibling_casefold_collisions(
    paths: &[Vec<NormalizedName>],
) -> Result<(), ValidationError> {
    let mut children = BTreeMap::<Vec<String>, BTreeMap<String, String>>::new();
    for path in paths {
        let (name, parent) = path.split_last().ok_or(ValidationError::Path)?;
        let parent = parent
            .iter()
            .map(|component| component.comparison_key().to_owned())
            .collect::<Vec<_>>();
        let siblings = children.entry(parent).or_default();
        if siblings
            .insert(name.comparison_key().to_owned(), name.display().to_owned())
            .is_some()
        {
            return Err(ValidationError::PathCollision);
        }
    }
    Ok(())
}

fn validate_filebeltkeep(entries: &[TreeEntry], keep: &TreeEntry) -> Result<(), ValidationError> {
    if keep.mode != TreeMode::File || keep.object_size_bytes != 0 {
        return Err(ValidationError::FileBeltKeep);
    }
    let parent = &keep.path_components[..keep.path_components.len() - 1];
    if entries.iter().any(|entry| {
        entry.path_components.len() > parent.len()
            && entry.path_components.starts_with(parent)
            && entry.path_components != keep.path_components
    }) {
        return Err(ValidationError::FileBeltKeep);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid() -> ObjectId {
        ObjectId {
            format: ObjectFormat::Sha256,
            value: vec![7; ObjectFormat::Sha256.oid_bytes()],
        }
    }

    fn entry(path_components: &[&str], mode: TreeMode, size: u64) -> TreeEntry {
        TreeEntry {
            path_components: path_components
                .iter()
                .map(|part| (*part).to_owned())
                .collect(),
            mode,
            object_id: oid(),
            object_size_bytes: size,
        }
    }

    #[test]
    fn accepts_canonical_directory_tree() {
        let tree = [
            entry(&["docs"], TreeMode::Directory, 0),
            entry(&["docs", "readme.md"], TreeMode::File, 12),
            entry(&["main.rs"], TreeMode::File, 34),
        ];
        assert_eq!(validate_tree(&tree, ObjectFormat::Sha256), Ok(()));
    }

    #[test]
    fn rejects_casefolded_git_and_noncanonical_paths() {
        let git = [entry(&[".GiT"], TreeMode::Directory, 0)];
        assert_eq!(
            validate_tree(&git, ObjectFormat::Sha256),
            Err(ValidationError::GitDirectory)
        );
        let unordered = [
            entry(&["z"], TreeMode::File, 1),
            entry(&["a"], TreeMode::File, 1),
        ];
        assert_eq!(
            validate_tree(&unordered, ObjectFormat::Sha256),
            Err(ValidationError::PathOrder)
        );
    }

    #[test]
    fn rejects_normalized_sibling_collisions_and_oversized_paths() {
        let colliding = [
            entry(&["STRASSE"], TreeMode::File, 1),
            entry(&["Straße"], TreeMode::File, 1),
        ];
        assert_eq!(
            validate_tree(&colliding, ObjectFormat::Sha256),
            Err(ValidationError::PathCollision)
        );

        let components = vec!["a".to_owned(); filebelt_domain::MAX_PATH_COMPONENTS + 1];
        let too_deep = [TreeEntry {
            path_components: components,
            mode: TreeMode::File,
            object_id: oid(),
            object_size_bytes: 1,
        }];
        assert_eq!(
            validate_tree(&too_deep, ObjectFormat::Sha256),
            Err(ValidationError::Path)
        );
    }

    #[test]
    fn enforces_filebeltkeep_empty_directory_rule() {
        let valid = [
            entry(&["empty"], TreeMode::Directory, 0),
            entry(&["empty", ".filebeltkeep"], TreeMode::File, 0),
        ];
        assert_eq!(validate_tree(&valid, ObjectFormat::Sha256), Ok(()));

        let invalid = [
            entry(&["empty"], TreeMode::Directory, 0),
            entry(&["empty", ".filebeltkeep"], TreeMode::File, 0),
            entry(&["empty", "other"], TreeMode::File, 1),
        ];
        assert_eq!(
            validate_tree(&invalid, ObjectFormat::Sha256),
            Err(ValidationError::FileBeltKeep)
        );
    }

    #[test]
    fn validates_staging_and_bounded_commit_chain() {
        let change = TreeChange {
            path_components: vec!["new.txt".into()],
            kind: ChangeKind::Upsert,
            entry: Some(entry(&["new.txt"], TreeMode::File, 1)),
        };
        assert_eq!(validate_changes(&[change], ObjectFormat::Sha256), Ok(()));
        assert_eq!(
            validate_commit_chain(&[oid()], ObjectFormat::Sha256),
            Ok(())
        );
        assert_eq!(validate_pack_size(MAX_PACK_BYTES), Ok(()));
    }

    fn wire_fence() -> DirectoryRepositoryFence {
        DirectoryRepositoryFence {
            tenant_id: Uuid::from_u128(1).to_string(),
            directory_root_id: Uuid::from_u128(2).to_string(),
            operation_id: Uuid::from_u128(3).to_string(),
            fencing_token: 4,
        }
    }

    #[test]
    fn validates_and_frames_generated_prepare_contract() {
        let request = DirectoryRepositoryExecuteRequest {
            request_id: Uuid::from_u128(4).to_string(),
            operation: Some(directory_repository_execute_request::Operation::Prepare(
                PrepareDirectoryRepository {
                    fence: Some(wire_fence()),
                    object_format: GitObjectFormat::Sha256 as i32,
                    expected_head: None,
                },
            )),
        };
        let response = DirectoryRepositoryExecuteResponse {
            request_id: request.request_id.clone(),
            result: Some(directory_repository_execute_response::Result::Accepted(
                DirectoryRepositoryAccepted {
                    head: None,
                    tree: None,
                },
            )),
        };

        assert_eq!(validate_request(&request), Ok(()));
        assert_eq!(validate_response(&request, &response), Ok(()));
        let frame = encode_frame(&request).expect("request frame");
        let decoded = decode_frame::<DirectoryRepositoryExecuteRequest>(&frame).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn rejects_an_unspecified_repository_object_format() {
        let request = DirectoryRepositoryExecuteRequest {
            request_id: Uuid::from_u128(4).to_string(),
            operation: Some(directory_repository_execute_request::Operation::Prepare(
                PrepareDirectoryRepository {
                    fence: Some(wire_fence()),
                    object_format: GitObjectFormat::Unspecified as i32,
                    expected_head: None,
                },
            )),
        };

        assert_eq!(validate_request(&request), Err(ValidationError::ObjectId));
    }

    #[test]
    fn rejects_an_unspecified_stage_format_and_zero_object_id() {
        let stage = DirectoryRepositoryExecuteRequest {
            request_id: Uuid::from_u128(4).to_string(),
            operation: Some(directory_repository_execute_request::Operation::Stage(
                StageDirectoryRepository {
                    fence: Some(wire_fence()),
                    changes: vec![],
                    object_format: GitObjectFormat::Unspecified as i32,
                },
            )),
        };
        assert_eq!(validate_request(&stage), Err(ValidationError::ObjectId));
        assert_eq!(
            validate_object_id(
                &ObjectId {
                    format: ObjectFormat::Sha256,
                    value: vec![0; 32],
                },
                ObjectFormat::Sha256,
            ),
            Err(ValidationError::ObjectId)
        );
    }

    #[test]
    fn rejects_an_untagged_generated_object_id() {
        let request = DirectoryRepositoryExecuteRequest {
            request_id: Uuid::from_u128(4).to_string(),
            operation: Some(directory_repository_execute_request::Operation::Verify(
                VerifyDirectoryRepository {
                    fence: Some(wire_fence()),
                    object_format: GitObjectFormat::Sha256 as i32,
                    entries: vec![],
                    commits: vec![GitObjectId {
                        format: GitObjectFormat::Unspecified as i32,
                        value: vec![7; 32],
                    }],
                    pack_size_bytes: 0,
                },
            )),
        };

        assert_eq!(validate_request(&request), Err(ValidationError::ObjectId));
    }

    #[test]
    fn rejects_a_promote_response_for_a_different_head() {
        let new_head = GitObjectId {
            format: GitObjectFormat::Sha256 as i32,
            value: vec![7; 32],
        };
        let request = DirectoryRepositoryExecuteRequest {
            request_id: Uuid::from_u128(4).to_string(),
            operation: Some(directory_repository_execute_request::Operation::Promote(
                PromoteDirectoryRepository {
                    fence: Some(wire_fence()),
                    expected_head: None,
                    new_head: Some(new_head.clone()),
                    commits: vec![new_head],
                },
            )),
        };
        let response = DirectoryRepositoryExecuteResponse {
            request_id: request.request_id.clone(),
            result: Some(directory_repository_execute_response::Result::Accepted(
                DirectoryRepositoryAccepted {
                    head: Some(GitObjectId {
                        format: GitObjectFormat::Sha256 as i32,
                        value: vec![8; 32],
                    }),
                    tree: None,
                },
            )),
        };

        assert_eq!(
            validate_response(&request, &response),
            Err(ValidationError::ResponseMismatch)
        );
    }
}

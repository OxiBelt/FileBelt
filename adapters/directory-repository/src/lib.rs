// SPDX-License-Identifier: Apache-2.0

//! Private directory-repository adapter scaffold.
//!
//! The compatibility release includes generated Protobuf bindings but enables
//! no listener or Git command execution. The executable validates the exact
//! GPL Git version only; it does not accept a public transport or execute an
//! unframed caller-controlled Git command.

#![deny(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use filebelt_directory_repository_protocol::{
    DirectoryRepositoryExecuteRequest, DirectoryRepositoryExecuteResponse, ObjectFormat, ObjectId,
    OperationFence, TreeChange, TreeEntry, ValidationError, validate_changes,
    validate_commit_chain, validate_fence, validate_pack_size, validate_request, validate_response,
    validate_tree,
};
use thiserror::Error;

pub const REQUIRED_GIT_VERSION: &str = "2.55.0";
pub const COORDINATOR_URI_SAN: &str = "spiffe://filebelt/directory-repository-coordinator/git";

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("directory-repository request is invalid: {0}")]
    Validation(#[from] ValidationError),
    #[error("the configured Git executable is unavailable or has the wrong version")]
    GitVersion,
    #[error("the generated private wire bindings are unavailable")]
    WireBindingsUnavailable,
}

#[derive(Clone, Debug)]
pub struct SystemGit {
    executable: PathBuf,
}

impl SystemGit {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }

    pub fn verify_version(&self) -> Result<(), AdapterError> {
        let output = Command::new(&self.executable)
            .args(["--no-pager", "--version"])
            .env_clear()
            .output()
            .map_err(|_| AdapterError::GitVersion)?;
        if output.status.success()
            && String::from_utf8(output.stdout)
                .ok()
                .is_some_and(|value| value.trim() == format!("git version {REQUIRED_GIT_VERSION}"))
        {
            Ok(())
        } else {
            Err(AdapterError::GitVersion)
        }
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

/// Validates an already-authorized directory-repository operation before a
/// future generated wire handler translates it to the isolated Git process.
pub fn validate_prepare(
    fence: OperationFence,
    object_format: ObjectFormat,
    expected_head: Option<&ObjectId>,
) -> Result<(), AdapterError> {
    validate_fence(fence)?;
    if let Some(head) = expected_head {
        filebelt_directory_repository_protocol::validate_object_id(head, object_format)?;
    }
    Ok(())
}

pub fn validate_stage(
    fence: OperationFence,
    object_format: ObjectFormat,
    changes: &[TreeChange],
) -> Result<(), AdapterError> {
    validate_fence(fence)?;
    validate_changes(changes, object_format)?;
    Ok(())
}

pub fn validate_verify(
    fence: OperationFence,
    object_format: ObjectFormat,
    entries: &[TreeEntry],
    commits: &[ObjectId],
    pack_size_bytes: u64,
) -> Result<(), AdapterError> {
    validate_fence(fence)?;
    validate_tree(entries, object_format)?;
    validate_commit_chain(commits, object_format)?;
    validate_pack_size(pack_size_bytes)?;
    Ok(())
}

/// Validates generated private DTOs before a future framed-stdio bridge passes
/// them to the separate Git executable. This has no socket or process side
/// effect while the transport remains intentionally disabled.
pub fn validate_private_request(
    request: &DirectoryRepositoryExecuteRequest,
) -> Result<(), AdapterError> {
    validate_request(request)?;
    Ok(())
}

pub fn validate_private_response(
    request: &DirectoryRepositoryExecuteRequest,
    response: &DirectoryRepositoryExecuteResponse,
) -> Result<(), AdapterError> {
    validate_response(request, response)?;
    Ok(())
}

/// The binary deliberately exposes no socket while the compatibility release
/// lacks reviewed runtime grants, recovery evidence, and an admitted command
/// dispatcher.
pub fn serve_private_mtls_scaffold() -> Result<(), AdapterError> {
    Err(AdapterError::WireBindingsUnavailable)
}

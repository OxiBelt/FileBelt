// SPDX-License-Identifier: GPL-2.0-only

//! GPL adapter implementation for the isolated FileBelt Git revision store.

#![deny(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use filebelt_revision_protocol::{
    CONTENT_ENTRY_NAME, FILEBOLT_REF, MAX_LINE_DIFF_LINES, MAX_LINE_DIFF_OUTPUT_BYTES,
    MAX_TEXT_BYTES, MaintainRevisionRepositoryResult, PreparedRevisionCommit,
    ReconcileRevisionRefResult, RevisionBlob, RevisionComparison, RevisionComparisonKind,
    RevisionError, RevisionErrorCode, RevisionExecuteRequest, RevisionExecuteResponse,
    RevisionHistogram, RevisionLine, RevisionLineDiffHunk, RevisionLineKind,
    VerifyRevisionRepositoryResult, revision_execute_request, revision_execute_response,
    validate_edit_text, validate_oid, validate_read_text, validate_request,
};
use prost::Message as _;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;
use tokio::time::timeout;
use uuid::Uuid;

pub const REQUIRED_GIT_VERSION: &str = "2.55.0";
pub const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_GIT_OUTPUT_BYTES: usize = MAX_LINE_DIFF_OUTPUT_BYTES;
const ZERO_SHA256_OID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum GitError {
    #[error("request is invalid")]
    Invalid,
    #[error("repository does not exist")]
    NotFound,
    #[error("expected ref state does not match")]
    Conflict,
    #[error("Git process timed out")]
    TimedOut,
    #[error("Git process output exceeds the limit")]
    OutputTooLarge,
    #[error("Git process failed")]
    Failed,
    #[error("system Git is not the required version")]
    WrongVersion,
    #[error("repository integrity verification failed")]
    Integrity,
    #[error("adapter I/O failed")]
    Io,
}

#[derive(Clone, Debug)]
pub struct GitRepository {
    root: PathBuf,
    git: PathBuf,
}

impl GitRepository {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, git: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            git: git.into(),
        }
    }

    pub async fn verify_system_git(&self) -> Result<(), GitError> {
        let output = String::from_utf8(self.run_raw(&["--version"], &[]).await?)
            .map_err(|_| GitError::Integrity)?;
        if output.trim() == format!("git version {REQUIRED_GIT_VERSION}") {
            Ok(())
        } else {
            Err(GitError::WrongVersion)
        }
    }

    // These arguments are the already-validated `PrepareRevisionCommit` wire
    // fields. Keeping the boundary explicit avoids introducing an adapter type
    // that could diverge from the provider-neutral protocol contract.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_commit(
        &self,
        repository_id: &str,
        version_id: &str,
        ordinal: u64,
        committed_at_unix_seconds: i64,
        content: &[u8],
        expected_old_commit_oid: &str,
        migration_import: bool,
    ) -> Result<PreparedRevisionCommit, GitError> {
        if migration_import {
            validate_read_text(content).map_err(|_| GitError::Invalid)?;
        } else {
            validate_edit_text(content).map_err(|_| GitError::Invalid)?;
        }
        let repository = self.ensure_repository(repository_id).await?;
        let blob_oid = self
            .git_input(&repository, &["hash-object", "-w", "--stdin"], content)
            .await?;
        let tree_input = format!("100644 blob {blob_oid}\t{CONTENT_ENTRY_NAME}\n");
        let tree_oid = self
            .git_input(&repository, &["mktree"], tree_input.as_bytes())
            .await?;
        let mut arguments = vec!["commit-tree", tree_oid.as_str()];
        if !expected_old_commit_oid.is_empty() {
            arguments.extend(["-p", expected_old_commit_oid]);
        }
        let message = format!("FileBelt revision {version_id} ordinal {ordinal}\n");
        let timestamp = format!("{committed_at_unix_seconds} +0000");
        let commit_oid = self
            .git_input_with_env(
                &repository,
                &arguments,
                message.as_bytes(),
                &[
                    ("GIT_AUTHOR_NAME", "FileBelt"),
                    ("GIT_AUTHOR_EMAIL", "noreply@filebelt.invalid"),
                    ("GIT_COMMITTER_NAME", "FileBelt"),
                    ("GIT_COMMITTER_EMAIL", "noreply@filebelt.invalid"),
                    ("GIT_AUTHOR_DATE", timestamp.as_str()),
                    ("GIT_COMMITTER_DATE", timestamp.as_str()),
                ],
            )
            .await?;
        validate_oid(&blob_oid).map_err(|_| GitError::Integrity)?;
        validate_oid(&tree_oid).map_err(|_| GitError::Integrity)?;
        validate_oid(&commit_oid).map_err(|_| GitError::Integrity)?;
        let (_, _, repository_size_kib) = self.measure(&repository).await?;
        Ok(PreparedRevisionCommit {
            commit_oid,
            blob_oid,
            tree_oid,
            repository_size_kib,
        })
    }

    pub async fn read_blob(
        &self,
        repository_id: &str,
        commit_oid: &str,
    ) -> Result<RevisionBlob, GitError> {
        let repository = self.existing_repository(repository_id)?;
        let listing = self
            .git(&repository, &["ls-tree", "--full-tree", commit_oid])
            .await?;
        let Some((mode, kind, blob_oid, name)) = parse_tree_entry(&listing) else {
            return Err(GitError::Integrity);
        };
        if mode != "100644" || kind != "blob" || name != CONTENT_ENTRY_NAME {
            return Err(GitError::Integrity);
        }
        validate_oid(blob_oid).map_err(|_| GitError::Integrity)?;
        let content = self
            .git_bytes_limited(&repository, &["cat-file", "blob", blob_oid], MAX_TEXT_BYTES)
            .await?;
        validate_read_text(&content).map_err(|_| GitError::Integrity)?;
        Ok(RevisionBlob {
            commit_oid: commit_oid.into(),
            blob_oid: blob_oid.into(),
            content,
        })
    }

    pub async fn compare_histogram(
        &self,
        repository_id: &str,
        base: &str,
        target: &str,
    ) -> Result<RevisionComparison, GitError> {
        let repository = self.existing_repository(repository_id)?;
        let output = self
            .git(
                &repository,
                &[
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--diff-algorithm=histogram",
                    "--numstat",
                    base,
                    target,
                    "--",
                    CONTENT_ENTRY_NAME,
                ],
            )
            .await?;
        let (added_lines, deleted_lines) = parse_numstat(&output)?;
        Ok(RevisionComparison {
            kind: RevisionComparisonKind::Histogram as i32,
            histogram: Some(RevisionHistogram {
                added_lines,
                deleted_lines,
                changed_files: u64::from(added_lines != 0 || deleted_lines != 0),
            }),
            line_diff: Vec::new(),
        })
    }

    pub async fn compare_line_diff(
        &self,
        repository_id: &str,
        base: &str,
        target: &str,
    ) -> Result<RevisionComparison, GitError> {
        let repository = self.existing_repository(repository_id)?;
        let output = self
            .git(
                &repository,
                &[
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-color",
                    "--diff-algorithm=histogram",
                    "--unified=3",
                    base,
                    target,
                    "--",
                    CONTENT_ENTRY_NAME,
                ],
            )
            .await?;
        let line_diff = parse_line_diff(&output)?;
        let comparison = RevisionComparison {
            kind: RevisionComparisonKind::LineDiff as i32,
            histogram: None,
            line_diff,
        };
        if comparison.encoded_len() > MAX_LINE_DIFF_OUTPUT_BYTES {
            return Err(GitError::OutputTooLarge);
        }
        Ok(comparison)
    }

    pub async fn reconcile_ref(
        &self,
        repository_id: &str,
        expected_old: &str,
        new: &str,
    ) -> Result<ReconcileRevisionRefResult, GitError> {
        let repository = self.existing_repository(repository_id)?;
        let previous = if expected_old.is_empty() {
            ZERO_SHA256_OID
        } else {
            expected_old
        };
        match self
            .git(&repository, &["update-ref", FILEBOLT_REF, new, previous])
            .await
        {
            Ok(_) => Ok(ReconcileRevisionRefResult {
                advanced: true,
                observed_commit_oid: new.into(),
            }),
            Err(GitError::Failed) => Ok(ReconcileRevisionRefResult {
                advanced: false,
                observed_commit_oid: self.current_ref(&repository).await?.unwrap_or_default(),
            }),
            Err(error) => Err(error),
        }
    }

    pub async fn verify(
        &self,
        repository_id: &str,
    ) -> Result<VerifyRevisionRepositoryResult, GitError> {
        let repository = self.existing_repository(repository_id)?;
        self.git(
            &repository,
            &["fsck", "--strict", "--no-dangling", "--no-reflogs"],
        )
        .await
        .map_err(|_| GitError::Integrity)?;
        let (loose_objects, packed_objects, _) = self.measure(&repository).await?;
        Ok(VerifyRevisionRepositoryResult {
            head_commit_oid: self.current_ref(&repository).await?.unwrap_or_default(),
            loose_objects,
            packed_objects,
        })
    }

    pub async fn maintain(
        &self,
        repository_id: &str,
    ) -> Result<MaintainRevisionRepositoryResult, GitError> {
        let repository = self.existing_repository(repository_id)?;
        self.git(&repository, &["maintenance", "run", "--auto"])
            .await?;
        let (loose_objects, packed_objects, size_kib) = self.measure(&repository).await?;
        Ok(MaintainRevisionRepositoryResult {
            loose_objects,
            packed_objects,
            size_kib,
        })
    }

    pub async fn delete(&self, repository_id: &str) -> Result<bool, GitError> {
        let repository = self.repository_path(repository_id)?;
        if !repository.exists() {
            return Ok(false);
        }
        if std::fs::symlink_metadata(&repository)
            .map_err(|_| GitError::Io)?
            .file_type()
            .is_symlink()
        {
            return Err(GitError::Integrity);
        }
        std::fs::remove_dir_all(repository).map_err(|_| GitError::Io)?;
        Ok(true)
    }

    async fn ensure_repository(&self, repository_id: &str) -> Result<PathBuf, GitError> {
        let repository = self.repository_path(repository_id)?;
        std::fs::create_dir_all(&self.root).map_err(|_| GitError::Io)?;
        if repository.exists() {
            return self.existing_repository(repository_id);
        }
        self.run_raw(
            &[
                "init",
                "--bare",
                "--object-format=sha256",
                repository.to_str().ok_or(GitError::Invalid)?,
            ],
            &[],
        )
        .await?;
        self.git(&repository, &["symbolic-ref", "HEAD", FILEBOLT_REF])
            .await?;
        Ok(repository)
    }

    fn existing_repository(&self, repository_id: &str) -> Result<PathBuf, GitError> {
        let repository = self.repository_path(repository_id)?;
        if !repository.is_dir() {
            return Err(GitError::NotFound);
        }
        if std::fs::symlink_metadata(&repository)
            .map_err(|_| GitError::Io)?
            .file_type()
            .is_symlink()
        {
            return Err(GitError::Integrity);
        }
        Ok(repository)
    }

    fn repository_path(&self, repository_id: &str) -> Result<PathBuf, GitError> {
        Uuid::parse_str(repository_id).map_err(|_| GitError::Invalid)?;
        Ok(self.root.join(format!("{repository_id}.git")))
    }

    async fn current_ref(&self, repository: &Path) -> Result<Option<String>, GitError> {
        match self
            .git(
                repository,
                &["rev-parse", "--verify", "--quiet", FILEBOLT_REF],
            )
            .await
        {
            Ok(value) => {
                validate_oid(&value).map_err(|_| GitError::Integrity)?;
                Ok(Some(value))
            }
            Err(GitError::Failed) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn measure(&self, repository: &Path) -> Result<(u64, u64, u64), GitError> {
        let output = self.git(repository, &["count-objects", "-v"]).await?;
        let mut loose = None;
        let mut packed = None;
        let mut loose_size_kib = None::<u64>;
        let mut size_kib = None::<u64>;
        for line in output.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key {
                "count" => loose = value.trim().parse().ok(),
                "in-pack" => packed = value.trim().parse().ok(),
                "size" => loose_size_kib = value.trim().parse().ok(),
                "size-pack" => size_kib = value.trim().parse().ok(),
                _ => {}
            }
        }
        Ok((
            loose.ok_or(GitError::Integrity)?,
            packed.ok_or(GitError::Integrity)?,
            loose_size_kib
                .ok_or(GitError::Integrity)?
                .checked_add(size_kib.ok_or(GitError::Integrity)?)
                .ok_or(GitError::Integrity)?,
        ))
    }

    async fn git(&self, repository: &Path, args: &[&str]) -> Result<String, GitError> {
        String::from_utf8(
            self.git_bytes_limited(repository, args, MAX_GIT_OUTPUT_BYTES)
                .await?,
        )
        .map(|value| value.trim_end_matches('\n').into())
        .map_err(|_| GitError::Integrity)
    }

    async fn git_bytes_limited(
        &self,
        repository: &Path,
        args: &[&str],
        maximum_output: usize,
    ) -> Result<Vec<u8>, GitError> {
        self.git_bytes_with_env(repository, args, &[], &[], maximum_output)
            .await
    }

    async fn git_input(
        &self,
        repository: &Path,
        args: &[&str],
        input: &[u8],
    ) -> Result<String, GitError> {
        String::from_utf8(
            self.git_bytes_with_env(repository, args, input, &[], MAX_GIT_OUTPUT_BYTES)
                .await?,
        )
        .map(|value| value.trim_end_matches('\n').into())
        .map_err(|_| GitError::Integrity)
    }

    async fn git_input_with_env(
        &self,
        repository: &Path,
        args: &[&str],
        input: &[u8],
        extra_env: &[(&str, &str)],
    ) -> Result<String, GitError> {
        String::from_utf8(
            self.git_bytes_with_env(repository, args, input, extra_env, MAX_GIT_OUTPUT_BYTES)
                .await?,
        )
        .map(|value| value.trim_end_matches('\n').into())
        .map_err(|_| GitError::Integrity)
    }

    async fn git_bytes_with_env(
        &self,
        repository: &Path,
        args: &[&str],
        input: &[u8],
        extra_env: &[(&str, &str)],
        maximum_output: usize,
    ) -> Result<Vec<u8>, GitError> {
        let mut command = self.command(repository, args, extra_env);
        command.kill_on_drop(true);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| GitError::Io)?;
        let mut stdin = child.stdin.take().ok_or(GitError::Io)?;
        let stdout = child.stdout.take().ok_or(GitError::Io)?;
        let stderr = child.stderr.take().ok_or(GitError::Io)?;
        let result = timeout(GIT_COMMAND_TIMEOUT, async move {
            let write = async move {
                stdin.write_all(input).await.map_err(|_| GitError::Io)?;
                stdin.shutdown().await.map_err(|_| GitError::Io)
            };
            let wait = async { child.wait().await.map_err(|_| GitError::Io) };
            let ((), stdout, stderr, status) = tokio::try_join!(
                write,
                read_limited(stdout, maximum_output),
                read_limited(stderr, maximum_output),
                wait,
            )?;
            Ok::<_, GitError>((stdout, stderr, status.success()))
        })
        .await
        .map_err(|_| GitError::TimedOut)??;
        checked_output(result.0, result.1, result.2, maximum_output)
    }

    async fn run_raw(
        &self,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Result<Vec<u8>, GitError> {
        let result = timeout(
            GIT_COMMAND_TIMEOUT,
            Command::new(&self.git)
                .args(args)
                .envs(git_environment())
                .envs(extra_env.iter().copied())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .map_err(|_| GitError::TimedOut)?
        .map_err(|_| GitError::Io)?;
        checked_output(
            result.stdout,
            result.stderr,
            result.status.success(),
            MAX_GIT_OUTPUT_BYTES,
        )
    }

    fn command(&self, repository: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Command {
        let mut command = Command::new(&self.git);
        command.arg(format!("--git-dir={}", repository.display()));
        command.args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesfile=/dev/null",
            "-c",
            "diff.external=false",
            "-c",
            "filter.lfs.required=false",
            "-c",
            "advice.detachedHead=false",
        ]);
        command
            .args(args)
            .envs(git_environment())
            .envs(extra_env.iter().copied());
        command
    }
}

fn git_environment() -> [(&'static str, &'static str); 7] {
    [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_ALLOW_PROTOCOL", ""),
    ]
}

fn checked_output(
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    success: bool,
    maximum_output: usize,
) -> Result<Vec<u8>, GitError> {
    if stdout.len().saturating_add(stderr.len()) > maximum_output {
        return Err(GitError::OutputTooLarge);
    }
    if !success {
        return Err(GitError::Failed);
    }
    Ok(stdout)
}

async fn read_limited<R: AsyncRead + Unpin>(
    mut reader: R,
    maximum_output: usize,
) -> Result<Vec<u8>, GitError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await.map_err(|_| GitError::Io)?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > maximum_output {
            return Err(GitError::OutputTooLarge);
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn parse_tree_entry(value: &str) -> Option<(&str, &str, &str, &str)> {
    let (left, name) = value.trim_end_matches('\n').split_once('\t')?;
    let mut fields = left.split_ascii_whitespace();
    Some((fields.next()?, fields.next()?, fields.next()?, name))
}

fn parse_numstat(value: &str) -> Result<(u64, u64), GitError> {
    if value.is_empty() {
        return Ok((0, 0));
    }
    let mut fields = value.trim_end_matches('\n').split('\t');
    let added = fields
        .next()
        .ok_or(GitError::Integrity)?
        .parse()
        .map_err(|_| GitError::Integrity)?;
    let deleted = fields
        .next()
        .ok_or(GitError::Integrity)?
        .parse()
        .map_err(|_| GitError::Integrity)?;
    let name = fields.next().ok_or(GitError::Integrity)?;
    if fields.next().is_some() || name != CONTENT_ENTRY_NAME {
        return Err(GitError::Integrity);
    }
    Ok((added, deleted))
}

fn parse_line_diff(value: &str) -> Result<Vec<RevisionLineDiffHunk>, GitError> {
    let mut hunks = Vec::new();
    let mut current: Option<RevisionLineDiffHunk> = None;
    let mut line_count = 0_usize;

    for line in value.lines() {
        if let Some(header) = line.strip_prefix("@@ ") {
            if let Some(hunk) = current.take() {
                hunks.push(hunk);
            }
            if hunks.len() == filebelt_revision_protocol::MAX_LINE_DIFF_HUNKS {
                return Err(GitError::OutputTooLarge);
            }
            let (old_start, old_lines, new_start, new_lines) = parse_hunk_header(header)?;
            current = Some(RevisionLineDiffHunk {
                old_start,
                old_lines,
                new_start,
                new_lines,
                lines: Vec::new(),
            });
            continue;
        }
        let Some(hunk) = current.as_mut() else {
            continue;
        };
        let (kind, text) = match line.as_bytes().first() {
            Some(b' ') => (RevisionLineKind::Context, &line[1..]),
            Some(b'+') => (RevisionLineKind::Added, &line[1..]),
            Some(b'-') => (RevisionLineKind::Deleted, &line[1..]),
            Some(b'\\') => continue,
            _ => return Err(GitError::Integrity),
        };
        if line_count == MAX_LINE_DIFF_LINES {
            return Err(GitError::OutputTooLarge);
        }
        hunk.lines.push(RevisionLine {
            kind: kind as i32,
            text: text.into(),
        });
        line_count += 1;
    }
    if let Some(hunk) = current {
        hunks.push(hunk);
    }
    Ok(hunks)
}

fn parse_hunk_header(value: &str) -> Result<(u64, u64, u64, u64), GitError> {
    let mut parts = value.split_ascii_whitespace();
    let old = parts.next().ok_or(GitError::Integrity)?;
    let new = parts.next().ok_or(GitError::Integrity)?;
    if parts.next() != Some("@@") || parts.next().is_some() {
        return Err(GitError::Integrity);
    }
    let (old_start, old_lines) = parse_hunk_range(old, '-')?;
    let (new_start, new_lines) = parse_hunk_range(new, '+')?;
    Ok((old_start, old_lines, new_start, new_lines))
}

fn parse_hunk_range(value: &str, sign: char) -> Result<(u64, u64), GitError> {
    let value = value.strip_prefix(sign).ok_or(GitError::Integrity)?;
    let (start, lines) = match value.split_once(',') {
        Some((start, lines)) => (start, lines),
        None => (value, "1"),
    };
    Ok((
        start.parse().map_err(|_| GitError::Integrity)?,
        lines.parse().map_err(|_| GitError::Integrity)?,
    ))
}

/// Executes one already-authenticated adapter request.
pub async fn dispatch(
    repository: &GitRepository,
    request: RevisionExecuteRequest,
) -> RevisionExecuteResponse {
    let request_id = request.request_id.clone();
    let result = match validate_request(&request) {
        Err(_) => Err(GitError::Invalid),
        Ok(()) => match request.operation.expect("validated operation") {
            revision_execute_request::Operation::PrepareCommit(operation) => repository
                .prepare_commit(
                    &operation.repository_id,
                    &operation.version_id,
                    operation.ordinal,
                    operation.committed_at_unix_seconds,
                    &operation.content,
                    &operation.expected_old_commit_oid,
                    operation.migration_import,
                )
                .await
                .map(revision_execute_response::Result::PreparedCommit),
            revision_execute_request::Operation::ReadBlob(operation) => repository
                .read_blob(&operation.repository_id, &operation.commit_oid)
                .await
                .map(revision_execute_response::Result::Blob),
            revision_execute_request::Operation::CompareCommits(operation) => {
                match RevisionComparisonKind::try_from(operation.kind).ok() {
                    Some(RevisionComparisonKind::Histogram) => repository
                        .compare_histogram(
                            &operation.repository_id,
                            &operation.base_commit_oid,
                            &operation.target_commit_oid,
                        )
                        .await
                        .map(revision_execute_response::Result::Comparison),
                    Some(RevisionComparisonKind::LineDiff) => repository
                        .compare_line_diff(
                            &operation.repository_id,
                            &operation.base_commit_oid,
                            &operation.target_commit_oid,
                        )
                        .await
                        .map(revision_execute_response::Result::Comparison),
                    _ => Err(GitError::Invalid),
                }
            }
            revision_execute_request::Operation::ReconcileRef(operation) => repository
                .reconcile_ref(
                    &operation.repository_id,
                    &operation.expected_old_commit_oid,
                    &operation.new_commit_oid,
                )
                .await
                .map(revision_execute_response::Result::ReconcileResult),
            revision_execute_request::Operation::VerifyRepository(operation) => repository
                .verify(&operation.repository_id)
                .await
                .map(revision_execute_response::Result::VerifyResult),
            revision_execute_request::Operation::MaintainRepository(operation) => repository
                .maintain(&operation.repository_id)
                .await
                .map(revision_execute_response::Result::MaintainResult),
            revision_execute_request::Operation::DeleteRepository(operation) => repository
                .delete(&operation.repository_id)
                .await
                .map(|deleted| {
                    revision_execute_response::Result::DeleteResult(
                        filebelt_revision_protocol::DeleteRevisionRepositoryResult { deleted },
                    )
                }),
        },
    };
    RevisionExecuteResponse {
        request_id,
        result: Some(result.unwrap_or_else(|error| {
            revision_execute_response::Result::Error(error_response(error))
        })),
    }
}

fn error_response(error: GitError) -> RevisionError {
    let code = match error {
        GitError::Invalid | GitError::WrongVersion => RevisionErrorCode::InvalidRequest,
        GitError::NotFound => RevisionErrorCode::NotFound,
        GitError::Conflict => RevisionErrorCode::Conflict,
        GitError::OutputTooLarge => RevisionErrorCode::ResourceExhausted,
        GitError::TimedOut | GitError::Io => RevisionErrorCode::Unavailable,
        GitError::Integrity => RevisionErrorCode::IntegrityFailure,
        GitError::Failed => RevisionErrorCode::Internal,
    };
    RevisionError {
        code: code as i32,
        message: code.as_str_name().into(),
        retry_after_millis: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filebelt_revision_protocol::{
        PrepareRevisionCommit, ReconcileRevisionRef, revision_execute_request::Operation,
    };

    #[tokio::test]
    async fn sha256_repository_has_deterministic_single_entry_commits() {
        let temporary =
            std::env::temp_dir().join(format!("filebelt-git-adapter-{}", Uuid::new_v4()));
        let repository = GitRepository::new(&temporary, "git");
        let repo_id = "550e8400-e29b-41d4-a716-446655440000";
        let first = repository
            .prepare_commit(
                repo_id,
                "550e8400-e29b-41d4-a716-446655440001",
                1,
                1_700_000_000,
                b"first\n",
                "",
                false,
            )
            .await
            .unwrap();
        assert_eq!(first.commit_oid.len(), 64);
        assert!(
            repository
                .reconcile_ref(repo_id, "", &first.commit_oid)
                .await
                .unwrap()
                .advanced
        );
        let blob = repository
            .read_blob(repo_id, &first.commit_oid)
            .await
            .unwrap();
        assert_eq!(blob.content, b"first\n");
        assert!(
            !repository
                .reconcile_ref(repo_id, "", &first.commit_oid)
                .await
                .unwrap()
                .advanced
        );
        std::fs::remove_dir_all(temporary).unwrap();
    }

    #[tokio::test]
    async fn histogram_line_diff_is_typed_and_has_three_context_lines() {
        let temporary =
            std::env::temp_dir().join(format!("filebelt-git-adapter-{}", Uuid::new_v4()));
        let repository = GitRepository::new(&temporary, "git");
        let repo_id = "550e8400-e29b-41d4-a716-446655440000";
        let first = repository
            .prepare_commit(
                repo_id,
                "550e8400-e29b-41d4-a716-446655440001",
                1,
                1_700_000_000,
                b"one\ntwo\nthree\nfour\nfive\nsix\nseven\n",
                "",
                false,
            )
            .await
            .unwrap();
        let second = repository
            .prepare_commit(
                repo_id,
                "550e8400-e29b-41d4-a716-446655440002",
                2,
                1_700_000_001,
                b"one\ntwo\nthree\nFOUR\nfive\nsix\nseven\n",
                &first.commit_oid,
                false,
            )
            .await
            .unwrap();
        let comparison = repository
            .compare_line_diff(repo_id, &first.commit_oid, &second.commit_oid)
            .await
            .unwrap();
        assert_eq!(comparison.kind, RevisionComparisonKind::LineDiff as i32);
        assert_eq!(comparison.line_diff.len(), 1);
        let lines = &comparison.line_diff[0].lines;
        assert_eq!(lines.len(), 8);
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.kind == RevisionLineKind::Context as i32)
                .count(),
            6
        );
        assert!(
            lines
                .iter()
                .any(|line| line.kind == RevisionLineKind::Deleted as i32 && line.text == "four")
        );
        assert!(
            lines
                .iter()
                .any(|line| line.kind == RevisionLineKind::Added as i32 && line.text == "FOUR")
        );
        std::fs::remove_dir_all(temporary).unwrap();
    }

    #[tokio::test]
    async fn prepare_rejects_non_text_or_an_oversize_edit() {
        let repository = GitRepository::new("/nonexistent", "git");
        let repository_id = "550e8400-e29b-41d4-a716-446655440000";
        let version_id = "550e8400-e29b-41d4-a716-446655440001";
        assert!(matches!(
            repository
                .prepare_commit(repository_id, version_id, 1, 0, &[0xff], "", false)
                .await,
            Err(GitError::Invalid)
        ));
        assert!(matches!(
            repository
                .prepare_commit(
                    repository_id,
                    version_id,
                    1,
                    0,
                    &vec![b'x'; filebelt_revision_protocol::MAX_EDIT_BYTES + 1],
                    "",
                    false,
                )
                .await,
            Err(GitError::Invalid)
        ));
    }

    #[tokio::test]
    async fn dispatcher_rejects_unvalidated_input_before_git_execution() {
        let repository = GitRepository::new("/nonexistent", "git");
        let response = dispatch(
            &repository,
            RevisionExecuteRequest {
                request_id: "x".into(),
                operation: Some(Operation::ReconcileRef(ReconcileRevisionRef {
                    repository_id: "not-a-uuid".into(),
                    expected_old_commit_oid: String::new(),
                    new_commit_oid: "0".repeat(64),
                })),
            },
        )
        .await;
        assert!(matches!(
            response.result,
            Some(revision_execute_response::Result::Error(_))
        ));
        let _ = PrepareRevisionCommit::default();
    }
}

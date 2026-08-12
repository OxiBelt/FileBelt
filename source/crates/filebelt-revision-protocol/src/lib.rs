// SPDX-License-Identifier: Apache-2.0

//! Bounded, provider-neutral frames for the isolated revision-store adapter.

#![deny(unsafe_code)]

use std::io::{Read, Write};

use prost::Message as _;
use thiserror::Error;
use uuid::Uuid;

mod generated {
    include!("../../../../protocol/generated/rust/filebelt/revision/v1/filebelt.revision.v1.rs");
}

pub use generated::*;
pub use generated::{revision_execute_request, revision_execute_response};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_TEXT_BYTES: usize = 100 * 1024 * 1024;
pub const MAX_EDIT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = MAX_TEXT_BYTES + 4096;
pub const MAX_LINE_DIFF_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_REQUEST_ID_BYTES: usize = 128;
pub const MAX_LINE_DIFF_HUNKS: usize = 4_096;
pub const MAX_LINE_DIFF_LINES: usize = 50_000;
pub const FILEBOLT_REF: &str = "refs/heads/filebelt";
pub const CONTENT_ENTRY_NAME: &str = "content";

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FrameError {
    #[error("frame exceeds the configured limit")]
    TooLarge,
    #[error("frame has an invalid length prefix")]
    InvalidLength,
    #[error("frame cannot be decoded")]
    Decode,
    #[error("frame cannot be encoded")]
    Encode,
    #[error("I/O failed")]
    Io,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("request ID is invalid")]
    RequestId,
    #[error("request has no operation")]
    MissingOperation,
    #[error("repository or version identifier is invalid")]
    Identifier,
    #[error("Git object ID is invalid")]
    ObjectId,
    #[error("content exceeds the configured limit")]
    ContentTooLarge,
    #[error("content is not valid text")]
    ContentNotText,
    #[error("commit timestamp is invalid")]
    Timestamp,
    #[error("comparison is invalid")]
    Comparison,
    #[error("response does not match its request")]
    ResponseMismatch,
    #[error("adapter error is invalid")]
    Error,
}

/// Encodes one deterministic length-delimited protobuf frame.
pub fn encode_frame<M: prost::Message>(message: &M) -> Result<Vec<u8>, FrameError> {
    let body = message.encode_to_vec();
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge)?;
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decodes exactly one bounded length-delimited protobuf frame.
pub fn decode_frame<M: prost::Message + Default>(frame: &[u8]) -> Result<M, FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::InvalidLength);
    }
    let length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| FrameError::InvalidLength)?,
    ) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    if frame.len() != length + 4 {
        return Err(FrameError::InvalidLength);
    }
    M::decode(&frame[4..]).map_err(|_| FrameError::Decode)
}

pub fn read_frame<M: prost::Message + Default>(reader: &mut impl Read) -> Result<M, FrameError> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).map_err(|_| FrameError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).map_err(|_| FrameError::Io)?;
    M::decode(body.as_slice()).map_err(|_| FrameError::Decode)
}

pub fn write_frame<M: prost::Message>(
    writer: &mut impl Write,
    message: &M,
) -> Result<(), FrameError> {
    let frame = encode_frame(message)?;
    writer.write_all(&frame).map_err(|_| FrameError::Io)
}

pub fn validate_request(request: &RevisionExecuteRequest) -> Result<(), ValidationError> {
    validate_request_id(&request.request_id)?;
    match request
        .operation
        .as_ref()
        .ok_or(ValidationError::MissingOperation)?
    {
        revision_execute_request::Operation::PrepareCommit(operation) => {
            validate_uuid(&operation.repository_id)?;
            validate_uuid(&operation.version_id)?;
            validate_optional_oid(&operation.expected_old_commit_oid)?;
            if operation.migration_import {
                validate_read_text(&operation.content)?;
            } else {
                validate_edit_text(&operation.content)?;
            }
            if !(0..=4_102_444_800).contains(&operation.committed_at_unix_seconds) {
                return Err(ValidationError::Timestamp);
            }
        }
        revision_execute_request::Operation::ReadBlob(operation) => {
            validate_uuid(&operation.repository_id)?;
            validate_oid(&operation.commit_oid)?;
        }
        revision_execute_request::Operation::CompareCommits(operation) => {
            validate_uuid(&operation.repository_id)?;
            validate_oid(&operation.base_commit_oid)?;
            validate_oid(&operation.target_commit_oid)?;
            if RevisionComparisonKind::try_from(operation.kind).ok()
                != Some(RevisionComparisonKind::Histogram)
                && RevisionComparisonKind::try_from(operation.kind).ok()
                    != Some(RevisionComparisonKind::LineDiff)
            {
                return Err(ValidationError::Comparison);
            }
        }
        revision_execute_request::Operation::ReconcileRef(operation) => {
            validate_uuid(&operation.repository_id)?;
            validate_optional_oid(&operation.expected_old_commit_oid)?;
            validate_oid(&operation.new_commit_oid)?;
        }
        revision_execute_request::Operation::VerifyRepository(operation) => {
            validate_uuid(&operation.repository_id)?
        }
        revision_execute_request::Operation::MaintainRepository(operation) => {
            validate_uuid(&operation.repository_id)?
        }
        revision_execute_request::Operation::DeleteRepository(operation) => {
            validate_uuid(&operation.repository_id)?
        }
    }
    Ok(())
}

pub fn validate_response(
    request: &RevisionExecuteRequest,
    response: &RevisionExecuteResponse,
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
    if let revision_execute_response::Result::Error(error) = result {
        return validate_error(error);
    }
    match (operation, result) {
        (
            revision_execute_request::Operation::PrepareCommit(_),
            revision_execute_response::Result::PreparedCommit(prepared),
        ) => {
            validate_oid(&prepared.commit_oid)?;
            validate_oid(&prepared.blob_oid)?;
            validate_oid(&prepared.tree_oid)?;
            i64::try_from(prepared.repository_size_kib)
                .ok()
                .and_then(|size| size.checked_mul(1024))
                .ok_or(ValidationError::Identifier)?;
            Ok(())
        }
        (
            revision_execute_request::Operation::ReadBlob(operation),
            revision_execute_response::Result::Blob(blob),
        ) => {
            if blob.commit_oid != operation.commit_oid {
                return Err(ValidationError::ResponseMismatch);
            }
            validate_oid(&blob.commit_oid)?;
            validate_oid(&blob.blob_oid)?;
            validate_read_text(&blob.content)
        }
        (
            revision_execute_request::Operation::CompareCommits(operation),
            revision_execute_response::Result::Comparison(comparison),
        ) => validate_comparison(operation, comparison),
        (
            revision_execute_request::Operation::ReconcileRef(operation),
            revision_execute_response::Result::ReconcileResult(result),
        ) => {
            validate_optional_oid(&result.observed_commit_oid)?;
            if result.advanced && result.observed_commit_oid != operation.new_commit_oid {
                return Err(ValidationError::ResponseMismatch);
            }
            Ok(())
        }
        (
            revision_execute_request::Operation::VerifyRepository(_),
            revision_execute_response::Result::VerifyResult(result),
        ) => {
            validate_optional_oid(&result.head_commit_oid)?;
            result
                .loose_objects
                .checked_add(result.packed_objects)
                .ok_or(ValidationError::Identifier)?;
            Ok(())
        }
        (
            revision_execute_request::Operation::MaintainRepository(_),
            revision_execute_response::Result::MaintainResult(result),
        ) => {
            result
                .loose_objects
                .checked_add(result.packed_objects)
                .ok_or(ValidationError::Identifier)?;
            i64::try_from(result.size_kib)
                .ok()
                .and_then(|size| size.checked_mul(1024))
                .ok_or(ValidationError::Identifier)?;
            Ok(())
        }
        (
            revision_execute_request::Operation::DeleteRepository(_),
            revision_execute_response::Result::DeleteResult(_),
        ) => Ok(()),
        _ => Err(ValidationError::ResponseMismatch),
    }
}

fn validate_error(error: &RevisionError) -> Result<(), ValidationError> {
    match RevisionErrorCode::try_from(error.code).ok() {
        Some(RevisionErrorCode::InvalidRequest)
        | Some(RevisionErrorCode::NotFound)
        | Some(RevisionErrorCode::Conflict)
        | Some(RevisionErrorCode::ResourceExhausted)
        | Some(RevisionErrorCode::Unavailable)
        | Some(RevisionErrorCode::IntegrityFailure)
        | Some(RevisionErrorCode::Internal) => Ok(()),
        Some(RevisionErrorCode::Unspecified) | None => Err(ValidationError::Error),
    }
}

fn validate_comparison(
    request: &CompareRevisionCommits,
    comparison: &RevisionComparison,
) -> Result<(), ValidationError> {
    let requested_kind =
        RevisionComparisonKind::try_from(request.kind).map_err(|_| ValidationError::Comparison)?;
    let response_kind = RevisionComparisonKind::try_from(comparison.kind)
        .map_err(|_| ValidationError::Comparison)?;
    if response_kind != requested_kind {
        return Err(ValidationError::ResponseMismatch);
    }
    match response_kind {
        RevisionComparisonKind::Histogram => {
            let histogram = comparison
                .histogram
                .as_ref()
                .ok_or(ValidationError::Comparison)?;
            if !comparison.line_diff.is_empty()
                || histogram
                    .added_lines
                    .checked_add(histogram.deleted_lines)
                    .is_none()
                || histogram.changed_files
                    != u64::from(histogram.added_lines != 0 || histogram.deleted_lines != 0)
            {
                return Err(ValidationError::Comparison);
            }
        }
        RevisionComparisonKind::LineDiff => validate_line_diff(comparison)?,
        RevisionComparisonKind::Unspecified => return Err(ValidationError::Comparison),
    }
    Ok(())
}

fn validate_line_diff(comparison: &RevisionComparison) -> Result<(), ValidationError> {
    if comparison.histogram.is_some()
        || comparison.line_diff.len() > MAX_LINE_DIFF_HUNKS
        || comparison.encoded_len() > MAX_LINE_DIFF_OUTPUT_BYTES
    {
        return Err(ValidationError::Comparison);
    }
    let mut total_lines = 0_usize;
    for hunk in &comparison.line_diff {
        let mut old_lines = 0_u64;
        let mut new_lines = 0_u64;
        for line in &hunk.lines {
            total_lines = total_lines
                .checked_add(1)
                .ok_or(ValidationError::Comparison)?;
            if total_lines > MAX_LINE_DIFF_LINES
                || line.text.len() > 1_048_576
                || line.text.as_bytes().contains(&0)
            {
                return Err(ValidationError::Comparison);
            }
            match RevisionLineKind::try_from(line.kind).ok() {
                Some(RevisionLineKind::Context) => {
                    old_lines = old_lines
                        .checked_add(1)
                        .ok_or(ValidationError::Comparison)?;
                    new_lines = new_lines
                        .checked_add(1)
                        .ok_or(ValidationError::Comparison)?;
                }
                Some(RevisionLineKind::Added) => {
                    new_lines = new_lines
                        .checked_add(1)
                        .ok_or(ValidationError::Comparison)?;
                }
                Some(RevisionLineKind::Deleted) => {
                    old_lines = old_lines
                        .checked_add(1)
                        .ok_or(ValidationError::Comparison)?;
                }
                Some(RevisionLineKind::Unspecified) | None => {
                    return Err(ValidationError::Comparison);
                }
            }
        }
        if old_lines != hunk.old_lines
            || new_lines != hunk.new_lines
            || hunk.old_start.checked_add(hunk.old_lines).is_none()
            || hunk.new_start.checked_add(hunk.new_lines).is_none()
        {
            return Err(ValidationError::Comparison);
        }
    }
    Ok(())
}

fn validate_request_id(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > MAX_REQUEST_ID_BYTES || !value.is_ascii() {
        return Err(ValidationError::RequestId);
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<(), ValidationError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| ValidationError::Identifier)
}

pub fn validate_oid(value: &str) -> Result<(), ValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ValidationError::ObjectId);
    }
    Ok(())
}

/// Validates UTF-8 text accepted for a mutable revision edit.
pub fn validate_edit_text(value: &[u8]) -> Result<(), ValidationError> {
    validate_text(value, MAX_EDIT_BYTES)
}

/// Validates UTF-8 text returned from an immutable revision read.
pub fn validate_read_text(value: &[u8]) -> Result<(), ValidationError> {
    validate_text(value, MAX_TEXT_BYTES)
}

fn validate_text(value: &[u8], maximum: usize) -> Result<(), ValidationError> {
    if value.len() > maximum {
        return Err(ValidationError::ContentTooLarge);
    }
    if value.contains(&0) {
        return Err(ValidationError::ContentNotText);
    }
    std::str::from_utf8(value)
        .map(|_| ())
        .map_err(|_| ValidationError::ContentNotText)
}

fn validate_optional_oid(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        Ok(())
    } else {
        validate_oid(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const OID_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn request() -> RevisionExecuteRequest {
        RevisionExecuteRequest {
            request_id: "revision-request-1".into(),
            operation: Some(revision_execute_request::Operation::PrepareCommit(
                PrepareRevisionCommit {
                    repository_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                    version_id: "550e8400-e29b-41d4-a716-446655440001".into(),
                    ordinal: 7,
                    committed_at_unix_seconds: 1_700_000_000,
                    content: b"bounded content".to_vec(),
                    expected_old_commit_oid: String::new(),
                    migration_import: false,
                },
            )),
        }
    }

    fn request_with(operation: revision_execute_request::Operation) -> RevisionExecuteRequest {
        RevisionExecuteRequest {
            request_id: "revision-request-1".into(),
            operation: Some(operation),
        }
    }

    fn response_with(result: revision_execute_response::Result) -> RevisionExecuteResponse {
        RevisionExecuteResponse {
            request_id: "revision-request-1".into(),
            result: Some(result),
        }
    }

    fn valid_pairs() -> Vec<(RevisionExecuteRequest, RevisionExecuteResponse)> {
        let repository_id = "550e8400-e29b-41d4-a716-446655440000".to_owned();
        vec![
            (
                request(),
                response_with(revision_execute_response::Result::PreparedCommit(
                    PreparedRevisionCommit {
                        commit_oid: OID_A.into(),
                        blob_oid: OID_B.into(),
                        tree_oid: OID_C.into(),
                        repository_size_kib: 4,
                    },
                )),
            ),
            (
                request_with(revision_execute_request::Operation::ReadBlob(
                    ReadRevisionBlob {
                        repository_id: repository_id.clone(),
                        commit_oid: OID_A.into(),
                    },
                )),
                response_with(revision_execute_response::Result::Blob(RevisionBlob {
                    commit_oid: OID_A.into(),
                    blob_oid: OID_B.into(),
                    content: b"text\n".to_vec(),
                })),
            ),
            (
                request_with(revision_execute_request::Operation::CompareCommits(
                    CompareRevisionCommits {
                        repository_id: repository_id.clone(),
                        base_commit_oid: OID_A.into(),
                        target_commit_oid: OID_B.into(),
                        kind: RevisionComparisonKind::Histogram as i32,
                    },
                )),
                response_with(revision_execute_response::Result::Comparison(
                    RevisionComparison {
                        kind: RevisionComparisonKind::Histogram as i32,
                        histogram: Some(RevisionHistogram {
                            added_lines: 1,
                            deleted_lines: 0,
                            changed_files: 1,
                        }),
                        line_diff: Vec::new(),
                    },
                )),
            ),
            (
                request_with(revision_execute_request::Operation::ReconcileRef(
                    ReconcileRevisionRef {
                        repository_id: repository_id.clone(),
                        expected_old_commit_oid: OID_A.into(),
                        new_commit_oid: OID_B.into(),
                    },
                )),
                response_with(revision_execute_response::Result::ReconcileResult(
                    ReconcileRevisionRefResult {
                        advanced: true,
                        observed_commit_oid: OID_B.into(),
                    },
                )),
            ),
            (
                request_with(revision_execute_request::Operation::VerifyRepository(
                    VerifyRevisionRepository {
                        repository_id: repository_id.clone(),
                    },
                )),
                response_with(revision_execute_response::Result::VerifyResult(
                    VerifyRevisionRepositoryResult {
                        head_commit_oid: OID_A.into(),
                        loose_objects: 3,
                        packed_objects: 4,
                    },
                )),
            ),
            (
                request_with(revision_execute_request::Operation::MaintainRepository(
                    MaintainRevisionRepository {
                        repository_id: repository_id.clone(),
                    },
                )),
                response_with(revision_execute_response::Result::MaintainResult(
                    MaintainRevisionRepositoryResult {
                        loose_objects: 3,
                        packed_objects: 4,
                        size_kib: 8,
                    },
                )),
            ),
            (
                request_with(revision_execute_request::Operation::DeleteRepository(
                    DeleteRevisionRepository { repository_id },
                )),
                response_with(revision_execute_response::Result::DeleteResult(
                    DeleteRevisionRepositoryResult { deleted: true },
                )),
            ),
        ]
    }

    #[test]
    fn deterministic_bounded_frame_round_trips() {
        let request = request();
        let first = encode_frame(&request).unwrap();
        assert_eq!(first, encode_frame(&request).unwrap());
        assert_eq!(
            decode_frame::<RevisionExecuteRequest>(&first).unwrap(),
            request
        );
    }

    #[test]
    fn validation_rejects_uppercase_or_overlong_input() {
        let mut request = request();
        {
            let revision_execute_request::Operation::PrepareCommit(operation) =
                request.operation.as_mut().unwrap()
            else {
                panic!()
            };
            operation.expected_old_commit_oid = "A".repeat(64);
        }
        assert_eq!(validate_request(&request), Err(ValidationError::ObjectId));
        let revision_execute_request::Operation::PrepareCommit(operation) =
            request.operation.as_mut().unwrap()
        else {
            panic!()
        };
        operation.expected_old_commit_oid.clear();
        operation.content = vec![0; MAX_EDIT_BYTES + 1];
        assert_eq!(
            validate_request(&request),
            Err(ValidationError::ContentTooLarge)
        );
    }

    #[test]
    fn text_limits_distinguish_reads_from_edits() {
        let text = vec![b'x'; MAX_EDIT_BYTES + 1];
        assert_eq!(
            validate_edit_text(&text),
            Err(ValidationError::ContentTooLarge)
        );
        assert!(validate_read_text(&text).is_ok());
        assert_eq!(
            validate_read_text(&[0xff]),
            Err(ValidationError::ContentNotText)
        );

        let mut migration = request();
        let revision_execute_request::Operation::PrepareCommit(operation) =
            migration.operation.as_mut().unwrap()
        else {
            panic!()
        };
        operation.migration_import = true;
        operation.content = text;
        assert!(validate_request(&migration).is_ok());
    }

    #[test]
    fn text_validation_rejects_nul_without_rejecting_empty_bom_or_crlf() {
        assert_eq!(
            validate_read_text(b"prefix\0suffix"),
            Err(ValidationError::ContentNotText)
        );
        assert!(validate_edit_text(b"").is_ok());
        assert!(validate_edit_text(b"\xef\xbb\xbftext\r\n").is_ok());
    }

    #[test]
    fn response_validation_is_request_aware_for_every_operation() {
        let pairs = valid_pairs();
        for (request, response) in &pairs {
            assert_eq!(validate_response(request, response), Ok(()));
        }
        for index in 0..pairs.len() {
            let request = &pairs[index].0;
            let wrong = &pairs[(index + 1) % pairs.len()].1;
            assert_eq!(
                validate_response(request, wrong),
                Err(ValidationError::ResponseMismatch)
            );
        }
    }

    #[test]
    fn response_validation_rejects_identity_shape_and_overflow_failures() {
        let (read, mut blob_response) = valid_pairs().remove(1);
        if let Some(revision_execute_response::Result::Blob(blob)) = blob_response.result.as_mut() {
            blob.commit_oid = OID_C.into();
        } else {
            panic!()
        }
        assert_eq!(
            validate_response(&read, &blob_response),
            Err(ValidationError::ResponseMismatch)
        );
        if let Some(revision_execute_response::Result::Blob(blob)) = blob_response.result.as_mut() {
            blob.commit_oid = OID_A.into();
            blob.content = b"not\0text".to_vec();
        } else {
            panic!()
        }
        assert_eq!(
            validate_response(&read, &blob_response),
            Err(ValidationError::ContentNotText)
        );

        let (prepare, mut prepared_response) = valid_pairs().remove(0);
        let Some(revision_execute_response::Result::PreparedCommit(prepared)) =
            prepared_response.result.as_mut()
        else {
            panic!()
        };
        prepared.repository_size_kib = u64::MAX;
        assert_eq!(
            validate_response(&prepare, &prepared_response),
            Err(ValidationError::Identifier)
        );

        let mut wrong_id = valid_pairs().remove(0).1;
        wrong_id.request_id = "different-request".into();
        assert_eq!(
            validate_response(&prepare, &wrong_id),
            Err(ValidationError::ResponseMismatch)
        );
    }

    #[test]
    fn comparison_and_reconcile_results_must_be_internally_consistent() {
        let repository_id = "550e8400-e29b-41d4-a716-446655440000".to_owned();
        let comparison_request = request_with(revision_execute_request::Operation::CompareCommits(
            CompareRevisionCommits {
                repository_id: repository_id.clone(),
                base_commit_oid: OID_A.into(),
                target_commit_oid: OID_B.into(),
                kind: RevisionComparisonKind::LineDiff as i32,
            },
        ));
        let mut comparison = RevisionComparison {
            kind: RevisionComparisonKind::LineDiff as i32,
            histogram: None,
            line_diff: vec![RevisionLineDiffHunk {
                old_start: 1,
                old_lines: 1,
                new_start: 1,
                new_lines: 1,
                lines: vec![RevisionLine {
                    kind: RevisionLineKind::Context as i32,
                    text: "same".into(),
                }],
            }],
        };
        let response = response_with(revision_execute_response::Result::Comparison(
            comparison.clone(),
        ));
        assert_eq!(validate_response(&comparison_request, &response), Ok(()));
        comparison.line_diff[0].new_lines = 2;
        let response = response_with(revision_execute_response::Result::Comparison(comparison));
        assert_eq!(
            validate_response(&comparison_request, &response),
            Err(ValidationError::Comparison)
        );

        let reconcile_request = request_with(revision_execute_request::Operation::ReconcileRef(
            ReconcileRevisionRef {
                repository_id,
                expected_old_commit_oid: OID_A.into(),
                new_commit_oid: OID_B.into(),
            },
        ));
        let response = response_with(revision_execute_response::Result::ReconcileResult(
            ReconcileRevisionRefResult {
                advanced: true,
                observed_commit_oid: OID_C.into(),
            },
        ));
        assert_eq!(
            validate_response(&reconcile_request, &response),
            Err(ValidationError::ResponseMismatch)
        );
    }

    #[test]
    fn typed_errors_are_valid_for_every_request_but_unspecified_is_not() {
        for (request, _) in valid_pairs() {
            let response = response_with(revision_execute_response::Result::Error(RevisionError {
                code: RevisionErrorCode::NotFound as i32,
                message: "not found".into(),
                retry_after_millis: 0,
            }));
            assert_eq!(validate_response(&request, &response), Ok(()));
            let invalid = response_with(revision_execute_response::Result::Error(RevisionError {
                code: RevisionErrorCode::Unspecified as i32,
                message: String::new(),
                retry_after_millis: 0,
            }));
            assert_eq!(
                validate_response(&request, &invalid),
                Err(ValidationError::Error)
            );
        }
    }
}

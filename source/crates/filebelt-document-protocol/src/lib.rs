// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral document-session control-plane types.

#![deny(unsafe_code)]

use prost::Message as _;

mod generated {
    include!("../../../../protocol/generated/rust/filebelt/document/v1/filebelt.document.v1.rs");
}

pub use generated::{
    BeginDocumentRevisionCommand, CommitDocumentRevisionCommand, CreateDocumentConflictCopyCommand,
    CreateDocumentSessionCommand, DocumentAuthorizationGenerations, DocumentCallbackKind,
    DocumentCallbackReceipt, DocumentCallbackState, DocumentCommitOutcome, DocumentCommitState,
    DocumentConflictCopy, DocumentExecuteRequest, DocumentExecuteResponse, DocumentLaunch,
    DocumentLaunchGrant, DocumentParticipant, DocumentParticipantActivity,
    DocumentRevisionAdmission, DocumentRevisionKind, DocumentSession, DocumentSessionDetail,
    DocumentSessionError, DocumentSessionErrorCode, DocumentSessionMode, DocumentSessionPage,
    DocumentSessionPageAnchor, DocumentSessionState, ForceCloseDocumentSession,
    ForceCloseDocumentSessionCommand, GetDocumentSessionCommand, IssueDocumentLaunchGrantCommand,
    ListDocumentSessionsCommand, ReceiveDocumentCallbackCommand, RedeemDocumentLaunchCommand,
    RefreshDocumentSourceCommand, RevokeDocumentSession, RevokeDocumentSessionCommand,
    StartDocumentSession,
};
pub use generated::{document_execute_request, document_execute_response};

/// Encodes a provider-neutral document-session state projection.
#[must_use]
pub fn encode_session(session: &DocumentSession) -> Vec<u8> {
    session.encode_to_vec()
}

/// Decodes a provider-neutral document-session state projection.
pub fn decode_session(bytes: &[u8]) -> Result<DocumentSession, prost::DecodeError> {
    DocumentSession::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> DocumentSession {
        DocumentSession {
            session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            tenant_id: "550e8400-e29b-41d4-a716-446655440001".into(),
            drive_id: "550e8400-e29b-41d4-a716-446655440002".into(),
            node_id: "550e8400-e29b-41d4-a716-446655440003".into(),
            base_version_id: "550e8400-e29b-41d4-a716-446655440004".into(),
            principal_id: "550e8400-e29b-41d4-a716-446655440005".into(),
            api_session_id: "550e8400-e29b-41d4-a716-446655440006".into(),
            mode: DocumentSessionMode::Review as i32,
            state: DocumentSessionState::Active as i32,
            session_epoch: 1,
            resource_acl_generation: 2,
            drive_acl_generation: 3,
            membership_generation: 4,
            namespace_generation: 5,
            created_at_unix_seconds: 100,
            last_activity_at_unix_seconds: 110,
            expires_at_unix_seconds: 160,
            closed_at_unix_seconds: 0,
            conflict_head_version_id: String::new(),
        }
    }

    #[test]
    fn document_session_round_trips() {
        let expected = session();
        assert_eq!(
            decode_session(&encode_session(&expected)).unwrap(),
            expected
        );
    }

    #[test]
    fn error_codes_are_stable_and_provider_neutral() {
        for code in [
            DocumentSessionErrorCode::AuthenticationRequired,
            DocumentSessionErrorCode::AuthorizationChanged,
            DocumentSessionErrorCode::BaseVersionConflict,
            DocumentSessionErrorCode::ConflictCopyRequired,
        ] {
            let name = code.as_str_name();
            assert!(name.starts_with("DOCUMENT_SESSION_ERROR_CODE_"));
            assert!(!name.contains("ONLYOFFICE"));
            assert!(!name.contains("BROWSER"));
            assert!(!name.contains("DATABASE"));
        }
    }
}

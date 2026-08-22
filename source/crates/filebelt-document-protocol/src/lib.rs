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

    #[test]
    fn callback_output_file_type_crosses_the_provider_neutral_boundary() {
        let command = ReceiveDocumentCallbackCommand {
            tenant_id: "tenant".into(),
            document_session_id: "session".into(),
            participant_id: "participant".into(),
            provider_event_digest: vec![7; 32],
            callback_kind: DocumentCallbackKind::OutputRequired as i32,
            revision_kind: DocumentRevisionKind::FinalSave as i32,
            activity: DocumentParticipantActivity::Unspecified as i32,
            output_file_type: "odt".into(),
        };
        assert_eq!(
            ReceiveDocumentCallbackCommand::decode(command.encode_to_vec().as_slice())
                .unwrap()
                .output_file_type,
            "odt"
        );
    }

    #[test]
    fn close_commands_preserve_coordinator_operation_bindings() {
        let revoke = RevokeDocumentSessionCommand {
            tenant_id: "tenant".into(),
            actor_principal_id: "actor".into(),
            participant_id: "participant".into(),
            reason: "owner_revoke".into(),
            operation_digest: vec![7; 32],
            request_fingerprint: vec![8; 32],
        };
        let revoke = RevokeDocumentSessionCommand::decode(revoke.encode_to_vec().as_slice())
            .expect("decode revoke command");
        assert_eq!(revoke.operation_digest, vec![7; 32]);
        assert_eq!(revoke.request_fingerprint, vec![8; 32]);

        let close = ForceCloseDocumentSessionCommand {
            tenant_id: "tenant".into(),
            actor_principal_id: "actor".into(),
            document_session_id: "document-session".into(),
            reason: "manager_force_close".into(),
            api_session_id: "api-session".into(),
            drive_id: "drive".into(),
            node_id: "node".into(),
            generations: Some(DocumentAuthorizationGenerations {
                membership_generation: 1,
                drive_acl_generation: 2,
                namespace_generation: 3,
                resource_acl_generation: 4,
            }),
            operation_digest: vec![9; 32],
            request_fingerprint: vec![10; 32],
        };
        let close = ForceCloseDocumentSessionCommand::decode(close.encode_to_vec().as_slice())
            .expect("decode force-close command");
        assert_eq!(close.operation_digest, vec![9; 32]);
        assert_eq!(close.request_fingerprint, vec![10; 32]);
    }
}

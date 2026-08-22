// SPDX-License-Identifier: Apache-2.0

use filebelt_directory_repository_adapter::{
    AdapterError, COORDINATOR_URI_SAN, REQUIRED_GIT_VERSION, serve_private_mtls_scaffold,
    validate_prepare, validate_private_request, validate_private_response, validate_stage,
    validate_verify,
};
use filebelt_directory_repository_protocol::{
    ChangeKind, DirectoryRepositoryAccepted, DirectoryRepositoryExecuteRequest,
    DirectoryRepositoryExecuteResponse, DirectoryRepositoryFence, GitObjectFormat, ObjectFormat,
    ObjectId, OperationFence, PrepareDirectoryRepository, TreeChange, TreeEntry, TreeMode,
    directory_repository_execute_request, directory_repository_execute_response,
};
use uuid::Uuid;

fn fence() -> OperationFence {
    OperationFence {
        tenant_id: Uuid::from_u128(1),
        directory_root_id: Uuid::from_u128(2),
        operation_id: Uuid::from_u128(3),
        fencing_token: 4,
    }
}

#[test]
fn consumes_generated_private_dtos_without_enabling_transport() {
    let request = DirectoryRepositoryExecuteRequest {
        request_id: Uuid::from_u128(5).to_string(),
        operation: Some(directory_repository_execute_request::Operation::Prepare(
            PrepareDirectoryRepository {
                fence: Some(DirectoryRepositoryFence {
                    tenant_id: Uuid::from_u128(1).to_string(),
                    directory_root_id: Uuid::from_u128(2).to_string(),
                    operation_id: Uuid::from_u128(3).to_string(),
                    fencing_token: 4,
                }),
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

    assert!(validate_private_request(&request).is_ok());
    assert!(validate_private_response(&request, &response).is_ok());
    assert!(matches!(
        serve_private_mtls_scaffold(),
        Err(AdapterError::WireBindingsUnavailable)
    ));
}

fn oid() -> ObjectId {
    ObjectId {
        format: ObjectFormat::Sha256,
        value: vec![5; 32],
    }
}

#[test]
fn validates_private_tree_lifecycle_without_enabling_transport() {
    let directory = TreeEntry {
        path_components: vec!["empty".into()],
        mode: TreeMode::Directory,
        object_id: oid(),
        object_size_bytes: 0,
    };
    let keep = TreeEntry {
        path_components: vec!["empty".into(), ".filebeltkeep".into()],
        mode: TreeMode::File,
        object_id: oid(),
        object_size_bytes: 0,
    };
    let change = TreeChange {
        path_components: vec!["empty".into(), ".filebeltkeep".into()],
        kind: ChangeKind::Upsert,
        entry: Some(keep.clone()),
    };

    assert!(validate_prepare(fence(), ObjectFormat::Sha256, Some(&oid())).is_ok());
    assert!(validate_stage(fence(), ObjectFormat::Sha256, &[change]).is_ok());
    assert!(
        validate_verify(
            fence(),
            ObjectFormat::Sha256,
            &[directory, keep],
            &[oid()],
            0
        )
        .is_ok()
    );
    assert_eq!(
        COORDINATOR_URI_SAN,
        "spiffe://filebelt/directory-repository-coordinator/git"
    );
    assert_eq!(REQUIRED_GIT_VERSION, "2.55.0");
    assert!(matches!(
        serve_private_mtls_scaffold(),
        Err(AdapterError::WireBindingsUnavailable)
    ));
}

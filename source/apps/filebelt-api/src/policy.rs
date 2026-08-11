// SPDX-License-Identifier: Apache-2.0

use std::sync::OnceLock;

use filebelt_authz::{
    AclEntry, Effect, GroupMembership, Inheritance, PrincipalAuthorizationFacts, PrincipalContext,
    RecursiveShareAuthorizationRequest, RecursiveShareResolvedAclEntry, ResolvedAclEntry,
    evaluate_recursive_direct_shares,
};
use filebelt_database::{AuthorizationSnapshot, Database};
use filebelt_domain::{
    AclEntryId, Action, DriveOwner, Generation, GenerationSnapshot, GroupId, GroupRole, NodeId,
    PrincipalId, ResourceId,
};
use filebelt_runtime::OperationsState;
use prometheus_client::metrics::counter::Counter;
use uuid::Uuid;

use crate::error::ApiError;

static RECURSIVE_SHARE_DEPTH_LIMIT_DENIALS: OnceLock<Counter> = OnceLock::new();
static RECURSIVE_SHARE_EDGE_LIMIT_DENIALS: OnceLock<Counter> = OnceLock::new();

pub(crate) fn register_recursive_share_metrics(operations: &OperationsState) {
    let _ = RECURSIVE_SHARE_DEPTH_LIMIT_DENIALS.set(operations.register_counter(
        "recursive_share_depth_limit_denials_total",
        "Authorization denials caused by the recursive-share delegation-depth limit.",
    ));
    let _ = RECURSIVE_SHARE_EDGE_LIMIT_DENIALS.set(operations.register_counter(
        "recursive_share_edge_limit_denials_total",
        "Authorization denials caused by the recursive-share edge-count limit.",
    ));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizationGrant {
    pub(crate) membership_generation: u64,
    pub(crate) drive_acl_generation: u64,
    pub(crate) namespace_generation: u64,
    pub(crate) resource_acl_generation: u64,
}

pub(crate) async fn authorize(
    database: &Database,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    action: Action,
) -> Result<AuthorizationGrant, ApiError> {
    let snapshot = database
        .authorization_snapshot(tenant_id, actor_principal_id, drive_id, resource_id)
        .await
        .map_err(ApiError::from)?;
    evaluate_snapshot(&snapshot, action)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_capability(
    database: &Database,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    session_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    action: Action,
) -> Result<AuthorizationGrant, ApiError> {
    authorize_session_bound(
        database,
        tenant_id,
        actor_principal_id,
        session_id,
        drive_id,
        resource_id,
        action,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_session_bound(
    database: &Database,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    session_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    action: Action,
) -> Result<AuthorizationGrant, ApiError> {
    let snapshot = database
        .authorization_snapshot(tenant_id, actor_principal_id, drive_id, resource_id)
        .await
        .map_err(ApiError::from)?;
    let grant = evaluate_snapshot(&snapshot, action)?;
    database
        .publish_authorization_generations(&snapshot, session_id)
        .await
        .map_err(ApiError::from)?;
    Ok(grant)
}

fn evaluate_snapshot(
    snapshot: &AuthorizationSnapshot,
    action: Action,
) -> Result<AuthorizationGrant, ApiError> {
    let context = principal_context(snapshot.actor_principal_id, &snapshot.actor_groups)?;
    let resource = ResourceId::Node(node(snapshot.resource_id)?);
    let entries = snapshot
        .entries
        .iter()
        .map(recursive_share_entry)
        .collect::<Result<Vec<_>, ApiError>>()?;
    let creator_facts = snapshot
        .creator_facts
        .iter()
        .map(|facts| {
            Ok(PrincipalAuthorizationFacts::new(
                principal_context(facts.principal_id, &facts.groups)?,
                facts
                    .entries
                    .iter()
                    .map(recursive_share_entry)
                    .collect::<Result<Vec<_>, ApiError>>()?,
            ))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let generations = GenerationSnapshot {
        resource_acl: generation(snapshot.resource_acl_generation)?,
        membership: generation(snapshot.membership_generation)?,
        namespace: generation(snapshot.namespace_generation)?,
    };
    let decision = evaluate_recursive_direct_shares(RecursiveShareAuthorizationRequest {
        principal: &context,
        resource,
        drive_owner: drive_owner(snapshot)?,
        action,
        entries: &entries,
        creator_facts: &creator_facts,
        generations,
    })
    .map_err(|error| {
        record_recursive_share_limit(error);
        ApiError::not_found()
    })?;
    if !decision.allowed() {
        return Err(ApiError::not_found());
    }
    Ok(AuthorizationGrant {
        membership_generation: generations.membership.get(),
        drive_acl_generation: positive_u64(snapshot.drive_acl_generation)?,
        namespace_generation: generations.namespace.get(),
        resource_acl_generation: generations.resource_acl.get(),
    })
}

fn record_recursive_share_limit(error: filebelt_authz::RecursiveShareEvaluationError) {
    let reason = match error {
        filebelt_authz::RecursiveShareEvaluationError::DelegationDepthExceeded => {
            if let Some(counter) = RECURSIVE_SHARE_DEPTH_LIMIT_DENIALS.get() {
                counter.inc();
            }
            "delegation_depth"
        }
        filebelt_authz::RecursiveShareEvaluationError::RecursiveEdgeLimitExceeded => {
            if let Some(counter) = RECURSIVE_SHARE_EDGE_LIMIT_DENIALS.get() {
                counter.inc();
            }
            "recursive_edges"
        }
    };
    tracing::warn!(reason, "recursive-share authorization graph limit exceeded");
}

fn principal_context(
    principal_id: Uuid,
    groups: &[filebelt_database::GroupInputRow],
) -> Result<PrincipalContext, ApiError> {
    let memberships = groups
        .iter()
        .map(|group| {
            Ok(GroupMembership {
                group_id: group_id(group.group_id)?,
                group_principal_id: principal(group.principal_id)?,
                role: match group.role.as_str() {
                    "member" => GroupRole::Member,
                    "manager" => GroupRole::Manager,
                    _ => return Err(ApiError::internal()),
                },
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(PrincipalContext::new(principal(principal_id)?, memberships))
}

fn recursive_share_entry(
    row: &filebelt_database::AclInputRow,
) -> Result<RecursiveShareResolvedAclEntry, ApiError> {
    if row.direct_share_id.is_some() && !row.direct_share_active {
        return Err(ApiError::internal());
    }
    let entry = AclEntry::new(
        acl_entry(row.id)?,
        ResourceId::Node(node(row.resource_id)?),
        principal(row.principal_id)?,
        parse_action(&row.action)?,
        match row.effect.as_str() {
            "allow" => Effect::Allow,
            "deny" => Effect::Deny,
            _ => return Err(ApiError::internal()),
        },
        match row.inheritance.as_str() {
            "self" => Inheritance::ThisResource,
            "children" => Inheritance::Children,
            "descendants" | "self_and_descendants" => Inheritance::Descendants,
            _ => return Err(ApiError::internal()),
        },
        generation(row.generation)?,
        principal(row.created_by)?,
    );
    let resolved = if row.direct {
        ResolvedAclEntry::direct(entry)
    } else {
        let distance = u32::try_from(row.depth).map_err(|_| ApiError::internal())?;
        ResolvedAclEntry::inherited(entry, distance).ok_or_else(ApiError::internal)?
    };
    if row.direct_share_active && row.inheritance == "self_and_descendants" {
        Ok(RecursiveShareResolvedAclEntry::recursive_direct_share(
            resolved,
            principal(row.created_by)?,
        ))
    } else {
        Ok(RecursiveShareResolvedAclEntry::independent(resolved))
    }
}

fn drive_owner(snapshot: &AuthorizationSnapshot) -> Result<DriveOwner, ApiError> {
    match snapshot.owner_kind.as_str() {
        "user" => Ok(DriveOwner::User(principal(snapshot.owner_principal_id)?)),
        "group" => Ok(DriveOwner::Group(group_id(
            snapshot.owner_group_id.ok_or_else(ApiError::internal)?,
        )?)),
        "organization" => Ok(DriveOwner::Organization(principal(
            snapshot.owner_principal_id,
        )?)),
        "service" => Ok(DriveOwner::Service(principal(snapshot.owner_principal_id)?)),
        _ => Err(ApiError::internal()),
    }
}

fn parse_action(value: &str) -> Result<Action, ApiError> {
    Action::ALL
        .into_iter()
        .find(|candidate| candidate.as_str() == value)
        .ok_or_else(ApiError::internal)
}

fn positive_u64(value: i64) -> Result<u64, ApiError> {
    let value = u64::try_from(value).map_err(|_| ApiError::internal())?;
    if value == 0 {
        return Err(ApiError::internal());
    }
    Ok(value)
}

fn generation(value: i64) -> Result<Generation, ApiError> {
    positive_u64(value).map(Generation::new)
}

fn principal(value: Uuid) -> Result<PrincipalId, ApiError> {
    PrincipalId::from_uuid(value).map_err(|_| ApiError::internal())
}

fn group_id(value: Uuid) -> Result<GroupId, ApiError> {
    GroupId::from_uuid(value).map_err(|_| ApiError::internal())
}

fn node(value: Uuid) -> Result<NodeId, ApiError> {
    NodeId::from_uuid(value).map_err(|_| ApiError::internal())
}

fn acl_entry(value: Uuid) -> Result<AclEntryId, ApiError> {
    AclEntryId::from_uuid(value).map_err(|_| ApiError::internal())
}

#[cfg(test)]
mod tests {
    use super::{evaluate_snapshot, parse_action, recursive_share_entry};
    use filebelt_database::{AclInputRow, AuthorizationPrincipalFact, AuthorizationSnapshot};
    use filebelt_domain::Action;
    use uuid::Uuid;

    fn acl_row(
        resource_id: Uuid,
        principal_id: Uuid,
        action: Action,
        inheritance: &str,
        depth: i32,
        direct: bool,
        created_by: Uuid,
    ) -> AclInputRow {
        AclInputRow {
            id: Uuid::new_v4(),
            resource_id,
            principal_id,
            action: action.as_str().into(),
            effect: "allow".into(),
            inheritance: inheritance.into(),
            depth,
            direct,
            generation: 1,
            created_by,
            direct_share_id: Some(Uuid::new_v4()),
            direct_share_active: true,
        }
    }

    fn snapshot(
        owner: Uuid,
        actor: Uuid,
        resource_id: Uuid,
        entries: Vec<AclInputRow>,
        creator_facts: Vec<AuthorizationPrincipalFact>,
    ) -> AuthorizationSnapshot {
        AuthorizationSnapshot {
            tenant_id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            resource_id,
            owner_principal_id: owner,
            owner_kind: "user".into(),
            owner_group_id: None,
            actor_principal_id: actor,
            actor_groups: Vec::new(),
            entries,
            creator_facts,
            membership_generation: 1,
            drive_acl_generation: 1,
            namespace_generation: 1,
            resource_acl_generation: 1,
        }
    }

    #[test]
    fn persisted_action_vocabulary_is_exact() {
        for action in Action::ALL {
            assert_eq!(parse_action(action.as_str()).expect("known action"), action);
        }
        assert!(parse_action("read_content").is_err());
    }

    #[test]
    fn recursive_direct_share_rows_keep_creator_provenance() {
        let mut row = AclInputRow {
            id: Uuid::new_v4(),
            resource_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            action: "READ_CONTENT".into(),
            effect: "allow".into(),
            inheritance: "self_and_descendants".into(),
            depth: 0,
            direct: true,
            generation: 1,
            created_by: Uuid::new_v4(),
            direct_share_id: Some(Uuid::new_v4()),
            direct_share_active: true,
        };
        assert!(matches!(
            recursive_share_entry(&row)
                .expect("valid share row")
                .provenance(),
            filebelt_authz::RecursiveShareProvenance::RecursiveDirectShare { .. }
        ));
        row.direct_share_active = false;
        assert!(recursive_share_entry(&row).is_err());
    }

    #[test]
    fn graph_evaluator_replaces_the_legacy_snapshot_evaluator() {
        let source = include_str!("policy.rs");
        let runtime = source
            .split_once("#[cfg(test)]")
            .expect("tests follow runtime")
            .0;
        assert!(runtime.contains("evaluate_recursive_direct_shares"));
        assert!(runtime.contains("creator_facts: &creator_facts"));
        assert!(!runtime.contains("evaluate(AuthorizationRequest"));
    }

    #[test]
    fn self_only_manager_cannot_broaden_a_recursive_share_to_a_child() {
        let owner = Uuid::new_v4();
        let manager = Uuid::new_v4();
        let recipient = Uuid::new_v4();
        let root = Uuid::new_v4();
        let child = Uuid::new_v4();
        let creator_root_facts = AuthorizationPrincipalFact {
            principal_id: manager,
            groups: Vec::new(),
            entries: vec![
                acl_row(root, manager, Action::Share, "self", 0, true, owner),
                acl_row(root, manager, Action::ReadMetadata, "self", 0, true, owner),
            ],
        };
        let root_snapshot = snapshot(
            owner,
            recipient,
            root,
            vec![acl_row(
                root,
                recipient,
                Action::ReadMetadata,
                "self_and_descendants",
                0,
                true,
                manager,
            )],
            vec![creator_root_facts],
        );
        assert!(evaluate_snapshot(&root_snapshot, Action::ReadMetadata).is_ok());

        let child_snapshot = snapshot(
            owner,
            recipient,
            child,
            vec![acl_row(
                root,
                recipient,
                Action::ReadMetadata,
                "self_and_descendants",
                1,
                false,
                manager,
            )],
            vec![AuthorizationPrincipalFact {
                principal_id: manager,
                groups: Vec::new(),
                entries: Vec::new(),
            }],
        );
        assert!(evaluate_snapshot(&child_snapshot, Action::ReadMetadata).is_err());
    }

    #[test]
    fn owner_recursive_share_reaches_children_but_self_share_does_not() {
        let owner = Uuid::new_v4();
        let recipient = Uuid::new_v4();
        let root = Uuid::new_v4();
        let child = Uuid::new_v4();
        let owner_facts = || AuthorizationPrincipalFact {
            principal_id: owner,
            groups: Vec::new(),
            entries: Vec::new(),
        };
        let recursive_child = snapshot(
            owner,
            recipient,
            child,
            vec![acl_row(
                root,
                recipient,
                Action::ReadMetadata,
                "self_and_descendants",
                1,
                false,
                owner,
            )],
            vec![owner_facts()],
        );
        assert!(evaluate_snapshot(&recursive_child, Action::ReadMetadata).is_ok());

        let self_root = snapshot(
            owner,
            recipient,
            root,
            vec![acl_row(
                root,
                recipient,
                Action::ReadMetadata,
                "self",
                0,
                true,
                owner,
            )],
            Vec::new(),
        );
        assert!(evaluate_snapshot(&self_root, Action::ReadMetadata).is_ok());
        let self_child = snapshot(owner, recipient, child, Vec::new(), Vec::new());
        assert!(evaluate_snapshot(&self_child, Action::ReadMetadata).is_err());
    }
}

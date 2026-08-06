// SPDX-License-Identifier: Apache-2.0

use filebelt_authz::{
    AclEntry, AuthorizationRequest, Effect, GroupMembership, Inheritance, PrincipalContext,
    ResolvedAclEntry, evaluate,
};
use filebelt_database::{AuthorizationSnapshot, Database};
use filebelt_domain::{
    AclEntryId, Action, DriveOwner, Generation, GenerationSnapshot, GroupId, GroupRole, NodeId,
    PrincipalId, ResourceId,
};
use uuid::Uuid;

use crate::error::ApiError;

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
    let principal_id = principal(snapshot.actor_principal_id)?;
    let memberships = snapshot
        .actor_groups
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
    let context = PrincipalContext::new(principal_id, memberships);
    let resource = ResourceId::Node(node(snapshot.resource_id)?);
    let entries = snapshot
        .entries
        .iter()
        .map(|row| {
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
            if row.direct {
                Ok(ResolvedAclEntry::direct(entry))
            } else {
                let distance = u32::try_from(row.depth).map_err(|_| ApiError::internal())?;
                ResolvedAclEntry::inherited(entry, distance).ok_or_else(ApiError::internal)
            }
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let generations = GenerationSnapshot {
        resource_acl: generation(snapshot.resource_acl_generation)?,
        membership: generation(snapshot.membership_generation)?,
        namespace: generation(snapshot.namespace_generation)?,
    };
    let decision = evaluate(AuthorizationRequest {
        principal: &context,
        resource,
        drive_owner: drive_owner(snapshot)?,
        action,
        entries: &entries,
        generations,
    });
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
    use super::parse_action;
    use filebelt_domain::Action;

    #[test]
    fn persisted_action_vocabulary_is_exact() {
        for action in Action::ALL {
            assert_eq!(parse_action(action.as_str()).expect("known action"), action);
        }
        assert!(parse_action("read_content").is_err());
    }
}

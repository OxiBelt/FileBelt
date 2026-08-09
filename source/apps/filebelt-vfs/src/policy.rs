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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationGrant {
    pub membership_generation: i64,
    pub drive_acl_generation: i64,
    pub namespace_generation: i64,
    pub resource_acl_generation: i64,
}

pub async fn authorize(
    database: &Database,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    action: Action,
) -> Result<AuthorizationGrant, ()> {
    let snapshot = database
        .authorization_snapshot(tenant_id, actor_principal_id, drive_id, resource_id)
        .await
        .map_err(|_| ())?;
    evaluate_snapshot(&snapshot, action)
}

/// NFS lookup evaluates traversal separately from listing. This helper keeps
/// the protocol adapter from treating directory visibility as traversal
/// authority and preserves deny precedence through the common evaluator.
#[allow(dead_code)]
pub async fn authorize_traverse(
    database: &Database,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    drive_id: Uuid,
    ancestor_resource_ids: &[Uuid],
) -> Result<(), ()> {
    if ancestor_resource_ids.is_empty() || ancestor_resource_ids.len() > 128 {
        return Err(());
    }
    for resource_id in ancestor_resource_ids {
        authorize(
            database,
            tenant_id,
            actor_principal_id,
            drive_id,
            *resource_id,
            Action::Traverse,
        )
        .await?;
    }
    Ok(())
}

fn evaluate_snapshot(
    snapshot: &AuthorizationSnapshot,
    action: Action,
) -> Result<AuthorizationGrant, ()> {
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
                    _ => return Err(()),
                },
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
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
                    _ => return Err(()),
                },
                match row.inheritance.as_str() {
                    "self" => Inheritance::ThisResource,
                    "children" => Inheritance::Children,
                    "descendants" | "self_and_descendants" => Inheritance::Descendants,
                    _ => return Err(()),
                },
                generation(row.generation)?,
                principal(row.created_by)?,
            );
            if row.direct {
                Ok(ResolvedAclEntry::direct(entry))
            } else {
                let distance = u32::try_from(row.depth).map_err(|_| ())?;
                ResolvedAclEntry::inherited(entry, distance).ok_or(())
            }
        })
        .collect::<Result<Vec<_>, ()>>()?;
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
        return Err(());
    }
    Ok(AuthorizationGrant {
        membership_generation: snapshot.membership_generation,
        drive_acl_generation: snapshot.drive_acl_generation,
        namespace_generation: snapshot.namespace_generation,
        resource_acl_generation: snapshot.resource_acl_generation,
    })
}

fn drive_owner(snapshot: &AuthorizationSnapshot) -> Result<DriveOwner, ()> {
    match snapshot.owner_kind.as_str() {
        "user" => Ok(DriveOwner::User(principal(snapshot.owner_principal_id)?)),
        "group" => Ok(DriveOwner::Group(group_id(
            snapshot.owner_group_id.ok_or(())?,
        )?)),
        "organization" => Ok(DriveOwner::Organization(principal(
            snapshot.owner_principal_id,
        )?)),
        "service" => Ok(DriveOwner::Service(principal(snapshot.owner_principal_id)?)),
        _ => Err(()),
    }
}

fn parse_action(value: &str) -> Result<Action, ()> {
    Action::ALL
        .into_iter()
        .find(|candidate| candidate.as_str() == value)
        .ok_or(())
}

fn positive_u64(value: i64) -> Result<u64, ()> {
    let value = u64::try_from(value).map_err(|_| ())?;
    if value == 0 {
        return Err(());
    }
    Ok(value)
}

fn generation(value: i64) -> Result<Generation, ()> {
    positive_u64(value).map(Generation::new)
}

fn principal(value: Uuid) -> Result<PrincipalId, ()> {
    PrincipalId::from_uuid(value).map_err(|_| ())
}

fn group_id(value: Uuid) -> Result<GroupId, ()> {
    GroupId::from_uuid(value).map_err(|_| ())
}

fn node(value: Uuid) -> Result<NodeId, ()> {
    NodeId::from_uuid(value).map_err(|_| ())
}

fn acl_entry(value: Uuid) -> Result<AclEntryId, ()> {
    AclEntryId::from_uuid(value).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::parse_action;
    use filebelt_domain::Action;

    #[test]
    fn mount_actions_use_the_common_virtual_acl_vocabulary() {
        for action in Action::ALL {
            assert_eq!(parse_action(action.as_str()), Ok(action));
        }
    }

    #[test]
    fn traversal_uses_the_stable_common_action() {
        assert_eq!(parse_action("TRAVERSE"), Ok(Action::Traverse));
    }
}

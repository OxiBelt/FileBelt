// SPDX-License-Identifier: Apache-2.0

//! Deterministic, pure evaluation of FileBelt Virtual ACL policy.
//!
//! Callers resolve ancestry and group membership from authoritative state,
//! then pass those facts to this crate. Database access, caches, transports,
//! clocks, and audit persistence remain outside this package.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use filebelt_domain::{
    AclEntryId, Action, DriveOwner, Generation, GenerationSnapshot, GroupId, GroupRole,
    PrincipalId, ResourceId,
};

pub mod repository;

/// Whether an ACL entry grants or rejects an action.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Effect {
    Allow,
    Deny,
}

/// How an ACL entry propagates below the resource where it is attached.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Inheritance {
    /// Apply only to the resource that owns the entry.
    ThisResource,
    /// Apply to the resource and its immediate children.
    Children,
    /// Apply to the resource and every descendant.
    Descendants,
}

impl Inheritance {
    /// Returns whether the entry applies at an ancestry distance.
    #[must_use]
    pub const fn applies_at(self, distance: u32) -> bool {
        distance == 0
            || match self {
                Self::ThisResource => false,
                Self::Children => distance == 1,
                Self::Descendants => true,
            }
    }
}

/// One explicit Virtual ACL rule attached to a resource.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AclEntry {
    id: AclEntryId,
    resource: ResourceId,
    principal: PrincipalId,
    action: Action,
    effect: Effect,
    inheritance: Inheritance,
    generation: Generation,
    created_by: PrincipalId,
}

impl AclEntry {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        id: AclEntryId,
        resource: ResourceId,
        principal: PrincipalId,
        action: Action,
        effect: Effect,
        inheritance: Inheritance,
        generation: Generation,
        created_by: PrincipalId,
    ) -> Self {
        Self {
            id,
            resource,
            principal,
            action,
            effect,
            inheritance,
            generation,
            created_by,
        }
    }

    #[must_use]
    pub const fn id(self) -> AclEntryId {
        self.id
    }

    #[must_use]
    pub const fn resource(self) -> ResourceId {
        self.resource
    }

    #[must_use]
    pub const fn principal(self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub const fn action(self) -> Action {
        self.action
    }

    #[must_use]
    pub const fn effect(self) -> Effect {
        self.effect
    }

    #[must_use]
    pub const fn inheritance(self) -> Inheritance {
        self.inheritance
    }

    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    #[must_use]
    pub const fn created_by(self) -> PrincipalId {
        self.created_by
    }
}

/// An ACL entry paired with its authoritative ancestry distance to the target.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResolvedAclEntry {
    entry: AclEntry,
    distance: u32,
}

/// Whether a resolved entry is an independent ACL fact or a recursive direct
/// share whose authority is continuously attenuated by its creator.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RecursiveShareProvenance {
    /// The entry is an independently administered ACL fact.
    Independent,
    /// The entry came from a recursive direct share created by this principal.
    RecursiveDirectShare { creator: PrincipalId },
}

/// A resolved ACL entry with the provenance needed for recursive-share
/// attenuation. Existing callers can continue to use [`ResolvedAclEntry`] and
/// [`evaluate`]; only recursive-share evaluation needs this wrapper.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecursiveShareResolvedAclEntry {
    resolved: ResolvedAclEntry,
    provenance: RecursiveShareProvenance,
}

impl RecursiveShareResolvedAclEntry {
    #[must_use]
    pub const fn independent(resolved: ResolvedAclEntry) -> Self {
        Self {
            resolved,
            provenance: RecursiveShareProvenance::Independent,
        }
    }

    #[must_use]
    pub const fn recursive_direct_share(resolved: ResolvedAclEntry, creator: PrincipalId) -> Self {
        Self {
            resolved,
            provenance: RecursiveShareProvenance::RecursiveDirectShare { creator },
        }
    }

    #[must_use]
    pub const fn resolved(self) -> ResolvedAclEntry {
        self.resolved
    }

    #[must_use]
    pub const fn provenance(self) -> RecursiveShareProvenance {
        self.provenance
    }
}

impl ResolvedAclEntry {
    /// Creates a direct entry attached to the target resource.
    #[must_use]
    pub const fn direct(entry: AclEntry) -> Self {
        Self { entry, distance: 0 }
    }

    /// Creates an entry resolved from an ancestor.
    ///
    /// A zero distance is rejected so direct and inherited evidence cannot be
    /// confused in audit decisions.
    pub const fn inherited(entry: AclEntry, distance: u32) -> Option<Self> {
        if distance == 0 {
            None
        } else {
            Some(Self { entry, distance })
        }
    }

    #[must_use]
    pub const fn entry(self) -> AclEntry {
        self.entry
    }

    #[must_use]
    pub const fn distance(self) -> u32 {
        self.distance
    }

    #[must_use]
    pub const fn is_direct(self) -> bool {
        self.distance == 0
    }

    #[must_use]
    pub const fn applies(self) -> bool {
        self.entry.inheritance.applies_at(self.distance)
    }
}

/// One authoritative flat-group membership for the acting principal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GroupMembership {
    pub group_id: GroupId,
    /// The immutable group principal targeted by ACL entries.
    pub group_principal_id: PrincipalId,
    pub role: GroupRole,
}

/// Fully resolved principal facts needed by the pure evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalContext {
    principal_id: PrincipalId,
    memberships: Vec<GroupMembership>,
}

impl PrincipalContext {
    /// Creates a context and canonicalizes duplicate group facts.
    #[must_use]
    pub fn new(principal_id: PrincipalId, mut memberships: Vec<GroupMembership>) -> Self {
        memberships.sort_unstable();
        memberships.dedup();
        Self {
            principal_id,
            memberships,
        }
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    #[must_use]
    pub fn memberships(&self) -> &[GroupMembership] {
        &self.memberships
    }

    /// Whether an ACL subject denotes the actor directly or through a group.
    #[must_use]
    pub fn includes_principal(&self, candidate: PrincipalId) -> bool {
        candidate == self.principal_id
            || self
                .memberships
                .iter()
                .any(|membership| membership.group_principal_id == candidate)
    }

    /// Whether the actor manages the specified flat group.
    #[must_use]
    pub fn manages_group(&self, group_id: GroupId) -> bool {
        self.memberships.iter().any(|membership| {
            membership.group_id == group_id && membership.role == GroupRole::Manager
        })
    }
}

/// Complete authorization facts for one possible creator in a recursive direct
/// share proof. The facts must describe the same requested resource as the
/// enclosing recursive-share request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalAuthorizationFacts {
    principal: PrincipalContext,
    entries: Vec<RecursiveShareResolvedAclEntry>,
}

impl PrincipalAuthorizationFacts {
    #[must_use]
    pub fn new(principal: PrincipalContext, entries: Vec<RecursiveShareResolvedAclEntry>) -> Self {
        Self { principal, entries }
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalContext {
        &self.principal
    }

    #[must_use]
    pub fn entries(&self) -> &[RecursiveShareResolvedAclEntry] {
        &self.entries
    }
}

/// Stable reason for an allow or deny decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DecisionReason {
    Owner,
    GroupOwnerManager,
    ExplicitAllow,
    InheritedAllow,
    ExplicitDeny,
    InheritedDeny,
    NoMatchingGrant,
}

impl DecisionReason {
    /// Stable machine-readable audit reason.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Owner => "authz.allow.owner",
            Self::GroupOwnerManager => "authz.allow.group_owner_manager",
            Self::ExplicitAllow => "authz.allow.explicit",
            Self::InheritedAllow => "authz.allow.inherited",
            Self::ExplicitDeny => "authz.deny.explicit",
            Self::InheritedDeny => "authz.deny.inherited",
            Self::NoMatchingGrant => "authz.deny.no_matching_grant",
        }
    }
}

/// Deterministic authorization result and the generations that qualify it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecision {
    allowed: bool,
    reason: DecisionReason,
    source_entries: Vec<AclEntryId>,
    generations: GenerationSnapshot,
}

impl AuthorizationDecision {
    #[must_use]
    pub const fn allowed(&self) -> bool {
        self.allowed
    }

    #[must_use]
    pub const fn reason(&self) -> DecisionReason {
        self.reason
    }

    /// Sorted, deduplicated entries that determined the result.
    #[must_use]
    pub fn source_entries(&self) -> &[AclEntryId] {
        &self.source_entries
    }

    #[must_use]
    pub const fn generations(&self) -> GenerationSnapshot {
        self.generations
    }

    /// Whether all authoritative generation inputs are still current.
    #[must_use]
    pub const fn remains_valid_at(&self, current: GenerationSnapshot) -> bool {
        self.generations.resource_acl.get() == current.resource_acl.get()
            && self.generations.membership.get() == current.membership.get()
            && self.generations.namespace.get() == current.namespace.get()
    }
}

/// Complete input for one authorization evaluation.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationRequest<'a> {
    pub principal: &'a PrincipalContext,
    pub resource: ResourceId,
    pub drive_owner: DriveOwner,
    pub action: Action,
    pub entries: &'a [ResolvedAclEntry],
    pub generations: GenerationSnapshot,
}

/// Evaluates one action with non-removable owner rights and global deny precedence.
///
/// An applicable deny always defeats explicit or inherited allows. The only
/// exception is an implicit drive owner right, which ACL rows cannot remove.
#[must_use]
pub fn evaluate(request: AuthorizationRequest<'_>) -> AuthorizationDecision {
    if let Some(reason) =
        implicit_owner_reason(request.principal, request.drive_owner, request.action)
    {
        return AuthorizationDecision {
            allowed: true,
            reason,
            source_entries: Vec::new(),
            generations: request.generations,
        };
    }

    let mut direct_denies = Vec::new();
    let mut inherited_denies = Vec::new();
    let mut direct_allows = Vec::new();
    let mut inherited_allows = Vec::new();

    for resolved in request.entries {
        let entry = resolved.entry();
        if entry.action() != request.action
            || !request.principal.includes_principal(entry.principal())
            || !resolved.applies()
            || (resolved.is_direct() != (entry.resource() == request.resource))
        {
            continue;
        }

        match (entry.effect(), resolved.is_direct()) {
            (Effect::Deny, true) => direct_denies.push(entry.id()),
            (Effect::Deny, false) => inherited_denies.push(entry.id()),
            (Effect::Allow, true) => direct_allows.push(entry.id()),
            (Effect::Allow, false) => inherited_allows.push(entry.id()),
        }
    }

    canonicalize_ids(&mut direct_denies);
    canonicalize_ids(&mut inherited_denies);
    canonicalize_ids(&mut direct_allows);
    canonicalize_ids(&mut inherited_allows);

    if !direct_denies.is_empty() || !inherited_denies.is_empty() {
        let reason = if direct_denies.is_empty() {
            DecisionReason::InheritedDeny
        } else {
            DecisionReason::ExplicitDeny
        };
        direct_denies.extend(inherited_denies);
        canonicalize_ids(&mut direct_denies);
        return AuthorizationDecision {
            allowed: false,
            reason,
            source_entries: direct_denies,
            generations: request.generations,
        };
    }

    if !direct_allows.is_empty() || !inherited_allows.is_empty() {
        let reason = if direct_allows.is_empty() {
            DecisionReason::InheritedAllow
        } else {
            DecisionReason::ExplicitAllow
        };
        direct_allows.extend(inherited_allows);
        canonicalize_ids(&mut direct_allows);
        return AuthorizationDecision {
            allowed: true,
            reason,
            source_entries: direct_allows,
            generations: request.generations,
        };
    }

    AuthorizationDecision {
        allowed: false,
        reason: DecisionReason::NoMatchingGrant,
        source_entries: Vec::new(),
        generations: request.generations,
    }
}

/// The maximum number of recursive direct-share creators in one proof.
pub const MAX_RECURSIVE_SHARE_DELEGATION_DEPTH: usize = 128;
/// The maximum number of recursive direct-share edges examined in one proof.
pub const MAX_RECURSIVE_SHARE_EDGES: usize = 4096;

/// Complete input for a continuously attenuated recursive direct-share check.
///
/// `entries` are facts for `principal`; `creator_facts` supplies the same kind
/// of facts for every creator reachable from a recursive direct-share entry.
/// All facts concern `resource` and its authoritative ancestry.
#[derive(Clone, Debug)]
pub struct RecursiveShareAuthorizationRequest<'a> {
    pub principal: &'a PrincipalContext,
    pub resource: ResourceId,
    pub drive_owner: DriveOwner,
    pub action: Action,
    pub entries: &'a [RecursiveShareResolvedAclEntry],
    pub creator_facts: &'a [PrincipalAuthorizationFacts],
    pub generations: GenerationSnapshot,
}

/// A bounded recursive-share graph could not be evaluated safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecursiveShareEvaluationError {
    DelegationDepthExceeded,
    RecursiveEdgeLimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RecursiveShareNodeKey {
    principal: PrincipalId,
    action: Action,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RecursiveShareCandidate {
    entry_id: AclEntryId,
    creator: PrincipalId,
}

#[derive(Clone, Debug, Default)]
struct RecursiveShareNode {
    denied: Option<(DecisionReason, Vec<AclEntryId>)>,
    independent: Option<(DecisionReason, Vec<AclEntryId>)>,
    candidates: Vec<RecursiveShareCandidate>,
}

#[derive(Clone, Copy)]
struct RecursiveShareSubject<'a> {
    principal: &'a PrincipalContext,
    entries: &'a [RecursiveShareResolvedAclEntry],
}

/// Evaluates direct shares with recursive inheritance under continuous
/// delegation attenuation.
///
/// A recursive direct-share allow is usable only when its creator can currently
/// prove both `SHARE` and the requested action at this exact resource.
/// Exact-resource `self` direct-share rows and independently administered ACL
/// rows remain roots. The proof is a least fixed point: rootless cycles confer
/// nothing, while cycles reachable from an independent root can succeed.
pub fn evaluate_recursive_direct_shares(
    request: RecursiveShareAuthorizationRequest<'_>,
) -> Result<AuthorizationDecision, RecursiveShareEvaluationError> {
    let mut creator_facts = BTreeMap::new();
    for facts in request.creator_facts {
        let principal = facts.principal().principal_id();
        match creator_facts.entry(principal) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(facts));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }

    let root = RecursiveShareNodeKey {
        principal: request.principal.principal_id(),
        action: request.action,
    };
    let mut depths = BTreeMap::from([(root, 0_usize)]);
    let mut pending = VecDeque::from([root]);
    let mut nodes = BTreeMap::new();
    let mut recursive_edges = 0_usize;

    while let Some(key) = pending.pop_front() {
        if nodes.contains_key(&key) {
            continue;
        }
        let Some(subject) = recursive_share_subject(key.principal, &request, &creator_facts) else {
            nodes.insert(key, RecursiveShareNode::default());
            continue;
        };
        let node = recursive_share_node(subject, key.action, &request);
        let depth = *depths
            .get(&key)
            .expect("every queued recursive-share node has a depth");
        for candidate in &node.candidates {
            recursive_edges += 1;
            if recursive_edges > MAX_RECURSIVE_SHARE_EDGES {
                return Err(RecursiveShareEvaluationError::RecursiveEdgeLimitExceeded);
            }
            let next_depth = depth + 1;
            if next_depth > MAX_RECURSIVE_SHARE_DELEGATION_DEPTH {
                return Err(RecursiveShareEvaluationError::DelegationDepthExceeded);
            }
            enqueue_recursive_share_node(
                &mut depths,
                &mut pending,
                RecursiveShareNodeKey {
                    principal: candidate.creator,
                    action: Action::Share,
                },
                next_depth,
            );
            if key.action != Action::Share {
                enqueue_recursive_share_node(
                    &mut depths,
                    &mut pending,
                    RecursiveShareNodeKey {
                        principal: candidate.creator,
                        action: key.action,
                    },
                    next_depth,
                );
            }
        }
        nodes.insert(key, node);
    }

    let mut allowed = BTreeMap::<RecursiveShareNodeKey, Option<RecursiveShareCandidate>>::new();
    for (key, node) in &nodes {
        if node.denied.is_none() && node.independent.is_some() {
            allowed.insert(*key, None);
        }
    }
    loop {
        let mut changed = false;
        for (key, node) in &nodes {
            if allowed.contains_key(key) || node.denied.is_some() {
                continue;
            }
            if let Some(candidate) = node.candidates.iter().find(|candidate| {
                recursive_share_candidate_is_proven(**candidate, key.action, &allowed)
            }) {
                allowed.insert(*key, Some(*candidate));
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let node = nodes
        .get(&root)
        .expect("the root recursive-share node is always collected");
    if let Some((reason, source_entries)) = &node.denied {
        return Ok(AuthorizationDecision {
            allowed: false,
            reason: *reason,
            source_entries: source_entries.clone(),
            generations: request.generations,
        });
    }
    if let Some((reason, source_entries)) = &node.independent {
        return Ok(AuthorizationDecision {
            allowed: true,
            reason: *reason,
            source_entries: source_entries.clone(),
            generations: request.generations,
        });
    }
    if let Some(Some(candidate)) = allowed.get(&root) {
        return Ok(AuthorizationDecision {
            allowed: true,
            reason: DecisionReason::InheritedAllow,
            source_entries: vec![candidate.entry_id],
            generations: request.generations,
        });
    }
    Ok(AuthorizationDecision {
        allowed: false,
        reason: DecisionReason::NoMatchingGrant,
        source_entries: Vec::new(),
        generations: request.generations,
    })
}

fn recursive_share_subject<'a>(
    principal: PrincipalId,
    request: &'a RecursiveShareAuthorizationRequest<'a>,
    creator_facts: &BTreeMap<PrincipalId, Option<&'a PrincipalAuthorizationFacts>>,
) -> Option<RecursiveShareSubject<'a>> {
    if principal == request.principal.principal_id() {
        return Some(RecursiveShareSubject {
            principal: request.principal,
            entries: request.entries,
        });
    }
    creator_facts.get(&principal).and_then(|facts| {
        facts.map(|facts| RecursiveShareSubject {
            principal: facts.principal(),
            entries: facts.entries(),
        })
    })
}

fn recursive_share_node(
    subject: RecursiveShareSubject<'_>,
    action: Action,
    request: &RecursiveShareAuthorizationRequest<'_>,
) -> RecursiveShareNode {
    if let Some(reason) = implicit_owner_reason(subject.principal, request.drive_owner, action) {
        return RecursiveShareNode {
            denied: None,
            independent: Some((reason, Vec::new())),
            candidates: Vec::new(),
        };
    }

    let mut direct_denies = Vec::new();
    let mut inherited_denies = Vec::new();
    let mut direct_allows = Vec::new();
    let mut inherited_allows = Vec::new();
    let mut candidates = Vec::new();

    for provenanced in subject.entries {
        let resolved = provenanced.resolved();
        let entry = resolved.entry();
        if entry.action() != action
            || !subject.principal.includes_principal(entry.principal())
            || !resolved.applies()
            || resolved.is_direct() != (entry.resource() == request.resource)
        {
            continue;
        }
        match entry.effect() {
            Effect::Deny => {
                if resolved.is_direct() {
                    direct_denies.push(entry.id());
                } else {
                    inherited_denies.push(entry.id());
                }
            }
            Effect::Allow => match provenanced.provenance() {
                RecursiveShareProvenance::Independent if resolved.is_direct() => {
                    direct_allows.push(entry.id());
                }
                RecursiveShareProvenance::Independent => inherited_allows.push(entry.id()),
                RecursiveShareProvenance::RecursiveDirectShare { creator }
                    if entry.created_by() == creator =>
                {
                    candidates.push(RecursiveShareCandidate {
                        entry_id: entry.id(),
                        creator,
                    });
                }
                RecursiveShareProvenance::RecursiveDirectShare { .. } => {}
            },
        }
    }

    canonicalize_ids(&mut direct_denies);
    canonicalize_ids(&mut inherited_denies);
    canonicalize_ids(&mut direct_allows);
    canonicalize_ids(&mut inherited_allows);
    candidates.sort_unstable();
    candidates.dedup();

    if !direct_denies.is_empty() || !inherited_denies.is_empty() {
        let reason = if direct_denies.is_empty() {
            DecisionReason::InheritedDeny
        } else {
            DecisionReason::ExplicitDeny
        };
        direct_denies.extend(inherited_denies);
        canonicalize_ids(&mut direct_denies);
        return RecursiveShareNode {
            denied: Some((reason, direct_denies)),
            independent: None,
            candidates: Vec::new(),
        };
    }
    if !direct_allows.is_empty() || !inherited_allows.is_empty() {
        let reason = if direct_allows.is_empty() {
            DecisionReason::InheritedAllow
        } else {
            DecisionReason::ExplicitAllow
        };
        direct_allows.extend(inherited_allows);
        canonicalize_ids(&mut direct_allows);
        return RecursiveShareNode {
            denied: None,
            independent: Some((reason, direct_allows)),
            candidates: Vec::new(),
        };
    }
    RecursiveShareNode {
        denied: None,
        independent: None,
        candidates,
    }
}

fn enqueue_recursive_share_node(
    depths: &mut BTreeMap<RecursiveShareNodeKey, usize>,
    pending: &mut VecDeque<RecursiveShareNodeKey>,
    key: RecursiveShareNodeKey,
    depth: usize,
) {
    if match depths.get(&key) {
        Some(current) => depth < *current,
        None => true,
    } {
        depths.insert(key, depth);
        pending.push_back(key);
    }
}

fn recursive_share_candidate_is_proven(
    candidate: RecursiveShareCandidate,
    action: Action,
    allowed: &BTreeMap<RecursiveShareNodeKey, Option<RecursiveShareCandidate>>,
) -> bool {
    let share = RecursiveShareNodeKey {
        principal: candidate.creator,
        action: Action::Share,
    };
    allowed.contains_key(&share)
        && (action == Action::Share
            || allowed.contains_key(&RecursiveShareNodeKey {
                principal: candidate.creator,
                action,
            }))
}

fn implicit_owner_reason(
    principal: &PrincipalContext,
    drive_owner: DriveOwner,
    action: Action,
) -> Option<DecisionReason> {
    if action == Action::BypassRepositoryRules {
        return None;
    }
    match drive_owner {
        DriveOwner::User(owner) | DriveOwner::Organization(owner) | DriveOwner::Service(owner)
            if owner == principal.principal_id() =>
        {
            Some(DecisionReason::Owner)
        }
        DriveOwner::Group(group_id) if principal.manages_group(group_id) => {
            Some(DecisionReason::GroupOwnerManager)
        }
        _ => None,
    }
}

fn canonicalize_ids(ids: &mut Vec<AclEntryId>) {
    ids.sort_unstable();
    ids.dedup();
}

/// UI/API permission presets. These expand to explicit actions before persistence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PermissionPreset {
    Viewer,
    Contributor,
    Manager,
}

const VIEWER_ACTIONS: &[Action] = &[
    Action::ReadMetadata,
    Action::ListChildren,
    Action::ReadContent,
    Action::UseExternalEditor,
];

const CONTRIBUTOR_ACTIONS: &[Action] = &[
    Action::ReadMetadata,
    Action::ListChildren,
    Action::ReadContent,
    Action::CreateChild,
    Action::WriteContent,
    Action::CreateVersion,
    Action::Rename,
    Action::Move,
    Action::Delete,
    Action::Restore,
    Action::SetAttributes,
    Action::UseExternalEditor,
    Action::Comment,
    Action::Review,
];

const MANAGER_ACTIONS: &[Action] = &[
    Action::ReadMetadata,
    Action::ListChildren,
    Action::ReadContent,
    Action::CreateChild,
    Action::WriteContent,
    Action::CreateVersion,
    Action::Rename,
    Action::Move,
    Action::Delete,
    Action::Restore,
    Action::SetAttributes,
    Action::Share,
    Action::ManageAcl,
    Action::UseExternalEditor,
    Action::Comment,
    Action::Review,
];

impl PermissionPreset {
    /// Stable action expansion for this preset.
    #[must_use]
    pub const fn actions(self) -> &'static [Action] {
        match self {
            Self::Viewer => VIEWER_ACTIONS,
            Self::Contributor => CONTRIBUTOR_ACTIONS,
            Self::Manager => MANAGER_ACTIONS,
        }
    }

    /// Owned set useful for comparison and persistence planning.
    #[must_use]
    pub fn action_set(self) -> BTreeSet<Action> {
        self.actions().iter().copied().collect()
    }
}

/// Authority under which a caller is attempting to create a grant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DelegationMode {
    /// Preset-style content collaboration using `SHARE`.
    Share,
    /// Advanced per-action editing using `MANAGE_ACL`.
    ManageAcl,
}

impl DelegationMode {
    #[must_use]
    pub const fn required_action(self) -> Action {
        match self {
            Self::Share => Action::Share,
            Self::ManageAcl => Action::ManageAcl,
        }
    }
}

/// Stable reason a proposed grant violates strict attenuation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DelegationError {
    MissingAuthority(Action),
    ActionNotHeld(Action),
    ShareRequiresContentPreset(Action),
}

impl DelegationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingAuthority(_) => "authz.delegation.missing_authority",
            Self::ActionNotHeld(_) => "authz.delegation.action_not_held",
            Self::ShareRequiresContentPreset(_) => "authz.delegation.share_action_not_permitted",
        }
    }
}

/// Verifies a proposed grant without trimming or broadening it.
///
/// `Share` can issue Viewer/Contributor content actions. Advanced or policy
/// actions require `ManageAcl`. In both modes every requested action must be
/// held by the actor. Ownership is not an ACL action and cannot be delegated.
pub fn validate_delegation(
    held_actions: &BTreeSet<Action>,
    requested_actions: &BTreeSet<Action>,
    mode: DelegationMode,
) -> Result<(), DelegationError> {
    let authority = mode.required_action();
    if !held_actions.contains(&authority) {
        return Err(DelegationError::MissingAuthority(authority));
    }

    if mode == DelegationMode::Share {
        let shareable: BTreeSet<_> = CONTRIBUTOR_ACTIONS.iter().copied().collect();
        if let Some(action) = requested_actions
            .iter()
            .find(|action| !shareable.contains(action))
        {
            return Err(DelegationError::ShareRequiresContentPreset(*action));
        }
    }

    if let Some(action) = requested_actions
        .iter()
        .find(|action| !held_actions.contains(action))
    {
        return Err(DelegationError::ActionNotHeld(*action));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use filebelt_domain::{DriveId, NodeId};

    fn principal(index: u64) -> PrincipalId {
        PrincipalId::from_str(&format!("00000000-0000-4000-8000-{index:012x}"))
            .expect("test principal UUIDv4")
    }

    fn group(index: u64) -> GroupId {
        GroupId::from_str(&format!("10000000-0000-4000-8000-{index:012x}"))
            .expect("test group UUIDv4")
    }

    fn node(index: u64) -> ResourceId {
        ResourceId::Node(
            NodeId::from_str(&format!("20000000-0000-4000-8000-{index:012x}"))
                .expect("test node UUIDv4"),
        )
    }

    fn entry_id(index: u64) -> AclEntryId {
        AclEntryId::from_str(&format!("30000000-0000-4000-8000-{index:012x}"))
            .expect("test entry UUIDv4")
    }

    fn entry(
        index: u64,
        resource: ResourceId,
        subject: PrincipalId,
        action: Action,
        effect: Effect,
        inheritance: Inheritance,
    ) -> AclEntry {
        AclEntry::new(
            entry_id(index),
            resource,
            subject,
            action,
            effect,
            inheritance,
            Generation::new(index),
            principal(99),
        )
    }

    fn snapshot() -> GenerationSnapshot {
        GenerationSnapshot {
            resource_acl: Generation::new(3),
            membership: Generation::new(5),
            namespace: Generation::new(8),
        }
    }

    fn context(principal_id: PrincipalId) -> PrincipalContext {
        PrincipalContext::new(principal_id, Vec::new())
    }

    fn entry_with_creator(
        index: u64,
        resource: ResourceId,
        subject: PrincipalId,
        action: Action,
        effect: Effect,
        inheritance: Inheritance,
        creator: PrincipalId,
    ) -> AclEntry {
        AclEntry::new(
            entry_id(index),
            resource,
            subject,
            action,
            effect,
            inheritance,
            Generation::new(index),
            creator,
        )
    }

    fn independent_direct(
        index: u64,
        subject: PrincipalId,
        action: Action,
        effect: Effect,
    ) -> RecursiveShareResolvedAclEntry {
        RecursiveShareResolvedAclEntry::independent(ResolvedAclEntry::direct(entry_with_creator(
            index,
            node(1),
            subject,
            action,
            effect,
            Inheritance::ThisResource,
            principal(99),
        )))
    }

    fn independent_inherited_deny(
        index: u64,
        subject: PrincipalId,
        action: Action,
    ) -> RecursiveShareResolvedAclEntry {
        RecursiveShareResolvedAclEntry::independent(
            ResolvedAclEntry::inherited(
                entry_with_creator(
                    index,
                    node(2),
                    subject,
                    action,
                    Effect::Deny,
                    Inheritance::Descendants,
                    principal(99),
                ),
                1,
            )
            .expect("inherited deny"),
        )
    }

    fn recursive_inherited(
        index: u64,
        subject: PrincipalId,
        action: Action,
        creator: PrincipalId,
    ) -> RecursiveShareResolvedAclEntry {
        let entry = entry_with_creator(
            index,
            node(2),
            subject,
            action,
            Effect::Allow,
            Inheritance::Descendants,
            creator,
        );
        RecursiveShareResolvedAclEntry::recursive_direct_share(
            ResolvedAclEntry::inherited(entry, 1).expect("inherited recursive share"),
            creator,
        )
    }

    fn recursive_direct(
        index: u64,
        subject: PrincipalId,
        action: Action,
        creator: PrincipalId,
    ) -> RecursiveShareResolvedAclEntry {
        let entry = entry_with_creator(
            index,
            node(1),
            subject,
            action,
            Effect::Allow,
            Inheritance::Descendants,
            creator,
        );
        RecursiveShareResolvedAclEntry::recursive_direct_share(
            ResolvedAclEntry::direct(entry),
            creator,
        )
    }

    fn recursive_request<'a>(
        principal: &'a PrincipalContext,
        action: Action,
        entries: &'a [RecursiveShareResolvedAclEntry],
        creator_facts: &'a [PrincipalAuthorizationFacts],
        drive_owner: DriveOwner,
    ) -> RecursiveShareAuthorizationRequest<'a> {
        RecursiveShareAuthorizationRequest {
            principal,
            resource: node(1),
            drive_owner,
            action,
            entries,
            creator_facts,
            generations: snapshot(),
        }
    }

    fn non_owner() -> DriveOwner {
        DriveOwner::User(principal(90))
    }

    fn evaluate_entries(
        context: &PrincipalContext,
        resource: ResourceId,
        action: Action,
        entries: &[ResolvedAclEntry],
    ) -> AuthorizationDecision {
        evaluate(AuthorizationRequest {
            principal: context,
            resource,
            drive_owner: non_owner(),
            action,
            entries,
            generations: snapshot(),
        })
    }

    #[test]
    fn allow_deny_inheritance_matrix_is_fail_closed() {
        struct Case {
            name: &'static str,
            entries: Vec<ResolvedAclEntry>,
            allowed: bool,
            reason: DecisionReason,
        }

        let actor = principal(1);
        let context = PrincipalContext::new(actor, Vec::new());
        let target = node(1);
        let ancestor = node(2);
        let allow = entry(
            1,
            target,
            actor,
            Action::ReadContent,
            Effect::Allow,
            Inheritance::ThisResource,
        );
        let direct_deny = entry(
            2,
            target,
            actor,
            Action::ReadContent,
            Effect::Deny,
            Inheritance::ThisResource,
        );
        let inherited_allow = entry(
            3,
            ancestor,
            actor,
            Action::ReadContent,
            Effect::Allow,
            Inheritance::Descendants,
        );
        let inherited_deny = entry(
            4,
            ancestor,
            actor,
            Action::ReadContent,
            Effect::Deny,
            Inheritance::Descendants,
        );
        let child_only = entry(
            5,
            ancestor,
            actor,
            Action::ReadContent,
            Effect::Allow,
            Inheritance::Children,
        );
        let self_only = entry(
            6,
            ancestor,
            actor,
            Action::ReadContent,
            Effect::Allow,
            Inheritance::ThisResource,
        );

        let cases = [
            Case {
                name: "default deny",
                entries: vec![],
                allowed: false,
                reason: DecisionReason::NoMatchingGrant,
            },
            Case {
                name: "direct allow",
                entries: vec![ResolvedAclEntry::direct(allow)],
                allowed: true,
                reason: DecisionReason::ExplicitAllow,
            },
            Case {
                name: "direct deny beats direct allow",
                entries: vec![
                    ResolvedAclEntry::direct(allow),
                    ResolvedAclEntry::direct(direct_deny),
                ],
                allowed: false,
                reason: DecisionReason::ExplicitDeny,
            },
            Case {
                name: "inherited allow",
                entries: vec![ResolvedAclEntry::inherited(inherited_allow, 2).expect("ancestor")],
                allowed: true,
                reason: DecisionReason::InheritedAllow,
            },
            Case {
                name: "inherited deny cannot be overridden",
                entries: vec![
                    ResolvedAclEntry::direct(allow),
                    ResolvedAclEntry::inherited(inherited_deny, 2).expect("ancestor"),
                ],
                allowed: false,
                reason: DecisionReason::InheritedDeny,
            },
            Case {
                name: "children entry does not reach grandchildren",
                entries: vec![ResolvedAclEntry::inherited(child_only, 2).expect("ancestor")],
                allowed: false,
                reason: DecisionReason::NoMatchingGrant,
            },
            Case {
                name: "self entry does not inherit",
                entries: vec![ResolvedAclEntry::inherited(self_only, 1).expect("ancestor")],
                allowed: false,
                reason: DecisionReason::NoMatchingGrant,
            },
        ];

        for case in cases {
            let decision = evaluate_entries(&context, target, Action::ReadContent, &case.entries);
            assert_eq!(decision.allowed(), case.allowed, "{}", case.name);
            assert_eq!(decision.reason(), case.reason, "{}", case.name);
            assert_eq!(decision.generations(), snapshot(), "{}", case.name);
        }
    }

    #[test]
    fn unrelated_or_inconsistent_entries_do_not_apply() {
        let actor = principal(1);
        let context = PrincipalContext::new(actor, Vec::new());
        let target = node(1);
        let entries = [
            ResolvedAclEntry::direct(entry(
                1,
                target,
                principal(2),
                Action::ReadContent,
                Effect::Allow,
                Inheritance::ThisResource,
            )),
            ResolvedAclEntry::direct(entry(
                2,
                target,
                actor,
                Action::ReadMetadata,
                Effect::Allow,
                Inheritance::ThisResource,
            )),
            ResolvedAclEntry::direct(entry(
                3,
                node(2),
                actor,
                Action::ReadContent,
                Effect::Allow,
                Inheritance::ThisResource,
            )),
            ResolvedAclEntry::inherited(
                entry(
                    4,
                    target,
                    actor,
                    Action::ReadContent,
                    Effect::Allow,
                    Inheritance::Descendants,
                ),
                1,
            )
            .expect("nonzero distance"),
        ];
        assert_eq!(
            evaluate_entries(&context, target, Action::ReadContent, &entries).reason(),
            DecisionReason::NoMatchingGrant
        );
    }

    #[test]
    fn user_owner_rights_are_non_removable() {
        let actor = principal(1);
        let context = PrincipalContext::new(actor, Vec::new());
        let target = node(1);
        let deny = ResolvedAclEntry::direct(entry(
            1,
            target,
            actor,
            Action::Delete,
            Effect::Deny,
            Inheritance::ThisResource,
        ));
        let decision = evaluate(AuthorizationRequest {
            principal: &context,
            resource: target,
            drive_owner: DriveOwner::User(actor),
            action: Action::Delete,
            entries: &[deny],
            generations: snapshot(),
        });
        assert!(decision.allowed());
        assert_eq!(decision.reason(), DecisionReason::Owner);
        assert!(decision.source_entries().is_empty());
    }

    #[test]
    fn only_group_managers_receive_group_owner_rights() {
        let owner_group = group(1);
        let group_principal = principal(10);
        let member_context = PrincipalContext::new(
            principal(1),
            vec![GroupMembership {
                group_id: owner_group,
                group_principal_id: group_principal,
                role: GroupRole::Member,
            }],
        );
        let manager_context = PrincipalContext::new(
            principal(2),
            vec![GroupMembership {
                group_id: owner_group,
                group_principal_id: group_principal,
                role: GroupRole::Manager,
            }],
        );
        let target = node(1);
        let owner = DriveOwner::Group(owner_group);

        let member = evaluate(AuthorizationRequest {
            principal: &member_context,
            resource: target,
            drive_owner: owner,
            action: Action::ManageDrive,
            entries: &[],
            generations: snapshot(),
        });
        let manager = evaluate(AuthorizationRequest {
            principal: &manager_context,
            resource: target,
            drive_owner: owner,
            action: Action::ManageDrive,
            entries: &[],
            generations: snapshot(),
        });

        assert!(!member.allowed());
        assert_eq!(member.reason(), DecisionReason::NoMatchingGrant);
        assert!(manager.allowed());
        assert_eq!(manager.reason(), DecisionReason::GroupOwnerManager);
    }

    #[test]
    fn group_acl_entries_apply_to_members_and_managers() {
        let group_principal = principal(10);
        let membership = GroupMembership {
            group_id: group(1),
            group_principal_id: group_principal,
            role: GroupRole::Member,
        };
        let context = PrincipalContext::new(principal(1), vec![membership, membership]);
        assert_eq!(context.memberships(), &[membership]);
        let target = node(1);
        let allow = ResolvedAclEntry::direct(entry(
            1,
            target,
            group_principal,
            Action::ListChildren,
            Effect::Allow,
            Inheritance::ThisResource,
        ));
        assert!(evaluate_entries(&context, target, Action::ListChildren, &[allow]).allowed());
    }

    #[test]
    fn entry_order_cannot_change_a_decision_or_its_evidence() {
        let actor = principal(1);
        let context = PrincipalContext::new(actor, Vec::new());
        let target = node(1);
        let ancestor = node(2);
        let base = vec![
            ResolvedAclEntry::direct(entry(
                4,
                target,
                actor,
                Action::ReadContent,
                Effect::Allow,
                Inheritance::ThisResource,
            )),
            ResolvedAclEntry::inherited(
                entry(
                    3,
                    ancestor,
                    actor,
                    Action::ReadContent,
                    Effect::Deny,
                    Inheritance::Descendants,
                ),
                1,
            )
            .expect("ancestor"),
            ResolvedAclEntry::direct(entry(
                2,
                target,
                actor,
                Action::ReadContent,
                Effect::Deny,
                Inheritance::ThisResource,
            )),
            ResolvedAclEntry::direct(entry(
                1,
                target,
                actor,
                Action::ReadContent,
                Effect::Deny,
                Inheritance::ThisResource,
            )),
        ];
        let expected = evaluate_entries(&context, target, Action::ReadContent, &base);
        for shift in 0..base.len() {
            let mut candidate = base.clone();
            candidate.rotate_left(shift);
            assert_eq!(
                evaluate_entries(&context, target, Action::ReadContent, &candidate),
                expected
            );
            candidate.reverse();
            assert_eq!(
                evaluate_entries(&context, target, Action::ReadContent, &candidate),
                expected
            );
        }
        assert_eq!(
            expected.source_entries(),
            &[entry_id(1), entry_id(2), entry_id(3)]
        );
    }

    #[test]
    fn permission_presets_are_monotonic_and_exclude_management_boundaries() {
        let viewer = PermissionPreset::Viewer.action_set();
        let contributor = PermissionPreset::Contributor.action_set();
        let manager = PermissionPreset::Manager.action_set();
        assert!(viewer.is_subset(&contributor));
        assert!(contributor.is_subset(&manager));
        assert!(manager.contains(&Action::Share));
        assert!(manager.contains(&Action::ManageAcl));
        assert!(!manager.contains(&Action::ManageDrive));
        assert!(!manager.contains(&Action::UseMcp));
        assert!(!manager.contains(&Action::ReadRepository));
        assert!(!manager.contains(&Action::WriteRepository));
        assert!(!manager.contains(&Action::ManageRepository));
        assert!(!manager.contains(&Action::BypassRepositoryRules));
        assert!(viewer.contains(&Action::UseExternalEditor));
        assert!(contributor.contains(&Action::UseExternalEditor));
        assert!(contributor.contains(&Action::Comment));
        assert!(contributor.contains(&Action::Review));
    }

    #[test]
    fn repository_rule_bypass_is_not_an_implicit_owner_right() {
        let actor = principal(1);
        let principal = context(actor);
        let decision = evaluate(AuthorizationRequest {
            principal: &principal,
            resource: node(1),
            drive_owner: DriveOwner::User(actor),
            action: Action::BypassRepositoryRules,
            entries: &[],
            generations: snapshot(),
        });
        assert!(!decision.allowed());
        assert_eq!(decision.reason(), DecisionReason::NoMatchingGrant);

        let management = evaluate(AuthorizationRequest {
            principal: &principal,
            resource: node(1),
            drive_owner: DriveOwner::User(actor),
            action: Action::ManageRepository,
            entries: &[],
            generations: snapshot(),
        });
        assert!(management.allowed());
        assert_eq!(management.reason(), DecisionReason::Owner);
    }

    #[test]
    fn delegation_is_strict_and_share_is_not_manage_acl() {
        let mut held = PermissionPreset::Manager.action_set();
        assert_eq!(
            validate_delegation(
                &held,
                &PermissionPreset::Contributor.action_set(),
                DelegationMode::Share
            ),
            Ok(())
        );
        assert_eq!(
            validate_delegation(
                &held,
                &PermissionPreset::Manager.action_set(),
                DelegationMode::Share
            ),
            Err(DelegationError::ShareRequiresContentPreset(Action::Share))
        );

        held.remove(&Action::ManageAcl);
        assert_eq!(
            validate_delegation(
                &held,
                &PermissionPreset::Viewer.action_set(),
                DelegationMode::ManageAcl
            ),
            Err(DelegationError::MissingAuthority(Action::ManageAcl))
        );

        held.insert(Action::ManageAcl);
        let requested = [Action::ReadContent, Action::Export].into_iter().collect();
        assert_eq!(
            validate_delegation(&held, &requested, DelegationMode::ManageAcl),
            Err(DelegationError::ActionNotHeld(Action::Export))
        );
    }

    #[test]
    fn authorization_decisions_are_bound_to_every_generation() {
        let actor = principal(1);
        let context = PrincipalContext::new(actor, Vec::new());
        let target = node(1);
        let decision = evaluate_entries(&context, target, Action::ReadContent, &[]);
        assert!(decision.remains_valid_at(snapshot()));
        for current in [
            GenerationSnapshot {
                resource_acl: Generation::new(4),
                ..snapshot()
            },
            GenerationSnapshot {
                membership: Generation::new(6),
                ..snapshot()
            },
            GenerationSnapshot {
                namespace: Generation::new(9),
                ..snapshot()
            },
        ] {
            assert!(!decision.remains_valid_at(current));
        }
    }

    #[test]
    fn inheritance_and_reason_codes_are_stable() {
        assert!(Inheritance::ThisResource.applies_at(0));
        assert!(!Inheritance::ThisResource.applies_at(1));
        assert!(Inheritance::Children.applies_at(1));
        assert!(!Inheritance::Children.applies_at(2));
        assert!(Inheritance::Descendants.applies_at(u32::MAX));
        assert!(
            ResolvedAclEntry::inherited(
                entry(
                    1,
                    ResourceId::Drive(DriveId::generate()),
                    principal(1),
                    Action::ReadMetadata,
                    Effect::Allow,
                    Inheritance::Descendants,
                ),
                0
            )
            .is_none()
        );

        let reasons = [
            DecisionReason::Owner,
            DecisionReason::GroupOwnerManager,
            DecisionReason::ExplicitAllow,
            DecisionReason::InheritedAllow,
            DecisionReason::ExplicitDeny,
            DecisionReason::InheritedDeny,
            DecisionReason::NoMatchingGrant,
        ];
        for (index, reason) in reasons.iter().enumerate() {
            assert!(reason.code().starts_with("authz."));
            assert!(
                !reasons[..index]
                    .iter()
                    .any(|previous| previous.code() == reason.code())
            );
        }
    }

    #[test]
    fn recursive_share_respects_direct_denies_at_the_requested_child() {
        let recipient = context(principal(1));
        let creator = principal(2);
        let recipient_entries = [
            recursive_inherited(1, principal(1), Action::ReadContent, creator),
            independent_direct(2, principal(1), Action::ReadContent, Effect::Deny),
        ];
        let creator_entries = vec![
            independent_direct(3, creator, Action::Share, Effect::Allow),
            independent_direct(4, creator, Action::ReadContent, Effect::Allow),
        ];
        let facts = [PrincipalAuthorizationFacts::new(
            context(creator),
            creator_entries,
        )];

        let decision = evaluate_recursive_direct_shares(recursive_request(
            &recipient,
            Action::ReadContent,
            &recipient_entries,
            &facts,
            non_owner(),
        ))
        .expect("bounded graph");

        assert!(!decision.allowed());
        assert_eq!(decision.reason(), DecisionReason::ExplicitDeny);
    }

    #[test]
    fn recursive_share_at_its_root_requires_the_creator_proof() {
        let recipient = context(principal(1));
        let creator = principal(2);
        let recipient_entries = [recursive_direct(
            1,
            principal(1),
            Action::ReadContent,
            creator,
        )];
        let missing_proof = [PrincipalAuthorizationFacts::new(
            context(creator),
            Vec::new(),
        )];
        assert!(
            !evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &recipient_entries,
                &missing_proof,
                non_owner(),
            ))
            .expect("bounded graph")
            .allowed()
        );

        let proof = [PrincipalAuthorizationFacts::new(
            context(creator),
            vec![
                independent_direct(2, creator, Action::Share, Effect::Allow),
                independent_direct(3, creator, Action::ReadContent, Effect::Allow),
            ],
        )];
        assert!(
            evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &recipient_entries,
                &proof,
                non_owner(),
            ))
            .expect("bounded graph")
            .allowed()
        );
    }

    #[test]
    fn recursive_share_respects_inherited_denies_at_the_requested_child() {
        let recipient = context(principal(1));
        let creator = principal(2);
        let recipient_entries = [
            recursive_inherited(1, principal(1), Action::ReadContent, creator),
            independent_inherited_deny(2, principal(1), Action::ReadContent),
        ];
        let facts = [PrincipalAuthorizationFacts::new(
            context(creator),
            vec![
                independent_direct(3, creator, Action::Share, Effect::Allow),
                independent_direct(4, creator, Action::ReadContent, Effect::Allow),
            ],
        )];

        let decision = evaluate_recursive_direct_shares(recursive_request(
            &recipient,
            Action::ReadContent,
            &recipient_entries,
            &facts,
            non_owner(),
        ))
        .expect("bounded graph");

        assert!(!decision.allowed());
        assert_eq!(decision.reason(), DecisionReason::InheritedDeny);
    }

    #[test]
    fn recursive_share_requires_creator_share_and_the_requested_action() {
        let recipient = context(principal(1));
        let creator = principal(2);
        let recipient_entries = [recursive_inherited(
            1,
            principal(1),
            Action::ReadContent,
            creator,
        )];

        let no_share = [PrincipalAuthorizationFacts::new(
            context(creator),
            vec![independent_direct(
                2,
                creator,
                Action::ReadContent,
                Effect::Allow,
            )],
        )];
        let no_share_decision = evaluate_recursive_direct_shares(recursive_request(
            &recipient,
            Action::ReadContent,
            &recipient_entries,
            &no_share,
            non_owner(),
        ))
        .expect("bounded graph");
        assert!(!no_share_decision.allowed());

        let no_action = [PrincipalAuthorizationFacts::new(
            context(creator),
            vec![independent_direct(3, creator, Action::Share, Effect::Allow)],
        )];
        let no_action_decision = evaluate_recursive_direct_shares(recursive_request(
            &recipient,
            Action::ReadContent,
            &recipient_entries,
            &no_action,
            non_owner(),
        ))
        .expect("bounded graph");
        assert!(!no_action_decision.allowed());
    }

    #[test]
    fn recursive_share_accepts_user_and_group_owner_roots() {
        let recipient = context(principal(1));
        let user_owner = principal(2);
        let recipient_entries = [recursive_inherited(
            1,
            principal(1),
            Action::ReadContent,
            user_owner,
        )];
        let user_facts = [PrincipalAuthorizationFacts::new(
            context(user_owner),
            Vec::new(),
        )];
        assert!(
            evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &recipient_entries,
                &user_facts,
                DriveOwner::User(user_owner),
            ))
            .expect("bounded graph")
            .allowed()
        );

        let manager = principal(3);
        let owner_group = group(1);
        let manager_context = PrincipalContext::new(
            manager,
            vec![GroupMembership {
                group_id: owner_group,
                group_principal_id: principal(4),
                role: GroupRole::Manager,
            }],
        );
        let group_entries = [recursive_inherited(
            2,
            principal(1),
            Action::ReadContent,
            manager,
        )];
        let group_facts = [PrincipalAuthorizationFacts::new(
            manager_context,
            Vec::new(),
        )];
        assert!(
            evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &group_entries,
                &group_facts,
                DriveOwner::Group(owner_group),
            ))
            .expect("bounded graph")
            .allowed()
        );
    }

    #[test]
    fn recursive_share_allows_a_safe_transitive_chain() {
        let recipient = context(principal(1));
        let first_creator = principal(2);
        let owner = principal(3);
        let recipient_entries = [recursive_inherited(
            1,
            principal(1),
            Action::ReadContent,
            first_creator,
        )];
        let first_entries = vec![
            recursive_inherited(2, first_creator, Action::Share, owner),
            recursive_inherited(3, first_creator, Action::ReadContent, owner),
        ];
        let facts = [
            PrincipalAuthorizationFacts::new(context(first_creator), first_entries),
            PrincipalAuthorizationFacts::new(context(owner), Vec::new()),
        ];

        assert!(
            evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &recipient_entries,
                &facts,
                DriveOwner::User(owner),
            ))
            .expect("bounded graph")
            .allowed()
        );
    }

    #[test]
    fn recursive_share_cycles_need_an_independent_root() {
        let recipient = context(principal(1));
        let first = principal(2);
        let second = principal(3);
        let recipient_entries = [recursive_inherited(
            1,
            principal(1),
            Action::ReadContent,
            first,
        )];
        let first_entries = vec![
            recursive_inherited(2, first, Action::Share, second),
            recursive_inherited(3, first, Action::ReadContent, second),
        ];
        let second_entries = vec![
            recursive_inherited(4, second, Action::Share, first),
            recursive_inherited(5, second, Action::ReadContent, first),
        ];
        let rootless_facts = [
            PrincipalAuthorizationFacts::new(context(first), first_entries.clone()),
            PrincipalAuthorizationFacts::new(context(second), second_entries.clone()),
        ];
        assert!(
            !evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &recipient_entries,
                &rootless_facts,
                non_owner(),
            ))
            .expect("bounded graph")
            .allowed()
        );

        let rooted_facts = [
            PrincipalAuthorizationFacts::new(context(first), first_entries),
            PrincipalAuthorizationFacts::new(
                context(second),
                vec![
                    independent_direct(6, second, Action::Share, Effect::Allow),
                    independent_direct(7, second, Action::ReadContent, Effect::Allow),
                ],
            ),
        ];
        assert!(
            evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &recipient_entries,
                &rooted_facts,
                non_owner(),
            ))
            .expect("bounded graph")
            .allowed()
        );
    }

    #[test]
    fn recursive_share_uses_an_alternate_proof_and_resumes_when_facts_change() {
        let recipient = context(principal(1));
        let missing_creator = principal(2);
        let working_creator = principal(3);
        let recipient_entries = [
            recursive_inherited(1, principal(1), Action::ReadContent, missing_creator),
            recursive_inherited(2, principal(1), Action::ReadContent, working_creator),
        ];
        let blocked_facts = [PrincipalAuthorizationFacts::new(
            context(working_creator),
            vec![independent_direct(
                3,
                working_creator,
                Action::Share,
                Effect::Allow,
            )],
        )];
        assert!(
            !evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &recipient_entries,
                &blocked_facts,
                non_owner(),
            ))
            .expect("bounded graph")
            .allowed()
        );

        let resumed_facts = [PrincipalAuthorizationFacts::new(
            context(working_creator),
            vec![
                independent_direct(3, working_creator, Action::Share, Effect::Allow),
                independent_direct(4, working_creator, Action::ReadContent, Effect::Allow),
            ],
        )];
        assert!(
            evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &recipient_entries,
                &resumed_facts,
                non_owner(),
            ))
            .expect("bounded graph")
            .allowed()
        );
    }

    #[test]
    fn recursive_share_graph_depth_limit_is_exact() {
        fn chain(
            edges: usize,
        ) -> (
            PrincipalContext,
            Vec<RecursiveShareResolvedAclEntry>,
            Vec<PrincipalAuthorizationFacts>,
            DriveOwner,
        ) {
            let recipient = context(principal(1));
            let owner = principal(u64::try_from(edges + 1).expect("small chain"));
            let recipient_entries = vec![recursive_inherited(
                1,
                principal(1),
                Action::ReadContent,
                principal(2),
            )];
            let mut facts = Vec::new();
            for index in 0..edges.saturating_sub(1) {
                let actor = principal(u64::try_from(index + 2).expect("small chain"));
                let creator = principal(u64::try_from(index + 3).expect("small chain"));
                let entry_index = u64::try_from(index * 2 + 2).expect("small chain");
                facts.push(PrincipalAuthorizationFacts::new(
                    context(actor),
                    vec![
                        recursive_inherited(entry_index, actor, Action::Share, creator),
                        recursive_inherited(entry_index + 1, actor, Action::ReadContent, creator),
                    ],
                ));
            }
            facts.push(PrincipalAuthorizationFacts::new(context(owner), Vec::new()));
            (recipient, recipient_entries, facts, DriveOwner::User(owner))
        }

        let (recipient, entries, facts, owner) = chain(MAX_RECURSIVE_SHARE_DELEGATION_DEPTH);
        assert!(
            evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &entries,
                &facts,
                owner,
            ))
            .expect("exact depth limit succeeds")
            .allowed()
        );

        let (recipient, entries, facts, owner) = chain(MAX_RECURSIVE_SHARE_DELEGATION_DEPTH + 1);
        assert_eq!(
            evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &entries,
                &facts,
                owner,
            )),
            Err(RecursiveShareEvaluationError::DelegationDepthExceeded)
        );
    }

    #[test]
    fn recursive_share_edge_limit_is_exact() {
        fn wide_entries(count: usize) -> (PrincipalContext, Vec<RecursiveShareResolvedAclEntry>) {
            let recipient_id = principal(1);
            let memberships = (0..count)
                .map(|index| GroupMembership {
                    group_id: group(u64::try_from(index + 1).expect("small graph")),
                    group_principal_id: principal(
                        u64::try_from(index + 10_000).expect("small graph"),
                    ),
                    role: GroupRole::Member,
                })
                .collect();
            let entries = (0..count)
                .map(|index| {
                    let subject = principal(u64::try_from(index + 10_000).expect("small graph"));
                    let creator = principal(u64::try_from(index + 20_000).expect("small graph"));
                    recursive_inherited(
                        u64::try_from(index + 1).expect("small graph"),
                        subject,
                        Action::ReadContent,
                        creator,
                    )
                })
                .collect();
            (PrincipalContext::new(recipient_id, memberships), entries)
        }

        let (recipient, entries) = wide_entries(MAX_RECURSIVE_SHARE_EDGES);
        assert!(
            !evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &entries,
                &[],
                non_owner(),
            ))
            .expect("exact edge limit succeeds")
            .allowed()
        );

        let (recipient, entries) = wide_entries(MAX_RECURSIVE_SHARE_EDGES + 1);
        assert_eq!(
            evaluate_recursive_direct_shares(recursive_request(
                &recipient,
                Action::ReadContent,
                &entries,
                &[],
                non_owner(),
            )),
            Err(RecursiveShareEvaluationError::RecursiveEdgeLimitExceeded)
        );
    }
}

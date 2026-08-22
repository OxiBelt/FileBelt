// SPDX-License-Identifier: Apache-2.0

//! Pure evaluation of layered directory-repository ref protection.
//!
//! Callers select the active rulesets whose branch or tag patterns match the
//! proposed ref. This module combines those already-authoritative facts using
//! FileBelt's most-restrictive-wins contract. Authentication, Virtual ACL,
//! recent-OIDC bypass grants, persistence, Git inspection, and status posting
//! remain outside this package.

use std::collections::BTreeSet;

/// The kind of ref mutation proposed by a repository operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefMutation {
    Create,
    Update,
    Delete,
}

/// A signer identity class understood by repository rules.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VerifiedSigner {
    AuthenticatedActor,
    FileBeltService,
    OtherRegistered,
}

/// Signer evidence required by one or more active rulesets.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RequiredSigner {
    AnyVerified,
    AuthenticatedActor,
    FileBeltService,
}

/// The combined requirements of one active ruleset.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepositoryRuleRequirements {
    pub deny_create: bool,
    pub deny_update: bool,
    pub deny_delete: bool,
    pub require_fast_forward: bool,
    pub require_linear_history: bool,
    pub require_pull_request: bool,
    pub minimum_approvals: u16,
    pub require_last_push_approval: bool,
    pub required_signers: BTreeSet<RequiredSigner>,
    pub required_status_checks: BTreeSet<String>,
    pub required_deployments: BTreeSet<String>,
}

impl RepositoryRuleRequirements {
    /// The default `main` policy for a newly created directory repository.
    ///
    /// Direct, signed, fast-forward updates remain available to authorized Web,
    /// mount, and Git writers. Ref deletion and history replacement fail closed.
    #[must_use]
    pub fn safe_writable_main() -> Self {
        Self {
            deny_delete: true,
            require_fast_forward: true,
            required_signers: [RequiredSigner::AnyVerified].into_iter().collect(),
            ..Self::default()
        }
    }

    /// Combines another matching active ruleset without weakening either one.
    pub fn require(&mut self, other: &Self) {
        self.deny_create |= other.deny_create;
        self.deny_update |= other.deny_update;
        self.deny_delete |= other.deny_delete;
        self.require_fast_forward |= other.require_fast_forward;
        self.require_linear_history |= other.require_linear_history;
        self.require_pull_request |= other.require_pull_request;
        self.minimum_approvals = self.minimum_approvals.max(other.minimum_approvals);
        self.require_last_push_approval |= other.require_last_push_approval;
        self.required_signers
            .extend(other.required_signers.iter().copied());
        self.required_status_checks
            .extend(other.required_status_checks.iter().cloned());
        self.required_deployments
            .extend(other.required_deployments.iter().cloned());
    }
}

/// Validated evidence for the exact proposed ref target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryAdmissionEvidence {
    pub mutation: RefMutation,
    pub fast_forward: bool,
    pub linear_history: bool,
    pub signer: Option<VerifiedSigner>,
    pub pull_request: bool,
    pub approvals: u16,
    pub last_push_approved: bool,
    pub successful_status_checks: BTreeSet<String>,
    pub successful_deployments: BTreeSet<String>,
    /// A separately authorized, recent-OIDC, reason-bearing, one-operation
    /// bypass grant. The evaluator never manufactures this authority.
    pub validated_bypass: bool,
}

/// Stable reasons that a ref update failed repository protection.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RepositoryAdmissionFailure {
    CreationDenied,
    UpdateDenied,
    DeletionDenied,
    NonFastForward,
    NonLinearHistory,
    PullRequestRequired,
    ApprovalsRequired { required: u16, actual: u16 },
    LastPushApprovalRequired,
    VerifiedSignatureRequired,
    AuthenticatedActorSignatureRequired,
    FileBeltServiceSignatureRequired,
    StatusCheckRequired(String),
    DeploymentRequired(String),
}

/// Evaluates already-matched active rulesets for one exact target ref.
#[must_use]
pub fn evaluate_repository_admission(
    requirements: &RepositoryRuleRequirements,
    evidence: &RepositoryAdmissionEvidence,
) -> Vec<RepositoryAdmissionFailure> {
    if evidence.validated_bypass {
        return Vec::new();
    }

    let mut failures = BTreeSet::new();
    match evidence.mutation {
        RefMutation::Create if requirements.deny_create => {
            failures.insert(RepositoryAdmissionFailure::CreationDenied);
        }
        RefMutation::Update if requirements.deny_update => {
            failures.insert(RepositoryAdmissionFailure::UpdateDenied);
        }
        RefMutation::Delete if requirements.deny_delete => {
            failures.insert(RepositoryAdmissionFailure::DeletionDenied);
        }
        RefMutation::Create | RefMutation::Update | RefMutation::Delete => {}
    }
    if requirements.require_fast_forward
        && evidence.mutation == RefMutation::Update
        && !evidence.fast_forward
    {
        failures.insert(RepositoryAdmissionFailure::NonFastForward);
    }
    if requirements.require_linear_history && !evidence.linear_history {
        failures.insert(RepositoryAdmissionFailure::NonLinearHistory);
    }
    if requirements.require_pull_request && !evidence.pull_request {
        failures.insert(RepositoryAdmissionFailure::PullRequestRequired);
    }
    if evidence.approvals < requirements.minimum_approvals {
        failures.insert(RepositoryAdmissionFailure::ApprovalsRequired {
            required: requirements.minimum_approvals,
            actual: evidence.approvals,
        });
    }
    if requirements.require_last_push_approval && !evidence.last_push_approved {
        failures.insert(RepositoryAdmissionFailure::LastPushApprovalRequired);
    }
    for required in &requirements.required_signers {
        let satisfied = match required {
            RequiredSigner::AnyVerified => evidence.signer.is_some(),
            RequiredSigner::AuthenticatedActor => {
                evidence.signer == Some(VerifiedSigner::AuthenticatedActor)
            }
            RequiredSigner::FileBeltService => {
                evidence.signer == Some(VerifiedSigner::FileBeltService)
            }
        };
        if !satisfied {
            failures.insert(match required {
                RequiredSigner::AnyVerified => {
                    RepositoryAdmissionFailure::VerifiedSignatureRequired
                }
                RequiredSigner::AuthenticatedActor => {
                    RepositoryAdmissionFailure::AuthenticatedActorSignatureRequired
                }
                RequiredSigner::FileBeltService => {
                    RepositoryAdmissionFailure::FileBeltServiceSignatureRequired
                }
            });
        }
    }
    for context in requirements
        .required_status_checks
        .difference(&evidence.successful_status_checks)
    {
        failures.insert(RepositoryAdmissionFailure::StatusCheckRequired(
            context.clone(),
        ));
    }
    for environment in requirements
        .required_deployments
        .difference(&evidence.successful_deployments)
    {
        failures.insert(RepositoryAdmissionFailure::DeploymentRequired(
            environment.clone(),
        ));
    }
    failures.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{
        RefMutation, RepositoryAdmissionEvidence, RepositoryAdmissionFailure,
        RepositoryRuleRequirements, RequiredSigner, VerifiedSigner, evaluate_repository_admission,
    };
    use std::collections::BTreeSet;

    fn evidence() -> RepositoryAdmissionEvidence {
        RepositoryAdmissionEvidence {
            mutation: RefMutation::Update,
            fast_forward: true,
            linear_history: true,
            signer: Some(VerifiedSigner::AuthenticatedActor),
            pull_request: false,
            approvals: 0,
            last_push_approved: false,
            successful_status_checks: BTreeSet::new(),
            successful_deployments: BTreeSet::new(),
            validated_bypass: false,
        }
    }

    #[test]
    fn safe_writable_main_allows_signed_fast_forward_updates() {
        let requirements = RepositoryRuleRequirements::safe_writable_main();
        assert!(evaluate_repository_admission(&requirements, &evidence()).is_empty());

        let mut unsigned = evidence();
        unsigned.signer = None;
        assert_eq!(
            evaluate_repository_admission(&requirements, &unsigned),
            vec![RepositoryAdmissionFailure::VerifiedSignatureRequired]
        );

        let mut forced = evidence();
        forced.fast_forward = false;
        assert_eq!(
            evaluate_repository_admission(&requirements, &forced),
            vec![RepositoryAdmissionFailure::NonFastForward]
        );

        let mut deletion = evidence();
        deletion.mutation = RefMutation::Delete;
        assert_eq!(
            evaluate_repository_admission(&requirements, &deletion),
            vec![RepositoryAdmissionFailure::DeletionDenied]
        );
    }

    #[test]
    fn layered_rules_union_requirements_without_weakening() {
        let mut requirements = RepositoryRuleRequirements::safe_writable_main();
        requirements.require(&RepositoryRuleRequirements {
            require_pull_request: true,
            minimum_approvals: 2,
            require_last_push_approval: true,
            required_signers: [RequiredSigner::AuthenticatedActor].into_iter().collect(),
            required_status_checks: ["build".to_owned()].into_iter().collect(),
            required_deployments: ["production".to_owned()].into_iter().collect(),
            ..RepositoryRuleRequirements::default()
        });

        let failures = evaluate_repository_admission(&requirements, &evidence());
        assert_eq!(
            failures,
            vec![
                RepositoryAdmissionFailure::PullRequestRequired,
                RepositoryAdmissionFailure::ApprovalsRequired {
                    required: 2,
                    actual: 0,
                },
                RepositoryAdmissionFailure::LastPushApprovalRequired,
                RepositoryAdmissionFailure::StatusCheckRequired("build".to_owned()),
                RepositoryAdmissionFailure::DeploymentRequired("production".to_owned()),
            ]
        );
    }

    #[test]
    fn incompatible_signer_layers_fail_closed() {
        let requirements = RepositoryRuleRequirements {
            required_signers: [
                RequiredSigner::AuthenticatedActor,
                RequiredSigner::FileBeltService,
            ]
            .into_iter()
            .collect(),
            ..RepositoryRuleRequirements::default()
        };
        let failures = evaluate_repository_admission(&requirements, &evidence());
        assert_eq!(
            failures,
            vec![RepositoryAdmissionFailure::FileBeltServiceSignatureRequired]
        );
    }

    #[test]
    fn only_prevalidated_bypass_skips_rules() {
        let requirements = RepositoryRuleRequirements {
            deny_update: true,
            require_pull_request: true,
            minimum_approvals: u16::MAX,
            ..RepositoryRuleRequirements::default()
        };
        let mut bypass = evidence();
        bypass.validated_bypass = true;
        assert!(evaluate_repository_admission(&requirements, &bypass).is_empty());
    }
}

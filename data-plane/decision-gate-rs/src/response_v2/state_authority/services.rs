use super::contract::{AuthorityError, AuthorityResult, Identifier};
use super::lifecycle::OperationKind;
use super::rpc::AuthorityArtifactType;
use super::topology::{ServiceRole, TrustedHostTopology};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThinServiceContract {
    pub role: ServiceRole,
    pub private_key_count: u8,
    pub can_sign_authority_artifacts: bool,
    pub direct_postgres_access: bool,
    pub upstream_network_access: bool,
    pub accepts_raw_credentials: bool,
    pub accepts_raw_upstream_bytes: bool,
    pub operations: &'static [OperationKind],
}

const ROUTER_OPERATIONS: &[OperationKind] = &[
    OperationKind::GenerationReady,
];

const STATE_OPERATIONS: &[OperationKind] = &[
    OperationKind::GenerationInstall,
    OperationKind::GenerationReconcile,
    OperationKind::GenerationReady,
    OperationKind::AttemptReserve,
    OperationKind::AttemptAuthorize,
    OperationKind::ObjectCommitRaw,
    OperationKind::ObjectInspectImmutableRaw,
    OperationKind::AttemptStage,
    OperationKind::DispatchBegin,
    OperationKind::DispatchRecordOutcome,
    OperationKind::AttemptTerminalize,
    OperationKind::AttemptFinalize,
    OperationKind::AttemptPublish,
    OperationKind::ReleaseConsumeAndRetrieveExact,
    OperationKind::ReleaseResolveReplay,
    OperationKind::AttemptSettle,
    OperationKind::AttemptArchive,
    OperationKind::FenceRevoke,
    OperationKind::FenceObserveQuiescence,
    OperationKind::EvidenceAppend,
    OperationKind::PublisherEnqueue,
    OperationKind::PublisherAcknowledge,
    OperationKind::TransparencyCheckpoint,
    OperationKind::TrustedTimeAdvance,
    OperationKind::ReconciliationTransition,
    OperationKind::ReconciliationTerminalizeExpiredAttempt,
    OperationKind::StateQuery,
];

const CREDENTIAL_OPERATIONS: &[OperationKind] = &[
    OperationKind::GenerationReady,
    OperationKind::DispatchBegin,
    OperationKind::DispatchRecordOutcome,
    OperationKind::EvidenceAppend,
];

const POLICY_OPERATIONS: &[OperationKind] = &[
    OperationKind::GenerationReady,
    OperationKind::AttemptAuthorize,
    OperationKind::ObjectInspectImmutableRaw,
    OperationKind::EvidenceAppend,
    OperationKind::AttemptFinalize,
];

const ARTIFACT_OPERATIONS: &[OperationKind] = &[
    OperationKind::GenerationReady,
    OperationKind::ObjectCommitRaw,
    OperationKind::ObjectInspectImmutableRaw,
    OperationKind::EvidenceAppend,
    OperationKind::AttemptArchive,
];

const RELEASE_OPERATIONS: &[OperationKind] = &[
    OperationKind::GenerationReady,
    OperationKind::AttemptFinalize,
    OperationKind::AttemptPublish,
    OperationKind::ObjectInspectImmutableRaw,
    OperationKind::ReleaseConsumeAndRetrieveExact,
    OperationKind::ReleaseResolveReplay,
    OperationKind::PublisherEnqueue,
    OperationKind::PublisherAcknowledge,
    OperationKind::TransparencyCheckpoint,
    OperationKind::EvidenceAppend,
];

const CLEANUP_OPERATIONS: &[OperationKind] = &[
    OperationKind::GenerationReconcile,
    OperationKind::GenerationReady,
    OperationKind::StateQuery,
    OperationKind::FenceRevoke,
    OperationKind::FenceObserveQuiescence,
    OperationKind::ReconciliationTransition,
    OperationKind::ReconciliationTerminalizeExpiredAttempt,
    OperationKind::AttemptSettle,
    OperationKind::AttemptTerminalize,
    OperationKind::EvidenceAppend,
];

pub const fn service_contract(role: ServiceRole) -> ThinServiceContract {
    match role {
        ServiceRole::CustodyRouter => ThinServiceContract {
            role,
            private_key_count: 1,
            can_sign_authority_artifacts: true,
            direct_postgres_access: false,
            upstream_network_access: false,
            accepts_raw_credentials: false,
            accepts_raw_upstream_bytes: false,
            operations: ROUTER_OPERATIONS,
        },
        ServiceRole::StateAuthority => ThinServiceContract {
            role,
            private_key_count: 1,
            can_sign_authority_artifacts: true,
            direct_postgres_access: true,
            upstream_network_access: false,
            accepts_raw_credentials: false,
            accepts_raw_upstream_bytes: false,
            operations: STATE_OPERATIONS,
        },
        ServiceRole::CredentialTransport => ThinServiceContract {
            role,
            private_key_count: 1,
            can_sign_authority_artifacts: true,
            direct_postgres_access: false,
            upstream_network_access: true,
            accepts_raw_credentials: true,
            accepts_raw_upstream_bytes: true,
            operations: CREDENTIAL_OPERATIONS,
        },
        ServiceRole::PolicyProofVerifier => ThinServiceContract {
            role,
            private_key_count: 1,
            can_sign_authority_artifacts: true,
            direct_postgres_access: false,
            upstream_network_access: false,
            accepts_raw_credentials: false,
            accepts_raw_upstream_bytes: false,
            operations: POLICY_OPERATIONS,
        },
        ServiceRole::ImmutableArtifactLedger => ThinServiceContract {
            role,
            private_key_count: 1,
            can_sign_authority_artifacts: true,
            direct_postgres_access: false,
            upstream_network_access: false,
            accepts_raw_credentials: false,
            accepts_raw_upstream_bytes: true,
            operations: ARTIFACT_OPERATIONS,
        },
        ServiceRole::ReleaseAttestorPublisher => ThinServiceContract {
            role,
            private_key_count: 1,
            can_sign_authority_artifacts: true,
            direct_postgres_access: false,
            upstream_network_access: false,
            accepts_raw_credentials: false,
            accepts_raw_upstream_bytes: false,
            operations: RELEASE_OPERATIONS,
        },
        ServiceRole::CleanupWatchdog => ThinServiceContract {
            role,
            private_key_count: 1,
            can_sign_authority_artifacts: true,
            direct_postgres_access: false,
            upstream_network_access: false,
            accepts_raw_credentials: false,
            accepts_raw_upstream_bytes: false,
            operations: CLEANUP_OPERATIONS,
        },
    }
}

pub fn service_contracts() -> Vec<ThinServiceContract> {
    ServiceRole::ALL
        .into_iter()
        .map(service_contract)
        .collect()
}

pub fn validate_service_operation_matrix(
    topology: &TrustedHostTopology,
) -> AuthorityResult<()> {
    for identity in &topology.roles {
        let expected: BTreeSet<_> = service_contract(identity.role)
            .operations
            .iter()
            .map(|operation| Identifier(operation.as_str().to_owned()))
            .collect();
        let actual: BTreeSet<_> =
            identity.enabled_operations.iter().cloned().collect();
        if actual != expected
            || actual.len() != identity.enabled_operations.len()
        {
            return Err(AuthorityError::InvalidContract {
                field: "providerGeneration.topology.roles.enabledOperations",
                reason: format!(
                    "{} operations do not match the fixed response-v2 role matrix",
                    identity.role.as_str()
                ),
            });
        }
    }
    Ok(())
}

pub const fn artifact_contract_allows(
    role: ServiceRole,
    operation: OperationKind,
    artifact_type: AuthorityArtifactType,
) -> bool {
    use AuthorityArtifactType as Artifact;
    use OperationKind as Operation;
    use ServiceRole as Role;

    matches!(
        (role, operation, artifact_type),
        (
            Role::CustodyRouter
                | Role::StateAuthority
                | Role::CredentialTransport
                | Role::PolicyProofVerifier
                | Role::ImmutableArtifactLedger
                | Role::ReleaseAttestorPublisher
                | Role::CleanupWatchdog,
            Operation::GenerationReady,
            Artifact::RoleReadiness
        )
            | (
                Role::CustodyRouter,
                Operation::GenerationReady,
                Artifact::RouterTopologyAttestation
            )
            | (
                Role::PolicyProofVerifier,
                Operation::AttemptAuthorize,
                Artifact::TransitionAuthorization
            )
            | (
                Role::ImmutableArtifactLedger,
                Operation::ObjectCommitRaw,
                Artifact::ArtifactCommit
            )
            | (
                Role::CredentialTransport,
                Operation::DispatchBegin,
                Artifact::CredentialUse
            )
            | (
                Role::CredentialTransport,
                Operation::DispatchRecordOutcome,
                Artifact::TargetEffect
            )
            | (
                Role::PolicyProofVerifier,
                Operation::AttemptFinalize,
                Artifact::FinalEnvelopeVerification
            )
            | (
                Role::ReleaseAttestorPublisher,
                Operation::AttemptPublish
                    | Operation::PublisherEnqueue
                    | Operation::PublisherAcknowledge,
                Artifact::Publication
            )
            | (
                Role::ReleaseAttestorPublisher,
                Operation::ReleaseConsumeAndRetrieveExact,
                Artifact::ReleaseAuthorization
                    | Artifact::ReleaseConsumptionPreauthorization
            )
            | (
                Role::StateAuthority,
                Operation::ReleaseConsumeAndRetrieveExact,
                Artifact::ReleasePreparationReceipt
            )
            | (
                Role::StateAuthority,
                Operation::ObjectInspectImmutableRaw,
                Artifact::ImmutableInspection
            )
            | (
                Role::CleanupWatchdog,
                Operation::AttemptSettle,
                Artifact::Reconciliation | Artifact::Recovery
            )
            | (
                Role::ImmutableArtifactLedger,
                Operation::AttemptArchive,
                Artifact::Archive
            )
            | (
                Role::CleanupWatchdog,
                Operation::FenceRevoke | Operation::FenceObserveQuiescence,
                Artifact::CleanupObservation
            )
            | (
                Role::StateAuthority,
                Operation::TrustedTimeAdvance,
                Artifact::TrustedTime
            )
            | (
                Role::CleanupWatchdog,
                Operation::ReconciliationTransition,
                Artifact::Reconciliation
            )
            | (
                Role::CleanupWatchdog,
                Operation::ReconciliationTerminalizeExpiredAttempt,
                Artifact::Recovery
            )
            | (
                Role::ReleaseAttestorPublisher,
                Operation::TransparencyCheckpoint,
                Artifact::TransparencyCheckpoint
            )
            | (
                Role::StateAuthority,
                Operation::EvidenceAppend,
                Artifact::StateCas
            )
            | (
                Role::PolicyProofVerifier,
                Operation::EvidenceAppend,
                Artifact::PolicyProof
            )
            | (
                Role::CredentialTransport,
                Operation::EvidenceAppend,
                Artifact::CredentialUse | Artifact::TargetEffect
            )
            | (
                Role::ImmutableArtifactLedger,
                Operation::EvidenceAppend,
                Artifact::ArtifactCommit | Artifact::Archive
            )
            | (
                Role::ReleaseAttestorPublisher,
                Operation::EvidenceAppend,
                Artifact::Attestation
                    | Artifact::Publication
                    | Artifact::ReleaseAuthorization
                    | Artifact::TransparencyCheckpoint
            )
            | (
                Role::CleanupWatchdog,
                Operation::EvidenceAppend,
                Artifact::Recovery
                    | Artifact::CleanupObservation
                    | Artifact::TrustedTime
                    | Artifact::Reconciliation
            )
    )
}

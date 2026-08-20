use super::contract::{
    AuthorityError, AuthorityResult, Digest, Identifier,
    LOCAL_FAULT_DOMAIN_ID, LOCAL_QUORUM_PROFILE,
    PROVIDER_GENERATION_API_VERSION, PROVIDER_GENERATION_KIND,
    SIGNATURE_ALGORITHM,
};
use super::lifecycle::ReconciliationDomain;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceRole {
    CustodyRouter,
    StateAuthority,
    CredentialTransport,
    PolicyProofVerifier,
    ImmutableArtifactLedger,
    ReleaseAttestorPublisher,
    CleanupWatchdog,
}

impl ServiceRole {
    pub const ALL: [Self; 7] = [
        Self::CustodyRouter,
        Self::StateAuthority,
        Self::CredentialTransport,
        Self::PolicyProofVerifier,
        Self::ImmutableArtifactLedger,
        Self::ReleaseAttestorPublisher,
        Self::CleanupWatchdog,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CustodyRouter => "custody-router",
            Self::StateAuthority => "state-authority",
            Self::CredentialTransport => "credential-transport",
            Self::PolicyProofVerifier => "policy-proof-verifier",
            Self::ImmutableArtifactLedger => "immutable-artifact-ledger",
            Self::ReleaseAttestorPublisher => {
                "release-attestor-publisher"
            }
            Self::CleanupWatchdog => "cleanup-watchdog",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum QuorumProfile {
    #[serde(rename = "LOCAL_1_OF_1")]
    Local1Of1,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum GenerationAttestationProfile {
    TrustedHostNoTee,
    TeeHardware,
}

impl GenerationAttestationProfile {
    pub const fn hardware_proof(self) -> bool {
        matches!(self, Self::TeeHardware)
    }
}

impl QuorumProfile {
    pub const fn as_str(self) -> &'static str {
        LOCAL_QUORUM_PROFILE
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GenerationStatus {
    Provisioned,
    Reconciling,
    Ready,
    Quarantined,
    Retired,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleIdentity {
    pub role_id: Identifier,
    pub role: ServiceRole,
    pub process_id: Identifier,
    pub unix_uid: u32,
    pub unix_gid: u32,
    pub fault_domain_id: Identifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Identifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_base64url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_sha256: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_algorithm: Option<String>,
    pub authority_artifact_signing: bool,
    pub executable_sha256: Digest,
    pub configuration_sha256: Digest,
    pub enabled_operations: Vec<Identifier>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogicalRoleBinding {
    pub logical_role: Identifier,
    pub service_role: ServiceRole,
    pub process_id: Identifier,
    pub role_id: Identifier,
    pub key_id: Identifier,
    pub public_key_base64url: String,
    pub public_key_sha256: Digest,
    pub signing_algorithm: String,
    pub enabled_operations: Vec<Identifier>,
    pub authority_scope_sha256: Digest,
}

impl LogicalRoleBinding {
    pub fn validate(&self) -> AuthorityResult<()> {
        self.logical_role
            .validate("logicalRoleBinding.logicalRole", 128)?;
        self.process_id
            .validate("logicalRoleBinding.processId", 128)?;
        self.role_id.validate("logicalRoleBinding.roleId", 128)?;
        self.key_id.validate("logicalRoleBinding.keyId", 128)?;
        self.public_key_sha256
            .validate("logicalRoleBinding.publicKeySha256")?;
        self.authority_scope_sha256
            .validate("logicalRoleBinding.authorityScopeSha256")?;
        if self.signing_algorithm != SIGNATURE_ALGORITHM
            || self.public_key_base64url.len() != 43
            || !self.public_key_base64url.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
            })
            || self.enabled_operations.is_empty()
            || self.enabled_operations.len() > 27
        {
            return Err(AuthorityError::InvalidContract {
                field: "logicalRoleBinding",
                reason: "logical subkeys require Ed25519, one exact public key, and one to 27 operations"
                    .to_owned(),
            });
        }
        let mut operations = BTreeSet::new();
        for operation in &self.enabled_operations {
            operation.validate("logicalRoleBinding.enabledOperations[]", 128)?;
            if !operations.insert(operation.clone()) {
                return Err(AuthorityError::InvalidContract {
                    field: "logicalRoleBinding.enabledOperations",
                    reason: "duplicate operation".to_owned(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadinessContract {
    pub required_service_roles: Vec<ServiceRole>,
    pub required_reconciliation_domains: Vec<ReconciliationDomain>,
    pub service_receipt_count: u8,
    pub reconciliation_domain_receipt_count: u8,
    pub contract_sha256: Digest,
}

impl RoleIdentity {
    pub fn validate(&self) -> AuthorityResult<()> {
        self.role_id.validate("roleIdentity.roleId", 128)?;
        self.process_id
            .validate("roleIdentity.processId", 128)?;
        self.fault_domain_id
            .validate("roleIdentity.faultDomainId", 128)?;
        self.executable_sha256
            .validate("roleIdentity.executableSha256")?;
        self.configuration_sha256
            .validate("roleIdentity.configurationSha256")?;
        if self.fault_domain_id.0 != LOCAL_FAULT_DOMAIN_ID {
            return Err(AuthorityError::InvalidContract {
                field: "roleIdentity.faultDomainId",
                reason: "TrustedHostNoTee requires host-1".to_owned(),
            });
        }
        if !self.authority_artifact_signing {
            return Err(AuthorityError::InvalidContract {
                field: "roleIdentity.authorityArtifactSigning",
                reason: "all seven services must sign their own readiness artifacts"
                    .to_owned(),
            });
        }
        let key_id = self.key_id.as_ref().ok_or_else(|| {
                AuthorityError::InvalidContract {
                    field: "roleIdentity.keyId",
                    reason: "service role requires a key ID".to_owned(),
                }
            })?;
        key_id.validate("roleIdentity.keyId", 128)?;
        let public_key = self
            .public_key_base64url
            .as_ref()
            .ok_or_else(|| AuthorityError::InvalidContract {
                    field: "roleIdentity.publicKeyBase64url",
                    reason: "service role requires an Ed25519 public key"
                        .to_owned(),
                })?;
        if public_key.len() != 43
            || !public_key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || byte == b'_'
                    || byte == b'-'
            })
        {
            return Err(AuthorityError::InvalidContract {
                field: "roleIdentity.publicKeyBase64url",
                reason: "Ed25519 public key must be exactly 43 unpadded base64url characters"
                    .to_owned(),
            });
        }
        self.public_key_sha256
            .as_ref()
            .ok_or_else(|| AuthorityError::InvalidContract {
                    field: "roleIdentity.publicKeySha256",
                    reason: "service role requires a public-key digest"
                        .to_owned(),
                })?
            .validate("roleIdentity.publicKeySha256")?;
        if self.signing_algorithm.as_deref() != Some(SIGNATURE_ALGORITHM) {
            return Err(AuthorityError::InvalidContract {
                field: "roleIdentity.signingAlgorithm",
                reason: "service roles require Ed25519".to_owned(),
            });
        }
        if self.enabled_operations.is_empty() {
            return Err(AuthorityError::InvalidContract {
                field: "roleIdentity.enabledOperations",
                reason: "at least one exact operation is required".to_owned(),
            });
        }
        if self.enabled_operations.len() > 27 {
            return Err(AuthorityError::InvalidContract {
                field: "roleIdentity.enabledOperations",
                reason: "at most 27 exact operations are permitted".to_owned(),
            });
        }
        let mut operations = BTreeSet::new();
        for operation in &self.enabled_operations {
            operation.validate("roleIdentity.enabledOperations[]", 128)?;
            if !operations.insert(operation.clone()) {
                return Err(AuthorityError::InvalidContract {
                    field: "roleIdentity.enabledOperations",
                    reason: "duplicate operation".to_owned(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedHostTopology {
    pub attestation_mode: GenerationAttestationProfile,
    pub fault_domain_id: Identifier,
    pub fault_domain_count: u8,
    pub quorum_profile: QuorumProfile,
    pub external_witness_count: u8,
    pub hardware_proof: bool,
    pub roles: Vec<RoleIdentity>,
    pub logical_role_bindings: Vec<LogicalRoleBinding>,
    pub readiness_contract: ReadinessContract,
}

impl TrustedHostTopology {
    pub fn validate(&self) -> AuthorityResult<()> {
        if self.fault_domain_id.0 != LOCAL_FAULT_DOMAIN_ID
            || self.fault_domain_count != 1
            || self.quorum_profile != QuorumProfile::Local1Of1
            || self.external_witness_count != 0
            || self.hardware_proof
                != self.attestation_mode.hardware_proof()
        {
            return Err(AuthorityError::InvalidContract {
                field: "topology",
                reason: "topology must exactly pair TrustedHostNoTee with hardwareProof=false or TeeHardware with hardwareProof=true while retaining host-1, LOCAL_1_OF_1, one fault domain, zero external witnesses, and zero fault tolerance"
                    .to_owned(),
            });
        }
        if self.roles.len() != ServiceRole::ALL.len() {
            return Err(AuthorityError::InvalidContract {
                field: "topology.roles",
                reason: "exactly seven roles are required".to_owned(),
            });
        }

        let mut seen_roles = BTreeSet::new();
        let mut seen_role_ids = BTreeSet::new();
        let mut seen_processes = BTreeSet::new();
        let mut seen_keys = BTreeSet::new();
        for identity in &self.roles {
            identity.validate()?;
            if !seen_roles.insert(identity.role) {
                return Err(AuthorityError::InvalidContract {
                    field: "topology.roles",
                    reason: "duplicate logical role".to_owned(),
                });
            }
            if !seen_role_ids.insert(identity.role_id.clone()) {
                return Err(AuthorityError::InvalidContract {
                    field: "topology.roles",
                    reason: "duplicate role identity".to_owned(),
                });
            }
            if !seen_processes.insert(identity.process_id.clone()) {
                return Err(AuthorityError::InvalidContract {
                    field: "topology.roles",
                    reason: "each role requires a distinct process identity"
                        .to_owned(),
                });
            }
            if let Some(key_id) = &identity.key_id {
                if !seen_keys.insert(key_id.clone()) {
                    return Err(AuthorityError::InvalidContract {
                        field: "topology.roles",
                        reason: "each authority role requires a distinct RPC identity key"
                            .to_owned(),
                    });
                }
            }
        }
        let required: BTreeSet<_> =
            ServiceRole::ALL.into_iter().collect();
        if seen_roles != required {
            return Err(AuthorityError::InvalidContract {
                field: "topology.roles",
                reason: "the exact seven-role set is required".to_owned(),
            });
        }
        if self.logical_role_bindings.len() != 22 {
            return Err(AuthorityError::InvalidContract {
                field: "topology.logicalRoleBindings",
                reason: "exactly 22 logical authority subkeys are required"
                    .to_owned(),
            });
        }
        let mut logical_roles = BTreeSet::new();
        let mut logical_keys = BTreeSet::new();
        for binding in &self.logical_role_bindings {
            binding.validate()?;
            let process = self
                .roles
                .iter()
                .find(|role| role.role == binding.service_role)
                .ok_or_else(|| AuthorityError::InvalidContract {
                    field: "topology.logicalRoleBindings",
                    reason: "logical role references an absent service role"
                        .to_owned(),
                })?;
            if process.process_id != binding.process_id
                || process.role_id != binding.role_id
                || process.executable_sha256.0.is_empty()
                || !logical_roles.insert(binding.logical_role.clone())
                || !logical_keys.insert(binding.key_id.clone())
            {
                return Err(AuthorityError::InvalidContract {
                    field: "topology.logicalRoleBindings",
                    reason: "logical role process, role ID, or key assignment is inconsistent or duplicated"
                        .to_owned(),
                });
            }
        }
        let readiness_roles: BTreeSet<_> = self
            .readiness_contract
            .required_service_roles
            .iter()
            .copied()
            .collect();
        let readiness_domains: BTreeSet<_> = self
            .readiness_contract
            .required_reconciliation_domains
            .iter()
            .copied()
            .collect();
        if readiness_roles != required
            || self.readiness_contract.required_service_roles.len()
                != ServiceRole::ALL.len()
            || readiness_domains
                != ReconciliationDomain::ALL.into_iter().collect()
            || self
                .readiness_contract
                .required_reconciliation_domains
                .len()
                != ReconciliationDomain::ALL.len()
            || self.readiness_contract.service_receipt_count
                != ServiceRole::ALL.len() as u8
            || self.readiness_contract.reconciliation_domain_receipt_count
                != ReconciliationDomain::ALL.len() as u8
        {
            return Err(AuthorityError::InvalidContract {
                field: "topology.readinessContract",
                reason: "readiness contract must name the exact service and reconciliation domain sets"
                    .to_owned(),
            });
        }
        self.readiness_contract
            .contract_sha256
            .validate("topology.readinessContract.contractSha256")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderGeneration {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub predecessor_generation_id: Option<Identifier>,
    pub source_commit_sha256: Digest,
    pub source_tree_sha256: Digest,
    pub schema_bundle_sha256: Digest,
    pub migration_sha256: Digest,
    pub topology: TrustedHostTopology,
    pub rollback_floor: u64,
    pub not_before_epoch_millis: u64,
    pub not_after_epoch_millis: u64,
}

impl ProviderGeneration {
    pub fn validate(&self) -> AuthorityResult<()> {
        if self.api_version != PROVIDER_GENERATION_API_VERSION
            || self.kind != PROVIDER_GENERATION_KIND
            || self.schema_version != "1"
        {
            return Err(AuthorityError::InvalidContract {
                field: "providerGeneration",
                reason: "unsupported version or kind".to_owned(),
            });
        }
        self.generation_id
            .validate("providerGeneration.generationId", 128)?;
        if let Some(predecessor) = &self.predecessor_generation_id {
            predecessor.validate(
                "providerGeneration.predecessorGenerationId",
                128,
            )?;
            if predecessor == &self.generation_id {
                return Err(AuthorityError::InvalidContract {
                    field:
                        "providerGeneration.predecessorGenerationId",
                    reason: "generation cannot succeed itself".to_owned(),
                });
            }
        }
        self.source_commit_sha256
            .validate("providerGeneration.sourceCommitSha256")?;
        self.source_tree_sha256
            .validate("providerGeneration.sourceTreeSha256")?;
        self.schema_bundle_sha256
            .validate("providerGeneration.schemaBundleSha256")?;
        self.migration_sha256
            .validate("providerGeneration.migrationSha256")?;
        self.topology.validate()?;
        if self.not_before_epoch_millis >= self.not_after_epoch_millis {
            return Err(AuthorityError::InvalidContract {
                field: "providerGeneration.validity",
                reason: "notBefore must precede notAfter".to_owned(),
            });
        }
        Ok(())
    }

    pub fn role(&self, role: ServiceRole) -> AuthorityResult<&RoleIdentity> {
        self.topology
            .roles
            .iter()
            .find(|identity| identity.role == role)
            .ok_or_else(|| AuthorityError::InvalidContract {
                field: "providerGeneration.topology.roles",
                reason: format!("missing {}", role.as_str()),
            })
    }

    pub fn logical_role(
        &self,
        logical_role: &Identifier,
    ) -> AuthorityResult<&LogicalRoleBinding> {
        self.topology
            .logical_role_bindings
            .iter()
            .find(|binding| &binding.logical_role == logical_role)
            .ok_or_else(|| AuthorityError::Authentication {
                code: "logical_role_not_assigned",
                reason: "logical authority role is absent from the generation"
                    .to_owned(),
            })
    }
}

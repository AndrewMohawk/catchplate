use super::contract::{Digest, Identifier};
pub use super::lifecycle::ReconciliationDomain;
use super::rpc::FrameAuthentication;
use super::topology::ServiceRole;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const READINESS_API_VERSION: &str =
    "catchplate.responseV2.stateAuthorityReadiness/v1";
pub const READINESS_KIND: &str =
    "CatchplateResponseV2StateAuthorityReadiness";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadinessBlocker {
    pub code: Identifier,
    pub domain: ReconciliationDomain,
    pub authoritative_cursor: u64,
    pub detail_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleReadiness {
    pub role: ServiceRole,
    pub role_id: Identifier,
    pub process_id: Identifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Identifier>,
    pub reconciled_generation_id: Identifier,
    pub readiness_artifact_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadinessReport {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub fault_domain_id: Identifier,
    pub quorum_profile: String,
    pub hardware_proof: bool,
    pub reconciliation_checkpoint_sha256: Digest,
    pub completed_domains: Vec<ReconciliationDomain>,
    pub roles: Vec<RoleReadiness>,
    pub blockers: Vec<ReadinessBlocker>,
    pub ready: bool,
}

impl ReadinessReport {
    pub fn structurally_ready(&self) -> bool {
        if !self.ready
            || self.hardware_proof
            || !self.blockers.is_empty()
            || self.fault_domain_id.0 != "host-1"
            || self.quorum_profile != "LOCAL_1_OF_1"
        {
            return false;
        }
        let domains: BTreeSet<_> =
            self.completed_domains.iter().copied().collect();
        let required_domains: BTreeSet<_> =
            ReconciliationDomain::REQUIRED.into_iter().collect();
        let roles: BTreeSet<_> =
            self.roles.iter().map(|role| role.role).collect();
        let required_roles: BTreeSet<_> =
            ServiceRole::ALL.into_iter().collect();
        domains == required_domains
            && roles == required_roles
            && self.roles.len() == ServiceRole::ALL.len()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReadinessReport {
    pub report: ReadinessReport,
    pub authentication: FrameAuthentication,
}

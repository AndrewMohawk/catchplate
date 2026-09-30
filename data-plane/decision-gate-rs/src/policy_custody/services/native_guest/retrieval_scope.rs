//! A data-only copy of the independently pinned original scope. This NEVER
//! constructs ProductionCustodyConfiguration, ProductionCustodyProofScope,
//! a driver, or a settlement capability.
use super::*;
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyData {role:AuthorityRole,key_id:Sha256Digest,key_spki_sha256:Sha256Digest,key_material_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    assignment_id:Sha256Digest,assignment_payload_sha256:Sha256Digest,assignment_revision:u64,
    authority_id:Sha256Digest,storage_realm_sha256:Sha256Digest,retrieval_namespace_sha256:Sha256Digest,
    authority_key_independence_sha256:Sha256Digest,production_configuration_binding_sha256:Sha256Digest,
    asserted_custody_key_set_root_sha256:Sha256Digest,execution_closure_manifest_sha256:Sha256Digest,
    structurally_verified_seccomp_policy_sha256:Sha256Digest,store_response_authority:KeyData,
    retrieval_response_authority:KeyData,binding_sha256:Sha256Digest,
}
impl Scope {
    pub(super) fn binding(&self)->&Sha256Digest {&self.binding_sha256}
    pub(super) fn configuration_binding(&self)->&Sha256Digest {&self.production_configuration_binding_sha256}
    pub(super) fn authority_payload(&self,role:PolicyShadowCustodySignerRole,receipt:&[u8])->Result<Vec<u8>,ShadowError> {
        canonical_json_bytes(&("serverware.policyShadowAssignmentBoundCustodyReceipt/v1",
            &self.binding_sha256,&self.execution_closure_manifest_sha256,&self.structurally_verified_seccomp_policy_sha256,
            role,Sha256Digest::compute(receipt)))
    }
    pub(super) fn check(&self,keys:&AdmittedKeys)->Result<(),ShadowError> {
        let a=keys.assignment.payload();let k=&keys.configuration.authorization.payload;
        require(self.assignment_id==a.assignment_id && self.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && self.assignment_revision==a.assignment_revision && self.authority_id==a.custody_authority.authority_id
            && self.storage_realm_sha256==a.custody_authority.storage_realm_sha256
            && self.retrieval_namespace_sha256==a.custody_authority.retrieval_namespace_sha256
            && self.authority_key_independence_sha256==a.authority_key_independence.independence_root_sha256
            && self.asserted_custody_key_set_root_sha256==k.full_key_set_root_sha256
            && self.execution_closure_manifest_sha256==*keys.closure.manifest_sha256()
            && self.structurally_verified_seccomp_policy_sha256==*keys.closure.seccomp_policy_sha256()
            && self.production_configuration_binding_sha256!=Sha256Digest::compute(&[]))?;
        for (data,role) in [(&self.store_response_authority,AuthorityRole::CustodyStoreResponse),
            (&self.retrieval_response_authority,AuthorityRole::CustodyRetrievalResponse)] {
            let expected=a.authority_key_independence.binding(role,&a.assignment_id)?;
            require(data.role==role && data.key_id==expected.key_id && data.key_spki_sha256==expected.key_spki_sha256
                && data.key_material_sha256==expected.key_material_sha256)?;
        }
        require(self.binding_sha256==hash_domain_frames(b"serverware.policyShadowProductionCustodyProofScope/v1",
            &[&canonical_json_bytes(&(&self.assignment_id,&self.assignment_payload_sha256,self.assignment_revision,
                &self.authority_id,&self.storage_realm_sha256,&self.retrieval_namespace_sha256,
                &self.authority_key_independence_sha256,&self.production_configuration_binding_sha256,
                &self.asserted_custody_key_set_root_sha256,&self.execution_closure_manifest_sha256,
                &self.structurally_verified_seccomp_policy_sha256))?]))
    }
    pub(super) fn namespace(&self)->&Sha256Digest {&self.retrieval_namespace_sha256}
    pub(super) fn require_payload(&self,role:PolicyShadowCustodySignerRole,receipt:&[u8],authority:&[u8])
        ->Result<(),ShadowError> {
        require(canonical_json_bytes(&("serverware.policyShadowAssignmentBoundCustodyReceipt/v1",
            &self.binding_sha256,&self.execution_closure_manifest_sha256,&self.structurally_verified_seccomp_policy_sha256,
            role,Sha256Digest::compute(receipt)))?==authority)
    }
}

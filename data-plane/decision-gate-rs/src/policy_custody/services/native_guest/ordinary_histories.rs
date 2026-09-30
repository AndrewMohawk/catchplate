//! Public ordinary histories embedded in an already authenticated native grant.
//! A marker is never a production runtime. Signed member roots are selected by
//! the independent supervisor; complete generation/history signatures and all
//! original windows are checked before constructing immutable keyrings.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::guest::native_guest as guest;
use services::generation_service::RemoteGrant;
use services::production::ProductionServiceHistoricalKeyringsV4;

pub(in crate::policy_shadow::policy_custody::services) const MAX_CONFIGURATION:usize=4*1024*1024;
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Member {
    generation_grant_original:String,runtime_original:String,history_original:String,
    root_key_id:Sha256Digest,root_key_spki_sha256:Sha256Digest,
}
pub(crate) type Bundle=BTreeMap<services::TrustedHostServiceRoleV3,Member>;

pub(super) fn shape(members:&Bundle)->Result<(),ShadowError>{
    require(members.keys().copied().collect::<BTreeSet<_>>()==services::generation_service_client::roles()
        && canonical_json_bytes(members)?.len()<=MAX_CONFIGURATION)?;
    for member in members.values(){
        for (raw,maximum) in [(&member.generation_grant_original,65536),
            (&member.runtime_original,MAX_CONFIGURATION),(&member.history_original,1024*1024)] {
            require(raw.is_ascii() && !raw.is_empty() && raw.len()<=maximum)?;
        }
    }Ok(())
}

fn equal(value:&serde_json::Value,name:&str,expected:&impl Serialize)->Result<(),ShadowError>{
    require(value.get(name)==Some(&serde_json::to_value(expected).map_err(fail)?))
}

/// Call only after the containing original's supervisor signature is checked.
pub(super) fn admit(members:&Bundle,keys:&AdmittedKeys,peer:&services::ExpectedPeerCredentialV3,
    configuration:&Sha256Digest,driver:&Sha256Digest,descriptors:&Sha256Digest,receipt:&Sha256Digest,
    issued_boot:u64,expires_boot:u64,issued_unix:i64,expires_unix:i64)
    ->Result<ProductionServiceHistoricalKeyringsV4,ShadowError>{
    shape(members)?;
    let guest=keys.association.binding();let assignment=keys.assignment.payload();
    let mut histories=BTreeMap::new();let mut common=None;
    let mut uids=BTreeSet::from([guest.uid,peer.uid]);let mut gids=BTreeSet::from([guest.gid,peer.gid]);
    for (role,member) in members {
        let runtime:serde_json::Value=guest::exact(member.runtime_original.as_bytes())?;
        let header:services::RuntimeConfigHeaderV3=guest::exact(&canonical_json_bytes(
            runtime.get("runtime").ok_or(ShadowError::BindingDrift)?)?)?;
        header.validate().map_err(fail)?;
        require(header.authority_history_root_key_id==member.root_key_id
            && header.authority_history_root_key_spki_sha256==member.root_key_spki_sha256
            && canonical_json_bytes(&header.expected_peer)?==canonical_json_bytes(peer)?)?;
        let history=header.history_from_original(member.history_original.as_bytes(),*role).map_err(fail)?;
        let grant=RemoteGrant::admit(member.generation_grant_original.as_bytes(),history,*role,&guest).map_err(fail)?;
        services::initial_history::require_remote_guest(member.history_original.as_bytes(),&header,*role,&grant).map_err(fail)?;
        let actual=grant.guest();
        require(actual.runtime_configuration_sha256==Sha256Digest::compute(member.runtime_original.as_bytes())
            && uids.insert(actual.uid) && gids.insert(actual.gid))?;
        let (scope_raw,grant_issued,grant_expires)=grant.history_scope_original().map_err(fail)?;
        let scope:serde_json::Value=guest::exact(&scope_raw)?;
        if let Some(previous)=&common{require(previous==&scope_raw)?;}else{common=Some(scope_raw.clone());}
        equal(&scope,"assignmentId",&assignment.assignment_id)?;
        equal(&scope,"assignmentPayloadSha256",keys.assignment.payload_sha256())?;
        equal(&scope,"assignmentRevision",&assignment.assignment_revision)?;
        equal(&scope,"successorConfigurationBindingSha256",configuration)?;
        equal(&scope,"kernelDriverIdentitySha256",driver)?;
        equal(&scope,"retainedDescriptorSetSha256",descriptors)?;
        equal(&scope,"driverGenerationReceiptSha256",receipt)?;
        require(scope.get("previousConfigurationBindingSha256")==Some(&serde_json::Value::Null)
            && grant_issued<=issued_boot && issued_boot<expires_boot && expires_boot<=grant_expires
            && scope.get("installationIssuedAtUnixNanos").and_then(serde_json::Value::as_i64)
                .is_some_and(|start|start<=issued_unix)
            && scope.get("installationExpiresAtUnixNanos").and_then(serde_json::Value::as_i64)
                .is_some_and(|end|issued_unix<expires_unix && expires_unix<=end))?;
        require(histories.insert(*role,grant.into_history()).is_none())?;
    }
    use services::TrustedHostServiceRoleV3 as Role;
    let mut take=|role|histories.remove(&role).ok_or(ShadowError::BindingDrift);
    ProductionServiceHistoricalKeyringsV4::new(take(Role::DurableRecoveryStore)?,
        take(Role::CleanupAuthorizationConsumer)?,take(Role::RecoveryTargetProvider)?,
        take(Role::CurrentSignatureAuthority)?,take(Role::BoundedCleanupHelper)?).map_err(fail)
}

//! Explicit four-proof bridge. Construction still requires all five real
//! service sessions, ten receipt endpoints and original driver prerequisites.
use super::*;
use super::super::FileAdmission;
use crate::policy_shadow::policy_custody::services as services;
use services::production::{ProductionRpcRuntimeConfigV4,ProductionProofEndpointConfigV4,
    ProductionProofEndpointKindV4};
use super::retrieval_peer::EndpointKind;
use std::os::fd::{AsFd,OwnedFd};
#[path="proof_client_peer.rs"] mod inspection;
pub(in crate::policy_shadow::policy_custody::services) use inspection::{Inspector,Session};
const KINDS:[EndpointKind;4]=[EndpointKind::Retrieval,EndpointKind::Persistence,
    EndpointKind::TrustedTime,EndpointKind::GenerationInstallEnvelope];
struct Selection {entries:BTreeMap<EndpointKind,ProductionProofEndpointConfigV4>,runtime_sha256:Sha256Digest}
pub(super) fn assigned_peers(files:&FileAdmission)->Result<BTreeMap<EndpointKind,services::ExpectedPeerCredentialV3>,ShadowError> {
    files.check_preparation().map_err(fail)?;
    Ok(Selection::original(&files.retrieval_client_runtime().map_err(fail)?)?.entries.into_iter()
        .map(|(kind,endpoint)|(kind,endpoint.expected_peer)).collect())
}
impl Selection {
    fn original(raw:&[u8])->Result<Self,ShadowError> {
        let runtime:ProductionRpcRuntimeConfigV4=exact(raw)?;runtime.validate().map_err(fail)?;
        let mut entries=BTreeMap::new();
        for kind in KINDS {
            let mut matching=runtime.proof_endpoints.iter().filter(|v|v.endpoint_kind==kind.production_kind());
            let endpoint=matching.next().ok_or(ShadowError::BindingDrift)?;
            require(matching.next().is_none() && endpoint.expected_socket_path==std::path::Path::new(kind.socket_path())
                && KINDS.iter().all(|k|endpoint.activation_fd_name!=k.peer_directory_name()))?;
            endpoint.expected_peer.checked().map_err(fail)?;
            entries.insert(kind,endpoint.clone());
        }
        require(runtime.proof_endpoints.len()==KINDS.len())?;
        Ok(Self{entries,runtime_sha256:Sha256Digest::compute(raw)})
    }
}
pub(in crate::policy_shadow::policy_custody::services) struct Prepared {
    selection:Selection,channel:OwnedFd,directories:BTreeMap<EndpointKind,inspection::Directory>,
}
impl Prepared {
    pub(super) fn open(delivery:&mut PreparedGuestServiceDelivery,channel:OwnedFd,time_grant:&Pin)
        ->Result<(Self,admission::trusted_time::ClientGrant),ShadowError> {
        let selection=Selection::original(&delivery.retrieval_client_runtime().map_err(fail)?)?;
        let mut directories=BTreeMap::new();
        for (kind,endpoint) in &selection.entries {
            require(endpoint.expected_peer.uid!=delivery.role_uid() && endpoint.expected_peer.uid!=0 && endpoint.expected_peer.gid!=0)?;
            inspection::unconnected(delivery.activation.get(&endpoint.activation_fd_name)
                .ok_or(ShadowError::BindingDrift)?.as_fd())?;
            let fd=delivery.activation.remove(kind.peer_directory_name()).ok_or(ShadowError::BindingDrift)?;
            directories.insert(*kind,inspection::Directory::open(fd,endpoint.expected_peer.uid,delivery.role_gid(),*kind)?);
        }
        retrieval_peer::configure(channel.as_fd())?;
        let grant=admission::trusted_time::ClientGrant::open(time_grant)?;
        Ok((Self{selection,channel,directories},grant))
    }
    pub(in crate::policy_shadow::policy_custody::services) fn attach(mut self,
        activation:&mut BTreeMap<String,OwnedFd>,configured:&[ProductionProofEndpointConfigV4],owner:Arc<AdmittedGuest>)
        ->Result<BTreeMap<ProductionProofEndpointKindV4,Session>,ShadowError> {
        owner.check()?;owner.delivery().check_startup().map_err(fail)?;
        require(owner.delivery().payload.runtime_config.sha256==self.selection.runtime_sha256)?;
        let channel=inspection::Channel::bind(self.channel,&owner)?;
        let mut sessions=BTreeMap::new();
        for (kind,expected) in self.selection.entries {
            let actual=configured.iter().find(|v|v.endpoint_kind==kind.production_kind()).ok_or(ShadowError::BindingDrift)?;
            require(canonical_json_bytes(actual)?==canonical_json_bytes(&expected)?)?;
            let socket=activation.remove(&actual.activation_fd_name).ok_or(ShadowError::BindingDrift)?;
            let directory=self.directories.remove(&kind).ok_or(ShadowError::BindingDrift)?;
            let session=Session::connect(Arc::clone(&channel),directory,socket,
                actual.expected_peer.checked().map_err(fail)?,Arc::clone(&owner),kind)?;
            session.check()?;sessions.insert(kind.production_kind(),session);
        }
        require(self.directories.is_empty())?;Ok(sessions)
    }
}
pub(super) fn run(owner:Arc<AdmittedGuest>,prepared:Prepared)->Result<(),ShadowError> {
    owner.check()?;require(owner.proof_bridge_selected())?;
    let loaded=owner.delivery().load::<ProductionRpcRuntimeConfigV4>().map_err(fail)?;
    let activation=owner.bridge_activation.lock().map_err(fail)?.take().ok_or(ShadowError::BindingDrift)?;
    services::production::run_production_rpc_service_native_proofs(loaded,activation,prepared,owner).map_err(fail)
}

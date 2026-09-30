//! Explicit four-proof bridge. Construction still requires all five real
//! service sessions, ten receipt endpoints and original driver prerequisites.
use super::*;
use super::super::FileAdmission;
use crate::policy_shadow::policy_custody::services as services;
use services::production::{ProductionRpcRuntimeConfigV4,
    ProductionProofEndpointKindV4};
use super::retrieval_peer::EndpointKind;
use std::os::fd::{AsFd,OwnedFd};
#[path="proof_client_peer.rs"] mod inspection;
pub(in crate::policy_shadow::policy_custody::services) use inspection::{Inspector,Session};
pub(in crate::policy_shadow::policy_custody::services) use inspection::facade::{Acceptor as FacadeAcceptor,Session as FacadeSession};
const KINDS:[EndpointKind;4]=[EndpointKind::Retrieval,EndpointKind::Persistence,
    EndpointKind::TrustedTime,EndpointKind::GenerationInstallEnvelope];
#[derive(Clone)]
struct Entry {activation_fd_name:String,expected_peer:services::ExpectedPeerCredentialV3,exact:Vec<u8>}
struct Selection {entries:BTreeMap<EndpointKind,Entry>,runtime_sha256:Sha256Digest}
pub(super) fn assigned_peers(files:&FileAdmission)->Result<BTreeMap<EndpointKind,services::ExpectedPeerCredentialV3>,ShadowError> {
    assigned_peers_selected(files,false)
}
pub(super) fn assigned_peers_selected(files:&FileAdmission,commitment:bool)
    ->Result<BTreeMap<EndpointKind,services::ExpectedPeerCredentialV3>,ShadowError> {
    files.check_preparation().map_err(fail)?;
    Ok(Selection::original(&files.retrieval_client_runtime().map_err(fail)?,commitment)?.entries.into_iter()
        .map(|(kind,endpoint)|(kind,endpoint.expected_peer)).collect())
}
impl Selection {
    fn original(raw:&[u8],commitment:bool)->Result<Self,ShadowError> {
        let runtime:ProductionRpcRuntimeConfigV4=exact(raw)?;runtime.validate().map_err(fail)?;
        require(runtime.commit_request.is_some()==commitment)?;
        let mut entries=BTreeMap::new();
        for kind in KINDS {
            let mut matching=runtime.proof_endpoints.iter().filter(|v|Some(v.endpoint_kind)==kind.production_kind());
            let endpoint=matching.next().ok_or(ShadowError::BindingDrift)?;
            require(matching.next().is_none() && endpoint.expected_socket_path==std::path::Path::new(kind.socket_path())
                && KINDS.iter().all(|k|endpoint.activation_fd_name!=k.peer_directory_name()))?;
            endpoint.expected_peer.checked().map_err(fail)?;
            entries.insert(kind,Entry{activation_fd_name:endpoint.activation_fd_name.clone(),expected_peer:endpoint.expected_peer.clone(),
                exact:canonical_json_bytes(endpoint)?});
        }
        require(runtime.proof_endpoints.len()==KINDS.len())?;
        if commitment {
            let kind=EndpointKind::CommitRequest;
            let mut found=runtime.parent_signer_endpoints.iter().filter(|v|v.signer_role==PolicyShadowCustodySignerRole::LedgerAppend);
            let endpoint=found.next().ok_or(ShadowError::BindingDrift)?;
            require(found.next().is_none() && endpoint.expected_socket_path==std::path::Path::new(kind.socket_path()))?;
            endpoint.expected_peer.checked().map_err(fail)?;
            entries.insert(kind,Entry{activation_fd_name:endpoint.activation_fd_name.clone(),expected_peer:endpoint.expected_peer.clone(),
                exact:canonical_json_bytes(endpoint)?});
        }
        Ok(Self{entries,runtime_sha256:Sha256Digest::compute(raw)})
    }
}
pub(in crate::policy_shadow::policy_custody::services) struct Prepared {
    selection:Selection,channel:OwnedFd,directories:BTreeMap<EndpointKind,inspection::Directory>,
    native_facade:bool,
    outgoing_directories:BTreeMap<String,inspection::facade::OutgoingDirectory>,
}
impl Prepared {
    pub(super) fn open(delivery:&mut PreparedGuestServiceDelivery,channel:OwnedFd,time_grant:&Pin)
        ->Result<(Self,admission::trusted_time::ClientGrant),ShadowError> {
        Self::open_selected(delivery,channel,time_grant,false)
    }
    pub(super) fn open_selected(delivery:&mut PreparedGuestServiceDelivery,channel:OwnedFd,time_grant:&Pin,commitment:bool)
        ->Result<(Self,admission::trusted_time::ClientGrant),ShadowError> {
        let grant=admission::trusted_time::ClientGrant::open(time_grant)?;
        Ok((Self::prepare_owned(delivery,channel,commitment)?,grant))
    }
    pub(super) fn open_late(delivery:&mut PreparedGuestServiceDelivery,channel:OwnedFd,time_grant:Original,commitment:bool)
        ->Result<(Self,admission::trusted_time::ClientGrant),ShadowError>{
        require(delivery.owner.native_continuation.is_some())?;
        let grant=admission::trusted_time::ClientGrant::from_retained(time_grant)?;
        Ok((Self::prepare_owned(delivery,channel,commitment)?,grant))
    }
    fn prepare_owned(delivery:&mut PreparedGuestServiceDelivery,channel:OwnedFd,commitment:bool)->Result<Self,ShadowError>{
        let selection=Selection::original(&delivery.retrieval_client_runtime().map_err(fail)?,commitment)?;
        let mut directories=BTreeMap::new();
        for (kind,endpoint) in &selection.entries {
            require(endpoint.expected_peer.uid!=delivery.role_uid() && endpoint.expected_peer.uid!=0 && endpoint.expected_peer.gid!=0)?;
            inspection::unconnected(delivery.activation.get(&endpoint.activation_fd_name)
                .ok_or(ShadowError::BindingDrift)?.as_fd())?;
            let fd=delivery.activation.remove(kind.peer_directory_name()).ok_or(ShadowError::BindingDrift)?;
            directories.insert(*kind,inspection::Directory::open(fd,endpoint.expected_peer.uid,delivery.role_gid(),*kind)?);
        }
        retrieval_peer::configure(channel.as_fd())?;
        let native_facade=delivery.owner.native_continuation.as_ref().is_some_and(|v|v.bridge_admission_selected());
        let mut outgoing_directories=BTreeMap::new();
        if native_facade {
            let runtime:ProductionRpcRuntimeConfigV4=exact(&delivery.retrieval_client_runtime().map_err(fail)?)?;
            let native_names:BTreeSet<_>=selection.entries.values().map(|v|v.activation_fd_name.clone()).collect();
            for (name,_,_) in runtime.native_outgoing_selections().map_err(fail)? {
                if native_names.contains(&name) {continue;}
                let name=inspection::facade::outgoing_directory_name(outgoing_directories.len());
                let fd=delivery.activation.remove(&name).ok_or(ShadowError::BindingDrift)?;
                outgoing_directories.insert(name,inspection::facade::OutgoingDirectory::open(fd)?);
            }
        }
        Ok(Self{selection,channel,directories,native_facade,outgoing_directories})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn attach(mut self,
        activation:&mut BTreeMap<String,OwnedFd>,runtime:&ProductionRpcRuntimeConfigV4,owner:Arc<AdmittedGuest>)
        ->Result<(BTreeMap<ProductionProofEndpointKindV4,Session>,Option<Session>,Option<FacadeAcceptor>),ShadowError> {
        owner.check()?;owner.delivery().check_startup().map_err(fail)?;
        require(owner.delivery().payload.runtime_config.sha256==self.selection.runtime_sha256)?;
        let channel=inspection::Channel::bind(self.channel,&owner)?;
        let native_names=self.selection.entries.values().map(|v|v.activation_fd_name.clone()).collect();
        let facade=if self.native_facade {
            Some(FacadeAcceptor::new(Arc::clone(&channel),Arc::clone(&owner),runtime,&native_names,self.outgoing_directories)?)
        } else {None};
        let mut sessions=BTreeMap::new();let mut signer=None;
        for (kind,expected) in self.selection.entries {
            let actual=if let Some(proof)=kind.production_kind() {
                canonical_json_bytes(runtime.proof_endpoints.iter().find(|v|v.endpoint_kind==proof).ok_or(ShadowError::BindingDrift)?)?
            } else {canonical_json_bytes(runtime.parent_signer_endpoints.iter().find(|v|v.signer_role==PolicyShadowCustodySignerRole::LedgerAppend)
                .ok_or(ShadowError::BindingDrift)?)?};
            require(actual==expected.exact)?;
            let socket=activation.remove(&expected.activation_fd_name).ok_or(ShadowError::BindingDrift)?;
            let directory=self.directories.remove(&kind).ok_or(ShadowError::BindingDrift)?;
            let session=Session::connect(Arc::clone(&channel),directory,socket,
                expected.expected_peer.checked().map_err(fail)?,Arc::clone(&owner),kind)?;
            session.check()?;
            if let Some(proof)=kind.production_kind(){sessions.insert(proof,session);}else{require(signer.is_none())?;signer=Some(session);}
        }
        require(self.directories.is_empty())?;Ok((sessions,signer,facade))
    }
}
pub(super) fn run(owner:Arc<AdmittedGuest>,prepared:Prepared)->Result<(),ShadowError> {
    owner.check()?;require(owner.proof_bridge_selected())?;
    let loaded=owner.delivery().load::<ProductionRpcRuntimeConfigV4>().map_err(fail)?;
    let activation=owner.bridge_activation.lock().map_err(fail)?.take().ok_or(ShadowError::BindingDrift)?;
    services::production::run_production_rpc_service_native_proofs(loaded,activation,prepared,owner).map_err(fail)
}

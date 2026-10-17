//! Actual final-role retrieval client selection and bridge construction.
//! The signed C9 runtime selects the peer and public key. This does not
//! construct a production driver or replace any other bridge prerequisite.
use super::*;
use super::super::FileAdmission;
use crate::policy_shadow::policy_custody::services as services;
use services::production::{ProductionRpcRuntimeConfigV4,ProductionProofEndpointConfigV4,
    ProductionProofEndpointKindV4};
use std::os::fd::{AsFd,OwnedFd};
#[path="retrieval_client_peer.rs"] mod inspection;
pub(in crate::policy_shadow::policy_custody::services) use inspection::{Inspector,Session};
pub(super) const DIRECTORY_NAME:&str="retrieval-peer-directory";
pub(super) const SOCKET_PATH:&str="/run/catchplate-shadow-retrieval/listener.sock";

struct Selection {endpoint:ProductionProofEndpointConfigV4,runtime_sha256:Sha256Digest}
pub(super) fn assigned_peer(files:&FileAdmission)->Result<services::ExpectedPeerCredentialV3,ShadowError> {
    files.check_preparation().map_err(fail)?;
    Ok(Selection::original(&files.retrieval_client_runtime().map_err(fail)?)?.endpoint.expected_peer)
}
impl Selection {
    // Data decoding is private and reachable only from the retained C9
    // preparation owners below, never a caller-asserted measurement object.
    fn original(raw:&[u8])->Result<Self,ShadowError> {
        let runtime:ProductionRpcRuntimeConfigV4=exact(raw)?;
        runtime.validate().map_err(fail)?;
        let mut entries=runtime.proof_endpoints.into_iter()
            .filter(|v|v.endpoint_kind==ProductionProofEndpointKindV4::Retrieval);
        let endpoint=entries.next().ok_or(ShadowError::BindingDrift)?;
        require(entries.next().is_none() && endpoint.expected_socket_path==std::path::Path::new(SOCKET_PATH)
            && endpoint.activation_fd_name!=DIRECTORY_NAME)?;
        endpoint.expected_peer.checked().map_err(fail)?;
        Ok(Self{endpoint,runtime_sha256:Sha256Digest::compute(raw)})
    }
}
pub(in crate::policy_shadow::policy_custody::services) struct Prepared {
    selection:Selection,channel:OwnedFd,directory:inspection::Directory,
}
impl Prepared {
    pub(super) fn open(delivery:&mut PreparedGuestServiceDelivery,channel:OwnedFd)->Result<Self,ShadowError> {
        let selection=Selection::original(&delivery.retrieval_client_runtime().map_err(fail)?)?;
        require(selection.endpoint.expected_peer.uid!=delivery.role_uid()
            && selection.endpoint.expected_peer.uid!=0 && selection.endpoint.expected_peer.gid!=0)?;
        let socket=delivery.activation.get(&selection.endpoint.activation_fd_name).ok_or(ShadowError::BindingDrift)?;
        inspection::unconnected(socket.as_fd())?;
        let fd=delivery.activation.remove(DIRECTORY_NAME).ok_or(ShadowError::BindingDrift)?;
        let directory=inspection::Directory::open(fd,selection.endpoint.expected_peer.uid,delivery.role_gid())?;
        retrieval_peer::configure(channel.as_fd())?;
        Ok(Self{selection,channel,directory})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn attach(self,socket:OwnedFd,
        configured:&ProductionProofEndpointConfigV4,owner:Arc<AdmittedGuest>)->Result<Session,ShadowError> {
        owner.check()?;
        require(owner.delivery().payload.runtime_config.sha256==self.selection.runtime_sha256
            && canonical_json_bytes(configured)?==canonical_json_bytes(&self.selection.endpoint)?)?;
        owner.delivery().check_startup().map_err(fail)?;
        let session=Session::connect(self.channel,self.directory,socket,
            configured.expected_peer.checked().map_err(fail)?,owner)?;
        session.check()?;Ok(session)
    }
}

pub(super) fn run(owner:Arc<AdmittedGuest>,prepared:Prepared)->Result<(),ShadowError> {
    owner.check()?;
    require(owner.bridge_selected && owner.retrieval_client.is_none() && owner.retrieval.is_none())?;
    let loaded=owner.delivery().load::<ProductionRpcRuntimeConfigV4>().map_err(fail)?;
    // Consume the activation map once from this same retained owner. No new FD
    // constructor or current pathname lookup may substitute for this handoff.
    let activation=owner.bridge_activation.lock().map_err(fail)?.take().ok_or(ShadowError::BindingDrift)?;
    services::production::run_production_rpc_service_inspected(
        loaded,activation,prepared,owner).map_err(fail)
}

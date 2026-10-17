//! Real separately inspected endpoint for one fixed ingress, Ledger or terminal owner.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::guest::native_guest::{self as guest,retrieval_peer as peer};
use services::production::{ProductionAuthorityEndpointIdentityV4 as Endpoint,ProductionAuthorityEndpointRequestV4 as Request,
    ProductionAuthorityEndpointReplyV4 as Reply};
use crate::policy_shadow::policy_custody::production_dispatch::PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION;
use crate::policy_shadow::policy_custody::protocol::domain_separated_signature_preimage;
use super::spool_signer::{self as signer,Kind};
use std::os::fd::OwnedFd;
impl Kind {
    pub(super) fn endpoint(self)->peer::EndpointKind{match self{Self::Ingress=>peer::EndpointKind::IngressAdmission,Self::Ledger=>peer::EndpointKind::CommitRequest,Self::Terminal=>peer::EndpointKind::TerminalAppend,
        Self::DispatchBarrier=>peer::EndpointKind::DispatchBarrier,Self::ActiveEffectBarrier=>peer::EndpointKind::ActiveEffectBarrier,Self::ActiveEffectCommit=>peer::EndpointKind::ActiveEffectCommit}}
}
pub(crate) struct Prepared {work:signer::Prepared,listener:OwnedFd,inspection:OwnedFd,kind:Kind}
impl Prepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,kind:Kind,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{
        Self::open_selected(pin,kind,delivery,inspection,false)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn open_completion(pin:&guest::Pin,kind:Kind,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{
        Self::open_selected(pin,kind,delivery,inspection,true)
    }
    fn open_selected(pin:&guest::Pin,kind:Kind,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd,completion:bool)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        let name=kind.endpoint().listener_name();require(delivery.activation.len()==1 && delivery.activation.contains_key(name))?;
        let work=if completion{signer::Prepared::open_completion(pin,kind,delivery)?}else{signer::Prepared::open(pin,kind,delivery)?};
        let listener=delivery.activation.remove(name).ok_or(ShadowError::BindingDrift)?;
        Ok(Self{work,listener,inspection,kind})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Service,ShadowError>{
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;
        let work=self.work.bind(keys,delivery,trust,time)?;require(work.kind()?==self.kind)?;
        let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind_endpoint(self.inspection,self.listener,work.expected_peer().checked().map_err(fail)?,
            delivery,&check,self.kind.endpoint())?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        Ok(Service{work,channel})
    }
}
pub(crate) struct Service {work:signer::Work,channel:peer::Client}
impl Service {
    pub(in crate::policy_shadow::policy_custody::services) fn serve(mut self,keys:&AdmittedKeys,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError>{
        let kind=self.work.kind()?;
        loop {
            check()?;self.work.check(keys,trust,time)?;self.channel.check()?;
            let Some(packet)=self.channel.receive()? else{unsafe{libc::poll(std::ptr::null_mut(),0,1);}continue;};
            // The existing complete 8 MiB endpoint frame remains the limit.
            let wire:Request=services::common::decode_canonical_frame(&packet.bytes).map_err(fail)?;
            require(wire.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION && wire.endpoint==Endpoint::ParentSigner(kind.signer())
                && wire.request_sha256==wire.computed_request_sha256().map_err(fail)? && guest::now()?<wire.deadline_boottime_nanos
                && wire.deadline_boottime_nanos<=keys.association.lifetime())?;
            self.channel.inspect(peer::Phase::BeforeDispatch,Some(&packet.bytes),Some(&packet),wire.deadline_boottime_nanos,check)?;
            let result=self.work.handle(&wire,keys,trust,time)?;
            let local=keys.keys.get(&kind.role()).ok_or(ShadowError::SignerBindingMismatch)?;
            let result_sha256=hash_domain_frames(b"catchplate.policyCustodyProductionAuthorityEndpointResponse/v4",&[&canonical_json_bytes(&result)?]);
            let mut reply=Reply{api_version:PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.into(),endpoint:wire.endpoint,
                request_sha256:wire.request_sha256,replay_id_sha256:wire.replay_id_sha256,completed_at_boottime_nanos:guest::now()?,
                authority_key_id:local.binding.key_id.clone(),authority_key_spki_sha256:local.binding.key_spki_sha256.clone(),
                result,result_sha256,signature_base64:String::new()};
            require(reply.completed_at_boottime_nanos<wire.deadline_boottime_nanos)?;check()?;self.work.check(keys,trust,time)?;
            reply.signature_base64=URL_SAFE_NO_PAD.encode(local.key.sign(&domain_separated_signature_preimage(
                b"catchplate.policyCustodyProductionAuthorityEndpointSignature/v4",&reply.signature_payload().map_err(fail)?).map_err(fail)?).to_bytes());
            let raw=services::common::encode_canonical_frame(&reply).map_err(fail)?;
            require(raw.len()<=services::common::MAX_SERVICE_FRAME_BYTES)?;
            loop {
                check()?;self.work.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                self.channel.inspect(peer::Phase::BeforeResponse,Some(&raw),Some(&packet),wire.deadline_boottime_nanos,check)?;
                check()?;self.work.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                if self.channel.send(&raw)?{break;}unsafe{libc::poll(std::ptr::null_mut(),0,1);}
            }
        }
    }
}

//! One explicit public signature-authenticated activation endpoint. The
//! inherited channel is transport custody, not a peer-attestation shortcut.
use super::*;
use crate::policy_shadow::native_activation as operation;
use crate::policy_shadow::policy_custody::services as services;
use services::guest::native_guest as guest;
use serverware_decision_gate::native_policy_activation_transport::ChannelVersion;
use std::os::fd::{AsFd,AsRawFd,OwnedFd};
use ed25519_dalek::Signer;
const DOMAIN:&str="serverware.nativeShadowActivationServiceAssignment.signature/v1";
const DOMAIN_V2:&str="serverware.nativeShadowActivationServiceAssignment.signature/v2";
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,guest:GuestClosureBinding,assignment_payload_sha256:Sha256Digest,
    key_authorization_sha256:Sha256Digest,authority:guest::Pin,initial_state_sha256:Sha256Digest,
    generation_id:Sha256Digest,generation_publication_envelope_sha256:Sha256Digest,
    trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    fn version(&self)->Result<ChannelVersion,ShadowError>{match self.payload.api_version.as_str(){
        "serverware.nativeShadowActivationServiceAssignment/v1"=>Ok(ChannelVersion::UnixV1),
        "serverware.nativeShadowActivationServiceAssignment/v2"=>Ok(ChannelVersion::VsockV2),
        _=>Err(ShadowError::BindingDrift),
    }}
    fn verify(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        keys.check(trust,time)?;require(keys.result.is_some())?;
        let domain=match self.version()?{ChannelVersion::UnixV1=>DOMAIN,ChannelVersion::VsockV2=>DOMAIN_V2};
        let p=&self.payload;let checkpoint=trust.current_checkpoint()?;
        require(p.purpose=="native-policy-activation-publication" && p.guest==keys.association.binding()
            && p.guest.service_role=="production-bridge" && p.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&keys.configuration.authorization)?)
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256
            && p.expires_at_unix_nanos<=keys.authorization.payload.expires_at_unix_nanos
            && p.expires_at_unix_nanos<=keys.configuration.authorization.payload.expires_at_unix_nanos)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let supervisor=keys.assignment.payload().authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,
            &keys.assignment.payload().assignment_id)?;
        require(supervisor.key_id==p.signing_key_id && supervisor.key_spki_sha256==p.signing_key_spki_sha256)?;
        let public=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &supervisor.key_id,&supervisor.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&public)==supervisor.key_material_sha256)?;
        public.verify_strict(&signature_preimage(domain,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        let local=keys.keys.get(&AuthorityRole::CustodyActivationPublication).ok_or(ShadowError::SignerBindingMismatch)?;
        let binding=keys.assignment.payload().authority_key_independence.binding(AuthorityRole::CustodyActivationPublication,
            &keys.assignment.payload().assignment_id)?;
        require(local.binding.key_id==binding.key_id && local.binding.key_spki_sha256==binding.key_spki_sha256
            && local.binding.key_material_sha256==binding.key_material_sha256 && trust.current_checkpoint()?==checkpoint)
    }
}
pub(crate) struct Prepared {
    original:services::guest_original::Original,configuration:Configuration,authority_original:services::guest_original::Original,
    authority:operation::Authority,channel:OwnedFd,journal:OwnedFd,
}
impl Prepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        require(delivery.activation.len()==2 && delivery.activation.contains_key("activation-channel")
            && delivery.activation.contains_key("activation-journal"))?;
        let original=pin.open(65536)?;
        let configuration:Configuration=guest::exact(&original.read(65536).map_err(fail)?)?;
        require(configuration.payload.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        let authority_original=configuration.payload.authority.open(8*1024*1024)?;
        let authority=operation::Authority::admit(&authority_original.read(8*1024*1024).map_err(fail)?)?;
        let channel=delivery.activation.remove("activation-channel").ok_or(ShadowError::BindingDrift)?;
        let journal=delivery.activation.remove("activation-journal").ok_or(ShadowError::BindingDrift)?;
        configuration.version()?.validate(channel.as_fd()).map_err(fail)?;
        Ok(Self{original,configuration,authority_original,authority,channel,journal})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Service,ShadowError>{
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;
        keys.association.check_startup().map_err(fail)?;self.configuration.verify(keys,trust,time)?;
        let journal=operation::store::Journal::open(self.journal,&self.configuration.payload.initial_state_sha256)?;
        let channel=serverware_decision_gate::native_policy_activation_transport::ServiceChannel::from_delivery_version(
            self.channel,self.configuration.version()?).map_err(fail)?;
        let value=Service{original:self.original,configuration:self.configuration,authority_original:self.authority_original,
            authority:self.authority,channel,journal};
        value.check(keys,trust,time)?;keys.association.check_startup().map_err(fail)?;Ok(value)
    }
}
pub(crate) struct Service {
    original:services::guest_original::Original,configuration:Configuration,authority_original:services::guest_original::Original,
    authority:operation::Authority,channel:serverware_decision_gate::native_policy_activation_transport::ServiceChannel,
    journal:operation::store::Journal,
}
impl Service {
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.original.read(65536).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        self.authority.require_original(&self.authority_original.read(8*1024*1024).map_err(fail)?)?;
        self.configuration.verify(keys,trust,time)?;self.authority.check(&keys.assignment,trust,time)?;
        self.channel.check().map_err(fail)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn serve(mut self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,
        time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError>{
        self.check(keys,trust,time)?;check()?;
        let mut request=loop{
            self.check(keys,trust,time)?;check()?;
            if let Some(value)=self.channel.receive(keys.association.lifetime()).map_err(fail)?{break value;}
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        };
        let prepared=operation::VerifiedPrepared::verify(request.original(),&self.authority,&keys.assignment,trust,time)?;
        require(operation::digest(prepared.prepared(),"generationId")?==self.configuration.payload.generation_id
            && operation::digest(prepared.prepared(),"generationPublicationEnvelopeSha256")?==self.configuration.payload.generation_publication_envelope_sha256
            && operation::integer(prepared.prepared(),"expiresAtUnixNanos")?<=self.configuration.payload.expires_at_unix_nanos)?;
        if self.configuration.version()?==ChannelVersion::VsockV2{
            // The other machine's BOOTTIME is never meaningful here. Derive
            // once from the genuinely verified original expiry and the local
            // trusted epoch interval, anchored before sampling that interval.
            let before_time=guest::now()?;
            let(earliest,latest)=time.now_interval_unix_nanos()?;
            let after_time=guest::now()?;
            let expires=operation::integer(prepared.prepared(),"expiresAtUnixNanos")?;
            let remaining=u64::try_from(expires.checked_sub(latest).ok_or(ShadowError::BindingDrift)?).map_err(fail)?;
            let deadline=keys.association.lifetime().min(
                before_time.checked_add(remaining).ok_or(ShadowError::BindingDrift)?);
            require(before_time<=after_time && earliest<=latest && after_time<deadline)?;
            request.narrow_deadline(deadline).map_err(fail)?;
        }
        // Split borrows deliberately: the journal remains exclusively held
        // across the effect, signing, durable receipt readback and emission.
        let configuration=&self.configuration;let original=&self.original;let authority=&self.authority;
        let authority_original=&self.authority_original;let channel=&mut self.channel;
        let live=||{
            check()?;keys.check(trust,time)?;configuration.verify(keys,trust,time)?;
            require(original.read(65536).map_err(fail)?.as_slice()==canonical_json_bytes(configuration)?.as_slice())?;
            authority.require_original(&authority_original.read(8*1024*1024).map_err(fail)?)?;
            prepared.check(authority,trust,time)?;request.check().map_err(fail)
        };
        let mut committed=self.journal.publish(&prepared,&live)?;
        live()?;committed.check()?;
        let key=keys.keys.get(&AuthorityRole::CustodyActivationPublication).ok_or(ShadowError::SignerBindingMismatch)?;
        let payload=committed.payload(&prepared,time,&key.binding)?;
        let signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(key.key.sign(
            &signature_preimage(operation::PUBLICATION_DOMAIN,&canonical_json_bytes(&payload)?)).to_bytes()));
        let receipt=operation::Publication::from_committed(payload,signature,&committed,&prepared,trust,time)?;
        committed.retain_receipt(&receipt,&live)?;
        let bytes=receipt.original()?;
        loop{
            live()?;committed.check()?;
            if channel.send(&request,&bytes).map_err(fail)?{break;}
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
        // One publication only. A disconnected/missing reply never restarts
        // this owner or creates a new window; durable recovery is separate.
        loop{live()?;committed.check()?;channel.check().map_err(fail)?;unsafe{libc::poll(std::ptr::null_mut(),0,25);}}
    }
}

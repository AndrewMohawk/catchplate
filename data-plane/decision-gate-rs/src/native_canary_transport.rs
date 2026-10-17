//! Retained native canary TLS/signature owner. Durable operations are fixed
//! phases; only an actual completed claim can reach the single intake contact.
use super::*;
use catchplate_decision_gate::{native_canary_evidence_v1 as wire,
    enclave_runtime_identity_v1::NativeCanaryHttpClient};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::rand::{SecureRandom, SystemRandom};

pub(super) struct Owner {
    client: NativeCanaryHttpClient, deployment: String, instance: String,
    relays: Arc<NativeUpstreamRelaysV1>, pid: u32,
}

/// For the actual cold owner: construction uses admitted CP roots and
/// the retained native relay table. It never imports a client key/certificate
/// or opens an ordinary direct-network fallback. No contact occurs here.
pub(super) fn prepare(roots: &ControlPlaneClientConfig, relays: &Arc<NativeUpstreamRelaysV1>,
    intake_url: &str, deployment: &str, instance: &str, identity: &mut EnclaveRuntimeIdentityV1, deadline: u64)
    -> Result<Owner, String> {
    let tls = identity.canary_client_identity(deployment, instance, deadline)?;
    identity.verify_canary_tls(&tls, deadline)?;
    let client = tls.bind_http_client(roots.builder(Duration::from_secs(2))
        .proxy(relays.service_proxy(&[intake_url])?), intake_url, deadline)?;
    client.check(identity, deadline)?;
    Ok(Owner { client, deployment: deployment.to_owned(), instance: instance.to_owned(),
        relays: Arc::clone(relays), pid: std::process::id() })
}

impl Owner {
    fn check(&self, state: &GateState) -> Result<(), String> {
        if self.pid != std::process::id() || state.server_instance_id.as_deref() != Some(self.instance.as_str())
            || !state.native_upstream_relays.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, &self.relays)) {
            return Err("canary sender changed process, native instance or actual relay owner".into());
        }
        native_service_remaining(state)?.ok_or("canary requires retained native lifetime")?;
        self.client.tls().check(self.client.tls().deadline())
    }

    /// Claims about the canary and its independent assignment remain data.
    /// Root's genuine exporters and durable phase must own those originals.
    /// Native identity fields, policy, binary, TLS and nonce are not accepted
    /// from an incoming request or copied from an audit certificate.
    pub(super) fn prepare_evidence(&self, state: &GateState, operation: wire::Operation,
        batch: wire::BatchOriginal, purpose_assignment_sha256: &str, canary_assignment_sha256: &str,
        canary_boot_id: &str, deadline: u64) -> Result<wire::PreparedEvidence, String> {
        self.check(state)?;
        let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else { return Err("canary native signer absent".into()); };
        signer.transport.require_native()?;
        let snapshot = current_snapshot(state);
        if !snapshot_is_active(state, &snapshot) { return Err("canary actual policy is not active".into()); }
        let binary = current_binary_digest()?;
        if binary != state.binary_digest { return Err("canary executable differs from actual gate binary".into()); }
        let deadline = {
            let mut authority = state.mitm_authority.as_ref().ok_or("canary native authority absent")?
                .lock().map_err(|_| "canary native authority poisoned")?;
            let MitmAuthority::Native(identity) = &mut *authority else { return Err("canary refuses imported TLS authority".into()); };
            let original = deadline.min(identity.deadline()).min(self.client.tls().deadline());
            self.client.check(identity, original)?;
            original
        };
        let issued = epoch_ns()?;
        let observed = boottime_ns()?;
        let deadline = deadline.min(observed.checked_add(30_000_000_000).ok_or("canary BOOTTIME overflow")?);
        let remaining = deadline.checked_sub(observed).ok_or("canary original operation deadline elapsed")?;
        let expires = issued.checked_add(remaining).ok_or("canary epoch overflow")?;
        let mut nonce = [0u8; 32]; SystemRandom::new().fill(&mut nonce).map_err(|_| "canary fresh nonce unavailable")?;
        if nonce == [0; 32] { return Err("canary fresh nonce is zero".into()); }
        let tls = self.client.tls();
        let statement = wire::Statement {
            api_version: wire::SCHEMA.into(), operation: operation.label().into(), request_id: batch.request_id().to_owned(),
            deployment_id: self.deployment.clone(), instance_id: self.instance.clone(),
            holder_id: catchplate_decision_gate::native_currentness_v1::holder_id(&signer.boot_id, &signer.key_id)?,
            boot_id: signer.boot_id.clone(), key_id: signer.key_id.clone(),
            control_plane_response_signing_key_id: signer.control_plane_response_signing_key_id.clone(),
            policy_hash: snapshot.hash.clone(), data_plane_binary_sha256: binary,
            purpose_assignment_sha256: purpose_assignment_sha256.to_owned(), canary_id: batch.canary_id().to_owned(),
            canary_assignment_sha256: canary_assignment_sha256.to_owned(), canary_boot_id: canary_boot_id.to_owned(),
            batch_sha256: batch.sha256().to_owned(), workload_uri: tls.workload_uri().to_owned(),
            client_certificate_sha256: tls.certificate_sha256().to_owned(), client_spki_sha256: tls.spki_sha256().to_owned(),
            nonce: URL_SAFE_NO_PAD.encode(nonce), issued_at_epoch_ns: issued, expires_at_epoch_ns: expires,
        };
        let prepared = wire::PreparedEvidence::new(statement, batch, tls, deadline)?;
        self.check(state)?;
        if !snapshot_is_active(state, &snapshot) { return Err("canary policy changed during preparation".into()); }
        Ok(prepared)
    }

    pub(super) fn sign(&self, state: &GateState, prepared: &wire::PreparedEvidence)
        -> Result<wire::SignedEvidence, String> {
        self.check(state)?;
        let snapshot = current_snapshot(state);
        if !snapshot_is_active(state, &snapshot) || prepared.statement().policy_hash != snapshot.hash
            || prepared.statement().data_plane_binary_sha256 != state.binary_digest {
            return Err("canary preparation differs from current actual policy/binary".into());
        }
        let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else { return Err("canary native signer absent".into()); };
        let mut authority = state.mitm_authority.as_ref().ok_or("canary native authority absent")?
            .lock().map_err(|_| "canary native authority poisoned")?;
        let MitmAuthority::Native(identity) = &mut *authority else { return Err("canary refuses imported TLS authority".into()); };
        let deadline = prepared.deadline();
        self.client.check(identity, deadline)?;
        let result = signer.transport.canary_evidence(identity, self.client.tls(), prepared, deadline)?;
        self.client.check(identity, deadline)?;
        drop(authority);
        self.check(state)?;
        if !snapshot_is_active(state, &snapshot) { return Err("canary policy changed during signing".into()); }
        result.check()?; Ok(result)
    }
    pub(super) fn endpoint(&self, operation: wire::Operation) -> &str { self.client.endpoint(operation) }

    pub(super) fn delivery(&mut self,state:&GateState,authority:&catchplate_decision_gate::native_canary_delivery_v1::Authority,
        operation:catchplate_decision_gate::native_canary_delivery_v1::Operation,base:&catchplate_decision_gate::native_canary_delivery_v1::Sender,
        request:Value,assignment:&str,original_expires:u64,deadline:u64)
        ->Result<catchplate_decision_gate::native_canary_delivery_v1::Completion,String>{
        use catchplate_decision_gate::native_canary_delivery_v1 as delivery;
        self.check(state)?;authority.check()?;
        let snapshot=current_snapshot(state);
        if !snapshot_is_active(state,&snapshot) || base.policy_hash!=snapshot.hash || base.data_plane_binary_sha256!=current_binary_digest()? {
            return Err("delivery lost actual current policy/source owner".into());
        }
        let deadline=authority.operation_deadline(deadline,false)?.min(self.client.tls().deadline());
        let issued=epoch_ns()?;let remaining=deadline.checked_sub(boottime_ns()?).ok_or("delivery original deadline")?;
        let mut nonce=[0u8;32];SystemRandom::new().fill(&mut nonce).map_err(|_|"delivery nonce")?;
        let mut uuid=[0u8;16];SystemRandom::new().fill(&mut uuid).map_err(|_|"delivery phase UUID")?;uuid[6]=(uuid[6]&15)|64;uuid[8]=(uuid[8]&63)|128;
        let encoded=hex::encode(uuid);let request_id=format!("{}-{}-{}-{}-{}",&encoded[..8],&encoded[8..12],&encoded[12..16],&encoded[16..20],&encoded[20..]);
        let mut expires=issued.checked_add(remaining).ok_or("delivery epoch overflow")?;
        if operation!=delivery::Operation::Recover {expires=expires.min(original_expires);}
        let prepared=delivery::Prepared::new(operation,base,request,request_id,URL_SAFE_NO_PAD.encode(nonce),assignment,issued,
            expires,original_expires,self.client.tls(),deadline)?;
        authority.require_sender(prepared.statement(),true)?;
        let signed={
            let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else{return Err("delivery actual native signer absent".into());};
            let mut guard=state.mitm_authority.as_ref().ok_or("delivery actual native identity absent")?.lock().map_err(|_|"delivery native identity poisoned")?;
            let MitmAuthority::Native(identity)=&mut *guard else{return Err("delivery imported identity refused".into());};
            self.client.check(identity,deadline)?;
            let signed=signer.transport.canary_delivery(identity,self.client.tls(),&prepared,deadline)?;
            self.client.check(identity,deadline)?;signed
        };
        self.check(state)?;authority.check()?;
        let raw=self.client.delivery_once(&signed)?;
        self.check(state)?;
        if !snapshot_is_active(state,&snapshot){return Err("delivery policy changed during contact".into());}
        delivery::Completion::verify(authority,&signed,&raw)
    }
    pub(super) fn intake_once(&mut self,state:&GateState,completion:catchplate_decision_gate::native_canary_delivery_v1::Completion,
        original:&wire::SignedEvidence)->Result<Vec<u8>,String>{
        self.check(state)?;
        let response=self.client.intake_once(completion,original)?;
        self.check(state)?;Ok(response)
    }
    pub(super) fn recovery_sender(&self,state:&GateState,binding:&catchplate_decision_gate::native_canary_delivery_v1::CanaryBinding,
        deadline:u64)->Result<catchplate_decision_gate::native_canary_delivery_v1::Sender,String>{
        self.check(state)?;let snapshot=current_snapshot(state);
        let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else{return Err("recovery native signer absent".into());};
        signer.transport.require_native()?;
        if !snapshot_is_active(state,&snapshot) || current_binary_digest()?!=state.binary_digest{return Err("recovery native source/policy changed".into());}
        let mut guard=state.mitm_authority.as_ref().ok_or("recovery native identity absent")?.lock().map_err(|_|"recovery native identity poisoned")?;
        let MitmAuthority::Native(identity)=&mut *guard else{return Err("recovery imported identity refused".into());};
        self.client.check(identity,deadline)?;let tls=self.client.tls();
        Ok(catchplate_decision_gate::native_canary_delivery_v1::Sender{deployment_id:self.deployment.clone(),instance_id:self.instance.clone(),
            holder_id:catchplate_decision_gate::native_currentness_v1::holder_id(&signer.boot_id,&signer.key_id)?,boot_id:signer.boot_id.clone(),key_id:signer.key_id.clone(),
            control_plane_response_signing_key_id:signer.control_plane_response_signing_key_id.clone(),policy_hash:snapshot.hash.clone(),data_plane_binary_sha256:state.binary_digest.clone(),
            canary_id:binding.canary_id.clone(),canary_assignment_sha256:binding.canary_assignment_sha256.clone(),canary_boot_id:binding.canary_boot_id.clone(),
            workload_uri:tls.workload_uri().into(),client_certificate_sha256:tls.certificate_sha256().into(),client_spki_sha256:tls.spki_sha256().into()})
    }
}

fn epoch_ns() -> Result<u64, String> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "canary epoch clock")?.as_nanos()
        .try_into().map_err(|_| "canary epoch overflow".into())
}
pub(super) fn boottime_ns() -> Result<u64, String> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0
        || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) { return Err("canary BOOTTIME unavailable".into()); }
    (value.tv_sec as u64).checked_mul(1_000_000_000).and_then(|v| v.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| "canary BOOTTIME overflow".into())
}

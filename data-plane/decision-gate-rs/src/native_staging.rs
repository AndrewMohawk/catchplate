//! Private measured-gate preparation for the selected staging family. It
//! captures real process originals and cannot be constructed by deserialization.
use super::*;
use catchplate_decision_gate::native_staging_v1 as profile;
use catchplate_decision_gate::native_response_gate::staging::{self as wire, CurrentProcess};

pub(super) struct Prepared<'a> {
    state:&'a GateState,
    snapshot:Arc<Snapshot>,
    process:CurrentProcess,
    statement:wire::NativeStatement,
    deadline:u64,
}
fn require(ok:bool)->Result<(),String> {
    if ok {Ok(())} else {Err("native staging actual producer binding differs".into())}
}
fn epoch_ns()->Result<u64,String> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"staging epoch clock")?.as_nanos()
        .try_into().map_err(|_|"staging epoch overflow".into())
}
impl<'a> Prepared<'a> {
    pub(super) fn open(state:&'a GateState,snapshot:&Arc<Snapshot>,decision:&Value,
        request:&V2OperationRequest,session:&ResponseObservationV2Session<'_>,predecessor:Option<String>)
        ->Result<Self,String> {
        let lifetime=state.native_runtime_lifetime.as_ref().ok_or("staging actual native lifetime absent")?;
        lifetime.check()?;
        let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else {return Err("staging native signer absent".into());};
        signer.transport.require_native()?;
        require(session.client.native_staging && session.client.guest_listener.is_some()
            && policy_trust_is_fresh(state) && decision.get("allowed").and_then(Value::as_bool)==Some(true))?;
        let binding=request.mutation_binding().ok_or("staging actual mutation binding absent")?;
        require(binding.custody_boot_id==session.client.boot_id
            && binding.client_identity_sha256==session.client.authenticated_client_identity_sha256
            && binding.monotonic_deadline==session.monotonic_deadline
            && binding.deadline_at_epoch_ms==session.deadline_at_epoch_ms
            && binding.transaction.policy_sha256==snapshot.hash
            && decision.get("principal_id").and_then(Value::as_str)==Some(binding.transaction.principal_id.as_str())
            && decision.get("route_id").and_then(Value::as_str)==Some(binding.transaction.route_id.as_str())
            && decision.get("client_request_digest").and_then(Value::as_str)==Some(binding.transaction.client_request_sha256.as_str())
            && decision.get("request_digest").and_then(Value::as_str)==Some(binding.transaction.decision_request_sha256.as_str())
            && snapshot.routes.iter().any(|route|route.id==binding.transaction.route_id))?;
        let process=CurrentProcess::capture()?;
        let original=wire::Original {api_version:wire::ORIGINAL.into(),generation_id:session.client.generation_id.clone(),
            generation:session.client.provider_generation,session_sha256:session.hello_attestation.authenticated_session_sha256.clone(),
            gate_key_id:signer.key_id.clone(),owner:process.original()?.clone(),request:request.clone(),
            predecessor_result_sha256:predecessor};
        let deadline=profile::deadline(&original)?;
        require(deadline<=lifetime.deadline()&&deadline>catchplate_decision_gate::native_secret_broker_v1::now()?)?;
        let issued=epoch_ns()?;
        let expires=issued.checked_add(30_000_000_000).ok_or("staging expiry overflow")?
            .min(binding.deadline_at_epoch_ms.checked_mul(1_000_000).ok_or("staging original epoch overflow")?);
        let statement=wire::NativeStatement {api_version:wire::STATEMENT.into(),original,boot_id:signer.boot_id.clone(),
            key_id:signer.key_id.clone(),control_plane_response_signing_key_id:signer.control_plane_response_signing_key_id.clone(),
            issued_at_epoch_ns:issued,expires_at_epoch_ns:expires};
        let value=Self {state,snapshot:Arc::clone(snapshot),process,statement,deadline}; value.check()?;Ok(value)
    }
    fn check(&self)->Result<(),String> {
        self.state.native_runtime_lifetime.as_ref().ok_or("staging lifetime disappeared")?.check()?;
        self.process.check()?;
        require(policy_trust_is_fresh(self.state)
            && snapshot_is_active(self.state,&self.snapshot)
            && profile::binding(&self.statement.original)?.transaction.policy_sha256==self.snapshot.hash
            && catchplate_decision_gate::native_secret_broker_v1::now()?<self.deadline)?;
        profile::validate_statement(&self.statement,epoch_ns()?)
    }
    pub(super) fn statement(&self)->Result<&wire::NativeStatement,String> {
        self.check()?;Ok(&self.statement)
    }
    pub(super) fn request(&self)->Result<wire::StagingRequest,String> {
        self.check()?;
        let ResponseProofSigner::Custody(signer)=&self.state.response_proof_signer else {return Err("staging signer disappeared".into());};
        let evidence={
            let mut identity=self.state.mitm_authority.as_ref().ok_or("staging actual identity absent")?.lock()
                .map_err(|_|"staging native identity poisoned")?;
            let MitmAuthority::Native(identity)=&mut *identity else {return Err("staging identity is not native".into());};
            signer.transport.staging_evidence(identity,self,self.deadline)?
        };
        self.check()?;Ok(wire::StagingRequest {api_version:wire::REQUEST.into(),evidence})
    }
}

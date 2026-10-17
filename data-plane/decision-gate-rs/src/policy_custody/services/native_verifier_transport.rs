//! Public bytes only. The untrusted relay cannot supply verifier authority.
use super::*;
use super::super::super::guest_original::Original;
use catchplate_decision_gate::enclave_vsock_v1::VsockStreamV1;
use std::io::{Read, Write};
use std::path::Path;

const CONFIGURATION_PATH: &str = "/etc/catchplate/native-shadow-public-exchange.json";
const DOMAIN: &str = "catchplate.nativeShadowVerifierTransport.signature/v1";
const REQUEST_MAGIC: &[u8; 8] = b"SWNSVQ1\0";
const RESULT_MAGIC: &[u8; 8] = b"SWNSVR1\0";
const MAX_EVIDENCE: usize = 128 * 1024;
const MAX_RESULT: usize = 32 * 1024;

/// Independently selected only after the C9 original exists. Putting this pin
/// inside C9/runtime/closure transitive digests would create a self-pin cycle.
/// This data alone never admits the configuration or constructs a live owner.
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(crate) struct NativeVerifierTransportPin { path: String, sha256: Sha256Digest }

/// Chosen from the actual launch variant, never deserialized from a pin.
/// The shared legacy path remains explicit; there is no fallback file lookup.
#[derive(Clone,Copy)]
pub(crate) enum NativeVerifierTransportRole {
    Retrieval, Persistence, TrustedTime, GenerationInstall, CommitRequest,
    IngressAdmission, TerminalAppend, DispatchBarrier, ActiveEffectBarrier,
    ActiveEffectCommit, Bridge,PublicationReconciliation,PublicationGenesisRetrieval,PublicationGenesis,PublicationGenesisCoordinator,
}
impl NativeVerifierTransportRole {
    fn path(self)->&'static str {
        match self {
            Self::Retrieval=>"/etc/catchplate/native-pilot-inputs/native-retrieval-verifier.json",
            Self::Persistence=>"/etc/catchplate/native-pilot-inputs/native-persistence-verifier.json",
            Self::TrustedTime=>"/etc/catchplate/native-pilot-inputs/native-trustedTime-verifier.json",
            Self::GenerationInstall=>"/etc/catchplate/native-pilot-inputs/native-generationInstall-verifier.json",
            Self::CommitRequest=>"/etc/catchplate/native-pilot-inputs/native-commitRequest-verifier.json",
            Self::IngressAdmission=>"/etc/catchplate/native-pilot-inputs/native-ingressAdmission-verifier.json",
            Self::TerminalAppend=>"/etc/catchplate/native-pilot-inputs/native-terminalAppend-verifier.json",
            Self::DispatchBarrier=>"/etc/catchplate/native-pilot-inputs/native-dispatchBarrier-verifier.json",
            Self::ActiveEffectBarrier=>"/etc/catchplate/native-pilot-inputs/native-activeEffectBarrier-verifier.json",
            Self::ActiveEffectCommit=>"/etc/catchplate/native-pilot-inputs/native-activeEffectCommit-verifier.json",
            Self::Bridge=>"/etc/catchplate/native-pilot-inputs/native-bridge-verifier.json",
            Self::PublicationReconciliation=>"/etc/catchplate/native-pilot-inputs/native-publicationReconciliation-verifier.json",
            Self::PublicationGenesisRetrieval=>"/etc/catchplate/native-pilot-inputs/native-publicationGenesisRetrieval-verifier.json",
            Self::PublicationGenesis=>"/etc/catchplate/native-pilot-inputs/native-publicationGenesis-verifier.json",
            Self::PublicationGenesisCoordinator=>"/etc/catchplate/native-pilot-inputs/native-publicationGenesisCoordinator-verifier.json",
        }
    }
}
impl NativeVerifierTransportPin {
    pub(in crate::policy_shadow::policy_custody::services) fn retained_pin(&self)->Result<(&str,&Sha256Digest),ShadowError>{
        self.retained_selected_pin(None)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn retained_selected_pin(&self,
        role:Option<NativeVerifierTransportRole>)->Result<(&str,&Sha256Digest),ShadowError>{
        let fixed_only=matches!(role,Some(NativeVerifierTransportRole::PublicationReconciliation|NativeVerifierTransportRole::PublicationGenesisRetrieval
            |NativeVerifierTransportRole::PublicationGenesis|NativeVerifierTransportRole::PublicationGenesisCoordinator));
        require((!fixed_only && self.path==CONFIGURATION_PATH) || role.map(|role|self.path==role.path()).unwrap_or(false))?;
        Ok((&self.path,&self.sha256))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Payload {
    api_version: String, purpose: String, assignment_id: Sha256Digest,
    assignment_payload_sha256: Sha256Digest, assignment_revision: u64,
    key_authorization_sha256: Sha256Digest, guest: GuestClosureBinding,
    full_key_set_root_sha256: Sha256Digest, challenge_base64url: String,
    verifier_key_id: Sha256Digest, verifier_key_spki_sha256: Sha256Digest,
    verifier_key_material_sha256: Sha256Digest, parent_port: u32,
    trust_checkpoint_id: Sha256Digest, revocation_generation: u64,
    revocation_root_sha256: Sha256Digest, issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64, signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Authorization { payload: Payload, signature: CanonicalEd25519Signature }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Configuration { api_version: String, authorization: Authorization }

impl Configuration {
    fn verify(&self, key_configuration: &NativeCustodyKeyConfiguration,
        assignment: &VerifiedAssignment, association: &GuestClosureAssociation,
        trust: &dyn EnvelopeKeyTrust, time: &dyn TrustedTime) -> Result<(), ShadowError> {
        let checkpoint = trust.current_checkpoint()?;
        super::verify(key_configuration,assignment,association,&checkpoint,trust,time)?;
        let p = &self.authorization.payload;
        let a = assignment.payload();
        let k = &key_configuration.authorization.payload;
        require(self.api_version == "catchplate.nativeShadowVerifierTransport/v1"
            && p.api_version == "catchplate.nativeShadowVerifierTransportAssignment/v1"
            && p.purpose == "public-shadow-nitro-verification"
            && p.assignment_id == a.assignment_id
            && p.assignment_payload_sha256 == *assignment.payload_sha256()
            && p.assignment_revision == a.assignment_revision
            && p.key_authorization_sha256 == Sha256Digest::compute(&canonical_json_bytes(&key_configuration.authorization)?)
            && p.guest == association.binding()
            && p.full_key_set_root_sha256 == k.full_key_set_root_sha256
            && p.challenge_base64url == k.challenge_base64url
            && p.parent_port > 1023 && p.parent_port < u32::MAX
            && p.trust_checkpoint_id == k.trust_checkpoint_id
            && p.revocation_generation == k.revocation_generation
            && p.revocation_root_sha256 == k.revocation_root_sha256)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,
            time,MAX_ENVELOPE_AGE_NANOS)?;
        let verifier = a.authority_key_independence.binding(AuthorityRole::CustodyAttestationVerifier,&a.assignment_id)?;
        require(verifier.key_id == p.verifier_key_id
            && verifier.key_spki_sha256 == p.verifier_key_spki_sha256
            && verifier.key_material_sha256 == p.verifier_key_material_sha256)?;
        // Resolve both distinct roles at the actual current checkpoint. A
        // transport signature is never permission to replace the verifier key.
        let verifier_key = trust.resolve_ed25519_key(&checkpoint,
            authority_role_signature_domain(AuthorityRole::CustodyAttestationVerifier),
            &verifier.key_id,&verifier.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&verifier_key) == verifier.key_material_sha256)?;
        let signer = a.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&a.assignment_id)?;
        require(signer.key_id == p.signing_key_id && signer.key_spki_sha256 == p.signing_key_spki_sha256)?;
        let key = trust.resolve_ed25519_key(&checkpoint,
            authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &signer.key_id,&signer.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key) == signer.key_material_sha256)?;
        key.verify_strict(&signature_preimage(DOMAIN,&canonical_json_bytes(p)?),
            &Signature::from_bytes(&self.authorization.signature.decode()?)).map_err(|_| ShadowError::SignatureInvalid)?;
        require(trust.current_checkpoint()? == checkpoint)
    }
}

pub(super) struct PreparedTransport { original: Original, configuration: Configuration }
impl PreparedTransport {
    /// Same fixed public framing, but only the real explicit admission owner
    /// supplies its original quote. This cannot construct a production result.
    pub(super) fn exchange_admission(&self,owner:&admission::AdmittedKeys,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Vec<u8>,ShadowError> {
        owner.check_transport(self,trust,time)?;
        let evidence=owner.original_evidence()?;
        require(!evidence.is_empty() && evidence.len()<=MAX_EVIDENCE)?;
        let deadline=owner.original_deadline();
        let mut stream=VsockStreamV1::connect_parent(self.configuration.authorization.payload.parent_port,deadline).map_err(fail)?;
        let result=(||{
            owner.check_transport(self,trust,time)?;stream.verify_connected_original(deadline).map_err(fail)?;
            stream.write_all(REQUEST_MAGIC).map_err(fail)?;
            stream.write_all(&(evidence.len() as u32).to_be_bytes()).map_err(fail)?;
            stream.write_all(&evidence).map_err(fail)?;
            owner.check_transport(self,trust,time)?;
            let mut header=[0;12];stream.read_exact(&mut header).map_err(fail)?;
            require(&header[..8]==RESULT_MAGIC)?;
            let count=u32::from_be_bytes(header[8..].try_into().map_err(fail)?) as usize;
            require(count>0 && count<=MAX_RESULT)?;
            let mut raw=vec![0;count];stream.read_exact(&mut raw).map_err(fail)?;
            let mut extra=[0;1];require(stream.read(&mut extra).map_err(fail)?==0)?;
            owner.check_transport(self,trust,time)?;Ok(raw)
        })();
        let closed=stream.shutdown().map_err(fail);let raw=result?;closed?;Ok(raw)
    }
    pub(super) fn check(&self, keys: &NativeCustodyKeyConfiguration, assignment: &VerifiedAssignment,
        association: &GuestClosureAssociation, trust: &dyn EnvelopeKeyTrust,
        time: &dyn TrustedTime) -> Result<(),ShadowError> {
        // Held-descriptor/stat/byte checks work after real final-role drop and
        // root switch. No path reopen or demand for the old root UID occurs.
        let raw = self.original.read(32768).map_err(fail)?;
        require(canonical_json_bytes(&self.configuration)?.as_slice() == raw.as_slice())?;
        self.configuration.verify(keys,assignment,association,trust,time)
    }
    fn check_final(&self, owner: &NativeCustodyKeys, trust: &dyn EnvelopeKeyTrust,
        time: &dyn TrustedTime) -> Result<(),ShadowError> {
        owner.check(trust,time)?;
        owner.association.check_startup().map_err(fail)?;
        self.check(&owner.configuration,&owner.assignment,&owner.association,trust,time)
    }
}
impl PreparedNativeCustodyKeys {
    pub(in crate::policy_shadow::policy_custody::services) fn prepare_late_verifier(&mut self,
        original:Original,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.association.check_native_preparation().map_err(fail)?;
        require(self.association.owner.native_continuation.is_some() && self.verifier_transport.is_none())?;
        let checkpoint=trust.current_checkpoint()?;require(self.checkpoint.permits_successor(&checkpoint))?;
        super::verify(&self.configuration,&self.assignment,&self.association,&checkpoint,trust,time)?;
        let bytes=original.read(32768).map_err(fail)?;
        let configuration:Configuration=serde_json::from_slice(bytes.as_slice()).map_err(fail)?;
        require(canonical_json_bytes(&configuration)?.as_slice()==bytes.as_slice())?;
        let source=PreparedTransport{original,configuration};
        source.check(&self.configuration,&self.assignment,&self.association,trust,time)?;
        self.verifier_transport=Some(source);Ok(())
    }
    /// Actual same-process root preparation only. The separately assigned pin
    /// selects one protected public original; its signature admits the purpose.
    pub(crate) fn prepare_external_verifier(&mut self, pin: NativeVerifierTransportPin,
        trust: &dyn EnvelopeKeyTrust, time: &dyn TrustedTime) -> Result<(),ShadowError> {
        self.prepare_selected_external_verifier(pin,None,trust,time)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn prepare_selected_external_verifier(&mut self,
        pin:NativeVerifierTransportPin,role:Option<NativeVerifierTransportRole>,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.association.check_preparation().map_err(fail)?;
        require(self.verifier_transport.is_none())?;
        let (path,digest)=match role {
            Some(role)=>pin.retained_selected_pin(Some(role))?,
            None=>pin.retained_pin()?,
        };
        let checkpoint = trust.current_checkpoint()?;
        require(self.checkpoint.permits_successor(&checkpoint))?;
        super::verify(&self.configuration,&self.assignment,&self.association,&checkpoint,trust,time)?;
        let original = Original::open(Path::new(path),0,0,32768,digest.clone()).map_err(fail)?;
        let bytes = original.read(32768).map_err(fail)?;
        let configuration: Configuration = serde_json::from_slice(bytes.as_slice()).map_err(fail)?;
        require(canonical_json_bytes(&configuration)?.as_slice() == bytes.as_slice())?;
        let source = PreparedTransport { original, configuration };
        source.check(&self.configuration,&self.assignment,&self.association,trust,time)?;
        self.association.check_preparation().map_err(fail)?;
        self.verifier_transport = Some(source);
        Ok(())
    }
}

impl NativeCustodyKeys {
    /// Explicit native-launcher hook, not an automatic legacy-profile fallback.
    /// Reads the same root-prepared public assignment, never caller evidence,
    /// a URL, a peer identity, an asserted deadline or a verified-result DTO.
    pub(crate) fn verify_external(&mut self, trust: &dyn EnvelopeKeyTrust,
        time: &dyn TrustedTime) -> Result<(), ShadowError> {
        let result = (|| {
            self.check(trust,time)?;
            self.association.check_startup().map_err(fail)?;
            require(!self.attempted && !self.admitted && self.evidence.is_none())?;
            let transport = self.verifier_transport.take().ok_or(ShadowError::CustodyUnavailable)?;
            transport.check_final(self,trust,time)?;
            let evidence = canonical_json_bytes(self.quote(trust,time)?)?;
            require(!evidence.is_empty() && evidence.len() <= MAX_EVIDENCE)?;
            transport.check_final(self,trust,time)?;
            let deadline = self.association.startup();
            let mut stream = VsockStreamV1::connect_parent(transport.configuration.authorization.payload.parent_port,deadline).map_err(fail)?;
            let exchange = (|| {
                transport.check_final(self,trust,time)?;
                stream.verify_connected_original(deadline).map_err(fail)?;
                stream.write_all(REQUEST_MAGIC).map_err(fail)?;
                stream.write_all(&(evidence.len() as u32).to_be_bytes()).map_err(fail)?;
                stream.write_all(&evidence).map_err(fail)?;
                // Never half-close here: the real parent relay stops both read
                // directions on its first EOF. Length framing ends the request.
                transport.check_final(self,trust,time)?;
                let mut header = [0u8;12];
                stream.read_exact(&mut header).map_err(fail)?;
                require(&header[..8] == RESULT_MAGIC)?;
                let length = u32::from_be_bytes(header[8..].try_into().map_err(fail)?) as usize;
                require(length > 0 && length <= MAX_RESULT)?;
                let mut raw = vec![0u8;length];
                stream.read_exact(&mut raw).map_err(fail)?;
                let mut extra = [0u8;1];
                require(stream.read(&mut extra).map_err(fail)? == 0)?;
                transport.check_final(self,trust,time)?;
                // Only this existing verifier admits the result's independent
                // signature, exact retained quote, full root and current trust.
                self.accept_verifier_original(&raw,trust,time)?;
                transport.check_final(self,trust,time)
            })();
            let closed = stream.shutdown().map_err(fail);
            exchange?;
            closed?;
            self.association.check_startup().map_err(fail)?;
            self.check(trust,time)
        })();
        if result.is_err() { self.poisoned.store(true,Ordering::Release); }
        result
    }
}

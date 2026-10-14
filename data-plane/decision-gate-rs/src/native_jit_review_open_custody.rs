//! Actual native key/quote joins. There is no public raw opening signer or
//! caller-supplied view: all statements originate from this retained owner.
use super::*;
use crate::native_jit_review_open_v1::{self as opening, RequestOutcome};
use crate::native_jit_review_browser_v1::{Accepted, Kind};
use crate::native_response_profile_v1::canonical_ascii_bytes;

impl CustodyRuntime {
    pub fn configure_native_jit_review_open(&self, config: opening::Configuration, assignment: &[u8],
        broker: &mut native_secret_broker_v1::Owner, identity: &mut EnclaveRuntimeIdentityV1,
        binary: &str, deadline: u64) -> Result<opening::Owner, ProtocolError> {
        self.verify_native_process()?;
        if !matches!(&self.signing_backend,CustodySigningBackend::Native{..}) || !self.release_profile.is_native()
            || deadline != identity.deadline() { return Err(invalid_statement("opening requires actual cold native custody")); }
        self.verify_native_identity(identity,deadline)?;
        opening::Owner::configure(config,assignment,broker,identity,&self.boot_id,&self.key_id,
            self.control_plane_response_signing_key_id.as_deref().ok_or_else(||invalid_statement("opening CP key absent"))?,
            binary,deadline).map_err(native_proof_error)
    }

    pub fn handle_native_jit_review_open(&self, admitted: &mut opening::Owner,
        broker: &mut native_secret_broker_v1::Owner, identity: &mut EnclaveRuntimeIdentityV1,
        request: &mut Accepted, binary: &str) -> Result<(), ProtocolError> {
        let result=(||{
            self.verify_native_process()?;
            let CustodySigningBackend::Native{owner,..}=&self.signing_backend else {
                return Err(invalid_statement("opening refuses imported custody"));
            };
            {
                // This identity join permanently clips shared key custody.
                // Retain its cohort lifetime; socket/attempt checks stay local.
                let mut owner=owner.lock().map_err(|_|invalid_statement("opening key poisoned"))?;
                let original=identity.deadline().min(owner.deadline());
                owner.verify_identity(identity,original).map_err(native_proof_error)?;
            }
            // Actual shared ownership is checked under its original lifetime,
            // never a caller-controlled socket deadline. A stale/wrong socket
            // is then refused locally without poisoning the cohort or broker.
            let owner_deadline=admitted.deadline(identity.deadline());
            admitted.check(broker,identity,owner_deadline).map_err(native_proof_error)?;
            if let RequestOutcome::Refused=RequestOutcome::local(admitted.require_request(request)) { return Ok(()); }
            let deadline=owner_deadline.min(request.deadline());
            if let RequestOutcome::Refused=RequestOutcome::local(request.narrow_deadline(deadline)) { return Ok(()); }
            match request.kind(){
                Kind::Page=>{ let _socket_outcome=RequestOutcome::local(admitted.page(request)); Ok(()) },
                Kind::Challenge=>{
                    let RequestOutcome::Ready((id,statement))=RequestOutcome::local(admitted.begin_challenge(request))
                        else { return Ok(()); };
                    let original=self.sign_review_open_statement(admitted,broker,identity,statement,binary,request.deadline())?;
                    if let RequestOutcome::Refused=RequestOutcome::local(admitted.finish_challenge(&id,original,request)) {
                        admitted.discard_attempt(&id);
                    }
                    Ok(())
                },
                Kind::Prepare=>{
                    let RequestOutcome::Ready(plan)=RequestOutcome::local(admitted.plan_preparation(request))
                        else { return Ok(()); };
                    let (id,statement)=admitted.prepare(plan,broker,identity).map_err(native_proof_error)?;
                    let original=self.sign_review_open_statement(admitted,broker,identity,statement,binary,request.deadline())?;
                    if let RequestOutcome::Refused=RequestOutcome::local(admitted.finish_preparation(&id,original,request)) {
                        admitted.discard_attempt(&id);
                    }
                    Ok(())
                },
                Kind::Disclose=>{
                    let RequestOutcome::Ready(plan)=RequestOutcome::local(admitted.plan_disclosure(request))
                        else { return Ok(()); };
                    // The attempt is already Spent. A socket-only uncertain
                    // write cannot rearm it or poison unrelated shared custody.
                    let _socket_outcome=RequestOutcome::local(admitted.disclose(plan,request));
                    Ok(())
                },
            }
        })();
        if result.is_err(){admitted.poison();}result
    }

    fn sign_review_open_statement(&self, admitted:&mut opening::Owner, broker:&mut native_secret_broker_v1::Owner,
        identity:&mut EnclaveRuntimeIdentityV1,statement:Value,binary:&str,deadline:u64)->Result<String,ProtocolError>{
        let CustodySigningBackend::Native{owner,quote,..}=&self.signing_backend else{return Err(invalid_statement("opening native key absent"));};
        let schema=statement["schema"].as_str().ok_or_else(||invalid_statement("opening purpose absent"))?;
        let purpose=match schema{opening::CHALLENGE_SCHEMA=>"challenge",opening::PREPARATION_SCHEMA=>"preparation",_=>return Err(invalid_statement("opening signing purpose refused"))};
        if statement["identity"]!=*admitted.identity() || statement["identity"]["bootId"]!=self.boot_id
            || statement["identity"]["keyId"]!=self.key_id || statement["identity"]["expectedBinaryDigest"]!=binary
            || statement["identity"]["controlPlaneResponseSigningKeyId"].as_str()!=self.control_plane_response_signing_key_id.as_deref(){
            return Err(invalid_statement("opening actual identity changed"));
        }
        let canonical=canonical_ascii_bytes(&statement).map_err(native_proof_error)?;
        let mut preimage=schema.as_bytes().to_vec();preimage.push(0);preimage.extend(&canonical);
        let mut owner=owner.lock().map_err(|_|invalid_statement("opening key poisoned"))?;
        let original=identity.deadline().min(owner.deadline());
        owner.verify_identity(identity,original).map_err(native_proof_error)?;
        let deadline=deadline.min(original).min(admitted.deadline(deadline));
        let policy=statement["identity"]["policyHash"].as_str().ok_or_else(||invalid_statement("opening policy absent"))?;
        let mut policy_bytes=[0u8;32];hex::decode_to_slice(&policy[7..],&mut policy_bytes).map_err(|_|invalid_statement("opening policy digest"))?;
        owner.verify_policy_commitment(policy_bytes,deadline).map_err(native_proof_error)?;
        identity.verify_policy_commitment(policy_bytes,deadline).map_err(native_proof_error)?;
        let key=owner.public_key_bytes().map_err(native_proof_error)?;
        if quote.public_key()!=key.as_slice() || sha256_prefixed(&ed25519_spki_der(&key))!=self.key_id{return Err(invalid_statement("opening actual signing key changed"));}
        admitted.check(broker,identity,deadline).map_err(native_proof_error)?;
        let signature=owner.sign(&preimage,deadline).map_err(native_proof_error)?;
        let mut hash=Sha256::new();hash.update(format!("serverware/native-jit-review-open-{purpose}-attestation/v1\0").as_bytes());
        hash.update(Sha256::digest(&canonical));hash.update(signature);let nonce:[u8;32]=hash.finalize().into();
        let fresh=owner.quote_fresh(identity,nonce,deadline).map_err(native_proof_error)?;
        if fresh.public_key()!=key.as_slice() || fresh.user_data()!=quote.user_data() || fresh.nonce()!=&nonce
            || fresh.document().is_empty() || fresh.document().len()>12*1024{return Err(invalid_statement("opening role-4 quote scope changed"));}
        admitted.check(broker,identity,deadline).map_err(native_proof_error)?;owner.verify_live(deadline).map_err(native_proof_error)?;
        let proof=serde_json::json!({"statement":statement,"signature":format!("ed25519:{}",general_purpose::URL_SAFE_NO_PAD.encode(signature)),
            "nativeKeyEvidence":{"apiVersion":"serverware.nativeResponseProofKeyEvidence/v1",
                "responseProofPublicKey":general_purpose::URL_SAFE_NO_PAD.encode(fresh.public_key()),
                "attestationDocumentB64":general_purpose::URL_SAFE_NO_PAD.encode(fresh.document())},
            "assignmentOriginal":admitted.assignment_original()});
        let raw=canonical_ascii_bytes(&proof).map_err(native_proof_error)?;
        if raw.len()>128*1024{return Err(invalid_statement("opening proof bound"));}
        String::from_utf8(raw).map_err(|_|invalid_statement("opening proof ASCII"))
    }
}

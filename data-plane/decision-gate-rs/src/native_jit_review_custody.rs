//! No raw pair signer: this entrypoint obtains the actual broker preparation
//! from its retained admitted owner and signs only those original bindings.
use super::*;
use crate::native_jit_review_v1 as jit;
use crate::native_response_profile_v1::canonical_ascii_bytes;

impl CustodyRuntime {
    pub fn configure_native_jit_review(&self, config: jit::Configuration, assignment: &[u8],
        broker: &mut native_secret_broker_v1::Owner, identity: &mut EnclaveRuntimeIdentityV1,
        binary: &str, deadline: u64) -> Result<jit::Owner, ProtocolError> {
        self.verify_native_process()?;
        if !matches!(&self.signing_backend, CustodySigningBackend::Native { .. })
            || !self.release_profile.is_native() || deadline != identity.deadline() {
            return Err(invalid_statement("JIT cold configuration requires the actual native owner"));
        }
        self.verify_native_identity(identity, deadline)?;
        jit::Owner::configure(config, assignment, broker, identity, &self.boot_id, &self.key_id,
            self.control_plane_response_signing_key_id.as_deref().ok_or_else(|| invalid_statement("JIT CP key absent"))?,
            binary, deadline).map_err(native_proof_error)
    }

    pub fn prepare_native_release_jit_review(&self, admitted: &mut jit::Owner,
        broker: &mut native_secret_broker_v1::Owner, identity: &mut EnclaveRuntimeIdentityV1,
        runtime: &[u8], parent: &[u8], child: &[u8], binary: &str, deadline: u64)
        -> Result<jit::SignedReleasePair, ProtocolError> {
        let result = (|| {
            self.verify_native_process()?;
            let CustodySigningBackend::Native { owner, quote, .. } = &self.signing_backend else {
                return Err(invalid_statement("JIT preparation refuses imported custody"));
            };
            let deadline = admitted.deadline(deadline).min(identity.deadline());
            let prepared = admitted.prepare(broker, identity, runtime, parent, child, deadline).map_err(native_proof_error)?;
            broker.check_release_jit_review_prepared(identity, &prepared).map_err(native_proof_error)?;
            let mut statement = prepared.statement_bindings().clone();
            let bindings = statement.as_object_mut().ok_or_else(|| invalid_statement("JIT statement bindings absent"))?;
            if bindings.len() != 27 || bindings.get("bootId") != Some(&Value::String(self.boot_id.clone()))
                || bindings.get("keyId") != Some(&Value::String(self.key_id.clone()))
                || bindings.get("controlPlaneResponseSigningKeyId").and_then(Value::as_str) != self.control_plane_response_signing_key_id.as_deref()
                || bindings.get("expectedBinaryDigest").and_then(Value::as_str) != Some(binary) {
                return Err(invalid_statement("JIT prepared signing scope differs"));
            }
            bindings.insert("apiVersion".into(), Value::String(jit::SCHEMA.into()));
            bindings.insert("operation".into(), Value::String(jit::SIGN_OPERATION.into()));
            let canonical = canonical_ascii_bytes(&statement).map_err(native_proof_error)?;
            let mut preimage = jit::SCHEMA.as_bytes().to_vec(); preimage.push(0); preimage.extend(&canonical);
            let mut owner = owner.lock().map_err(|_| invalid_statement("JIT key owner poisoned"))?;
            // This join retains the shared key's cohort lifetime. Request-local
            // checks/sign/quote use the narrower deadline without renewing it.
            let original = identity.deadline().min(owner.deadline());
            owner.verify_identity(identity, original).map_err(native_proof_error)?;
            let deadline = deadline.min(original);
            let policy = statement["policyHash"].as_str().ok_or_else(|| invalid_statement("JIT policy absent"))?;
            let mut policy_bytes = [0u8; 32]; hex::decode_to_slice(&policy[7..], &mut policy_bytes).map_err(|_| invalid_statement("JIT policy digest"))?;
            owner.verify_policy_commitment(policy_bytes, deadline).map_err(native_proof_error)?;
            identity.verify_policy_commitment(policy_bytes, deadline).map_err(native_proof_error)?;
            let key = owner.public_key_bytes().map_err(native_proof_error)?;
            if quote.public_key() != key.as_slice() || sha256_prefixed(&ed25519_spki_der(&key)) != self.key_id {
                return Err(invalid_statement("JIT actual signing key changed"));
            }
            admitted.check(broker, identity, deadline).map_err(native_proof_error)?;
            broker.check_release_jit_review_prepared(identity, &prepared).map_err(native_proof_error)?;
            let signature = owner.sign(&preimage, deadline).map_err(native_proof_error)?;
            let mut hash = Sha256::new(); hash.update(jit::ATTESTATION_DOMAIN);
            hash.update(native_currentness_v1::bytes32(statement["challenge"].as_str().ok_or_else(|| invalid_statement("JIT challenge absent"))?).map_err(native_proof_error)?);
            hash.update(Sha256::digest(&canonical)); hash.update(signature);
            let nonce: [u8; 32] = hash.finalize().into();
            let fresh = owner.quote_fresh(identity, nonce, deadline).map_err(native_proof_error)?;
            if fresh.public_key() != key.as_slice() || fresh.user_data() != quote.user_data() || fresh.nonce() != &nonce
                || fresh.document().is_empty() || fresh.document().len() > 12 * 1024 {
                return Err(invalid_statement("JIT fresh role-4 quote lost original scope"));
            }
            admitted.check(broker, identity, deadline).map_err(native_proof_error)?;
            broker.check_release_jit_review_prepared(identity, &prepared).map_err(native_proof_error)?;
            owner.verify_live(deadline).map_err(native_proof_error)?;
            let proof = serde_json::json!({"statement": statement,
                "signature": format!("ed25519:{}", general_purpose::URL_SAFE_NO_PAD.encode(signature)),
                "nativeKeyEvidence": {"apiVersion":"serverware.nativeResponseProofKeyEvidence/v1",
                    "responseProofPublicKey":general_purpose::URL_SAFE_NO_PAD.encode(fresh.public_key()),
                    "attestationDocumentB64":general_purpose::URL_SAFE_NO_PAD.encode(fresh.document())},
                "assignmentOriginal":admitted.assignment_original()});
            let pair = canonical_ascii_bytes(prepared.pair()).map_err(native_proof_error)?;
            let proof = canonical_ascii_bytes(&proof).map_err(native_proof_error)?;
            if pair.len() > 1024 * 1024 || proof.len() > 128 * 1024 {
                return Err(invalid_statement("JIT literal evidence bounds"));
            }
            Ok(jit::SignedReleasePair { pair_original: String::from_utf8(pair).map_err(|_| invalid_statement("JIT pair ASCII"))?,
                proof_original: String::from_utf8(proof).map_err(|_| invalid_statement("JIT proof ASCII"))? })
        })();
        if result.is_err() { admitted.poison(); broker.poison_jit_review(); }
        result
    }
}

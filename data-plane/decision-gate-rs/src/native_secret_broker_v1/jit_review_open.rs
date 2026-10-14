//! Separate opening channel on the same actual combined-JIT broker. Only
//! recipient-encrypted redacted material returns to its retained native owner.
use super::*;
use crate::native_oauth_exchange_v1::BrowserTls;
use crate::native_jit_review_open_v1::NATIVE_FIELDS;
use std::collections::BTreeSet;
const CHANNEL: &str = "serverware.nativeJitReviewOpenChannel/v1";
const DOMAIN: &[u8] = b"serverware/native-jit-review-open-ciphertext/v1\0";
pub(super) struct Configured {
    ingress: Arc<BrowserTls>, marker: Arc<()>, identity: Value, owner_scope: String,
    capacity: usize, spent: BTreeSet<String>,
}
impl Owner {
    pub(crate) fn configure_jit_review_open(&mut self, configuration: Value, ingress: Arc<BrowserTls>,
        identity: &mut EnclaveRuntimeIdentityV1, deadline: u64) -> Result<Arc<()>, String> {
        let result = (|| {
            self.check(deadline)?; identity.verify_browser_ingress(&ingress, deadline)?;
            let service = self.service_token_scope.as_ref().ok_or("review service custody absent")?;
            ensure(self.jit_open_configuration.is_none() && self.jit_review_is_cold() && !self.credential_phase_started
                && self.static_configuration.is_none() && self.static_rotation_configuration.is_none()
                && self.exchange_configuration.is_none() && self.setup_configuration.is_none()
                && self.reconnect_configuration.is_none() && self.succession_configuration.is_none()
                && self.refresh_configuration.is_none() && self.cleanup_configuration.is_none()
                && self.pending_retirement_configuration.is_none() && self.capture_retirement_configuration.is_none()
                && self.historical_configuration_sha256.is_none() && identity.deadline() == self.deadline,
                "review requires cold combined JIT owner")?;
            fields(&configuration, &["apiVersion","sourceContractDigest","controlPlaneConfigurationDigest","policy","assignmentOriginal"])?;
            ensure(configuration["apiVersion"] == "serverware.nativeJitReviewOpenConfiguration/v1", "review broker profile")?;
            let assignment = document(configuration["assignmentOriginal"].as_str().ok_or("review assignment")?.as_bytes(),64*1024)?;
            let selected = &assignment["payload"]["assignment"];
            let sealing = self.jit_review_cold_scope()?;
            ensure(sealing["sourceContractDigest"] == configuration["sourceContractDigest"]
                && sealing["controlPlaneConfigurationDigest"] == configuration["controlPlaneConfigurationDigest"]
                && sealing["instanceId"] == selected["instanceId"] && sealing["secretKekId"] == selected["secretKekId"],
                "combined JIT cold configuration differs")?;
            for name in NATIVE_FIELDS { ensure(sealing["identity"][*name] == selected[*name],"combined JIT actual identity differs")?; }
            ensure(selected["secretKekId"] == self.secret_kek_id && selected["instanceId"] == service.instance_id
                && selected["policyHash"] == service.policy_hash && selected["expectedBinaryDigest"] == service.binary_digest
                && configuration["policy"]["nativeOrigin"] == ingress.origin()
                && Sha256::digest(identity.ca_certificate_der()).as_slice() == self.owner_ca,
                "review actual service identity differs")?;
            identity.require_serving_privileges(self.serving.as_ref().ok_or("review serving owner")?,deadline)?;
            let scope = identity.refresh_scope(deadline)?;
            for name in ["releaseRecordSha256","policyHash","configurationSha256","caCertificateSha256","caPublicKeySpkiSha256"] {
                ensure(scope[name] == selected[name],"review assignment actual identity differs")?;
            }
            let mut actual = serde_json::Map::new();
            for name in NATIVE_FIELDS { actual.insert((*name).into(),selected[*name].clone()); }
            let capacity = configuration["policy"]["attemptCapacity"].as_u64().filter(|n| (1..=16).contains(n)).ok_or("review capacity")? as usize;
            let owner_scope = sha(&canonical_ascii_bytes(&configuration)?);
            let raw = canonical_ascii_bytes(&json!({"apiVersion":CHANNEL,"phase":"configure","configuration":configuration}))?;
            ensure(raw.len() <= 641*1024,"review cold bound")?;
            let reply = document(&self.process.exchange(&raw,deadline)?,4096)?;
            fields(&reply,&["apiVersion","phase"])?;
            ensure(reply["apiVersion"] == CHANNEL && reply["phase"] == "configured","review cold broker refused")?;
            self.check(deadline)?; identity.verify_live(deadline)?;
            let marker = Arc::new(());
            self.jit_open_configuration = Some(Configured { ingress, marker: Arc::clone(&marker),
                identity:Value::Object(actual),owner_scope,capacity,spent:BTreeSet::new() });
            Ok(marker)
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); } result
    }
    pub(crate) fn jit_review_open_marker(&mut self, identity:&mut EnclaveRuntimeIdentityV1,
        ingress:&Arc<BrowserTls>,deadline:u64)->Result<Arc<()>,String>{
        self.check(deadline)?;identity.verify_browser_ingress(ingress,deadline)?;
        let held=self.jit_open_configuration.as_ref().ok_or("review broker not configured")?;
        ensure(Arc::ptr_eq(ingress,&held.ingress) && identity.deadline()==self.deadline
            && Sha256::digest(identity.ca_certificate_der()).as_slice()==self.owner_ca,"review broker owner changed")?;
        identity.require_serving_privileges(self.serving.as_ref().ok_or("review serving owner")?,deadline)?;
        let scope=identity.refresh_scope(deadline)?;
        for name in ["releaseRecordSha256","policyHash","configurationSha256","caCertificateSha256","caPublicKeySpkiSha256"]{
            ensure(scope[name]==held.identity[name],"review broker retained scope changed")?;
        }
        Ok(Arc::clone(&held.marker))
    }
    pub(crate) fn prepare_jit_review_open(&mut self,identity:&mut EnclaveRuntimeIdentityV1,
        ingress:&Arc<BrowserTls>,command:&Value,recipient:CredentialRecipientV1,salt:[u8;32],deadline:u64)
        ->Result<Zeroizing<Vec<u8>>,String>{
        let result=(||{
            self.jit_review_open_marker(identity,ingress,deadline)?;
            fields(command,&["apiVersion","phase","challengeOriginal","authorizationOriginal","parentOriginal","childOriginal","pairOriginal","evidenceOriginal","deadlineBoottimeNs"])?;
            ensure(command["apiVersion"]==CHANNEL && command["phase"]=="prepare" && command["deadlineBoottimeNs"]==deadline,"review command purpose")?;
            let challenge=document(command["challengeOriginal"].as_str().ok_or("review challenge")?.as_bytes(),128*1024)?;
            let scope=&challenge["statement"];
            let public=recipient.public_key_bytes()?;
            ensure(scope["recipientPublicKey"]==encoded(&public)
                && scope["challenge"]==encoded(&salt),"review retained recipient differs")?;
            let held=self.jit_open_configuration.as_mut().ok_or("review broker not configured")?;
            ensure(scope["ownerScopeDigest"]==held.owner_scope && held.spent.len()<held.capacity,"review broker attempt capacity")?;
            let challenge_sha=sha(command["challengeOriginal"].as_str().ok_or("review challenge")?.as_bytes());
            ensure(held.spent.insert(challenge_sha),"review broker challenge spent")?;
            let raw=canonical_ascii_bytes(command)?;ensure(raw.len()<=5*1024*1024,"review command bound")?;
            let expected=sha(&raw);
            let reply=document(&self.process.exchange(&raw,deadline)?,512*1024)?;
            fields(&reply,&["apiVersion","requestSha256","recipientPublicKey","serverEphemeralPublicKey","aeadNonce","ciphertext"])?;
            ensure(reply["apiVersion"]=="serverware.nativeJitReviewOpenCiphertext/v1" && reply["requestSha256"]==expected
                && reply["recipientPublicKey"]==encoded(&public),"review recipient ciphertext differs")?;
            let peer:[u8;32]=decoded(&reply["serverEphemeralPublicKey"],32,Some(32))?.try_into().map_err(|_|"review peer width")?;
            let nonce:[u8;12]=decoded(&reply["aeadNonce"],12,Some(12))?.try_into().map_err(|_|"review nonce width")?;
            let mut ciphertext=Zeroizing::new(decoded(&reply["ciphertext"],256*1024+16,None)?);
            let shared=recipient.derive_shared_key(peer)?;
            let mut aad=DOMAIN.to_vec();aad.extend(digest(&expected)?);
            let salt=hkdf::Salt::new(hkdf::HKDF_SHA256,&salt);let prk=salt.extract(shared.as_ref());
            let mut key=Zeroizing::new([0u8;32]);prk.expand(&[aad.as_slice()],AesKey).map_err(|_|"review KDF")?
                .fill(key.as_mut()).map_err(|_|"review key")?;
            let key=aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM,key.as_ref()).map_err(|_|"review AEAD")?);
            let length=key.open_in_place(aead::Nonce::assume_unique_for_key(nonce),aead::Aad::from(&aad),ciphertext.as_mut())
                .map_err(|_|"review ciphertext authentication refused")?.len();
            ciphertext.truncate(length);
            ensure(!ciphertext.is_empty() && std::str::from_utf8(&ciphertext).is_ok(),"review UTF8")?;
            self.jit_review_open_marker(identity,ingress,deadline)?;Ok(ciphertext)
        })();
        if result.is_err(){self.poisoned=true;self.process.terminate();}result
    }
}

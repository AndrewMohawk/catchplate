//! Same C9/closure owner: ciphertext original -> real KMS recipient -> assigned
//! local key owners. No file materialization, key export or readiness claim.
use super::*;
use serverware_decision_gate::{enclave_runtime_identity_v1::CredentialRecipientV1,
    native_secret_broker_v1::shadow_key_delivery::{self as mechanism,PreparedShadowKeyHelper}};
use ring::{aead,hkdf};
use zeroize::Zeroize;
const CREDENTIAL:&str="shadow-encrypted-role-inventory";
const DOMAIN:&str="serverware.nativeShadowEncryptedKeyDelivery.signature/v1";
const EXTENDED_DOMAIN:&str="serverware.nativeShadowEncryptedKeyDelivery.signature/v2";
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,assignment_id:Sha256Digest,assignment_payload_sha256:Sha256Digest,
    assignment_revision:u64,key_authorization_sha256:Sha256Digest,guest:GuestClosureBinding,
    full_key_set_root_sha256:Sha256Digest,local_key_set_root_sha256:Sha256Digest,challenge_base64url:String,
    transport:mechanism::Configuration,trust_checkpoint_id:Sha256Digest,revocation_generation:u64,
    revocation_root_sha256:Sha256Digest,issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,
    signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Authorization {payload:Payload,signature:CanonicalEd25519Signature}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct LegacyConfiguration {api_version:String,authorization:Authorization}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct CommitmentConfiguration {api_version:String,authorization:Authorization,request_commitment:commitment::Authorization}
#[derive(Serialize,Deserialize)]
#[serde(untagged)]
pub(crate) enum NativeShadowEncryptedKeysConfiguration {Legacy(LegacyConfiguration),Commitment(CommitmentConfiguration)}
impl NativeShadowEncryptedKeysConfiguration {
    pub(in crate::policy_shadow::policy_custody::services) fn has_commitment(&self)->bool {self.commitment().is_some()}
    pub(in crate::policy_shadow::policy_custody::services) fn sampling_selected(&self)->bool {
        self.commitment().is_some_and(|v|v.sampling_selected())
    }
    fn authorization(&self)->&Authorization {match self {Self::Legacy(v)=>&v.authorization,Self::Commitment(v)=>&v.authorization}}
    fn commitment(&self)->Option<&commitment::Authorization> {match self {Self::Legacy(_)=>None,Self::Commitment(v)=>Some(&v.request_commitment)}}
    pub(super) fn verify(&self,key_configuration:&NativeCustodyKeyConfiguration,assignment:&VerifiedAssignment,
        association:&GuestClosureAssociation,checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust,
        time:&dyn TrustedTime)->Result<(),ShadowError> {
        super::verify(key_configuration,assignment,association,checkpoint,trust,time)?;
        let authorization=self.authorization();let p=&authorization.payload;let a=assignment.payload();let k=&key_configuration.authorization.payload;
        match self {
            Self::Legacy(v)=>require(v.api_version=="serverware.nativeShadowEncryptedKeyDelivery/v1"
                && p.api_version=="serverware.nativeShadowEncryptedKeyDeliveryAssignment/v1" && p.purpose=="kms-recipient-shadow-local-keys"
                && p.transport.api_version=="serverware.nativeShadowKeyKmsTransport/v1")?,
            Self::Commitment(v)=>{
                require(v.api_version=="serverware.nativeShadowEncryptedKeyDelivery/v2"
                    && p.api_version=="serverware.nativeShadowEncryptedKeyDeliveryAssignment/v2"
                    && p.purpose=="kms-recipient-shadow-local-keys-and-request-commitment"
                    && p.transport.api_version=="serverware.nativeShadowKeyKmsTransport/v2")?;
                v.request_commitment.verify(key_configuration,assignment,association,checkpoint,trust,time)?;
            }
        }
        require(key_configuration.api_version=="serverware.nativeShadowRoleKeys/v2"
            && p.assignment_id==a.assignment_id&&p.assignment_payload_sha256==*assignment.payload_sha256()
            && p.assignment_revision==a.assignment_revision&&p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&key_configuration.authorization)?)
            && p.guest==association.binding()&&p.full_key_set_root_sha256==k.full_key_set_root_sha256
            && p.challenge_base64url==k.challenge_base64url&&p.trust_checkpoint_id==k.trust_checkpoint_id
            && p.revocation_generation==k.revocation_generation&&p.revocation_root_sha256==k.revocation_root_sha256)?;
        let bindings=full_bindings(assignment)?;
        let local:BTreeMap<_,_>=k.local_roles.iter().map(|role|(*role,bindings[role].clone())).collect();
        require(production_custody_key_set_root(&local)?==p.local_key_set_root_sha256)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        p.transport.validate().map_err(fail)?;
        let (entry,_)=association.owner.credentials.get(CREDENTIAL).ok_or(ShadowError::CustodyUnavailable)?;
        require(entry.signing.is_none()&&entry.length>0&&entry.length<=32768
            && entry.original.sha256.as_str()==p.transport.encrypted_inventory_sha256)?;
        // The explicit encrypted profile must never accidentally read a legacy
        // plaintext local-role slot, including nonselected local roles.
        for role in PRODUCTION_CUSTODY_AUTHORITY_ROLES.iter().take(16) {
            require(!association.owner.credentials.contains_key(credential(*role)?))?;
        }
        let signer=a.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&a.assignment_id)?;
        require(signer.key_id==p.signing_key_id&&signer.key_spki_sha256==p.signing_key_spki_sha256)?;
        let key=trust.resolve_ed25519_key(checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &signer.key_id,&signer.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key)==signer.key_material_sha256)?;
        let domain=if self.commitment().is_some(){EXTENDED_DOMAIN}else{DOMAIN};
        key.verify_strict(&signature_preimage(domain,&canonical_json_bytes(p)?),&Signature::from_bytes(&authorization.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        require(trust.current_checkpoint()?==*checkpoint)
    }
}
pub(super) struct Prepared {configuration:NativeShadowEncryptedKeysConfiguration,helper:PreparedShadowKeyHelper}
impl PreparedNativeCustodyKeys {
    pub(in crate::policy_shadow::policy_custody::services) fn open_encrypted_late(
        configuration:NativeCustodyKeyConfiguration,encrypted:NativeShadowEncryptedKeysConfiguration,
        assignment:&VerifiedAssignment,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,
        delivery:&PreparedGuestServiceDelivery,prepared:super::super::native_guest::driver_continuation::Resources)
        ->Result<Self,ShadowError> {
        let association=delivery.native_closure_association().map_err(fail)?;
        let owner=association.owner.native_continuation.as_ref().ok_or(ShadowError::BindingDrift)?;
        owner.check_startup()?;let checkpoint=trust.current_checkpoint()?;
        let k=&configuration.authorization.payload;let p=&encrypted.authorization().payload;
        require(configuration.api_version=="serverware.nativeShadowRoleKeys/v2"
            && k.trust_checkpoint_id==checkpoint.checkpoint_id && k.revocation_generation==checkpoint.revocation_generation
            && k.revocation_root_sha256==checkpoint.revocation_root_sha256
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
        verify(&configuration,assignment,&association,&checkpoint,trust,time)?;
        encrypted.verify(&configuration,assignment,&association,&checkpoint,trust,time)?;
        let (nsm,helper)=prepared.consume(&encrypted.authorization().payload.transport,owner)?;
        association.check_native_preparation().map_err(fail)?;
        Ok(Self{configuration,assignment:assignment.clone(),association,nsm,checkpoint,
            encrypted:Some(Prepared{configuration:encrypted,helper}),verifier_transport:None})
    }
    pub(crate) fn open_encrypted(configuration:NativeCustodyKeyConfiguration,encrypted:NativeShadowEncryptedKeysConfiguration,
        assignment:&VerifiedAssignment,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,
        delivery:&PreparedGuestServiceDelivery)->Result<Self,ShadowError> {
        let association=delivery.closure_association().map_err(fail)?;association.check_preparation().map_err(fail)?;
        let checkpoint=trust.current_checkpoint()?;let k=&configuration.authorization.payload;let p=&encrypted.authorization().payload;
        require(configuration.api_version=="serverware.nativeShadowRoleKeys/v2"
            && k.trust_checkpoint_id==checkpoint.checkpoint_id&&k.revocation_generation==checkpoint.revocation_generation
            && k.revocation_root_sha256==checkpoint.revocation_root_sha256
            && p.trust_checkpoint_id==checkpoint.checkpoint_id&&p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
        verify(&configuration,assignment,&association,&checkpoint,trust,time)?;
        encrypted.verify(&configuration,assignment,&association,&checkpoint,trust,time)?;
        let nsm=PreparedShadowNsmV1::open(association.startup(),association.lifetime()).map_err(fail)?;
        let guest=association.binding();
        let helper=PreparedShadowKeyHelper::open(p.transport.clone(),guest.uid,guest.gid,association.startup()).map_err(fail)?;
        association.check_preparation().map_err(fail)?;
        Ok(Self{configuration,assignment:assignment.clone(),association,nsm,checkpoint,
            encrypted:Some(Prepared{configuration:encrypted,helper}),verifier_transport:None})
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Seed {role:AuthorityRole,key_id:Sha256Digest,seed_base64url:String}
impl Drop for Seed {fn drop(&mut self){self.seed_base64url.zeroize();}}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Seeds {api_version:String,inventory_sha256:Sha256Digest,seeds:Vec<Seed>}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct CommitmentSecret {key_id:Sha256Digest,key_epoch:u64,secret_base64url:String}
impl Drop for CommitmentSecret {fn drop(&mut self){self.secret_base64url.zeroize();}}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct CommitmentSeeds {api_version:String,inventory_sha256:Sha256Digest,seeds:Vec<Seed>,request_commitment:CommitmentSecret}
struct KeyLength;
impl hkdf::KeyType for KeyLength {fn len(&self)->usize {32}}
fn decode(value:&serde_json::Value,maximum:usize,exact:Option<usize>)->Result<Zeroizing<Vec<u8>>,ShadowError> {
    let text=value.as_str().ok_or(ShadowError::BindingDrift)?;
    decode_text(text,maximum,exact)
}
fn decode_text(text:&str,maximum:usize,exact:Option<usize>)->Result<Zeroizing<Vec<u8>>,ShadowError> {
    require(!text.is_empty()&&text.len()<=(maximum*4+2)/3)?;
    let raw=Zeroizing::new(URL_SAFE_NO_PAD.decode(text).map_err(fail)?);
    let canonical=Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_slice()));
    require(raw.len()<=maximum&&exact.is_none_or(|n|n==raw.len())&&canonical.as_str()==text)?;Ok(raw)
}
impl Prepared {
    pub(super) fn bind(self,key_configuration:&NativeCustodyKeyConfiguration,assignment:&VerifiedAssignment,
        association:&GuestClosureAssociation,closure:&NativeCustodyClosureOwner,production:&ProductionCustodyConfiguration,
        nsm:&mut ShadowNsmV1,checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<(BTreeMap<AuthorityRole,LocalKey>,NativeShadowEncryptedKeysConfiguration),ShadowError> {
        // This older production-driver constructor has no HMAC operation owner.
        // The explicit successor is selected only by actual native admission.
        require(self.configuration.commitment().is_none())?;
        let bindings=full_bindings(assignment)?;
        for (role,binding) in &bindings {require(production.authority_binding(*role)?==binding)?;}
        let (keys,configuration,commitment)=self.bind_keys(key_configuration,assignment,association,closure,&bindings,nsm,checkpoint,trust,time)?;
        require(commitment.is_none())?;Ok((keys,configuration))
    }
    pub(super) fn bind_admission(self,key_configuration:&NativeCustodyKeyConfiguration,assignment:&VerifiedAssignment,
        association:&GuestClosureAssociation,closure:&NativeCustodyClosureOwner,nsm:&mut ShadowNsmV1,
        checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<(BTreeMap<AuthorityRole,LocalKey>,NativeShadowEncryptedKeysConfiguration,Option<commitment::Owner>),ShadowError> {
        // Actual independently verified assignment, not a production driver or
        // caller-provided authority map. Admission exposes no service signing.
        let bindings=full_bindings(assignment)?;
        self.bind_keys(key_configuration,assignment,association,closure,&bindings,nsm,checkpoint,trust,time)
    }
    fn bind_keys(self,key_configuration:&NativeCustodyKeyConfiguration,assignment:&VerifiedAssignment,
        association:&GuestClosureAssociation,closure:&NativeCustodyClosureOwner,
        bindings:&BTreeMap<AuthorityRole,ProductionCustodyKeyBinding>,nsm:&mut ShadowNsmV1,
        checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<(BTreeMap<AuthorityRole,LocalKey>,NativeShadowEncryptedKeysConfiguration,Option<commitment::Owner>),ShadowError> {
        association.check_startup().map_err(fail)?;closure.require_origin(association)?;
        self.configuration.verify(key_configuration,assignment,association,checkpoint,trust,time)?;
        let mut public_keys=Vec::new();
        for role in &key_configuration.authorization.payload.local_roles {
            let b=bindings.get(role).ok_or(ShadowError::SignerBindingMismatch)?;
            let key=trust.resolve_ed25519_key(checkpoint,authority_role_signature_domain(*role),b.key_id(),b.key_spki_sha256())?;
            require(ed25519_public_key_material_sha256(&key)==*b.key_material_sha256())?;
            public_keys.push(PublicKey{role:*role,key_id:b.key_id().clone(),key_spki_sha256:b.key_spki_sha256().clone(),
                key_material_sha256:b.key_material_sha256().clone(),public_key_base64url:URL_SAFE_NO_PAD.encode(key.to_bytes())});
        }
        let p=&self.configuration.authorization().payload;
        let extended=self.configuration.commitment().is_some();
        let mut inventory=serde_json::json!({"apiVersion":if extended{"serverware.nativeShadowLocalKeyInventory/v2"}else{"serverware.nativeShadowLocalKeyInventory/v1"},
            "fullKeySetRootSha256":p.full_key_set_root_sha256,"localKeySetRootSha256":p.local_key_set_root_sha256,"localKeys":public_keys});
        if let Some(authorization)=self.configuration.commitment() {
            inventory["requestCommitment"]=serde_json::to_value(authorization.descriptor()).map_err(fail)?;
        }
        let inventory_sha=Sha256Digest::compute(&canonical_json_bytes(&inventory)?);
        let binding=mechanism::Binding{api_version:if extended{"serverware.nativeShadowKeyDeliveryBinding/v2".into()}else{"serverware.nativeShadowKeyDeliveryBinding/v1".into()},
            guest:serde_json::to_value(association.binding()).map_err(fail)?,key_authorization_sha256:p.key_authorization_sha256.as_str().into(),
            delivery_authorization_sha256:Sha256Digest::compute(&canonical_json_bytes(self.configuration.authorization())?).as_str().into(),
            inventory,challenge_base64url:p.challenge_base64url.clone(),execution_closure_manifest_sha256:closure.manifest_sha256().as_str().into(),
            worker_executable_sha256:closure.worker_executable_sha256().as_str().into(),
            structurally_verified_seccomp_policy_sha256:closure.seccomp_policy_sha256().as_str().into()};
        // Ciphertext is the SAME C9 held original, never a root-switch path reopen.
        let ciphertext=association.owner.read(CREDENTIAL,32768).map_err(fail)?;
        let recipient=CredentialRecipientV1::generate().map_err(fail)?;
        let mut pending=self.helper.begin(binding,&recipient,ciphertext).map_err(fail)?;
        association.check_startup().map_err(fail)?;closure.require_origin(association)?;
        self.configuration.verify(key_configuration,assignment,association,checkpoint,trust,time)?;
        let quote=nsm.quote_shadow_recipient(&mut pending,association.startup()).map_err(fail)?;
        association.check_startup().map_err(fail)?;closure.require_origin(association)?;
        self.configuration.verify(key_configuration,assignment,association,checkpoint,trust,time)?;
        let request_sha=pending.request_sha256().to_owned();let salt=pending.nonce();
        let output=pending.provision(quote).map_err(fail)?;
        association.check_startup().map_err(fail)?;closure.require_origin(association)?;
        self.configuration.verify(key_configuration,assignment,association,checkpoint,trust,time)?;
        let peer:[u8;32]=decode(&output["serverEphemeralPublicKey"],32,Some(32))?.as_slice().try_into().map_err(fail)?;
        let nonce:[u8;12]=decode(&output["aeadNonce"],12,Some(12))?.as_slice().try_into().map_err(fail)?;
        let shared=recipient.derive_shared_key(peer).map_err(fail)?;
        let mut aad=mechanism::OUTPUT_DOMAIN.to_vec();
        aad.extend_from_slice(&Sha256Digest::parse(&request_sha)?.raw_bytes()?);
        let salt=hkdf::Salt::new(hkdf::HKDF_SHA256,&salt);let prk=salt.extract(shared.as_ref());
        let info=[aad.as_slice()];let mut key=Zeroizing::new([0u8;32]);
        prk.expand(&info,KeyLength).map_err(fail)?.fill(key.as_mut()).map_err(fail)?;
        let cipher=aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM,key.as_ref()).map_err(fail)?);
        let mut encrypted=decode(&output["ciphertext"],16384,None)?;
        let plaintext=cipher.open_in_place(aead::Nonce::assume_unique_for_key(nonce),aead::Aad::from(&aad),encrypted.as_mut()).map_err(fail)?;
        let (seeds,commitment)=if let Some(authorization)=self.configuration.commitment() {
            let document:CommitmentSeeds=serde_json::from_slice(plaintext).map_err(fail)?;
            let canonical=Zeroizing::new(canonical_json_bytes(&document)?);
            require(canonical.as_slice()==plaintext && document.api_version=="serverware.nativeShadowLocalKeySeeds/v2"
                && document.inventory_sha256==inventory_sha && document.seeds.len()==public_keys.len())?;
            let d=authorization.descriptor();let supplied=&document.request_commitment;
            require(supplied.key_id==d.key_id && supplied.key_epoch==d.key_epoch)?;
            let secret=decode_text(&supplied.secret_base64url,32,Some(32))?;
            for seed in &document.seeds {
                require(decode_text(&seed.seed_base64url,32,Some(32))?.as_slice()!=secret.as_slice())?;
            }
            let owner=commitment::Owner::from_recipient(authorization.clone(),secret.as_slice())?;
            (document.seeds,Some(owner))
        } else {
            let document:Seeds=serde_json::from_slice(plaintext).map_err(fail)?;
            let canonical=Zeroizing::new(canonical_json_bytes(&document)?);
            require(canonical.as_slice()==plaintext && document.api_version=="serverware.nativeShadowLocalKeySeeds/v1"
                && document.inventory_sha256==inventory_sha && document.seeds.len()==public_keys.len())?;
            (document.seeds,None)
        };
        let mut keys=BTreeMap::new();
        for (original,expected) in seeds.iter().zip(&public_keys) {
            require(original.role==expected.role&&original.key_id==expected.key_id)?;
            let bytes=decode_text(&original.seed_base64url,32,Some(32))?;
            let seed=Zeroizing::new(<[u8;32]>::try_from(bytes.as_slice()).map_err(fail)?);
            let key=SigningKey::from_bytes(&seed);let public=key.verifying_key();
            require(URL_SAFE_NO_PAD.encode(public.to_bytes())==expected.public_key_base64url)?;
            keys.insert(expected.role,LocalKey{key,binding:bindings.get(&expected.role).ok_or(ShadowError::SignerBindingMismatch)?.clone(),public:public.to_bytes()});
        }
        association.check_startup().map_err(fail)?;closure.require_origin(association)?;
        self.configuration.verify(key_configuration,assignment,association,checkpoint,trust,time)?;
        Ok((keys,self.configuration,commitment))
    }
}

//! Actual retained public key history, not assignmentRevision renamed as a
//! key epoch. The separately signed coordinator grant assigns the next epoch;
//! every predecessor installation and every retained key remains verifiable.
use super::*;
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct RetainedKey {role:AuthorityRole,key_id:Sha256Digest,key_spki_sha256:Sha256Digest,key_material_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Entry {
    installation_original:String,
    keys:BTreeMap<AuthorityRole,RetainedKey>,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Admission {current_key_epoch:u64,predecessors:Vec<Entry>}
impl Admission {
    pub(super) fn derive(&self,keys:&AdmittedKeys,grant_sha256:&Sha256Digest,
        expected_previous:Option<&Sha256Digest>,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<ProductionCustodyKeyHistoryState,ShadowError>{
        require(self.current_key_epoch>0 && self.predecessors.len()<=16)?;
        let checkpoint=trust.current_checkpoint()?;
        let mut previous:Option<ProductionCustodyGenerationInstallReceiptPayload>=None;
        let mut originals=Vec::new();let mut first=None;let mut total=0usize;
        for entry in &self.predecessors {
            total=total.checked_add(entry.installation_original.len()).ok_or(ShadowError::CounterOverflow)?;
            require(total<=1024*1024 && !entry.installation_original.is_empty() && entry.installation_original.is_ascii())?;
            let wire:SignedEnvelope<ProductionCustodyGenerationInstallReceiptPayload>=guest::exact(entry.installation_original.as_bytes())?;
            let envelope_key=entry.keys.get(&AuthorityRole::CustodyResultEnvelope).ok_or(ShadowError::SignerBindingMismatch)?;
            let verified=verify_envelope(wire.clone(),ExpectedSigner{key_id:&envelope_key.key_id,key_spki_sha256:&envelope_key.key_spki_sha256},
                trust,time,MAX_ENVELOPE_AGE_NANOS)?;
            let payload:&ProductionCustodyGenerationInstallReceiptPayload=verified.payload();
            require(payload==wire.untrusted_payload()
                && entry.keys.keys().copied().collect::<BTreeSet<_>>()==PRODUCTION_CUSTODY_AUTHORITY_ROLES.iter().copied().collect())?;
            let mut admitted=BTreeMap::new();
            for (role,binding) in &entry.keys {
                require(binding.role==*role)?;
                let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(*role),&binding.key_id,&binding.key_spki_sha256)?;
                require(ed25519_public_key_material_sha256(&key)==binding.key_material_sha256)?;
                admitted.insert(*role,ProductionCustodyKeyBinding{role:*role,key_id:binding.key_id.clone(),
                    key_spki_sha256:binding.key_spki_sha256.clone(),key_material_sha256:binding.key_material_sha256.clone()});
            }
            require(production_custody_key_set_root(&admitted)?==payload.key_history.current_key_set_root_sha256)?;
            require(wire.untrusted_signer()==(&envelope_key.key_id,&envelope_key.key_spki_sha256))?;
            if let Some(prior)=&previous {
                require(payload.previous_configuration_binding_sha256.as_ref()==Some(&prior.successor_configuration_binding_sha256)
                    && payload.key_history.current_key_epoch==prior.key_history.current_key_epoch.checked_add(1).ok_or(ShadowError::CounterOverflow)?
                    && payload.key_history.predecessor_historical_key_chain_root_sha256.as_ref()==Some(&prior.key_history.historical_key_chain_root_sha256)
                    && payload.key_history.oldest_retained_key_epoch==prior.key_history.oldest_retained_key_epoch)?;
            } else {
                require(payload.key_history.current_key_epoch==payload.key_history.oldest_retained_key_epoch
                    && payload.key_history.predecessor_historical_key_chain_root_sha256.is_none())?;
                first=Some(payload.key_history.current_key_epoch);
            }
            originals.push(Sha256Digest::compute(entry.installation_original.as_bytes()));previous=Some(payload.clone());
        }
        match (&previous,expected_previous) {
            (None,None)=>require(self.current_key_epoch==1)?,
            (Some(prior),Some(expected))=>require(&prior.successor_configuration_binding_sha256==expected
                && self.current_key_epoch==prior.key_history.current_key_epoch.checked_add(1).ok_or(ShadowError::CounterOverflow)?)?,
            _=>return Err(ShadowError::BindingDrift),
        }
        let current=production_custody_key_set_root(&full_bindings(&keys.assignment)?)?;
        let predecessor=previous.as_ref().map(|p|p.key_history.historical_key_chain_root_sha256.clone());
        let history=ProductionCustodyKeyHistoryState{current_key_epoch:self.current_key_epoch,
            oldest_retained_key_epoch:first.unwrap_or(self.current_key_epoch),current_key_set_root_sha256:current.clone(),
            predecessor_historical_key_chain_root_sha256:predecessor.clone(),
            historical_key_chain_root_sha256:hash_domain_frames(b"serverware.nativeGenerationKeyHistory/v1",
                &[&canonical_json_bytes(&(self.current_key_epoch,&current,&predecessor,&originals,grant_sha256))?]),
            rotation_continuity_receipt_sha256:grant_sha256.clone(),trust_checkpoint_sha256:checkpoint.checkpoint_id.clone(),
            revocation_generation:checkpoint.revocation_generation,revocation_root_sha256:checkpoint.revocation_root_sha256.clone()};
        require(trust.current_checkpoint()?==checkpoint)?;Ok(history)
    }
}

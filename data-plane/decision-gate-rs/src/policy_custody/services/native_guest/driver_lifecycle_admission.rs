//! One actual constructed census and one independently signed admission.
//! This never certifies installation, business effects, or completed reaping.
use super::*;

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Command {api_version:String,operation:String,original:Option<String>}

impl Owner {
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn constructed_selected(&self)->bool{self.configuration.constructed_selected()}
    pub(super) fn check_constructed(&self)->Result<(),ShadowError>{
        self.check()?;require(self.configuration.constructed_selected())?;
        let raw=self.constructed_census.as_ref().ok_or(ShadowError::BindingDrift)?;
        let original:Observation=exact(raw)?;
        self.descriptors.as_ref().ok_or(ShadowError::BindingDrift)?.check()?;
        let actual:Vec<_>=census::descendants(self.parent.original.process_id)?.into_iter().map(|v|v.original).collect();
        require(actual==original.descendants && original.parent==self.parent.original)
    }
    fn capture_constructed(&mut self,child:&Child,observation:&driver_identity::Observation,scope:&[u8])
        ->Result<Vec<u8>,ShadowError>{
        self.check()?;require(self.constructed_census.is_none() && now()?<self.startup)?;
        let (pid,start,pidfd)=child.lifecycle_identity()?;
        require(pid==observation.process_id && start==observation.driver.process_start_time_ticks)?;
        let driver=census::HeldProcess::open(pid)?;
        require(inode(pidfd)?==(driver.original.pidfd_device,driver.original.pidfd_inode))?;
        if self.descriptors.is_none(){self.descriptors=Some(census::Descriptors::capture(&driver)?);}
        let descriptors=self.descriptors.as_ref().ok_or(ShadowError::BindingDrift)?;descriptors.check()?;
        let before:Vec<_>=census::descendants(self.parent.original.process_id)?.into_iter().map(|v|v.original).collect();
        let after:Vec<_>=census::descendants(self.parent.original.process_id)?.into_iter().map(|v|v.original).collect();
        require(before==after && before.iter().any(|v|v==&driver.original))?;
        driver.check()?;descriptors.check()?;
        let raw=canonical_json_bytes(&Observation{api_version:"serverware.nativeShadowDriverLifecycleObservation/v1".into(),
            configuration_sha256:self.configuration_sha256.clone(),window_sha256:self.window_sha256.clone(),
            bootstrap_observation_sha256:Sha256Digest::compute(&canonical_json_bytes(observation)?),
            scope_sha256:Sha256Digest::compute(scope),phase:"constructed-driver-subtree".into(),
            parent:self.parent.original.clone(),parent_executable_sha256:self.executable_sha256.clone(),
            pid_namespace_sha256:self.pid_namespace_sha256.clone(),driver:driver.original,descendants:before,
            descriptors:descriptors.originals.clone(),descriptor_set_sha256:Sha256Digest::compute(&canonical_json_bytes(&descriptors.originals)?),
            observed_at_boottime_ns:now()?.to_string(),lifetime_deadline_boottime_ns:self.lifetime.to_string()})?;
        require(raw.len()<=48*1024)?;self.constructed_census=Some(raw.clone());self.check_constructed()?;Ok(raw)
    }
    /// The caller is authenticated by the real clone parent's existing control
    /// owner. No request supplies a PID, path, descriptor list, or measurement.
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn constructed_control(&mut self,raw:&[u8],child:&Child,observation:&driver_identity::Observation,
        scope:&[u8])->Result<(Vec<u8>,Option<OwnedFd>),ShadowError>{
        self.check()?;require(self.configuration.constructed_selected() && self.bound && self.listening && now()?<self.startup)?;
        let command:Command=exact(raw)?;
        require(command.api_version=="serverware.nativeShadowConstructedDriverControl/v1")?;
        if command.operation=="export" {
            require(command.original.is_none() && !self.constructed_exported && self.constructed_admission.is_none())?;
            self.constructed_exported=true; // no second export after any attempt
            let census=self.capture_constructed(child,observation,scope)?;
            let (notice,_,file)=self.facade.as_ref().ok_or(ShadowError::BindingDrift)?.constructed_public()?;
            let reply=canonical_json_bytes(&serde_json::json!({"apiVersion":"serverware.nativeShadowConstructedDriverExport/v1",
                "censusOriginal":String::from_utf8(census).map_err(fail)?,
                "publicAdmissionNoticeOriginal":String::from_utf8(notice).map_err(fail)?}))?;
            require(reply.len()<=wire::MAX_FRAME)?;return Ok((reply,Some(file)));
        }
        require(command.operation=="admit" && self.constructed_exported && self.constructed_admission.is_none())?;
        let original=command.original.ok_or(ShadowError::BindingDrift)?;
        require(original.is_ascii() && !original.is_empty() && original.len()<=16384)?;
        let grant:wire::ConstructedAdmission=exact(original.as_bytes())?;
        let p=&grant.payload;let authority=self.configuration.constructed_admission_authority.as_ref().ok_or(ShadowError::BindingDrift)?;
        authority.key()?.verify_strict(&signature_preimage(wire::CONSTRUCTED_DOMAIN,&canonical_json_bytes(p)?),
            &ed25519_dalek::Signature::from_bytes(&grant.signature.decode()?)).map_err(|_|ShadowError::SignatureInvalid)?;
        self.check_constructed()?;
        require(grant.bootstrap_admission_original.is_ascii() && grant.bootstrap_admission_original.len()<=8192
            && p.bootstrap_admission_sha256==Sha256Digest::compute(grant.bootstrap_admission_original.as_bytes()))?;
        let early:wire::BootstrapAdmission=exact(grant.bootstrap_admission_original.as_bytes())?;let e=&early.payload;
        authority.key()?.verify_strict(&signature_preimage(wire::BOOTSTRAP_ADMISSION_DOMAIN,&canonical_json_bytes(e)?),
            &ed25519_dalek::Signature::from_bytes(&early.signature.decode()?)).map_err(|_|ShadowError::SignatureInvalid)?;
        require(e.api_version=="serverware.nativeShadowBootstrapDriverAdmission/v1" && e.purpose=="native-driver-bootstrap-admission"
            && e.configuration_sha256==self.configuration_sha256 && e.window_sha256==self.window_sha256
            && e.bootstrap_observation_original.as_bytes()==canonical_json_bytes(observation)? && e.parent==self.parent.original
            && e.parent_executable_sha256==self.executable_sha256 && e.pid_namespace_sha256==self.pid_namespace_sha256
            && e.signing_key_id==authority.key_id && e.signing_key_spki_sha256==authority.key_spki_sha256
            && e.startup_deadline_boottime_ns==self.startup.to_string() && e.lifetime_deadline_boottime_ns==self.lifetime.to_string()
            && e.issued_at_unix_nanos<=p.issued_at_unix_nanos && p.expires_at_unix_nanos<=e.expires_at_unix_nanos
            && e.expires_at_unix_nanos.checked_sub(e.issued_at_unix_nanos).is_some_and(|v|v>0 && v<=30_000_000_000))?;
        let (_,public,_)=self.facade.as_ref().ok_or(ShadowError::BindingDrift)?.constructed_public()?;
        let public_original:wire::PublicAdmission=exact(&public)?;
        let bundle:serde_json::Value=exact(public_original.phase_bundle_original.as_bytes())?;
        let grants=bundle.get("generationOriginals").and_then(serde_json::Value::as_object).ok_or(ShadowError::BindingDrift)?;
        require(grants.len()==5)?;
        for raw in grants.values(){let original:serde_json::Value=exact(raw.as_str().ok_or(ShadowError::BindingDrift)?.as_bytes())?;
            require(original.get("payload").and_then(|v|v.get("scope")).and_then(|v|v.get("driverGenerationReceiptSha256"))
                ==Some(&serde_json::to_value(&p.bootstrap_admission_sha256).map_err(fail)?))?;}
        let evidence:serde_json::Value=exact(public_original.evidence_original.as_bytes())?;
        let statement=evidence.get("statement").ok_or(ShadowError::BindingDrift)?;
        let authorization:serde_json::Value=exact(public_original.key_configuration_original.as_bytes())?;
        let key_payload=authorization.get("authorization").and_then(|v|v.get("payload")).ok_or(ShadowError::BindingDrift)?;
        let digest=|value:&serde_json::Value,name:&str|->Result<Sha256Digest,ShadowError>{
            serde_json::from_value(value.get(name).ok_or(ShadowError::BindingDrift)?.clone()).map_err(fail)};
        require(p.api_version=="serverware.nativeShadowConstructedDriverAdmission/v1" && p.purpose=="constructed-native-driver-admission"
            && p.configuration_sha256==self.configuration_sha256 && p.window_sha256==self.window_sha256
            && p.bootstrap_observation_sha256==Sha256Digest::compute(&canonical_json_bytes(observation)?)
            && p.phase_scope_sha256==Sha256Digest::compute(scope)
            && p.census_sha256==Sha256Digest::compute(self.constructed_census.as_ref().ok_or(ShadowError::BindingDrift)?)
            && p.public_admission_sha256==Sha256Digest::compute(&public)
            && p.kernel_driver_identity_sha256==observation.driver.identity_sha256
            && p.production_configuration_binding_sha256==digest(statement,"productionConfigurationBindingSha256")?
            && p.assignment_id==digest(statement,"assignmentId")? && p.assignment_payload_sha256==digest(statement,"assignmentPayloadSha256")?
            && Some(p.assignment_revision)==statement.get("assignmentRevision").and_then(serde_json::Value::as_u64)
            && p.trust_checkpoint_id==digest(key_payload,"trustCheckpointId")?
            && p.revocation_generation==key_payload.get("revocationGeneration").and_then(serde_json::Value::as_u64).ok_or(ShadowError::BindingDrift)?
            && p.revocation_root_sha256==digest(key_payload,"revocationRootSha256")?
            && p.signing_key_id==authority.key_id && p.signing_key_spki_sha256==authority.key_spki_sha256
            && p.signing_key_id==digest(key_payload,"signingKeyId")? && p.signing_key_spki_sha256==digest(key_payload,"signingKeySpkiSha256")?
            && p.startup_deadline_boottime_ns==self.startup.to_string() && p.lifetime_deadline_boottime_ns==self.lifetime.to_string())?;
        validate_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,p.issued_at_unix_nanos,MAX_ENVELOPE_AGE_NANOS)?;
        require(p.issued_at_unix_nanos>=key_payload.get("issuedAtUnixNanos").and_then(serde_json::Value::as_i64).ok_or(ShadowError::BindingDrift)?
            && p.expires_at_unix_nanos<=key_payload.get("expiresAtUnixNanos").and_then(serde_json::Value::as_i64).ok_or(ShadowError::BindingDrift)?)?;
        let reply=canonical_json_bytes(&serde_json::json!({"apiVersion":"serverware.nativeShadowConstructedDriverRetained/v1",
            "admissionSha256":Sha256Digest::compute(original.as_bytes()),"censusSha256":p.census_sha256}))?;
        self.constructed_admission=Some(original.into_bytes());self.check_constructed()?;Ok((reply,None))
    }
}

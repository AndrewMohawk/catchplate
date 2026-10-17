//! Fixed succession helper protocol, retaining one full historical inventory.
//! Only the actual definite CONTACT/CLAIM/CAPTURE phase permits a fixed relay;
//! every response returns to the same private owner before any secret opens.
use super::*;
use crate::native_oauth_browser_v1::Accepted;
use crate::native_oauth_succession_v1::{self as wire, BrowserTls, Configuration, Prepared, Reply};
use crate::native_upstream_relays_v1::NativeUpstreamRelaysV1;

impl Owner {
    pub fn configure_succession(&mut self, config:Configuration, ingress:Arc<BrowserTls>,
        identity:&mut EnclaveRuntimeIdentityV1, boot:&str, key:&str, cp_key:&str, binary:&str,
        deadline:u64)->Result<(),String>{
        let result=(||{
            config.validate()?; self.check(deadline)?; identity.verify_browser_ingress(&ingress,deadline)?;
            ensure(self.static_configuration.is_none() && self.succession_configuration.is_none() && self.reconnect_configuration.is_none() && self.setup_configuration.is_none()
                && self.exchange_configuration.is_none() && !self.service_phase_closed
                && self.historical_configuration_sha256.is_some() && self.historical_original.is_some()
                && config.callback_origin==ingress.origin()
                && Sha256::digest(identity.ca_certificate_der()).as_slice()==self.owner_ca,
                "succession requires its original cold CA and exclusive browser owner")?;
            let mut scope=identity.refresh_scope(deadline)?;
            let fields=scope.as_object_mut().ok_or("succession native identity")?;
            fields.insert("holderId".to_owned(),json!(crate::native_currentness_v1::holder_id(boot,key)?));
            fields.insert("bootId".to_owned(),json!(boot)); fields.insert("keyId".to_owned(),json!(key));
            fields.insert("controlPlaneResponseSigningKeyId".to_owned(),json!(cp_key));
            fields.insert("expectedBinaryDigest".to_owned(),json!(binary));
            let mut value=serde_json::to_value(&config).map_err(|_|"succession configuration encoding")?;
            let object=value.as_object_mut().ok_or("succession configuration object")?;
            object.remove("browserVsockPort"); object.insert("identity".to_owned(),scope);
            object.insert("ingressLeafCertificateSha256".to_owned(),json!(ingress.certificate_sha));
            object.insert("ingressLeafSpkiSha256".to_owned(),json!(ingress.spki_sha));
            let raw=canonical_ascii_bytes(&json!({"apiVersion":wire::CHANNEL,"phase":"configure","configuration":value}))?;
            ensure(raw.len()<=MAX_FRAME,"succession complete configuration frame bound")?;
            let response=document(&self.process.exchange(&raw,deadline)?,4096)?;
            wire::fields(&response,&["apiVersion","phase"])?;
            ensure(response["apiVersion"]==wire::CHANNEL && response["phase"]=="configured","succession private cold admission failed")?;
            self.succession_configuration=Some((config,ingress)); self.check(deadline)
        })();
        if result.is_err(){self.poisoned=true;self.process.terminate();} result
    }

    pub fn succession_browser(&mut self, request:&Accepted, relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        let (_,ingress)=self.succession_configuration.as_ref().ok_or("succession helper is not configured")?;
        request.verify_ingress(ingress)?;
        // Begin and callback can only prepare a controlled operation. Neither
        // command itself carries the committed claim needed for provider TLS.
        self.succession_request(request.succession_command()?,None,request.deadline(),relays)
    }

    pub fn succession_receipt(&mut self, originals:Value, prepared:&Prepared, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        prepared.verify_ingress(&self.succession_configuration.as_ref().ok_or("succession helper is not configured")?.1,deadline)?;
        wire::fields(&originals,&["requestOriginal","responseOriginal"])?;
        let purpose=match prepared.operation(){
            "oauth.measured-succession.contact"=>Some("retirement"),
            "oauth.measured-succession.claim"=>Some("token"),
            "oauth.measured-succession.capture"=>Some("identity"),
            "oauth.measured-succession.inspect"|"oauth.measured-succession.material-claim"|"oauth.measured-succession.finish"
                |"oauth.measured-succession.recover"|"oauth.measured-succession.prepare"|"oauth.measured-succession.stage"|"oauth.measured-succession.cancel"=>None,
            _=>return Err("succession receipt purpose differs".to_owned()),
        };
        let contact=purpose.map(|purpose|prepared.provider().map(|provider|(provider,purpose))).transpose()?;
        self.succession_request(json!({"apiVersion":wire::CHANNEL,"phase":"receipt","originals":originals}),contact,deadline,relays)
    }

    pub fn recover_succession(&mut self, id:&str, originals:Value, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        wire::fields(&originals,&["apiVersion","okForAction","journalOriginal","scopeOriginal","materialOriginals","attemptOriginals",
            "exchangeOriginal","custodyOriginal","candidateOriginal"])?;
        ensure(originals["apiVersion"]=="catchplate.nativeOAuthSuccessionRecoveryOriginalResponse/v1"
            && originals["okForAction"]==false,"succession recovery acquisition is not data-only")?;
        ensure(self.succession_configuration.as_ref().is_some_and(|(config,_)|config.recovery_targets.iter().any(|item|item==id)),
            "succession recovery target is not cold-selected")?;
        self.succession_request(json!({"apiVersion":wire::CHANNEL,"phase":"recover","exchangeId":id,
            "originals":originals,"deadlineBoottimeNs":deadline}),None,deadline,relays)
    }

    fn succession_request(&mut self, request:Value, contact:Option<(&str,&str)>, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        let result=(||{
            self.check(deadline)?;
            let (config,ingress)=self.succession_configuration.as_ref().ok_or("succession helper is not configured")?.clone();
            ingress.check(deadline)?;
            let raw=canonical_ascii_bytes(&request)?;
            ensure(raw.len()<=MAX_FRAME,"succession complete command frame bound")?;
            let mut response=document(&self.process.exchange(&raw,deadline)?,MAX_FRAME)?;
            let mut transport:Option<VsockStreamV1>=None;
            let mut sequence=0u64; let mut total=0usize;
            while response["apiVersion"]=="catchplate.nativeOAuthSuccessionTls/v1" {
                wire::fields(&response,&["apiVersion","providerId","purpose","sequence","ciphertext","read"])?;
                let (provider,purpose)=contact.ok_or("succession TLS requires its actual committed receipt phase")?;
                ensure(matches!(purpose,"retirement"|"token"|"identity") && response["providerId"]==provider
                    && response["purpose"]==purpose && config.applications.contains_key(provider),"succession fixed TLS scope changed")?;
                sequence+=1;
                ensure(sequence<=512 && response["sequence"].as_u64()==Some(sequence),"succession TLS sequence differs")?;
                let read=response["read"].as_bool().ok_or("succession TLS read flag")?;
                let output=if response["ciphertext"].is_null(){Vec::new()}else{decoded(&response["ciphertext"],65536,None)?};
                total=total.checked_add(output.len()).ok_or("succession TLS aggregate overflow")?;
                ensure(total<=512*1024 && (!read || total<512*1024),"succession TLS aggregate bound")?;
                // At most one socket per receipt, never reopened after EOF or
                // any transport uncertainty. CAPTURE separates the two contacts.
                if transport.is_none(){transport=Some(if purpose=="retirement"{relays.cleanup_stream(provider,deadline)?}
                    else{relays.exchange_stream(provider,purpose,deadline)?});}
                let stream=transport.as_mut().ok_or("succession TLS transport absent")?;
                stream.verify_connected_original(deadline).map_err(|_|"succession TLS original changed")?;
                if !output.is_empty(){stream.write_all(&output).map_err(|_|"succession TLS write uncertain")?;}
                let mut input=vec![0u8;65536.min(512*1024-total)];
                let size=if read{stream.read(&mut input).map_err(|_|"succession TLS read uncertain")?}else{0}; input.truncate(size);
                total=total.checked_add(size).ok_or("succession TLS aggregate overflow")?;
                self.check(deadline)?;
                response=document(&self.process.exchange(&canonical_ascii_bytes(&json!({"apiVersion":"catchplate.nativeOAuthSuccessionTls/v1",
                    "sequence":sequence,"ciphertext":if input.is_empty(){Value::Null}else{json!(encoded(&input))},
                    "eof":read&&size==0}))?,deadline)?,MAX_FRAME)?;
                if read && size==0 {
                    ensure(response["apiVersion"]!="catchplate.nativeOAuthSuccessionTls/v1","succession TLS cannot continue after EOF")?;
                }
            }
            self.check(deadline)?; ingress.check(deadline)?; Reply::parse(response,&config,&ingress)
        })();
        if result.is_err(){self.poisoned=true;self.process.terminate();} result
    }
}

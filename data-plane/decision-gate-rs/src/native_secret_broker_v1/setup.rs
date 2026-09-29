//! Sealed browser requests and actual controlled receipts enter the same
//! private helper. No plaintext code, cookie, verifier or token leaves the
//! native process closure, and no caller-supplied TLS verdict is accepted.
use super::*;
use crate::native_oauth_setup_v1::{self as wire, BrowserTls, Configuration, Prepared, Reply};
use crate::native_oauth_browser_v1::Accepted;
use crate::native_upstream_relays_v1::NativeUpstreamRelaysV1;

impl Owner {
    pub fn configure_setup(&mut self, config: Configuration, ingress: Arc<BrowserTls>,
        identity: &mut EnclaveRuntimeIdentityV1, boot: &str, key: &str, cp_key: &str, binary: &str,
        deadline: u64) -> Result<(),String> {
        let result=(|| {
            config.validate()?; self.check(deadline)?; identity.verify_browser_ingress(&ingress,deadline)?;
            ensure(self.setup_configuration.is_none() && self.exchange_configuration.is_none() && self.reconnect_configuration.is_none() && !self.service_phase_closed
                && config.callback_origin==ingress.origin() && Sha256::digest(identity.ca_certificate_der()).as_slice()==self.owner_ca,
                "Setup helper requires its same cold CA and browser owner")?;
            let mut scope=identity.refresh_scope(deadline)?;
            let fields=scope.as_object_mut().ok_or("Setup native identity")?;
            fields.insert("holderId".to_owned(),json!(crate::native_currentness_v1::holder_id(boot,key)?));
            fields.insert("bootId".to_owned(),json!(boot)); fields.insert("keyId".to_owned(),json!(key));
            fields.insert("controlPlaneResponseSigningKeyId".to_owned(),json!(cp_key));
            fields.insert("expectedBinaryDigest".to_owned(),json!(binary));
            let mut value=serde_json::to_value(&config).map_err(|_|"Setup cold configuration encoding")?;
            let object=value.as_object_mut().ok_or("Setup cold configuration object")?;
            object.remove("browserVsockPort"); object.insert("identity".to_owned(),scope);
            object.insert("ingressLeafCertificateSha256".to_owned(),json!(ingress.certificate_sha));
            object.insert("ingressLeafSpkiSha256".to_owned(),json!(ingress.spki_sha));
            let response=document(&self.process.exchange(&canonical_ascii_bytes(&json!({"apiVersion":wire::CHANNEL,
                "phase":"configure","configuration":value}))?,deadline)?,4096)?;
            wire::fields(&response,&["apiVersion","phase"])?;
            ensure(response["apiVersion"]==wire::CHANNEL && response["phase"]=="configured","Setup helper cold admission failed")?;
            self.setup_configuration=Some((config,ingress)); self.check(deadline)
        })();
        if result.is_err(){self.poisoned=true;self.process.terminate();} result
    }

    pub fn setup_browser(&mut self, request: &Accepted, relays: &NativeUpstreamRelaysV1) -> Result<Reply,String> {
        let (_, ingress) = self.setup_configuration.as_ref().ok_or("Setup helper is not configured")?;
        request.verify_ingress(ingress)?;
        self.setup_request(request.setup_command()?,None,request.deadline(),relays)
    }

    pub fn setup_draft_delivered(&mut self, prepared: &Prepared, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        prepared.verify_ingress(&self.setup_configuration.as_ref().ok_or("Setup helper is not configured")?.1, deadline)?;
        ensure(prepared.operation()=="oauth.measured-setup.prepare","only original draft can receive a native cookie")?;
        self.setup_request(json!({"apiVersion":wire::CHANNEL,"phase":"draft-delivered","exchangeId":prepared.exchange_id()?}),
            Some(prepared.provider()?),deadline,relays)
    }

    pub fn setup_receipt(&mut self, originals:Value, prepared:&Prepared, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        prepared.verify_ingress(&self.setup_configuration.as_ref().ok_or("Setup helper is not configured")?.1, deadline)?;
        wire::fields(&originals,&["requestOriginal","responseOriginal"])?;
        self.setup_request(json!({"apiVersion":wire::CHANNEL,"phase":"receipt","originals":originals}),
            Some(prepared.provider()?),deadline,relays)
    }

    pub fn recover_setup(&mut self, id:&str, originals:Value, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        wire::fields(&originals,&["apiVersion","okForAction","exchangeOriginal","custodyOriginal","setupOriginal"])?;
        ensure(originals["apiVersion"]=="serverware.nativeOAuthSetupRecoveryOriginalResponse/v1" && originals["okForAction"]==false,
            "Setup recovery acquisition is not data-only")?;
        ensure(self.setup_configuration.as_ref().is_some_and(|(config,_)|config.recovery_targets.iter().any(|item|item==id)),
            "Setup recovery target is not cold-selected")?;
        self.setup_request(json!({"apiVersion":wire::CHANNEL,"phase":"recover","exchangeId":id,
            "exchangeOriginal":originals["exchangeOriginal"],"custodyOriginal":originals["custodyOriginal"],"setupOriginal":originals["setupOriginal"],"deadlineBoottimeNs":deadline}),None,deadline,relays)
    }

    fn setup_request(&mut self, request:Value, provider:Option<&str>, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        let result=(||{
            self.check(deadline)?;
            let (config,ingress)=self.setup_configuration.as_ref().ok_or("Setup helper is not configured")?.clone();
            ingress.check(deadline)?;
            let mut response=document(&self.process.exchange(&canonical_ascii_bytes(&request)?,deadline)?,MAX_FRAME)?;
            let mut transport:Option<VsockStreamV1>=None;
            let mut purpose:Option<String>=None; let mut sequence=0u64; let mut total=0usize;
            while response["apiVersion"]=="serverware.nativeOAuthSetupExchangeTls/v1" {
                wire::fields(&response,&["apiVersion","providerId","purpose","sequence","ciphertext","read"])?;
                let actual_provider=provider.ok_or("Setup TLS requires an actual prior measured preparation")?;
                let next=response["purpose"].as_str().ok_or("Setup TLS purpose")?;
                ensure(matches!(next,"token"|"identity") && response["providerId"]==actual_provider
                    && config.applications.contains_key(actual_provider),"Setup TLS fixed scope changed")?;
                // Each receipt can trigger only one fixed provider contact.
                // Capture acknowledgement separates token POST and identity GET.
                if let Some(prior)=&purpose {ensure(prior==next,"Setup TLS cannot switch purpose within one receipt")?;}
                else {purpose=Some(next.to_owned());}
                sequence+=1;
                ensure(sequence<=512 && response["sequence"].as_u64()==Some(sequence),"Setup TLS sequence differs")?;
                let read=response["read"].as_bool().ok_or("Setup TLS read flag")?;
                let output=if response["ciphertext"].is_null(){Vec::new()}else{decoded(&response["ciphertext"],65536,None)?};
                if transport.is_none(){transport=Some(relays.exchange_stream(actual_provider,next,deadline)?);}
                let stream=transport.as_mut().ok_or("Setup TLS transport absent")?;
                stream.verify_connected_original(deadline).map_err(|_|"Setup TLS transport changed")?;
                if !output.is_empty(){stream.write_all(&output).map_err(|_|"Setup TLS transport write uncertain")?;}
                let mut input=vec![0u8;65536];
                let size=if read{stream.read(&mut input).map_err(|_|"Setup TLS transport read uncertain")?}else{0}; input.truncate(size);
                total=total.checked_add(output.len()+input.len()).ok_or("Setup TLS aggregate overflow")?;
                ensure(total<=512*1024,"Setup TLS aggregate bound")?; self.check(deadline)?;
                response=document(&self.process.exchange(&canonical_ascii_bytes(&json!({"apiVersion":"serverware.nativeOAuthSetupExchangeTls/v1",
                    "sequence":sequence,"ciphertext":if input.is_empty(){Value::Null}else{json!(encoded(&input))},"eof":read&&size==0}))?,deadline)?,MAX_FRAME)?;
            }
            self.check(deadline)?; Reply::parse(response,&config,&ingress)
        })();
        if result.is_err(){self.poisoned=true;self.process.terminate();} result
    }
}

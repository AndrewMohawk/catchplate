//! A reconnect-only private helper protocol. The retained browser TLS owner and
//! measured preparation select the fixed provider stream; no parent plaintext,
//! caller-selected destination, permission conversion, or uncertain POST retry.
use super::*;
use crate::native_oauth_browser_v1::Accepted;
use crate::native_oauth_reconnect_v1::{self as wire, BrowserTls, Configuration, Prepared, Reply};
use crate::native_upstream_relays_v1::NativeUpstreamRelaysV1;

impl Owner {
    pub fn configure_reconnect(&mut self, config:Configuration, ingress:Arc<BrowserTls>,
        identity:&mut EnclaveRuntimeIdentityV1, boot:&str, key:&str, cp_key:&str, binary:&str,
        deadline:u64)->Result<(),String>{
        let result=(||{
            config.validate()?; self.check(deadline)?; identity.verify_browser_ingress(&ingress,deadline)?;
            ensure(self.static_configuration.is_none() && self.reconnect_configuration.is_none() && self.succession_configuration.is_none() && self.setup_configuration.is_none()
                && self.exchange_configuration.is_none() && !self.service_phase_closed
                && config.callback_origin==ingress.origin()
                && Sha256::digest(identity.ca_certificate_der()).as_slice()==self.owner_ca,
                "reconnect requires its original cold CA and exclusive browser owner")?;
            let mut scope=identity.refresh_scope(deadline)?;
            let fields=scope.as_object_mut().ok_or("reconnect native identity")?;
            fields.insert("holderId".to_owned(),json!(crate::native_currentness_v1::holder_id(boot,key)?));
            fields.insert("bootId".to_owned(),json!(boot)); fields.insert("keyId".to_owned(),json!(key));
            fields.insert("controlPlaneResponseSigningKeyId".to_owned(),json!(cp_key));
            fields.insert("expectedBinaryDigest".to_owned(),json!(binary));
            let mut value=serde_json::to_value(&config).map_err(|_|"reconnect configuration encoding")?;
            let object=value.as_object_mut().ok_or("reconnect configuration object")?;
            object.remove("browserVsockPort"); object.insert("identity".to_owned(),scope);
            object.insert("ingressLeafCertificateSha256".to_owned(),json!(ingress.certificate_sha));
            object.insert("ingressLeafSpkiSha256".to_owned(),json!(ingress.spki_sha));
            let raw=canonical_ascii_bytes(&json!({"apiVersion":wire::CHANNEL,"phase":"configure","configuration":value}))?;
            ensure(raw.len()<=MAX_FRAME,"reconnect complete configuration frame bound")?;
            let response=document(&self.process.exchange(&raw,deadline)?,4096)?;
            wire::fields(&response,&["apiVersion","phase"])?;
            ensure(response["apiVersion"]==wire::CHANNEL && response["phase"]=="configured","reconnect private cold admission failed")?;
            self.reconnect_configuration=Some((config,ingress)); self.check(deadline)
        })();
        if result.is_err(){self.poisoned=true;self.process.terminate();} result
    }

    pub fn reconnect_browser(&mut self, request:&Accepted, relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        let (_,ingress)=self.reconnect_configuration.as_ref().ok_or("reconnect helper is not configured")?;
        request.verify_ingress(ingress)?;
        // Begin and callback can only prepare a controlled operation. Neither
        // command itself carries the committed claim needed for provider TLS.
        self.reconnect_request(request.reconnect_command()?,None,request.deadline(),relays)
    }

    pub fn reconnect_receipt(&mut self, originals:Value, prepared:&Prepared, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        prepared.verify_ingress(&self.reconnect_configuration.as_ref().ok_or("reconnect helper is not configured")?.1,deadline)?;
        wire::fields(&originals,&["requestOriginal","responseOriginal"])?;
        let purpose=match prepared.operation(){
            "oauth.measured-reconnect.claim"=>Some("token"),
            "oauth.measured-reconnect.capture"|"oauth.measured-reconnect.recover"=>Some("identity"),
            "oauth.measured-reconnect.prepare"|"oauth.measured-reconnect.stage"|"oauth.measured-reconnect.cancel"=>None,
            _=>return Err("reconnect receipt purpose differs".to_owned()),
        };
        let contact=purpose.map(|purpose|prepared.provider().map(|provider|(provider,purpose))).transpose()?;
        self.reconnect_request(json!({"apiVersion":wire::CHANNEL,"phase":"receipt","originals":originals}),contact,deadline,relays)
    }

    pub fn recover_reconnect(&mut self, id:&str, originals:Value, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        wire::fields(&originals,&["apiVersion","okForAction","journalOriginal","exchangeOriginal","custodyOriginal","candidateOriginal"])?;
        ensure(originals["apiVersion"]=="catchplate.nativeOAuthReconnectRecoveryOriginalResponse/v1"
            && originals["okForAction"]==false,"reconnect recovery acquisition is not data-only")?;
        ensure(self.reconnect_configuration.as_ref().is_some_and(|(config,_)|config.recovery_targets.iter().any(|item|item==id)),
            "reconnect recovery target is not cold-selected")?;
        self.reconnect_request(json!({"apiVersion":wire::CHANNEL,"phase":"recover","exchangeId":id,
            "journalOriginal":originals["journalOriginal"],"exchangeOriginal":originals["exchangeOriginal"],
            "custodyOriginal":originals["custodyOriginal"],"candidateOriginal":originals["candidateOriginal"],
            "deadlineBoottimeNs":deadline}),None,deadline,relays)
    }

    fn reconnect_request(&mut self, request:Value, contact:Option<(&str,&str)>, deadline:u64,
        relays:&NativeUpstreamRelaysV1)->Result<Reply,String>{
        let result=(||{
            self.check(deadline)?;
            let (config,ingress)=self.reconnect_configuration.as_ref().ok_or("reconnect helper is not configured")?.clone();
            ingress.check(deadline)?;
            let raw=canonical_ascii_bytes(&request)?;
            ensure(raw.len()<=MAX_FRAME,"reconnect complete command frame bound")?;
            let mut response=document(&self.process.exchange(&raw,deadline)?,MAX_FRAME)?;
            let mut transport:Option<VsockStreamV1>=None;
            let mut sequence=0u64; let mut total=0usize;
            while response["apiVersion"]=="catchplate.nativeOAuthReconnectTls/v1" {
                wire::fields(&response,&["apiVersion","providerId","purpose","sequence","ciphertext","read"])?;
                let (provider,purpose)=contact.ok_or("reconnect TLS requires its actual committed receipt phase")?;
                ensure(matches!(purpose,"token"|"identity") && response["providerId"]==provider
                    && response["purpose"]==purpose && config.applications.contains_key(provider),"reconnect fixed TLS scope changed")?;
                sequence+=1;
                ensure(sequence<=512 && response["sequence"].as_u64()==Some(sequence),"reconnect TLS sequence differs")?;
                let read=response["read"].as_bool().ok_or("reconnect TLS read flag")?;
                let output=if response["ciphertext"].is_null(){Vec::new()}else{decoded(&response["ciphertext"],65536,None)?};
                total=total.checked_add(output.len()).ok_or("reconnect TLS aggregate overflow")?;
                ensure(total<=512*1024 && (!read || total<512*1024),"reconnect TLS aggregate bound")?;
                // At most one socket per receipt, never reopened after EOF or
                // any transport uncertainty. CAPTURE separates the two contacts.
                if transport.is_none(){transport=Some(relays.exchange_stream(provider,purpose,deadline)?);}
                let stream=transport.as_mut().ok_or("reconnect TLS transport absent")?;
                stream.verify_connected_original(deadline).map_err(|_|"reconnect TLS original changed")?;
                if !output.is_empty(){stream.write_all(&output).map_err(|_|"reconnect TLS write uncertain")?;}
                let mut input=vec![0u8;65536.min(512*1024-total)];
                let size=if read{stream.read(&mut input).map_err(|_|"reconnect TLS read uncertain")?}else{0}; input.truncate(size);
                total=total.checked_add(size).ok_or("reconnect TLS aggregate overflow")?;
                self.check(deadline)?;
                response=document(&self.process.exchange(&canonical_ascii_bytes(&json!({"apiVersion":"catchplate.nativeOAuthReconnectTls/v1",
                    "sequence":sequence,"ciphertext":if input.is_empty(){Value::Null}else{json!(encoded(&input))},
                    "eof":read&&size==0}))?,deadline)?,MAX_FRAME)?;
                if read && size==0 {
                    ensure(response["apiVersion"]!="catchplate.nativeOAuthReconnectTls/v1","reconnect TLS cannot continue after EOF")?;
                }
            }
            self.check(deadline)?; ingress.check(deadline)?; Reply::parse(response,&config,&ingress)
        })();
        if result.is_err(){self.poisoned=true;self.process.terminate();} result
    }
}

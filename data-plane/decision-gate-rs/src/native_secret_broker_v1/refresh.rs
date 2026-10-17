//! Only actual helper preparations and authenticated receipt delivery. No
//! generic decrypt/sign/contact endpoint; relay frames are bounded TLS bytes.
use super::*;
use crate::native_oauth_refresh_v1::{self as refresh, Configuration, Reply};
use crate::native_upstream_relays_v1::NativeUpstreamRelaysV1;

impl Owner {
    pub fn configure_refresh(&mut self, config: Configuration, identity: &mut EnclaveRuntimeIdentityV1,
        boot: &str, key: &str, cp_key: &str, binary: &str, deadline: u64) -> Result<(), String> {
        let result = (|| {
            config.validate()?; self.check(deadline)?;
            ensure(self.refresh_configuration.is_none() && !self.service_phase_closed,
                "refresh must be configured once before serving")?;
            ensure(Sha256::digest(identity.ca_certificate_der()).as_slice() == self.owner_ca,
                "refresh helper belongs to another actual CA")?;
            let mut scope = identity.refresh_scope(deadline)?;
            let scope_fields = scope.as_object_mut().ok_or("refresh original scope")?;
            scope_fields.insert("holderId".to_owned(), json!(crate::native_currentness_v1::holder_id(boot, key)?));
            scope_fields.insert("bootId".to_owned(), json!(boot)); scope_fields.insert("keyId".to_owned(), json!(key));
            scope_fields.insert("controlPlaneResponseSigningKeyId".to_owned(), json!(cp_key));
            scope_fields.insert("expectedBinaryDigest".to_owned(), json!(binary));
            let mut value = serde_json::to_value(&config).map_err(|_|"refresh cold encoding")?;
            value.as_object_mut().ok_or("refresh cold object")?.insert("identity".to_owned(), scope);
            let request = canonical_ascii_bytes(&json!({"apiVersion":refresh::CHANNEL,"phase":"configure","configuration":value}))?;
            let response = document(&self.process.exchange(&request, deadline)?, 4096)?;
            fields(&response, &["apiVersion","phase"])?;
            ensure(response["apiVersion"] == refresh::CHANNEL && response["phase"] == "configured", "refresh helper configuration failed")?;
            self.refresh_configuration = Some(config); self.check(deadline)
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }

    pub fn begin_refresh(&mut self, credential: &str, recovery: Option<u64>, deadline: u64,
        relays: &NativeUpstreamRelaysV1) -> Result<Reply, String> {
        let request = json!({"apiVersion":refresh::CHANNEL,"phase":"begin","credentialId":credential,
            "recoveryVersion":recovery,"deadlineBoottimeNs":deadline});
        self.refresh_exchange(request, credential, deadline, relays)
    }

    pub fn refresh_receipt(&mut self, originals: Value, credential: &str, deadline: u64,
        relays: &NativeUpstreamRelaysV1) -> Result<Reply, String> {
        fields(&originals, &["requestOriginal","responseOriginal","currentnessBarrierSha256"])?;
        self.refresh_exchange(json!({"apiVersion":refresh::CHANNEL,"phase":"receipt","originals":originals}), credential, deadline, relays)
    }

    fn refresh_exchange(&mut self, request: Value, credential: &str, deadline: u64,
        relays: &NativeUpstreamRelaysV1) -> Result<Reply, String> {
        let result = (|| {
            self.check(deadline)?;
            let config = self.refresh_configuration.as_ref().ok_or("refresh helper is not configured")?.clone();
            let provider = config.applications.iter().find(|(_, app)| app.credential_ids.iter().any(|id| id == credential))
                .map(|(name, _)| name.clone()).ok_or("refresh credential is not assigned")?;
            let mut response = document(&self.process.exchange(&canonical_ascii_bytes(&request)?, deadline)?, MAX_FRAME)?;
            let mut transport: Option<VsockStreamV1> = None;
            let mut sequence = 0u64; let mut total = 0usize;
            while response["apiVersion"] == "catchplate.nativeOAuthRefreshTls/v1" {
                fields(&response, &["apiVersion","providerId","sequence","ciphertext","read"])?;
                sequence += 1;
                ensure(sequence <= 512 && response["sequence"].as_u64() == Some(sequence)
                    && response["providerId"] == provider, "refresh TLS relay sequence or provider changed")?;
                let read = response["read"].as_bool().ok_or("refresh TLS read flag")?;
                let output = if response["ciphertext"].is_null() { Vec::new() } else { decoded(&response["ciphertext"], 65536, None)? };
                if transport.is_none() { transport = Some(relays.refresh_stream(&provider, deadline)?); }
                let stream = transport.as_mut().ok_or("refresh TLS relay absent")?;
                stream.verify_connected_original(deadline).map_err(|_|"refresh TLS relay changed")?;
                if !output.is_empty() { stream.write_all(&output).map_err(|_|"refresh TLS relay write uncertain")?; }
                let mut input = vec![0u8; 65536];
                let size = if read { stream.read(&mut input).map_err(|_|"refresh TLS relay read uncertain")? } else { 0 };
                input.truncate(size); total = total.checked_add(output.len() + input.len()).ok_or("refresh relay count overflow")?;
                ensure(total <= 512 * 1024, "refresh TLS relay aggregate bound")?;
                self.check(deadline)?;
                let reply = json!({"apiVersion":"catchplate.nativeOAuthRefreshTls/v1","sequence":sequence,
                    "ciphertext":if input.is_empty(){Value::Null}else{json!(encoded(&input))},"eof":read && size == 0});
                response = document(&self.process.exchange(&canonical_ascii_bytes(&reply)?, deadline)?, MAX_FRAME)?;
            }
            self.check(deadline)?;
            Reply::parse(response, &config)
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }
}

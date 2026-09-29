//! Only actual helper preparations and authenticated receipt delivery. No
//! generic decrypt/sign/contact endpoint; relay frames are bounded TLS bytes.
use super::*;
use crate::native_oauth_capture_retirement_v1::{self as retirement, Configuration, Reply};
use crate::native_upstream_relays_v1::NativeUpstreamRelaysV1;

impl Owner {
    pub fn configure_capture_retirement(&mut self, config: Configuration, identity: &mut EnclaveRuntimeIdentityV1,
        boot: &str, key: &str, cp_key: &str, binary: &str, deadline: u64) -> Result<(), String> {
        let result = (|| {
            config.validate()?; self.check(deadline)?;
            ensure(self.capture_retirement_configuration.is_none() && !self.service_phase_closed,
                "retirement must be configured once before serving")?;
            ensure(Sha256::digest(identity.ca_certificate_der()).as_slice() == self.owner_ca,
                "retirement helper belongs to another actual CA")?;
            let mut scope = identity.refresh_scope(deadline)?;
            let scope_fields = scope.as_object_mut().ok_or("retirement original scope")?;
            scope_fields.insert("holderId".to_owned(), json!(crate::native_currentness_v1::holder_id(boot, key)?));
            scope_fields.insert("bootId".to_owned(), json!(boot)); scope_fields.insert("keyId".to_owned(), json!(key));
            scope_fields.insert("controlPlaneResponseSigningKeyId".to_owned(), json!(cp_key));
            scope_fields.insert("expectedBinaryDigest".to_owned(), json!(binary));
            let mut value = serde_json::to_value(&config).map_err(|_|"retirement cold encoding")?;
            value.as_object_mut().ok_or("retirement cold object")?.insert("identity".to_owned(), scope);
            let request = canonical_ascii_bytes(&json!({"apiVersion":retirement::CHANNEL,"phase":"configure","configuration":value}))?;
            let response = document(&self.process.exchange(&request, deadline)?, 4096)?;
            fields(&response, &["apiVersion","phase"])?;
            ensure(response["apiVersion"] == retirement::CHANNEL && response["phase"] == "configured", "retirement helper configuration failed")?;
            self.capture_retirement_configuration = Some(config); self.check(deadline)
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }

    pub fn begin_capture_retirement(&mut self, pending: &str, deadline: u64,
        relays: &NativeUpstreamRelaysV1) -> Result<Reply, String> {
        let request = json!({"apiVersion":retirement::CHANNEL,"phase":"begin","exchangeId":pending,"deadlineBoottimeNs":deadline});
        self.capture_retirement_exchange(request, pending, deadline, relays)
    }

    pub fn capture_retirement_receipt(&mut self, originals: Value, pending: &str, deadline: u64,
        relays: &NativeUpstreamRelaysV1) -> Result<Reply, String> {
        fields(&originals, &["requestOriginal","responseOriginal","currentnessBarriers"])?;
        self.capture_retirement_exchange(json!({"apiVersion":retirement::CHANNEL,"phase":"receipt","originals":originals}), pending, deadline, relays)
    }

    fn capture_retirement_exchange(&mut self, request: Value, pending: &str, deadline: u64,
        relays: &NativeUpstreamRelaysV1) -> Result<Reply, String> {
        let result = (|| {
            self.check(deadline)?;
            let config = self.capture_retirement_configuration.as_ref().ok_or("retirement helper is not configured")?.clone();
            let grant = config.target(pending)?.grant()?;
            let provider = grant["providerId"].as_str().ok_or("retirement target provider absent")?.to_owned();
            let mut response = document(&self.process.exchange(&canonical_ascii_bytes(&request)?, deadline)?, MAX_FRAME)?;
            let mut transport: Option<VsockStreamV1> = None;
            let mut sequence = 0u64; let mut total = 0usize;
            while response["apiVersion"] == retirement::TLS {
                fields(&response, &["apiVersion","providerId","sequence","ciphertext","read"])?;
                sequence += 1;
                ensure(sequence <= 512 && response["sequence"].as_u64() == Some(sequence)
                    && response["providerId"] == provider, "retirement TLS relay sequence or provider changed")?;
                let read = response["read"].as_bool().ok_or("retirement TLS read flag")?;
                let output = if response["ciphertext"].is_null() { Vec::new() } else { decoded(&response["ciphertext"], 65536, None)? };
                if transport.is_none() { transport = Some(relays.cleanup_stream(&provider, deadline)?); }
                let stream = transport.as_mut().ok_or("retirement TLS relay absent")?;
                stream.verify_connected_original(deadline).map_err(|_|"retirement TLS relay changed")?;
                if !output.is_empty() { stream.write_all(&output).map_err(|_|"retirement TLS relay write uncertain")?; }
                let mut input = vec![0u8; 65536];
                let size = if read { stream.read(&mut input).map_err(|_|"retirement TLS relay read uncertain")? } else { 0 };
                input.truncate(size); total = total.checked_add(output.len() + input.len()).ok_or("retirement relay count overflow")?;
                ensure(total <= 512 * 1024, "retirement TLS relay aggregate bound")?;
                self.check(deadline)?;
                let reply = json!({"apiVersion":retirement::TLS,"sequence":sequence,
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

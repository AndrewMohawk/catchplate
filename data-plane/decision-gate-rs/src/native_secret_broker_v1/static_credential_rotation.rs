//! Only the same retained static TLS owner reaches the provisioned helper.
use super::*;
use crate::native_static_credential_rotation_browser_v1::{Accepted, Kind};
use crate::native_static_credential_rotation_v1::{self as wire, BrowserTls, Configuration, Reply};

impl Owner {
    pub fn configure_static_credential_rotation(&mut self, config: Configuration, ingress: Arc<BrowserTls>,
        identity: &mut EnclaveRuntimeIdentityV1, boot: &str, key: &str, cp_key: &str, binary: &str,
        deadline: u64) -> Result<(), String> {
        let result = (|| {
            config.validate()?; self.check(deadline)?; identity.verify_browser_ingress(&ingress, deadline)?;
            ensure(self.static_rotation_configuration.is_none() && self.static_configuration.is_none() && self.exchange_configuration.is_none()
                && self.setup_configuration.is_none() && self.reconnect_configuration.is_none()
                && self.succession_configuration.is_none() && !self.service_phase_closed
                && config.intake_origin == ingress.origin()
                && config.static_credential_rotation_policy.native_secret_kek_id == self.secret_kek_id
                && Sha256::digest(identity.ca_certificate_der()).as_slice() == self.owner_ca,
                "static helper requires its same cold CA, KEK and browser owner")?;
            let mut scope = identity.refresh_scope(deadline)?;
            let fields = scope.as_object_mut().ok_or("static native identity")?;
            fields.insert("holderId".to_owned(), json!(crate::native_currentness_v1::holder_id(boot, key)?));
            fields.insert("bootId".to_owned(), json!(boot)); fields.insert("keyId".to_owned(), json!(key));
            fields.insert("controlPlaneResponseSigningKeyId".to_owned(), json!(cp_key));
            fields.insert("expectedBinaryDigest".to_owned(), json!(binary));
            let mut value = serde_json::to_value(&config).map_err(|_| "static cold configuration encoding")?;
            let object = value.as_object_mut().ok_or("static cold configuration object")?;
            object.remove("browserVsockPort"); object.insert("identity".to_owned(), scope);
            object.insert("ingressLeafCertificateSha256".to_owned(), json!(ingress.certificate_sha));
            object.insert("ingressLeafSpkiSha256".to_owned(), json!(ingress.spki_sha));
            let response = document(&self.process.exchange(&canonical_ascii_bytes(&json!({"apiVersion": wire::CHANNEL,
                "phase": "configure", "configuration": value}))?, deadline)?, 4096)?;
            wire::fields(&response, &["apiVersion", "phase"])?;
            ensure(response["apiVersion"] == wire::CHANNEL && response["phase"] == "configured", "static helper cold admission failed")?;
            self.static_rotation_configuration = Some((config, ingress)); self.check(deadline)
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }

    pub fn static_credential_rotation_browser(&mut self, request: &Accepted) -> Result<Reply, String> {
        let result = (|| {
            self.check(request.deadline())?;
            let (config, ingress) = self.static_rotation_configuration.as_ref().ok_or("static helper not configured")?.clone();
            request.verify_ingress(&ingress)?;
            ensure(matches!(request.kind(), Kind::Intake | Kind::Prepare), "static page cannot dispatch a private command")?;
            let command = request.command()?;
            let raw = Zeroizing::new(canonical_ascii_bytes(&command)?);
            let response = document(&self.process.exchange(&raw, request.deadline())?, MAX_FRAME)?;
            request.check()?; self.check(request.deadline())?;
            Reply::parse(response, &config, &ingress, &command)
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }
}

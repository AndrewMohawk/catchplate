//! Explicit v2 historical key inventory. All keys stay inside the same actual
//! measured helper; no generic decrypt or caller recipient constructor exists.
use super::*;

pub const CONFIGURATION: &str = "catchplate.nativeSecretBrokerConfiguration/v2";
const HISTORY_CHANNEL: &str = "catchplate.nativeHistoricalBrokerChannel/v1";
const REQUEST: &str = "catchplate.nativeHistoricalBrokerKmsRecipientRequest/v1";
const RESPONSE: &str = "catchplate.nativeHistoricalBrokerKmsRecipientCiphertext/v1";
const MAX_CONFIGURATION: usize = 256 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyAssignment {
    kms_key_id: String,
    ciphertext_blob_sha256: String,
    encryption_context: BTreeMap<String, String>,
    kek_sha256: String,
    secret_kek_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationV2 {
    api_version: String,
    kms_parent_port: u32,
    kms_key_id: String,
    ciphertext_blob_sha256: String,
    encryption_context: BTreeMap<String, String>,
    kek_sha256: String,
    secret_kek_id: String,
    helper_image: ImageConfiguration,
    historical_keys: Vec<KeyAssignment>,
}

impl ConfigurationV2 {
    fn primary(&self) -> Configuration {
        // Data decomposition only. The original v2 commitment is retained and
        // installed in the real primary recipient request before its quote.
        Configuration { api_version: "catchplate.nativeSecretBrokerConfiguration/v1".to_owned(),
            kms_parent_port: self.kms_parent_port, kms_key_id: self.kms_key_id.clone(),
            ciphertext_blob_sha256: self.ciphertext_blob_sha256.clone(), encryption_context: self.encryption_context.clone(),
            kek_sha256: self.kek_sha256.clone(), secret_kek_id: self.secret_kek_id.clone(), helper_image: self.helper_image.clone() }
    }

    pub fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == CONFIGURATION && self.historical_keys.len() <= 16,
            "historical broker requires its explicit bounded v2 profile")?;
        self.primary().validate()?;
        let mut previous: Option<&str> = None;
        let mut ids = std::collections::BTreeSet::from([self.secret_kek_id.as_str()]);
        for entry in &self.historical_keys {
            let shape = Configuration { api_version: "catchplate.nativeSecretBrokerConfiguration/v1".to_owned(),
                kms_parent_port: self.kms_parent_port, kms_key_id: entry.kms_key_id.clone(),
                ciphertext_blob_sha256: entry.ciphertext_blob_sha256.clone(), encryption_context: entry.encryption_context.clone(),
                kek_sha256: entry.kek_sha256.clone(), secret_kek_id: entry.secret_kek_id.clone(), helper_image: self.helper_image.clone() };
            shape.validate()?;
            ensure(previous.is_none_or(|before| before < entry.kek_sha256.as_str())
                && entry.kek_sha256 != self.kek_sha256 && ids.insert(entry.secret_kek_id.as_str()),
                "historical key full commitments/IDs must be unique and exclude current key")?;
            previous = Some(&entry.kek_sha256);
        }
        ensure(canonical_ascii_bytes(self)?.len() <= MAX_CONFIGURATION,
            "complete historical key inventory exceeds its pre-contact bound")
    }

    pub fn into_parts(self) -> Result<(Configuration, HistoricalConfiguration), String> {
        self.validate()?;
        let original = canonical_ascii_bytes(&self)?;
        let primary = self.primary();
        let primary_original = canonical_ascii_bytes(&primary)?;
        Ok((primary, HistoricalConfiguration { original, primary_original,
            entries: self.historical_keys, parent_port: self.kms_parent_port }))
    }
}

/// Retained cold data, not key custody or decryption permission. Only the closed
/// v2 decoder produces it; all actual effects require the genuine helper owner.
pub struct HistoricalConfiguration {
    original: Vec<u8>, primary_original: Vec<u8>, entries: Vec<KeyAssignment>, parent_port: u32,
}
impl HistoricalConfiguration {
    pub(crate) fn commitment(&self) -> String { sha(&self.original) }
    pub fn require_primary(&self, primary: &Configuration) -> Result<(), String> {
        ensure(canonical_ascii_bytes(primary)? == self.primary_original
            && self.original.len() <= MAX_CONFIGURATION && self.entries.len() <= 16,
            "historical inventory lost its exact primary/v2 association")
    }
    pub(crate) fn bind_pending(&self, pending: &mut PendingBroker) -> Result<(), String> {
        self.require_primary(&pending.config)?;
        ensure(!pending.quoted && pending.owner_ca.is_none(), "historical primary quote was already consumed")?;
        pending.request["configurationSha256"] = json!(sha(&self.original));
        Ok(())
    }

    pub(crate) fn provision(self, owner: &mut Owner, identity: &mut EnclaveRuntimeIdentityV1) -> Result<(), String> {
        let result = (|| {
            let deadline = owner.deadline;
            owner.check(deadline)?;
            ensure(identity.deadline() == deadline && owner.historical_configuration_sha256.is_none()
                && !owner.service_phase_closed && Sha256::digest(identity.ca_certificate_der()).as_slice() == owner.owner_ca,
                "historical keys need original identity, lifetime and unused actual broker")?;
            let digest = sha(&self.original);
            let initialize = canonical_ascii_bytes(&json!({"apiVersion":HISTORY_CHANNEL,"phase":"initialize",
                "configurationOriginal":encoded(&self.original),"deadlineBoottimeNs":deadline}))?;
            ensure(initialize.len() <= MAX_FRAME, "historical complete initialization frame bound")?;
            let response = document(&owner.process.exchange(&initialize,deadline)?,4096)?;
            fields(&response,&["apiVersion","phase","configurationSha256"])?;
            ensure(response["apiVersion"] == HISTORY_CHANNEL && response["phase"] == "initialized"
                && response["configurationSha256"] == digest, "historical helper original admission failed")?;
            let mut quotes = Vec::with_capacity(self.entries.len());
            for (index, entry) in self.entries.iter().enumerate() {
                let mut pending = PendingHistoricalKey::begin(owner, entry, index, &digest, self.parent_port)?;
                let quote = identity.quote_historical_broker_recipient(&mut pending,deadline)?;
                pending.provision(&quote)?;
                quotes.push(quote);
            }
            let response = document(&owner.process.exchange(&canonical_ascii_bytes(&json!({"apiVersion":HISTORY_CHANNEL,
                "phase":"finish","configurationSha256":digest}))?,deadline)?,4096)?;
            fields(&response,&["apiVersion","phase","configurationSha256","keyCount"])?;
            ensure(response["apiVersion"] == HISTORY_CHANNEL && response["phase"] == "finished"
                && response["configurationSha256"] == digest && response["keyCount"].as_u64() == Some(self.entries.len() as u64),
                "historical helper inventory was not fully initialized")?;
            owner.historical_configuration_sha256 = Some(digest);
            owner.historical_original = Some(self.original);
            owner._historical_quotes = quotes;
            owner.check(deadline)
        })();
        if result.is_err() { owner.poisoned = true; owner.process.terminate(); }
        result
    }
}

pub(crate) struct PendingHistoricalKey<'a> {
    owner: &'a mut Owner, public_key: Vec<u8>, nonce: [u8;32], request: Value,
    configuration_sha256: String, index: usize, parent_port: u32, quoted: bool,
}
impl<'a> PendingHistoricalKey<'a> {
    fn begin(owner: &'a mut Owner, entry: &KeyAssignment, index: usize, configuration_sha256: &str, parent_port:u32)
        -> Result<Self,String> {
        let deadline = owner.deadline; owner.check(deadline)?;
        let response = document(&owner.process.exchange(&canonical_ascii_bytes(&json!({"apiVersion":HISTORY_CHANNEL,
            "phase":"recipient","index":index,"configurationSha256":configuration_sha256}))?,deadline)?,8192)?;
        fields(&response,&["apiVersion","phase","index","configurationSha256","assignmentSha256",
            "recipientPublicKey","recipientPublicKeySha256","nonce"])?;
        let public_key = decoded(&response["recipientPublicKey"],1024,None)?;
        let nonce: [u8;32] = decoded(&response["nonce"],32,Some(32))?.try_into().map_err(|_|"historical nonce width")?;
        ensure(response["apiVersion"] == HISTORY_CHANNEL && response["phase"] == "recipient"
            && response["index"].as_u64() == Some(index as u64) && response["configurationSha256"] == configuration_sha256
            && response["assignmentSha256"] == sha(&canonical_ascii_bytes(entry)?)
            && response["recipientPublicKeySha256"] == sha(&public_key) && nonce != [0;32],
            "historical recipient does not match exact configured assignment")?;
        let request = json!({"apiVersion":REQUEST,"material":"historical-broker-kek","configurationSha256":configuration_sha256,
            "kmsKeyId":entry.kms_key_id,"ciphertextBlobSha256":entry.ciphertext_blob_sha256,"encryptionContext":entry.encryption_context,
            "kekSha256":entry.kek_sha256,"secretKekId":entry.secret_kek_id,"recipientPublicKeySha256":sha(&public_key),
            "nonce":encoded(&nonce),"deadlineBoottimeNs":deadline});
        Ok(Self { owner, public_key, nonce, request, configuration_sha256:configuration_sha256.to_owned(), index, parent_port, quoted:false })
    }

    pub(crate) fn quote_parts(&mut self, owner_ca:[u8;32], deadline:u64)->Result<(Vec<u8>,[u8;32],[u8;32]),String> {
        self.owner.check(deadline)?;
        ensure(!self.quoted && deadline == self.owner.deadline && owner_ca == self.owner.owner_ca,
            "historical recipient quote needs the same retained gate identity/lifetime")?;
        self.quoted = true;
        Ok((self.public_key.clone(),self.nonce,Sha256::digest(canonical_ascii_bytes(&self.request)?).into()))
    }

    fn provision(self, quote:&RuntimeKeyQuoteV1)->Result<(),String> {
        let deadline = self.owner.deadline;
        self.owner.check(deadline)?;
        ensure(self.quoted && quote.public_key() == self.public_key && quote.nonce() == &self.nonce,
            "historical actual recipient attestation differs")?;
        let request_original = canonical_ascii_bytes(&self.request)?;
        let request_sha = sha(&request_original);
        let envelope = canonical_ascii_bytes(&json!({"request":self.request,"requestSha256":request_sha,
            "attestationDocument":encoded(quote.document())}))?;
        ensure(envelope.len() <= 32768,"historical complete KMS request bound")?;
        // Exactly one fixed parent connection and one ciphertext request for
        // this actual recipient. Any uncertainty consumes the whole owner.
        let mut transport = VsockStreamV1::connect_parent(self.parent_port,deadline).map_err(|_|"historical fixed KMS parent unavailable")?;
        transport.write_all(&(envelope.len() as u32).to_be_bytes()).map_err(|_|"historical KMS write uncertain")?;
        transport.write_all(&envelope).map_err(|_|"historical KMS write uncertain")?;
        let mut length = [0u8;4]; transport.read_exact(&mut length).map_err(|_|"historical KMS read uncertain")?;
        let length = u32::from_be_bytes(length) as usize;
        ensure(length > 0 && length <= 96 * 1024,"historical KMS ciphertext response bound")?;
        let mut raw = vec![0u8;length]; transport.read_exact(&mut raw).map_err(|_|"historical KMS read uncertain")?;
        transport.verify_connected_original(deadline).map_err(|_|"historical parent connection changed")?;
        let response = document(&raw,96 * 1024)?;
        fields(&response,&["apiVersion","requestSha256","ciphertextForRecipient","ciphertextSha256"])?;
        let cms = decoded(&response["ciphertextForRecipient"],65536,None)?;
        ensure(response["apiVersion"] == RESPONSE && response["requestSha256"] == request_sha
            && response["ciphertextSha256"] == sha(&cms),"historical KMS ciphertext correlation differs")?;
        let response = document(&self.owner.process.exchange(&canonical_ascii_bytes(&json!({"apiVersion":HISTORY_CHANNEL,
            "phase":"provision","index":self.index,"requestOriginal":encoded(&request_original),
            "ciphertextForRecipient":encoded(&cms),"ciphertextSha256":sha(&cms)}))?,deadline)?,4096)?;
        fields(&response,&["apiVersion","phase","index","configurationSha256","requestSha256"])?;
        ensure(response["apiVersion"] == HISTORY_CHANNEL && response["phase"] == "provisioned"
            && response["index"].as_u64() == Some(self.index as u64) && response["requestSha256"] == request_sha
            && response["configurationSha256"] == self.configuration_sha256,"historical key private admission failed")?;
        self.owner.check(deadline)
    }
}

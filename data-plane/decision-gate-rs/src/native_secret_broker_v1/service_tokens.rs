//! One cold service-token operation on the actual provisioned broker owner.
//! No generic decrypt, plaintext IPC, callable listener or caller-owned key.
use super::*;
use serde::de::DeserializeOwned;
use zeroize::Zeroize;

const BINDING: &str = "serverware.nativeServiceTokensBinding/v1";
const ENVELOPE: &str = "serverware.nativeServiceTokensEnvelope/v1";
const PLAINTEXT: &str = "serverware.nativeServiceTokens/v1";
const OUTPUT: &str = "serverware.nativeServiceTokensGateCiphertext/v1";
const DOMAIN: &[u8] = b"serverware/native-service-tokens-gate-ciphertext/v1\0";
const MAX_PLAINTEXT: usize = 24576;

fn required_option<'de, D: serde::Deserializer<'de>, T: DeserializeOwned>(d: D)
    -> Result<Option<T>, D::Error> { Option::<T>::deserialize(d) }

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub api_version: String,
    pub instance_id: String,
    pub data_plane_binary_digest: String,
    pub policy_hash: String,
    pub atomic_release_authorization_enabled: bool,
    pub credential_lease_url: String,
    #[serde(deserialize_with = "required_option")]
    pub grant_consume_url: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub rate_limit_consume_url: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub release_authorization_base_url: Option<String>,
}

impl Binding {
    pub fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == BINDING && self.instance_id.is_ascii()
            && self.instance_id.len() <= 4096 && self.instance_id.starts_with("spiffe://")
            && self.instance_id.bytes().all(|b| b > 32 && b < 127), "native service-token instance differs")?;
        let uri = url::Url::parse(&self.instance_id).map_err(|_| "native service-token instance URI")?;
        ensure(uri.scheme() == "spiffe" && uri.host_str().is_some()
            && uri.username().is_empty() && uri.password().is_none() && uri.port().is_none()
            && uri.query().is_none() && uri.fragment().is_none() && uri.path().starts_with('/'),
            "native service-token instance scope differs")?;
        digest(&self.data_plane_binary_digest)?;
        digest(&self.policy_hash)?;
        for (endpoint, path) in [
            (Some(self.credential_lease_url.as_str()), "/api/data-plane/credential-leases"),
            (self.grant_consume_url.as_deref(), "/api/data-plane/grants/consume"),
            (self.rate_limit_consume_url.as_deref(), "/api/data-plane/rate-limits/consume"),
            (self.release_authorization_base_url.as_deref(), "/api/data-plane/release-authorizations"),
        ] {
            if let Some(endpoint) = endpoint {
                ensure(!endpoint.is_empty() && endpoint.len() <= 4096 && endpoint.is_ascii()
                    && endpoint.bytes().all(|b| b > 32 && b < 127), "native service-token endpoint bound")?;
                let uri = url::Url::parse(endpoint).map_err(|_| "native service-token endpoint URI")?;
                ensure(uri.scheme() == "https" && uri.host_str().is_some()
                    && uri.username().is_empty() && uri.password().is_none() && uri.path() == path
                    && uri.port() != Some(0) && uri.query().is_none() && uri.fragment().is_none(),
                    "native service-token endpoint scope differs")?;
            }
        }
        ensure(if self.atomic_release_authorization_enabled { self.release_authorization_base_url.is_some() }
            else { self.grant_consume_url.is_some() && self.rate_limit_consume_url.is_some() },
            "native service-token required endpoint absent")?;
        ensure(canonical_ascii_bytes(self)?.len() <= 24576, "native service-token binding bound")
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    api_version: String,
    pub binding: Binding,
    secret_kek_id: String,
    nonce: String,
    ciphertext: String,
}

impl Envelope {
    pub fn validate(&self, expected: &Binding) -> Result<(), String> {
        expected.validate()?;
        self.binding.validate()?;
        ensure(self.api_version == ENVELOPE && &self.binding == expected
            && self.secret_kek_id.len() == "attested-memory-kek:".len() + 24
            && self.secret_kek_id.starts_with("attested-memory-kek:")
            && self.secret_kek_id["attested-memory-kek:".len()..].bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "native service-token envelope scope differs")?;
        decoded(&Value::String(self.nonce.clone()), 12, Some(12))?;
        decoded(&Value::String(self.ciphertext.clone()), 32784, Some(32784))?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tokens {
    #[serde(deserialize_with = "required_option")]
    pub credential_lease_token: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub grant_consume_token: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub rate_limit_consume_token: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub release_authorization_token: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub management_token: Option<String>,
}

impl Tokens {
    pub fn validate(&self, binding: &Binding) -> Result<(), String> {
        binding.validate()?;
        let mut seen = std::collections::BTreeSet::new();
        for (token, required) in [
            (&self.credential_lease_token, true), (&self.management_token, true),
            (&self.grant_consume_token, binding.grant_consume_url.is_some()),
            (&self.rate_limit_consume_token, binding.rate_limit_consume_url.is_some()),
            (&self.release_authorization_token, binding.release_authorization_base_url.is_some()),
        ] {
            ensure(token.is_some() == required, "native service-token role coverage differs")?;
            if let Some(token) = token {
                ensure((32..=4096).contains(&token.len()) && token.bytes().all(|b| b > 32 && b < 127)
                    && token.bytes().collect::<std::collections::BTreeSet<_>>().len() >= 8
                    && seen.insert(token.as_str()), "native service-token strength or separation differs")?;
            }
        }
        Ok(())
    }
}

impl Drop for Tokens {
    fn drop(&mut self) {
        self.credential_lease_token.zeroize(); self.management_token.zeroize();
        self.grant_consume_token.zeroize(); self.rate_limit_consume_token.zeroize();
        self.release_authorization_token.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TokenDocument { api_version: String, tokens: Tokens }

impl Owner {
    pub fn open_service_tokens(&mut self, identity: &mut EnclaveRuntimeIdentityV1,
        envelope: Envelope, expected: &Binding, deadline: u64) -> Result<Tokens, String> {
        let deadline = deadline.min(self.deadline).min(identity.deadline());
        let result = (|| {
            self.check(deadline)?;
            ensure(!self.service_phase_closed, "native service-token phase already consumed")?;
            self.service_phase_closed = true;
            envelope.validate(expected)?;
            ensure(envelope.secret_kek_id == self.secret_kek_id
                && Sha256::digest(identity.ca_certificate_der()).as_slice() == self.owner_ca,
                "native service-token KEK or actual gate owner differs")?;
            let policy = digest(&expected.policy_hash)?;
            identity.verify_policy_commitment(policy, deadline)?;
            let recipient = CredentialRecipientV1::generate()?;
            let public = recipient.public_key_bytes()?;
            let mut nonce = [0u8; 32]; let mut operation = [0u8; 32];
            SystemRandom::new().fill(&mut nonce).map_err(|_| "native service-token entropy unavailable")?;
            SystemRandom::new().fill(&mut operation).map_err(|_| "native service-token entropy unavailable")?;
            let request = canonical_ascii_bytes(&json!({"apiVersion":"serverware.nativeBrokerOpenServiceTokens/v1",
                "operationId":hex::encode(operation),"gateRecipientPublicKey":encoded(&public),
                "gateRecipientNonce":encoded(&nonce),"deadlineBoottimeNs":deadline,
                "expectedBinding":expected,"envelope":envelope}))?;
            ensure(request.len() <= 128 * 1024, "native service-token request bound")?;
            let request_sha = sha(&request);
            let response = document(&self.process.exchange(&request, deadline)?, 64 * 1024)?;
            fields(&response, &["apiVersion","requestSha256","recipientPublicKey",
                "serverEphemeralPublicKey","aeadNonce","ciphertext"])?;
            ensure(response["apiVersion"] == OUTPUT && response["requestSha256"] == request_sha
                && response["recipientPublicKey"] == encoded(&public), "native service-token response scope differs")?;
            let peer: [u8; 32] = decoded(&response["serverEphemeralPublicKey"], 32, Some(32))?.try_into().unwrap();
            let aead_nonce: [u8; 12] = decoded(&response["aeadNonce"], 12, Some(12))?.try_into().unwrap();
            let mut ciphertext = Zeroizing::new(decoded(&response["ciphertext"], MAX_PLAINTEXT + 16, None)?);
            let shared = recipient.derive_shared_key(peer)?;
            let mut aad = DOMAIN.to_vec(); aad.extend_from_slice(&digest(&request_sha)?);
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &nonce);
            let prk = salt.extract(shared.as_ref());
            let info = [aad.as_slice()]; let mut key = Zeroizing::new([0u8; 32]);
            prk.expand(&info, AesKey).map_err(|_| "native service-token HKDF rejected")?.fill(key.as_mut())
                .map_err(|_| "native service-token HKDF failed")?;
            let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key.as_ref())
                .map_err(|_| "native service-token AEAD key rejected")?);
            let plaintext = key.open_in_place(aead::Nonce::assume_unique_for_key(aead_nonce),
                aead::Aad::from(&aad), ciphertext.as_mut()).map_err(|_| "native service-token AEAD refused")?;
            ensure(!plaintext.is_empty() && plaintext.len() <= MAX_PLAINTEXT, "native service-token plaintext bound")?;
            let original: TokenDocument = serde_json::from_slice(plaintext)
                .map_err(|_| "native service-token plaintext shape differs")?;
            let canonical = Zeroizing::new(canonical_ascii_bytes(&original)?);
            ensure(original.api_version == PLAINTEXT && canonical.as_slice() == plaintext,
                "native service-token plaintext original differs")?;
            original.tokens.validate(expected)?;
            identity.verify_policy_commitment(policy, deadline)?;
            self.check(deadline)?;
            self.service_token_scope = Some(ServiceTokenScope {
                instance_id: expected.instance_id.clone(), policy_hash: expected.policy_hash.clone(),
                binary_digest: expected.data_plane_binary_digest.clone(),
            });
            Ok(original.tokens)
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }
}

//! Active-family reconnect uses its own measured preparation and signing purpose.
//! Shared scalar/TLS encodings do not convert issuance or Setup permission.
use crate::native_currentness_v1 as current;
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const CHANNEL: &str = "serverware.nativeOAuthReconnectChannel/v1";
pub const SCHEMA: &str = "serverware.nativeOAuthReconnectStatement/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"serverware/native-oauth-reconnect-attestation/v1\0";
pub const SIGN_OPERATION: &str = "nativeOAuthReconnectExchange.sign/v1";
pub const HTTP_REQUEST: &str = "serverware.nativeOAuthReconnectRequest/v1";
pub const HTTP_RESPONSE: &str = "serverware.nativeOAuthReconnectResponse/v1";
pub(crate) use crate::native_oauth_refresh_v1::{ensure, sha};
pub use crate::native_oauth_exchange_v1::{origin, Application, BrowserTls, Limits, Windows};

pub(crate) fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    ensure(value.as_object().is_some_and(|map| map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))), "reconnect fields differ")
}
fn bounded_original(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    ensure(!value.is_empty() && value.len() <= (maximum * 4 + 2) / 3, "reconnect encoded original bound")?;
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| "reconnect original encoding")?;
    ensure(!raw.is_empty() && raw.len() <= maximum && URL_SAFE_NO_PAD.encode(&raw) == value, "reconnect original bound")?;
    Ok(raw)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct ReconnectLimits { pub affected_lineage_capacity: u64, pub history_capacity: u64, pub authorization_max_seconds: u64 }
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub api_version: String, pub source_revision: String, pub authority_root_public_key: String,
    pub authority_root_spki_sha256: String, pub authority_configuration_original: String,
    pub control_plane_configuration_digest: String, pub deployment_id: String, pub instance_id: String,
    pub limits: Limits, pub reconnect_limits: ReconnectLimits, pub windows: Windows,
    pub applications: BTreeMap<String, Application>, pub recovery_targets: Vec<String>,
    pub callback_origin: String, pub portal_origin: String, pub browser_vsock_port: u32,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == "serverware.nativeOAuthReconnectExchangeConfiguration/v1"
            && !self.source_revision.is_empty() && self.source_revision.len() <= 128 && !self.source_revision.chars().any(char::is_control)
            && current::identifier(&self.deployment_id) && current::digest(&self.authority_root_spki_sha256)
            && current::digest(&self.control_plane_configuration_digest) && self.instance_id.starts_with("spiffe://")
            && self.instance_id.len() <= 4096 && !self.instance_id.chars().any(char::is_control)
            && self.limits.pending_capacity == 64 && self.limits.revocation_capacity == 64
            && self.reconnect_limits.affected_lineage_capacity == 7 && self.reconnect_limits.history_capacity == 64
            && self.reconnect_limits.authorization_max_seconds == 3600
            && self.windows.contact_max_seconds == 600 && self.windows.retention_max_seconds == 600
            && self.windows.pending_max_seconds == 3600 && self.windows.operation_max_seconds == 30 && self.windows.recovery_max_seconds == 30
            && self.browser_vsock_port >= 1024 && self.browser_vsock_port < u32::MAX
            && self.callback_origin != self.portal_origin && !self.applications.is_empty() && self.applications.len() <= 2,
            "native reconnect configuration invalid")?;
        origin(&self.callback_origin)?; origin(&self.portal_origin)?;
        let root = current::bytes32(&self.authority_root_public_key)?;
        let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]; spki.extend(root);
        ensure(sha(&spki) == self.authority_root_spki_sha256, "reconnect root pin differs")?;
        bounded_original(&self.authority_configuration_original, 1024 * 1024)?;
        for (provider, application) in &self.applications {
            ensure(matches!(provider.as_str(), "google" | "x") && application.material.is_object()
                && !application.tls_roots_pem.is_empty() && application.tls_roots_pem.len() <= 128 * 1024 && application.tls_roots_pem.is_ascii(),
                "reconnect application inventory invalid")?;
            bounded_original(&application.enrollment_original, 32768)?;
        }
        ensure(self.recovery_targets.len() <= 64 && self.recovery_targets.windows(2).all(|pair| pair[0] < pair[1])
            && self.recovery_targets.iter().all(|item| current::uuid(item)), "reconnect recovery inventory invalid")?;
        ensure(canonical_ascii_bytes(self)?.len() <= 2 * 1024 * 1024, "reconnect configuration bound")
    }
}

pub struct Prepared { arguments: Value, operation: String, issued: u64, expires: u64,
    config: Configuration, ingress: Arc<BrowserTls> }
pub enum Reply {
    Prepared(Prepared),
    Redirect { exchange_id: String, location: String, name: String, value: String, expires: u64 },
    Complete { exchange_id: String, status: String, custody_sha: String },
}
impl Reply {
    pub(crate) fn parse(value: Value, config: &Configuration, ingress: &Arc<BrowserTls>) -> Result<Self, String> {
        ensure(value["apiVersion"] == CHANNEL && canonical_ascii_bytes(&value)?.len() <= 8 * 1024 * 1024, "reconnect helper channel or aggregate differs")?;
        match value["phase"].as_str().ok_or("reconnect helper phase")? {
            "prepared" => {
                fields(&value, &["apiVersion","phase","operation","arguments","issuedAtEpochNs","expiresAtEpochNs"])?;
                let prepared = Prepared { arguments: value["arguments"].clone(), operation: value["operation"].as_str().ok_or("reconnect operation")?.to_owned(),
                    issued: value["issuedAtEpochNs"].as_u64().ok_or("reconnect issue")?, expires: value["expiresAtEpochNs"].as_u64().ok_or("reconnect expiry")?,
                    config: config.clone(), ingress: Arc::clone(ingress) };
                fields(&prepared.arguments, &["action","resource_id","payload_digest","actor_id","request","approval_id","credential_policy",
                    "enrollment_original","control_plane_configuration_digest","assignment_original","authorization_original"])?;
                ensure(prepared.arguments["action"] == "credential.oauth.measured-reconnect" && prepared.arguments["approval_id"].is_null()
                    && prepared.arguments["assignment_original"].is_object() && prepared.arguments["credential_policy"].is_object()
                    && prepared.arguments["control_plane_configuration_digest"] == config.control_plane_configuration_digest
                    && current::uuid(prepared.exchange_id()?) && prepared.arguments["request"]["exchangeId"] == prepared.exchange_id()?
                    && prepared.issued > 0 && prepared.expires > prepared.issued && prepared.expires <= i64::MAX as u64 && prepared.expires - prepared.issued <= 30_000_000_000
                    && prepared.arguments["payload_digest"] == sha(&canonical_ascii_bytes(&prepared.arguments["request"])?), "reconnect preparation differs")?;
                prepared.provider()?; prepared.check_binding()?;
                ensure(canonical_ascii_bytes(&prepared.arguments)?.len() <= 2 * 1024 * 1024, "reconnect argument bound")?;
                Ok(Self::Prepared(prepared))
            },
            "authorization-redirect" => {
                fields(&value, &["apiVersion","phase","exchangeId","location","cookieName","cookieValue","expiresAtEpochNs"])?;
                let id = value["exchangeId"].as_str().ok_or("reconnect exchange")?.to_owned();
                let location = value["location"].as_str().ok_or("reconnect authorization URL")?.to_owned();
                let name = value["cookieName"].as_str().ok_or("reconnect cookie name")?.to_owned();
                let nonce = value["cookieValue"].as_str().ok_or("reconnect cookie value")?.to_owned();
                let expires = value["expiresAtEpochNs"].as_u64().ok_or("reconnect cookie expiry")?;
                let url = url::Url::parse(&location).map_err(|_| "reconnect authorization URL")?;
                ensure(current::uuid(&id) && name == format!("__Host-serverware-native-oauth-{}", id.replace('-', ""))
                    && current::bytes32(&nonce).is_ok() && expires > 0 && expires <= i64::MAX as u64
                    && location.len() <= 16384 && url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
                    && url.fragment().is_none() && url.port_or_known_default() == Some(443)
                    && matches!((url.host_str(),url.path()), (Some("accounts.google.com"),"/o/oauth2/v2/auth") | (Some("twitter.com"),"/i/oauth2/authorize")),
                    "reconnect redirect or original cookie differs")?;
                Ok(Self::Redirect { exchange_id: id, location, name, value: nonce, expires })
            },
            "complete" => {
                fields(&value, &["apiVersion","phase","exchangeId","status","custodyRowSha256"])?;
                let id = value["exchangeId"].as_str().ok_or("reconnect exchange")?.to_owned();
                let status = value["status"].as_str().ok_or("reconnect status")?.to_owned();
                let digest = value["custodyRowSha256"].as_str().ok_or("reconnect custody original")?.to_owned();
                ensure(current::uuid(&id) && current::digest(&digest)
                    && matches!(status.as_str(),"staged"|"cancelled"|"captured-unusable"|"observed-staged"|"observed-committed"), "reconnect completion differs")?;
                Ok(Self::Complete { exchange_id: id, status, custody_sha: digest })
            },
            _ => Err("unknown native reconnect helper phase".to_owned()),
        }
    }
}
impl Prepared {
    pub fn operation(&self) -> &str { &self.operation }
    pub fn exchange_id(&self) -> Result<&str,String> { self.arguments["resource_id"].as_str().ok_or_else(|| "reconnect exchange absent".to_owned()) }
    pub fn provider(&self) -> Result<&str,String> {
        let original = self.arguments["enrollment_original"].as_str().ok_or("reconnect enrollment absent")?;
        let matches: Vec<_> = self.config.applications.iter().filter(|(_, app)| app.enrollment_original == original).collect();
        ensure(matches.len() == 1, "reconnect application absent")?;
        Ok(matches[0].0.as_str())
    }
    fn authorization(&self) -> Result<(Vec<u8>,Value),String> {
        let raw = bounded_original(self.arguments["authorization_original"].as_str().ok_or("reconnect authorization absent")?,64*1024)?;
        let envelope = crate::native_oauth_refresh_v1::response_document(&raw)?;
        fields(&envelope,&["schema","payload","signatureBase64Url"])?;
        ensure(envelope["schema"] == "serverware.signedOAuthFamilyReconnectAuthorization/v1"
            && canonical_ascii_bytes(&envelope)? == raw, "reconnect authorization original differs")?;
        let signature = bounded_original(envelope["signatureBase64Url"].as_str().ok_or("reconnect authorization signature")?,64)?;
        ensure(signature.len() == 64,"reconnect authorization signature shape")?;
        Ok((raw,envelope["payload"].clone()))
    }
    fn check_binding(&self) -> Result<(),String> {
        let (_, grant) = self.authorization()?;
        let enrollment = bounded_original(self.arguments["enrollment_original"].as_str().ok_or("reconnect enrollment absent")?,32768)?;
        fields(&grant,&["schema","sourceRevision","purpose","authorizationId","configurationDigest","deploymentId","credentialId","credentialVersion",
            "credentialRowSha256","generationRowSha256","providerId","providerSubject","providerAccount","clientId","enrollmentSha256","requesterId",
            "scopes","metadataSha256","familyScope","affectedLineages","issuedAtEpochNs","contactExpiresAtEpochNs","retentionExpiresAtEpochNs","pendingExpiresAtEpochNs","expiresAtEpochNs"])?;
        ensure(grant["schema"] == "serverware.oauthFamilyReconnectAuthorization/v1" && grant["purpose"] == "measured-oauth-active-family-replacement"
            && grant["authorizationId"] == self.exchange_id()? && grant["providerId"] == self.provider()?
            && grant["sourceRevision"] == self.config.source_revision && grant["configurationDigest"] == self.config.control_plane_configuration_digest
            && grant["deploymentId"] == self.config.deployment_id && grant["requesterId"] == self.arguments["actor_id"]
            && self.arguments["actor_id"].as_str().is_some_and(|actor| actor.starts_with("oidc:") && actor.len() <= 512)
            && grant["enrollmentSha256"] == sha(&enrollment)
            && current::uuid(grant["credentialId"].as_str().ok_or("reconnect target absent")?)
            && grant["credentialVersion"].as_u64().is_some_and(|version| version > 0 && version < i64::MAX as u64)
            && grant["issuedAtEpochNs"].as_u64().is_some_and(|start| start > 0 && start <= self.issued)
            && grant["expiresAtEpochNs"].as_u64().is_some_and(|end| self.expires <= end && end <= i64::MAX as u64)
            && current::digest(self.arguments["request"]["fencedRowSha256"].as_str().ok_or("reconnect fence absent")?), "reconnect retained family binding differs")?;
        let request = &self.arguments["request"];
        let names: &[&str] = match self.operation.as_str() {
            "oauth.measured-reconnect.prepare" => &["exchangeId","stateSha256","browserNonceSha256","pkceVerifierSha256","stateOriginalSha256","stateEnvelope",
                "reservedEnvelope","providerId","redirectUri","credentialName","scopes","metadata","issuedAtEpochNs","contactExpiresAtEpochNs",
                "retentionExpiresAtEpochNs","pendingExpiresAtEpochNs","enrollmentSha256","limits","pkceChallenge","portalOrigin","callbackOrigin","fencedRowSha256"],
            "oauth.measured-reconnect.claim" => &["exchangeId","exchangeRowSha256","ownerNonceSha256","callbackSha256","callbackEnvelope","codeSha256","contactRequestSha256","limits","fencedRowSha256"],
            "oauth.measured-reconnect.capture" => &["exchangeId","exchangeRowSha256","ownerNonce","rawResponseSha256","rawResponseEnvelope","issuedMaterialSha256","issuedMaterialEnvelope","receivedAtEpochNs","limits","fencedRowSha256"],
            "oauth.measured-reconnect.stage" => &["exchangeId","exchangeRowSha256","ownerNonce","tokenSecretSha256","tokenEnvelope","identityRawSha256","identityRawEnvelope","metadata","review","payloadDigest","recoveryRequestDigest","limits","fencedRowSha256"],
            "oauth.measured-reconnect.recover" => &["exchangeId","custodyRowSha256","captureInputSha256","ownerNonceSha256","issuedAtEpochNs","expiresAtEpochNs","limits","fencedRowSha256"],
            "oauth.measured-reconnect.cancel" => &["exchangeId","exchangeRowSha256","callbackSha256","callbackEnvelope","limits","fencedRowSha256"],
            _ => return Err("reconnect operation is not fixed".to_owned()),
        };
        fields(request,names)?;
        ensure(request["limits"] == serde_json::to_value(&self.config.limits).map_err(|_|"reconnect limits encoding")?,"reconnect original limits differ")?;
        if self.operation.ends_with(".prepare") {
            ensure(["contactExpiresAtEpochNs","retentionExpiresAtEpochNs","pendingExpiresAtEpochNs"].iter().all(|name| request[*name] == grant[*name])
                && request["providerId"] == grant["providerId"] && request["scopes"] == grant["scopes"]
                && grant["metadataSha256"] == sha(&canonical_ascii_bytes(&request["metadata"])?), "reconnect initial grant originals differ")?;
        }
        if self.operation.ends_with(".stage") {
            ensure(request["tokenEnvelope"]["credential_version"].as_u64() == grant["credentialVersion"].as_u64().and_then(|version| version.checked_add(1))
                && request["review"]["reconnect_credential_id"] == grant["credentialId"]
                && request["review"]["reconnect_credential_version"] == grant["credentialVersion"],
                "reconnect encrypted successor generation differs")?;
        }
        Ok(())
    }
    pub(crate) fn ingress(&self) -> &BrowserTls { &self.ingress }
    pub(crate) fn verify_ingress(&self, expected:&Arc<BrowserTls>, deadline:u64) -> Result<(),String> {
        ensure(Arc::ptr_eq(&self.ingress,expected),"reconnect preparation belongs to another browser owner")?;
        self.ingress.check(deadline)
    }
    pub(crate) fn statement(&self,boot:&str,key:&str,cp:&str,policy:&str,binary:&str)->Result<Statement,String> {
        self.check_binding()?;
        let enrollment = bounded_original(self.arguments["enrollment_original"].as_str().ok_or("reconnect enrollment")?,32768)?;
        let (grant,_) = self.authorization()?;
        let mut nonce = [0u8;32];
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new().fill(&mut nonce).map_err(|_|"reconnect evidence entropy")?;
        // The independently frozen reconnect policy names PREPARE's proof
        // phase "draft" even though its browser has no draft round-trip.
        let phase = if self.operation.ends_with(".prepare") {"draft"} else {self.operation.rsplit('.').next().ok_or("reconnect phase")?};
        Ok(Statement(json!({"apiVersion":SCHEMA,"phase":phase,"holderId":current::holder_id(boot,key)?,"bootId":boot,"keyId":key,
            "controlPlaneResponseSigningKeyId":cp,"deploymentId":self.config.deployment_id,"instanceId":self.config.instance_id,
            "providerId":self.provider()?,"enrollmentSha256":sha(&enrollment),"exchangeId":self.exchange_id()?,"inputSha256":sha(&canonical_ascii_bytes(&self.arguments)?),
            "authorizationSha256":sha(&grant),"fencedRowSha256":self.arguments["request"]["fencedRowSha256"],"challenge":URL_SAFE_NO_PAD.encode(nonce),
            "policyHash":policy,"dataPlaneBinarySha256":binary,"callbackOrigin":self.ingress.origin,"portalOrigin":self.config.portal_origin,
            "ingressLeafCertificateSha256":self.ingress.certificate_sha,"ingressLeafSpkiSha256":self.ingress.spki_sha,
            "issuedAtEpochNs":self.issued,"expiresAtEpochNs":self.expires})))
    }
    pub fn wire(&self,evidence:Value)->Result<Value,String> {
        let (grant,_) = self.authorization()?;
        let phase=if self.operation.ends_with(".prepare"){"draft"}else{self.operation.rsplit('.').next().ok_or("reconnect phase")?};
        ensure(evidence["statement"]["apiVersion"] == SCHEMA
            && evidence["statement"]["phase"] == phase && evidence["statement"]["exchangeId"] == self.exchange_id()?
            && evidence["statement"]["issuedAtEpochNs"] == self.issued && evidence["statement"]["expiresAtEpochNs"] == self.expires
            && evidence["statement"]["inputSha256"] == sha(&canonical_ascii_bytes(&self.arguments)?)
            && evidence["statement"]["authorizationSha256"] == sha(&grant)
            && evidence["statement"]["fencedRowSha256"] == self.arguments["request"]["fencedRowSha256"], "reconnect proof originals changed")?;
        let mut arguments = self.arguments.clone(); arguments.as_object_mut().ok_or("reconnect arguments")?.insert("native_evidence".to_owned(),evidence);
        ensure(canonical_ascii_bytes(&arguments)?.len() <= 2*1024*1024,"reconnect complete argument bound")?;
        let value = json!({"apiVersion":HTTP_REQUEST,"operation":self.operation,"arguments":arguments});
        ensure(canonical_ascii_bytes(&value)?.len() <= 3*1024*1024,"reconnect HTTP request bound")?;
        Ok(value)
    }
}
pub(crate) struct Statement(pub(crate) Value);
impl Statement {
    pub(crate) fn validate(&self,now:u64)->Result<(),String> {
        let start=self.0["issuedAtEpochNs"].as_u64().ok_or("reconnect issue time")?;
        let end=self.0["expiresAtEpochNs"].as_u64().ok_or("reconnect expiry")?;
        ensure(start<=now && now<end && end-start<=30_000_000_000,"reconnect statement expired")
    }
    pub(crate) fn canonical(&self)->Result<Vec<u8>,String>{canonical_ascii_bytes(&self.0)}
    pub(crate) fn preimage(&self)->Result<Vec<u8>,String>{let mut raw=SCHEMA.as_bytes().to_vec();raw.push(0);raw.extend(self.canonical()?);Ok(raw)}
}

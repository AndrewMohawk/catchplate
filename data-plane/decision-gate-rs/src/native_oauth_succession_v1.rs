//! Retired-scope succession: exact historical inventory and a distinct purpose.
//! Neither active reconnect nor a caller DTO can supply its consumed claim.
use crate::native_currentness_v1 as current;
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const CHANNEL: &str = "catchplate.nativeOAuthSuccessionChannel/v1";
pub const SCHEMA: &str = "catchplate.nativeOAuthSuccessionStatement/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"catchplate/native-oauth-retired-scope-succession-attestation/v1\0";
pub const SIGN_OPERATION: &str = "nativeOAuthRetiredScopeSuccession.sign/v1";
pub const HTTP_REQUEST: &str = "catchplate.nativeOAuthSuccessionRequest/v1";
pub const HTTP_RESPONSE: &str = "catchplate.nativeOAuthSuccessionResponse/v1";
pub(crate) use crate::native_oauth_refresh_v1::{ensure, sha};
pub use crate::native_oauth_exchange_v1::{origin, Application, BrowserTls, Limits, Windows};

pub(crate) fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    ensure(value.as_object().is_some_and(|map| map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))), "succession fields differ")
}
fn bounded_original(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    ensure(!value.is_empty() && value.len() <= (maximum * 4 + 2) / 3, "succession encoded original bound")?;
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| "succession original encoding")?;
    ensure(!raw.is_empty() && raw.len() <= maximum && URL_SAFE_NO_PAD.encode(&raw) == value, "succession original bound")?;
    Ok(raw)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct SuccessionLimits { pub material_capacity:u64, pub affected_lineage_capacity: u64,
    pub population_capacity:u64, pub history_capacity: u64, pub authorization_max_seconds: u64 }
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct HistoricalApplication { pub enrollment_sha256:String, pub enrollment_root_spki_sha256:String, pub application:Application }
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub api_version: String, pub source_revision: String, pub authority_root_public_key: String,
    pub authority_root_spki_sha256: String, pub authority_configuration_original: String,
    pub control_plane_configuration_digest: String, pub deployment_id: String, pub instance_id: String,
    pub limits: Limits, pub succession_limits: SuccessionLimits, pub windows: Windows,
    pub applications: BTreeMap<String, Application>, pub historical_applications:Vec<HistoricalApplication>, pub recovery_targets: Vec<String>,
    pub callback_origin: String, pub portal_origin: String, pub browser_vsock_port: u32,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == "catchplate.nativeOAuthSuccessionConfiguration/v1"
            && !self.source_revision.is_empty() && self.source_revision.len() <= 128 && !self.source_revision.chars().any(char::is_control)
            && current::identifier(&self.deployment_id) && current::digest(&self.authority_root_spki_sha256)
            && current::digest(&self.control_plane_configuration_digest) && self.instance_id.starts_with("spiffe://")
            && self.instance_id.len() <= 4096 && !self.instance_id.chars().any(char::is_control)
            && self.limits.pending_capacity == 64 && self.limits.revocation_capacity == 64
            && self.succession_limits.material_capacity == 16 && self.succession_limits.population_capacity == 16
            && self.succession_limits.affected_lineage_capacity == 7 && self.succession_limits.history_capacity == 64
            && self.succession_limits.authorization_max_seconds == 3600
            && self.windows.contact_max_seconds == 600 && self.windows.retention_max_seconds == 600
            && self.windows.pending_max_seconds == 3600 && self.windows.operation_max_seconds == 30 && self.windows.recovery_max_seconds == 30
            && self.browser_vsock_port >= 1024 && self.browser_vsock_port < u32::MAX
            && self.callback_origin != self.portal_origin && !self.applications.is_empty() && self.applications.len() <= 2,
            "native succession configuration invalid")?;
        origin(&self.callback_origin)?; origin(&self.portal_origin)?;
        let root = current::bytes32(&self.authority_root_public_key)?;
        let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]; spki.extend(root);
        ensure(sha(&spki) == self.authority_root_spki_sha256, "succession root pin differs")?;
        bounded_original(&self.authority_configuration_original, 1024 * 1024)?;
        for (provider, application) in &self.applications {
            ensure(matches!(provider.as_str(), "google" | "x") && application.material.is_object()
                && !application.tls_roots_pem.is_empty() && application.tls_roots_pem.len() <= 128 * 1024 && application.tls_roots_pem.is_ascii(),
                "succession application inventory invalid")?;
            bounded_original(&application.enrollment_original, 32768)?;
        }
        ensure(self.historical_applications.len()<=16 && self.historical_applications.windows(2)
            .all(|pair|pair[0].enrollment_sha256<pair[1].enrollment_sha256),"succession historical application inventory bound")?;
        for entry in &self.historical_applications {
            let raw=bounded_original(&entry.application.enrollment_original,32768)?;
            ensure(current::digest(&entry.enrollment_sha256) && sha(&raw)==entry.enrollment_sha256
                && current::digest(&entry.enrollment_root_spki_sha256) && entry.application.material.is_object()
                && !entry.application.tls_roots_pem.is_empty() && entry.application.tls_roots_pem.len()<=128*1024
                && entry.application.tls_roots_pem.is_ascii()
                && !self.applications.values().any(|app|app.enrollment_original==entry.application.enrollment_original),
                "succession historical enrollment is not an exact distinct original")?;
        }
        ensure(self.recovery_targets.len() <= 64 && self.recovery_targets.windows(2).all(|pair| pair[0] < pair[1])
            && self.recovery_targets.iter().all(|item| current::uuid(item)), "succession recovery inventory invalid")?;
        ensure(canonical_ascii_bytes(self)?.len() <= 2 * 1024 * 1024, "succession configuration bound")
    }
}

pub struct Prepared { arguments: Value, operation: String, issued: u64, expires: u64,
    config: Configuration, ingress: Arc<BrowserTls> }
pub enum Reply {
    Prepared(Prepared),
    Redirect { exchange_id: String, location: String, name: String, value: String, expires: u64 },
    Complete { exchange_id: String, status: String, custody_sha: Option<String> },
}
impl Reply {
    pub(crate) fn parse(value: Value, config: &Configuration, ingress: &Arc<BrowserTls>) -> Result<Self, String> {
        ensure(value["apiVersion"] == CHANNEL && canonical_ascii_bytes(&value)?.len() <= 8 * 1024 * 1024, "succession helper channel or aggregate differs")?;
        match value["phase"].as_str().ok_or("succession helper phase")? {
            "prepared" => {
                fields(&value, &["apiVersion","phase","operation","arguments","issuedAtEpochNs","expiresAtEpochNs"])?;
                let prepared = Prepared { arguments: value["arguments"].clone(), operation: value["operation"].as_str().ok_or("succession operation")?.to_owned(),
                    issued: value["issuedAtEpochNs"].as_u64().ok_or("succession issue")?, expires: value["expiresAtEpochNs"].as_u64().ok_or("succession expiry")?,
                    config: config.clone(), ingress: Arc::clone(ingress) };
                fields(&prepared.arguments, &["action","resource_id","payload_digest","actor_id","request","approval_id","credential_policy",
                    "enrollment_original","control_plane_configuration_digest","assignment_original","authorization_original"])?;
                ensure(prepared.arguments["action"] == "credential.oauth.measured-succession" && prepared.arguments["approval_id"].is_null()
                    && prepared.arguments["assignment_original"].is_object() && prepared.arguments["credential_policy"].is_object()
                    && prepared.arguments["control_plane_configuration_digest"] == config.control_plane_configuration_digest
                    && current::uuid(prepared.exchange_id()?)
                    && prepared.issued > 0 && prepared.expires > prepared.issued && prepared.expires <= i64::MAX as u64 && prepared.expires - prepared.issued <= 30_000_000_000
                    && prepared.arguments["payload_digest"] == sha(&canonical_ascii_bytes(&prepared.arguments["request"])?), "succession preparation differs")?;
                prepared.provider()?; prepared.check_binding()?;
                ensure(canonical_ascii_bytes(&prepared.arguments)?.len() <= 2 * 1024 * 1024, "succession argument bound")?;
                Ok(Self::Prepared(prepared))
            },
            "authorization-redirect" => {
                fields(&value, &["apiVersion","phase","exchangeId","location","cookieName","cookieValue","expiresAtEpochNs"])?;
                let id = value["exchangeId"].as_str().ok_or("succession exchange")?.to_owned();
                let location = value["location"].as_str().ok_or("succession authorization URL")?.to_owned();
                let name = value["cookieName"].as_str().ok_or("succession cookie name")?.to_owned();
                let nonce = value["cookieValue"].as_str().ok_or("succession cookie value")?.to_owned();
                let expires = value["expiresAtEpochNs"].as_u64().ok_or("succession cookie expiry")?;
                let url = url::Url::parse(&location).map_err(|_| "succession authorization URL")?;
                ensure(current::uuid(&id) && name == format!("__Host-catchplate-native-oauth-{}", id.replace('-', ""))
                    && current::bytes32(&nonce).is_ok() && expires > 0 && expires <= i64::MAX as u64
                    && location.len() <= 16384 && url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
                    && url.fragment().is_none() && url.port_or_known_default() == Some(443)
                    && matches!((url.host_str(),url.path()), (Some("accounts.google.com"),"/o/oauth2/v2/auth") | (Some("twitter.com"),"/i/oauth2/authorize")),
                    "succession redirect or original cookie differs")?;
                Ok(Self::Redirect { exchange_id: id, location, name, value: nonce, expires })
            },
            "complete" => {
                fields(&value, &["apiVersion","phase","exchangeId","status","custodyRowSha256"])?;
                let id = value["exchangeId"].as_str().ok_or("succession exchange")?.to_owned();
                let status = value["status"].as_str().ok_or("succession status")?.to_owned();
                let digest=if value["custodyRowSha256"].is_null(){None}else{Some(value["custodyRowSha256"].as_str().ok_or("succession custody original")?.to_owned())};
                ensure(current::uuid(&id) && digest.as_ref().is_none_or(|value|current::digest(value))
                    && matches!(status.as_str(),"staged"|"cancelled"|"captured-unusable"|"retirement-rejected"|"retirement-unknown"
                        |"observed-fenced"|"observed-prepared"|"observed-claimed"|"observed-captured"|"observed-staged"|"observed-cancelled"|"observed-committed")
                    && (digest.is_some() || matches!(status.as_str(),"retirement-rejected"|"retirement-unknown"|"observed-fenced")),
                    "succession completion differs")?;
                Ok(Self::Complete { exchange_id: id, status, custody_sha: digest })
            },
            _ => Err("unknown native succession helper phase".to_owned()),
        }
    }
}
impl Prepared {
    pub fn operation(&self) -> &str { &self.operation }
    pub fn exchange_id(&self) -> Result<&str,String> { self.arguments["resource_id"].as_str().ok_or_else(|| "succession exchange absent".to_owned()) }
    pub fn material_id(&self)->Option<&str>{self.arguments["request"]["materialId"].as_str()}
    pub fn token_purpose(&self)->Option<&str>{self.arguments["request"]["tokenPurpose"].as_str()}
    pub fn provider(&self) -> Result<&str,String> {
        let original = self.arguments["enrollment_original"].as_str().ok_or("succession enrollment absent")?;
        let count=self.config.applications.values().filter(|app|app.enrollment_original==original).count()
            +self.config.historical_applications.iter().filter(|app|app.application.enrollment_original==original).count();
        let provider=self.arguments["assignment_original"]["providerId"].as_str().ok_or("succession assigned provider absent")?;
        ensure(count==1 && matches!(provider,"google"|"x"),"succession exact enrollment absent")?;
        Ok(provider)
    }
    fn authorization(&self) -> Result<(Vec<u8>,Value),String> {
        let raw = bounded_original(self.arguments["authorization_original"].as_str().ok_or("succession authorization absent")?,128*1024)?;
        let envelope = crate::native_oauth_refresh_v1::response_document(&raw)?;
        fields(&envelope,&["schema","payload","signatureBase64Url"])?;
        ensure(envelope["schema"] == "catchplate.signedOAuthRetiredScopeSuccessionAuthorization/v1"
            && canonical_ascii_bytes(&envelope)? == raw, "succession authorization original differs")?;
        let signature = bounded_original(envelope["signatureBase64Url"].as_str().ok_or("succession authorization signature")?,64)?;
        ensure(signature.len() == 64,"succession authorization signature shape")?;
        Ok((raw,envelope["payload"].clone()))
    }
    fn check_binding(&self) -> Result<(),String> {
        let (_, grant) = self.authorization()?;
        let enrollment = bounded_original(self.arguments["enrollment_original"].as_str().ok_or("succession enrollment absent")?,32768)?;
        fields(&grant,&["schema","sourceRevision","purpose","authorizationId","configurationDigest","deploymentId","credentialId","credentialVersion",
            "credentialRowSha256","generationRowSha256","providerId","providerSubject","providerAccount","clientId","enrollmentSha256","requesterId",
            "scopes","metadataSha256","scope","predecessors","previousHeadSha256","affectedLineages","materials","exchangeOrigins","inventoryRoots",
            "issuedAtEpochNs","admissionExpiresAtEpochNs","contactExpiresAtEpochNs","retentionExpiresAtEpochNs","pendingExpiresAtEpochNs","expiresAtEpochNs"])?;
        ensure(grant["schema"] == "catchplate.oauthRetiredScopeSuccessionAuthorization/v1" && grant["purpose"] == "measured-oauth-retired-scope-succession"
            && grant["authorizationId"] == self.exchange_id()? && grant["providerId"] == self.provider()?
            && grant["sourceRevision"] == self.config.source_revision && grant["configurationDigest"] == self.config.control_plane_configuration_digest
            && grant["deploymentId"] == self.config.deployment_id && grant["requesterId"] == self.arguments["actor_id"]
            && self.arguments["actor_id"].as_str().is_some_and(|actor| actor.starts_with("oidc:") && actor.len() <= 512)
            && current::uuid(grant["credentialId"].as_str().ok_or("succession target absent")?)
            && grant["credentialVersion"].as_u64().is_some_and(|version| version > 0 && version < i64::MAX as u64)
            && grant["issuedAtEpochNs"].as_u64().is_some_and(|start| start > 0 && start <= self.issued)
            && grant["expiresAtEpochNs"].as_u64().is_some_and(|end| self.expires <= end && end <= i64::MAX as u64)
            && current::digest(self.arguments["request"]["scopeRowSha256"].as_str().ok_or("succession fence absent")?), "succession retained family binding differs")?;
        let request = &self.arguments["request"];
        let names: &[&str] = match self.operation.as_str() {
            "oauth.measured-succession.inspect"=>&["scopeRowSha256","materialId","issuedAtEpochNs","expiresAtEpochNs"],
            "oauth.measured-succession.material-claim"=>&["scopeRowSha256","materialId","materialOriginalSha256","ownerNonceSha256"],
            "oauth.measured-succession.contact"=>&["scopeRowSha256","materialId","materialRowSha256","ownerNonce","tokenPurpose","contactRequestSha256"],
            "oauth.measured-succession.finish"=>&["scopeRowSha256","materialId","attemptRowSha256","ownerNonce","tokenPurpose","transportOriginal"],
            "oauth.measured-succession.prepare" => &["exchangeId","stateSha256","browserNonceSha256","pkceVerifierSha256","stateOriginalSha256","stateEnvelope",
                "reservedEnvelope","providerId","redirectUri","credentialName","scopes","metadata","issuedAtEpochNs","contactExpiresAtEpochNs",
                "retentionExpiresAtEpochNs","pendingExpiresAtEpochNs","enrollmentSha256","limits","pkceChallenge","portalOrigin","callbackOrigin","scopeRowSha256"],
            "oauth.measured-succession.claim" => &["exchangeId","exchangeRowSha256","ownerNonceSha256","callbackSha256","callbackEnvelope","codeSha256","contactRequestSha256","limits","scopeRowSha256"],
            "oauth.measured-succession.capture" => &["exchangeId","exchangeRowSha256","ownerNonce","rawResponseSha256","rawResponseEnvelope","issuedMaterialSha256","issuedMaterialEnvelope","receivedAtEpochNs","limits","scopeRowSha256"],
            "oauth.measured-succession.stage" => &["exchangeId","exchangeRowSha256","ownerNonce","tokenSecretSha256","tokenEnvelope","identityRawSha256","identityRawEnvelope","metadata","review","payloadDigest","recoveryRequestDigest","limits","scopeRowSha256"],
            "oauth.measured-succession.recover" => &["scopeRowSha256","materialId","custodyRowSha256","issuedAtEpochNs","expiresAtEpochNs"],
            "oauth.measured-succession.cancel" => &["exchangeId","exchangeRowSha256","callbackSha256","callbackEnvelope","limits","scopeRowSha256"],
            _ => return Err("succession operation is not fixed".to_owned()),
        };
        fields(request,names)?;
        ensure(!matches!(self.operation.as_str(),"oauth.measured-succession.inspect"|"oauth.measured-succession.material-claim"
            |"oauth.measured-succession.contact"|"oauth.measured-succession.finish") || self.material_id().is_some(),
            "succession historical material is required")?;
        if self.operation=="oauth.measured-succession.recover"{ensure(request["materialId"].is_null(),"native recovery observes the complete retained scope")?;}
        let pins=grant["materials"].as_array().ok_or("succession material inventory absent")?;
        ensure(pins.len()<=16,"succession material inventory bound")?;
        if let Some(id)=self.material_id(){
            let selected:Vec<_>=pins.iter().filter(|pin|pin["materialId"]==id).collect();
            ensure(current::uuid(id) && selected.len()==1 && selected[0]["enrollmentSha256"]==sha(&enrollment),"succession historical assignment differs")?;
            if let Some(purpose)=self.token_purpose(){ensure(matches!(purpose,"access"|"refresh")
                && selected[0]["tokenPurposes"].as_array().is_some_and(|values|values.iter().any(|value|value==purpose)),"succession token purpose differs")?;}
        }else{
            ensure(grant["enrollmentSha256"]==sha(&enrollment),"succession current application differs")?;
            if self.operation!="oauth.measured-succession.recover"{
                ensure(request["exchangeId"]==self.exchange_id()? && request["limits"]==serde_json::to_value(&self.config.limits)
                    .map_err(|_|"succession limits encoding")?,"succession fresh request differs")?;
            }
        }
        ensure(self.arguments["assignment_original"]["enrollmentSha256"]==sha(&enrollment),"succession exact assignment pair differs")?;
        if self.operation.ends_with(".prepare") {
            ensure(["contactExpiresAtEpochNs","retentionExpiresAtEpochNs","pendingExpiresAtEpochNs"].iter().all(|name| request[*name] == grant[*name])
                && request["providerId"] == grant["providerId"] && request["scopes"] == grant["scopes"]
                && grant["metadataSha256"] == sha(&canonical_ascii_bytes(&request["metadata"])?), "succession initial grant originals differ")?;
        }
        if self.operation.ends_with(".stage") {
            ensure(request["tokenEnvelope"]["credential_version"].as_u64() == grant["credentialVersion"].as_u64().and_then(|version| version.checked_add(1))
                && request["review"]["succession_credential_id"] == grant["credentialId"]
                && request["review"]["succession_credential_version"] == grant["credentialVersion"]
                && request["review"]["succession_scope_sha256"]==request["scopeRowSha256"]
                && current::digest(request["review"]["succession_material_closure_sha256"].as_str().ok_or("succession closure absent")?)
                && request["recoveryRequestDigest"].is_null(),
                "succession encrypted successor generation differs")?;
        }
        Ok(())
    }
    pub(crate) fn ingress(&self) -> &BrowserTls { &self.ingress }
    pub(crate) fn verify_ingress(&self, expected:&Arc<BrowserTls>, deadline:u64) -> Result<(),String> {
        ensure(Arc::ptr_eq(&self.ingress,expected),"succession preparation belongs to another browser owner")?;
        self.ingress.check(deadline)
    }
    pub(crate) fn statement(&self,boot:&str,key:&str,cp:&str,policy:&str,binary:&str)->Result<Statement,String> {
        self.check_binding()?;
        let enrollment = bounded_original(self.arguments["enrollment_original"].as_str().ok_or("succession enrollment")?,32768)?;
        let (grant,_) = self.authorization()?;
        let mut nonce = [0u8;32];
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new().fill(&mut nonce).map_err(|_|"succession evidence entropy")?;
        let phase=self.operation.rsplit('.').next().ok_or("succession phase")?;
        Ok(Statement(json!({"apiVersion":SCHEMA,"phase":phase,"holderId":current::holder_id(boot,key)?,"bootId":boot,"keyId":key,
            "controlPlaneResponseSigningKeyId":cp,"deploymentId":self.config.deployment_id,"instanceId":self.config.instance_id,
            "providerId":self.provider()?,"enrollmentSha256":sha(&enrollment),"exchangeId":self.exchange_id()?,"inputSha256":sha(&canonical_ascii_bytes(&self.arguments)?),
            "authorizationSha256":sha(&grant),"scopeRowSha256":self.arguments["request"]["scopeRowSha256"],"materialId":self.material_id(),"challenge":URL_SAFE_NO_PAD.encode(nonce),
            "policyHash":policy,"dataPlaneBinarySha256":binary,"callbackOrigin":self.ingress.origin,"portalOrigin":self.config.portal_origin,
            "ingressLeafCertificateSha256":self.ingress.certificate_sha,"ingressLeafSpkiSha256":self.ingress.spki_sha,
            "issuedAtEpochNs":self.issued,"expiresAtEpochNs":self.expires})))
    }
    pub fn wire(&self,evidence:Value)->Result<Value,String> {
        let (grant,_) = self.authorization()?;
        let phase=self.operation.rsplit('.').next().ok_or("succession phase")?;
        ensure(evidence["statement"]["apiVersion"] == SCHEMA
            && evidence["statement"]["phase"] == phase && evidence["statement"]["exchangeId"] == self.exchange_id()?
            && evidence["statement"]["issuedAtEpochNs"] == self.issued && evidence["statement"]["expiresAtEpochNs"] == self.expires
            && evidence["statement"]["inputSha256"] == sha(&canonical_ascii_bytes(&self.arguments)?)
            && evidence["statement"]["authorizationSha256"] == sha(&grant)
            && evidence["statement"]["materialId"]==json!(self.material_id())
            && evidence["statement"]["scopeRowSha256"] == self.arguments["request"]["scopeRowSha256"], "succession proof originals changed")?;
        let mut arguments = self.arguments.clone(); arguments.as_object_mut().ok_or("succession arguments")?.insert("native_evidence".to_owned(),evidence);
        ensure(canonical_ascii_bytes(&arguments)?.len() <= 2*1024*1024,"succession complete argument bound")?;
        let value = json!({"apiVersion":HTTP_REQUEST,"operation":self.operation,"arguments":arguments});
        ensure(canonical_ascii_bytes(&value)?.len() <= 3*1024*1024,"succession HTTP request bound")?;
        Ok(value)
    }
}
pub(crate) struct Statement(pub(crate) Value);
impl Statement {
    pub(crate) fn validate(&self,now:u64)->Result<(),String> {
        let start=self.0["issuedAtEpochNs"].as_u64().ok_or("succession issue time")?;
        let end=self.0["expiresAtEpochNs"].as_u64().ok_or("succession expiry")?;
        ensure(start<=now && now<end && end-start<=30_000_000_000,"succession statement expired")
    }
    pub(crate) fn canonical(&self)->Result<Vec<u8>,String>{canonical_ascii_bytes(&self.0)}
    pub(crate) fn preimage(&self)->Result<Vec<u8>,String>{let mut raw=SCHEMA.as_bytes().to_vec();raw.push(0);raw.extend(self.canonical()?);Ok(raw)}
}

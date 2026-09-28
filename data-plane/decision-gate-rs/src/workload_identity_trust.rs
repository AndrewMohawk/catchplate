//! Independently authorized, immutable standard-PEM workload ingress trust.
//! Native framed-DER custody is a different profile. Files are read only during
//! startup; policy refresh never renews this authority or reloads a trust root.

use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use serde_json::{json, Map, Value};

use crate::{Snapshot, ProxyIngressAttestation, ProxyIngressTlsConfig};
use crate::workload_identity_trust_crypto as crypto;

pub(super) const SOURCE_REVISION: &str =
    "serverware.policyCandidateAuthoritySource/2026-07-30.238";
const PROFILE: &str = "immutable-single-issuer-startup-v1";
const SCHEMA: &str = "serverware.workloadIdentityTrustAuthorization/v1";
const PREFIX: &str = "SERVERWARE_WORKLOAD_IDENTITY_TRUST_";
const NAMES: [&str; 4] = [
    "SERVERWARE_WORKLOAD_IDENTITY_TRUST_AUTHORIZATION",
    "SERVERWARE_WORKLOAD_IDENTITY_TRUST_AUTHORIZER_PUBLIC_KEY",
    "SERVERWARE_WORKLOAD_IDENTITY_TRUST_AUTHORIZER_SHA256",
    "SERVERWARE_WORKLOAD_IDENTITY_TRUST_DEPLOYMENT_ID",
];
const MAX_AUTHORIZATION: u64 = 128 * 1024;
const MAX_KEY: u64 = 16 * 1024;
pub(super) const MAX_BUNDLE: u64 = 64 * 1024;
const MAX_PRINCIPALS_BYTES: usize = 64 * 1024;
const PROCESSING: Duration = Duration::from_secs(30);
const MAX_PERIOD_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

fn refused() -> String { "workload trust authorization or original scope is invalid".to_owned() }

fn epoch_ns() -> Result<u64, String> {
    let value = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| refused())?.as_nanos();
    u64::try_from(value).map_err(|_| refused())
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let result = value.as_object().ok_or_else(refused)?;
    if result.len() != fields.len() || fields.iter().any(|name| !result.contains_key(*name)) {
        return Err(refused());
    }
    Ok(result)
}

fn text<'a>(value: &'a Value, maximum: usize) -> Result<&'a str, String> {
    let result = value.as_str().ok_or_else(refused)?;
    if result.is_empty() || result.len() > maximum || !result.bytes().all(|c| (32..=126).contains(&c)) {
        return Err(refused());
    }
    Ok(result)
}

fn integer(value: &Value) -> Result<u64, String> {
    value.as_u64().filter(|n| *n <= i64::MAX as u64).ok_or_else(refused)
}

fn digest(value: &Value) -> Result<&str, String> {
    let result = text(value, 71)?;
    if !crate::is_sha256_digest(result) { return Err(refused()); }
    Ok(result)
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|_| refused())
}

fn mentioned() -> bool {
    env::vars_os().any(|(name, _)| name.to_string_lossy().starts_with(PREFIX))
}

pub(super) fn reject_native_namespace() -> Result<(), String> {
    if env::args_os().nth(1).is_some() && mentioned() {
        return Err("standard workload trust environment cannot enter native startup".to_owned());
    }
    Ok(())
}

pub(super) struct PendingTrust {
    payload: Value,
    authorization: Arc<[u8]>,
    authorizer_original: Arc<[u8]>,
    authorizer: VerifyingKey,
    authorizer_spki: Vec<u8>,
    deployment: String,
    started: Instant,
    processing_deadline: Instant,
    epoch: u64,
    issued: u64,
    expires: u64,
}

impl PendingTrust {
    fn current(&self) -> Result<(), String> {
        let now = epoch_ns()?;
        if Instant::now() >= self.processing_deadline || now < self.epoch
            || now < self.issued || now >= self.expires {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn admit(self, snapshot: &Snapshot, binary_digest: &str,
        ingress: &ProxyIngressTlsConfig, attestation: &ProxyIngressAttestation,
        bundle: Arc<[u8]>) -> Result<Arc<AdmittedTrust>, String> {
        self.current()?;
        if ingress.native_owner.is_some() || attestation.mode != "mtls"
            || self.authorizer.as_bytes() == snapshot.policy_verifying_key.as_bytes()
            || bundle.is_empty() || bundle.len() as u64 > MAX_BUNDLE {
            return Err(refused());
        }
        let (der, issuer_spki) = crypto::issuer(&bundle, self.issued, self.expires, epoch_ns()?)?;
        self.current()?;
        if issuer_spki == self.authorizer_spki || ingress.client_trust_certificates.len() != 1
            || ingress.client_trust_certificates[0].as_ref() != der.as_slice() {
            return Err(refused());
        }
        let actual_binary = crypto::running_binary(self.processing_deadline)?;
        self.current()?;
        if actual_binary != binary_digest { return Err(refused()); }
        let server_spki = attestation.server_leaf_spki_sha256.as_deref().ok_or_else(refused)?;
        let bundle_digest = crate::sha256_prefixed(&bundle);
        let issuer_digest = crate::sha256_prefixed(&issuer_spki);
        let principals = principal_inventory(snapshot, &issuer_digest)?;
        let scope = json!({"schema":"serverware.workloadIdentityTrustStartupScope/v1",
            "profile":PROFILE, "deploymentId":self.deployment,
            "runtimeBinarySha256":actual_binary, "policyHash":snapshot.hash,
            "serverCertificateSpkiSha256":server_spki, "clientTrustBundleSha256":bundle_digest});
        let configuration = crate::sha256_prefixed(&canonical(&scope)?);
        let expected = [
            ("deploymentId", Value::String(self.deployment.clone())),
            ("configurationDigest", Value::String(configuration.clone())),
            ("runtimeBinarySha256", Value::String(actual_binary)),
            ("serverCertificateSpkiSha256", Value::String(server_spki.to_owned())),
            ("policyHash", Value::String(snapshot.hash.clone())),
            ("bundle", json!({"byteCount":bundle.len(), "bytesDigest":bundle_digest})),
            ("issuer", json!({"certificateDerSha256":crate::sha256_prefixed(&der), "spkiSha256":issuer_digest})),
            ("principals", principals.clone()),
        ];
        if attestation.client_trust_bundle_sha256.as_deref() != Some(bundle_digest.as_str())
            || expected.iter().any(|(field, value)| self.payload.get(*field) != Some(value)) {
            return Err(refused());
        }
        let deadline = self.started.checked_add(Duration::from_nanos(self.expires - self.epoch))
            .ok_or_else(refused)?;
        self.current()?;
        let public = json!({"schema":"serverware.workloadIdentityTrustAdmission/v1", "profile":PROFILE,
            "authorizationSha256":crate::sha256_prefixed(&self.authorization),
            "authorizerSpkiSha256":crate::sha256_prefixed(&self.authorizer_spki),
            "configurationDigest":configuration,
            "issuedAtEpochNs":self.issued, "expiresAtEpochNs":self.expires});
        let result = Arc::new(AdmittedTrust {
            _authorization: self.authorization, _authorizer_original: self.authorizer_original,
            _bundle: bundle, server_config: Arc::clone(&ingress.server_config),
            certificates: Arc::clone(&ingress.client_trust_certificates),
            policy_hash: snapshot.hash.clone(), policy_key: snapshot.policy_verifying_key.clone(),
            issuer_spki: issuer_digest, principals, public, issued: self.issued,
            expires: self.expires, deadline, pid: std::process::id(),
            last_epoch: Mutex::new(self.epoch), stopped: AtomicBool::new(false),
        });
        result.require_live()?;
        Ok(result)
    }
}

pub(super) fn prepare(is_production: bool) -> Result<Option<PendingTrust>, String> {
    if !mentioned() {
        return if is_production { Err("production requires independent workload trust authorization".to_owned()) }
            else { Ok(None) };
    }
    for (name, _) in env::vars_os().filter(|(name, _)| name.to_string_lossy().starts_with(PREFIX)) {
        if !NAMES.iter().any(|expected| name == *expected) { return Err(refused()); }
    }
    let values = NAMES.iter().map(|name| env::var(name).map_err(|_| refused()))
        .collect::<Result<Vec<_>, _>>()?;
    if values.iter().any(|value| value.is_empty() || value.trim() != value || value.chars().any(char::is_control))
        || !crate::is_sha256_digest(&values[2]) || values[3].len() > 128
        || !values[3].bytes().enumerate().all(|(i, c)| c.is_ascii_alphanumeric()
            || (i > 0 && b"._:-".contains(&c))) {
        return Err(refused());
    }
    let started = Instant::now();
    let epoch = epoch_ns()?;
    let processing_deadline = started.checked_add(PROCESSING).ok_or_else(refused)?;
    // Fixed public originals: authorization128KiB + key16KiB + bundle64KiB.
    // Binary measurement is separately streamed, not a new 64MiB Python ledger.
    let key = crate::read_proxy_tls_file_snapshot(&PathBuf::from(&values[1]),
        "workload trust authorizer", MAX_KEY, false)?;
    if Instant::now() >= processing_deadline || crate::sha256_prefixed(&key) != values[2] {
        return Err(refused());
    }
    let (authorizer, authorizer_spki) = crypto::authorizer(&key)?;
    let authorization = crate::read_proxy_tls_file_snapshot(&PathBuf::from(&values[0]),
        "workload trust authorization", MAX_AUTHORIZATION, false)?;
    if Instant::now() >= processing_deadline { return Err(refused()); }
    let envelope = crate::strict_json_value_from_slice(&authorization).map_err(|_| refused())?;
    object(&envelope, &["schema", "payload", "signature"])?;
    if envelope["schema"] != "serverware.signedWorkloadIdentityTrustAuthorization/v1"
        || canonical(&envelope)? != authorization { return Err(refused()); }
    let payload = envelope["payload"].clone();
    object(&payload, &["schema", "sourceRevision", "purpose", "trustMode", "profile",
        "authorizerSpkiSha256", "deploymentId", "configurationDigest", "runtimeBinarySha256",
        "serverCertificateSpkiSha256", "policyHash", "bundle", "issuer", "principals",
        "issuedAtEpochNs", "expiresAtEpochNs"])?;
    if payload["schema"] != SCHEMA || payload["sourceRevision"] != SOURCE_REVISION
        || payload["purpose"] != "workload-identity-ingress-trust"
        || payload["trustMode"] != "trusted-host-local" || payload["profile"] != PROFILE
        || digest(&payload["authorizerSpkiSha256"])? != crate::sha256_prefixed(&authorizer_spki) {
        return Err(refused());
    }
    for field in ["configurationDigest", "runtimeBinarySha256", "serverCertificateSpkiSha256", "policyHash"] {
        digest(&payload[field])?;
    }
    object(&payload["bundle"], &["byteCount", "bytesDigest"])?;
    let size = integer(&payload["bundle"]["byteCount"])?;
    if size == 0 || size > MAX_BUNDLE { return Err(refused()); }
    digest(&payload["bundle"]["bytesDigest"])?;
    object(&payload["issuer"], &["certificateDerSha256", "spkiSha256"])?;
    digest(&payload["issuer"]["certificateDerSha256"])?;
    digest(&payload["issuer"]["spkiSha256"])?;
    let issued = integer(&payload["issuedAtEpochNs"])?;
    let expires = integer(&payload["expiresAtEpochNs"])?;
    if issued == 0 || issued > epoch || expires <= epoch || expires <= issued || expires - issued > MAX_PERIOD_NS {
        return Err(refused());
    }
    let signature_text = text(&envelope["signature"], 94)?.strip_prefix("ed25519:").ok_or_else(refused)?;
    let signature_bytes = general_purpose::URL_SAFE_NO_PAD.decode(signature_text).map_err(|_| refused())?;
    if signature_bytes.len() != 64 || general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes) != signature_text {
        return Err(refused());
    }
    let raw_signature: [u8; 64] = signature_bytes.try_into().map_err(|_| refused())?;
    let mut signed = SCHEMA.as_bytes().to_vec();
    signed.push(0);
    signed.extend_from_slice(&canonical(&payload)?);
    authorizer.verify_strict(&signed, &Signature::from_bytes(&raw_signature)).map_err(|_| refused())?;
    let pending = PendingTrust { payload, authorization: authorization.into(), authorizer_original: key.into(),
        authorizer, authorizer_spki, deployment: values[3].clone(), started, processing_deadline,
        epoch, issued, expires };
    pending.current()?;
    Ok(Some(pending))
}

fn principal_inventory(snapshot: &Snapshot, issuer: &str) -> Result<Value, String> {
    let mut principals = Vec::new();
    for principal in &snapshot.principals {
        let Some(policy) = principal.mtls.as_ref() else { continue; };
        text(&Value::String(principal.id.clone()), 512)?;
        if policy.issuer_spki_sha256.as_deref() != Some(issuer) { return Err(refused()); }
        let mut mtls = Map::new();
        mtls.insert("verifiedByTrustedIngress".to_owned(), Value::Bool(true));
        mtls.insert("issuerSpkiSha256".to_owned(), Value::String(issuer.to_owned()));
        for (name, values) in [("sanSpiffeIds", &policy.san_spiffe_ids),
            ("sanDnsNames", &policy.san_dns_names), ("sanUris", &policy.san_uris)] {
            if values.is_empty() { continue; }
            let mut sorted = values.clone();
            sorted.sort();
            if sorted.len() > 32 || sorted.windows(2).any(|pair| pair[0] == pair[1])
                || sorted.iter().any(|value| !value.is_ascii() || value.bytes().any(|c| !(32..=126).contains(&c))) {
                return Err(refused());
            }
            mtls.insert(name.to_owned(), json!(sorted));
        }
        for (name, value) in [("certificateSha256", &policy.certificate_sha256), ("spkiSha256", &policy.spki_sha256)] {
            if let Some(value) = value { mtls.insert(name.to_owned(), Value::String(value.clone())); }
        }
        if mtls.len() == 2 { return Err(refused()); }
        principals.push(json!({"principalId":principal.id, "mtls":mtls}));
    }
    principals.sort_by(|a, b| a["principalId"].as_str().cmp(&b["principalId"].as_str()));
    if principals.is_empty() || principals.len() > 64
        || principals.windows(2).any(|pair| pair[0]["principalId"] == pair[1]["principalId"]) {
        return Err(refused());
    }
    let value = Value::Array(principals);
    if canonical(&json!({"schema":"serverware.workloadIdentityTrustPrincipals/v1", "principals":value}))?.len()
        > MAX_PRINCIPALS_BYTES { return Err(refused()); }
    Ok(value)
}

pub(super) struct AdmittedTrust {
    _authorization: Arc<[u8]>,
    _authorizer_original: Arc<[u8]>,
    _bundle: Arc<[u8]>,
    server_config: Arc<ServerConfig>,
    certificates: Arc<Vec<CertificateDer<'static>>>,
    policy_hash: String,
    policy_key: VerifyingKey,
    issuer_spki: String,
    principals: Value,
    public: Value,
    issued: u64,
    expires: u64,
    deadline: Instant,
    pid: u32,
    last_epoch: Mutex<u64>,
    stopped: AtomicBool,
}

impl AdmittedTrust {
    fn sample_live(&self) -> Option<(u64, Instant)> {
        if self.stopped.load(Ordering::Acquire) { return None; }
        let sampled = (|| {
            let mut last = self.last_epoch.lock().ok()?;
            if self.stopped.load(Ordering::Acquire) { return None; }
            // Sample under the lock: an older concurrent sample must not look
            // like a clock rollback merely because another thread ran first.
            let now = match epoch_ns() {
                Ok(now) => now,
                Err(_) => { self.stopped.store(true, Ordering::Release); return None; }
            };
            let monotonic = Instant::now();
            if self.pid != std::process::id() || monotonic >= self.deadline
                || now < *last || now < self.issued || now >= self.expires {
                self.stopped.store(true, Ordering::Release);
                return None;
            }
            *last = now;
            Some((now, monotonic))
        })();
        if sampled.is_none() { self.stopped.store(true, Ordering::Release); }
        sampled
    }

    pub(super) fn is_live(&self) -> bool {
        self.sample_live().is_some()
    }

    pub(super) fn require_live(&self) -> Result<(), String> {
        if self.is_live() { Ok(()) } else { Err("workload ingress trust authority has expired or lost continuity".to_owned()) }
    }

    pub(super) fn supports_window(&self, window: Duration) -> bool {
        let Some((now, monotonic)) = self.sample_live() else { return false; };
        !self.stopped.load(Ordering::Acquire)
            && monotonic.checked_add(window).is_some_and(|end| end < self.deadline)
            && u128::from(now).checked_add(window.as_nanos())
                .is_some_and(|end| end < u128::from(self.expires))
    }

    pub(super) fn check_ingress(&self, ingress: &ProxyIngressTlsConfig) -> Result<(), String> {
        self.require_live()?;
        if !Arc::ptr_eq(&self.server_config, &ingress.server_config)
            || !Arc::ptr_eq(&self.certificates, &ingress.client_trust_certificates)
            || ingress.client_trust_bundle_original.as_ref()
                .is_none_or(|original| !Arc::ptr_eq(&self._bundle, original)) {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn check_snapshot(&self, snapshot: &Snapshot) -> Result<(), String> {
        self.require_live()?;
        if snapshot.hash != self.policy_hash || snapshot.policy_verifying_key != self.policy_key
            || principal_inventory(snapshot, &self.issuer_spki)? != self.principals {
            return Err("policy change requires separately authorized workload trust and restart".to_owned());
        }
        Ok(())
    }

    pub(super) fn public_value(&self) -> Value { self.public.clone() }
}

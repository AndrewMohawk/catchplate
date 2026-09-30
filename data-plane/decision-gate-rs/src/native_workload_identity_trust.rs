//! Cold native root-install authorization. It is not standard PEM trust,
//! a quote verdict, issuance permission, rotation or a renewable lease.
use super::*;
use super::workload_identity_trust_crypto as crypto;
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const MAX_AUTHORIZATION: usize = 128 * 1024;
const SCHEMA: &str = "serverware.nativeWorkloadIdentityTrustAuthorization/v1";
const PROFILE: &str = "immutable-native-framed-der-startup-v1";
const PERIOD: u64 = 24 * 60 * 60 * 1_000_000_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Authorizer { public_key_pem: String, public_key_pem_sha256: String }

fn refused() -> String { "native workload trust original or retained scope is invalid".into() }
fn require(value: bool) -> Result<(), String> { if value { Ok(()) } else { Err(refused()) } }
fn exact<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a serde_json::Map<String, Value>, String> {
    let object = value.as_object().ok_or_else(refused)?;
    require(object.len() == fields.len() && fields.iter().all(|name| object.contains_key(*name)))?;
    Ok(object)
}
fn bytes(value: &Value) -> Result<Vec<u8>, String> { serde_json::to_vec(value).map_err(|_| refused()) }
fn number(value: &Value) -> Result<u64, String> {
    value.as_u64().filter(|n| *n > 0 && *n <= i64::MAX as u64).ok_or_else(refused)
}
fn printable(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|c| (32..=126).contains(&c))
}
fn clocks() -> Result<(u64, u64), String> {
    let wall = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| refused())?.as_nanos();
    let mut boot: libc::timespec = unsafe { std::mem::zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot) } == 0
        && boot.tv_sec >= 0 && (0..1_000_000_000).contains(&boot.tv_nsec))?;
    let wall = u64::try_from(wall).map_err(|_| refused())?;
    let boot = u64::try_from(boot.tv_sec as u128 * 1_000_000_000 + boot.tv_nsec as u128)
        .map_err(|_| refused())?;
    require(wall > 0 && boot > 0)?;
    Ok((wall, boot))
}

impl Authorizer {
    fn key(&self) -> Result<(VerifyingKey, Vec<u8>), String> {
        require(self.public_key_pem.len() <= 16 * 1024
            && is_sha256_digest(&self.public_key_pem_sha256)
            && sha256_prefixed(self.public_key_pem.as_bytes()) == self.public_key_pem_sha256)?;
        crypto::authorizer(self.public_key_pem.as_bytes())
    }
    pub(super) fn exclude_original(&self, original: &str) -> Result<(), String> {
        let (key, _) = self.key()?;
        let (other, _) = verifying_key_from_spki_pem_text(original, "native trust exclusion")?;
        require(key != other)
    }
}

/// The complete existing normalized policy inventory, with each explicit
/// issuer selector joined to the actual ordered native root inventory.
fn principals(snapshot: &Snapshot, issuers: &HashSet<String>) -> Result<Value, String> {
    let mut entries = Vec::new();
    for principal in &snapshot.principals {
        let Some(policy) = principal.mtls.as_ref() else { continue; };
        require(printable(&principal.id, 512))?;
        let issuer = policy.issuer_spki_sha256.as_ref().ok_or_else(refused)?;
        require(issuers.contains(issuer))?;
        let mut mtls = serde_json::Map::new();
        mtls.insert("verifiedByTrustedIngress".into(), Value::Bool(true));
        mtls.insert("issuerSpkiSha256".into(), Value::String(issuer.clone()));
        for (name, values, maximum) in [("sanSpiffeIds", &policy.san_spiffe_ids, 2048),
            ("sanDnsNames", &policy.san_dns_names, 253), ("sanUris", &policy.san_uris, 2048)] {
            if values.is_empty() { continue; }
            let mut values = values.clone();
            values.sort();
            require(values.len() <= 32 && values.windows(2).all(|p| p[0] != p[1])
                && values.iter().all(|s| printable(s, maximum)))?;
            mtls.insert(name.into(), json!(values));
        }
        for (name, value) in [("certificateSha256", &policy.certificate_sha256),
            ("spkiSha256", &policy.spki_sha256)] {
            if let Some(value) = value { mtls.insert(name.into(), Value::String(value.clone())); }
        }
        require(mtls.len() > 2)?;
        entries.push(json!({"principalId":principal.id,"mtls":mtls}));
    }
    entries.sort_by(|a, b| a["principalId"].as_str().cmp(&b["principalId"].as_str()));
    require((1..=64).contains(&entries.len())
        && entries.windows(2).all(|p| p[0]["principalId"] != p[1]["principalId"]))?;
    let result = Value::Array(entries);
    require(bytes(&json!({"schema":"serverware.workloadIdentityTrustPrincipals/v1",
        "principals":result}))?.len() <= 64 * 1024)?;
    Ok(result)
}

pub(super) struct Pending {
    original: Arc<[u8]>, authorizer_original: Arc<[u8]>, key: VerifyingKey,
    payload: Value, roots: Vec<Vec<u8>>, issuers: HashSet<String>,
    pid: u32, wall: u64, boot: u64, issued: u64, expires: u64, deadline: u64,
}

impl Pending {
    pub(super) fn prepare(authorizer: Authorizer, original: Vec<u8>,
        configuration: &str, launch: &[u8], launch_pin: &str, deployment: &str,
        instance: &str, parameters: &native_startup::NativeStartupParametersV1,
        checkpoint: &PolicyHighWater) -> Result<Self, String> {
        let (wall, boot) = clocks()?;
        require(!original.is_empty() && original.len() <= MAX_AUTHORIZATION && original.is_ascii()
            && printable(deployment, 128) && deployment.bytes().enumerate().all(|(i, c)|
                c.is_ascii_alphanumeric() || (i > 0 && b"._:-".contains(&c)))
            && printable(instance, 1024) && sha256_prefixed(launch) == launch_pin
            && boot < parameters.deadline_boottime_ns)?;
        let (key, spki) = authorizer.key()?;
        require(key != parameters.control_plane_response_key)?;
        let envelope = strict_json_value_from_slice(&original).map_err(|_| refused())?;
        exact(&envelope, &["schema", "payload", "signature"])?;
        require(envelope["schema"] == "serverware.signedNativeWorkloadIdentityTrustAuthorization/v1"
            && bytes(&envelope)? == original)?;
        let payload = envelope["payload"].clone();
        exact(&payload, &["schema","sourceRevision","purpose","profile","authorizerSpkiSha256",
            "deploymentId","instanceId","configurationSha256","launchSha256","releaseRecordSha256",
            "policyHash","policySequence","rollbackEpoch","deadlineBoottimeNs","clientTrustProfile",
            "clientTrustBundleSha256","issuers","principals","issuedAtEpochNs","expiresAtEpochNs"])?;
        let launch = strict_json_value_from_slice(launch).map_err(|_| refused())?;
        let issued = number(&payload["issuedAtEpochNs"])?;
        let expires = number(&payload["expiresAtEpochNs"])?;
        require(issued <= wall && wall < expires && expires > issued && expires - issued <= PERIOD
            && i128::from(issued) >= parameters.ca_not_before.unix_timestamp_nanos()
            && i128::from(expires) <= parameters.ca_not_after.unix_timestamp_nanos()
            && i128::from(issued) >= parameters.ingress_not_before.unix_timestamp_nanos()
            && i128::from(expires) <= parameters.ingress_not_after.unix_timestamp_nanos())?;
        let expected = [
            ("schema", json!(SCHEMA)), ("sourceRevision", json!(workload_identity_trust::SOURCE_REVISION)),
            ("purpose", json!("native-workload-identity-ingress-trust")), ("profile", json!(PROFILE)),
            ("authorizerSpkiSha256", json!(sha256_prefixed(&spki))),
            ("deploymentId", json!(deployment)), ("instanceId", json!(instance)),
            ("configurationSha256", json!(configuration)), ("launchSha256", json!(launch_pin)),
            ("releaseRecordSha256", launch["releaseRecordSha256"].clone()),
            ("policyHash", json!(checkpoint.policy_hash)), ("policySequence", json!(checkpoint.sequence)),
            ("rollbackEpoch", json!(checkpoint.rollback_epoch)),
            ("deadlineBoottimeNs", json!(parameters.deadline_boottime_ns)),
            ("clientTrustProfile", json!("native-framed-der-v1")),
        ];
        require(expected.iter().all(|(name, value)| payload.get(*name) == Some(value)))?;
        for name in ["policySequence", "rollbackEpoch", "deadlineBoottimeNs"] { number(&payload[name])?; }
        let roots = &parameters.ingress_client_roots;
        require((1..=32).contains(&roots.len()))?;
        let mut total = 0usize;
        let mut unique = HashSet::new();
        let mut issuers = HashSet::new();
        let mut inventory = Vec::new();
        let mut framed = Sha256::new();
        framed.update(b"serverware/mutual-tls-client-trust/v1\0");
        framed.update((roots.len() as u32).to_be_bytes());
        for root in roots {
            total = total.checked_add(root.len()).ok_or_else(refused)?;
            require(!root.is_empty() && root.len() <= 64 * 1024 && total <= 1024 * 1024
                && unique.insert(root.as_slice()))?;
            let (_, issuer_spki) = crypto::issuer_der(root, issued, expires, wall)?;
            require(issuer_spki != spki)?;
            let issuer_id = sha256_prefixed(&issuer_spki);
            issuers.insert(issuer_id.clone());
            inventory.push(json!({"certificateDerSha256":sha256_prefixed(root), "spkiSha256":issuer_id}));
            framed.update((root.len() as u64).to_be_bytes());
            framed.update(root);
        }
        require(payload["issuers"] == json!(inventory)
            && payload["clientTrustBundleSha256"] == format!("sha256:{}", hex::encode(framed.finalize())))?;
        let signature = envelope["signature"].as_str().and_then(|s| s.strip_prefix("ed25519:"))
            .ok_or_else(refused)?;
        let signature = decode_canonical_base64url_exact(signature, 64, "native trust signature")?;
        let signature = ed25519_dalek::Signature::from_slice(&signature).map_err(|_| refused())?;
        let mut signed = SCHEMA.as_bytes().to_vec();
        signed.push(0); signed.extend_from_slice(&bytes(&payload)?);
        key.verify_strict(&signed, &signature).map_err(|_| refused())?;
        let pending = Self { original: original.into(), authorizer_original: authorizer.public_key_pem.into_bytes().into(),
            key, payload, roots: roots.clone(), issuers, pid: std::process::id(), wall, boot,
            issued, expires, deadline: parameters.deadline_boottime_ns };
        pending.current()?;
        Ok(pending)
    }

    fn current(&self) -> Result<(), String> {
        let (wall, boot) = clocks()?;
        require(std::process::id() == self.pid && wall >= self.wall && boot >= self.boot
            && self.issued <= wall && wall < self.expires && boot < self.deadline)
    }

    pub(super) fn admit(self, state: &GateState, ingress: &QuotedMutualTlsIngressV1,
        lifetime: Arc<NativeRuntimeLifetimeV1>) -> Result<Arc<Admitted>, String> {
        self.current()?;
        lifetime.check()?;
        require(lifetime.deadline() == self.deadline && ingress.deadline() == self.deadline)?;
        ingress.verify_live(self.deadline)?;
        let snapshot = current_snapshot(state);
        require(snapshot_is_active(state, &snapshot) && snapshot.policy_verifying_key != self.key
            && self.payload["policyHash"] == snapshot.hash
            && self.payload["policySequence"] == snapshot.policy_sequence
            && self.payload["rollbackEpoch"] == snapshot.rollback_epoch
            && self.payload["instanceId"] == state.server_instance_id.as_deref().ok_or_else(refused)?
            && principals(&snapshot, &self.issuers)? == self.payload["principals"])?;
        let (proof, _) = verifying_key_from_spki_pem_text(&state.response_proof_public_key_pem, "native trust proof exclusion")?;
        require(proof != self.key)?;
        let tls = ingress.tls();
        let (_, spki) = crypto::authorizer(&self.authorizer_original)?;
        require(tls.client_trust_certificates() == self.roots.as_slice()
            && tls.leaf_public_key_spki_der() != spki.as_slice())?;
        // The native runtime independently verifies this generated leaf/CA
        // cohort; this additional exclusion reads its actual certificate CA.
        for certificate in tls.certificate_chain() {
            let certificate = parse_exact_x509_certificate(certificate, "native trust TLS exclusion")?;
            require(certificate.tbs_certificate.subject_pki.raw != spki.as_slice())?;
        }
        self.current()?;
        let result = Arc::new(Admitted { _original: self.original, _authorizer_original: self.authorizer_original,
            snapshot, server_config: tls.server_config(), roots: self.roots, issuers: self.issuers,
            payload: self.payload, lifetime, pid: self.pid, issued: self.issued, expires: self.expires,
            deadline: self.deadline, clocks: Mutex::new((self.wall, self.boot)), failed: AtomicBool::new(false) });
        result.require_live()?;
        Ok(result)
    }
}

pub(super) struct Admitted {
    _original: Arc<[u8]>, _authorizer_original: Arc<[u8]>, snapshot: Arc<Snapshot>,
    server_config: Arc<ServerConfig>, roots: Vec<Vec<u8>>, issuers: HashSet<String>, payload: Value,
    lifetime: Arc<NativeRuntimeLifetimeV1>, pid: u32, issued: u64, expires: u64, deadline: u64,
    clocks: Mutex<(u64, u64)>, failed: AtomicBool,
}

impl Admitted {
    fn sample(&self) -> Result<(u64, u64), String> {
        let result = (|| {
            require(!self.failed.load(Ordering::Acquire) && self.pid == std::process::id())?;
            let mut previous = self.clocks.lock().map_err(|_| refused())?;
            self.lifetime.check()?;
            let now = clocks()?;
            require(!self.failed.load(Ordering::Acquire) && now.0 >= previous.0 && now.1 >= previous.1
                && self.issued <= now.0 && now.0 < self.expires && now.1 < self.deadline)?;
            *previous = now;
            Ok(now)
        })();
        if result.is_err() { self.failed.store(true, Ordering::Release); }
        result
    }
    pub(super) fn require_live(&self) -> Result<(), String> { self.sample().map(|_| ()) }
    pub(super) fn is_current(&self, state: &GateState) -> bool {
        if self.require_live().is_err() { return false; }
        let Ok(snapshot) = state.snapshot.try_read() else { return false; };
        let same = Arc::ptr_eq(&snapshot, &self.snapshot) && snapshot.epoch == self.snapshot.epoch;
        if !same { self.failed.store(true, Ordering::Release); }
        same
    }
    pub(super) fn supports_window(&self, window: Duration) -> bool {
        let Ok((wall, boot)) = self.sample() else { return false; };
        let Ok(nanos) = u64::try_from(window.as_nanos()) else { return false; };
        wall.checked_add(nanos).is_some_and(|end| end < self.expires)
            && boot.checked_add(nanos).is_some_and(|end| end < self.deadline)
    }
    pub(super) fn check_snapshot(&self, snapshot: &Snapshot) -> Result<(), String> {
        self.require_live()?;
        require(snapshot.hash == self.snapshot.hash && snapshot.policy_sequence == self.snapshot.policy_sequence
            && snapshot.rollback_epoch == self.snapshot.rollback_epoch
            && snapshot.policy_verifying_key == self.snapshot.policy_verifying_key
            && principals(snapshot, &self.issuers)? == self.payload["principals"])
    }
    pub(super) fn check_quote(&self, state: &GateState, owner: &QuotedMutualTlsIngressV1) -> Result<(), String> {
        self.require_live()?;
        // Enrollment/principal callers may already hold a policy read guard.
        // Never block behind a writer while recursively acquiring that lock.
        let snapshot = state.snapshot.try_read().map_err(|_| refused())?;
        require(Arc::ptr_eq(&snapshot, &self.snapshot) && snapshot.epoch == self.snapshot.epoch)?;
        self.check_snapshot(&snapshot)?;
        owner.verify_live(self.deadline)?;
        require(owner.deadline() == self.deadline
            && Arc::ptr_eq(&self.server_config, &owner.tls().server_config())
            && owner.tls().client_trust_certificates() == self.roots.as_slice())
    }
    pub(super) fn check_ingress(&self, state: &GateState, ingress: &ProxyIngressTlsConfig) -> Result<(), String> {
        let owner = ingress.native_owner.as_ref().ok_or_else(refused)?;
        self.check_quote(state, owner)?;
        require(ingress.workload_identity_trust.is_none() && ingress.client_trust_bundle_original.is_none()
            && Arc::ptr_eq(&self.server_config, &ingress.server_config)
            && ingress.client_trust_certificates.len() == self.roots.len()
            && ingress.client_trust_certificates.iter().zip(&self.roots).all(|(a, b)| a.as_ref() == b.as_slice()))
    }
}

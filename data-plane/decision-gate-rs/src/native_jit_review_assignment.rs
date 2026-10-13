//! Independent signed JIT-purpose selection, never a static/audit assignment.
use super::*;
use std::{sync::Mutex, time::{SystemTime, UNIX_EPOCH}};

const PAYLOAD: &str = "serverware.nativeJitReviewAssignment/v1";
const MAX_INTERVAL: u64 = 86_400_000_000_000;
const DYNAMIC: &[&str] = &["holderId", "bootId", "keyId", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256", "expectedModuleId"];
const ASSIGNMENT: &[&str] = &["holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
    "caPublicKeySpkiSha256", "expectedBinaryDigest", "expectedPcrs", "expectedEif", "expectedModuleId",
    "maxAgeSeconds", "futureSkewSeconds", "instanceId", "secretKekId"];

pub(super) fn trust(value: &Value) -> Result<(), String> {
    fields(value, &["apiVersion", "awsNitroRootCertificatesPem", "awsNitroCrlsDerBase64url", "nitroCertificateProfile"])?;
    require(value["apiVersion"] == "serverware.nativeJitReviewNativeTrustRoots/v1"
        && value["awsNitroCrlsDerBase64url"] == json!([]) && canonical_ascii_bytes(value)?.len() <= 128 * 1024)?;
    let roots = value["awsNitroRootCertificatesPem"].as_array().filter(|v| !v.is_empty() && v.len() <= 16).ok_or("JIT trust roots")?;
    let mut pins = BTreeSet::new();
    for value in roots {
        let pem = value.as_str().filter(|v| v.is_ascii() && !v.is_empty() && v.len() <= 64 * 1024).ok_or("JIT trust certificate")?;
        let (tail, cert) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| "JIT trust PEM")?;
        require(tail.is_empty() && cert.label == "CERTIFICATE")?;
        let (tail, parsed) = x509_parser::parse_x509_certificate(&cert.contents).map_err(|_| "JIT trust DER")?;
        require(tail.is_empty() && parsed.basic_constraints().map_err(|_| "JIT trust CA")?.is_some_and(|v| v.value.ca)
            && pins.insert(sha(&cert.contents)))?;
        let encoded = STANDARD.encode(&cert.contents);
        let mut canonical = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) { canonical.push_str(std::str::from_utf8(line).map_err(|_| "JIT PEM")?); canonical.push('\n'); }
        canonical.push_str("-----END CERTIFICATE-----\n"); require(canonical == pem)?;
    }
    let profile = &value["nitroCertificateProfile"];
    fields(profile, &["profileId", "allowedLeafExtendedKeyUsageOids"])?;
    require(profile["profileId"] == "aws-nitro-attestation-pki-native-v1")?;
    let oids = profile["allowedLeafExtendedKeyUsageOids"].as_array().filter(|v| v.len() <= 32).ok_or("JIT OIDs")?;
    let mut previous = None;
    for oid in oids {
        let oid = oid.as_str().filter(|v| v.len() <= 128 && v.contains('.')
            && v.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))).ok_or("JIT OID")?;
        require(previous.is_none_or(|prior| prior < oid))?; previous = Some(oid);
    }
    Ok(())
}

pub(super) fn clocks() -> Result<(u64, u64), String> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } == 0
        && value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec))?;
    let boot = (value.tv_sec as u64).checked_mul(1_000_000_000).and_then(|v| v.checked_add(value.tv_nsec as u64)).ok_or("JIT BOOTTIME overflow")?;
    // BOOTTIME first; this conversion may only shorten the original interval.
    let epoch = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "JIT wall clock")?.as_nanos()).map_err(|_| "JIT wall overflow")?;
    require(epoch > 0 && epoch <= i64::MAX as u64 && boot > 0)?; Ok((epoch, boot))
}

pub(super) struct Admission {
    pub(super) original: String, pub(super) expires: u64, pub(super) deadline: u64,
    issued: u64, pid: u32, observation: Mutex<(u64, u64, bool)>,
}
impl Admission {
    pub(super) fn check(&self) -> Result<(), String> {
        let mut held = self.observation.lock().map_err(|_| "JIT assignment observation poisoned")?;
        let result = (|| {
            let (wall, boot) = clocks()?;
            require(held.2 && self.pid == std::process::id() && held.0 <= wall && held.1 <= boot
                && self.issued <= wall && wall < self.expires && boot < self.deadline)?;
            *held = (wall, boot, true); Ok(())
        })();
        if result.is_err() { held.2 = false; } result
    }
}

// Signature and cold-scope validation only. The returned graph is not an Owner
// or admission: admit below must join the actual identity and original clock.
pub(super) fn signed_original(config: &Configuration, original: &[u8], wall: u64) -> Result<Value, String> {
    config.validate()?;
    require(wall > 0 && !original.is_empty() && original.len() <= MAX_ASSIGNMENT && original.is_ascii())?;
    // Existing bounded duplicate-rejecting integer-only parser. This input is
    // a signed assignment, never the float/bigint parent request.
    let value = crate::native_secret_broker_v1::jit_review::assignment_document(original)?;
    fields(&value, &["schema", "payload", "signature"])?;
    require(value["schema"] == SIGNED_ASSIGNMENT && canonical_ascii_bytes(&value)? == original)?;
    let payload = &value["payload"];
    fields(payload, &["schema", "sourceContractDigest", "controlPlaneConfigurationDigest", "deploymentId",
        "assignment", "issuedAtEpochNs", "expiresAtEpochNs"])?;
    let policy = &config.native_jit_review_custody_policy;
    let issued = payload["issuedAtEpochNs"].as_u64().ok_or("JIT assignment issue")?;
    let expires = payload["expiresAtEpochNs"].as_u64().ok_or("JIT assignment expiry")?;
    require(payload["schema"] == PAYLOAD && payload["sourceContractDigest"] == policy.source_contract_digest
        && payload["controlPlaneConfigurationDigest"] == config.control_plane_configuration_digest
        && payload["deploymentId"] == policy.deployment_id && issued > 0 && issued <= wall && wall < expires
        && expires <= i64::MAX as u64 && expires - issued <= MAX_INTERVAL)?;
    let item = &payload["assignment"]; fields(item, ASSIGNMENT)?;
    let selected = item.as_object().ok_or("JIT assignment object")?.iter().filter(|(name, _)| !DYNAMIC.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone())).collect::<serde_json::Map<String, Value>>();
    let boot = item["bootId"].as_str().ok_or("JIT assignment boot")?;
    let key = item["keyId"].as_str().ok_or("JIT assignment key")?;
    require(Value::Object(selected) == serde_json::to_value(&policy.target).map_err(|_| "JIT target encoding")?
        && item["holderId"] == current::holder_id(boot, key)?
        && policy.assignment_authorizer.public_key_spki_sha256 != key
        && key != policy.target.control_plane_response_signing_key_id
        && item["expectedModuleId"].as_str().is_some_and(|v| text(v, 256)))?;
    for name in ["releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256"] {
        require(item[name].as_str().is_some_and(current::digest))?;
    }
    let encoded = value["signature"].as_str().filter(|v| v.len() == 86).ok_or("JIT assignment signature")?;
    let signature = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| "JIT assignment signature encoding")?;
    require(signature.len() == 64 && URL_SAFE_NO_PAD.encode(&signature) == encoded)?;
    let raw = canonical_ascii_bytes(payload)?;
    let mut hash = Sha256::new(); hash.update(SIGNED_ASSIGNMENT.as_bytes()); hash.update([0]);
    hash.update((raw.len() as u64).to_be_bytes()); hash.update(raw);
    let message = format!("sha256:{}", hex::encode(hash.finalize()));
    config.key()?.verify_strict(message.as_bytes(), &Signature::from_slice(&signature).map_err(|_| "JIT signature width")?)
        .map_err(|_| "JIT independent assignment signature refused")?;
    Ok(value)
}

pub(super) fn admit(config: &Configuration, original: &[u8], identity: &mut EnclaveRuntimeIdentityV1,
    boot: &str, key: &str, cp: &str, binary: &str, deadline: u64) -> Result<Admission, String> {
    let (wall, mono) = clocks()?;
    require(identity.deadline() == deadline && mono < deadline)?;
    let value = signed_original(config, original, wall)?;
    let payload = &value["payload"]; let item = &payload["assignment"];
    require(item["bootId"] == boot && item["keyId"] == key
        && item["controlPlaneResponseSigningKeyId"] == cp && item["expectedBinaryDigest"] == binary)?;
    let scope = identity.refresh_scope(deadline)?;
    for name in ["releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256"] {
        require(item[name] == scope[name])?;
    }
    let issued = payload["issuedAtEpochNs"].as_u64().ok_or("JIT assignment issue")?;
    let expires = payload["expiresAtEpochNs"].as_u64().ok_or("JIT assignment expiry")?;
    let held = Admission { original: std::str::from_utf8(original).map_err(|_| "JIT assignment ASCII")?.to_owned(),
        issued, expires, deadline: mono.checked_add(expires - wall).ok_or("JIT assignment clock overflow")?.min(deadline),
        pid: std::process::id(), observation: Mutex::new((wall, mono, true)) };
    held.check()?; Ok(held)
}

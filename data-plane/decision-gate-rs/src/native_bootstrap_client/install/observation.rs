//! Fixed-purpose signature produced only beside actual installation/readback.
//! The host key is independently cold assigned, not a workload/CA authority.

#[path = "../../native_workload_bootstrap_request_v1.rs"]
mod encoding;
#[path = "../../native_enrollment_bootstrap_packet_v2.rs"]
mod packet;

use super::{authority::Authorization, destination::Destination, digest, digest_text, ensure,
    reservation::Reservation, InstallGuard};
use super::super::{config, identity, json, native_verifier, originals::{ArtifactV1, HeldOriginal}, OriginalClock};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use ring::{rand::SystemRandom, signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING}};
use rustls::{pki_types::{CertificateDer, UnixTime}, server::WebPkiClientVerifier, RootCertStore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"serverware.nativeSetupCaInstallObservation/v1\0";
const POSSESSION: &[u8] = b"serverware.nativeSetupCaInstallPossession/v1\0";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in super::super) struct Inputs {
    prepared: ArtifactV1,
    enrollment: ArtifactV1,
    host_signing_seed: ArtifactV1,
    host_public_key_base64url: String,
    target_private_key: ArtifactV1,
}

impl Inputs {
    pub(in super::super) fn validate(&self) -> Result<(), String> {
        for pin in [&self.prepared, &self.enrollment, &self.host_signing_seed, &self.target_private_key] { config::artifact(pin)?; }
        ensure(decode(&self.host_public_key_base64url, 32)?.len() == 32, "host observation public key differs")
    }
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key).and_then(Value::as_str).ok_or_else(|| "host observation original field differs".to_owned())
}
fn integer(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key).and_then(Value::as_u64).ok_or_else(|| "host observation integer differs".to_owned())
}
fn decode(v: &str, max: usize) -> Result<Vec<u8>, String> {
    ensure(!v.is_empty() && v.len() <= (max * 4 + 2) / 3, "host observation encoded original bound")?;
    let raw = URL_SAFE_NO_PAD.decode(v).map_err(|_| "host observation original encoding")?;
    ensure(!raw.is_empty() && raw.len() <= max && URL_SAFE_NO_PAD.encode(&raw) == v, "host observation original bound")?;
    Ok(raw)
}
fn private_der(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "host observation target private encoding")?;
    let body = text.strip_prefix("-----BEGIN PRIVATE KEY-----\n").and_then(|x| x.strip_suffix("-----END PRIVATE KEY-----\n"))
        .ok_or("host observation target private PKCS8 required")?;
    let encoded = Zeroizing::new(body.replace('\n', ""));
    let der = Zeroizing::new(STANDARD.decode(encoded.as_bytes()).map_err(|_| "host observation target private base64")?);
    let b64 = Zeroizing::new(STANDARD.encode(der.as_slice()));
    let mut canonical = Zeroizing::new(String::from("-----BEGIN PRIVATE KEY-----\n"));
    for chunk in b64.as_bytes().chunks(64) { canonical.push_str(std::str::from_utf8(chunk).map_err(|_| "private encoding")?); canonical.push('\n'); }
    canonical.push_str("-----END PRIVATE KEY-----\n");
    ensure(canonical.as_bytes() == raw && !der.is_empty() && der.len() <= 16384, "host observation private original differs")?;
    Ok(der)
}

/// Non-Clone and no raw signing/export method; all originals remain in-process.
pub(in super::super) struct Prepared {
    clock: Arc<OriginalClock>,
    held: Vec<HeldOriginal>,
    seed_original: HeldOriginal,
    target_original: HeldOriginal,
    signer: SigningKey,
    target: EcdsaKeyPair,
    host_key_id: String,
    prepared: Value,
    prepared_sha: String,
    enrollment_sha: String,
    certificate_sha: String,
    association_sha: String,
    policy_sha: String,
    principal: String,
    target_certificate: Vec<u8>,
    packet: packet::BootstrapPacketOriginalsV2,
    spent: bool,
}

impl Prepared {
    pub(in super::super) fn open(inputs: Inputs, clock: Arc<OriginalClock>, configuration: &HeldOriginal) -> Result<Self, String> {
        clock.check()?; configuration.require_private()?;
        let mut held = Vec::new();
        let prepared_raw = super::super::read(inputs.prepared, 8192, &clock, &mut held)?;
        let enrollment_raw = super::super::read(inputs.enrollment, 1500000, &clock, &mut held)?;
        let prepared = json::parse(&prepared_raw, 8192)?;
        let fields = ["apiVersion", "attemptId", "sessionId", "enrollmentSha256", "intentSha256", "certificateSha256",
            "associationSha256", "installationAuthorizationSha256", "hostKeyId", "nonceSha256", "issuedAtEpochNs", "expiresAtEpochNs"];
        ensure(encoding::encode_canonical(&prepared, 8192)? == prepared_raw
            && prepared.as_object().map(|x| x.len()) == Some(12)
            && fields.iter().all(|field| prepared.get(*field).is_some())
            && text(&prepared, "apiVersion")? == "serverware.setupNativeCaInstallationPrepared/v1", "host observation prepared profile differs")?;
        let row = json::parse(&enrollment_raw, 1500000)?;
        ensure(row.as_object().map(|x| x.len()) == Some(17) && integer(&row, "revision")? == 1
            && text(&row, "phase")? == "certificate_issued" && text(&row, "session_id")? == text(&prepared, "sessionId")?,
            "host observation enrollment original differs")?;
        let intent_raw = text(&row, "intent_original")?.as_bytes();
        let intent = json::parse(intent_raw, 1200000)?;
        ensure(intent.as_object().map(|x| x.len()) == Some(17)
            && text(&intent, "apiVersion")? == "serverware.setupNativeEnrollmentIntent/v1"
            && text(&intent, "sessionId")? == text(&prepared, "sessionId")?
            && text(&prepared, "intentSha256")? == digest_text(&digest(intent_raw)), "host observation issuer intent differs")?;
        let certificate_raw = decode(text(&row, "certificate_original")?, 65536)?;
        let certificate_sha = digest_text(&digest(&certificate_raw));
        let association_sha = digest_text(&digest(text(&row, "association_original")?.as_bytes()));
        let enrollment_sha = digest_text(&digest(&enrollment_raw));
        ensure(text(&row, "certificate_sha256")? == certificate_sha && text(&prepared, "certificateSha256")? == certificate_sha
            && text(&prepared, "associationSha256")? == association_sha && text(&prepared, "enrollmentSha256")? == enrollment_sha,
            "host observation exact retained enrollment hashes differ")?;
        let packet_raw = decode(text(&intent, "packet")?, packet::MAX_PACKET_BYTES)?;
        let policy_sha = text(&intent, "policyHash")?.to_owned();
        let principal = text(&intent, "principalId")?.to_owned();
        let packet = packet::decode_original(&packet_raw)?;
        ensure(packet.target_request_original() == decode(text(&intent, "request")?, 65536)?, "host observation target original differs")?;
        let before = integer(&prepared, "issuedAtEpochNs")?;
        let until = integer(&prepared, "expiresAtEpochNs")?;
        ensure(before > 0 && before < until && until - before <= 300 * super::super::SECOND
            && before >= integer(&intent, "issuedAtEpochNs")? && until <= integer(&intent, "expiresAtEpochNs")?, "host observation original interval differs")?;
        ensure(super::super::sample()?.0 >= before, "host observation precedes original preparation")?;
        clock.restrict_until_epoch_ns(until)?;
        let (seed_original, seed) = HeldOriginal::read_private(inputs.host_signing_seed, 32)?;
        ensure(seed.len() == 32, "host observation seed must be independently supplied exact32")?;
        let mut bytes = Zeroizing::new([0u8; 32]); bytes.copy_from_slice(&seed);
        let signer = SigningKey::from_bytes(&bytes); drop(seed); drop(bytes);
        let public = signer.verifying_key().to_bytes();
        ensure(decode(&inputs.host_public_key_base64url, 32)? == public, "host observation cold assigned public key differs")?;
        let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]; spki.extend_from_slice(&public);
        let host_key_id = digest_text(&digest(&spki));
        ensure(text(&prepared, "hostKeyId")? == host_key_id, "host observation prepared host signer differs")?;
        let (target_original, key_pem) = HeldOriginal::read_private(inputs.target_private_key, 16384)?;
        let der = private_der(&key_pem)?;
        let target = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der, &SystemRandom::new())
            .map_err(|_| "host observation actual target key is not P256")?;
        drop(der); drop(key_pem);
        let target_certificate = identity::workload_issuer_original(&certificate_raw)?;
        let mut result = Self { clock, held, seed_original, target_original, signer, target, host_key_id,
            prepared, prepared_sha: digest_text(&digest(&prepared_raw)), enrollment_sha, certificate_sha,
            association_sha, policy_sha, principal, target_certificate, packet, spent: false };
        result.check()?; Ok(result)
    }

    pub(super) fn check(&mut self) -> Result<(), String> {
        self.clock.check()?;
        for original in &mut self.held { original.recheck()?; self.clock.check()?; }
        for original in [&mut self.seed_original, &mut self.target_original] { original.require_private()?; original.recheck()?; original.require_private()?; }
        self.clock.check()
    }

    pub(super) fn bind(&mut self, proof: &mut native_verifier::BootstrapInstallationOriginals, grant: &Authorization) -> Result<(), String> {
        self.check()?; proof.check(self.clock.boottime_deadline()?)?;
        let d = proof.delegation();
        ensure(text(&self.prepared, "installationAuthorizationSha256")? == digest_text(&grant.original_sha256)
            && integer(&self.prepared, "issuedAtEpochNs")? >= grant.issued_at_epoch_ns
            && integer(&self.prepared, "expiresAtEpochNs")? <= grant.expires_at_epoch_ns
            && digest(self.packet.setup_original()) == proof.setup_sha256()
            && digest(self.packet.delegation_original()) == proof.delegation_sha256()
            && digest(self.packet.target_request_original()) == d.target_request_sha256
            && self.policy_sha == digest_text(&d.policy_hash) && self.principal == d.target_principal_id
            && digest(self.packet.target_issuer_original()) == d.target_issuer_certificate_der_sha256,
            "host observation differs from actual native connection/bootstrap owners")?;
        for key in [grant.root_key_id, d.authorizer_key_id, d.runtime_ca_spki_sha256, d.caller_issuer_spki_sha256,
                d.caller_spki_sha256, d.target_issuer_spki_sha256, d.target_spki_sha256] {
            ensure(self.host_key_id != digest_text(&key), "host observation signing roles overlap")?;
        }
        let (rest, leaf) = x509_parser::parse_x509_certificate(&self.target_certificate).map_err(|_| "host observation target leaf invalid")?;
        ensure(rest.is_empty() && digest(leaf.public_key().raw) == d.target_spki_sha256
            && leaf.public_key().subject_public_key.data.as_ref() == self.target.public_key().as_ref(), "host observation leaf/retained key differs")?;
        let until = u64::try_from(leaf.validity().not_after.timestamp()).map_err(|_| "host observation leaf expiry invalid")?
            .checked_mul(super::super::SECOND).ok_or("host observation leaf expiry overflow")?;
        self.clock.restrict_until_epoch_ns(until)?;
        let sans = leaf.subject_alternative_name().map_err(|_| "host observation SAN invalid")?.ok_or("host observation SAN absent")?;
        let (mut dns, mut uris) = (Vec::new(), Vec::new());
        for name in &sans.value.general_names {
            match name {
                x509_parser::extensions::GeneralName::DNSName(v) => dns.push(v.to_string()),
                x509_parser::extensions::GeneralName::URI(v) => uris.push(v.to_string()),
                _ => return Err("host observation unsupported target SAN".to_owned()),
            }
        }
        ensure(dns == d.target_requested_dns && uris == d.target_requested_uris, "host observation actual full target SAN inventory differs")?;
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(self.packet.target_issuer_original().to_vec())).map_err(|_| "host observation target issuer invalid")?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build().map_err(|_| "host observation target verifier failed")?;
        let now = super::super::sample()?.0;
        verifier.verify_client_cert(&CertificateDer::from(self.target_certificate.clone()), &[], UnixTime::since_unix_epoch(std::time::Duration::from_nanos(now)))
            .map_err(|_| "host observation independent target leaf verification failed")?;
        self.check()
    }

    pub(super) fn finish(&mut self, grant: &Authorization, guard: &InstallGuard, destination: &mut Destination,
        reservation: &Reservation, operation: &[u8;32], slot: &[u8;32]) -> Result<String, String> {
        ensure(!self.spent && Arc::ptr_eq(&self.clock, &guard.clock), "host observation owner/deadline differs")?;
        self.spent = true; self.check()?; guard.check()?; reservation.require_completed()?;
        let before = super::super::sample()?.0;
        ensure(destination.installed_certificate_der_sha256()? == Some(grant.runtime_ca_certificate_sha256), "host observation final CA bytes differ")?;
        let identity = destination.observation_identity()?;
        self.check()?; guard.check()?; reservation.require_completed()?;
        let after = super::super::sample()?.0;
        let payload = json!({"apiVersion":"serverware.nativeSetupCaInstallObservation/v1", "purpose":"setup-ca-installation-readback",
            "trustMode":"trusted-host-local", "preparedSha256":self.prepared_sha, "enrollmentSha256":self.enrollment_sha,
            "certificateSha256":self.certificate_sha, "associationSha256":self.association_sha,
            "installationAuthorizationSha256":digest_text(&grant.original_sha256), "nativeSetupSha256":digest_text(&grant.setup_sha256),
            "targetRequestSha256":digest_text(&grant.target_request_sha256), "runtimeCaCertificateSha256":digest_text(&grant.runtime_ca_certificate_sha256),
            "hostId":grant.network_owner.host_id, "machineIdSha256":digest_text(&grant.machine_id_sha256), "bootId":grant.network_owner.boot_id,
            "namespaceDevice":grant.network_owner.namespace_device, "namespaceInode":grant.network_owner.namespace_inode,
            "destinationPath":grant.ca_install.destination_path, "destinationIdentity":identity, "operationSha256":digest_text(operation),
            "reservationSha256":digest_text(slot), "observedBeforeEpochNs":before, "observedAfterEpochNs":after,
            "hostSigningKeyId":self.host_key_id, "workloadSpkiSha256":digest_text(&digest(x509_parser::parse_x509_certificate(&self.target_certificate)
                .map_err(|_| "host observation retained leaf invalid")?.1.public_key().raw))});
        let raw = encoding::encode_canonical(&payload, 24576)?;
        let mut host_preimage = DOMAIN.to_vec(); host_preimage.extend_from_slice(&raw);
        let mut target_preimage = POSSESSION.to_vec(); target_preimage.extend_from_slice(&raw);
        self.check()?; guard.check()?; reservation.require_completed()?; destination.check()?;
        let host_signature = self.signer.sign(&host_preimage);
        let target_signature = self.target.sign(&SystemRandom::new(), &target_preimage).map_err(|_| "host observation possession signing failed")?;
        let envelope = json!({"payload":payload, "signature":format!("ed25519:{}", URL_SAFE_NO_PAD.encode(host_signature.to_bytes())),
            "workloadSignature":format!("ecdsa-p256-sha256:{}", URL_SAFE_NO_PAD.encode(target_signature.as_ref()))});
        let output = encoding::encode_canonical(&envelope, 32768)?;
        self.check()?; guard.check()?; reservation.require_completed()?; destination.check()?;
        String::from_utf8(output).map_err(|_| "host observation output encoding".to_owned())
    }
}

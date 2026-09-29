//! Receiving assignment supplied only by independently admitted guest originals.
use super::{digest_bytes, ensure, fixed};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const API: &str = "serverware.responseV2.targetDispatchAssignment/v1";
pub const PURPOSE: &str = "native-gate-target-dispatch-capture-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub assignment: Assignment,
    pub trust_roots: NitroRoots,
    pub valid_from_epoch_ms: u64,
    pub valid_until_epoch_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assignment {
    pub purpose: String,
    pub kernel_boot_id: String,
    pub boot_id: String,
    pub key_id: String,
    pub control_plane_response_signing_key_id: String,
    pub release_record_sha256: String,
    pub policy_hash: String,
    pub configuration_sha256: String,
    pub ca_certificate_sha256: String,
    pub ca_public_key_spki_sha256: String,
    pub expected_binary_digest: String,
    pub expected_pcrs: BTreeMap<String, String>,
    pub expected_eif: String,
    pub expected_module_id: String,
    pub max_age_seconds: u64,
    pub future_skew_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NitroRoots {
    pub api_version: String,
    pub aws_nitro_root_certificates_pem: Vec<String>,
    pub aws_nitro_crls_der_base64url: Vec<String>,
    pub nitro_certificate_profile: CertificateProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateProfile {
    pub profile_id: String,
    pub allowed_leaf_extended_key_usage_oids: Vec<String>,
}

// These private types are the same narrow inputs consumed by the unchanged
// original Nitro verifier. They are not authorization results or wire DTOs.
pub(super) struct Expectations {
    pub module_id: String,
    pub pcrs: BTreeMap<u8, [u8; 48]>,
    pub max_age: u64,
    pub future_skew: u64,
}
pub(super) struct TrustRoots {
    pub certificates: Vec<Vec<u8>>,
    pub allowed_leaf_eku: Vec<String>,
}

impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        let value = &self.assignment;
        ensure(self.api_version == API && self.generation > 0 && self.generation <= i64::MAX as u64
            && crate::native_currentness_v1::identifier(&self.generation_id)
            && value.purpose == PURPOSE && crate::native_currentness_v1::uuid(&value.kernel_boot_id)
            && self.valid_from_epoch_ms > 0 && self.valid_until_epoch_ms > self.valid_from_epoch_ms
            && self.valid_until_epoch_ms <= i64::MAX as u64 / 1_000_000
            && (1..=300).contains(&value.max_age_seconds) && value.future_skew_seconds <= 30
            && !value.expected_module_id.is_empty() && value.expected_module_id.len() <= 256
            && value.expected_module_id.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            && super::canonical(self)?.len() <= 512 * 1024,
            "target-dispatch independent assignment is invalid")?;
        ensure(fixed::<32>(&value.boot_id)? != [0; 32], "target-dispatch native boot is zero")?;
        for digest in [&value.key_id, &value.control_plane_response_signing_key_id, &value.release_record_sha256,
            &value.policy_hash, &value.configuration_sha256, &value.ca_certificate_sha256,
            &value.ca_public_key_spki_sha256, &value.expected_binary_digest] {
            digest_bytes(digest)?;
        }
        ensure(value.key_id != value.control_plane_response_signing_key_id,
            "target-dispatch executor cannot be its control-plane signing authority")?;
        self.expectations()?;
        self.roots()?;
        Ok(())
    }

    pub(super) fn admit(&self, now_ns: u64) -> Result<(Expectations, TrustRoots), String> {
        self.validate()?;
        let now_ms = now_ns / 1_000_000;
        ensure(self.valid_from_epoch_ms <= now_ms && now_ms < self.valid_until_epoch_ms,
            "target-dispatch assignment is not current")?;
        Ok((self.expectations()?, self.roots()?))
    }

    fn expectations(&self) -> Result<Expectations, String> {
        let value = &self.assignment;
        ensure((3..=32).contains(&value.expected_pcrs.len()), "target-dispatch PCR inventory invalid")?;
        let mut pcrs = BTreeMap::new();
        for (name, encoded) in &value.expected_pcrs {
            let index = name.strip_prefix("PCR").and_then(|value| value.parse::<u8>().ok())
                .filter(|index| *index <= 31).ok_or("target-dispatch PCR index invalid")?;
            ensure(name == &format!("PCR{index}"), "target-dispatch PCR index is noncanonical")?;
            pcrs.insert(index, sha384(encoded, index <= 2)?);
        }
        ensure([0, 1, 2].iter().all(|index| pcrs.contains_key(index))
            && pcrs.get(&0) == Some(&sha384(&value.expected_eif, true)?),
            "target-dispatch EIF/PCR scope differs")?;
        Ok(Expectations { module_id: value.expected_module_id.clone(), pcrs,
            max_age: value.max_age_seconds, future_skew: value.future_skew_seconds })
    }

    fn roots(&self) -> Result<TrustRoots, String> {
        let value = &self.trust_roots;
        ensure(value.api_version == "serverware.nativeResponseAttestationTrustRoots/v1"
            && (1..=16).contains(&value.aws_nitro_root_certificates_pem.len())
            && value.aws_nitro_crls_der_base64url.is_empty()
            && value.nitro_certificate_profile.profile_id == "aws-nitro-attestation-pki-native-v1",
            "target-dispatch Nitro roots differ from the fixed native PKI profile")?;
        let mut certificates = Vec::new();
        for pem in &value.aws_nitro_root_certificates_pem {
            let der = pem_certificate(pem)?;
            ensure(!certificates.contains(&der), "target-dispatch Nitro root repeats")?;
            certificates.push(der);
        }
        let oids = &value.nitro_certificate_profile.allowed_leaf_extended_key_usage_oids;
        ensure(oids.len() <= 32 && oids.windows(2).all(|pair| pair[0] < pair[1])
            && oids.iter().all(|oid| !oid.is_empty() && oid.len() <= 128
                && oid.split('.').count() >= 2
                && oid.split('.').all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))),
            "target-dispatch leaf EKU inventory invalid")?;
        Ok(TrustRoots { certificates, allowed_leaf_eku: oids.clone() })
    }
}

fn sha384(value: &str, nonzero: bool) -> Result<[u8; 48], String> {
    let value = value.strip_prefix("sha384:").ok_or("target-dispatch PCR digest prefix invalid")?;
    ensure(value.len() == 96 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "target-dispatch PCR digest invalid")?;
    let mut raw = [0; 48];
    hex::decode_to_slice(value, &mut raw).map_err(|_| "target-dispatch PCR digest invalid")?;
    ensure(!nonzero || raw != [0; 48], "target-dispatch measured PCR cannot be zero")?;
    Ok(raw)
}

fn pem_certificate(value: &str) -> Result<Vec<u8>, String> {
    ensure(!value.is_empty() && value.len() <= 64 * 1024 && value.is_ascii(), "target-dispatch root PEM exceeds bound")?;
    let head = "-----BEGIN CERTIFICATE-----\n";
    let tail = "-----END CERTIFICATE-----\n";
    let body = value.strip_prefix(head).and_then(|value| value.strip_suffix(tail)).ok_or("target-dispatch PEM armor differs")?;
    let compact: String = body.chars().filter(|value| *value != '\n').collect();
    let raw = general_purpose::STANDARD.decode(compact).map_err(|_| "target-dispatch PEM invalid")?;
    ensure(!raw.is_empty(), "target-dispatch root is empty")?;
    let encoded = general_purpose::STANDARD.encode(&raw);
    let mut canonical = head.to_owned();
    for line in encoded.as_bytes().chunks(64) {
        canonical.push_str(std::str::from_utf8(line).map_err(|_| "target-dispatch PEM invalid")?);
        canonical.push('\n');
    }
    canonical.push_str(tail);
    ensure(canonical == value, "target-dispatch root PEM is not canonical")?;
    Ok(raw)
}

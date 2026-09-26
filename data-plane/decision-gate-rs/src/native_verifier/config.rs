//! Independently pinned originals, never expectations learned from evidence.

use super::{decode_b64, ensure, exact, fixed_b64, json, parse_digest, pem_der, text, uint};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) struct Expectations {
    pub(super) release_record: [u8; 32],
    pub(super) policy: [u8; 32],
    pub(super) configuration: [u8; 32],
    pub(super) ca_certificate: [u8; 32],
    pub(super) ca_spki: [u8; 32],
    pub(super) binary: [u8; 32],
    pub(super) pcrs: BTreeMap<u8, [u8; 48]>,
    pub(super) module_id: String,
    pub(super) max_age: u64,
    pub(super) future_skew: u64,
    pub(super) boot: [u8; 32],
    pub(super) key_id: [u8; 32],
    pub(super) control_plane_key_id: [u8; 32],
    pub(super) nonce: Vec<u8>,
}

impl Expectations {
    pub(super) fn parse(raw: &[u8]) -> Result<Self, String> {
        let value = json::parse(raw, 16 * 1024)?;
        exact(&value, &[
            "apiVersion", "releaseRecordSha256", "policyHash", "configurationSha256",
            "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest",
            "expectedPcrs", "expectedEif", "expectedModuleId", "maxAgeSeconds",
            "futureSkewSeconds", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "nonce",
        ])?;
        ensure(text(&value, "apiVersion")? == "serverware.nativeResponseAttestationExpectations/v1",
            "native expectations version differs")?;
        let pin = |field| parse_digest::<32>(text(&value, field)?, "sha256:", true);
        let inventory = value.get("expectedPcrs").and_then(Value::as_object)
            .ok_or("native expected PCR inventory is not an object")?;
        ensure((3..=32).contains(&inventory.len()), "native expected PCR inventory size differs")?;
        let mut pcrs = BTreeMap::new();
        for (name, value) in inventory {
            let index: u8 = name.strip_prefix("PCR").ok_or("native PCR name differs")?
                .parse().map_err(|_| "native PCR index is invalid")?;
            ensure(index <= 31 && name == &format!("PCR{index}"), "native PCR name is not canonical")?;
            let bytes = parse_digest::<48>(value.as_str().ok_or("native PCR is not text")?,
                "sha384:", index < 3)?;
            ensure(pcrs.insert(index, bytes).is_none(), "native PCR repeats")?;
        }
        ensure((0..=2).all(|index| pcrs.contains_key(&index)), "native core PCRs are missing")?;
        let eif = parse_digest::<48>(text(&value, "expectedEif")?, "sha384:", true)?;
        ensure(pcrs.get(&0) == Some(&eif), "native expected EIF differs from PCR0")?;
        let module_id = text(&value, "expectedModuleId")?;
        // Native Nitro identifiers are ASCII. This avoids importing Unicode
        // normalization semantics into the independently pinned identity field.
        ensure(!module_id.is_empty() && module_id.len() <= 256
            && module_id.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
            "native module ID is not bounded printable ASCII")?;
        let max_age = uint(&value, "maxAgeSeconds")?;
        let future_skew = uint(&value, "futureSkewSeconds")?;
        ensure((1..=300).contains(&max_age) && future_skew <= 30, "native age limits differ")?;
        let nonce = decode_b64(text(&value, "nonce")?, 64)?;
        ensure(nonce.len() >= 32, "native expected nonce is too short")?;
        Ok(Self {
            release_record: pin("releaseRecordSha256")?, policy: pin("policyHash")?,
            configuration: pin("configurationSha256")?, ca_certificate: pin("caCertificateSha256")?,
            ca_spki: pin("caPublicKeySpkiSha256")?, binary: pin("expectedBinaryDigest")?,
            pcrs, module_id: module_id.to_owned(), max_age, future_skew,
            boot: fixed_b64(text(&value, "bootId")?)?, key_id: pin("keyId")?,
            control_plane_key_id: pin("controlPlaneResponseSigningKeyId")?, nonce,
        })
    }
}

pub(super) struct TrustRoots {
    pub(super) certificates: Vec<Vec<u8>>,
    pub(super) allowed_leaf_eku: Vec<String>,
}

impl TrustRoots {
    pub(super) fn parse(raw: &[u8]) -> Result<Self, String> {
        let value = json::parse(raw, 1024 * 1024)?;
        exact(&value, &[
            "apiVersion", "awsNitroRootCertificatesPem", "awsNitroCrlsDerBase64url", "nitroCertificateProfile",
        ])?;
        ensure(text(&value, "apiVersion")? == "serverware.nativeResponseAttestationTrustRoots/v1",
            "native trust-root version differs")?;
        let input = value.get("awsNitroRootCertificatesPem").and_then(Value::as_array)
            .ok_or("native root inventory is not an array")?;
        ensure((1..=16).contains(&input.len()), "native root inventory size differs")?;
        let mut certificates = Vec::new();
        for pem in input {
            let der = pem_der(pem.as_str().ok_or("native root PEM is not text")?, "CERTIFICATE", 64 * 1024)?;
            ensure(!certificates.contains(&der), "native root repeats")?;
            certificates.push(der);
        }
        ensure(value.get("awsNitroCrlsDerBase64url").and_then(Value::as_array)
            .is_some_and(Vec::is_empty), "native Nitro profile requires an empty CRL inventory")?;
        let profile = value.get("nitroCertificateProfile").ok_or("native certificate profile missing")?;
        exact(profile, &["profileId", "allowedLeafExtendedKeyUsageOids"])?;
        ensure(text(profile, "profileId")? == "aws-nitro-attestation-pki-native-v1",
            "native certificate profile differs")?;
        let oids = profile.get("allowedLeafExtendedKeyUsageOids").and_then(Value::as_array)
            .ok_or("native leaf EKUs are not an array")?;
        ensure(oids.len() <= 32, "native leaf EKU inventory exceeds its bound")?;
        let mut allowed_leaf_eku: Vec<String> = Vec::new();
        for oid in oids {
            let oid = oid.as_str().ok_or("native EKU OID is not text")?;
            let mut parts = oid.split('.');
            ensure(!oid.is_empty() && oid.len() <= 128
                && parts.clone().count() >= 2
                && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                && allowed_leaf_eku.last().is_none_or(|last| last.as_str() < oid),
                "native leaf EKUs are invalid or not sorted and unique")?;
            allowed_leaf_eku.push(oid.to_owned());
        }
        Ok(Self { certificates, allowed_leaf_eku })
    }
}

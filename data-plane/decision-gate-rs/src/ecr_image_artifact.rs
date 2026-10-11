//! Standalone, unwired OCI/Docker image content verification, not authority.
//!
//! The exact original manifest and every referenced unique blob are measured.
//! Config bytes are opaque; layers are not decompressed or extracted. This is
//! not runnable-image validation, immutable staging, approval or an AWS effect.
//! Readers are consumed at their current positions, never opened, sought,
//! closed or retained. Their caller owns blocking, cancellation and deadlines.
//! A serialized commitment alone is not evidence of an actual byte observation.

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_BLOB_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_LAYERS: usize = 128;
pub const READ_CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_READ_CALLS_PER_BLOB: usize = 8192;
pub const SCHEMA: &str = "serverware.ecrVerifiedImage/v1";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYERS: [&str; 3] = ["application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd"];
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const DOCKER_LAYER: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageArtifactError;

impl fmt::Display for ImageArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ECR image artifact unavailable")
    }
}
impl std::error::Error for ImageArtifactError {}

/// The declared digest is a lookup key only; actual stream bytes must match it.
pub struct BlobInput<'a> {
    pub digest: &'a str,
    pub reader: &'a mut dyn Read,
}

/// Private construction; the public getters do not retain readers or blob data.
pub struct VerifiedImage {
    manifest: Vec<u8>,
    commitment: Value,
    canonical: Vec<u8>,
    digest: String,
}

impl VerifiedImage {
    pub fn manifest_bytes(&self) -> &[u8] { &self.manifest }
    pub fn commitment(&self) -> Value { self.commitment.clone() }
    pub fn commitment_bytes(&self) -> &[u8] { &self.canonical }
    pub fn commitment_sha256(&self) -> &str { &self.digest }
}

// Missing and explicitly empty annotations remain distinct descriptor shapes.
#[derive(Clone, Default, Eq, PartialEq)]
enum Annotations {
    #[default]
    Missing,
    Present(BTreeMap<String, String>),
}

impl<'de> Deserialize<'de> for Annotations {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AnnotationVisitor;
        impl<'de> Visitor<'de> for AnnotationVisitor {
            type Value = Annotations;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded unique annotations")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
                let mut rows = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, String>()? {
                    if rows.len() >= 32 || key.is_empty() || key.len() > 256
                        || !key.bytes().all(|b| (b'!'..=b'~').contains(&b))
                        || value.len() > 4096 || value.contains('\0') || rows.contains_key(&key)
                    {
                        return Err(de::Error::custom("invalid annotations"));
                    }
                    rows.insert(key, value);
                }
                Ok(Annotations::Present(rows))
            }
        }
        deserializer.deserialize_map(AnnotationVisitor)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default)]
    annotations: Annotations,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "mediaType")]
    media_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default)]
    annotations: Annotations,
}

// Fields deliberately in lexicographic order: canonical serialization does
// not depend on serde_json's optional preserve_order feature or map ordering.
#[derive(Serialize)]
struct PublicDescriptor<'a> { digest: &'a str, media_type: &'a str, size: u64 }
#[derive(Serialize)]
struct PublicBlob<'a> { digest: &'a str, size: u64 }
#[derive(Serialize)]
struct Commitment<'a> {
    blobs: Vec<PublicBlob<'a>>,
    config: PublicDescriptor<'a>,
    layers: Vec<PublicDescriptor<'a>>,
    manifest: PublicDescriptor<'a>,
    schema: &'static str,
    total_blob_bytes: u64,
}

fn public(row: &Descriptor) -> PublicDescriptor<'_> {
    PublicDescriptor { digest: &row.digest, media_type: &row.media_type, size: row.size }
}
fn hash(body: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(body)) }
fn valid_digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:")
        && value.as_bytes()[7..].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn bounded_json(raw: &[u8]) -> Result<Manifest, ImageArtifactError> {
    if raw.is_empty() || raw.len() > MAX_MANIFEST_BYTES || std::str::from_utf8(raw).is_err() {
        return Err(ImageArtifactError);
    }
    let (mut depth, mut punctuation, mut quoted, mut escaped) = (0i32, 0usize, false, false);
    for &byte in raw {
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => { depth += 1; punctuation += 1; }
                b']' | b'}' => depth -= 1,
                b',' | b':' => punctuation += 1,
                _ => (),
            }
        }
        if !(0..=8).contains(&depth) || punctuation > 20000 { return Err(ImageArtifactError); }
    }
    if quoted || depth != 0 { return Err(ImageArtifactError); }
    // Typed unsigned integer fields reject negative/float/exponent/bool/null
    // tokens. Derived closed structs also reject duplicate decoded field names.
    serde_json::from_slice(raw).map_err(|_| ImageArtifactError)
}

fn descriptor_valid(row: &Descriptor, media: &[&str], maximum: u64, oci: bool) -> bool {
    media.contains(&row.media_type.as_str()) && valid_digest(&row.digest)
        && (1..=maximum).contains(&row.size)
        && (oci || row.annotations == Annotations::Missing)
}

fn verify_blob(reader: &mut dyn Read, descriptor: &Descriptor, buffer: &mut [u8])
    -> Result<(), ImageArtifactError>
{
    let (mut remaining, mut calls, mut hasher) = (descriptor.size, 0usize, Sha256::new());
    while remaining != 0 {
        if calls >= MAX_READ_CALLS_PER_BLOB { return Err(ImageArtifactError); }
        let amount = remaining.min(buffer.len() as u64) as usize;
        let count = reader.read(&mut buffer[..amount]).map_err(|_| ImageArtifactError)?;
        calls += 1;
        if count == 0 || count > amount { return Err(ImageArtifactError); }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if calls >= MAX_READ_CALLS_PER_BLOB { return Err(ImageArtifactError); }
    let count = reader.read(&mut buffer[..1]).map_err(|_| ImageArtifactError)?;
    if count != 0 || format!("sha256:{:x}", hasher.finalize()) != descriptor.digest {
        return Err(ImageArtifactError);
    }
    Ok(())
}

/// Verify the entire closed roster before touching any reader, then measure all
/// unique streams exactly once. No partial observation is returned on failure.
pub fn verify_image(manifest_bytes: &[u8], blobs: &mut [BlobInput<'_>])
    -> Result<VerifiedImage, ImageArtifactError>
{
    let manifest = bounded_json(manifest_bytes)?;
    let oci = manifest.media_type == OCI_MANIFEST;
    if (!oci && manifest.media_type != DOCKER_MANIFEST) || manifest.schema_version != 2
        || manifest.layers.len() > MAX_LAYERS || (!oci && manifest.annotations != Annotations::Missing)
        || !descriptor_valid(&manifest.config, &[if oci { OCI_CONFIG } else { DOCKER_CONFIG }], MAX_CONFIG_BYTES, oci)
        || manifest.layers.iter().any(|row| !descriptor_valid(row,
            if oci { &OCI_LAYERS } else { std::slice::from_ref(&DOCKER_LAYER) }, MAX_BLOB_BYTES, oci))
    {
        return Err(ImageArtifactError);
    }
    let mut unique = BTreeMap::<&str, &Descriptor>::new();
    let mut total = 0u64;
    for row in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        if let Some(previous) = unique.get(row.digest.as_str()) {
            if *previous != row { return Err(ImageArtifactError); }
        } else {
            total = total.checked_add(row.size).ok_or(ImageArtifactError)?;
            if total > MAX_TOTAL_BYTES { return Err(ImageArtifactError); }
            unique.insert(&row.digest, row);
        }
    }
    if blobs.len() != unique.len() { return Err(ImageArtifactError); }
    let mut supplied = BTreeMap::new();
    for (index, input) in blobs.iter().enumerate() {
        if !valid_digest(input.digest) || !unique.contains_key(input.digest)
            || supplied.insert(input.digest, index).is_some()
        { return Err(ImageArtifactError); }
    }
    let mut buffer = vec![0u8; READ_CHUNK_BYTES];
    for (digest, row) in &unique {
        let index = *supplied.get(digest).ok_or(ImageArtifactError)?;
        verify_blob(blobs[index].reader, row, &mut buffer)?;
    }
    let manifest_digest = hash(manifest_bytes);
    let commitment = Commitment {
        blobs: unique.iter().map(|(digest, row)| PublicBlob { digest, size: row.size }).collect(),
        config: public(&manifest.config), layers: manifest.layers.iter().map(public).collect(),
        manifest: PublicDescriptor { digest: &manifest_digest, media_type: &manifest.media_type,
            size: manifest_bytes.len() as u64 }, schema: SCHEMA, total_blob_bytes: total,
    };
    let canonical = serde_json::to_vec(&commitment).map_err(|_| ImageArtifactError)?;
    let value = serde_json::to_value(&commitment).map_err(|_| ImageArtifactError)?;
    Ok(VerifiedImage { manifest: manifest_bytes.to_vec(), commitment: value,
        digest: hash(&canonical), canonical })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{self, Cursor};

    fn vector() -> Value {
        serde_json::from_str(include_str!("../../../scripts/fixtures/ecr_image_artifact_v1.json")).unwrap()
    }
    fn rows() -> Vec<(String, Vec<u8>)> {
        vector()["blobs"].as_array().unwrap().iter().map(|row| (
            row["digest"].as_str().unwrap().to_owned(), row["utf8"].as_str().unwrap().as_bytes().to_vec()
        )).collect()
    }
    fn measured(raw: &[u8], rows: &[(String, Vec<u8>)]) -> Result<VerifiedImage, ImageArtifactError> {
        let mut readers: Vec<_> = rows.iter().map(|(_, bytes)| Cursor::new(bytes.as_slice())).collect();
        let mut inputs: Vec<_> = rows.iter().zip(readers.iter_mut())
            .map(|((digest, _), reader)| BlobInput { digest, reader }).collect();
        verify_image(raw, &mut inputs)
    }
    fn descriptor(body: &[u8], media: &str) -> Value {
        json!({"mediaType": media, "digest": hash(body), "size": body.len()})
    }
    fn config_only(body: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": descriptor(body, OCI_CONFIG), "layers": []})).unwrap()
    }
    struct Counted {
        bytes: Cursor<Vec<u8>>, limit: usize, calls: usize, amounts: Vec<usize>, fail: Option<usize>,
    }
    impl Counted {
        fn new(body: &[u8], limit: usize) -> Self {
            Self { bytes: Cursor::new(body.to_vec()), limit, calls: 0, amounts: Vec::new(), fail: None }
        }
    }
    impl Read for Counted {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            self.amounts.push(output.len());
            if self.fail == Some(self.calls) { return Err(io::Error::from(io::ErrorKind::Interrupted)); }
            let amount = output.len().min(self.limit);
            self.bytes.read(&mut output[..amount])
        }
    }

    #[test]
    fn ecr_image_artifact_shared_literal_commitment_and_original_bytes() {
        let fixture = vector();
        let raw = fixture["manifest"].as_str().unwrap().as_bytes();
        let image = measured(raw, &rows()).unwrap();
        assert_eq!(image.manifest_bytes(), raw);
        assert_eq!(image.commitment(), fixture["expected_commitment"]);
        assert_eq!(image.commitment_bytes(), fixture["expected_commitment_json"].as_str().unwrap().as_bytes());
        assert_eq!(image.commitment_sha256(), fixture["expected_commitment_sha256"].as_str().unwrap());
        let mut detached = image.commitment();
        detached["total_blob_bytes"] = json!(0);
        assert_eq!(image.commitment()["total_blob_bytes"], 18);
        let compact = serde_json::to_vec(&serde_json::from_slice::<Value>(raw).unwrap()).unwrap();
        assert_ne!(measured(&compact, &rows()).unwrap().commitment_sha256(), image.commitment_sha256());
    }

    #[test]
    fn ecr_image_artifact_media_families_and_opaque_zero_layer_config() {
        let opaque = b"not a runnable config";
        assert!(measured(&config_only(opaque), &[(hash(opaque), opaque.to_vec())]).is_ok());
        let mut manifest: Value = serde_json::from_str(vector()["manifest"].as_str().unwrap()).unwrap();
        for media in OCI_LAYERS {
            for layer in manifest["layers"].as_array_mut().unwrap() { layer["mediaType"] = json!(media); }
            assert!(measured(&serde_json::to_vec(&manifest).unwrap(), &rows()).is_ok());
        }
        manifest["mediaType"] = json!(DOCKER_MANIFEST);
        manifest["config"]["mediaType"] = json!(DOCKER_CONFIG);
        for layer in manifest["layers"].as_array_mut().unwrap() { layer["mediaType"] = json!(DOCKER_LAYER); }
        assert!(measured(&serde_json::to_vec(&manifest).unwrap(), &rows()).is_err()); // OCI annotations forbidden.
        manifest.as_object_mut().unwrap().remove("annotations");
        assert!(measured(&serde_json::to_vec(&manifest).unwrap(), &rows()).is_ok());
        manifest["config"]["mediaType"] = json!(OCI_CONFIG);
        assert!(measured(&serde_json::to_vec(&manifest).unwrap(), &rows()).is_err());
    }

    #[test]
    fn ecr_image_artifact_strict_duplicate_scalar_and_closed_grammar() {
        let original = String::from_utf8(config_only(b"{}" )).unwrap();
        let mut cases = vec![original.replace("\"schemaVersion\":2", "\"schemaVersion\":2,\"schemaVersion\":2"),
            original.replace("\"size\":2", "\"size\":2,\"size\":2"),
            original.replace("\"size\":2", "\"size\":2,\"urls\":[]"),
            original.replace("\"layers\":[]", "\"layers\":[],\"extra\":true")];
        for token in ["-0", "0", "-1", "2.0", "2e0", "true", "null", "NaN", "10000000000"] {
            cases.push(original.replace("\"size\":2", &format!("\"size\":{token}")));
        }
        cases.push(original.replace("\"layers\":[]", "\"layers\":[],\"annotations\":{\"x\":\"a\",\"x\":\"b\"}"));
        cases.push(original.replace("\"layers\":[]", "\"layers\":[],\"annotations\":null"));
        cases.push(original.replace("\"layers\":[]", "\"layers\":[],\"annotations\":{\"x\":\"\\ud800\"}"));
        for raw in cases { assert!(measured(raw.as_bytes(), &[(hash(b"{}"), b"{}".to_vec())]).is_err()); }
        assert!(bounded_json(b"[[[[[[[[[]]]]]]]]]").is_err());
        assert!(bounded_json(&vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
    }

    #[test]
    fn ecr_image_artifact_exact_roster_content_size_and_eof() {
        let fixture = vector();
        let raw = fixture["manifest"].as_str().unwrap().as_bytes();
        let original = rows();
        assert!(measured(raw, &original[..1]).is_err());
        let mut extra = original.clone(); extra.push((hash(b"extra"), b"extra".to_vec()));
        assert!(measured(raw, &extra).is_err());
        let duplicate = vec![original[0].clone(), original[0].clone()];
        assert!(measured(raw, &duplicate).is_err());
        for changed in [b"[]".to_vec(), b"{".to_vec(), b"{}x".to_vec()] {
            let mut wrong = original.clone(); wrong[0].1 = changed;
            assert!(measured(raw, &wrong).is_err());
        }
        let mut reversed = original; reversed.reverse();
        assert!(measured(raw, &reversed).is_ok());
    }

    #[test]
    fn ecr_image_artifact_repeated_layer_measured_once_with_short_reads() {
        let fixture = vector(); let original = rows();
        let mut config = Counted::new(&original[0].1, 3);
        let mut layer = Counted::new(&original[1].1, 3);
        let image = verify_image(fixture["manifest"].as_str().unwrap().as_bytes(), &mut [
            BlobInput { digest: &original[0].0, reader: &mut config },
            BlobInput { digest: &original[1].0, reader: &mut layer },
        ]).unwrap();
        assert_eq!(config.calls, 2); assert_eq!(layer.calls, 7);
        assert_eq!(layer.amounts.last(), Some(&1));
        assert_eq!(image.commitment()["layers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn ecr_image_artifact_annotation_bounds_and_repeat_conflicts() {
        let fixture = vector();
        let original: Value = serde_json::from_str(fixture["manifest"].as_str().unwrap()).unwrap();
        for annotations in [json!({"": "x"}), json!({"space key": "x"}), json!({"λ": "x"}),
            json!({"x": "\u{0}"}), json!({"x": "x".repeat(4097)}), json!({"x": false}),
            Value::Object((0..33).map(|n| (format!("x{n}"), json!("x"))).collect())] {
            let mut bad = original.clone(); bad["annotations"] = annotations;
            assert!(measured(&serde_json::to_vec(&bad).unwrap(), &rows()).is_err());
        }
        let mut good = original.clone(); good["annotations"] = json!({"x": "\nλ\u{7f}"});
        assert!(measured(&serde_json::to_vec(&good).unwrap(), &rows()).is_ok());
        for changed in [json!({}), json!({"x": "different"})] {
            let mut bad = original.clone(); bad["layers"][1]["annotations"] = changed;
            let mut config = Counted::new(b"{}", 2); let mut layer = Counted::new(b"synthetic-layer\n", 16);
            let rows = rows();
            assert!(verify_image(&serde_json::to_vec(&bad).unwrap(), &mut [
                BlobInput { digest: &rows[0].0, reader: &mut config },
                BlobInput { digest: &rows[1].0, reader: &mut layer },
            ]).is_err());
            assert_eq!(config.calls + layer.calls, 0);
        }
    }

    #[test]
    fn ecr_image_artifact_limits_are_preflight_not_large_reads() {
        let base: Value = serde_json::from_slice(&config_only(b"{}" )).unwrap();
        let mut cases = Vec::new();
        let mut config = base.clone(); config["config"]["size"] = json!(MAX_CONFIG_BYTES + 1); cases.push(config);
        let fake = |id, size| json!({"mediaType": OCI_LAYERS[0], "digest": format!("sha256:{id:064x}"), "size": size});
        let mut layer = base.clone(); layer["layers"] = json!([fake(1, MAX_BLOB_BYTES + 1)]); cases.push(layer);
        let mut total = base.clone(); total["layers"] = json!([fake(1, MAX_BLOB_BYTES), fake(2, MAX_BLOB_BYTES)]); cases.push(total);
        let mut count = base.clone(); count["layers"] = json!(vec![fake(1, 1); MAX_LAYERS + 1]); cases.push(count);
        let mut conflict = base; conflict["layers"] = json!([fake(1, 1), fake(1, 2)]); cases.push(conflict);
        for bad in cases {
            let mut reader = Counted::new(b"{}", 2);
            assert!(verify_image(&serde_json::to_vec(&bad).unwrap(), &mut [
                BlobInput { digest: &hash(b"{}"), reader: &mut reader },
            ]).is_err());
            assert_eq!(reader.calls, 0);
        }
    }

    #[test]
    fn ecr_image_artifact_chunk_limit_read_budget_and_interruption() {
        let body = vec![7; READ_CHUNK_BYTES + 19];
        let mut reader = Counted::new(&body, usize::MAX);
        assert!(verify_image(&config_only(&body), &mut [BlobInput { digest: &hash(&body), reader: &mut reader }]).is_ok());
        assert_eq!(reader.amounts, [READ_CHUNK_BYTES, 19, 1]);
        for (size, allowed) in [(8191, true), (8192, false)] {
            let body = vec![9; size]; let mut reader = Counted::new(&body, 1);
            assert_eq!(verify_image(&config_only(&body), &mut [BlobInput { digest: &hash(&body), reader: &mut reader }]).is_ok(), allowed);
            assert_eq!(reader.calls, MAX_READ_CALLS_PER_BLOB);
        }
        for failed_call in [1, 2] {
            let mut reader = Counted::new(b"{}", 2); reader.fail = Some(failed_call);
            let result = verify_image(&config_only(b"{}"), &mut [BlobInput { digest: &hash(b"{}"), reader: &mut reader }]);
            assert!(result.is_err()); assert_eq!(reader.calls, failed_call);
        }
        assert_eq!(ImageArtifactError.to_string(), "ECR image artifact unavailable");
    }
}

//! Own-process native quote verification, never a caller-supplied verdict.
//!
//! The independently admitted static x86-64 ELF must implement the exact four
//! configuration flags and stdin/stdout contract of
//! scripts/verify_native_response_attestation.py. The separate Rust verifier
//! now has a static production packaging target; this adapter still requires
//! an independently admitted executable and pin. There is no interpreter fallback.
//! Digests authenticate supplied bytes, not their release provenance. The child
//! verdict remains local signature/quote evidence, not HTTP/exporter truth.
//!
//! Filesystem/exec/reap syscalls can block in the kernel despite surrounding
//! deadline checks; a hard outer watchdog remains necessary. Process-group
//! cleanup is not containment of malicious independently trusted verifier code.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::Signature;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_EXECUTABLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXPECTATIONS_BYTES: usize = 16 * 1024;
const MAX_TRUST_BYTES: usize = 1024 * 1024;
const MAX_INPUT_BYTES: usize = 512 * 1024;
const MAX_STATEMENT_BYTES: usize = 256 * 1024;
const MAX_OUTPUT_BYTES: usize = 4096;
const CHALLENGE_DOMAIN: &[u8] = b"serverware/native-response-attestation-challenge/v1\0";
const BOOT_DOMAIN: &[u8] = b"serverware/native-proof-custody-boot/v1\0";

pub(super) struct NativeVerifierConfigV1 {
    pub(super) executable: PathBuf,
    pub(super) executable_sha256: String,
    pub(super) expectations: PathBuf,
    pub(super) expectations_sha256: String,
    pub(super) trust_roots: PathBuf,
    pub(super) trust_roots_sha256: String,
}

struct HeldInput {
    path: PathBuf,
    pin: String,
    file: File,
    metadata: fs::Metadata,
    chain: Vec<super::FileIdentity>,
    maximum: usize,
    // Configuration originals remain retained. Executable bytes are retained
    // in the sealed executable descriptor instead of a second 64 MiB vector.
    original: Option<Vec<u8>>,
}

pub(super) struct NativeResponseVerifierV1 {
    inputs: [HeldInput; 3],
    executable: File,
    expected: Value,
    nonce: Vec<u8>,
    control_plane_key_id: String,
    ca_certificate_sha256: String,
    ca_public_key_spki_sha256: String,
    deadline: Instant,
    owner_pid: u32,
}

impl NativeResponseVerifierV1 {
    pub(super) fn open(config: NativeVerifierConfigV1, deadline: Instant) -> Result<Self, String> {
        live(deadline)?;
        if !cfg!(target_os = "linux") {
            return Err("native verifier descriptor execution requires Linux".to_owned());
        }
        let (executable_input, executable_bytes) = HeldInput::open(
            config.executable, config.executable_sha256, MAX_EXECUTABLE_BYTES, false, deadline,
        )?;
        if executable_input.metadata.mode() & 0o111 == 0
            || executable_input.metadata.mode() & 0o6000 != 0 {
            return Err("native verifier must be an executable without set-ID bits".to_owned());
        }
        validate_static_elf(&executable_bytes, deadline)?;
        let executable = seal_executable(&executable_bytes, deadline)?;
        let (expectations, expected_bytes) = HeldInput::open(
            config.expectations, config.expectations_sha256, MAX_EXPECTATIONS_BYTES, true, deadline,
        )?;
        let expected = strict_json(&expected_bytes, MAX_EXPECTATIONS_BYTES, deadline)?;
        let nonce = validate_expectations(&expected)?;
        let control_plane_key_id = text(&expected, "controlPlaneResponseSigningKeyId")?.to_owned();
        let ca_certificate_sha256 = text(&expected, "caCertificateSha256")?.to_owned();
        let ca_public_key_spki_sha256 = text(&expected, "caPublicKeySpkiSha256")?.to_owned();
        let (trust_roots, trust_bytes) = HeldInput::open(
            config.trust_roots, config.trust_roots_sha256, MAX_TRUST_BYTES, true, deadline,
        )?;
        validate_trust(&strict_json(&trust_bytes, MAX_TRUST_BYTES, deadline)?)?;
        live(deadline)?;
        Ok(Self {
            inputs: [executable_input, expectations, trust_roots], executable, expected,
            nonce, control_plane_key_id, ca_certificate_sha256, ca_public_key_spki_sha256,
            deadline, owner_pid: std::process::id(),
        })
    }

    pub(super) fn expected_nonce(&self) -> Result<Vec<u8>, String> {
        self.check_live(self.deadline)?;
        Ok(self.nonce.clone())
    }

    pub(super) fn control_plane_key_id(&self) -> &str { &self.control_plane_key_id }
    pub(super) fn ca_certificate_sha256(&self) -> &str { &self.ca_certificate_sha256 }
    pub(super) fn ca_public_key_spki_sha256(&self) -> &str { &self.ca_public_key_spki_sha256 }

    pub(super) fn recheck_inputs(&self) -> Result<(), String> {
        self.check_live(self.deadline)?;
        for input in &self.inputs { input.verify(self.deadline)?; }
        verify_seals(&self.executable)?;
        self.check_live(self.deadline)
    }

    pub(super) fn input_paths(&self) -> [&Path; 3] {
        [&self.inputs[0].path, &self.inputs[1].path, &self.inputs[2].path]
    }

    /// Identity inventory for output-alias rejection, not an admission token.
    pub(super) fn input_file_identities(&self) -> [(u64, u64); 3] {
        self.inputs.each_ref().map(|input| (input.metadata.dev(), input.metadata.ino()))
    }

    fn check_live(&self, deadline: Instant) -> Result<(), String> {
        if std::process::id() != self.owner_pid {
            return Err("native verifier owner crossed its creating process".to_owned());
        }
        live(deadline.min(self.deadline))
    }

    pub(super) fn verify(&self, proof: &Value, session_nonce: &[u8], deadline: Instant)
        -> Result<Value, String> {
        let deadline = deadline.min(self.deadline);
        self.check_live(deadline)?;
        if session_nonce != self.nonce.as_slice() {
            return Err("native verifier expectations differ from the actual client nonce".to_owned());
        }
        value_bounds(proof, MAX_INPUT_BYTES, deadline)?;
        let expected_result = expected_verdict(proof, &self.expected, session_nonce)?;
        let original = serde_json::to_vec(proof).map_err(|_| "encode actual native proof")?;
        if original.is_empty() || original.len() > MAX_INPUT_BYTES {
            return Err("native proof exceeds the verifier input bound".to_owned());
        }
        for input in &self.inputs { input.verify(deadline)?; }
        verify_seals(&self.executable)?;
        let started = epoch_seconds()?;
        let operation_deadline = Instant::now().checked_add(Duration::from_secs(10))
            .ok_or("native verifier deadline overflow")?.min(deadline);
        let output = run_verifier(&self.executable, &self.inputs, &original, operation_deadline)?;
        for input in &self.inputs { input.verify(deadline)?; }
        verify_seals(&self.executable)?;
        self.check_live(deadline)?;
        let output = output.strip_suffix(b"\n").ok_or("native verifier result lacks its one final newline")?;
        let result = strict_json(output, MAX_OUTPUT_BYTES, deadline)?;
        if serde_json::to_vec(&result).map_err(|_| "encode native verifier result")? != output {
            return Err("native verifier result is not exact compact canonical JSON".to_owned());
        }
        let finished = epoch_seconds()?;
        if finished < started { return Err("native verifier local clock moved backwards".to_owned()); }
        let issued = uint(&result, "issuedAtUnix")?;
        fresh(issued, finished, &self.expected)?;
        fresh(uint(&expected_result, "statementIssuedAtUnix")?, finished, &self.expected)?;
        let mut joined = expected_result;
        joined.as_object_mut().ok_or("native verifier result projection is not an object")?
            .insert("issuedAtUnix".to_owned(), Value::from(issued));
        if result != joined {
            return Err("native verifier output differs from actual proof/session/pinned expectations".to_owned());
        }
        self.check_live(deadline)?;
        Ok(result)
    }
}

impl HeldInput {
    fn open(path: PathBuf, pin: String, maximum: usize, retain: bool, deadline: Instant)
        -> Result<(Self, Vec<u8>), String> {
        live(deadline)?;
        if !path.is_absolute() || path.as_os_str().len() > 4096 || !nonzero_digest(&pin) {
            return Err("native verifier inputs require absolute normalized paths and independent SHA256 pins".to_owned());
        }
        let (file, chain, metadata) = super::open_trusted_input_path(
            &path, "native verifier input", false, maximum,
        )?;
        let bytes = read_held(&file, &metadata, maximum, deadline)?;
        if super::sha256_prefixed(&bytes) != pin { return Err("native verifier input digest mismatch".to_owned()); }
        let (_, current_chain, current) = super::open_trusted_input_path(
            &path, "native verifier input", false, maximum,
        )?;
        if current_chain != chain || !same_metadata(&metadata, &current) {
            return Err("native verifier input path changed during acquisition".to_owned());
        }
        live(deadline)?;
        Ok((Self { path, pin, file, metadata, chain, maximum,
            original: retain.then(|| bytes.clone()) }, bytes))
    }

    fn verify(&self, deadline: Instant) -> Result<(), String> {
        live(deadline)?;
        let (_, chain, metadata) = super::open_trusted_input_path(
            &self.path, "native verifier retained input", false, self.maximum,
        )?;
        if chain != self.chain || !same_metadata(&metadata, &self.metadata) {
            return Err("native verifier input path no longer names its retained original".to_owned());
        }
        let bytes = read_held(&self.file, &self.metadata, self.maximum, deadline)?;
        if super::sha256_prefixed(&bytes) != self.pin
            || self.original.as_ref().is_some_and(|original| original != &bytes) {
            return Err("native verifier retained input content changed".to_owned());
        }
        let (_, final_chain, final_metadata) = super::open_trusted_input_path(
            &self.path, "native verifier retained input", false, self.maximum,
        )?;
        if final_chain != self.chain || !same_metadata(&final_metadata, &self.metadata) {
            return Err("native verifier input path changed during remeasurement".to_owned());
        }
        live(deadline)
    }
}

fn same_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    super::trusted_metadata_fingerprint(left) == super::trusted_metadata_fingerprint(right)
        && left.uid() == right.uid() && left.gid() == right.gid()
}

fn read_held(file: &File, expected: &fs::Metadata, maximum: usize, deadline: Instant)
    -> Result<Vec<u8>, String> {
    live(deadline)?;
    let before = file.metadata().map_err(|_| "inspect retained native verifier input")?;
    if !same_metadata(&before, expected) || before.len() == 0 || before.len() > maximum as u64 {
        return Err("native verifier retained file metadata changed".to_owned());
    }
    let mut original = Vec::with_capacity(before.len() as usize);
    let mut chunk = [0u8; 64 * 1024];
    while original.len() < before.len() as usize {
        live(deadline)?;
        let remaining = (before.len() as usize - original.len()).min(chunk.len());
        let count = match file.read_at(&mut chunk[..remaining], original.len() as u64) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("read retained native verifier input".to_owned()),
        };
        live(deadline)?;
        if count == 0 { return Err("native verifier input ended before its retained size".to_owned()); }
        original.extend_from_slice(&chunk[..count]);
    }
    let count = loop {
        live(deadline)?;
        match file.read_at(&mut chunk[..1], before.len()) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => break result.map_err(|_| "probe retained native verifier EOF")?,
        }
    };
    let after = file.metadata().map_err(|_| "reinspect retained native verifier input")?;
    live(deadline)?;
    if count != 0 || !same_metadata(&before, &after) {
        return Err("native verifier input changed while read".to_owned());
    }
    Ok(original)
}

fn live(deadline: Instant) -> Result<(), String> {
    if Instant::now() >= deadline { Err("native verifier original deadline expired".to_owned()) } else { Ok(()) }
}

fn epoch_seconds() -> Result<u64, String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native verifier local wall clock is invalid")?.as_secs();
    if now == 0 { Err("native verifier local wall clock is zero".to_owned()) } else { Ok(now) }
}

fn object<'a>(value: &'a Value, fields: &[&str], label: &str) -> Result<&'a Map<String, Value>, String> {
    let object = value.as_object().ok_or_else(|| format!("{label} must be an object"))?;
    super::require_exact_fields(object, fields, label)?;
    Ok(object)
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| format!("native verifier field {field} must be text"))
}

fn uint(value: &Value, field: &str) -> Result<u64, String> {
    value.get(field).and_then(Value::as_u64).ok_or_else(|| format!("native verifier field {field} must be unsigned"))
}

fn nonzero_digest(value: &str) -> bool {
    super::is_sha256_digest(value) && value[7..].bytes().any(|byte| byte != b'0')
}

fn digest_bytes(value: &str) -> Result<[u8; 32], String> {
    if !nonzero_digest(value) { return Err("native verifier SHA256 pin is invalid".to_owned()); }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&value[7..], &mut bytes).map_err(|_| "decode native verifier SHA256 pin")?;
    Ok(bytes)
}

fn b64(value: &str, minimum: usize, maximum: usize) -> Result<Vec<u8>, String> {
    if value.len() > maximum.saturating_mul(4).div_ceil(3) || value.contains('=') {
        return Err("native verifier base64url field exceeds its canonical bound".to_owned());
    }
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| "native verifier field is not base64url")?;
    if decoded.len() < minimum || decoded.len() > maximum
        || general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err("native verifier base64url field is not exact canonical data".to_owned());
    }
    Ok(decoded)
}

fn validate_expectations(expected: &Value) -> Result<Vec<u8>, String> {
    object(expected, &[
        "apiVersion", "releaseRecordSha256", "policyHash", "configurationSha256",
        "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest",
        "expectedPcrs", "expectedEif", "expectedModuleId", "maxAgeSeconds", "futureSkewSeconds",
        "bootId", "keyId", "controlPlaneResponseSigningKeyId", "nonce",
    ], "native verifier expectations")?;
    if text(expected, "apiVersion")? != "serverware.nativeResponseAttestationExpectations/v1" {
        return Err("native verifier expectations version mismatch".to_owned());
    }
    for field in ["releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
        "caPublicKeySpkiSha256", "expectedBinaryDigest", "keyId", "controlPlaneResponseSigningKeyId"] {
        digest_bytes(text(expected, field)?)?;
    }
    b64(text(expected, "bootId")?, 32, 32)?;
    let nonce = b64(text(expected, "nonce")?, 32, 64)?;
    if !(1..=300).contains(&uint(expected, "maxAgeSeconds")?) || uint(expected, "futureSkewSeconds")? > 30 {
        return Err("native verifier age expectations are outside the fixed profile".to_owned());
    }
    let module = text(expected, "expectedModuleId")?;
    if module.is_empty() || module.len() > 256 || module.chars().any(|ch| ch <= '\u{1f}' || ch == '\u{7f}') {
        return Err("native verifier module pin is invalid".to_owned());
    }
    let pcrs = expected.get("expectedPcrs").and_then(Value::as_object)
        .ok_or("native verifier PCR pins are not an object")?;
    if !(3..=32).contains(&pcrs.len()) { return Err("native verifier complete PCR inventory is invalid".to_owned()); }
    for (name, value) in pcrs {
        let number = name.strip_prefix("PCR").and_then(|suffix| suffix.parse::<u8>().ok())
            .filter(|number| *number <= 31 && name == &format!("PCR{number}"))
            .ok_or("native verifier PCR index is invalid")?;
        let value = value.as_str().ok_or("native verifier PCR pin is not text")?;
        if value.len() != 103 || !value.starts_with("sha384:")
            || !value[7..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || (number <= 2 && value[7..].bytes().all(|byte| byte == b'0')) {
            return Err("native verifier PCR digest is invalid".to_owned());
        }
    }
    if ["PCR0", "PCR1", "PCR2"].iter().any(|name| !pcrs.contains_key(*name))
        || pcrs.get("PCR0").and_then(Value::as_str) != Some(text(expected, "expectedEif")?) {
        return Err("native verifier core PCR/EIF pins disagree".to_owned());
    }
    Ok(nonce)
}

fn validate_trust(trust: &Value) -> Result<(), String> {
    object(trust, &["apiVersion", "awsNitroRootCertificatesPem", "awsNitroCrlsDerBase64url",
        "nitroCertificateProfile"], "native verifier trust roots")?;
    let roots = trust.get("awsNitroRootCertificatesPem").and_then(Value::as_array)
        .ok_or("native verifier trust root inventory is invalid")?;
    if text(trust, "apiVersion")? != "serverware.nativeResponseAttestationTrustRoots/v1"
        || !(1..=16).contains(&roots.len())
        || roots.iter().any(|value| value.as_str().is_none_or(|pem| pem.is_empty() || pem.len() > 64 * 1024 || !pem.is_ascii()))
        || trust.get("awsNitroCrlsDerBase64url") != Some(&json!([])) {
        return Err("native verifier trust material differs from the fixed native profile".to_owned());
    }
    let profile = trust.get("nitroCertificateProfile").ok_or("native verifier certificate profile absent")?;
    object(profile, &["profileId", "allowedLeafExtendedKeyUsageOids"], "native verifier certificate profile")?;
    let eku = profile.get("allowedLeafExtendedKeyUsageOids").and_then(Value::as_array)
        .ok_or("native verifier EKU pins are invalid")?;
    if text(profile, "profileId")? != "aws-nitro-attestation-pki-native-v1"
        || eku.len() > 32 || eku.iter().any(|value| value.as_str().is_none_or(|oid| oid.is_empty() || oid.len() > 256)) {
        return Err("native verifier certificate profile is invalid".to_owned());
    }
    // Full PEM/X509/profile validation belongs to the genuine pinned verifier.
    Ok(())
}

fn fresh(issued: u64, now: u64, expected: &Value) -> Result<(), String> {
    if issued == 0 || issued > now.saturating_add(uint(expected, "futureSkewSeconds")?)
        || now.saturating_sub(issued) > uint(expected, "maxAgeSeconds")? {
        return Err("native verifier quote/statement is outside its pinned age interval".to_owned());
    }
    Ok(())
}

fn expected_verdict(proof: &Value, expected: &Value, nonce: &[u8]) -> Result<Value, String> {
    object(proof, &["apiVersion", "kind", "server_statement", "server_statement_sha256",
        "server_signature", "native_attestation"], "native proof envelope")?;
    if text(proof, "apiVersion")? != "serverware.nativeResponseRuntimeProof/v1"
        || text(proof, "kind")? != "ServerwareNativeResponseRuntimeProof" {
        return Err("native proof envelope discriminator mismatch".to_owned());
    }
    let statement = proof.get("server_statement").ok_or("native statement absent")?;
    let version = text(statement, "apiVersion")?;
    if !matches!(version, "serverware.proxyResponseStatement/v2" | "serverware.streamingResponseStatement/v1"
        | "serverware.responseObservationStatement/v1")
        || (version != "serverware.proxyResponseStatement/v2" && nonce.len() != 32)
        || text(statement, "client_nonce")? != general_purpose::URL_SAFE_NO_PAD.encode(nonce) {
        return Err("native statement family or actual session nonce mismatch".to_owned());
    }
    let policy = if version == "serverware.responseObservationStatement/v1" {
        text(statement.get("policy").ok_or("native observation policy absent")?, "digest")?
    } else { text(statement, "policy_digest")? };
    if policy != text(expected, "policyHash")?
        || text(statement, "data_plane_binary_digest")? != text(expected, "expectedBinaryDigest")? {
        return Err("native statement policy/binary differs from pinned scope".to_owned());
    }
    let canonical = serde_json::to_vec(statement).map_err(|_| "encode native statement")?;
    if canonical.is_empty() || canonical.len() > MAX_STATEMENT_BYTES { return Err("native statement exceeds bound".to_owned()); }
    let statement_digest = super::sha256_prefixed(&canonical);
    if text(proof, "server_statement_sha256")? != statement_digest { return Err("native statement digest mismatch".to_owned()); }
    let signed = proof.get("server_signature").ok_or("native signature absent")?;
    object(signed, &["algorithm", "key_id", "public_key_pem", "signature"], "native signature")?;
    let pem = text(signed, "public_key_pem")?;
    if pem.is_empty() || pem.len() > 4096 { return Err("native proof PEM exceeds bound".to_owned()); }
    let (key, key_id) = super::decode_public_key_pem(pem)?;
    if text(signed, "algorithm")? != "Ed25519" || text(signed, "key_id")? != key_id
        || key_id != text(expected, "keyId")? { return Err("native proof key differs from pinned SPKI identity".to_owned()); }
    let signature = b64(text(signed, "signature")?.strip_prefix("ed25519:")
        .ok_or("native signature encoding is invalid")?, 64, 64)?;
    let signature_array: [u8; 64] = signature.as_slice().try_into().map_err(|_| "native signature length mismatch")?;
    key.verify_strict(&canonical, &Signature::from_bytes(&signature_array))
        .map_err(|_| "native statement signature verification failed")?;
    let evidence = proof.get("native_attestation").ok_or("native attestation absent")?;
    object(evidence, &["apiVersion", "attestationDocumentB64", "responseProofPublicKey"], "native attestation")?;
    let evidence_key = b64(text(evidence, "responseProofPublicKey")?, 32, 32)?;
    if text(evidence, "apiVersion")? != "serverware.nativeResponseProofKeyEvidence/v1"
        || evidence_key.as_slice() != key.as_bytes().as_slice() {
        return Err("native original quote public key differs from actual signature key".to_owned());
    }
    let document = b64(text(evidence, "attestationDocumentB64")?, 1, 12 * 1024)?;
    let mut challenge = Sha256::new();
    challenge.update(CHALLENGE_DOMAIN);
    challenge.update([u8::try_from(nonce.len()).map_err(|_| "native client nonce length overflow")?]);
    challenge.update(nonce);
    challenge.update(Sha256::digest(&canonical));
    challenge.update(&signature);
    let challenge: [u8; 32] = challenge.finalize().into();
    let mut boot = Sha256::new();
    boot.update(BOOT_DOMAIN);
    boot.update(b64(text(expected, "bootId")?, 32, 32)?);
    boot.update(digest_bytes(text(expected, "keyId")?)?);
    boot.update(digest_bytes(text(expected, "controlPlaneResponseSigningKeyId")?)?);
    let boot: [u8; 32] = boot.finalize().into();
    let statement_issued = uint(statement, "issued_at_unix")?;
    fresh(statement_issued, epoch_seconds()?, expected)?;
    Ok(json!({
        "apiVersion":"serverware.nativeResponseAttestationVerification/v1", "ok":true, "debug":false,
        "resultScope":"local-signature-and-native-quote-only", "okForAction":false,
        "statementApiVersion":version, "serverStatementSha256":statement_digest,
        "signatureSha256":super::sha256_prefixed(&signature), "clientNonce":text(expected,"nonce")?,
        "quoteChallenge":general_purpose::URL_SAFE_NO_PAD.encode(challenge), "bootId":text(expected,"bootId")?,
        "keyId":key_id, "controlPlaneResponseSigningKeyId":text(expected,"controlPlaneResponseSigningKeyId")?,
        "policyHash":policy, "dataPlaneBinaryDigest":text(expected,"expectedBinaryDigest")?,
        "requestBindingSha256":format!("sha256:{}",hex::encode(boot)),
        "attestationDocumentSha256":super::sha256_prefixed(&document), "issuedAtUnix":0,
        "statementIssuedAtUnix":statement_issued,
    }))
}

// serde_json's default Value map overwrites duplicate keys. Keep originals
// strict without imposing canonical whitespace on independently pinned files.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded JSON without duplicate keys or floats")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> { Ok(UniqueValue(Value::Bool(value))) }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> { Ok(UniqueValue(Value::from(value))) }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> { Ok(UniqueValue(Value::from(value))) }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> { Err(E::custom("floating JSON is not accepted")) }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> { Ok(UniqueValue(Value::String(value.to_owned()))) }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> { Ok(UniqueValue(Value::String(value))) }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> { Ok(UniqueValue(Value::Null)) }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> { Ok(UniqueValue(Value::Null)) }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    if values.len() >= 100_000 { return Err(de::Error::custom("too many JSON array entries")); }
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.len() >= 100_000 || values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate or excessive JSON object keys"));
                    }
                    values.insert(key, map.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn strict_json(bytes: &[u8], maximum: usize, deadline: Instant) -> Result<Value, String> {
    live(deadline)?;
    if bytes.is_empty() || bytes.len() > maximum { return Err("native verifier JSON exceeds byte bound".to_owned()); }
    let parsed: UniqueValue = serde_json::from_slice(bytes).map_err(|_| "native verifier JSON is not strict")?;
    value_bounds(&parsed.0, maximum, deadline)?;
    Ok(parsed.0)
}

fn value_bounds(value: &Value, maximum: usize, deadline: Instant) -> Result<(), String> {
    let mut pending = vec![(value, 0usize)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        live(deadline)?;
        nodes = nodes.checked_add(1).ok_or("native verifier node count overflow")?;
        if nodes > 100_000 || depth > 64 { return Err("native verifier JSON exceeds structural bound".to_owned()); }
        match value {
            Value::Object(object) => {
                if object.len() > 100_000 { return Err("native verifier JSON object exceeds bound".to_owned()); }
                for (key, child) in object {
                    bytes = bytes.checked_add(key.len()).ok_or("native verifier JSON size overflow")?;
                    pending.push((child, depth + 1));
                }
            }
            Value::Array(array) => {
                if array.len() > 100_000 { return Err("native verifier JSON array exceeds bound".to_owned()); }
                pending.extend(array.iter().map(|child| (child, depth + 1)));
            }
            Value::String(text) => { bytes = bytes.checked_add(text.len()).ok_or("native verifier JSON size overflow")?; }
            Value::Number(number) if number.as_u64().is_none() && number.as_i64().is_none() => {
                return Err("native verifier JSON contains a noninteger number".to_owned());
            }
            _ => {},
        }
        if bytes > maximum || pending.len().saturating_add(nodes) > 100_000 {
            return Err("native verifier JSON exceeds aggregate bound".to_owned());
        }
    }
    live(deadline)
}

fn elf_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(bytes.get(offset..offset.saturating_add(2)).ok_or("truncated verifier ELF")?
        .try_into().map_err(|_| "invalid verifier ELF integer")?))
}
fn elf_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(bytes.get(offset..offset.saturating_add(4)).ok_or("truncated verifier ELF")?
        .try_into().map_err(|_| "invalid verifier ELF integer")?))
}
fn elf_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(bytes.get(offset..offset.saturating_add(8)).ok_or("truncated verifier ELF")?
        .try_into().map_err(|_| "invalid verifier ELF integer")?))
}

fn validate_static_elf(bytes: &[u8], deadline: Instant) -> Result<(), String> {
    live(deadline)?;
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4..7] != [2, 1, 1]
        || !matches!(elf_u16(bytes, 16)?, 2 | 3) || elf_u16(bytes, 18)? != 62
        || elf_u32(bytes, 20)? != 1 || elf_u16(bytes, 54)? != 56 {
        return Err("native verifier must be a static little-endian x86-64 ELF".to_owned());
    }
    let start = usize::try_from(elf_u64(bytes, 32)?).map_err(|_| "verifier ELF program offset overflow")?;
    let count = usize::from(elf_u16(bytes, 56)?);
    if !(1..=256).contains(&count) || start.checked_add(count * 56).is_none_or(|end| end > bytes.len()) {
        return Err("native verifier ELF program table is invalid".to_owned());
    }
    let mut load = false;
    for index in 0..count {
        live(deadline)?;
        let header = start + index * 56;
        let kind = elf_u32(bytes, header)?;
        if kind == 3 { return Err("native verifier must not use an interpreter".to_owned()); }
        if kind == 1 { load = true; }
        if kind != 2 { continue; }
        let offset = usize::try_from(elf_u64(bytes, header + 8)?).map_err(|_| "verifier dynamic offset overflow")?;
        let length = usize::try_from(elf_u64(bytes, header + 32)?).map_err(|_| "verifier dynamic size overflow")?;
        let end = offset.checked_add(length).ok_or("verifier dynamic segment overflow")?;
        if length % 16 != 0 || end > bytes.len() { return Err("verifier dynamic segment is invalid".to_owned()); }
        let mut terminated = false;
        for entry in (offset..end).step_by(16) {
            live(deadline)?;
            match elf_u64(bytes, entry)? {
                0 => { terminated = true; break; }
                1 => return Err("native verifier must not load shared libraries".to_owned()),
                _ => {},
            }
        }
        if !terminated { return Err("native verifier dynamic segment is unterminated".to_owned()); }
    }
    if !load { return Err("native verifier has no loadable ELF segment".to_owned()); }
    live(deadline)
}

fn seal_executable(bytes: &[u8], deadline: Instant) -> Result<File, String> {
    live(deadline)?;
    let descriptor = unsafe { libc::memfd_create(c"serverware-native-response-verifier".as_ptr(),
        libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 { return Err("create native verifier sealed snapshot".to_owned()); }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.set_permissions(fs::Permissions::from_mode(0o500)).map_err(|_| "set native verifier snapshot mode")?;
    for chunk in bytes.chunks(64 * 1024) {
        live(deadline)?;
        file.write_all(chunk).map_err(|_| "write native verifier snapshot")?;
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| "reset native verifier snapshot")?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err("seal native verifier snapshot".to_owned());
    }
    verify_seals(&file)?;
    live(deadline)?;
    Ok(file)
}

fn verify_seals(file: &File) -> Result<(), String> {
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    let actual = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if actual < 0 || actual & required != required { return Err("native verifier executable lost its seals".to_owned()); }
    Ok(())
}

/// The direct child stays unreaped until group shutdown, so its PID cannot be
/// recycled before the negative-PID signal. This owns cleanup on every error,
/// including setup errors after a successful spawn. It does not supervise code
/// that deliberately escapes its original process group.
struct VerifierChild {
    child: Child,
    reaped: bool,
}

impl VerifierChild {
    fn terminate_group(&mut self) -> Result<(), String> {
        if self.reaped { return Ok(()); }
        let pid = i32::try_from(self.child.id()).map_err(|_| "native verifier child PID overflow")?;
        let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            // The caller still owns/reaps the direct child on this error path.
            let _ = self.child.kill();
            return Err("terminate native verifier process group".to_owned());
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), String> {
        self.terminate_group()?;
        let status = self.child.wait().map_err(|_| "reap native verifier child")?;
        self.reaped = true;
        if !status.success() { return Err("native verifier did not exit successfully".to_owned()); }
        Ok(())
    }
}

impl Drop for VerifierChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.terminate_group();
            let _ = self.child.kill();
            if self.child.wait().is_ok() { self.reaped = true; }
        }
    }
}

fn nonblocking(descriptor: i32) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("set native verifier pipe nonblocking".to_owned());
    }
    Ok(())
}

/// Observes, but never reaps, the one child. WNOWAIT preserves PID reservation
/// until VerifierChild has terminated the original process group.
fn exited_successfully(child: &VerifierChild, deadline: Instant) -> Result<bool, String> {
    loop {
        live(deadline)?;
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let result = unsafe { libc::waitid(libc::P_PID, child.child.id() as libc::id_t,
            &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted { continue; }
            return Err("observe native verifier final exit".to_owned());
        }
        live(deadline)?;
        let pid = unsafe { info.si_pid() };
        if pid == 0 { return Ok(false); }
        if pid as u32 != child.child.id() || info.si_code != libc::CLD_EXITED
            || unsafe { info.si_status() } != 0 {
            return Err("native verifier failed or was terminated".to_owned());
        }
        return Ok(true);
    }
}

fn run_verifier(executable: &File, inputs: &[HeldInput; 3], original: &[u8], deadline: Instant)
    -> Result<Vec<u8>, String> {
    live(deadline)?;
    verify_seals(executable)?;
    // All storage and argument construction occurs before fork. The pre-exec
    // closure performs only libc syscalls and uses these already-owned bytes.
    let arguments = vec![
        CString::new(inputs[0].path.as_os_str().as_bytes()).map_err(|_| "verifier path contains NUL")?,
        CString::new("--expectations").map_err(|_| "fixed verifier argument")?,
        CString::new(inputs[1].path.as_os_str().as_bytes()).map_err(|_| "expectations path contains NUL")?,
        CString::new("--expectations-sha256").map_err(|_| "fixed verifier argument")?,
        CString::new(inputs[1].pin.as_bytes()).map_err(|_| "expectations pin contains NUL")?,
        CString::new("--trust-roots").map_err(|_| "fixed verifier argument")?,
        CString::new(inputs[2].path.as_os_str().as_bytes()).map_err(|_| "trust path contains NUL")?,
        CString::new("--trust-roots-sha256").map_err(|_| "fixed verifier argument")?,
        CString::new(inputs[2].pin.as_bytes()).map_err(|_| "trust pin contains NUL")?,
    ];
    let mut argument_pointers: Vec<usize> = arguments.iter().map(|value| value.as_ptr() as usize).collect();
    argument_pointers.push(0);
    // No inherited configuration, search path, loader knobs, or Python module
    // path. The separately pinned static executable must be self-contained.
    let environment = [CString::new("LANG=C").map_err(|_| "fixed verifier environment")?,
        CString::new("LC_ALL=C").map_err(|_| "fixed verifier environment")?,
        CString::new("TZ=UTC").map_err(|_| "fixed verifier environment")?];
    let mut environment_pointers: Vec<usize> = environment.iter().map(|value| value.as_ptr() as usize).collect();
    environment_pointers.push(0);
    let executable_fd = executable.as_raw_fd();
    let mut command = Command::new("/proc/self/exe");
    command.env_clear().current_dir("/").stdin(Stdio::piped())
        .stdout(Stdio::piped()).stderr(Stdio::null()).process_group(0);
    unsafe {
        command.pre_exec(move || {
            // Retain the backing CString allocations in this closure, not just
            // integer representations of their pointers.
            let _ = (&arguments, &environment);
            // CLOEXEC (not close) preserves Rust's spawn error pipe and the
            // executable until execveat; no unrelated descriptor crosses exec.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            libc::execveat(executable_fd, c"".as_ptr(),
                argument_pointers.as_ptr().cast(), environment_pointers.as_ptr().cast(),
                libc::AT_EMPTY_PATH);
            // Never fall through to Command's nominal executable/path lookup.
            Err(io::Error::last_os_error())
        });
    }
    live(deadline)?;
    let mut owner = VerifierChild { child: command.spawn().map_err(|_| "spawn pinned native verifier")?, reaped: false };
    live(deadline)?;
    let mut input = Some(owner.child.stdin.take().ok_or("native verifier stdin missing")?);
    let mut output_pipe = owner.child.stdout.take().ok_or("native verifier stdout missing")?;
    nonblocking(input.as_ref().ok_or("native verifier stdin missing")?.as_raw_fd())?;
    nonblocking(output_pipe.as_raw_fd())?;
    let mut written = 0usize;
    let mut output = Vec::with_capacity(MAX_OUTPUT_BYTES);
    let mut eof = false;
    loop {
        live(deadline)?;
        if let Some(pipe) = input.as_mut() {
            match pipe.write(&original[written..]) {
                Ok(0) => return Err("native verifier stdin made no progress".to_owned()),
                Ok(count) => written += count,
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {},
                Err(_) => return Err("write actual proof to native verifier".to_owned()),
            }
            if written == original.len() { input.take(); }
        }
        if !eof {
            let mut buffer = [0u8; MAX_OUTPUT_BYTES + 1];
            let remaining = MAX_OUTPUT_BYTES + 1 - output.len();
            match output_pipe.read(&mut buffer[..remaining]) {
                Ok(0) => eof = true,
                Ok(count) => {
                    output.extend_from_slice(&buffer[..count]);
                    if output.len() > MAX_OUTPUT_BYTES {
                        return Err("native verifier output exceeds its fixed bound".to_owned());
                    }
                },
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {},
                Err(_) => return Err("read actual native verifier result".to_owned()),
            }
        }
        let exited = exited_successfully(&owner, deadline)?;
        if exited && written != original.len() {
            return Err("native verifier exited without accepting the complete proof".to_owned());
        }
        if exited && eof {
            if output.is_empty() { return Err("native verifier returned no result".to_owned()); }
            // Kill same-group descendants while the exited leader is still
            // reserved, then reap exactly that leader and require its success.
            owner.finish()?;
            live(deadline)?;
            return Ok(output);
        }
        let mut polls = [libc::pollfd { fd: -1, events: 0, revents: 0 }; 2];
        if let Some(pipe) = &input { polls[0].fd = pipe.as_raw_fd(); polls[0].events = libc::POLLOUT; }
        if !eof { polls[1].fd = output_pipe.as_raw_fd(); polls[1].events = libc::POLLIN; }
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or("native verifier deadline expired")?;
        let slice = remaining.min(Duration::from_millis(5));
        let timeout = libc::timespec { tv_sec: 0, tv_nsec: slice.as_nanos() as _ };
        let result = unsafe { libc::ppoll(polls.as_mut_ptr(), polls.len() as _, &timeout, std::ptr::null()) };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err("poll native verifier pipes".to_owned());
        }
        if polls.iter().any(|poll| poll.revents & libc::POLLNVAL != 0) {
            return Err("native verifier pipe custody changed".to_owned());
        }
    }
}

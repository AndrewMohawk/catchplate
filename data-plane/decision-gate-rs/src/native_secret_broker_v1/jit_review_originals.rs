//! Exact private originals, not an authenticated caller or a Python float codec.
//! RawValue borrows numeric spellings, including integers outside u64. The actual
//! measured child additionally enforces Python's canonical number spelling and
//! the complete private-v2 semantics before it can return a successful reply.
use super::*;
use serde::de::{self, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::fmt;

const ARGUMENTS: &[&str] = &["schema", "route_id", "method", "principal_id", "credential_id",
    "credential_version", "policy_hash", "request_digest", "operation_digest", "pending_ttl_seconds",
    "grant_ttl_seconds", "grant_max_uses", "required_approver_roles", "allowed_approver_ids",
    "require_approver_webauthn", "approval_threshold", "approver_credential_policy", "url_commitment",
    "canonical_request_digest", "redacted_display_digest", "original_arguments_digest", "businessIntent"];

struct RawObject<'a>(BTreeMap<String, &'a RawValue>);
impl<'de> Deserialize<'de> for RawObject<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = RawObject<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("unique JSON object") }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut result = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if result.contains_key(&key) { return Err(de::Error::custom("duplicate private key")); }
                    result.insert(key, map.next_value::<&'de RawValue>()?);
                }
                Ok(RawObject(result))
            }
        }
        d.deserialize_map(ObjectVisitor)
    }
}
pub(super) fn object(raw: &[u8]) -> Result<BTreeMap<String, &RawValue>, String> {
    serde_json::from_slice::<RawObject<'_>>(raw).map(|v| v.0)
        .map_err(|_| "JIT original object differs".to_owned())
}
pub(super) fn keys(value: &BTreeMap<String, &RawValue>, expected: &[&str]) -> Result<(), String> {
    ensure(value.len() == expected.len() && expected.iter().all(|name| value.contains_key(*name)),
        "JIT original fields differ")
}

// Check bounded, duplicate-free, sorted compact structure without ever
// converting private numeric originals to serde_json::Number. Python's exact
// finite-float spelling is checked by the real child, not claimed by this leaf.
pub(super) fn structure(raw: &[u8], depth: usize, nodes: &mut usize) -> Result<(), String> {
    *nodes += 1;
    ensure(depth <= 32 && *nodes <= 131072 && !raw.is_empty() && raw.is_ascii(), "JIT original structure bound")?;
    match raw[0] {
        b'{' => {
            let values = object(raw)?;
            let mut canonical = Zeroizing::new(Vec::with_capacity(raw.len())); canonical.push(b'{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index > 0 { canonical.push(b','); }
                canonical.extend(canonical_ascii_bytes(key)?); canonical.push(b':');
                structure(value.get().as_bytes(), depth + 1, nodes)?;
                canonical.extend_from_slice(value.get().as_bytes());
            }
            canonical.push(b'}'); ensure(canonical.as_slice() == raw, "JIT object original is not compact canonical structure")
        }
        b'[' => {
            let values: Vec<&RawValue> = serde_json::from_slice(raw).map_err(|_| "JIT original array differs")?;
            let mut canonical = Zeroizing::new(Vec::with_capacity(raw.len())); canonical.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 { canonical.push(b','); }
                structure(value.get().as_bytes(), depth + 1, nodes)?;
                canonical.extend_from_slice(value.get().as_bytes());
            }
            canonical.push(b']'); ensure(canonical.as_slice() == raw, "JIT array original is not compact")
        }
        b'"' => {
            let value: String = serde_json::from_slice(raw).map_err(|_| "JIT original string differs")?;
            ensure(canonical_ascii_bytes(&value)? == raw, "JIT string original differs")
        }
        _ => {
            let value: &RawValue = serde_json::from_slice(raw).map_err(|_| "JIT original scalar differs")?;
            ensure(value.get().as_bytes() == raw, "JIT scalar contains outer whitespace")?;
            if (raw[0] == b'-' || raw[0].is_ascii_digit())
                && raw.iter().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                let number: f64 = std::str::from_utf8(raw).map_err(|_| "JIT number encoding")?
                    .parse().map_err(|_| "JIT number syntax")?;
                ensure(number.is_finite(), "JIT number is not finite")?;
            }
            Ok(())
        }
    }
}

pub(super) struct Originals {
    pub request: Value, pub plaintexts: [(String, usize); 2],
}

pub(super) fn read(runtime: &[u8], public: &[u8]) -> Result<Originals, String> {
    ensure(!runtime.is_empty() && runtime.len() <= MAX_COMMAND && public.len() <= MAX_COMMAND,
        "JIT originals exceed bound")?;
    structure(runtime, 0, &mut 0)?;
    let envelope = object(runtime)?;
    keys(&envelope, &["schema", "handler", "operationManifestDigest", "arguments", "privateDocuments"])?;
    let request = document(public, MAX_COMMAND)?;
    fields(&request, &["schema", "operation", "operationId", "requestDigest", "handler", "operationManifestDigest", "arguments"])?;
    ensure(request["schema"] == "catchplate.policyAuthorityV9Request/v1" && request["operation"] == "jit.request"
        && request["handler"] == "ensure_jit_approval_request", "JIT public request purpose differs")?;
    for (name, expected) in [("schema", json!("catchplate.policyAuthorityPrivateJitWriterInput/v2")),
        ("handler", request["handler"].clone()), ("operationManifestDigest", request["operationManifestDigest"].clone())] {
        ensure(document(envelope[name].get().as_bytes(), MAX_COMMAND)? == expected, "JIT private envelope differs")?;
    }
    let arguments = &request["arguments"]; fields(arguments, ARGUMENTS)?;
    ensure(arguments["schema"] == "catchplate.jitRequestCommitments/v2", "JIT public profile differs")?;
    let mut unsigned = arguments.as_object().ok_or("JIT public arguments")?.clone(); unsigned.remove("businessIntent");
    let unsigned = Value::Object(unsigned);
    ensure(document(envelope["arguments"].get().as_bytes(), MAX_COMMAND)? == unsigned, "JIT public/private arguments differ")?;
    let intent = &arguments["businessIntent"];
    fields(intent, &["schema", "operation", "planningAdapterId", "arguments"])?;
    ensure(intent["schema"] == "catchplate.policyAuthorityBusinessIntent/v2" && intent["operation"] == "jit.request"
        && intent["arguments"] == unsigned && !text(&intent["planningAdapterId"] )?.is_empty(), "JIT business intent differs")?;
    let auth = json!({"schema":"catchplate.policyAuthorityV9Authorization/v1", "operation":"jit.request",
        "handler":request["handler"], "operationManifestDigest":request["operationManifestDigest"], "arguments":arguments});
    let request_digest = framed("catchplate.policyAuthorityV9Request/v1", &[&canonical_ascii_bytes(&auth)?]);
    ensure(request["requestDigest"] == request_digest && request["operationId"] == framed(
        "catchplate.policyAuthorityOperation/v2", &[b"jit.request", request_digest.as_bytes()]), "JIT public commitment differs")?;
    let private = object(envelope["privateDocuments"].get().as_bytes())?;
    keys(&private, &["url", "canonical_request", "redacted_display"])?;
    let url: String = serde_json::from_str(private["url"].get()).map_err(|_| "JIT URL original differs")?;
    ensure(!url.is_empty(), "JIT URL is empty")?;
    object(private["canonical_request"].get().as_bytes())?; object(private["redacted_display"].get().as_bytes())?;
    for (field, raw) in [("url_commitment", url.as_bytes()), ("canonical_request_digest", private["canonical_request"].get().as_bytes()),
        ("redacted_display_digest", private["redacted_display"].get().as_bytes())] {
        ensure(arguments[field] == sha(raw), "JIT private byte commitment differs")?;
    }
    let public_originals = object(envelope["arguments"].get().as_bytes())?;
    let mut raw_arguments: BTreeMap<&str, &[u8]> = public_originals.iter().filter(|(name, _)| ![
        "schema", "url_commitment", "canonical_request_digest", "redacted_display_digest", "original_arguments_digest"
    ].contains(&name.as_str())).map(|(name, value)| (name.as_str(), value.get().as_bytes())).collect();
    raw_arguments.extend(private.iter().map(|(name, value)| (name.as_str(), value.get().as_bytes())));
    let raw_arguments = join(&raw_arguments)?;
    ensure(arguments["original_arguments_digest"] == sha(&raw_arguments), "JIT original arguments commitment differs")?;
    let wrapper = join(&BTreeMap::from([
        ("schema", b"\"catchplate.jitCanonicalReviewPayload/v1\"".as_slice()),
        ("url", private["url"].get().as_bytes()), ("canonical_request", private["canonical_request"].get().as_bytes())]))?;
    let display = private["redacted_display"].get().as_bytes();
    Ok(Originals { request, plaintexts: [(sha(&wrapper), wrapper.len()), (sha(display), display.len())] })
}

pub(super) fn join(values: &BTreeMap<&str, &[u8]>) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut raw = Zeroizing::new(Vec::new()); raw.push(b'{');
    for (index, (key, value)) in values.iter().enumerate() {
        if index > 0 { raw.push(b','); }
        raw.extend(canonical_ascii_bytes(key)?); raw.push(b':'); raw.extend_from_slice(value);
    }
    raw.push(b'}'); Ok(raw)
}

pub(super) fn command_inputs(raw: &[u8]) -> Result<(Originals, Value), String> {
    ensure(raw.len() <= MAX_COMMAND, "JIT command bound")?;
    structure(raw, 0, &mut 0)?;
    let values = object(raw)?;
    keys(&values, &["apiVersion", "phase", "runtimeInput", "publicRequest", "issuedAtEpochNs",
        "sealExpiresAtEpochNs", "documentExpiresAtEpochNs", "deadlineBoottimeNs", "challenge"])?;
    let originals = read(values["runtimeInput"].get().as_bytes(), values["publicRequest"].get().as_bytes())?;
    let control = values.iter().filter(|(key, _)| !["runtimeInput", "publicRequest"].contains(&key.as_str()))
        .map(|(key, value)| Ok((key.clone(), document(value.get().as_bytes(), MAX_COMMAND)?)))
        .collect::<Result<serde_json::Map<String, Value>, String>>()?;
    Ok((originals, Value::Object(control)))
}

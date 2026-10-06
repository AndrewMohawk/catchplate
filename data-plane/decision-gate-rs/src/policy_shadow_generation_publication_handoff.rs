//! Existing publication handoff protocol over a borrowed, independently admitted
//! purpose key and replay journal. This module does not admit either resource.
//!
//! The caller must serialize its actual owner, retain its original lifetime and
//! authenticate the replay namespace/current head (including rollback protection)
//! on every `check`. File identity, a checksum chain and flock do NOT supply that
//! authority. There is deliberately no path/env loader or poisoned-worker retry.
use crate::policy_shadow::{
    canonical_json_bytes, EnvelopePayload, Sha256Digest, SignedEnvelope,
    CANONICAL_PROFILE, SIGNED_ENVELOPE_DOMAIN,
};
use crate::policy_shadow_generation_publication_protocol::{
    verify_external_publication_record, GenerationPublicationExternalPayload,
    GenerationPublicationPayload, GenerationPublicationPreparationPayload,
    PublicationHandoffResponse, PublicationRequestBinding, PublicationTrustBinding,
    MAX_PUBLICATION_HANDOFF_OUTPUT_BYTES, MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS,
    PUBLICATION_HANDOFF_API_VERSION,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{pkcs8::EncodePublicKey, Signature, Signer, SigningKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::{fs::File, os::fd::AsRawFd, os::unix::fs::{FileExt, MetadataExt}};

// Same input ceiling as the existing native shadow worker, not a new transport.
const MAX_INPUT: usize = 32 * 1024 * 1024;
const MAX_FRAME: usize = 2 * MAX_INPUT + 4 * MAX_PUBLICATION_HANDOFF_OUTPUT_BYTES + 4096;
const JOURNAL_SCHEMA: &str = "serverware.privateGenerationPublicationJournal/v1";

pub(crate) struct Authority<'a> {
    pub(crate) key: &'a SigningKey,
    pub(crate) signing_key_id: &'a Sha256Digest,
    pub(crate) signing_key_spki_sha256: &'a Sha256Digest,
    pub(crate) replay_store_sha256: &'a Sha256Digest,
    // Explicit admitted resource ceiling; there is no default or growth grant.
    pub(crate) journal_limit_bytes: u64,
    // Actual owner, original clock and independently admitted replay currentness.
    // A newly constructed closure or an arbitrary file is not admission.
    pub(crate) check: &'a dyn Fn() -> Result<i64, String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    api_version: String,
    operation: String,
    shadow_role_signing_key_id: Sha256Digest,
    shadow_role_signing_key_spki_sha256: Sha256Digest,
    durable_replay_store_sha256: Sha256Digest,
    body: Value,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Prepare { proposed_preparation: GenerationPublicationPreparationPayload }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Commit {
    preparation_envelope_sha256: Sha256Digest,
    internal_publication_payload: GenerationPublicationPayload,
    publication_payload: GenerationPublicationExternalPayload,
}
enum Operation { Prepare(Prepare), Commit(Commit) }
impl Operation {
    fn request(&self) -> &PublicationRequestBinding {
        match self { Self::Prepare(v) => &v.proposed_preparation.request,
            Self::Commit(v) => &v.internal_publication_payload.request }
    }
    fn trust(&self) -> &PublicationTrustBinding {
        match self { Self::Prepare(v) => &v.proposed_preparation.trust,
            Self::Commit(v) => &v.internal_publication_payload.trust }
    }
    fn interval(&self) -> (i64, i64) {
        match self { Self::Prepare(v) => (v.proposed_preparation.issued_at_unix_nanos,
                v.proposed_preparation.expires_at_unix_nanos),
            Self::Commit(v) => (v.internal_publication_payload.issued_at_unix_nanos,
                v.internal_publication_payload.expires_at_unix_nanos) }
    }
    fn local_profile(&self) -> bool {
        let chain = match self { Self::Prepare(v) => &v.proposed_preparation.attestation_chain,
            Self::Commit(v) => &v.internal_publication_payload.attestation_chain };
        chain.attestation_mode == "trusted-host-no-tee" && !chain.hardware_attested
    }
}

// Private storage framing only: neither a signed evidence format nor a receipt.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Frame {
    api_version: String,
    replay_store_sha256: Sha256Digest,
    previous_sha256: Option<Sha256Digest>,
    request_original: String,
    result: Option<StoredResult>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredResult {
    response_original: String,
    // Commit also durably stores its prepare-or-recover response. The signed
    // envelopes are identical; readback does not re-sign or re-encode a result.
    recovery_original: Option<String>,
}
struct Completed { original: String, operation: Operation, result: StoredResult }

fn require(value: bool, detail: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(detail.into()) }
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    canonical_json_bytes(value).map_err(|e| e.to_string())
}
fn exact<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T, String> {
    let value: T = serde_json::from_slice(raw).map_err(|_| "publication original is not closed JSON")?;
    require(canonical(&value)? == raw, "publication original is not canonical")?;
    Ok(value)
}
fn text(raw: Vec<u8>) -> Result<String, String> {
    require(raw.is_ascii(), "publication original is not ASCII")?;
    String::from_utf8(raw).map_err(|_| "publication original encoding".into())
}
fn current(authority: &Authority<'_>, interval: (i64, i64)) -> Result<(), String> {
    let now = (authority.check)()?;
    require(interval.0 > 0 && interval.0 <= now && now < interval.1
        && interval.1.checked_sub(interval.0).is_some_and(|n| n <= MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS),
        "publication original lifetime is unavailable")
}
fn decode(raw: &[u8], authority: &Authority<'_>) -> Result<Operation, String> {
    require(!raw.is_empty() && raw.len() <= MAX_INPUT, "publication input exceeds original bound")?;
    let request: Request = exact(raw)?;
    require(request.api_version == PUBLICATION_HANDOFF_API_VERSION
        && &request.shadow_role_signing_key_id == authority.signing_key_id
        && &request.shadow_role_signing_key_spki_sha256 == authority.signing_key_spki_sha256
        && &request.durable_replay_store_sha256 == authority.replay_store_sha256,
        "publication input differs from admitted authority")?;
    let body = canonical(&request.body)?;
    let operation = match request.operation.as_str() {
        "prepare-or-recover" => {
            let value: Prepare = exact(&body)?;
            value.proposed_preparation.validate_intrinsic().map_err(|e| e.to_string())?;
            Operation::Prepare(value)
        }
        "commit" => {
            let value: Commit = exact(&body)?;
            let internal = &value.internal_publication_payload;
            let external = &value.publication_payload;
            internal.validate_intrinsic().map_err(|e| e.to_string())?;
            external.validate_intrinsic().map_err(|e| e.to_string())?;
            require(value.preparation_envelope_sha256 == internal.preparation_envelope_sha256
                && external.record.generation_evidence == *internal
                && external.issued_at_epoch_ns == internal.issued_at_unix_nanos
                && external.expires_at_epoch_ns == internal.expires_at_unix_nanos,
                "publication commit originals diverge")?;
            verify_external_publication_record(&external.record, internal)
                .map_err(|_| "publication external projection differs")?;
            Operation::Commit(value)
        }
        _ => return Err("publication operation is not admitted".into()),
    };
    let trust = operation.trust();
    require(&trust.publication_signing_key_id == authority.signing_key_id
        && &trust.publication_signing_key_spki_sha256 == authority.signing_key_spki_sha256
        && &trust.publication_replay_store_sha256 == authority.replay_store_sha256
        && operation.local_profile(),
        "publication payload differs from admitted authority")?;
    Ok(operation)
}

fn preimage<T: EnvelopePayload>(payload: &T) -> Result<Vec<u8>, String> {
    let raw = canonical(payload)?;
    // Exactly policy_shadow::signature_preimage, not custody's length framing.
    Ok([SIGNED_ENVELOPE_DOMAIN, &[0], payload.envelope_signature_domain().as_bytes(),
        &[0], CANONICAL_PROFILE.as_bytes(), &[0], raw.as_slice()].concat())
}
fn sign<T: EnvelopePayload>(payload: T, authority: &Authority<'_>) -> Result<SignedEnvelope<T>, String> {
    payload.validate_intrinsic().map_err(|e| e.to_string())?;
    let original = preimage(&payload)?;
    current(authority, (payload.issued_at_unix_nanos(), payload.expires_at_unix_nanos()))?;
    let signature = URL_SAFE_NO_PAD.encode(authority.key.sign(&original).to_bytes());
    let envelope = SignedEnvelope::from_external_signature(payload, authority.signing_key_id.clone(),
        authority.signing_key_spki_sha256.clone(), signature).map_err(|e| e.to_string())?;
    verify_stored(&envelope, authority)?;
    Ok(envelope)
}
fn verify_stored<T: EnvelopePayload>(envelope: &SignedEnvelope<T>, authority: &Authority<'_>) -> Result<(), String> {
    // Historical journal integrity only; each returned response separately uses
    // current() under its unchanged original interval. No expired action grant.
    let value = serde_json::to_value(envelope).map_err(|_| "publication envelope encoding")?;
    let signature = value.get("signature").and_then(Value::as_str).ok_or("publication signature absent")?;
    let bytes = URL_SAFE_NO_PAD.decode(signature).map_err(|_| "publication signature encoding")?;
    require(bytes.len() == 64 && URL_SAFE_NO_PAD.encode(&bytes) == signature, "publication signature is not canonical")?;
    let bytes: [u8; 64] = bytes.try_into().map_err(|_| "publication signature size")?;
    let expected = SignedEnvelope::from_external_signature(envelope.untrusted_payload().clone(),
        authority.signing_key_id.clone(), authority.signing_key_spki_sha256.clone(), signature.into())
        .map_err(|e| e.to_string())?;
    require(canonical(&expected)? == canonical(envelope)?, "stored publication envelope metadata differs")?;
    authority.key.verifying_key().verify_strict(&preimage(envelope.untrusted_payload())?, &Signature::from_bytes(&bytes))
        .map_err(|_| "stored publication signature is invalid".into())
}

fn encode_response(operation: &str, preparation: Option<SignedEnvelope<GenerationPublicationPreparationPayload>>,
    internal: Option<SignedEnvelope<GenerationPublicationPayload>>,
    external: Option<SignedEnvelope<GenerationPublicationExternalPayload>>) -> Result<String, String> {
    let raw = canonical(&PublicationHandoffResponse {
        api_version: PUBLICATION_HANDOFF_API_VERSION.into(), operation: operation.into(),
        status: if preparation.is_some() { "prepared" } else { "completed" }.into(),
        preparation, internal_publication: internal, publication: external,
    })?;
    require(raw.len() <= MAX_PUBLICATION_HANDOFF_OUTPUT_BYTES, "publication output exceeds original bound")?;
    text(raw)
}
fn parsed_response(raw: &str, operation: &str) -> Result<PublicationHandoffResponse, String> {
    require(raw.len() <= MAX_PUBLICATION_HANDOFF_OUTPUT_BYTES, "stored publication output exceeds original bound")?;
    let result: PublicationHandoffResponse = exact(raw.as_bytes())?;
    require(result.api_version == PUBLICATION_HANDOFF_API_VERSION && result.operation == operation,
        "stored publication response metadata differs")?;
    Ok(result)
}
fn sizing_result(operation: &Operation, authority: &Authority<'_>) -> Result<StoredResult, String> {
    // The canonical unpadded signature has exactly 86 non-escaping ASCII bytes.
    // These placeholders are used ONLY for size arithmetic, never persisted,
    // returned, verified as evidence, or passed to a signer.
    fn shape<T: EnvelopePayload>(payload: T, authority: &Authority<'_>) -> Result<SignedEnvelope<T>, String> {
        SignedEnvelope::from_external_signature(payload, authority.signing_key_id.clone(),
            authority.signing_key_spki_sha256.clone(), URL_SAFE_NO_PAD.encode([0u8; 64]))
            .map_err(|e| e.to_string())
    }
    match operation {
        Operation::Prepare(value) => Ok(StoredResult { response_original: encode_response("prepare-or-recover",
            Some(shape(value.proposed_preparation.clone(), authority)?), None, None)?, recovery_original: None }),
        Operation::Commit(value) => {
            let internal = shape(value.internal_publication_payload.clone(), authority)?;
            let external = shape(value.publication_payload.clone(), authority)?;
            Ok(StoredResult { response_original: encode_response("commit", None, Some(internal.clone()), Some(external.clone()))?,
                recovery_original: Some(encode_response("prepare-or-recover", None, Some(internal), Some(external))?) })
        }
    }
}
fn related(left: &PublicationRequestBinding, right: &PublicationRequestBinding) -> bool {
    left.request_id == right.request_id || left.replay_id == right.replay_id
        || left.management_handoff_id == right.management_handoff_id || left.request_sha256 == right.request_sha256
}
fn preparation<'a>(entries: &'a [Completed], request: &PublicationRequestBinding) -> Result<Option<&'a Completed>, String> {
    let mut found = None;
    for entry in entries {
        if let Operation::Prepare(_) = &entry.operation {
            if related(entry.operation.request(), request) {
                require(found.is_none() && entry.operation.request() == request, "publication replay identity conflicts")?;
                found = Some(entry);
            }
        }
    }
    Ok(found)
}
fn join_commit(value: &Commit, prepared: &Completed) -> Result<(), String> {
    let Operation::Prepare(original) = &prepared.operation else { return Err("publication preparation absent".into()); };
    let envelope = parsed_response(&prepared.result.response_original, "prepare-or-recover")?
        .preparation.ok_or("publication preparation envelope absent")?;
    let previous = &original.proposed_preparation;
    let next = &value.internal_publication_payload;
    require(Sha256Digest::compute(&canonical(&envelope)?) == value.preparation_envelope_sha256
        && next.request == previous.request && next.generation == previous.generation
        && next.runtime == previous.runtime && next.trust == previous.trust
        && next.attestation_chain == previous.attestation_chain
        && next.not_before_unix_nanos == previous.not_before_unix_nanos
        && next.issued_at_unix_nanos == previous.issued_at_unix_nanos
        && next.expires_at_unix_nanos == previous.expires_at_unix_nanos,
        "publication commit differs from its original durable preparation")
}
fn validate_result(operation: &Operation, stored: &StoredResult, entries: &[Completed], authority: &Authority<'_>) -> Result<(), String> {
    match operation {
        Operation::Prepare(value) => {
            require(stored.recovery_original.is_none(), "preparation has unexpected recovery output")?;
            let response = parsed_response(&stored.response_original, "prepare-or-recover")?;
            require(response.status == "prepared" && response.internal_publication.is_none()
                && response.publication.is_none(), "stored preparation shape differs")?;
            let envelope = response.preparation.ok_or("stored preparation absent")?;
            require(envelope.untrusted_payload() == &value.proposed_preparation, "stored preparation payload differs")?;
            verify_stored(&envelope, authority)
        }
        Operation::Commit(value) => {
            join_commit(value, preparation(entries, &value.internal_publication_payload.request)?
                .ok_or("commit has no durable preparation")?)?;
            let response = parsed_response(&stored.response_original, "commit")?;
            require(response.status == "completed" && response.preparation.is_none(), "stored commit shape differs")?;
            let internal = response.internal_publication.ok_or("stored internal publication absent")?;
            let external = response.publication.ok_or("stored external publication absent")?;
            require(internal.untrusted_payload() == &value.internal_publication_payload
                && external.untrusted_payload() == &value.publication_payload, "stored commit payload differs")?;
            verify_stored(&internal, authority)?;
            verify_stored(&external, authority)?;
            require(stored.recovery_original.as_deref() == Some(encode_response("prepare-or-recover", None,
                Some(internal), Some(external))?.as_str()), "stored completed recovery differs")
        }
    }
}

struct Journal<'a> {
    file: &'a File, identity: (u64, u64, u32, u32, u32), length: u64,
    previous: Option<Sha256Digest>,
}
impl Drop for Journal<'_> {
    fn drop(&mut self) { unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN); } }
}
impl<'a> Journal<'a> {
    fn open(file: &'a File, authority: &Authority<'_>) -> Result<Self, String> {
        (authority.check)()?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        require(flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDWR && flags & libc::O_APPEND == 0
            && metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o022 == 0
            && authority.journal_limit_bytes > 0 && metadata.len() <= authority.journal_limit_bytes,
            "publication journal descriptor is unavailable")?;
        require(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "publication journal is busy")?;
        let result = Self { file, identity: (metadata.dev(), metadata.ino(), metadata.uid(), metadata.gid(), metadata.mode()),
            length: metadata.len(), previous: None };
        result.check(authority)?;
        Ok(result)
    }
    fn check(&self, authority: &Authority<'_>) -> Result<(), String> {
        (authority.check)()?;
        let metadata = self.file.metadata().map_err(|e| e.to_string())?;
        require((metadata.dev(), metadata.ino(), metadata.uid(), metadata.gid(), metadata.mode()) == self.identity
            && metadata.nlink() == 1 && metadata.len() == self.length
            && self.length <= authority.journal_limit_bytes, "publication journal identity or length changed")
    }
    fn read(&mut self, authority: &Authority<'_>) -> Result<Vec<Completed>, String> {
        let mut entries = Vec::new();
        let mut pending: Option<String> = None;
        let mut offset = 0u64;
        while offset < self.length {
            self.check(authority)?;
            let mut prefix = [0u8; 8];
            require(self.length - offset >= 8, "publication journal is torn; outcome remains unknown")?;
            self.file.read_exact_at(&mut prefix, offset).map_err(|e| e.to_string())?;
            let size = u64::from_be_bytes(prefix);
            require(size > 0 && size <= MAX_FRAME as u64 && size <= self.length - offset - 8,
                "publication journal is torn; outcome remains unknown")?;
            let mut raw = vec![0; size as usize];
            self.file.read_exact_at(&mut raw, offset + 8).map_err(|e| e.to_string())?;
            let frame: Frame = exact(&raw)?;
            require(frame.api_version == JOURNAL_SCHEMA && &frame.replay_store_sha256 == authority.replay_store_sha256
                && frame.previous_sha256 == self.previous, "publication journal framing differs")?;
            let operation = decode(frame.request_original.as_bytes(), authority)?;
            match frame.result {
                None => {
                    require(pending.is_none(), "publication journal has unresolved intent")?;
                    validate_new(&operation, &frame.request_original, &entries)?;
                    pending = Some(frame.request_original);
                }
                Some(result) => {
                    require(pending.take().as_deref() == Some(frame.request_original.as_str()),
                        "publication journal result has no exact intent")?;
                    validate_result(&operation, &result, &entries, authority)?;
                    entries.push(Completed { original: frame.request_original, operation, result });
                }
            }
            self.previous = Some(Sha256Digest::compute(&raw));
            offset += 8 + size;
        }
        self.check(authority)?;
        require(pending.is_none(), "publication intent has no durable result; outcome remains unknown")?;
        Ok(entries)
    }
    fn append(&mut self, original: &str, result: Option<StoredResult>, authority: &Authority<'_>, interval: (i64, i64)) -> Result<(), String> {
        let raw = canonical(&Frame { api_version: JOURNAL_SCHEMA.into(), replay_store_sha256: authority.replay_store_sha256.clone(),
            previous_sha256: self.previous.clone(), request_original: original.into(), result })?;
        require(raw.len() <= MAX_FRAME, "publication journal frame exceeds fixed bound")?;
        let framed = [(raw.len() as u64).to_be_bytes().as_slice(), raw.as_slice()].concat();
        let end = self.length.checked_add(framed.len() as u64).ok_or("publication journal size overflow")?;
        require(end <= authority.journal_limit_bytes, "publication journal capacity unavailable")?;
        self.check(authority)?;
        current(authority, interval)?;
        // Any partial write/fsync failure is left intact. Never truncate, repair,
        // retry signing, or turn an absent response into permission to retry.
        let offset = self.length;
        self.file.write_all_at(&framed, offset).map_err(|e| e.to_string())?;
        self.length = end;
        self.check(authority)?;
        current(authority, interval)?;
        self.file.sync_all().map_err(|e| e.to_string())?;
        let mut readback = vec![0; framed.len()];
        self.file.read_exact_at(&mut readback, offset).map_err(|e| e.to_string())?;
        require(readback == framed, "publication journal append readback differs")?;
        self.check(authority)?;
        self.previous = Some(Sha256Digest::compute(&raw));
        current(authority, interval)?;
        Ok(())
    }
    fn reserve_pair(&self, original: &str, operation: &Operation, authority: &Authority<'_>) -> Result<(), String> {
        let intent = canonical(&Frame { api_version: JOURNAL_SCHEMA.into(), replay_store_sha256: authority.replay_store_sha256.clone(),
            previous_sha256: self.previous.clone(), request_original: original.into(), result: None })?;
        let terminal = canonical(&Frame { api_version: JOURNAL_SCHEMA.into(), replay_store_sha256: authority.replay_store_sha256.clone(),
            previous_sha256: Some(Sha256Digest::compute(&intent)), request_original: original.into(),
            result: Some(sizing_result(operation, authority)?) })?;
        require(intent.len() <= MAX_FRAME && terminal.len() <= MAX_FRAME,
            "publication journal frame exceeds fixed bound")?;
        let total = self.length.checked_add(16).and_then(|n| n.checked_add(intent.len() as u64))
            .and_then(|n| n.checked_add(terminal.len() as u64)).ok_or("publication journal size overflow")?;
        require(total <= authority.journal_limit_bytes, "publication journal pair capacity unavailable")?;
        self.check(authority)?;
        current(authority, operation.interval())
    }
    fn sync_recovered(&self, authority: &Authority<'_>, interval: (i64, i64)) -> Result<(), String> {
        // A complete tail may have been written by a process that died before
        // its fsync. Force its durability before returning retained originals.
        self.check(authority)?;
        current(authority, interval)?;
        self.file.sync_all().map_err(|e| e.to_string())?;
        self.check(authority)?;
        current(authority, interval)
    }
}

fn validate_new(operation: &Operation, original: &str, entries: &[Completed]) -> Result<(), String> {
    match operation {
        Operation::Prepare(value) => {
            require(preparation(entries, operation.request())?.is_none(), "publication preparation already exists")?;
            for entry in entries {
                if let Operation::Prepare(previous) = &entry.operation {
                    // Assignment revision is not an authenticated journal head.
                    require(value.proposed_preparation.generation.generation_id != previous.proposed_preparation.generation.generation_id,
                        "publication generation conflicts")?;
                }
            }
        }
        Operation::Commit(value) => {
            join_commit(value, preparation(entries, operation.request())?.ok_or("publication preparation absent")?)?;
            require(!entries.iter().any(|e| matches!(&e.operation, Operation::Commit(_))
                && (related(e.operation.request(), operation.request()) || e.original == original)),
                "publication already has a terminal result")?;
        }
    }
    Ok(())
}

/// The caller's admitted key/store/currentness capability is borrowed for this
/// entire call. Returning bytes reports only a durably retained signed outcome;
/// it does not install/activate anything or authorize a retry after any error.
pub(crate) fn handle(original: &[u8], file: &File, authority: Authority<'_>) -> Result<Vec<u8>, String> {
    (authority.check)()?;
    let spki = authority.key.verifying_key().to_public_key_der().map_err(|_| "publication key encoding")?;
    require(Sha256Digest::compute(spki.as_bytes()) == *authority.signing_key_spki_sha256,
        "publication key differs from admitted SPKI")?;
    let operation = decode(original, &authority)?;
    current(&authority, operation.interval())?;
    let original = std::str::from_utf8(original).map_err(|_| "publication original encoding")?;
    let mut journal = Journal::open(file, &authority)?;
    let entries = journal.read(&authority)?;
    if let Some(prepared) = preparation(&entries, operation.request())? {
        let complete = entries.iter().find(|entry| matches!(&entry.operation, Operation::Commit(_))
            && entry.operation.request() == operation.request());
        let retained = match &operation {
            Operation::Prepare(_) => {
                require(prepared.original == original, "publication preparation original conflicts")?;
                Some(match complete { Some(value) => value.result.recovery_original.as_ref().ok_or("completed recovery absent")?,
                    None => &prepared.result.response_original })
            }
            Operation::Commit(_) => match complete {
                Some(value) => { require(value.original == original, "publication commit original conflicts")?;
                    Some(&value.result.response_original) }, None => None,
            },
        };
        if let Some(retained) = retained {
            let output = retained.as_bytes().to_vec();
            journal.sync_recovered(&authority, operation.interval())?;
            return Ok(output);
        }
    }
    validate_new(&operation, original, &entries)?;
    journal.reserve_pair(original, &operation, &authority)?;
    journal.append(original, None, &authority, operation.interval())?;
    let result = match &operation {
        Operation::Prepare(value) => StoredResult { response_original: encode_response("prepare-or-recover",
            Some(sign(value.proposed_preparation.clone(), &authority)?), None, None)?, recovery_original: None },
        Operation::Commit(value) => {
            let internal = sign(value.internal_publication_payload.clone(), &authority)?;
            let external = sign(value.publication_payload.clone(), &authority)?;
            StoredResult { response_original: encode_response("commit", None, Some(internal.clone()), Some(external.clone()))?,
                recovery_original: Some(encode_response("prepare-or-recover", None, Some(internal), Some(external))?) }
        }
    };
    validate_result(&operation, &result, &entries, &authority)?;
    let output = result.response_original.as_bytes().to_vec();
    journal.append(original, Some(result), &authority, operation.interval())?;
    journal.check(&authority)?;
    current(&authority, operation.interval())?;
    Ok(output)
}

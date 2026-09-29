//! Actual claim-bound write-once publication and read-only operator inspection.
//! A historical result is never a start, cleanup, repair or retry capability.
use super::{hex, identity, FileIdentity, Journal, StartPermit, MAGIC, RECORD_BYTES, SLOT_DOMAIN};
use super::outcome_record as record;
use super::super::{lifecycle::LifecycleObservation, parent::DirectoryChain, start_authority};
use super::super::super::{ensure, json, originals::{ArtifactV1, HeldOriginal}, OriginalClock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileExt;
use std::time::Duration;
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;

fn now() -> Result<u64, String> {
    super::super::guardian_process::now().ok_or("native outcome BOOTTIME unavailable".to_owned())
}
fn name(slot: &[u8], suffix: &str) -> CString {
    CString::new(format!("{}.{}", hex(slot), suffix)).expect("fixed native outcome name")
}
fn claim(raw: &[u8], slot: &[u8]) -> Result<[u8; RECORD_BYTES], String> {
    ensure(raw.len() == RECORD_BYTES && &raw[..8] == MAGIC && raw[8] == 1 && &raw[9..41] == slot
        && raw[9..41].iter().any(|b| *b != 0) && raw[41..].iter().any(|b| *b != 0),
        "native outcome claim is malformed or belongs to another slot")?;
    raw.try_into().map_err(|_| "native outcome claim width differs".to_owned())
}

struct Original { file: File, identity: FileIdentity, raw: Vec<u8>, name: CString }
impl Original {
    fn recheck(&self, directory: &DirectoryChain, device: u64) -> Result<(), String> {
        directory.check_identity()?;
        ensure(identity(&self.file, device, self.raw.len() as u64)? == self.identity,
            "native outcome retained original changed")?;
        let mut raw = vec![0; self.raw.len()];
        ensure(self.file.read_at(&mut raw, 0).map_err(|_| "native outcome original readback failed")? == raw.len()
            && raw == self.raw, "native outcome original bytes changed")?;
        let fd = unsafe { libc::openat(directory.fd().as_raw_fd(), self.name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        ensure(fd >= 0, "native outcome named original disappeared")?;
        let named = unsafe { File::from_raw_fd(fd) };
        ensure(identity(&named, device, raw.len() as u64)? == self.identity
            && identity(&self.file, device, raw.len() as u64)? == self.identity,
            "native outcome name no longer selects its held original")?;
        raw.fill(0);
        ensure(named.read_at(&mut raw, 0).map_err(|_| "native outcome named readback failed")? == raw.len()
            && raw == self.raw && identity(&named, device, raw.len() as u64)? == self.identity
            && identity(&self.file, device, raw.len() as u64)? == self.identity,
            "native outcome named bytes differ from the retained original")?;
        directory.check_identity()
    }
}

fn open(directory: &DirectoryChain, device: u64, name: CString, maximum: usize)
    -> Result<Option<Original>, String> {
    directory.check_identity()?;
    let fd = unsafe { libc::openat(directory.fd().as_raw_fd(), name.as_ptr(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if fd < 0 {
        ensure(std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
            "native outcome record cannot be inspected")?;
        directory.check_identity()?;
        return Ok(None);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let length = file.metadata().map_err(|_| "native outcome size unavailable")?.len();
    ensure(length <= maximum as u64, "native outcome record exceeds its preallocation bound")?;
    let observed = identity(&file, device, length)?;
    let mut raw = vec![0; length as usize];
    ensure(file.read_at(&mut raw, 0).map_err(|_| "native outcome bounded read failed")? == raw.len(),
        "native outcome record read is incomplete")?;
    let held = Original { file, identity: observed, raw, name };
    held.recheck(directory, device)?;
    Ok(Some(held))
}

fn writer_check(permit: &StartPermit) -> Result<(), String> {
    ensure(permit.journal.owner.constraints().journal.outcome_profile.as_deref()
        == Some(start_authority::OUTCOME_PROFILE), "native outcome lacks its distinct signed purpose")?;
    permit.check_cleanup_integrity()?;
    let before = now()?;
    ensure(before >= permit.outcome_boottime.get() && before < permit.journal.owner.cleanup_boottime_ns(),
        "native outcome writer passed its original cleanup deadline or clock regressed")?;
    permit.journal.owner.check_outcome_originals()?;
    let after = now()?;
    ensure(after >= before && after < permit.journal.owner.cleanup_boottime_ns(),
        "native outcome original check missed cleanup deadline or clock regressed")?;
    permit.outcome_boottime.set(after);
    Ok(())
}

fn write_once(permit: &StartPermit, name: CString, raw: Vec<u8>) -> Result<Original, String> {
    writer_check(permit)?;
    let journal = &permit.journal;
    let device = journal.owner.constraints().journal.device;
    let fd = unsafe { libc::openat(journal.directory.fd().as_raw_fd(), name.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, 0o600) };
    ensure(fd >= 0, "native outcome exclusive publication refused; no replacement or retry")?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    // Any failure from this point preserves the exact name, even a partial
    // write or uncertain fsync. Emergency cleanup is independent of this IO.
    writer_check(permit)?;
    ensure(unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == 0, "native outcome permissions unavailable")?;
    identity(&file, device, 0)?;
    writer_check(permit)?;
    ensure(file.write(&raw).map_err(|_| "native outcome write uncertain; attempt consumed")? == raw.len(),
        "native outcome write partial; attempt consumed")?;
    writer_check(permit)?;
    let observed = identity(&file, device, raw.len() as u64)?;
    file.sync_all().map_err(|_| "native outcome file durability unknown")?;
    writer_check(permit)?;
    journal.directory.sync().map_err(|_| "native outcome directory durability unknown")?;
    writer_check(permit)?;
    let held = Original { file, identity: observed, raw, name };
    held.recheck(&journal.directory, device)?;
    writer_check(permit)?;
    Ok(held)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in super::super::super) struct Receipt {
    api_version: &'static str, result_scope: &'static str,
    slot_sha256: String, operation_sha256: String, outcome_sha256: String, raw_evidence_sha256: String,
    recorded_boottime_ns: u64, action_authorization: Option<()>, ok_for_action: bool,
}

pub(in super::super) struct Committed { receipt: Receipt, outcome: Original, complete: Original }
impl Committed {
    pub(in super::super) fn receipt(&self) -> &Receipt { &self.receipt }
    pub(in super::super) fn check(&self, permit: &StartPermit) -> Result<(), String> {
        // Read-only custody after publication; never renew the writing window.
        permit.check_cleanup_integrity()?;
        let device = permit.journal.owner.constraints().journal.device;
        self.outcome.recheck(&permit.journal.directory, device)?;
        self.complete.recheck(&permit.journal.directory, device)?;
        record::committed(&permit.journal.original, &self.outcome.raw, &self.complete.raw)?;
        Ok(())
    }
}

pub(in super::super) fn publish(permit: &StartPermit, observation: &LifecycleObservation)
    -> Result<Committed, String> {
    ensure(!permit.outcome_attempted.replace(true), "native outcome publication attempt already consumed")?;
    writer_check(permit)?;
    let originals = observation.publication_originals(permit)?;
    let canonical = canonical_ascii_bytes(observation)?;
    let claim = &permit.journal.original;
    let raw = record::encode(claim, permit.journal.owner.cleanup_boottime_ns(),
        [&canonical, originals.0, originals.1, originals.2, originals.3])?;
    let decoded = record::decode(&raw, claim)?;
    ensure(record::sha(&raw) != [0; 32] && decoded.evidence != [0; 32],
        "native outcome digest is zero")?;
    writer_check(permit)?;
    let outcome = write_once(permit, name(&claim[9..41], "outcome"), raw)?;
    let recorded = now()?;
    let complete_raw = record::marker(claim, &outcome.raw, recorded)?;
    let complete = write_once(permit, name(&claim[9..41], "complete"), complete_raw.to_vec())?;
    let result = Committed { receipt: Receipt {
        api_version: "serverware.nativeExecutionOutcomeReceipt/v1",
        result_scope: "local-durable-native-terminal-outcome", slot_sha256: format!("sha256:{}", hex(&claim[9..41])),
        operation_sha256: format!("sha256:{}", hex(&claim[41..])), outcome_sha256: record::digest(&record::sha(&outcome.raw)),
        raw_evidence_sha256: record::digest(&decoded.evidence), recorded_boottime_ns: recorded,
        action_authorization: None, ok_for_action: false }, outcome, complete };
    result.check(permit)?;
    writer_check(permit)?;
    Ok(result)
}

/// V3 inventory is additive and closed. V1/v2 keep their original claim-only
/// inventory; old claims are not promoted to publication permission.
pub(super) fn inventory(journal: &Journal) -> Result<(), String> {
    journal.check_admission()?;
    let fd = unsafe { libc::openat(journal.directory.fd().as_raw_fd(), b".\0".as_ptr().cast(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    ensure(fd >= 0, "native outcome inventory unavailable")?;
    let pointer = unsafe { libc::fdopendir(fd) };
    if pointer.is_null() { unsafe { libc::close(fd); } return Err("native outcome inventory unavailable".to_owned()); }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream { fn drop(&mut self) { unsafe { libc::closedir(self.0); } } }
    let stream = Stream(pointer); let mut names = BTreeSet::new(); let mut slots = BTreeSet::new();
    loop {
        journal.check_admission()?;
        unsafe { *libc::__errno_location() = 0; }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() { ensure(unsafe { *libc::__errno_location() } == 0, "native outcome inventory read failed")?; break; }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." { continue; }
        ensure(names.len() < 192 && bytes.len() >= 70 && bytes[..64].iter().all(|b|
            b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            && matches!(&bytes[64..], b".claim" | b".outcome" | b".complete")
            && names.insert(bytes.to_vec()), "native outcome inventory contains an unknown or excessive name")?;
        ensure(&bytes[..64] != hex(&journal.original[9..41]).as_bytes(),
            "native outcome slot is consumed; no retry or reattachment")?;
        slots.insert(bytes[..64].to_vec());
        ensure(slots.len() < 64, "native outcome journal has no free stable slot")?;
    }
    let device = journal.owner.constraints().journal.device;
    for slot_name in slots {
        journal.check_admission()?;
        let text = std::str::from_utf8(&slot_name).map_err(|_| "native outcome slot is not ASCII")?;
        let mut slot = [0u8; 32];
        for (index, byte) in slot.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| "native outcome slot invalid")?;
        }
        let originals = inspect(&journal.directory, device, &slot, None)?;
        ensure(originals.status != "no-claim", "native outcome inventory lacks its claim")?;
        journal.check_admission()?;
    }
    Ok(())
}

struct Inspection { status: &'static str, outcome: Option<Value>, hash: Option<String>, held: Vec<Original> }
fn inspect(directory: &DirectoryChain, device: u64, slot: &[u8; 32], expected: Option<&str>)
    -> Result<Inspection, String> {
    let claim_file = open(directory, device, name(slot, "claim"), RECORD_BYTES)?;
    let outcome = open(directory, device, name(slot, "outcome"), record::MAX_RECORD)?;
    let complete = open(directory, device, name(slot, "complete"), record::COMPLETE_BYTES)?;
    let mut held = Vec::with_capacity(3);
    let Some(claim_file) = claim_file else {
        ensure(outcome.is_none() && complete.is_none(), "native outcome orphaned records refused")?;
        return Ok(Inspection { status: "no-claim", outcome: None, hash: None, held });
    };
    let claim = claim(&claim_file.raw, slot)?;
    if let Some(expected) = expected {
        ensure(format!("sha256:{}", hex(&claim[41..])) == expected, "native outcome expected operation differs")?;
    }
    held.push(claim_file);
    match (outcome, complete) {
        (Some(outcome), Some(complete)) => {
            let (decoded, _) = record::committed(&claim, &outcome.raw, &complete.raw)?;
            let hash = Some(record::digest(&record::sha(&outcome.raw)));
            held.push(outcome); held.push(complete);
            Ok(Inspection { status: "committed-outcome-observed", outcome: Some(decoded.observation), hash, held })
        },
        (outcome, complete) => {
            if let Some(original) = outcome { held.push(original); }
            if let Some(original) = complete { held.push(original); }
            Ok(Inspection { status: "consumed-outcome-unknown", outcome: None, hash: None, held })
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupJournal { path: String, device: u64, inode: u64, namespace: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Lookup { api_version: String, journal: LookupJournal, capability_id: String, expected_operation_sha256: String }
fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

pub(in super::super::super) fn lookup(artifact: ArtifactV1, clock: &OriginalClock) -> Result<(), String> {
    // This new allowance is read-only, never projected into a claim/owner or
    // used to finish a stale writer. No network, private issuer key or exec.
    clock.limit(Duration::from_secs(5))?;
    ensure(unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
        && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0,
        "native outcome lookup requires the protected local operator")?;
    super::super::super::config::artifact(&artifact)?;
    let (mut original, raw) = HeldOriginal::read_private(artifact, 8192)?;
    clock.check()?;
    let value = json::parse(&raw, 8192)?;
    ensure(canonical_ascii_bytes(&value)? == raw.as_slice(), "native outcome lookup configuration is not canonical")?;
    let config: Lookup = serde_json::from_value(value).map_err(|_| "native outcome lookup configuration is not closed")?;
    ensure(config.api_version == "serverware.nativeExecutionOutcomeLookup/v1"
        && config.journal.device != 0 && config.journal.inode != 0
        && identifier(&config.journal.namespace) && identifier(&config.capability_id)
        && crate::is_sha256_digest(&config.expected_operation_sha256), "native outcome lookup scope differs")?;
    let directory = DirectoryChain::open(&config.journal.path, config.journal.device, config.journal.inode, true, clock)?;
    ensure(unsafe { libc::flock(directory.fd().as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0,
        "native outcome journal is still exclusively owned; lookup did not wait or alter it")?;
    let mut hash = Sha256::new(); hash.update(SLOT_DOMAIN);
    for part in [config.journal.namespace.as_bytes(), config.capability_id.as_bytes()] {
        hash.update((part.len() as u32).to_be_bytes()); hash.update(part);
    }
    let slot: [u8; 32] = hash.finalize().into();
    clock.check()?;
    let inspection = inspect(&directory, config.journal.device, &slot, Some(&config.expected_operation_sha256))?;
    clock.check()?; original.recheck()?; original.require_private()?;
    for held in &inspection.held { clock.check()?; held.recheck(&directory, config.journal.device)?; }
    let result = json!({"apiVersion":"serverware.nativeExecutionOutcomeLookupResult/v1",
        "resultScope":"local-protected-native-outcome-observation", "configurationSha256":record::digest(&record::sha(&raw)),
        "slotSha256":record::digest(&slot), "expectedOperationSha256":config.expected_operation_sha256,
        "status":inspection.status, "outcomeSha256":inspection.hash, "outcome":inspection.outcome,
        "actionAuthorization":null, "okForAction":false});
    let mut encoded = serde_json::to_vec(&result).map_err(|_| "native outcome lookup result encoding failed")?;
    ensure(encoded.len() < 32 * 1024 && !encoded.contains(&b'\n'), "native outcome lookup output exceeds its bound")?;
    encoded.push(b'\n');
    let stdout = std::io::stdout(); let mut output = stdout.lock();
    for chunk in encoded.chunks(4096) {
        clock.check()?; directory.check_identity()?;
        output.write_all(chunk).map_err(|_| "native outcome lookup output interrupted")?;
        clock.check()?;
    }
    output.flush().map_err(|_| "native outcome lookup output flush failed")?;
    clock.check()?; original.recheck()?; original.require_private()?; directory.check_identity()
}

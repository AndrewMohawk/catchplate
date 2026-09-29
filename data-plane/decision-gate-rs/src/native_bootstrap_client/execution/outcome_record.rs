//! Closed historical record codec. Parsing grants no action or retry permission.
use super::super::guardian_process;
use super::super::super::{ensure, json};
use serde_json::Value;
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};

pub(super) const MAX_RECORD: usize = 1152 * 1024;
pub(super) const COMPLETE_BYTES: usize = 192;
const HEADER: usize = 132;
const LIMITS: [usize; 5] = [24 * 1024, 1024 * 1024, guardian_process::FRAME_BYTES, 4096, 1024];
const MAGIC: &[u8; 8] = b"SWNEOUT1";
const COMPLETE: &[u8; 8] = b"SWNEOCM1";

pub(super) fn sha(raw: &[u8]) -> [u8; 32] { Sha256::digest(raw).into() }
pub(super) fn digest(raw: &[u8; 32]) -> String { format!("sha256:{}", super::hex(raw)) }
fn u64_at(raw: &[u8], at: usize) -> Result<u64, String> {
    Ok(u64::from_be_bytes(raw.get(at..at + 8).ok_or("native outcome integer is truncated")?
        .try_into().map_err(|_| "native outcome integer width differs")?))
}
fn shape(value: &Value, keys: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("native outcome object absent")?;
    ensure(object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)),
        "native outcome object is not closed")
}
fn positive(value: &Value) -> Result<u64, String> {
    value.as_u64().filter(|value| *value != 0).ok_or("native outcome positive integer absent".to_owned())
}
fn hash(value: &Value) -> Result<(), String> {
    ensure(value.as_str().is_some_and(crate::is_sha256_digest), "native outcome digest invalid")
}
fn inert(value: &Value) -> Result<(), String> {
    ensure(value["okForAction"] == false && value["actionAuthorization"].is_null(),
        "native outcome cannot carry action authority")
}
fn name(value: &Value, maximum: usize) -> Result<(), String> {
    let text = value.as_str().ok_or("native outcome name absent")?;
    ensure(!text.is_empty() && text.len() <= maximum && text.as_bytes()[0].is_ascii_alphanumeric()
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "native outcome name invalid")
}

fn observation(raw: &[u8], operation: [u8; 32], deadline: u64) -> Result<(Value, u64), String> {
    let value = json::parse(raw, LIMITS[0])?;
    ensure(canonical_ascii_bytes(&value)? == raw, "native outcome observation is not canonical")?;
    shape(&value, &["schema", "resultScope", "execution", "output", "cleanup", "retirement",
        "workloadSucceeded", "actionAuthorization", "okForAction"])?;
    inert(&value)?;
    ensure(value["schema"] == "serverware.nativeExecutionObservation/v2"
        && value["resultScope"] == "local-single-attempt-execution-and-cleanup-observation",
        "native outcome execution profile differs")?;
    let execution = &value["execution"];
    shape(execution, &["operationSha256", "execObservedBoottimeNs", "exitObservedBoottimeNs", "code",
        "status", "firewallSemanticSha256", "firewallEvidenceSha256", "attachmentSemanticSha256",
        "attachmentEvidenceSha256"])?;
    ensure(execution["operationSha256"] == digest(&operation), "native outcome operation differs")?;
    for key in ["firewallSemanticSha256", "firewallEvidenceSha256", "attachmentSemanticSha256",
        "attachmentEvidenceSha256"] { hash(&execution[key])?; }
    let exec = positive(&execution["execObservedBoottimeNs"])?;
    let exit = positive(&execution["exitObservedBoottimeNs"])?;
    let code = positive(&execution["code"])?;
    let status = execution["status"].as_u64().ok_or("native outcome exit status absent")?;
    ensure(exec <= exit && code <= 3 && status <= 255 && (code == 1 || (1..=64).contains(&status))
        && value["workloadSucceeded"] == (code == 1 && status == 0), "native outcome exit fields differ")?;
    let output = &value["output"];
    shape(output, &["stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256", "complete"])?;
    for key in ["stdoutBytes", "stderrBytes"] {
        ensure(output[key].as_u64().is_some_and(|v| v <= 67_108_864), "native outcome output count invalid")?;
    }
    hash(&output["stdoutSha256"])?; hash(&output["stderrSha256"])?;
    ensure(output["complete"] == true, "native outcome output is incomplete")?;
    let cleanup = &value["cleanup"];
    shape(cleanup, &["leaderReaped", "leafEmptyBoottimeNs", "leafKillAcknowledged",
        "guardianEmptyBoottimeNs", "guardianKillAcknowledged"])?;
    ensure(cleanup["leaderReaped"] == true && cleanup["leafKillAcknowledged"].is_boolean()
        && cleanup["guardianKillAcknowledged"].is_boolean(), "native outcome cleanup shape differs")?;
    let latest = exit.max(positive(&cleanup["leafEmptyBoottimeNs"])?).max(positive(&cleanup["guardianEmptyBoottimeNs"])?);
    let retirement = &value["retirement"];
    shape(retirement, &["schema", "resultScope", "operationSha256", "cleanupBeforeBoottimeNs",
        "hostVethAbsence", "cgroupRemoval", "actionAuthorization", "okForAction"])?;
    inert(retirement)?;
    ensure(retirement["schema"] == "serverware.nativeExecutionRetirementObservation/v1"
        && retirement["resultScope"] == "local-owned-network-and-cgroup-retirement-observation"
        && retirement["operationSha256"] == digest(&operation)
        && positive(&retirement["cleanupBeforeBoottimeNs"])? == deadline,
        "native outcome retirement association differs")?;
    let host = &retirement["hostVethAbsence"];
    shape(host, &["namespaceDevice", "namespaceInode", "ifindex", "name", "bridgeIfindex",
        "observedBoottimeNs", "evidenceSha256"])?;
    positive(&host["namespaceDevice"])?; positive(&host["namespaceInode"])?;
    let index = positive(&host["ifindex"])?; let bridge = positive(&host["bridgeIfindex"])?;
    ensure(index <= i32::MAX as u64 && bridge <= i32::MAX as u64 && index != bridge,
        "native outcome host link identity differs")?;
    name(&host["name"], 15)?; hash(&host["evidenceSha256"])?;
    let removed = &retirement["cgroupRemoval"];
    shape(removed, &["parentDevice", "parentInode", "device", "inode", "name", "observedBoottimeNs"])?;
    let parent = (positive(&removed["parentDevice"])?, positive(&removed["parentInode"])?);
    let leaf = (positive(&removed["device"])?, positive(&removed["inode"])?);
    ensure(parent != leaf, "native outcome leaf equals parent")?; name(&removed["name"], 80)?;
    let host_time = positive(&host["observedBoottimeNs"])?;
    let leaf_time = positive(&removed["observedBoottimeNs"])?;
    ensure(host_time >= latest && leaf_time >= latest && host_time < deadline && leaf_time < deadline,
        "native outcome retirement is outside its original cleanup window")?;
    Ok((value, host_time.max(leaf_time)))
}

pub(super) struct Decoded {
    pub(super) observation: Value,
    pub(super) latest: u64,
    pub(super) deadline: u64,
    pub(super) evidence: [u8; 32],
}

pub(super) fn encode(claim: &[u8; 73], deadline: u64, parts: [&[u8]; 5]) -> Result<Vec<u8>, String> {
    for (part, bound) in parts.iter().zip(LIMITS) {
        ensure(!part.is_empty() && part.len() <= bound, "native outcome original exceeds its fixed bound")?;
    }
    let mut raw = Vec::with_capacity(HEADER + parts.iter().map(|p| p.len()).sum::<usize>());
    raw.extend_from_slice(MAGIC); raw.extend_from_slice(&claim[9..]);
    raw.extend_from_slice(&sha(claim)); raw.extend_from_slice(&deadline.to_be_bytes());
    for part in &parts {
        raw.extend_from_slice(&(part.len() as u32).to_be_bytes());
    }
    for part in parts { raw.extend_from_slice(part); }
    ensure(raw.len() <= MAX_RECORD, "native outcome aggregate exceeds its bound")?;
    decode(&raw, claim)?;
    Ok(raw)
}

pub(super) fn decode(raw: &[u8], claim: &[u8; 73]) -> Result<Decoded, String> {
    ensure(raw.len() >= HEADER && raw.len() <= MAX_RECORD && &raw[..8] == MAGIC
        && raw[8..72] == claim[9..] && raw[72..104] == sha(claim),
        "native outcome original association differs")?;
    let deadline = u64_at(raw, 104)?;
    let mut parts: [&[u8]; 5] = [&[]; 5]; let mut offset = HEADER;
    for index in 0..5 {
        let at = 112 + index * 4;
        let length = u32::from_be_bytes(raw[at..at + 4].try_into().map_err(|_| "native outcome length differs")?) as usize;
        ensure(length > 0 && length <= LIMITS[index] && offset.checked_add(length).is_some_and(|end| end <= raw.len()),
            "native outcome original length is invalid")?;
        parts[index] = &raw[offset..offset + length]; offset += length;
    }
    ensure(offset == raw.len(), "native outcome original has trailing bytes")?;
    let operation: [u8; 32] = claim[41..].try_into().map_err(|_| "native outcome operation width differs")?;
    let (value, latest) = observation(parts[0], operation, deadline)?;
    // Exact actual host read requests and kernel datagrams, never a synthesized
    // absence verdict. This framing check is not a fresh kernel state check.
    let host = parts[1];
    ensure(host.len() >= 72 && &host[..8] == b"SWNATCL1" && host[8..40] == operation
        && host[40..72].iter().any(|b| *b != 0)
        && value["retirement"]["hostVethAbsence"]["evidenceSha256"] == digest(&sha(host)),
        "native outcome host original differs")?;
    let (mut cursor, mut requests, mut replies) = (72usize, 0usize, 0usize);
    while cursor < host.len() {
        ensure(host.len() - cursor >= 5, "native outcome host event truncated")?;
        let tag = host[cursor];
        let length = u32::from_be_bytes(host[cursor + 1..cursor + 5].try_into()
            .map_err(|_| "native outcome host event width differs")?) as usize;
        ensure(matches!(tag, 1 | 2) && (16..=65536).contains(&length)
            && cursor.checked_add(5 + length).is_some_and(|end| end <= host.len()),
            "native outcome host event invalid")?;
        if tag == 1 { requests += 1; } else { replies += 1; }
        ensure(requests <= 16 && replies <= 256, "native outcome host event inventory excessive")?;
        cursor += 5 + length;
    }
    ensure(requests >= 2 && replies >= 2, "native outcome host closing observation absent")?;
    let guardian: &[u8; guardian_process::FRAME_BYTES] = parts[2].try_into()
        .map_err(|_| "native outcome guardian original width differs")?;
    let (flags, observed) = guardian_process::decode(guardian, &operation, 2)
        .ok_or("native outcome guardian association differs")?;
    ensure(flags & 2 != 0 && value["cleanup"]["guardianEmptyBoottimeNs"] == observed
        && value["cleanup"]["guardianKillAcknowledged"] == (flags & 1 != 0),
        "native outcome guardian original disagrees")?;
    let events = std::str::from_utf8(parts[3]).map_err(|_| "native outcome events original is not text")?;
    ensure(events.is_ascii() && events.ends_with('\n'), "native outcome events original incomplete")?;
    let mut empty = false;
    for line in events.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        ensure(fields.len() == 2, "native outcome events fields differ")?;
        if fields[0] == "populated" {
            ensure(!empty && fields[1] == "0", "native outcome events do not uniquely observe empty")?;
            empty = true;
        }
    }
    ensure(empty, "native outcome events lack empty observation")?;
    let leader = json::parse(parts[4], LIMITS[4])?;
    ensure(canonical_ascii_bytes(&leader)? == parts[4], "native outcome reap original is not canonical")?;
    shape(&leader, &["apiVersion", "operationSha256", "leaderPid", "pidfdDevice", "pidfdInode", "code", "status"])?;
    ensure(leader["apiVersion"] == "serverware.nativeLeaderReapOriginal/v1"
        && leader["operationSha256"] == digest(&operation)
        && positive(&leader["leaderPid"])? <= i32::MAX as u64
        && positive(&leader["pidfdDevice"])? > 0 && positive(&leader["pidfdInode"])? > 0
        && leader["code"] == value["execution"]["code"] && leader["status"] == value["execution"]["status"],
        "native outcome actual reap differs from execution")?;
    let mut evidence = Sha256::new(); evidence.update(b"serverware.nativeTerminalOriginals/v1\0");
    for part in &parts[1..] { evidence.update((part.len() as u32).to_be_bytes()); evidence.update(part); }
    Ok(Decoded { observation: value, latest, deadline, evidence: evidence.finalize().into() })
}

pub(super) fn marker(claim: &[u8; 73], raw: &[u8], recorded: u64) -> Result<[u8; COMPLETE_BYTES], String> {
    let decoded = decode(raw, claim)?;
    ensure(recorded >= decoded.latest && recorded < decoded.deadline, "native outcome publication missed original cleanup bound")?;
    let mut result = [0u8; COMPLETE_BYTES]; result[..8].copy_from_slice(COMPLETE);
    result[8..72].copy_from_slice(&claim[9..]); result[72..104].copy_from_slice(&sha(claim));
    result[104..136].copy_from_slice(&sha(raw)); result[136..168].copy_from_slice(&decoded.evidence);
    result[168..176].copy_from_slice(&(raw.len() as u64).to_be_bytes());
    result[176..184].copy_from_slice(&recorded.to_be_bytes()); result[184..192].copy_from_slice(&decoded.deadline.to_be_bytes());
    Ok(result)
}

pub(super) fn committed(claim: &[u8; 73], raw: &[u8], complete: &[u8]) -> Result<(Decoded, u64), String> {
    ensure(complete.len() == COMPLETE_BYTES, "native outcome completion marker is incomplete")?;
    let recorded = u64_at(complete, 176)?;
    ensure(marker(claim, raw, recorded)?.as_slice() == complete, "native outcome completion marker differs")?;
    Ok((decode(raw, claim)?, recorded))
}

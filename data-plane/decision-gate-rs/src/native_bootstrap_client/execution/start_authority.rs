//! Separate signed start constraints, not proof that a workload may now run.
//!
//! The owning start path must still join actual native proof/network owners,
//! claim the protected journals and arm an independent whole-cgroup guardian.
//! This module never creates a process, cgroup, timer or execution permit.

use super::super::{json, native_verifier, sample, OriginalClock};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Signature;
use serde::Deserialize;
use serde_json::Value;
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};

pub(super) const MAX_BYTES: usize = 32 * 1024;
const SCHEMA: &str = "serverware.nativeWorkloadStartAuthorization/v1";
const ENVELOPE: &str = "serverware.signedNativeWorkloadStartAuthorization/v1";
const SECOND: u64 = 1_000_000_000;
const MAX_EPOCH_MS: u64 = 9_223_372_036_854;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope { schema: String, payload: Value, signature: String }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Host {
    pub(super) host_id: String,
    pub(super) boot_id: String,
    pub(super) namespace_device: u64,
    pub(super) namespace_inode: u64,
    pub(super) owner_uid: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Isolation {
    pub(super) profile: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) supplementary_groups: Vec<u32>,
    pub(super) no_new_privileges: bool,
    pub(super) namespaces: Vec<String>,
    pub(super) umask: u32,
    pub(super) stdio: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Resources {
    pub(super) memory_max_bytes: u64,
    pub(super) memory_swap_max_bytes: u64,
    pub(super) pids_max: u32,
    pub(super) cpu_max_quota_us: u64,
    pub(super) cpu_max_period_us: u64,
    pub(super) output_max_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Containment {
    pub(super) profile: String,
    pub(super) parent_path: String,
    pub(super) parent_device: u64,
    pub(super) parent_inode: u64,
    pub(super) child_name: String,
    pub(super) guardian_profile: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Capability {
    pub(super) capability_id: String,
    pub(super) capability_token_sha256: String,
    pub(super) expires_at_epoch_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub(super) path: String,
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) namespace: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Constraints {
    schema: String,
    source_revision: String,
    purpose: String,
    trust_mode: String,
    creation_mode: String,
    pub(super) authorization_id: String,
    pub(super) egress_authorization_sha256: String,
    pub(super) attachment_authorization_sha256: String,
    pub(super) launch_manifest_sha256: String,
    pub(super) execution_manifest_sha256: String,
    pub(super) launcher_binary_sha256: String,
    pub(super) machine_id_sha256: String,
    pub(super) network_owner: Host,
    pub(super) isolation: Isolation,
    pub(super) resources: Resources,
    pub(super) containment: Containment,
    pub(super) capability: Capability,
    pub(super) journal: Journal,
    pub(super) issued_at_epoch_ns: u64,
    pub(super) start_before_epoch_ns: u64,
    pub(super) stop_at_epoch_ns: u64,
    pub(super) cleanup_before_epoch_ns: u64,
}

/// Signature-derived constraints only, neither Clone nor a serialized verdict.
pub(super) struct Authorization {
    pub(super) constraints: Constraints,
    pub(super) root_key_id: [u8; 32],
    pub(super) original_sha256: [u8; 32],
    // Absolute projections from one original admission sample, never now+TTL.
    // Only a later actual start owner may transfer them into its guardian.
    pub(super) stop_boottime_ns: u64,
    pub(super) cleanup_boottime_ns: u64,
}

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native workload start authorization refused".to_owned()) }
}

fn text(value: &str, maximum: usize) -> Result<(), String> {
    require(!value.is_empty() && value.len() <= maximum
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)))
}

fn identifier(value: &str, maximum: usize) -> Result<(), String> {
    text(value, maximum)?;
    require(value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b':' | b'-')))
}

fn path(value: &str) -> Result<(), String> {
    text(value, 4096)?;
    require(value.len() > 1 && value.starts_with('/') && !value.contains('\\'))?;
    for (index, component) in value[1..].split('/').enumerate() {
        require(index < 64 && component.len() <= 255
            && !matches!(component, "" | "." | ".."))?;
    }
    Ok(())
}

fn digest(value: &str) -> Result<(), String> {
    require(crate::is_sha256_digest(value))
}

fn structure(raw: &[u8], clock: &OriginalClock) -> Result<(), String> {
    require(!raw.is_empty() && raw.len() <= MAX_BYTES)?;
    let mut stack = Vec::with_capacity(6);
    let (mut quoted, mut escaped) = (false, false);
    for (index, byte) in raw.iter().copied().enumerate() {
        if index % 1024 == 0 { clock.check()?; }
        require((0x20..=0x7e).contains(&byte))?;
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => { require(stack.len() < 6)?; stack.push(byte); }
                b'}' => require(stack.pop() == Some(b'{'))?,
                b']' => require(stack.pop() == Some(b'['))?,
                _ => {}
            }
        }
    }
    require(stack.is_empty() && !quoted && !escaped)?;
    clock.check()
}

fn validate(value: &Constraints, opening_wall: u64) -> Result<(), String> {
    require(value.schema == SCHEMA
        && value.source_revision == crate::authority_source_revision_v1::SOURCE_REVISION
        && value.purpose == "native-workload-start" && value.trust_mode == "trusted-host-local"
        && value.creation_mode == "new-execution-child-v1")?;
    identifier(&value.authorization_id, 128)?;
    for pin in [&value.egress_authorization_sha256, &value.attachment_authorization_sha256,
        &value.launch_manifest_sha256, &value.execution_manifest_sha256,
        &value.launcher_binary_sha256, &value.machine_id_sha256] { digest(pin)?; }
    require(value.egress_authorization_sha256 != value.attachment_authorization_sha256
        && value.launch_manifest_sha256 != value.execution_manifest_sha256)?;
    let host = &value.network_owner;
    identifier(&host.host_id, 128)?;
    require(host.boot_id.len() == 36 && host.boot_id.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
    }) && host.namespace_device != 0 && host.namespace_inode != 0 && host.owner_uid == 0)?;
    let isolation = &value.isolation;
    require(isolation.profile == "non-root-empty-capabilities-v1"
        && (1..u32::MAX).contains(&isolation.uid) && (1..u32::MAX).contains(&isolation.gid)
        && isolation.supplementary_groups.is_empty() && isolation.no_new_privileges
        && isolation.namespaces.iter().map(String::as_str)
            .eq(["mount", "ipc", "uts", "network", "pid"])
        && isolation.umask == 0o077 && isolation.stdio == "null-input-bounded-output-v1")?;
    let resources = &value.resources;
    require((16 * 1024 * 1024..=1_099_511_627_776).contains(&resources.memory_max_bytes)
        && resources.memory_swap_max_bytes == 0 && (1..=4096).contains(&resources.pids_max)
        && (1000..=6_400_000).contains(&resources.cpu_max_quota_us)
        && resources.cpu_max_period_us == 100_000
        && (4096..=67_108_864).contains(&resources.output_max_bytes))?;
    let containment = &value.containment;
    path(&containment.parent_path)?;
    identifier(&containment.child_name, 80)?;
    require(!containment.child_name.contains(':')
        && containment.profile == "cgroup-v2-new-leaf-kill-v1"
        && containment.guardian_profile == "independent-cgroup-guardian-v1"
        && containment.parent_device != 0 && containment.parent_inode != 0)?;
    let capability = &value.capability;
    identifier(&capability.capability_id, 128)?;
    digest(&capability.capability_token_sha256)?;
    require((1..=MAX_EPOCH_MS).contains(&capability.expires_at_epoch_ms))?;
    path(&value.journal.path)?;
    identifier(&value.journal.namespace, 128)?;
    require(value.journal.device != 0 && value.journal.inode != 0
        && value.journal.path != containment.parent_path
        && (value.journal.device, value.journal.inode)
            != (containment.parent_device, containment.parent_inode))?;
    for instant in [value.issued_at_epoch_ns, value.start_before_epoch_ns,
        value.stop_at_epoch_ns, value.cleanup_before_epoch_ns] {
        require((1..=i64::MAX as u64).contains(&instant))?;
    }
    require(value.issued_at_epoch_ns <= opening_wall && opening_wall < value.start_before_epoch_ns
        && value.start_before_epoch_ns - value.issued_at_epoch_ns <= 300 * SECOND
        && value.start_before_epoch_ns <= capability.expires_at_epoch_ms * 1_000_000
        && value.start_before_epoch_ns < value.stop_at_epoch_ns
        && value.stop_at_epoch_ns - value.start_before_epoch_ns <= 86_400 * SECOND
        && value.stop_at_epoch_ns < value.cleanup_before_epoch_ns
        && (100_000_000..=30 * SECOND).contains(
            &(value.cleanup_before_epoch_ns - value.stop_at_epoch_ns)))
}

pub(super) fn admit_constraints(raw: &[u8], root_pem: &[u8], root_pem_sha: &str,
    clock: &OriginalClock) -> Result<Authorization, String> {
    clock.check()?;
    let (opening_wall, opening_boot) = sample()?;
    structure(raw, clock)?;
    let value = json::parse(raw, MAX_BYTES)?;
    require(canonical_ascii_bytes(&value)? == raw)?;
    let envelope: Envelope = serde_json::from_value(value)
        .map_err(|_| "native workload start envelope is not closed")?;
    require(envelope.schema == ENVELOPE && envelope.signature.len() == 94
        && envelope.signature.starts_with("ed25519:"))?;
    let signature = URL_SAFE_NO_PAD.decode(&envelope.signature[8..])
        .map_err(|_| "native workload start signature is invalid")?;
    require(signature.len() == 64
        && format!("ed25519:{}", URL_SAFE_NO_PAD.encode(&signature)) == envelope.signature)?;
    require(!root_pem.is_empty() && root_pem.len() <= 16 * 1024)?;
    clock.check()?;
    let (root, root_key_id) = native_verifier::installation_authorizer(root_pem, root_pem_sha)?;
    clock.check()?;
    let canonical = canonical_ascii_bytes(&envelope.payload)?;
    let mut message = Vec::with_capacity(SCHEMA.len() + 1 + canonical.len());
    message.extend_from_slice(SCHEMA.as_bytes()); message.push(0); message.extend_from_slice(&canonical);
    root.verify_strict(&message, &Signature::from_slice(&signature)
        .map_err(|_| "native workload start signature width is invalid")?)
        .map_err(|_| "native workload start signature refused")?;
    clock.check()?;
    let constraints: Constraints = serde_json::from_value(envelope.payload)
        .map_err(|_| "native workload start constraints are not closed")?;
    validate(&constraints, opening_wall)?;
    let stop_boottime_ns = opening_boot.checked_add(constraints.stop_at_epoch_ns - opening_wall)
        .ok_or("native workload stop deadline overflows")?;
    let cleanup_boottime_ns = opening_boot.checked_add(constraints.cleanup_before_epoch_ns - opening_wall)
        .ok_or("native workload cleanup deadline overflows")?;
    // Preparation/start retains the old admission allowance. The separately
    // signed absolute continuation is data for the future guardian, not an
    // extension of this clock or a renewed bootstrap/CA/network proof.
    clock.restrict_until_epoch_ns(constraints.start_before_epoch_ns)?;
    let (closing_wall, closing_boot) = sample()?;
    require(closing_wall >= opening_wall && closing_boot >= opening_boot
        && closing_wall < constraints.start_before_epoch_ns && closing_boot < stop_boottime_ns)?;
    clock.check()?;
    Ok(Authorization { constraints, root_key_id, original_sha256: Sha256::digest(raw).into(),
        stop_boottime_ns, cleanup_boottime_ns })
}

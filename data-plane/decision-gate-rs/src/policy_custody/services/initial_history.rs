//! Explicit initial-history admission for the fixed ordinary guest services.
//!
//! INITIAL commitments are meaningful only inside this authenticated wrapper.
//! They are not historical receipts, revocation evidence or legacy substitutes.
//! Live admission precedes every gate; subsequent history loads authenticate
//! the wrapper without inspecting directories that those gates have written.
use super::*;
use super::super::protocol::{pidfd_stat_identity_sha256, ProtocolBoottimeDomain, ProtocolBoottimeDeadline};
use crate::policy_shadow::hash_domain_frames;
use sha2::{Digest, Sha256};
use std::os::unix::fs::FileExt;

const API: &str = "serverware.custodyOrdinaryInitialHistory/v1";
const STATE_API: &str = "serverware.custodyOrdinaryInitialState/v1";
const GENESIS_API: &str = "serverware.custodyOrdinaryInitialHistory/v2";
const GENESIS_STATE_API: &str = "serverware.custodyOrdinaryInitialState/v2";
const PREDECESSOR: &[u8] = b"serverware.custodyOrdinaryInitialCheckpointPredecessor/v1";
const HISTORY_ROOT: &[u8] = b"serverware.custodyOrdinaryInitialHistoryRoot/v1";
const DURABLE_HEAD: &[u8] = b"serverware.custodyOrdinaryInitialDurableHead/v1";
const MAX_EXECUTABLE: u64 = 256 * 1024 * 1024;
const ZERO: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn require(value: bool) -> Result<(), ServiceRunnerError> {
    if value { Ok(()) } else { Err(ServiceRunnerError::invalid("ordinary initial history refused")) }
}
fn error(value: impl fmt::Display) -> ServiceRunnerError {
    ServiceRunnerError::invalid(value.to_string())
}
fn ns(value: &str) -> Result<u64, ServiceRunnerError> {
    let number = value.parse::<u64>().map_err(error)?;
    require(number > 0 && number.to_string() == value)?;
    Ok(number)
}
fn role_name(role: TrustedHostServiceRoleV3) -> &'static str {
    match role {
        TrustedHostServiceRoleV3::DurableRecoveryStore => "durable-recovery-store",
        TrustedHostServiceRoleV3::CleanupAuthorizationConsumer => "cleanup-authorization-consumer",
        TrustedHostServiceRoleV3::RecoveryTargetProvider => "recovery-target-provider",
        TrustedHostServiceRoleV3::CurrentSignatureAuthority => "current-signature-authority",
        TrustedHostServiceRoleV3::BoundedCleanupHelper => "bounded-cleanup-helper",
    }
}
fn directory_names(role: TrustedHostServiceRoleV3) -> &'static [&'static str] {
    match role {
        TrustedHostServiceRoleV3::DurableRecoveryStore =>
            &["journal", "generation-journal", "dispatch-journal", "spool-head-journal"],
        TrustedHostServiceRoleV3::CleanupAuthorizationConsumer =>
            &["state", "journal", "generation-journal", "active-effect-cleanup-journal"],
        TrustedHostServiceRoleV3::RecoveryTargetProvider | TrustedHostServiceRoleV3::BoundedCleanupHelper =>
            &["journal", "generation-journal"],
        TrustedHostServiceRoleV3::CurrentSignatureAuthority =>
            &["generation-journal", "dispatch-journal", "spool-current-journal"],
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Directory { identity: ActivationDirectoryIdentityV3, entry_count: u64 }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct State {
    api_version: String, service_role: TrustedHostServiceRoleV3,
    preparation_sha256: Sha256Digest, resources_sha256: Sha256Digest, launch_sha256: Sha256Digest,
    endpoint_process_identity_sha256: Sha256Digest, boot_id_base64url: String,
    time_namespace_device: u64, time_namespace_inode: u64, issued_at_boottime_ns: String,
    startup_deadline_boottime_ns: String, lifetime_deadline_boottime_ns: String, invocation_id: String,
    deployment_generation_sha256: Sha256Digest, endpoint_generation: u64, service_generation: u64,
    operation_generation: u64, durable_epoch: u64, directories: BTreeMap<String, Directory>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Wrapper {
    api_version: String, initial_state: State,
    initial_checkpoint: SignedEndpointKeyAuthorizationCheckpoint,
    history: AuthorityHistoryManifestV3,
}
struct Authenticated {
    state: State, checkpoint: SignedEndpointKeyAuthorizationCheckpoint,
    history: RuntimeAuthorityHistory,
}

impl State {
    fn domain(&self) -> Result<BoottimeDomain, ServiceRunnerError> {
        let raw = URL_SAFE_NO_PAD.decode(&self.boot_id_base64url).map_err(error)?;
        require(raw.len() == 16 && URL_SAFE_NO_PAD.encode(&raw) == self.boot_id_base64url)?;
        let boot: [u8;16] = raw.try_into().map_err(|_| error("initial boot length"))?;
        BoottimeDomain::from_expected(boot, self.time_namespace_device, self.time_namespace_inode).map_err(error)
    }
    fn validate(&self, runtime: &RuntimeConfigHeaderV3, role: TrustedHostServiceRoleV3)
        -> Result<(), ServiceRunnerError> {
        let cold = runtime.api_version == super::publication_genesis_service::RUNTIME;
        require(self.api_version == (if cold { GENESIS_STATE_API } else { STATE_API })
            && self.service_role == role
            && self.endpoint_generation > 0 && self.service_generation > 0
            && self.operation_generation > 0 && self.durable_epoch > 0
            && self.service_generation == runtime.service_restart_epoch
            && self.operation_generation == runtime.operation_generation
            && self.deployment_generation_sha256 == runtime.deployment_generation_sha256
            && self.invocation_id.len() == 32 && self.invocation_id != "00000000000000000000000000000000"
            && self.invocation_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))?;
        require(canonical_json_bytes(self).map_err(error)?.len() <= 65536)?;
        for digest in [&self.preparation_sha256, &self.resources_sha256, &self.launch_sha256,
            &self.endpoint_process_identity_sha256, &self.deployment_generation_sha256] {
            require(digest.as_str() != ZERO && digest != &Sha256Digest::compute(&[]))?;
        }
        let issued = ns(&self.issued_at_boottime_ns)?;
        let startup = ns(&self.startup_deadline_boottime_ns)?;
        let lifetime = ns(&self.lifetime_deadline_boottime_ns)?;
        require(issued < startup && startup <= lifetime && startup - issued <= 30_000_000_000)?;
        self.domain()?;
        let names = if cold {
            match role {
                TrustedHostServiceRoleV3::DurableRecoveryStore => &["journal", "publication-genesis-journal"][..],
                TrustedHostServiceRoleV3::CurrentSignatureAuthority => &["publication-genesis-journal"][..],
                _ => return Err(error("cold publication history requires DRS or CSA")),
            }
        } else { directory_names(role) };
        let required: BTreeSet<_> = names.iter().copied().collect();
        require(self.directories.keys().map(String::as_str).collect::<BTreeSet<_>>() == required
            && runtime.activation_directory_identities.keys().map(String::as_str).collect::<BTreeSet<_>>() == required)?;
        let mut identities = BTreeSet::new();
        let mut owner = None;
        for (name, directory) in &self.directories {
            directory.identity.validate()?;
            let identity = &directory.identity;
            let uid_gid = (identity.uid, identity.gid);
            require(directory.entry_count == 0 && identity.mode == (libc::S_IFDIR | 0o700)
                && identity.uid > 0 && identity.gid > 0
                && identities.insert((identity.device_major, identity.device_minor, identity.inode))
                && owner.is_none_or(|previous| previous == uid_gid)
                && runtime.activation_directory_identity(name)? == &directory.identity)?;
            owner = Some(uid_gid);
        }
        Ok(())
    }
    fn commitment(&self, domain: &[u8]) -> Result<Sha256Digest, ServiceRunnerError> {
        let raw = canonical_json_bytes(self).map_err(error)?;
        Ok(hash_domain_frames(domain, &[&raw]))
    }
}

pub(super) fn selected(raw: &[u8]) -> Result<bool, ServiceRunnerError> {
    let value: serde_json::Value = decode_canonical_frame(raw)?;
    Ok(matches!(value.get("apiVersion").and_then(serde_json::Value::as_str), Some(API | GENESIS_API)))
}

fn authenticate(raw: &[u8], runtime: &RuntimeConfigHeaderV3, role: TrustedHostServiceRoleV3)
    -> Result<Authenticated, ServiceRunnerError> {
    authenticate_window(raw, runtime, role, true)
}

fn authenticate_window(raw: &[u8], runtime: &RuntimeConfigHeaderV3, role: TrustedHostServiceRoleV3,
    startup_admission: bool) -> Result<Authenticated, ServiceRunnerError> {
    let wrapper: Wrapper = decode_canonical_frame(raw)?;
    require(wrapper.api_version == if runtime.api_version == super::publication_genesis_service::RUNTIME { GENESIS_API } else { API })?;
    let state = wrapper.initial_state;
    state.validate(runtime, role)?;
    let manifest = wrapper.history;
    let anchor = &manifest.first_retained_epoch;
    let epoch = &anchor.retained_epoch;
    let retention = &manifest.retention;
    require(manifest.authority_role == HistoricalAuthorityRoleV3::IsolatedService(historical_service_role(role))
        && manifest.manifest_sha256 == runtime.authority_history_manifest_sha256
        && manifest.adjacent_transitions.is_empty() && manifest.compaction_anchors.is_empty()
        && manifest.replay_tombstones.is_empty() && epoch.authority_epoch_sequence == 1
        && epoch.checkpoint_sequence == 1 && epoch.predecessor_epoch_sha256.is_none()
        && epoch.endpoint_process_identity_sha256 == state.endpoint_process_identity_sha256
        && epoch.endpoint_generation == state.endpoint_generation && epoch.service_generation == state.service_generation
        && epoch.operation_generation == state.operation_generation && epoch.durable_epoch == state.durable_epoch
        && epoch.deployment_generation_sha256 == state.deployment_generation_sha256
        && epoch.durable_epoch_head_sha256 == state.commitment(DURABLE_HEAD)?
        && anchor.pruned_through_epoch_sequence == 0 && anchor.pruned_terminal_epoch_sha256.is_none()
        && anchor.pruned_history_root_sha256 == state.commitment(HISTORY_ROOT)?
        && retention.oldest_replayable_record_sequence == 0 && retention.current_record_sequence == 0
        && retention.oldest_retained_compaction_sequence == 0 && retention.current_compaction_sequence == 0
        && retention.maximum_retained_epochs == 1 && retention.maximum_compaction_anchors == 1
        && retention.maximum_replay_tombstones == 1)?;
    for directory in state.directories.values() {
        require(directory.identity.uid == epoch.endpoint_process_identity.endpoint_uid
            && directory.identity.gid == epoch.endpoint_process_identity.endpoint_gid)?;
    }
    let checkpoint = wrapper.initial_checkpoint;
    checkpoint.validate_shape().map_err(error)?;
    let payload = &checkpoint.payload;
    require(payload.checkpoint_sequence == 1 && payload.exact_endpoint_generation == state.endpoint_generation
        && payload.endpoint_process_identity_sha256 == state.endpoint_process_identity_sha256
        && payload.endpoint_role == epoch.endpoint_process_identity.endpoint_role
        && payload.predecessor_checkpoint_sha256 == state.commitment(PREDECESSOR)?
        && payload.rollback_floor_checkpoint_sequence == 1
        && payload.rollback_floor_endpoint_generation == state.endpoint_generation
        && payload.rollback_floor_consumer_sequence == 1
        && checkpoint.checkpoint_sha256 == epoch.checkpoint_sha256
        && checkpoint.authority_key_id == epoch.checkpoint_authority.key_id
        && checkpoint.authority_key_spki_sha256 == epoch.checkpoint_authority.key_spki_sha256
        && payload.authorized_signing_key_id == epoch.service_signing_key.key_id
        && payload.authorized_signing_key_spki_sha256 == epoch.service_signing_key.key_spki_sha256
        && payload.valid_from_boottime.domain() == &ProtocolBoottimeDomain::from_runtime(state.domain()?)
        && payload.valid_until_boottime.domain() == payload.valid_from_boottime.domain()
        && payload.valid_from_boottime.absolute_boottime_nanos() >= ns(&state.issued_at_boottime_ns)?
        && payload.valid_until_boottime.absolute_boottime_nanos() <= ns(&state.lifetime_deadline_boottime_ns)?)?;
    if role == TrustedHostServiceRoleV3::DurableRecoveryStore {
        require(payload.endpoint_role == PolicyCustodyEndpointRole::SettlementStore)?;
    }
    // The existing bounded owner authenticates all three original anchor
    // signatures and independent root/checkpoint/service key material first.
    let history = RuntimeAuthorityHistory::from_manifest(manifest,
        &runtime.authority_history_root_key_id, &runtime.authority_history_root_key_spki_sha256).map_err(error)?;
    let current = history.current_epoch().map_err(error)?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(&checkpoint.authority_signature_base64).map_err(error)?;
    require(signature_bytes.len() == 64
        && URL_SAFE_NO_PAD.encode(&signature_bytes) == checkpoint.authority_signature_base64)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(error)?;
    current.checkpoint_authority_key().verify_strict(&checkpoint.authority_signature_preimage().map_err(error)?,
        &signature).map_err(error)?;
    let now = boottime_now_nanos().map_err(error)?;
    require(payload.valid_from_boottime.absolute_boottime_nanos() <= now
        && now < payload.valid_until_boottime.absolute_boottime_nanos()
        && now < ns(if startup_admission { &state.startup_deadline_boottime_ns }
            else { &state.lifetime_deadline_boottime_ns })?)?;
    Ok(Authenticated { state, checkpoint, history })
}

pub(super) fn load(raw: &[u8], runtime: &RuntimeConfigHeaderV3, role: TrustedHostServiceRoleV3)
    -> Result<RuntimeAuthorityHistory, ServiceRunnerError> {
    Ok(authenticate(raw, runtime, role)?.history)
}

/// Operational signature verification of the exact original already pinned by
/// an authenticated v12 Factory. This performs no initial directory admission
/// and grants no new startup permission. Checkpoint currentness, boot/domain,
/// original lifetime, independent root and every wrapper signature still hold.
pub(super) fn load_retained_completed_invocation(raw: &[u8], runtime: &RuntimeConfigHeaderV3,
    role: TrustedHostServiceRoleV3) -> Result<(RuntimeAuthorityHistory, u64), ServiceRunnerError> {
    let owner = authenticate_window(raw, runtime, role, false)?;
    let deadline = owner.checkpoint.payload.valid_until_boottime.absolute_boottime_nanos()
        .min(ns(&owner.state.lifetime_deadline_boottime_ns)?);
    Ok((owner.history, deadline))
}

pub(super) struct HelperAuthorization {
    pub(super) checkpoint: SignedEndpointKeyAuthorizationCheckpoint,
    pub(super) checkpoint_authority: VerifyingKey,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

fn common_value<T: Serialize>(value: &T, excluded: &[&str]) -> Result<serde_json::Value, ServiceRunnerError> {
    let mut value = serde_json::to_value(value).map_err(error)?;
    let fields = value.as_object_mut().ok_or_else(|| error("helper common context is not an object"))?;
    for name in excluded { require(fields.remove(*name).is_some())?; }
    Ok(value)
}

/// Four independently authenticated role wrappers for the same measured
/// helper. Only role-derived identities and INITIAL commitments may differ.
/// The independent root comes from the signed runtime, never from a member.
pub(super) fn admit_helper_histories(primary_raw: &[u8], members: &helper_initial::Histories,
    pins: &BTreeMap<PolicyCustodyEndpointRole, EndpointTrustPinCredentialV3>,
    runtime: &RuntimeConfigHeaderV3, credentials: &CredentialDirectory,
    bootstrap: &Bootstrap, activation: &BTreeMap<String, OwnedFd>)
    -> Result<BTreeMap<PolicyCustodyEndpointRole, HelperAuthorization>, ServiceRunnerError> {
    require(runtime.api_version == helper_initial::RUNTIME)?;
    helper_initial::history_pins(members)?;
    require(pins.keys().copied().collect::<Vec<_>>() == helper_initial::ROLES)?;
    let role = TrustedHostServiceRoleV3::BoundedCleanupHelper;
    let primary = authenticate(primary_raw, runtime, role)?;
    let primary_epoch = primary.history.current_epoch().map_err(error)?.statement();
    require(members.get(&primary.checkpoint.payload.endpoint_role)
        .is_some_and(|raw| raw.as_bytes() == primary_raw))?;
    let state = common_value(&primary.state, &["endpointProcessIdentitySha256"])?;
    let identity = common_value(&primary_epoch.endpoint_process_identity, &["endpointRole", "identitySha256"])?;
    let payload = common_value(&primary.checkpoint.payload,
        &["endpointRole", "endpointProcessIdentitySha256", "predecessorCheckpointSha256"])?;
    let mut authenticated = BTreeMap::new();
    let mut forbidden = BTreeSet::new();
    for (endpoint_role, raw) in members {
        let wrapper: Wrapper = decode_canonical_frame(raw.as_bytes())?;
        let mut header = runtime.clone();
        // This semantic pin is selected by the signed runtime's literal member;
        // independent root/role/key and complete initial-wrapper verification
        // remain mandatory below. No member can choose a different root.
        header.authority_history_manifest_sha256 = wrapper.history.manifest_sha256.clone();
        let owner = authenticate(raw.as_bytes(), &header, role)?;
        let epoch = owner.history.current_epoch().map_err(error)?.statement();
        require(owner.checkpoint.payload.endpoint_role == *endpoint_role
            && common_value(&owner.state, &["endpointProcessIdentitySha256"])? == state
            && common_value(&epoch.endpoint_process_identity, &["endpointRole", "identitySha256"])? == identity
            && common_value(&owner.checkpoint.payload,
                &["endpointRole", "endpointProcessIdentitySha256", "predecessorCheckpointSha256"])? == payload
            && epoch.checkpoint_authority == primary_epoch.checkpoint_authority
            && epoch.service_signing_key == primary_epoch.service_signing_key)?;
        for domain in [PREDECESSOR, HISTORY_ROOT, DURABLE_HEAD] {
            forbidden.insert(owner.state.commitment(domain)?);
        }
        authenticated.insert(*endpoint_role, (header, owner));
    }
    let mut result = BTreeMap::new();
    for (endpoint_role, (header, owner)) in authenticated {
        let epoch = owner.history.current_epoch().map_err(error)?.statement();
        let authority = epoch.checkpoint_authority.validate_and_decode().map_err(error)?;
        let pin = pins.get(&endpoint_role).ok_or_else(|| error("initial helper role pin absent"))?;
        super::super::protocol::require_nonzero_digest("initialHelper.consumePredecessor",
            &pin.consume_cursor.expected_predecessor_receipt_sha256).map_err(error)?;
        require(pin.endpoint_process_identity == epoch.endpoint_process_identity
            && pin.signed_current_key_authorization == owner.checkpoint
            && pin.declared_socket_path == runtime.listener_socket_path
            && pin.consume_head_observed_at_boottime_nanos == ns(&owner.state.issued_at_boottime_ns)?
            && pin.consume_cursor.sequence_high_water == 0 && pin.consume_cursor.expected_next_sequence == 1)?;
        require(!forbidden.contains(&pin.consume_cursor.expected_predecessor_receipt_sha256))?;
        require(credentials.read_verifying_key(&pin.endpoint_verifying_key_credential)?
                == epoch.service_signing_key.validate_and_decode().map_err(error)?
            && credentials.read_verifying_key(&pin.checkpoint_authority_verifying_key_credential)? == authority)?;
        pin.build_historical(credentials)?;
        // All live process/executable/window and actual empty-directory checks
        // occur before the first generation/helper journal is opened.
        let raw = members.get(&endpoint_role).ok_or_else(|| error("initial helper member absent"))?;
        admit(raw.as_bytes(), &header, role, bootstrap, activation)?;
        let until = owner.checkpoint.payload.valid_until_boottime.to_runtime().map_err(error)?;
        let deadline = ProtocolBoottimeDeadline::from_runtime(
            super::super::boottime::BoottimeDeadline::from_absolute_in_expected_domain(until.domain(),
                until.absolute_nanos().min(ns(&owner.state.startup_deadline_boottime_ns)?)).map_err(error)?);
        result.insert(endpoint_role, HelperAuthorization { checkpoint: owner.checkpoint, checkpoint_authority: authority, deadline });
    }
    Ok(result)
}

/// Bind an authenticated initial wrapper to an already signature-admitted
/// remote generation grant. This checks public data only: it never constructs
/// a Bootstrap or claims to measure the remote process or its directories.
/// The ordinary local owner retains its separate live admission below.
pub(super) fn require_remote_guest(raw: &[u8], runtime: &RuntimeConfigHeaderV3,
    role: TrustedHostServiceRoleV3, grant: &generation_service::RemoteGrant)
    -> Result<(), ServiceRunnerError> {
    if !selected(raw)? { return Ok(()); }
    let owner = authenticate(raw, runtime, role)?;
    require_remote_guest_owner(&owner, grant)
}

/// Public-data association for a root-verified cold genesis grant. This does
/// not create the local owner or infer currentness from a checkpoint; actual
/// startup still performs executable/process/empty-directory admission below.
pub(super) fn require_genesis_guest(raw: &[u8], runtime: &RuntimeConfigHeaderV3,
    role: TrustedHostServiceRoleV3, binding: &guest::GuestClosureBinding) -> Result<(), ServiceRunnerError> {
    require(runtime.api_version == super::publication_genesis_service::RUNTIME && selected(raw)?)?;
    let owner = authenticate(raw, runtime, role)?;
    require_genesis_guest_owner(&owner, role, binding)
}

fn require_genesis_guest_owner(owner: &Authenticated, role: TrustedHostServiceRoleV3,
    binding: &guest::GuestClosureBinding) -> Result<(), ServiceRunnerError> {
    let state = &owner.state;
    let identity = &owner.history.current_epoch().map_err(error)?.statement().endpoint_process_identity;
    require(binding.service_role == role_name(role) && binding.uid == identity.endpoint_uid && binding.gid == identity.endpoint_gid
        && binding.boot_id_base64url == state.boot_id_base64url
        && binding.time_namespace_device == state.time_namespace_device && binding.time_namespace_inode == state.time_namespace_inode
        && binding.invocation_id == state.invocation_id && binding.startup_deadline_boottime_ns == state.startup_deadline_boottime_ns
        && binding.lifetime_deadline_boottime_ns == state.lifetime_deadline_boottime_ns
        && ns(&state.issued_at_boottime_ns)? <= ns(&binding.issued_at_boottime_ns)?)
}

pub(super) fn require_genesis_window(raw: &[u8], runtime: &RuntimeConfigHeaderV3,
    role: TrustedHostServiceRoleV3, issued: u64, expires: u64) -> Result<(), ServiceRunnerError> {
    require(runtime.api_version == super::publication_genesis_service::RUNTIME && selected(raw)?)?;
    let owner = authenticate(raw, runtime, role)?;
    require_genesis_window_owner(&owner, issued, expires)
}

fn require_genesis_window_owner(owner: &Authenticated, issued: u64, expires: u64) -> Result<(), ServiceRunnerError> {
    require(issued < expires && issued >= owner.checkpoint.payload.valid_from_boottime.absolute_boottime_nanos()
        && expires <= owner.checkpoint.payload.valid_until_boottime.absolute_boottime_nanos()
        && expires <= ns(&owner.state.lifetime_deadline_boottime_ns)?)
}

/// Only validation of a retained cold result after startup; not startup,
/// directory admission, renewed currentness, or permission to create a gate.
pub(super) fn load_retained_genesis_witness(raw: &[u8], runtime: &RuntimeConfigHeaderV3,
    role: TrustedHostServiceRoleV3, binding: &guest::GuestClosureBinding, issued: u64, expires: u64)
    -> Result<RuntimeAuthorityHistory, ServiceRunnerError> {
    require(runtime.api_version == super::publication_genesis_service::RUNTIME && selected(raw)?)?;
    let owner = authenticate_window(raw, runtime, role, false)?;
    require_genesis_guest_owner(&owner, role, binding)?;
    require_genesis_window_owner(&owner, issued, expires)?;
    Ok(owner.history)
}

pub(super) fn require_retained_completed_guest(raw: &[u8], runtime: &RuntimeConfigHeaderV3,
    role: TrustedHostServiceRoleV3, grant: &generation_service::RemoteGrant)
    -> Result<(), ServiceRunnerError> {
    require(selected(raw)?)?;
    let owner = authenticate_window(raw, runtime, role, false)?;
    require_remote_guest_owner(&owner, grant)
}

fn require_remote_guest_owner(owner: &Authenticated, grant: &generation_service::RemoteGrant)
    -> Result<(), ServiceRunnerError> {
    let state = &owner.state;
    let binding = grant.guest();
    let identity = &owner.history.current_epoch().map_err(error)?.statement().endpoint_process_identity;
    require(owner.history.manifest_sha256() == grant.history().manifest_sha256()
        && binding.service_role == role_name(state.service_role)
        && binding.uid == identity.endpoint_uid && binding.gid == identity.endpoint_gid
        && binding.boot_id_base64url == state.boot_id_base64url
        && binding.time_namespace_device == state.time_namespace_device
        && binding.time_namespace_inode == state.time_namespace_inode
        && binding.invocation_id == state.invocation_id
        && binding.startup_deadline_boottime_ns == state.startup_deadline_boottime_ns
        && binding.lifetime_deadline_boottime_ns == state.lifetime_deadline_boottime_ns
        && ns(&state.issued_at_boottime_ns)? <= ns(&binding.issued_at_boottime_ns)?)
}

fn check_window(owner: &Authenticated, bootstrap: &Bootstrap, process: &guest_original::Process)
    -> Result<(), ServiceRunnerError> {
    bootstrap.check()?;
    process.check()?;
    let state = &owner.state;
    let association = bootstrap.generation_association()?;
    association.check_startup()?;
    let binding = association.binding();
    let identity = &owner.history.current_epoch().map_err(error)?.statement().endpoint_process_identity;
    let now = boottime_now_nanos().map_err(error)?;
    require(binding.service_role == role_name(state.service_role)
        && binding.uid == identity.endpoint_uid && binding.gid == identity.endpoint_gid
        && binding.boot_id_base64url == state.boot_id_base64url
        && binding.time_namespace_device == state.time_namespace_device
        && binding.time_namespace_inode == state.time_namespace_inode && binding.invocation_id == state.invocation_id
        && binding.startup_deadline_boottime_ns == state.startup_deadline_boottime_ns
        && binding.lifetime_deadline_boottime_ns == state.lifetime_deadline_boottime_ns
        && ns(&state.issued_at_boottime_ns)? <= ns(&binding.issued_at_boottime_ns)?
        && process.domain() == state.domain()? && now >= ns(&state.issued_at_boottime_ns)?
        && now < association.startup() && now < owner.checkpoint.payload.valid_until_boottime.absolute_boottime_nanos()
        && now >= owner.checkpoint.payload.valid_from_boottime.absolute_boottime_nanos())?;
    Ok(())
}

fn ima(fd: BorrowedFd<'_>) -> Result<Sha256Digest, ServiceRunnerError> {
    let length = unsafe { libc::fgetxattr(fd.as_raw_fd(), c"security.ima".as_ptr(), ptr::null_mut(), 0) };
    require(length > 0 && length <= 4096)?;
    let mut bytes = vec![0u8; length as usize];
    let read = unsafe { libc::fgetxattr(fd.as_raw_fd(), c"security.ima".as_ptr(), bytes.as_mut_ptr().cast(), bytes.len()) };
    require(read == length)?;
    Ok(Sha256Digest::compute(&bytes))
}
#[repr(C, align(8))]
struct VerityDigest { algorithm: u16, length: u16, bytes: [u8;64] }
fn verity(fd: BorrowedFd<'_>) -> Result<Sha256Digest, ServiceRunnerError> {
    let mut value = VerityDigest { algorithm: 0, length: 64, bytes: [0;64] };
    require(unsafe { libc::ioctl(fd.as_raw_fd(), 0xc0046686u32 as libc::Ioctl, &mut value) } == 0
        && value.algorithm == 1 && value.length == 32)?;
    Sha256Digest::parse(format!("sha256:{}", hex::encode(&value.bytes[..32]))).map_err(error)
}

fn executable(owner: &Authenticated, bootstrap: &Bootstrap, process: &guest_original::Process)
    -> Result<(), ServiceRunnerError> {
    let expected = &owner.history.current_epoch().map_err(error)?.statement().endpoint_process_identity;
    let (pid, start, inode) = process.native_binding()?;
    let pidfd = descriptor_stat(process.descriptor())?;
    require(pid == expected.endpoint_pid && start == expected.endpoint_start_time_ticks
        && inode == expected.endpoint_pidfd_inode
        && pidfd_stat_identity_sha256(pidfd.st_dev, pidfd.st_ino, pidfd.st_mode, pidfd.st_uid, pidfd.st_gid)
            == expected.endpoint_pidfd_stat_sha256
        && unsafe { libc::getuid() } == expected.endpoint_uid && unsafe { libc::geteuid() } == expected.endpoint_uid
        && unsafe { libc::getgid() } == expected.endpoint_gid && unsafe { libc::getegid() } == expected.endpoint_gid)?;
    // This fixed kernel-owned self link is intentionally followed; no supplied
    // pathname or proc PID can select a different executable.
    let raw = unsafe { libc::open(c"/proc/self/exe".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if raw < 0 { return Err(io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let before = descriptor_stat(fd.as_fd())?;
    require(before.st_mode & libc::S_IFMT == libc::S_IFREG && before.st_mode & 0o7777 == 0o755
        && before.st_uid == 0 && before.st_gid == 0 && before.st_nlink == 1 && before.st_size > 0
        && before.st_size as u64 <= MAX_EXECUTABLE && before.st_dev == expected.executable_device
        && before.st_ino == expected.executable_inode && before.st_size as u64 == expected.executable_length)?;
    require(ima(fd.as_fd())? == expected.executable_ima_sha256
        && verity(fd.as_fd())? == expected.executable_fs_verity_sha256)?;
    let file = std::fs::File::from(fd);
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    let mut buffer = [0u8;65536];
    while offset < expected.executable_length {
        check_window(owner, bootstrap, process)?;
        let wanted = usize::try_from((expected.executable_length - offset).min(buffer.len() as u64)).map_err(error)?;
        let count = match file.read_at(&mut buffer[..wanted], offset) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        require(count > 0)?;
        hasher.update(&buffer[..count]); offset += count as u64;
    }
    let digest = Sha256Digest::parse(format!("sha256:{}", hex::encode(hasher.finalize()))).map_err(error)?;
    let after = descriptor_stat(file.as_fd())?;
    require(digest == expected.executable_sha256 && before.st_dev == after.st_dev && before.st_ino == after.st_ino
        && before.st_size == after.st_size && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid && before.st_gid == after.st_gid && before.st_nlink == after.st_nlink
        && before.st_mtime == after.st_mtime && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime && before.st_ctime_nsec == after.st_ctime_nsec
        && ima(file.as_fd())? == expected.executable_ima_sha256
        && verity(file.as_fd())? == expected.executable_fs_verity_sha256)?;
    check_window(owner, bootstrap, process)
}

fn empty_directory(fd: BorrowedFd<'_>, name: &str, expected: &ActivationDirectoryIdentityV3)
    -> Result<(), ServiceRunnerError> {
    validate_directory_capability(fd, name, expected)?;
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut filesystem) } != 0 { return Err(io::Error::last_os_error().into()); }
    require(matches!(filesystem.f_type as u64, 0xef53 | 0x58465342 | 0x9123683e))?;
    // A new OFD, not dup(), prevents a prior enumeration cursor hiding names.
    let raw = unsafe { libc::openat(fd.as_raw_fd(), c".".as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) };
    if raw < 0 { return Err(io::Error::last_os_error().into()); }
    let scan = unsafe { OwnedFd::from_raw_fd(raw) };
    validate_directory_capability(scan.as_fd(), name, expected)?;
    let mut buffer = [0u8;4096];
    let mut dots = BTreeSet::new();
    for _ in 0..8 {
        let count = unsafe { libc::syscall(libc::SYS_getdents64, scan.as_raw_fd(), buffer.as_mut_ptr(), buffer.len()) };
        if count < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(e.into());
        }
        if count == 0 {
            require(dots.len() == 2)?;
            validate_directory_capability(scan.as_fd(), name, expected)?;
            return validate_directory_capability(fd, name, expected);
        }
        let count = usize::try_from(count).map_err(error)?;
        require(count <= buffer.len())?;
        let mut offset = 0;
        while offset < count {
            require(count - offset >= 20)?;
            let length = u16::from_ne_bytes([buffer[offset+16], buffer[offset+17]]) as usize;
            require(length >= 20 && length <= count - offset)?;
            let name = &buffer[offset+19..offset+length];
            let end = name.iter().position(|b| *b == 0).ok_or_else(|| error("initial directory name missing terminator"))?;
            let name = &name[..end];
            require((name == b"." || name == b"..") && dots.insert(name.to_vec()))?;
            offset += length;
        }
    }
    Err(error("initial directory census did not terminate within bound"))
}

pub(super) fn admit(raw: &[u8], runtime: &RuntimeConfigHeaderV3, role: TrustedHostServiceRoleV3,
    bootstrap: &Bootstrap, activation: &BTreeMap<String, OwnedFd>) -> Result<RuntimeAuthorityHistory, ServiceRunnerError> {
    let owner = authenticate(raw, runtime, role)?;
    let process = guest_original::Process::capture()?;
    check_window(&owner, bootstrap, &process)?;
    executable(&owner, bootstrap, &process)?;
    let identity = &owner.history.current_epoch().map_err(error)?.statement().endpoint_process_identity;
    for (name, directory) in &owner.state.directories {
        check_window(&owner, bootstrap, &process)?;
        require(directory.identity.uid == identity.endpoint_uid && directory.identity.gid == identity.endpoint_gid)?;
        let fd = activation.get(name).ok_or_else(|| error("initial directory descriptor missing"))?;
        empty_directory(fd.as_fd(), name, &directory.identity)?;
        check_window(&owner, bootstrap, &process)?;
    }
    // No directory, journal, grant, key, receipt or readiness state was written.
    Ok(owner.history)
}

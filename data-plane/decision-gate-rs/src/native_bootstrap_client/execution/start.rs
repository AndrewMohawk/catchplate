//! Protected preparation and genuine pre-start ownership.
//!
//! Retains actual originals and filesystem owners, not serialized successful
//! checks. Separate executable-profile network parents and actual start/creation
//! journals precede cgroup effects. Executable children remain source-private
//! and blocked; there is no public start or exec-release operation.

use super::{filesystem::PreparedFilesystem, host, parent::ParentOwner, start_authority};
use super::super::egress::ExecutionParents;
use super::super::{config, ensure, originals::{ArtifactV1, HeldOriginal}, OriginalClock};
use super::super::install::{InstalledCa, PreparedInstallation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::os::fd::BorrowedFd;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in super::super) struct Inputs {
    authority: ArtifactV1,
    authority_root: ArtifactV1,
    capability_token: ArtifactV1,
    execution_manifest: ArtifactV1,
}

impl Inputs {
    pub(in super::super) fn validate(&self) -> Result<(), String> {
        let originals = [&self.authority, &self.authority_root,
            &self.capability_token, &self.execution_manifest];
        for original in originals { config::artifact(original)?; }
        for (index, original) in originals.iter().enumerate() {
            ensure(originals[..index].iter().all(|other|
                original.path != other.path && original.sha256 != other.sha256),
                "native start originals must occupy distinct artifact roles")?;
        }
        Ok(())
    }
}

/// Preparation is not a transferable execution permission. StartOwner consumes
/// this exact owner only after genuine executable-parent admission joins.
pub(in super::super) struct PreparedStart {
    clock: Arc<OriginalClock>,
    originals: RefCell<Vec<HeldOriginal>>,
    token: RefCell<HeldOriginal>,
    filesystem: PreparedFilesystem,
    combined_trust: bool,
    installation: Option<Arc<InstalledCa>>,
    host: RefCell<host::HostOwner>,
    authorization: start_authority::Authorization,
    thread_id: libc::pid_t,
    stopped: Cell<bool>,
}

fn thread_id() -> Result<libc::pid_t, String> {
    let value = unsafe { libc::syscall(libc::SYS_gettid) };
    let value = libc::pid_t::try_from(value).map_err(|_| "native start thread identity invalid")?;
    ensure(value > 0, "native start thread identity invalid")?;
    Ok(value)
}

fn digest_text(raw: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(raw)) }

impl PreparedStart {
    pub(in super::super) fn open(inputs: Inputs, clock: Arc<OriginalClock>) -> Result<Self, String> {
        Self::open_profile(inputs, clock, false)
    }

    pub(in super::super) fn open_with_trust(inputs: Inputs, clock: Arc<OriginalClock>) -> Result<Self, String> {
        Self::open_profile(inputs, clock, true)
    }

    fn open_profile(inputs: Inputs, clock: Arc<OriginalClock>, combined_trust: bool) -> Result<Self, String> {
        clock.check()?;
        inputs.validate()?;
        ensure(unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
            && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0,
            "native start preparation requires the privileged launcher")?;
        let owner_thread = thread_id()?;
        let root_pin = inputs.authority_root.sha256.clone();
        let manifest_pin = inputs.execution_manifest.sha256.clone();
        let token_pin = inputs.capability_token.sha256.clone();
        let mut originals = Vec::with_capacity(2);
        let root = super::super::read(inputs.authority_root, 16 * 1024, &clock, &mut originals)?;
        let original = super::super::read(inputs.authority,
            start_authority::MAX_BYTES, &clock, &mut originals)?;
        let authorization = start_authority::admit_constraints(&original, &root, &root_pin, &clock)?;
        let constraints = &authorization.constraints;
        ensure(constraints.execution_manifest_sha256 == manifest_pin
            && constraints.capability.capability_token_sha256 == token_pin,
            "native start signed manifest/token roles differ from cold pins")?;
        clock.check()?;
        let (mut token, secret) = HeldOriginal::read_private(inputs.capability_token, 256)?;
        clock.check()?;
        ensure((32..=256).contains(&secret.len()) && secret.iter().all(|byte|
            byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-')),
            "native start protected token shape differs")?;
        ensure(digest_text(&secret) == constraints.capability.capability_token_sha256,
            "native start protected token differs from signed authority")?;
        drop(secret);
        token.require_private()?;
        clock.check()?;
        token.recheck()?;
        clock.check()?;
        let signed_host = &constraints.network_owner;
        let observed_host = host::HostOwner::open(&host::Spec {
            host_id: signed_host.host_id.clone(),
            machine_id_sha256: constraints.machine_id_sha256.clone(),
            boot_id: signed_host.boot_id.clone(), namespace_device: signed_host.namespace_device,
            namespace_inode: signed_host.namespace_inode, owner_uid: signed_host.owner_uid,
        }, &clock)?;
        // Signature, exact cold pin and actual host admission precede detached
        // immutable-root preparation. This creates no child or visible mount.
        let filesystem = if combined_trust {
            PreparedFilesystem::open_with_trust(&inputs.execution_manifest, Arc::clone(&clock))?
        } else { PreparedFilesystem::open(&inputs.execution_manifest, Arc::clone(&clock))? };
        clock.check()?;
        let held_manifest = filesystem.manifest_sha256();
        ensure(format!("sha256:{}", held_manifest.iter().map(|byte| format!("{byte:02x}"))
            .collect::<String>()) == manifest_pin,
            "native start retained manifest differs from independently signed original")?;
        let prepared = Self { clock, originals: RefCell::new(originals), token: RefCell::new(token),
            filesystem, combined_trust, installation: None, host: RefCell::new(observed_host), authorization,
            thread_id: owner_thread, stopped: Cell::new(false) };
        prepared.check()?;
        Ok(prepared)
    }

    /// Only v6 can reach this consuming, separately authorized host effect.
    /// Join actual image trust and all start/parent authorities BEFORE its claim.
    pub(in super::super) fn install_ca(&mut self, pending: PreparedInstallation)
        -> Result<serde_json::Value, String>
    {
        ensure(self.combined_trust && self.installation.is_none(),
            "native combined CA installation was not cold-selected or was already consumed")?;
        self.check()?;
        pending.require_start(&self.authorization, &self.clock)?;
        self.filesystem.require_application_trust(pending.actual_ca_original()?, pending.destination_path())?;
        pending.require_start(&self.authorization, &self.clock)?;
        let installed = pending.install()?;
        let receipt = installed.receipt().clone();
        self.installation = Some(installed);
        self.check()?;
        Ok(receipt)
    }

    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "native start preparation is stopped")?;
        self.clock.check()?;
        ensure(thread_id()? == self.thread_id, "native start owner moved to another thread")?;
        self.host.try_borrow_mut().map_err(|_| "native start host already borrowed")?.check(&self.clock)?;
        for original in self.originals.try_borrow_mut()
            .map_err(|_| "native start originals already borrowed")?.iter_mut() {
            self.clock.check()?;
            original.recheck()?;
            self.clock.check()?;
        }
        {
            let mut token = self.token.try_borrow_mut().map_err(|_| "native start token already borrowed")?;
            token.require_private()?;
            self.clock.check()?;
            token.recheck()?;
            self.clock.check()?;
            token.require_private()?;
        }
        self.filesystem.check()?;
        if let Some(installation) = &self.installation {
            ensure(self.combined_trust, "legacy execution acquired combined CA ownership")?;
            installation.require_start(&self.authorization, &self.clock)?;
        }
        self.clock.check()?;
        self.host.try_borrow_mut().map_err(|_| "native start host already borrowed")?.check(&self.clock)?;
        self.clock.check()?;
        self.stopped.set(false);
        Ok(())
    }
}

/// Genuine retained parents and preparation, never a caller-built success
/// carrier. It owns neither a child nor a journal permit, so checks cannot
/// recurse through a lifecycle owner or create an Arc cycle.
pub(super) struct StartOwner {
    prepared: PreparedStart,
    parents: Arc<ExecutionParents>,
    parent: ParentOwner,
    operation: [u8; 32],
    pid: u32,
    claimed: Cell<bool>,
    stopped: Cell<bool>,
}

impl StartOwner {
    pub(super) fn bind(prepared: PreparedStart, parents: Arc<ExecutionParents>)
        -> Result<Arc<Self>, String>
    {
        prepared.check()?;
        ensure(prepared.combined_trust == prepared.installation.is_some(),
            "combined execution requires actual completed CA installation before any start claim")?;
        if let Some(installation) = &prepared.installation { installation.require_parents(&parents)?; }
        parents.require_start(&prepared.authorization, &prepared.clock)?;
        let parent = ParentOwner::open(&prepared.authorization.constraints.containment,
            &prepared.clock)?;
        let mut hash = Sha256::new();
        hash.update(b"serverware.nativeWorkloadStartOperation/v1\0");
        for original in [prepared.authorization.original_sha256,
            prepared.authorization.root_key_id, parents.operation_sha256(),
            prepared.filesystem.manifest_sha256()] { hash.update(original); }
        let owner = Arc::new(Self { prepared, parents, parent, operation: hash.finalize().into(),
            pid: std::process::id(), claimed: Cell::new(false), stopped: Cell::new(false) });
        owner.check_admission()?;
        Ok(owner)
    }

    pub(super) fn check_admission(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "native start admission owner is stopped")?;
        self.prepared.check()?;
        self.check_cleanup_scope()?;
        self.parents.require_start(&self.prepared.authorization, &self.prepared.clock)?;
        self.parent.check(&self.prepared.clock)?;
        self.prepared.check()?;
        self.stopped.set(false);
        Ok(())
    }

    /// Identity-only association for retained claim diagnostics. It never
    /// authorizes creation or extends expired/revoked admission. The leaf owner
    /// must still attempt exact-owned emergency termination if this fails.
    pub(super) fn check_cleanup_scope(&self) -> Result<(), String> {
        ensure(self.pid == std::process::id() && thread_id()? == self.prepared.thread_id
            && unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
            && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0,
            "native start retained claim crossed process/thread/privilege boundary")
    }

    pub(super) fn containment_parent(&self) -> BorrowedFd<'_> { self.parent.fd() }
    pub(super) fn constraints(&self) -> &start_authority::Constraints {
        &self.prepared.authorization.constraints
    }
    pub(super) fn cleanup_boottime_ns(&self) -> u64 { self.prepared.authorization.cleanup_boottime_ns }
    pub(super) fn stop_boottime_ns(&self) -> u64 { self.prepared.authorization.stop_boottime_ns }
    pub(super) fn filesystem(&self) -> &PreparedFilesystem { &self.prepared.filesystem }
    pub(super) fn operation_sha256(&self) -> [u8; 32] { self.operation }
    pub(super) fn clock(&self) -> &OriginalClock { &self.prepared.clock }
    pub(super) fn parents(&self) -> &Arc<ExecutionParents> { &self.parents }

    pub(super) fn begin_claim(&self) -> Result<(), String> {
        self.check_admission()?;
        ensure(!self.claimed.replace(true), "native start owner already attempted its irreversible claim")
    }
}

/// Source-private orchestration: real parent admission, durable start and
/// creation claims, then one new cgroup leaf. This does not spawn a workload.
pub(super) fn prepare_containment(prepared: PreparedStart, parents: Arc<ExecutionParents>)
    -> Result<super::containment::ContainmentOwner, String>
{
    let owner = StartOwner::bind(prepared, parents)?;
    let permit = super::start_reservation::claim(Arc::clone(&owner))?;
    super::containment::ContainmentOwner::create(owner, permit)
}

/// Both real irreversible claims and the new leaf precede the sole clone.
/// This deliberately returns only a blocked child, never execution authority.
pub(super) fn prepare_blocked_child(prepared: PreparedStart, parents: Arc<ExecutionParents>)
    -> Result<super::child::BlockedChild, String>
{
    super::child::BlockedChild::create(prepare_containment(prepared, parents)?)
}

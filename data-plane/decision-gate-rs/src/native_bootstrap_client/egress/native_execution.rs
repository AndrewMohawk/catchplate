//! Same-child networking for the actual claimed executable owner. This module
//! cannot create a child, send an exec command, adopt a PID, or promote a
//! diagnostic WorkloadOwner. The release permission is a retained Rust owner.

use super::{attachment, attachment_authority, attachment_backend::AttachmentBackend,
    attachment_readback, attachment_reservation::{self, AttachmentReservation, ClaimState},
    attachment_wire::AttachmentPlan, authority, effect::{self, Installed},
    owners::{AttachmentOwner, Owner, Phase}, workload::AttachmentDescriptors, ensure};
use super::super::execution::{child::BlockedChild, child_network::ChildNetworkBorrow};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn digest(raw: &[u8]) -> [u8; 32] { Sha256::digest(raw).into() }
fn signed_digest(text: &str) -> Result<[u8; 32], String> {
    let value = text.strip_prefix("sha256:").ok_or("executable network token digest prefix differs")?;
    ensure(value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "executable network token digest differs")?;
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "executable network token digest invalid")?;
    }
    ensure(result.iter().any(|b| *b != 0), "executable network token digest is zero")?;
    Ok(result)
}

/// Borrows the actual blocked executable child and its admitted parents. A
/// single attempt is burned on that child, not on a copy of this owner.
pub(in super::super) struct PreparedNetwork<'child> {
    child: ChildNetworkBorrow<'child>,
    reservation_id: [u8; 32],
    association_sha256: [u8; 32],
    token_sha256: [u8; 32],
    install_attempted: Cell<bool>,
    final_readback: Cell<bool>,
    stopped: Cell<bool>,
}

impl<'child> PreparedNetwork<'child> {
    pub(in super::super) fn open(child: &'child BlockedChild) -> Result<Self, String> {
        let child = child.network_borrow()?;
        child.begin_network()?;
        child.parents().check()?;
        let grant = child.parents().egress_authorization();
        ensure(grant.execution_profile && grant.creation_journal.is_some()
            && grant.child_network_policy == Some(authority::ChildNetworkPolicy::ManualDualStackV1),
            "executable networking requires its explicit admitted execution parent")?;
        child.parents().attachment_pending().require_egress(grant, child.parents().original_clock())?;
        let (nsdev, nsino, port, sockdev, sockino) = child.filter_identity()?;
        ensure((nsdev, nsino) != (grant.network_owner.namespace_device, grant.network_owner.namespace_inode),
            "executable child namespace must differ from the signed launcher namespace")?;
        let mut slot = Sha256::new();
        slot.update(b"catchplate/native-egress-installation-slot/v1\0");
        for scalar in [grant.journal.namespace.as_bytes(), grant.capability.capability_id.as_bytes()] {
            slot.update((scalar.len() as u64).to_be_bytes()); slot.update(scalar);
        }
        let token_sha256 = signed_digest(&grant.capability.capability_token_sha256)?;
        let mut operation = Sha256::new();
        operation.update(b"catchplate/native-executable-network-operation/v1\0");
        for value in [child.operation_sha256(), child.parents().operation_sha256(), grant.original_sha256] {
            operation.update(value);
        }
        for value in child.kernel_identity() { operation.update(value.to_be_bytes()); }
        for value in [nsdev, nsino, port as u64, sockdev, sockino] { operation.update(value.to_be_bytes()); }
        let (route_dev, route_ino, route_port) = child.route_identity()?;
        for value in [route_dev, route_ino, route_port as u64] { operation.update(value.to_be_bytes()); }
        child.check()?;
        let owner = Self { child, reservation_id: slot.finalize().into(),
            association_sha256: operation.finalize().into(), token_sha256,
            install_attempted: Cell::new(false), final_readback: Cell::new(false), stopped: Cell::new(false) };
        owner.check()?;
        Ok(owner)
    }

    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "executable network owner stopped")?;
        self.child.check()?;
        self.child.parents().check()?;
        self.child.check()?;
        self.stopped.set(false);
        Ok(())
    }
    pub(super) fn check_running(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "executable network owner stopped")?;
        // This source-owned child check requires consumed release + positive
        // EXEC. The sole final pre-detach snapshot is ALSO clipped by the
        // original admission; subsequent custody checks do not renew it.
        self.child.check_running()?;
        if self.final_readback.get() { self.child.parents().check()?; }
        self.stopped.set(false);
        Ok(())
    }
    pub(super) fn deadline(&self, phase: Phase) -> Result<Instant, String> {
        if phase == Phase::Admission { return self.child.deadline(); }
        self.check_running()?;
        if self.final_readback.get() { return self.child.parents().original_clock().instant_deadline(); }
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } == 0
            && now.tv_sec >= 0 && (0..1_000_000_000).contains(&now.tv_nsec),
            "executable network continuation clock unavailable")?;
        let boot = (now.tv_sec as u64).checked_mul(1_000_000_000)
            .and_then(|v| v.checked_add(now.tv_nsec as u64)).ok_or("network continuation clock overflow")?;
        let remaining = self.child.stop_boottime_ns().checked_sub(boot)
            .filter(|v| *v != 0).ok_or("network signed continuation ended")?;
        let result = Instant::now().checked_add(Duration::from_nanos(remaining))
            .ok_or("network continuation deadline overflow")?;
        self.check_running()?;
        Ok(result)
    }
    pub(super) fn authority(&self) -> &authority::Authorization { self.child.parents().egress_authorization() }
    pub(super) fn association(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (self.reservation_id, self.association_sha256, self.token_sha256)
    }
    pub(super) fn filter(&self) -> Result<File, String> { self.child.filter() }
    pub(super) fn backend_identity(&self) -> Result<(u64, u64, u32, u64, u64), String> {
        self.child.filter_identity()
    }
    pub(super) fn duplicate_attachment(&self) -> Result<AttachmentDescriptors, String> {
        self.check()?;
        let host_namespace = self.child.host_namespace()?;
        let child_namespace = self.child.child_namespace()?;
        let child_route = self.child.route()?;
        let host = host_namespace.metadata().map_err(|_| "executable host namespace original unavailable")?;
        let child = child_namespace.metadata().map_err(|_| "executable child namespace original unavailable")?;
        let (route_socket_device, route_socket_inode, route_port_id) = self.child.route_identity()?;
        self.check()?;
        Ok(AttachmentDescriptors { host_namespace, child_namespace, child_route,
            host_namespace_device: host.dev(), host_namespace_inode: host.ino(),
            child_namespace_device: child.dev(), child_namespace_inode: child.ino(),
            route_socket_device, route_socket_inode, route_port_id })
    }

    pub(in super::super) fn install(&self) -> Result<NetworkReady<'_, 'child>, String> {
        self.check()?;
        ensure(!self.install_attempted.replace(true), "executable network install attempt already consumed")?;
        let egress = Owner::Executable(self);
        let installed = effect::install_owner(egress)?;
        ensure(installed.created(), "executable network cannot adopt a historical firewall completion")?;
        let pending = self.child.parents().attachment_pending();
        pending.require_egress(self.authority(), self.child.parents().original_clock())?;
        let mut scope = Sha256::new();
        scope.update(b"catchplate/native-executable-attachment-operation/v1\0");
        for value in [pending.authorization().original_sha256, self.child.operation_sha256(),
            self.association_sha256, installed.semantic_sha256(), installed.evidence_sha256()] { scope.update(value); }
        let guard = Arc::new(ExecutableAttachmentGuard { egress, pending,
            installed: RefCell::new(installed), stopped: Cell::new(false) });
        guard.check()?;
        let owner = AttachmentOwner::Executable(Arc::clone(&guard));
        let a = guard.authority();
        let mut slot = Sha256::new();
        slot.update(b"catchplate/native-network-attachment-slot/v1\0");
        for value in [a.journal.namespace.as_bytes(), a.capability.capability_id.as_bytes()] {
            slot.update((value.len() as u32).to_be_bytes()); slot.update(value);
        }
        let mut journal = attachment_reservation::open_owner(attachment_reservation::Spec {
            journal_path: PathBuf::from(&a.journal.path), journal_device: a.journal.device,
            journal_inode: a.journal.inode, reservation_id: slot.finalize().into(),
            association_sha256: scope.finalize().into(), token_sha256: pending.token_sha256(),
            bridge_lock_path: PathBuf::from(&a.bridge.lock.path), bridge_lock_device: a.bridge.lock.device,
            bridge_lock_inode: a.bridge.lock.inode,
        }, owner.clone())?;
        let mut backend = AttachmentBackend::open_owner(owner.clone(), &journal)?;
        let plan = backend.plan()?;
        journal.reserve(&plan)?;
        ensure(matches!(journal.claim()?, ClaimState::Fresh),
            "executable child cannot reuse a completed attachment")?;
        let mut observed = false;
        let outcome = (|| {
            guard.verify_firewall(Phase::Admission)?;
            backend.submit_once(&plan, &journal)?;
            let snapshot = backend.snapshot()?;
            let transcript = backend.transcript()?;
            journal.observe(&transcript)?;
            observed = true;
            let verified = attachment_readback::verify_owner(&owner, &plan, &snapshot, &transcript, Phase::Admission)?;
            guard.verify_firewall(Phase::Admission)?;
            journal.complete(&plan, &verified)?;
            Ok::<_, String>((verified.original().to_vec(), transcript.sha256(), verified.retirement_links()))
        })();
        let (semantic, evidence_sha256, retirement_links) = match outcome {
            Ok(value) => value,
            Err(error) => {
                if !observed { if let Ok(transcript) = backend.transcript() { let _ = journal.observe(&transcript); } }
                return Err(error);
            }
        };
        guard.check()?;
        Ok(NetworkReady { prepared: self, guard, backend, journal, plan, semantic,
            evidence_sha256, retirement_links, retirement_prepared: Cell::new(false),
            phase: Phase::Admission, stopped: false })
    }
}

/// Owns the real Installed backend, not a copied success. Its Arc graph has no
/// edge back from Installed/PreparedNetwork to an attachment owner.
pub(super) struct ExecutableAttachmentGuard<'a> {
    egress: Owner<'a>,
    pending: &'a attachment::Pending,
    installed: RefCell<Installed<'a>>,
    stopped: Cell<bool>,
}
impl<'a> ExecutableAttachmentGuard<'a> {
    pub(super) fn egress(&self) -> Owner<'a> { self.egress }
    pub(super) fn authority(&self) -> &attachment_authority::Authorization { self.pending.authorization() }
    pub(super) fn check(&self) -> Result<(), String> { self.check_phase(Phase::Admission) }
    pub(super) fn check_running(&self) -> Result<(), String> { self.check_phase(Phase::Continuation) }
    fn check_phase(&self, phase: Phase) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "executable attachment owner stopped")?;
        self.egress.check_phase(phase)?;
        if phase == Phase::Admission {
            let prepared = match self.egress { Owner::Executable(value) => value,
                _ => return Err("executable attachment cannot use a diagnostic owner".to_owned()) };
            self.pending.require_egress(prepared.authority(), prepared.child.parents().original_clock())?;
        }
        self.installed.try_borrow().map_err(|_| "executable firewall owner already borrowed")?
            .require_source(self.egress, phase)?;
        self.egress.check_phase(phase)?;
        self.stopped.set(false);
        Ok(())
    }
    fn enter_continuation(&self) -> Result<(), String> {
        self.egress.check_phase(Phase::Continuation)?;
        self.installed.try_borrow_mut().map_err(|_| "executable firewall owner already borrowed")?
            .enter_continuation()?;
        self.check_running()
    }
    fn verify_firewall(&self, phase: Phase) -> Result<(), String> {
        self.check_phase(phase)?;
        self.installed.try_borrow_mut().map_err(|_| "executable firewall owner already borrowed")?.check_phase(phase)?;
        self.check_phase(phase)
    }
}

/// Non-Clone, non-serializable same-child release handoff. The installed
/// firewall backend, attachment journal and purpose-specific locks survive
/// while the lifecycle retains this value; completed originals stay durable.
pub(in super::super) struct NetworkReady<'network, 'child> {
    prepared: &'network PreparedNetwork<'child>,
    guard: Arc<ExecutableAttachmentGuard<'network>>,
    backend: AttachmentBackend<'network, 'network>,
    journal: AttachmentReservation<'network, 'network>,
    plan: AttachmentPlan,
    semantic: Vec<u8>,
    evidence_sha256: [u8; 32],
    retirement_links: attachment_readback::RetirementLinks,
    retirement_prepared: Cell<bool>,
    phase: Phase,
    stopped: bool,
}
impl NetworkReady<'_, '_> {
    pub(in super::super) fn prepare_retirement(&mut self) -> Result<super::attachment_backend::HostRetirement, String> {
        ensure(self.phase == Phase::Admission && !self.stopped && !self.retirement_prepared.replace(true),
            "executable cleanup host owner already prepared or not admitted")?;
        self.guard.check()?;
        self.journal.check()?;
        self.backend.prepare_retirement(&self.prepared.child, &self.plan, self.retirement_links.copy_for_cleanup())
    }
    pub(in super::super) fn require_child(&self, child: &BlockedChild) -> Result<(), String> {
        ensure(!self.stopped && self.phase == Phase::Admission, "executable network release permission stopped")?;
        self.prepared.child.require_child(child)?;
        self.guard.check()?;
        self.backend.current()?;
        self.journal.check()
    }
    pub(in super::super) fn check(&mut self) -> Result<(), String> {
        ensure(self.phase == Phase::Admission, "running network cannot regain admission authority")?;
        self.check_phase(Phase::Admission)
    }
    pub(in super::super) fn check_running(&mut self) -> Result<(), String> {
        ensure(!self.stopped, "executable network owner stopped")?;
        if self.phase == Phase::Admission {
            self.prepared.final_readback.set(true);
            self.prepared.check_running()?;
            self.guard.enter_continuation()?;
            self.backend.enter_continuation()?;
            self.phase = Phase::Continuation;
            self.check_phase(Phase::Continuation)?;
            self.prepared.final_readback.set(false);
            return Ok(());
        }
        // Lifetime custody is query-free. A fixed installation transcript is
        // not an unbounded periodic monitoring budget or continuous snapshot.
        self.stopped = true;
        self.prepared.check_running()?;
        self.guard.check_running()?;
        self.backend.current()?;
        self.stopped = false;
        Ok(())
    }
    fn check_phase(&mut self, phase: Phase) -> Result<(), String> {
        ensure(!std::mem::replace(&mut self.stopped, true), "executable network owner stopped")?;
        self.guard.verify_firewall(phase)?;
        let snapshot = self.backend.snapshot()?;
        let transcript = self.backend.transcript()?;
        let owner = AttachmentOwner::Executable(Arc::clone(&self.guard));
        let verified = attachment_readback::verify_owner(&owner, &self.plan, &snapshot, &transcript, phase)?;
        ensure(verified.original() == self.semantic, "executable attachment semantic state changed")?;
        if phase == Phase::Admission { self.journal.check()?; }
        self.guard.check_phase(phase)?;
        self.stopped = false;
        Ok(())
    }
    /// Historical data, never a replacement for the held owner or live checks.
    pub(in super::super) fn firewall_semantic_sha256(&self) -> [u8; 32] { self.guard.installed.borrow().semantic_sha256() }
    pub(in super::super) fn firewall_evidence_sha256(&self) -> [u8; 32] { self.guard.installed.borrow().evidence_sha256() }
    pub(in super::super) fn attachment_semantic_sha256(&self) -> [u8; 32] { digest(&self.semantic) }
    pub(in super::super) fn attachment_evidence_sha256(&self) -> [u8; 32] { self.evidence_sha256 }
}

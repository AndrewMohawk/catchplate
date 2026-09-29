//! Separate attachment permission joined to real stopped-child/firewall owners.

use super::{attachment_authority, authority, effect::Installed, ensure, EgressGuard};
use super::super::{config, originals::{ArtifactV1, HeldOriginal}, OriginalClock};
use serde::Deserialize;
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in super::super) struct Inputs {
    authority: ArtifactV1,
    authority_root: ArtifactV1,
    capability_token: ArtifactV1,
}

impl Inputs {
    pub(in super::super) fn validate(&self) -> Result<(), String> {
        for pin in [&self.authority, &self.authority_root, &self.capability_token] {
            config::artifact(pin)?;
        }
        Ok(())
    }
}

pub(in super::super) struct Pending {
    authorization: attachment_authority::Authorization,
    token: RefCell<HeldOriginal>,
    token_sha256: [u8; 32],
    clock: usize,
    pid: u32,
}

impl Pending {
    pub(super) fn require_egress(&self, egress: &authority::Authorization,
        clock: &OriginalClock) -> Result<(), String> {
        clock.check()?;
        let a = &self.authorization;
        ensure(self.clock == clock as *const OriginalClock as usize && self.pid == std::process::id()
            && egress.child_network_policy == Some(authority::ChildNetworkPolicy::ManualDualStackV1)
            && a.root_key_id != egress.root_key_id
            && a.egress_authorization_sha256 == egress.original_sha256
            && super::digest_text(&a.launch_manifest_sha256) == egress.workload.launch_manifest_sha256
            && a.setup_sha256 == egress.setup_sha256 && a.delegation_sha256 == egress.delegation_sha256
            && a.target_request_sha256 == egress.target_request_sha256
            && a.policy_requirements_sha256 == egress.policy_requirements_sha256
            && a.release_record_sha256 == egress.release_record_sha256 && a.policy_hash == egress.policy_hash
            && a.configuration_sha256 == egress.configuration_sha256
            && a.runtime_ca_certificate_sha256 == egress.runtime_ca_certificate_sha256
            && a.runtime_ca_spki_sha256 == egress.runtime_ca_spki_sha256
            && a.ingress_leaf_certificate_sha256 == egress.ingress_leaf_certificate_sha256
            && a.client_trust_bundle_sha256 == egress.client_trust_bundle_sha256
            && a.client_challenge_sha256 == egress.client_challenge_sha256
            && a.target_spki_sha256 == egress.target_spki_sha256
            && a.machine_id_sha256 == egress.machine_id_sha256
            && a.target_principal_id == egress.target_principal_id && a.target_nonce == egress.target_nonce
            && a.issued_at_epoch_ns >= egress.issued_at_epoch_ns
            && a.expires_at_epoch_ns <= egress.expires_at_epoch_ns,
            "native attachment differs from the admitted egress/network-creation scope")?;
        ensure(canonical_ascii_bytes(&a.network_owner)? == canonical_ascii_bytes(&egress.network_owner)?
            && a.capability.capability_id != egress.capability.capability_id
            && a.capability.capability_token_sha256 != egress.capability.capability_token_sha256,
            "native attachment reuses an egress capability or differs from launcher identity")?;
        let creation = egress.creation_journal.as_ref().ok_or("native attachment creation journal absent")?;
        for other in [&egress.journal, creation] {
            ensure(a.journal.path != other.path
                && (a.journal.device, a.journal.inode) != (other.device, other.inode)
                && a.journal.namespace != other.namespace,
                "native attachment journal reuses an existing purpose")?;
            ensure(!PathBuf::from(&a.bridge.lock.path).starts_with(&other.path),
                "native attachment bridge lock overlaps an existing closed journal")?;
        }
        let routes = &a.attachment.routes;
        ensure(routes.len() == egress.ruleset.rules.len(), "native attachment route inventory differs")?;
        for (route, rule) in routes.iter().zip(&egress.ruleset.rules) {
            ensure(route.family == rule.family && route.destination == rule.address,
                "native attachment routes are not the exact signed proxy destinations")?;
        }
        let mut token = self.token.try_borrow_mut().map_err(|_| "attachment token already borrowed")?;
        token.require_private()?;
        clock.check()?;
        token.recheck()?;
        token.require_private()?;
        clock.check()
    }
}

pub(in super::super) fn prepare(inputs: Inputs, clock: &OriginalClock,
    held: &mut Vec<HeldOriginal>) -> Result<Pending, String> {
    inputs.validate()?;
    clock.check()?;
    ensure(unsafe { libc::getuid() == 0 && libc::geteuid() == 0
        && libc::getgid() == 0 && libc::getegid() == 0 },
        "native attachment requires the authorized root launcher")?;
    held.first().ok_or("attachment configuration original absent")?.require_private()?;
    let root_pin = inputs.authority_root.sha256.clone();
    let root = super::super::read(inputs.authority_root, 16 * 1024, clock, held)?;
    let raw = super::super::read(inputs.authority, 32 * 1024, clock, held)?;
    let authorization = attachment_authority::admit(&raw, &root, &root_pin,
        crate::authority_source_revision_v1::SOURCE_REVISION, clock)?;
    let (mut token, secret) = HeldOriginal::read_private(inputs.capability_token, 256)?;
    clock.check()?;
    ensure((32..=256).contains(&secret.len()) && secret.iter().all(|byte|
        byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-')),
        "native attachment token shape differs")?;
    let token_sha256: [u8; 32] = Sha256::digest(&secret).into();
    ensure(super::digest_text(&token_sha256) == authorization.capability.capability_token_sha256,
        "native attachment protected token differs from its signed commitment")?;
    drop(secret);
    token.require_private()?;
    token.recheck()?;
    token.require_private()?;
    clock.check()?;
    Ok(Pending { authorization, token: RefCell::new(token), token_sha256,
        clock: clock as *const OriginalClock as usize, pid: std::process::id() })
}

/// The public continuation has no replay success or caller-supplied owner.
/// Every descriptor, plan and observed original comes from retained real owners.
pub(in super::super) fn execute<'egress>(pending: Pending, egress: &'egress EgressGuard,
    installed: Installed<'egress>, mut capture: serde_json::Value) -> Result<(), String> {
    use super::attachment_reservation::{self, ClaimState, Spec};
    let guard = PreattachmentGuard::bind(pending, egress, installed)?;
    let a = guard.authority();
    let mut slot = Sha256::new();
    slot.update(b"serverware/native-network-attachment-slot/v1\0");
    for value in [a.journal.namespace.as_bytes(), a.capability.capability_id.as_bytes()] {
        slot.update((value.len() as u32).to_be_bytes());
        slot.update(value);
    }
    // A stable capability slot cannot become fresh through a new child/proof.
    let spec = Spec {
        journal_path: PathBuf::from(&a.journal.path), journal_device: a.journal.device,
        journal_inode: a.journal.inode, reservation_id: slot.finalize().into(),
        association_sha256: guard.association_sha256, token_sha256: guard.pending.token_sha256,
        bridge_lock_path: PathBuf::from(&a.bridge.lock.path),
        bridge_lock_device: a.bridge.lock.device, bridge_lock_inode: a.bridge.lock.inode,
    };
    let mut journal = attachment_reservation::open(spec, &guard)?;
    // Journal lock precedes bridge lock, preflight and exact datagram planning.
    let mut backend = super::attachment_backend::AttachmentBackend::open(&guard, &journal)?;
    let plan = backend.plan()?;
    journal.reserve(&plan)?;
    match journal.claim()? {
        ClaimState::Fresh => (),
        ClaimState::Completed => return Err("native attachment already completed; no replay action permitted".to_owned()),
    }
    guard.verify_firewall()?;
    // A failed one-shot effect is never retried or repaired. Preserve whatever
    // typed transport evidence exists while the original custody remains live.
    let snapshot = match backend.submit_once(&plan, &journal).and_then(|()| backend.snapshot()) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if guard.check().is_ok() {
                if let Ok(transcript) = backend.transcript() { let _ = journal.observe(&transcript); }
            }
            return Err(error);
        }
    };
    let transcript = backend.transcript()?;
    journal.observe(&transcript)?;
    let verified = super::attachment_readback::verify(&guard, &plan, &snapshot, &transcript)?;
    guard.verify_firewall()?;
    journal.complete(&plan, &verified)?;
    let observation = serde_json::json!({
        "apiVersion":"serverware.nativeNetworkAttachmentObservation/v1",
        "resultScope":"local-authorized-network-attachment-observed-before-owner-teardown",
        "okForAction":false,
        "status":"observed-attached",
        "authorizationSha256":super::digest_text(&a.original_sha256),
        "planSha256":super::digest_text(&plan.sha256()),
        "evidenceSha256":super::digest_text(&transcript.sha256()),
        "semanticSha256":super::super::super::sha256_prefixed(verified.original()),
    });
    let observation_raw = serde_json::to_vec(&observation)
        .map_err(|_| "encode native attachment observation")?;
    ensure(!observation_raw.is_empty() && observation_raw.len() <= 8191,
        "native attachment observation exceeds its bound")?;
    capture["attachment"] = observation;
    let mut encoded = serde_json::to_vec(&capture).map_err(|_| "encode native attachment capture")?;
    ensure(!encoded.is_empty() && encoded.len() < super::super::MAX_CAPTURE_BYTES
        && !encoded.contains(&b'\n') && !encoded.contains(&b'\r'),
        "native attachment capture exceeds its single-line bound")?;
    encoded.push(b'\n');
    backend.current()?;
    journal.check()?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    for chunk in encoded.chunks(16 * 1024) {
        backend.current()?;
        output.write_all(chunk).map_err(|_| "write native attachment capture")?;
        backend.current()?;
    }
    output.flush().map_err(|_| "flush native attachment capture")?;
    backend.current()?;
    journal.check()?;
    // These held locks and owners outlive output. No start is sent: dropping
    // the real stopped-child owner tears down its transient namespace/veth.
    Ok(())
}

/// Real retained owners only. check() makes no RTNL/nft query and cannot mint
/// another IO allowance; exact semantic snapshots are explicit boundaries.
pub(super) struct PreattachmentGuard<'egress> {
    egress: &'egress EgressGuard,
    installed: RefCell<Installed<'egress>>,
    pending: Pending,
    association_sha256: [u8; 32],
    stopped: Cell<bool>,
}

impl<'egress> PreattachmentGuard<'egress> {
    fn bind(pending: Pending, egress: &'egress EgressGuard,
        installed: Installed<'egress>) -> Result<Self, String> {
        egress.check()?;
        installed.require_owner(egress)?;
        pending.require_egress(&egress.precreation.authorization, &egress.precreation.clock)?;
        let a = &pending.authorization;
        {
            let proof = egress.precreation.proof.try_borrow()
                .map_err(|_| "attachment parent proof already borrowed")?;
            let setup = proof.setup();
            let delegation = proof.delegation();
            ensure(a.capability.capability_id != setup.ca_install.capability_id
                && a.capability.capability_token_sha256 != setup.ca_install.capability_token_sha256
                && [setup.authorizer_key_id, delegation.authorizer_key_id,
                    delegation.runtime_ca_spki_sha256, delegation.caller_issuer_spki_sha256,
                    delegation.caller_spki_sha256, delegation.target_issuer_spki_sha256,
                    delegation.target_spki_sha256].iter().all(|key| key != &a.root_key_id),
                "native attachment reuses an independent parent key or CA capability")?;
        }
        let mut scope = Sha256::new();
        scope.update(b"serverware/native-network-attachment-operation/v1\0");
        for digest in [a.original_sha256, egress.precreation.creation_scope_sha256,
            egress.association_sha256, installed.semantic_sha256(), installed.evidence_sha256()]
        { scope.update(digest); }
        let guard = Self { egress, installed: RefCell::new(installed), pending,
            association_sha256: scope.finalize().into(), stopped: Cell::new(false) };
        guard.check()?;
        Ok(guard)
    }

    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "native attachment owner stopped")?;
        self.egress.check()?;
        self.pending.require_egress(&self.egress.precreation.authorization, &self.egress.precreation.clock)?;
        self.installed.try_borrow().map_err(|_| "attachment firewall owner already borrowed")?
            .require_owner(self.egress)?;
        self.egress.precreation.clock.check()?;
        self.stopped.set(false);
        Ok(())
    }

    pub(super) fn egress(&self) -> &EgressGuard { self.egress }
    pub(super) fn authority(&self) -> &attachment_authority::Authorization { &self.pending.authorization }
    pub(super) fn deadline(&self) -> Result<Instant, String> {
        self.check()?;
        self.egress.precreation.clock.instant_deadline()
    }

    fn verify_firewall(&self) -> Result<(), String> {
        self.check()?;
        self.installed.try_borrow_mut().map_err(|_| "attachment firewall owner already borrowed")?.check()?;
        self.check()
    }
}

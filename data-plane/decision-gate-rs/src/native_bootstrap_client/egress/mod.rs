//! Separate grants and genuine proof/host/child ownership for fixed networking.
//!
//! Creation is preceded by a distinct irreversible cross-invocation claim.
//! Diagnostic creation and executable-child borrowing remain separate owners;
//! neither can substitute for the independent workload start/release authority.
//! Network attachment requires its separate admitted grant and durable claim;
//! no generic effect API is exposed.

mod authority;
pub(super) mod attachment;
mod attachment_authority;
mod attachment_backend;
mod attachment_readback;
mod attachment_reservation;
mod attachment_wire;
mod backend;
mod child_network_policy;
mod creation_reservation;
mod effect;
mod execution_parents;
mod native_execution;
mod owners;
mod kernel_reservation;
mod readback;
mod reservation;
mod wire;
mod workload;
pub(super) use execution_parents::{bind_for_start, prepare_for_start, ExecutionParents, ExecutionPending};
pub(super) use creation_reservation::ExecutionCreationPermit;
pub(super) use native_execution::{NetworkReady, PreparedNetwork};
pub(super) use attachment_backend::{HostRetirement, HostVethAbsence};
// Reuse actual host observation, not the CA authorization or journal.
#[path = "../install/host.rs"]
mod host;

use super::{config, ensure, native_verifier, originals::{ArtifactV1, HeldOriginal},
    transport::Connection, OriginalClock};
use serde::{Deserialize, Serialize};
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Inputs {
    authority: ArtifactV1,
    authority_root: ArtifactV1,
    capability_token: ArtifactV1,
    launch_manifest: ArtifactV1,
}

impl Inputs {
    pub(super) fn validate(&self) -> Result<(), String> {
        for pin in [&self.authority, &self.authority_root, &self.capability_token, &self.launch_manifest] {
            config::artifact(pin)?;
        }
        Ok(())
    }
}

pub(super) struct Pending {
    authorization: authority::Authorization,
    launch: workload::LaunchSpec,
    token: HeldOriginal,
    token_sha256: [u8; 32],
}

/// Retains genuine precreation admission and originals. It never owns a child
/// or permit, so journal checks cannot recurse through a lifecycle owner.
pub(super) struct PrecreationOwner {
    clock: Arc<OriginalClock>,
    connection: Connection,
    proof: RefCell<native_verifier::BootstrapInstallationOriginals>,
    host: RefCell<host::HostOwner>,
    launch: RefCell<workload::LaunchSpec>,
    originals: RefCell<Vec<HeldOriginal>>,
    client_private: RefCell<HeldOriginal>,
    token: RefCell<HeldOriginal>,
    authorization: authority::Authorization,
    creation_scope_sha256: [u8; 32],
    token_sha256: [u8; 32],
    stopped: Cell<bool>,
}

impl PrecreationOwner {
    pub(super) fn creation_spec(&self) -> Result<creation_reservation::Spec, String> {
        self.check()?;
        let journal = self.authorization.creation_journal.as_ref()
            .ok_or("native egress durable creation authority is absent")?;
        Ok(creation_reservation::Spec {
            journal_path: PathBuf::from(&journal.path), journal_device: journal.device,
            journal_inode: journal.inode, journal_namespace: journal.namespace.clone(),
            capability_id: self.authorization.capability.capability_id.clone(),
            scope_sha256: self.creation_scope_sha256,
        })
    }

    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "native egress precreation owner is stopped")?;
        self.clock.check()?;
        self.connection.check_egress_originals(&mut self.proof.try_borrow_mut()
            .map_err(|_| "native egress proof already borrowed")?, &self.clock)?;
        self.host.try_borrow_mut().map_err(|_| "native egress host already borrowed")?
            .check(&self.clock)?;
        self.launch.try_borrow_mut().map_err(|_| "native egress launch original already borrowed")?
            .check(&self.clock)?;
        for original in self.originals.try_borrow_mut()
            .map_err(|_| "native egress originals already borrowed")?.iter_mut() {
            self.clock.check()?;
            original.recheck()?;
        }
        for cell in [&self.client_private, &self.token] {
            let mut original = cell.try_borrow_mut().map_err(|_| "native egress private owner already borrowed")?;
            original.require_private()?;
            self.clock.check()?;
            original.recheck()?;
            original.require_private()?;
        }
        self.host.try_borrow_mut().map_err(|_| "native egress host already borrowed")?
            .check(&self.clock)?;
        self.launch.try_borrow_mut().map_err(|_| "native egress launch original already borrowed")?
            .check(&self.clock)?;
        self.connection.check()?;
        self.clock.check()?;
        self.stopped.set(false);
        Ok(())
    }
}

/// The kernel journal accepts this concrete owner, never a validity callback,
/// parsed success DTO, supplied pidfd or caller-owned namespace.
pub(super) struct EgressGuard {
    // The child (and its cleanup) drops before the shared precreation owner.
    workload: RefCell<workload::WorkloadOwner>,
    precreation: Arc<PrecreationOwner>,
    reservation_id: [u8; 32],
    association_sha256: [u8; 32],
    token_sha256: [u8; 32],
    stopped: Cell<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreationObservation {
    creation_slot_sha256: String,
    creation_record_sha256: String,
    authorization_sha256: String,
    workload: workload::WorkloadIdentity,
}

impl EgressGuard {
    pub(super) fn install(&self) -> Result<effect::Installed<'_>, String> { effect::install(self) }

    pub(super) fn deadline(&self) -> Result<Instant, String> {
        self.check()?;
        self.precreation.clock.instant_deadline()
    }

    pub(super) fn duplicate_backend(&self) -> Result<File, String> {
        self.check()?;
        let duplicate = self.workload.try_borrow_mut()
            .map_err(|_| "native egress workload already borrowed")?
            .duplicate_backend(&self.precreation.clock)?;
        self.check()?;
        Ok(duplicate)
    }

    pub(super) fn duplicate_attachment(&self) -> Result<workload::AttachmentDescriptors, String> {
        self.check()?;
        let descriptors = self.workload.try_borrow_mut()
            .map_err(|_| "native egress workload already borrowed")?
            .duplicate_attachment(&self.precreation.clock)?;
        self.check()?;
        Ok(descriptors)
    }

    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "native egress owner is stopped")?;
        self.precreation.check()?;
        self.workload.try_borrow_mut().map_err(|_| "native egress workload already borrowed")?
            .check(&self.precreation.clock)?;
        self.precreation.check()?;
        self.stopped.set(false);
        Ok(())
    }

    /// Data observed under this live owner, not an execution or persistence
    /// receipt. The child is terminated when the actual owner is torn down.
    pub(super) fn observation(&self) -> Result<CreationObservation, String> {
        self.check()?;
        let result = {
            let child = self.workload.try_borrow().map_err(|_| "native egress workload already borrowed")?;
            CreationObservation {
                creation_slot_sha256: digest_text(&child.creation_slot_sha256()),
                creation_record_sha256: digest_text(&child.creation_record_sha256()),
                authorization_sha256: digest_text(&self.precreation.authorization.original_sha256),
                workload: child.identity().clone(),
            }
        };
        self.check()?;
        Ok(result)
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }
fn digest_text(bytes: &[u8; 32]) -> String {
    format!("sha256:{}", bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
}

/// Cold admission under the original invocation clock; this creates no child
/// and grants no action merely by returning. No independent proof is skipped.
pub(super) fn prepare(inputs: Inputs, clock: &OriginalClock,
    originals: &mut Vec<HeldOriginal>) -> Result<Pending, String> {
    prepare_profile(inputs, None, clock, originals)
}

pub(super) fn prepare_for_attachment(inputs: Inputs, attachment: &attachment::Pending,
    clock: &OriginalClock, originals: &mut Vec<HeldOriginal>) -> Result<Pending, String> {
    prepare_profile(inputs, Some(attachment), clock, originals)
}

fn prepare_profile(inputs: Inputs, attachment: Option<&attachment::Pending>, clock: &OriginalClock,
    originals: &mut Vec<HeldOriginal>) -> Result<Pending, String> {
    inputs.validate()?;
    clock.check()?;
    ensure(unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
        && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0,
        "native egress requires the explicit privileged launcher")?;
    originals.first().ok_or("native egress cold configuration absent")?.require_private()?;
    let root_pin = inputs.authority_root.sha256.clone();
    let root = super::read(inputs.authority_root, 16 * 1024, clock, originals)?;
    let raw = super::read(inputs.authority, 32 * 1024, clock, originals)?;
    let authorization = authority::admit(&raw, &root, &root_pin,
        crate::authority_source_revision_v1::SOURCE_REVISION, clock)?;
    ensure(!authorization.execution_profile,
        "native execution egress requires the separate cold-selected start admission")?;
    ensure(authorization.creation_journal.is_some(),
        "native egress requires versioned durable precreation authority")?;
    match attachment {
        Some(pending) => pending.require_egress(&authorization, clock)?,
        None => ensure(authorization.child_network_policy.is_none(),
            "native egress v3 network policy requires the explicit attachment client profile")?,
    }
    let (mut token, secret) = HeldOriginal::read_private(inputs.capability_token, 256)?;
    clock.check()?;
    ensure((32..=256).contains(&secret.len()) && secret.iter().all(|byte|
        byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-')),
        "native egress token shape differs")?;
    let token_sha256 = digest(&secret);
    ensure(digest_text(&token_sha256) == authorization.capability.capability_token_sha256,
        "native egress protected token differs from authorization")?;
    drop(secret);
    token.recheck()?;
    token.require_private()?;
    let launch = workload::admit(&authorization, &inputs.launch_manifest, clock)?;
    clock.check()?;
    Ok(Pending { authorization, launch, token, token_sha256 })
}

/// The genuine same-TLS proof and original inputs are consumed into this owner.
/// Namespace creation requires its own durable claim before clone3. A later,
/// distinct kernel claim still precedes the sole firewall mutation.
pub(super) fn bind(pending: Pending, proof: native_verifier::BootstrapInstallationOriginals,
    connection: Connection, clock: Arc<OriginalClock>, originals: Vec<HeldOriginal>,
    client_private: HeldOriginal, configuration_raw: &[u8]) -> Result<EgressGuard, String> {
    clock.check()?;
    ensure(!pending.authorization.execution_profile,
        "native execution egress cannot enter the legacy child-creation path")?;
    let grant = pending.authorization;
    let mut token = pending.token;
    let bound = bind_originals(&grant, proof, connection, clock, originals, client_private,
        &mut token, configuration_raw)?;
    let commitments = bound.commitments;
    let mut creation_scope = Sha256::new();
    creation_scope.update(b"serverware/native-egress-creation-operation/v1\0");
    for commitment in commitments { creation_scope.update(commitment); }
    let precreation = Arc::new(PrecreationOwner { clock: bound.clock, connection: bound.connection,
        proof: RefCell::new(bound.proof), host: RefCell::new(bound.host), launch: RefCell::new(pending.launch),
        originals: RefCell::new(bound.originals), client_private: RefCell::new(bound.client_private),
        token: RefCell::new(token), authorization: grant,
        creation_scope_sha256: creation_scope.finalize().into(), token_sha256: pending.token_sha256,
        stopped: Cell::new(false) });
    precreation.check()?;
    let permit = creation_reservation::claim(Arc::clone(&precreation))?;
    // An existing or uncertain creation record never yields a permit. No
    // application is executed; cleanup covers only this task-created child.
    let mut child = workload::WorkloadOwner::create(Arc::clone(&precreation), permit, &precreation.clock)?;
    child.check(&precreation.clock)?;
    let grant = &precreation.authorization;
    ensure((child.identity().namespace_device, child.identity().namespace_inode)
        != (grant.network_owner.namespace_device, grant.network_owner.namespace_inode),
        "native egress child namespace is not newly separate from the launcher")?;
    let child_original = canonical_ascii_bytes(&child.identity())?;
    let mut slot = Sha256::new();
    slot.update(b"serverware/native-egress-installation-slot/v1\0");
    for scalar in [grant.journal.namespace.as_bytes(), grant.capability.capability_id.as_bytes()] {
        slot.update((scalar.len() as u64).to_be_bytes()); slot.update(scalar);
    }
    let reservation_id = slot.finalize().into();
    let mut association = Sha256::new();
    association.update(b"serverware/native-egress-installation-operation/v1\0");
    for commitment in commitments { association.update(commitment); }
    association.update(digest(&child_original));
    let association_sha256 = association.finalize().into();
    let token_sha256 = precreation.token_sha256;
    let result = EgressGuard { workload: RefCell::new(child), precreation,
        reservation_id, association_sha256, token_sha256, stopped: Cell::new(false) };
    result.check()?;
    // The creation claim is retained by the child. No kernel claim or completion
    // is manufactured here: actual wire intent/readback still belong downstream.
    Ok(result)
}

/// Original-only common join. It cannot create a child, permission or network
/// effect; both distinct source-selected owners retain these actual objects.
struct BindingOriginals {
    clock: Arc<OriginalClock>,
    connection: Connection,
    proof: native_verifier::BootstrapInstallationOriginals,
    host: host::HostOwner,
    originals: Vec<HeldOriginal>,
    client_private: HeldOriginal,
    commitments: [[u8; 32]; 7],
}

fn bind_originals(grant: &authority::Authorization,
    mut proof: native_verifier::BootstrapInstallationOriginals, connection: Connection,
    clock: Arc<OriginalClock>, mut originals: Vec<HeldOriginal>, mut client_private: HeldOriginal,
    token: &mut HeldOriginal, configuration_raw: &[u8]) -> Result<BindingOriginals, String> {
    clock.check()?;
    connection.check_egress_originals(&mut proof, &clock)?;
    ensure(!configuration_raw.is_empty() && configuration_raw.len() <= config::MAX_CONFIGURATION_BYTES,
        "native egress original configuration exceeds bound")?;
    ensure(grant.creation_journal.is_some(), "native egress durable creation authority is absent")?;
    let setup = proof.setup();
    let delegation = proof.delegation();
    ensure(proof.setup_sha256() == grant.setup_sha256
        && proof.delegation_sha256() == grant.delegation_sha256
        && setup.target_request_sha256 == grant.target_request_sha256
        && setup.policy_requirements_sha256 == grant.policy_requirements_sha256
        && setup.release_record_sha256 == grant.release_record_sha256
        && setup.policy_hash == grant.policy_hash && setup.configuration_sha256 == grant.configuration_sha256
        && setup.runtime_ca_certificate_sha256 == grant.runtime_ca_certificate_sha256
        && setup.runtime_ca_spki_sha256 == grant.runtime_ca_spki_sha256
        && setup.target_principal_id == grant.target_principal_id && setup.target_nonce == grant.target_nonce
        && delegation.target_spki_sha256 == grant.target_spki_sha256
        && delegation.ingress_leaf_certificate_sha256 == grant.ingress_leaf_certificate_sha256
        && delegation.client_trust_bundle_sha256 == grant.client_trust_bundle_sha256
        && digest(&delegation.client_challenge) == grant.client_challenge_sha256,
        "native egress grant differs from genuinely admitted original runtime scope")?;
    ensure(canonical_ascii_bytes(&setup.proxy)? == canonical_ascii_bytes(&grant.proxy)?
        && canonical_ascii_bytes(&setup.network_owner)? == canonical_ascii_bytes(&grant.network_owner)?
        && setup.kubernetes.is_none(),
        "native egress destinations or launcher host association differ")?;
    ensure(grant.capability.capability_id != setup.ca_install.capability_id
        && grant.capability.capability_token_sha256 != setup.ca_install.capability_token_sha256,
        "native egress cannot reuse CA capability or protected token")?;
    ensure([setup.authorizer_key_id, delegation.authorizer_key_id,
        delegation.runtime_ca_spki_sha256, delegation.caller_issuer_spki_sha256,
        delegation.caller_spki_sha256, delegation.target_issuer_spki_sha256,
        delegation.target_spki_sha256].iter().all(|key| key != &grant.root_key_id),
        "native egress authorizer shares a parent, runtime or workload key role")?;
    let before = setup.not_before_unix_seconds.checked_mul(super::SECOND)
        .ok_or("native egress setup time overflow")?;
    let until = setup.expires_at_unix_seconds.checked_mul(super::SECOND)
        .ok_or("native egress setup time overflow")?;
    ensure(grant.issued_at_epoch_ns >= before && grant.expires_at_epoch_ns <= until,
        "native egress grant exceeds genuine parent interval")?;
    clock.restrict_until_epoch_ns(grant.expires_at_epoch_ns)?;
    let ca_sha256 = digest(connection.admitted_ca_original()?);
    ensure(ca_sha256 == grant.runtime_ca_certificate_sha256,
        "native egress CA differs from actual held TLS original")?;
    let mut observed = host::HostOwner::open(&host::Spec {
        host_id: grant.network_owner.host_id.clone(), machine_id_sha256: digest_text(&grant.machine_id_sha256),
        boot_id: grant.network_owner.boot_id.clone(), namespace_device: grant.network_owner.namespace_device,
        namespace_inode: grant.network_owner.namespace_inode, owner_uid: grant.network_owner.owner_uid,
    }, &clock)?;
    super::recheck(&mut originals, &mut client_private, &clock)?;
    token.require_private()?;
    token.recheck()?;
    token.require_private()?;
    connection.check_egress_originals(&mut proof, &clock)?;
    observed.check(&clock)?;
    let commitments = [grant.original_sha256, proof.setup_sha256(), proof.delegation_sha256(),
        proof.evidence_sha256(), proof.packet_sha256(), digest(configuration_raw), ca_sha256];
    clock.check()?;
    Ok(BindingOriginals { clock, connection, proof, host: observed, originals,
        client_private, commitments })
}

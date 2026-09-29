//! Separate grant, genuine proof, host and never-executed workload ownership.
//!
//! This is an internal foundation, not a callable installer. No public config
//! selects it before the fixed kernel transaction/readback and exact-byte
//! custody are integrated. It exposes no workload start or generic effect API.

mod authority;
mod reservation;
mod workload;
// Reuse actual host observation, not the CA authorization or journal.
#[path = "../install/host.rs"]
mod host;

use super::{config, ensure, native_verifier, originals::{ArtifactV1, HeldOriginal},
    transport::Connection, OriginalClock};
use serde::Deserialize;
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::sync::Arc;

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

/// The journal accepts this concrete owner, never a validity callback, parsed
/// success DTO, supplied pidfd or caller-owned namespace. Failure is sticky.
pub(super) struct EgressGuard {
    clock: Arc<OriginalClock>,
    connection: Connection,
    proof: RefCell<native_verifier::BootstrapInstallationOriginals>,
    host: RefCell<host::HostOwner>,
    workload: RefCell<workload::WorkloadOwner>,
    originals: RefCell<Vec<HeldOriginal>>,
    client_private: RefCell<HeldOriginal>,
    token: RefCell<HeldOriginal>,
    authorization: authority::Authorization,
    reservation_id: [u8; 32],
    association_sha256: [u8; 32],
    token_sha256: [u8; 32],
    stopped: Cell<bool>,
}

impl EgressGuard {
    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "native egress owner is stopped")?;
        self.clock.check()?;
        self.connection.check_egress_originals(&mut self.proof.try_borrow_mut()
            .map_err(|_| "native egress proof already borrowed")?, &self.clock)?;
        self.host.try_borrow_mut().map_err(|_| "native egress host already borrowed")?
            .check(&self.clock)?;
        self.workload.try_borrow_mut().map_err(|_| "native egress workload already borrowed")?
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
        self.workload.try_borrow_mut().map_err(|_| "native egress workload already borrowed")?
            .check(&self.clock)?;
        self.connection.check()?;
        self.clock.check()?;
        self.stopped.set(false);
        Ok(())
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
/// Namespace creation is separately authorized by this new profile BEFORE any
/// journal claim; only a later durable claim may precede a firewall mutation.
pub(super) fn bind(pending: Pending, mut proof: native_verifier::BootstrapInstallationOriginals,
    connection: Connection, clock: Arc<OriginalClock>, mut originals: Vec<HeldOriginal>,
    mut client_private: HeldOriginal, configuration_raw: &[u8]) -> Result<EgressGuard, String> {
    clock.check()?;
    connection.check_egress_originals(&mut proof, &clock)?;
    ensure(!configuration_raw.is_empty() && configuration_raw.len() <= config::MAX_CONFIGURATION_BYTES,
        "native egress original configuration exceeds bound")?;
    let grant = pending.authorization;
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
    let mut token = pending.token;
    token.require_private()?;
    token.recheck()?;
    token.require_private()?;
    connection.check_egress_originals(&mut proof, &clock)?;
    observed.check(&clock)?;
    // No application is executed; the newly created child is permanently parked
    // behind its fixed trampoline. Only its explicit never-started cleanup applies.
    let mut child = workload::WorkloadOwner::create(pending.launch, &clock)?;
    child.check(&clock)?;
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
    for commitment in [grant.original_sha256, proof.setup_sha256(), proof.delegation_sha256(),
        proof.evidence_sha256(), proof.packet_sha256(), digest(configuration_raw), ca_sha256,
        digest(&child_original)] { association.update(commitment); }
    let association_sha256 = association.finalize().into();
    let result = EgressGuard { clock, connection, proof: RefCell::new(proof), host: RefCell::new(observed),
        workload: RefCell::new(child), originals: RefCell::new(originals),
        client_private: RefCell::new(client_private), token: RefCell::new(token), authorization: grant,
        reservation_id, association_sha256, token_sha256: pending.token_sha256, stopped: Cell::new(false) };
    result.check()?;
    // No claim or completion is manufactured here. The backend must first
    // retain its exact intended wire transaction and later actual readback.
    Ok(result)
}

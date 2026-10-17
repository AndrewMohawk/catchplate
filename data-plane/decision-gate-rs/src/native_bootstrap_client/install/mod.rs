//! Explicit root-authorized host installation after actual native verification.
//!
//! Setup/evidence diagnostics are not permission. This owner composes the
//! independent host grant, original TLS/verifier children, actual local host,
//! protected token and irreversible journal before any destination mutation.

mod authority;
mod destination;
mod host;
mod reservation;
mod execution;
mod observation;

pub(super) use execution::{bind_for_execution, InstalledCa, PreparedInstallation};
pub(super) use observation::{Inputs as ObservationInputs, Prepared as Observation};

use super::{config, ensure, native_verifier, originals::{ArtifactV1, HeldOriginal},
    transport::Connection, OriginalClock};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Inputs {
    authority: ArtifactV1,
    authority_root: ArtifactV1,
    capability_token: ArtifactV1,
}

impl Inputs {
    pub(super) fn validate(&self) -> Result<(), String> {
        for pin in [&self.authority, &self.authority_root, &self.capability_token] {
            config::artifact(pin)?;
        }
        Ok(())
    }
}

pub(super) struct Pending {
    authorization: authority::Authorization,
    token: HeldOriginal,
    token_sha256: [u8; 32],
}

/// Concrete non-Clone owner shared by all protected side-effect primitives.
/// Interior borrowing only composes the same original owners; it cannot admit
/// a supplied callback/verdict or create another clock allowance.
pub(super) struct InstallGuard {
    clock: Arc<OriginalClock>,
    parent: ParentOriginals,
    host: RefCell<host::HostOwner>,
    token: RefCell<HeldOriginal>,
    stopped: Cell<bool>,
}

enum ParentOriginals {
    Standalone {
        connection: Connection,
        proof: RefCell<native_verifier::BootstrapInstallationOriginals>,
        originals: RefCell<Vec<HeldOriginal>>,
        client_private: RefCell<HeldOriginal>,
    },
    Execution(Arc<super::egress::ExecutionParents>),
}

impl InstallGuard {
    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "native installation owner is stopped")?;
        self.clock.check()?;
        match &self.parent {
            ParentOriginals::Standalone { connection, proof, originals, client_private } => {
                connection.check()?;
                proof.try_borrow_mut().map_err(|_| "native installation proof is already borrowed")?
                    .check(self.clock.boottime_deadline()?)?;
                self.host.try_borrow_mut().map_err(|_| "native installation host is already borrowed")?
                    .check(&self.clock)?;
                let mut originals = originals.try_borrow_mut()
                    .map_err(|_| "native installation originals are already borrowed")?;
                for original in originals.iter_mut() {
                    self.clock.check()?;
                    original.recheck()?;
                }
                let mut private = client_private.try_borrow_mut()
                    .map_err(|_| "native installation private original is already borrowed")?;
                private.require_private()?;
                self.clock.check()?;
                private.recheck()?;
                private.require_private()?;
                connection.check()?;
            },
            ParentOriginals::Execution(parents) => parents.check()?,
        }
        {
            let mut token = self.token.try_borrow_mut()
                .map_err(|_| "native installation token is already borrowed")?;
            token.require_private()?;
            self.clock.check()?;
            token.recheck()?;
            token.require_private()?;
        }
        self.host.try_borrow_mut().map_err(|_| "native installation host is already borrowed")?
            .check(&self.clock)?;
        match &self.parent {
            ParentOriginals::Standalone { connection, .. } => connection.check()?,
            ParentOriginals::Execution(parents) => parents.check()?,
        }
        self.clock.check()?;
        self.stopped.set(false);
        Ok(())
    }
}

fn digest(raw: &[u8]) -> [u8; 32] { Sha256::digest(raw).into() }
fn digest_text(raw: &[u8; 32]) -> String {
    format!("sha256:{}", raw.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
}

/// Called only after genuine startup admission, before network contact. The
/// secret token is read once into zeroizing storage and never returned/logged.
pub(super) fn prepare(inputs: Inputs, clock: &OriginalClock,
    held: &mut Vec<HeldOriginal>) -> Result<Pending, String> {
    clock.check()?;
    ensure(unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
        && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0,
        "native installation requires the explicit privileged host launcher")?;
    // The installation configuration itself is an independently pinned,
    // root-private launch original, not a mutable request-selected option.
    held.first().ok_or("native installation configuration owner is absent")?.require_private()?;
    let root_pin = inputs.authority_root.sha256.clone();
    let root = super::read(inputs.authority_root, 16 * 1024, clock, held)?;
    let raw = super::read(inputs.authority, 32 * 1024, clock, held)?;
    let authorization = authority::admit(&raw, &root, &root_pin,
        crate::authority_source_revision_v1::SOURCE_REVISION, clock)?;
    clock.check()?;
    let (mut token, secret) = HeldOriginal::read_private(inputs.capability_token, 256)?;
    clock.check()?;
    ensure((32..=256).contains(&secret.len()) && secret.iter().all(|byte|
        byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-')),
        "native installation token shape differs")?;
    let token_sha256 = digest(&secret);
    ensure(digest_text(&token_sha256) == authorization.ca_install.capability_token_sha256,
        "native installation protected token differs from host authorization")?;
    drop(secret);
    token.recheck()?;
    token.require_private()?;
    clock.check()?;
    Ok(Pending { authorization, token, token_sha256 })
}

pub(super) fn execute(pending: Pending, mut proof: native_verifier::BootstrapInstallationOriginals,
    connection: Connection, clock: Arc<OriginalClock>, originals: Vec<HeldOriginal>,
    client_private: HeldOriginal, configuration_raw: &[u8], mut capture: serde_json::Value,
    mut observation: Option<Observation>)
    -> Result<(), String> {
    clock.check()?;
    connection.check()?;
    proof.check(clock.boottime_deadline()?)?;
    // Reserve output space before an irreversible claim. This internal capture
    // is output-only and is never consulted for authority or installation facts.
    let capture_bytes = serde_json::to_vec(&capture).map_err(|_| "encode native installation capture")?;
    let output_reserve = 8192 + if observation.is_some() { 32768 } else { 0 };
    ensure(capture_bytes.len() < super::MAX_CAPTURE_BYTES - output_reserve,
        "native installation capture exceeds its reserved output bound")?;
    let installation_output = capture.get_mut("installation")
        .ok_or("native installation capture output field is absent")?;
    let grant = pending.authorization;
    if let Some(owner) = observation.as_mut() { owner.bind(&mut proof, &grant)?; }
    let setup = proof.setup();
    ensure(proof.setup_sha256() == grant.setup_sha256
        && proof.delegation_sha256() == grant.delegation_sha256
        && setup.target_request_sha256 == grant.target_request_sha256
        && setup.runtime_ca_certificate_sha256 == grant.runtime_ca_certificate_sha256
        && setup.runtime_ca_spki_sha256 == grant.runtime_ca_spki_sha256,
        "native installation host grant differs from genuinely admitted setup/runtime")?;
    ensure(serde_json::to_value(&setup.ca_install).map_err(|_| "encode genuine installation association")?
            == serde_json::to_value(&grant.ca_install).map_err(|_| "encode host installation association")?
        && serde_json::to_value(&setup.network_owner).map_err(|_| "encode genuine network association")?
            == serde_json::to_value(&grant.network_owner).map_err(|_| "encode host network association")?,
        "native installation capability/destination/host association differs")?;
    ensure(setup.kubernetes.is_none(),
        "native host installation cannot establish Kubernetes ownership")?;
    let setup_before = setup.not_before_unix_seconds.checked_mul(super::SECOND)
        .ok_or("native installation setup interval overflow")?;
    let setup_until = setup.expires_at_unix_seconds.checked_mul(super::SECOND)
        .ok_or("native installation setup interval overflow")?;
    ensure(grant.issued_at_epoch_ns >= setup_before && grant.expires_at_epoch_ns <= setup_until,
        "native installation host grant exceeds the genuine setup interval")?;
    ensure(grant.root_key_id != setup.authorizer_key_id
        && grant.root_key_id != proof.delegation_authorizer()
        && grant.root_key_id != grant.runtime_ca_spki_sha256,
        "native installation authorizer roles are not independent")?;
    let ca_der = connection.admitted_ca_original()?.to_vec();
    ensure(digest(&ca_der) == grant.runtime_ca_certificate_sha256,
        "native installation CA is not the actual admitted TLS/runtime original")?;
    let observed = host::HostOwner::open(&host::Spec {
        host_id: grant.network_owner.host_id.clone(),
        machine_id_sha256: digest_text(&grant.machine_id_sha256),
        boot_id: grant.network_owner.boot_id.clone(),
        namespace_device: grant.network_owner.namespace_device,
        namespace_inode: grant.network_owner.namespace_inode,
        owner_uid: grant.network_owner.owner_uid,
    }, &clock)?;
    let mut slot = Sha256::new();
    slot.update(b"catchplate/native-ca-installation-slot/v1\0");
    for scalar in [grant.journal.namespace.as_bytes(), grant.ca_install.capability_id.as_bytes()] {
        slot.update((scalar.len() as u64).to_be_bytes());
        slot.update(scalar);
    }
    let reservation_id: [u8; 32] = slot.finalize().into();
    let mut association = Sha256::new();
    association.update(b"catchplate/native-ca-installation-operation/v1\0");
    for commitment in [grant.original_sha256, proof.setup_sha256(), proof.evidence_sha256(),
        proof.packet_sha256(), digest(configuration_raw), digest(&ca_der)] { association.update(commitment); }
    let association_sha256: [u8; 32] = association.finalize().into();
    let guard = Arc::new(InstallGuard { clock,
        parent: ParentOriginals::Standalone { connection, proof: RefCell::new(proof),
            originals: RefCell::new(originals), client_private: RefCell::new(client_private) },
        host: RefCell::new(observed), token: RefCell::new(pending.token), stopped: Cell::new(false) });
    guard.check()?;
    let mut reservation = reservation::reserve(reservation::Spec {
        journal_path: PathBuf::from(&grant.journal.path), journal_device: grant.journal.device,
        journal_inode: grant.journal.inode, reservation_id, association_sha256,
        token_sha256: pending.token_sha256,
    }, Arc::clone(&guard))?;
    let destination_spec = destination::Spec {
        destination: grant.ca_install.destination_path.clone(), uid: grant.ca_install.owner_uid,
        gid: grant.ca_install.owner_gid, mode: grant.ca_install.file_mode,
        replace_existing: grant.ca_install.replace_existing,
        expected_existing_certificate_sha256: grant.ca_install.expected_existing_certificate_sha256
            .as_deref().map(parse_digest).transpose()?,
    };
    let mut destination = destination::Destination::prepare(&destination_spec, Arc::clone(&guard))?;
    let status = match reservation.claim()? {
        reservation::ClaimState::Fresh => {
            destination.install(&ca_der, grant.runtime_ca_certificate_sha256)?;
            destination.check()?;
            ensure(destination.installed_certificate_der_sha256()? == Some(grant.runtime_ca_certificate_sha256),
                "native installation final CA readback differs")?;
            reservation.check()?;
            guard.check()?;
            reservation = reservation.complete_retained()?;
            "installed"
        }
        reservation::ClaimState::AlreadyComplete => {
            ensure(destination.installed_certificate_der_sha256()? == Some(grant.runtime_ca_certificate_sha256),
                "native installation completed record differs from actual destination")?;
            reservation.check()?;
            "already-complete"
        }
    };
    destination.check()?;
    guard.check()?;
    let result = json!({"apiVersion":"catchplate.nativeCaInstallationReceipt/v1",
        "resultScope":"local-authorized-native-ca-installation-only", "okForAction":false,
        "status":status, "authorizationSha256":digest_text(&grant.original_sha256),
        "operationSha256":digest_text(&association_sha256), "reservationSha256":digest_text(&reservation_id),
        "setupSha256":digest_text(&grant.setup_sha256), "capabilityId":&grant.ca_install.capability_id,
        "runtimeCaCertificateSha256":digest_text(&grant.runtime_ca_certificate_sha256),
        "destinationPath":destination_spec.destination});
    let receipt = serde_json::to_vec(&result).map_err(|_| "encode native installation local receipt")?;
    ensure(receipt.len() < 8192 && !receipt.contains(&b'\n') && !receipt.contains(&b'\r'),
        "native installation local receipt exceeds its bound")?;
    *installation_output = result;
    if let Some(owner) = observation.as_mut() {
        let original = owner.finish(&grant, &guard, &mut destination, &reservation, &association_sha256, &reservation_id)?;
        capture["setupInstallationObservationOriginal"] = serde_json::Value::String(original);
    }
    let mut output = serde_json::to_vec(&capture).map_err(|_| "encode native installation capture")?;
    ensure(output.len() < super::MAX_CAPTURE_BYTES
        && !output.contains(&b'\n') && !output.contains(&b'\r'),
        "native installation capture exceeds its single-line bound")?;
    output.push(b'\n');
    guard.check()?;
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    for chunk in output.chunks(16 * 1024) {
        if let Some(owner) = observation.as_mut() { owner.check()?; }
        destination.check()?;
        guard.check()?;
        stdout.write_all(chunk).map_err(|_| "write native installation capture")?;
        guard.check()?;
    }
    stdout.flush().map_err(|_| "flush native installation capture")?;
    if let Some(owner) = observation.as_mut() { owner.check()?; }
    destination.check()?;
    guard.check()
}

fn parse_digest(value: &str) -> Result<[u8; 32], String> {
    ensure(super::super::is_sha256_digest(value), "native installation digest differs")?;
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes()[7..].chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| "native installation digest text differs")?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| "native installation digest hex differs")?;
    }
    Ok(bytes)
}

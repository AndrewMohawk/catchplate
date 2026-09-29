//! Separate CA authority composed with the actual executable-parent owner.
//! No receipt, copied verdict or in-image file supplies installation permission.

use super::{authority, destination, digest, digest_text, ensure, host, parse_digest,
    reservation, InstallGuard, ParentOriginals, Pending};
use super::super::{egress::ExecutionParents, execution::start_authority, OriginalClock};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(in super::super) struct PreparedInstallation {
    guard: Arc<InstallGuard>,
    grant: authority::Authorization,
    ca_der: Vec<u8>,
    association: [u8; 32],
    slot: [u8; 32],
    token_sha256: [u8; 32],
}

/// Actual completed effect and retained destination/journal originals. This is
/// non-Clone; only its Arc ownership can be shared inside the same local attempt.
pub(in super::super) struct InstalledCa {
    prepared: PreparedInstallation,
    destination: RefCell<destination::Destination>,
    reservation: reservation::Reservation,
    receipt: Value,
}

fn distinct_journal(grant: &authority::Authorization, path: &str, device: u64,
    inode: u64, namespace: &str) -> Result<(), String>
{
    ensure(!Path::new(&grant.journal.path).starts_with(path)
        && !Path::new(path).starts_with(&grant.journal.path)
        && (grant.journal.device, grant.journal.inode) != (device, inode)
        && grant.journal.namespace != namespace,
        "native CA journal overlaps another protected authority journal")
}

pub(in super::super) fn bind_for_execution(pending: Pending, parents: Arc<ExecutionParents>,
    configuration_raw: &[u8]) -> Result<PreparedInstallation, String>
{
    parents.check()?;
    let clock = parents.retain_original_clock();
    let grant = pending.authorization;
    let mut association = Sha256::new();
    association.update(b"serverware/native-ca-installation-operation/v1\0");
    let ca_der = parents.installation_ca_original()?.to_vec();
    {
        let proof = parents.installation_proof()?;
        let setup = proof.setup();
        ensure(proof.setup_sha256() == grant.setup_sha256
            && proof.delegation_sha256() == grant.delegation_sha256
            && setup.target_request_sha256 == grant.target_request_sha256
            && setup.runtime_ca_certificate_sha256 == grant.runtime_ca_certificate_sha256
            && setup.runtime_ca_spki_sha256 == grant.runtime_ca_spki_sha256,
            "combined CA grant differs from the actual admitted TLS/setup originals")?;
        ensure(serde_json::to_value(&setup.ca_install).map_err(|_| "encode actual CA association")?
                == serde_json::to_value(&grant.ca_install).map_err(|_| "encode signed CA association")?
            && serde_json::to_value(&setup.network_owner).map_err(|_| "encode actual CA host")?
                == serde_json::to_value(&grant.network_owner).map_err(|_| "encode signed CA host")?
            && setup.kubernetes.is_none(), "combined CA setup destination or host association differs")?;
        let before = setup.not_before_unix_seconds.checked_mul(super::super::SECOND)
            .ok_or("combined CA setup interval overflow")?;
        let until = setup.expires_at_unix_seconds.checked_mul(super::super::SECOND)
            .ok_or("combined CA setup interval overflow")?;
        ensure(grant.issued_at_epoch_ns >= before && grant.expires_at_epoch_ns <= until,
            "combined CA grant exceeds the genuine setup interval")?;
        let delegation = proof.delegation();
        ensure([setup.authorizer_key_id, delegation.authorizer_key_id,
            delegation.runtime_ca_spki_sha256, delegation.caller_issuer_spki_sha256,
            delegation.caller_spki_sha256, delegation.target_issuer_spki_sha256,
            delegation.target_spki_sha256].iter().all(|key| key != &grant.root_key_id),
            "combined CA authorizer reuses an actual parent or workload key")?;
        for commitment in [grant.original_sha256, proof.setup_sha256(), proof.evidence_sha256(),
            proof.packet_sha256(), digest(configuration_raw), digest(&ca_der)] {
            association.update(commitment);
        }
    }
    ensure(digest(&ca_der) == grant.runtime_ca_certificate_sha256,
        "combined CA is not the actual admitted TLS certificate")?;
    let observed = host::HostOwner::open(&host::Spec {
        host_id: grant.network_owner.host_id.clone(), machine_id_sha256: digest_text(&grant.machine_id_sha256),
        boot_id: grant.network_owner.boot_id.clone(), namespace_device: grant.network_owner.namespace_device,
        namespace_inode: grant.network_owner.namespace_inode, owner_uid: grant.network_owner.owner_uid,
    }, &clock)?;
    let mut slot = Sha256::new();
    slot.update(b"serverware/native-ca-installation-slot/v1\0");
    for scalar in [grant.journal.namespace.as_bytes(), grant.ca_install.capability_id.as_bytes()] {
        slot.update((scalar.len() as u64).to_be_bytes()); slot.update(scalar);
    }
    let result = PreparedInstallation {
        guard: Arc::new(InstallGuard { clock, parent: ParentOriginals::Execution(parents),
            host: RefCell::new(observed), token: RefCell::new(pending.token), stopped: Cell::new(false) }),
        grant, ca_der, association: association.finalize().into(), slot: slot.finalize().into(),
        token_sha256: pending.token_sha256,
    };
    result.check()?;
    Ok(result)
}

impl PreparedInstallation {
    fn parents(&self) -> Result<&Arc<ExecutionParents>, String> {
        match &self.guard.parent {
            ParentOriginals::Execution(parents) => Ok(parents),
            _ => Err("standalone CA installation cannot become executable ownership".to_owned()),
        }
    }

    fn check(&self) -> Result<(), String> {
        self.guard.check()?;
        let g = &self.grant;
        self.parents()?.require_ca_separation(g.root_key_id, &g.ca_install.capability_id,
            &g.ca_install.capability_token_sha256, &g.journal.path, g.journal.device,
            g.journal.inode, &g.journal.namespace, &g.ca_install.destination_path)?;
        ensure(!Path::new(&g.ca_install.destination_path).starts_with(&g.journal.path)
            && !Path::new(&g.journal.path).starts_with(&g.ca_install.destination_path),
            "combined CA destination overlaps its own protected journal")?;
        ensure(self.parents()?.installation_ca_original()? == self.ca_der.as_slice()
            && digest(&self.ca_der) == g.runtime_ca_certificate_sha256,
            "retained combined CA original changed")?;
        self.guard.check()
    }

    pub(in super::super) fn require_start(&self, start: &start_authority::Authorization,
        clock: &Arc<OriginalClock>) -> Result<(), String>
    {
        ensure(Arc::ptr_eq(clock, &self.guard.clock), "combined CA admission changed original clock")?;
        self.check()?;
        self.parents()?.require_start(start, clock)?;
        let c = &start.constraints;
        let g = &self.grant;
        ensure(start.root_key_id != g.root_key_id
            && c.capability.capability_id != g.ca_install.capability_id
            && c.capability.capability_token_sha256 != g.ca_install.capability_token_sha256
            && c.issued_at_epoch_ns >= g.issued_at_epoch_ns
            && c.start_before_epoch_ns <= g.expires_at_epoch_ns,
            "native start reuses or outlives independent CA installation authority")?;
        distinct_journal(g, &c.journal.path, c.journal.device, c.journal.inode, &c.journal.namespace)?;
        ensure(!Path::new(&g.ca_install.destination_path).starts_with(&c.journal.path)
            && !Path::new(&c.journal.path).starts_with(&g.ca_install.destination_path)
            && !Path::new(&g.journal.path).starts_with(&c.containment.parent_path)
            && !Path::new(&c.containment.parent_path).starts_with(&g.journal.path)
            && !Path::new(&g.ca_install.destination_path).starts_with(&c.containment.parent_path)
            && !Path::new(&c.containment.parent_path).starts_with(&g.ca_install.destination_path),
            "native CA effect overlaps start containment or its journal")?;
        self.check()
    }

    pub(in super::super) fn actual_ca_original(&self) -> Result<&[u8], String> {
        self.check()?;
        Ok(&self.ca_der)
    }

    pub(in super::super) fn destination_path(&self) -> &str { &self.grant.ca_install.destination_path }

    pub(in super::super) fn install(self) -> Result<Arc<InstalledCa>, String> {
        self.check()?;
        let g = &self.grant;
        let mut reservation = reservation::reserve(reservation::Spec {
            journal_path: PathBuf::from(&g.journal.path), journal_device: g.journal.device,
            journal_inode: g.journal.inode, reservation_id: self.slot, association_sha256: self.association,
            token_sha256: self.token_sha256,
        }, Arc::clone(&self.guard))?;
        let spec = destination::Spec { destination: g.ca_install.destination_path.clone(),
            uid: g.ca_install.owner_uid, gid: g.ca_install.owner_gid, mode: g.ca_install.file_mode,
            replace_existing: g.ca_install.replace_existing,
            expected_existing_certificate_sha256: g.ca_install.expected_existing_certificate_sha256
                .as_deref().map(parse_digest).transpose()?,
        };
        let mut destination = destination::Destination::prepare(&spec, Arc::clone(&self.guard))?;
        let status = match reservation.claim()? {
            reservation::ClaimState::Fresh => {
                destination.install(&self.ca_der, g.runtime_ca_certificate_sha256)?;
                ensure(destination.installed_certificate_der_sha256()? == Some(g.runtime_ca_certificate_sha256),
                    "combined CA actual destination readback differs")?;
                self.check()?;
                reservation = reservation.complete_retained()?;
                "installed"
            },
            reservation::ClaimState::AlreadyComplete => {
                ensure(destination.installed_certificate_der_sha256()? == Some(g.runtime_ca_certificate_sha256),
                    "combined CA historical completion differs from actual destination")?;
                "already-complete"
            },
        };
        let receipt = json!({"apiVersion":"serverware.nativeCaInstallationReceipt/v1",
            "resultScope":"local-authorized-native-ca-installation-only", "okForAction":false,
            "status":status, "authorizationSha256":digest_text(&g.original_sha256),
            "operationSha256":digest_text(&self.association), "reservationSha256":digest_text(&self.slot),
            "setupSha256":digest_text(&g.setup_sha256), "capabilityId":g.ca_install.capability_id,
            "runtimeCaCertificateSha256":digest_text(&g.runtime_ca_certificate_sha256),
            "destinationPath":g.ca_install.destination_path});
        ensure(serde_json::to_vec(&receipt).map_err(|_| "encode combined CA receipt")?.len() < 8192,
            "combined CA receipt exceeds its reserved bound")?;
        let installed = Arc::new(InstalledCa { prepared: self, destination: RefCell::new(destination),
            reservation, receipt });
        installed.check()?;
        Ok(installed)
    }
}

impl InstalledCa {
    pub(in super::super) fn check(&self) -> Result<(), String> {
        self.prepared.check()?;
        self.reservation.check()?;
        ensure(self.destination.try_borrow_mut().map_err(|_| "combined CA destination is already borrowed")?
            .installed_certificate_der_sha256()? == Some(self.prepared.grant.runtime_ca_certificate_sha256),
            "combined CA retained destination changed")?;
        self.prepared.check()
    }

    pub(in super::super) fn require_start(&self, start: &start_authority::Authorization,
        clock: &Arc<OriginalClock>) -> Result<(), String> {
        self.check()?;
        self.prepared.require_start(start, clock)
    }

    pub(in super::super) fn require_parents(&self, parents: &Arc<ExecutionParents>) -> Result<(), String> {
        ensure(Arc::ptr_eq(self.prepared.parents()?, parents), "combined CA changed genuine executable parents")?;
        self.check()
    }

    /// Historical completed-effect data; never rechecks/renews expired authority
    /// and never grants a later launch or retry.
    pub(in super::super) fn receipt(&self) -> &Value { &self.receipt }
}

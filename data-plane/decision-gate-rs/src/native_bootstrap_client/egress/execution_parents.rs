//! Explicit execution-profile parents, retained before any new child/effect.
//!
//! Neither this admission nor its operation digest is execution permission.
//! The independent start owner must join its own signed constraints and claim.

use super::{attachment, authority, bind_originals, creation_reservation, digest, digest_text,
    ensure, host, workload, Inputs};
use super::super::{execution::start_authority, native_verifier,
    originals::HeldOriginal, transport::Connection, OriginalClock};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::sync::Arc;

pub(in super::super) struct ExecutionPending {
    authorization: authority::Authorization,
    launch: workload::ExecutionLaunchSpec,
    attachment: attachment::Pending,
    token: HeldOriginal,
}

/// No child, creation permit, installed ruleset or attachment success is held
/// or fabricated here. All fields originate in actual original admission.
pub(in super::super) struct ExecutionParents {
    clock: Arc<OriginalClock>,
    connection: Connection,
    proof: RefCell<native_verifier::BootstrapInstallationOriginals>,
    host: RefCell<host::HostOwner>,
    launch: RefCell<workload::ExecutionLaunchSpec>,
    originals: RefCell<Vec<HeldOriginal>>,
    client_private: RefCell<HeldOriginal>,
    token: RefCell<HeldOriginal>,
    authorization: authority::Authorization,
    attachment: attachment::Pending,
    operation_sha256: [u8; 32],
    stopped: Cell<bool>,
}

pub(in super::super) fn prepare_for_start(inputs: Inputs, attachment: attachment::Pending,
    clock: &OriginalClock, originals: &mut Vec<HeldOriginal>) -> Result<ExecutionPending, String>
{
    prepare_selected(inputs, attachment, clock, originals, false)
}
pub(in super::super) fn prepare_for_application(inputs: Inputs, attachment: attachment::Pending,
    clock: &OriginalClock, originals: &mut Vec<HeldOriginal>) -> Result<ExecutionPending, String> {
    prepare_selected(inputs, attachment, clock, originals, true)
}
fn prepare_selected(inputs: Inputs, attachment: attachment::Pending,
    clock: &OriginalClock, originals: &mut Vec<HeldOriginal>, application: bool) -> Result<ExecutionPending, String> {
    inputs.validate()?;
    clock.check()?;
    ensure(unsafe { libc::getuid() == 0 && libc::geteuid() == 0
        && libc::getgid() == 0 && libc::getegid() == 0 },
        "native execution parent admission requires the privileged launcher")?;
    originals.first().ok_or("native execution cold configuration absent")?.require_private()?;
    let roles = [&inputs.authority, &inputs.authority_root, &inputs.capability_token, &inputs.launch_manifest];
    for (index, role) in roles.iter().enumerate() {
        ensure(roles[..index].iter().all(|other| role.path != other.path && role.sha256 != other.sha256),
            "native execution egress originals reuse a role")?;
    }
    let root_pin = inputs.authority_root.sha256.clone();
    let root = super::super::read(inputs.authority_root, 16 * 1024, clock, originals)?;
    let raw = super::super::read(inputs.authority, 32 * 1024, clock, originals)?;
    let authorization = authority::admit(&raw, &root, &root_pin,
        crate::authority_source_revision_v1::SOURCE_REVISION, clock)?;
    ensure(authorization.execution_profile && authorization.creation_journal.is_some()
        && authorization.application_proxy_sha256.is_some() == application
        && authorization.child_network_policy == Some(authority::ChildNetworkPolicy::ManualDualStackV1),
        "native execution parents require the explicitly selected egress v4/v5 authorization")?;
    attachment.require_egress(&authorization, clock)?;
    let (mut token, secret) = HeldOriginal::read_private(inputs.capability_token, 256)?;
    clock.check()?;
    ensure((32..=256).contains(&secret.len()) && secret.iter().all(|byte|
        byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-')),
        "native execution egress token shape differs")?;
    ensure(digest_text(&digest(&secret)) == authorization.capability.capability_token_sha256,
        "native execution protected token differs from its signed original")?;
    drop(secret);
    token.require_private()?;
    token.recheck()?;
    token.require_private()?;
    let launch = workload::admit_for_start(&authorization, &inputs.launch_manifest, clock)?;
    attachment.require_egress(&authorization, clock)?;
    clock.check()?;
    Ok(ExecutionPending { authorization, launch, attachment, token })
}

pub(in super::super) fn bind_for_start(pending: ExecutionPending,
    proof: native_verifier::BootstrapInstallationOriginals, connection: Connection,
    clock: Arc<OriginalClock>, originals: Vec<HeldOriginal>, client_private: HeldOriginal,
    configuration_raw: &[u8]) -> Result<Arc<ExecutionParents>, String>
{
    clock.check()?;
    ensure(pending.authorization.execution_profile, "legacy egress cannot become execution parents")?;
    pending.attachment.require_egress(&pending.authorization, &clock)?;
    let mut token = pending.token;
    let bound = bind_originals(&pending.authorization, proof, connection, clock, originals,
        client_private, &mut token, configuration_raw)?;
    let a = pending.attachment.authorization();
    let setup = bound.proof.setup();
    let delegation = bound.proof.delegation();
    ensure(a.capability.capability_id != setup.ca_install.capability_id
        && a.capability.capability_token_sha256 != setup.ca_install.capability_token_sha256
        && [setup.authorizer_key_id, delegation.authorizer_key_id,
            delegation.runtime_ca_spki_sha256, delegation.caller_issuer_spki_sha256,
            delegation.caller_spki_sha256, delegation.target_issuer_spki_sha256,
            delegation.target_spki_sha256].iter().all(|key| key != &a.root_key_id),
        "native execution attachment reuses a parent key or CA capability")?;
    let mut operation = Sha256::new();
    operation.update(b"serverware/native-egress-execution-parents/v1\0");
    for commitment in bound.commitments { operation.update(commitment); }
    operation.update(a.original_sha256);
    for scalar in [pending.launch.manifest_sha256(), pending.launch.execution_manifest_sha256(),
        pending.launch.launcher_binary_sha256()] {
        operation.update((scalar.len() as u32).to_be_bytes()); operation.update(scalar.as_bytes());
    }
    let result = Arc::new(ExecutionParents { clock: bound.clock, connection: bound.connection,
        proof: RefCell::new(bound.proof), host: RefCell::new(bound.host),
        launch: RefCell::new(pending.launch), originals: RefCell::new(bound.originals),
        client_private: RefCell::new(bound.client_private), token: RefCell::new(token),
        authorization: pending.authorization, attachment: pending.attachment,
        operation_sha256: operation.finalize().into(), stopped: Cell::new(false) });
    result.check()?;
    Ok(result)
}

impl ExecutionParents {
    pub(in super::super) fn require_application_manifest(&self,
        settings:&super::super::execution::application_proxy::Settings)->Result<(),String> {
        self.check()?;let a=&self.authorization;
        ensure(a.application_proxy_sha256.as_deref()==Some(settings.sha256()?.as_str())
            && a.ruleset.loopback_port==Some(settings.listener_port)
            && a.target_principal_id==settings.target_principal_id && a.proxy.endpoint==settings.proxy_endpoint,
            "application manifest differs from explicit parent effect permission")?;
        self.check()
    }
    pub(in super::super) fn require_application(&self,
        settings: &super::super::execution::application_proxy::Settings,
        target_spki: [u8;32], actual_ca: &[u8]) -> Result<(),String> {
        self.require_application_manifest(settings)?;
        let a=&self.authorization;
        ensure(a.application_proxy_sha256.as_deref()==Some(settings.sha256()?.as_str())
            && a.ruleset.loopback_port==Some(settings.listener_port)
            && a.target_principal_id==settings.target_principal_id && a.target_spki_sha256==target_spki
            && a.runtime_ca_certificate_sha256==digest(actual_ca) && a.proxy.endpoint==settings.proxy_endpoint,
            "application adapter differs from genuine target/CA/endpoint/egress originals")?;
        self.check()
    }
    pub(in super::super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "native execution parents are permanently stopped")?;
        self.clock.check()?;
        ensure(self.authorization.execution_profile, "execution parent profile changed")?;
        self.connection.check_egress_originals(&mut *self.proof.try_borrow_mut()
            .map_err(|_| "execution parent proof already borrowed")?, &self.clock)?;
        self.host.try_borrow_mut().map_err(|_| "execution parent host already borrowed")?.check(&self.clock)?;
        self.launch.try_borrow_mut().map_err(|_| "execution launch already borrowed")?.check(&self.clock)?;
        for original in self.originals.try_borrow_mut().map_err(|_| "execution originals already borrowed")?.iter_mut() {
            self.clock.check()?;
            original.recheck()?;
            self.clock.check()?;
        }
        for cell in [&self.client_private, &self.token] {
            let mut original = cell.try_borrow_mut().map_err(|_| "execution private original already borrowed")?;
            original.require_private()?;
            self.clock.check()?;
            original.recheck()?;
            original.require_private()?;
            self.clock.check()?;
        }
        self.attachment.require_egress(&self.authorization, &self.clock)?;
        self.host.try_borrow_mut().map_err(|_| "execution parent host already borrowed")?.check(&self.clock)?;
        self.launch.try_borrow_mut().map_err(|_| "execution launch already borrowed")?.check(&self.clock)?;
        self.connection.check()?;
        self.clock.check()?;
        self.stopped.set(false);
        Ok(())
    }

    pub(in super::super) fn require_start(&self, start: &start_authority::Authorization,
        clock: &Arc<OriginalClock>) -> Result<(), String>
    {
        ensure(Arc::ptr_eq(&self.clock, clock), "native start does not retain the original parent clock")?;
        self.check()?;
        let constraints = &start.constraints;
        let egress = &self.authorization;
        let attachment = self.attachment.authorization();
        ensure(constraints.application_proxy_sha256 == egress.application_proxy_sha256,
            "native start and egress differ on explicit application adapter permission")?;
        {
            let launch = self.launch.try_borrow().map_err(|_| "execution launch already borrowed")?;
            ensure(constraints.egress_authorization_sha256 == digest_text(&egress.original_sha256)
                && constraints.attachment_authorization_sha256 == digest_text(&attachment.original_sha256)
                && constraints.launch_manifest_sha256 == launch.manifest_sha256()
                && constraints.execution_manifest_sha256 == launch.execution_manifest_sha256()
                && constraints.launcher_binary_sha256 == launch.launcher_binary_sha256()
                && constraints.machine_id_sha256 == digest_text(&egress.machine_id_sha256),
                "native start does not select the actual retained execution parent originals")?;
        }
        let host = &constraints.network_owner;
        let parent_host = &egress.network_owner;
        ensure(host.host_id == parent_host.host_id && host.boot_id == parent_host.boot_id
            && host.namespace_device == parent_host.namespace_device
            && host.namespace_inode == parent_host.namespace_inode && host.owner_uid == parent_host.owner_uid,
            "native start differs from the actually admitted launcher host")?;
        ensure(constraints.issued_at_epoch_ns >= egress.issued_at_epoch_ns
            && constraints.issued_at_epoch_ns >= attachment.issued_at_epoch_ns
            && constraints.start_before_epoch_ns <= egress.expires_at_epoch_ns
            && constraints.start_before_epoch_ns <= attachment.expires_at_epoch_ns,
            "native start admission exceeds the genuine parent intervals")?;
        {
            let proof = self.proof.try_borrow().map_err(|_| "execution parent proof already borrowed")?;
            let setup = proof.setup();
            let delegation = proof.delegation();
            ensure([egress.root_key_id, attachment.root_key_id, setup.authorizer_key_id,
                delegation.authorizer_key_id, delegation.runtime_ca_spki_sha256,
                delegation.caller_issuer_spki_sha256, delegation.caller_spki_sha256,
                delegation.target_issuer_spki_sha256, delegation.target_spki_sha256]
                .iter().all(|key| key != &start.root_key_id),
                "native start authorizer reuses an independent parent or workload key")?;
            for (id, token) in [(&egress.capability.capability_id, &egress.capability.capability_token_sha256),
                (&attachment.capability.capability_id, &attachment.capability.capability_token_sha256),
                (&setup.ca_install.capability_id, &setup.ca_install.capability_token_sha256)] {
                ensure(&constraints.capability.capability_id != id
                    && &constraints.capability.capability_token_sha256 != token,
                    "native start reuses a parent capability or protected token")?;
            }
        }
        let creation = egress.creation_journal.as_ref().ok_or("execution creation journal is absent")?;
        for (path, device, inode, namespace) in [
            (&egress.journal.path, egress.journal.device, egress.journal.inode, &egress.journal.namespace),
            (&creation.path, creation.device, creation.inode, &creation.namespace),
            (&attachment.journal.path, attachment.journal.device, attachment.journal.inode, &attachment.journal.namespace),
        ] {
            ensure(&constraints.journal.path != path
                && (constraints.journal.device, constraints.journal.inode) != (device, inode)
                && &constraints.journal.namespace != namespace,
                "native start journal reuses an independent parent journal")?;
        }
        ensure(!PathBuf::from(&attachment.bridge.lock.path).starts_with(&constraints.journal.path)
            && !PathBuf::from(&constraints.journal.path).starts_with(&attachment.bridge.lock.path),
            "native start journal overlaps the protected bridge lock")?;
        // Stop/cleanup are separately signed absolute continuation constraints;
        // they cannot extend this admission clock or the original network proof.
        self.check()
    }

    pub(in super::super) fn operation_sha256(&self) -> [u8; 32] { self.operation_sha256 }

    // Read-only selected originals. These getters never replace check(), a
    // durable purpose-specific claim, the actual child or a live namespace.
    pub(in super::super) fn egress_authorization(&self) -> &authority::Authorization {
        &self.authorization
    }
    pub(in super::super) fn attachment_pending(&self) -> &attachment::Pending { &self.attachment }
    pub(in super::super) fn original_clock(&self) -> &OriginalClock { &self.clock }

    // Narrow actual-original borrows for the separately authorized CA effect.
    // The installation guard retains this same owner; no proof is cloned and
    // no data projection or local receipt substitutes for check().
    pub(in super::super) fn installation_proof(&self)
        -> Result<std::cell::Ref<'_, native_verifier::BootstrapInstallationOriginals>, String>
    {
        self.check()?;
        self.proof.try_borrow().map_err(|_| "execution installation proof already borrowed".to_owned())
    }

    pub(in super::super) fn installation_ca_original(&self) -> Result<&[u8], String> {
        self.check()?;
        self.connection.admitted_ca_original()
    }

    pub(in super::super) fn retain_original_clock(&self) -> Arc<OriginalClock> {
        Arc::clone(&self.clock)
    }

    pub(in super::super) fn require_ca_separation(&self, root_key: [u8; 32],
        capability_id: &str, token_sha256: &str, journal_path: &str,
        journal_device: u64, journal_inode: u64, journal_namespace: &str,
        destination: &str) -> Result<(), String>
    {
        self.check()?;
        let egress = &self.authorization;
        let attachment = self.attachment.authorization();
        ensure(root_key != egress.root_key_id && root_key != attachment.root_key_id,
            "combined CA authorizer reuses egress or attachment authority")?;
        for (id, token) in [(&egress.capability.capability_id, &egress.capability.capability_token_sha256),
            (&attachment.capability.capability_id, &attachment.capability.capability_token_sha256)] {
            ensure(capability_id != id && token_sha256 != token,
                "combined CA reuses a network capability or protected token")?;
        }
        let creation = egress.creation_journal.as_ref().ok_or("execution creation journal absent")?;
        for (path, device, inode, namespace) in [
            (&egress.journal.path, egress.journal.device, egress.journal.inode, &egress.journal.namespace),
            (&creation.path, creation.device, creation.inode, &creation.namespace),
            (&attachment.journal.path, attachment.journal.device, attachment.journal.inode, &attachment.journal.namespace),
        ] {
            ensure(!PathBuf::from(journal_path).starts_with(path)
                && !PathBuf::from(path).starts_with(journal_path)
                && (journal_device, journal_inode) != (device, inode) && journal_namespace != namespace
                && !PathBuf::from(destination).starts_with(path)
                && !PathBuf::from(path).starts_with(destination),
                "combined CA journal overlaps an independent network journal")?;
        }
        ensure(!PathBuf::from(&attachment.bridge.lock.path).starts_with(journal_path)
            && !PathBuf::from(journal_path).starts_with(&attachment.bridge.lock.path)
            && !PathBuf::from(destination).starts_with(&attachment.bridge.lock.path)
            && !PathBuf::from(&attachment.bridge.lock.path).starts_with(destination),
            "combined CA journal overlaps the actual bridge lock")?;
        self.check()
    }

    pub(in super::super) fn claim_creation(self: &Arc<Self>)
        -> Result<creation_reservation::ExecutionCreationPermit, String>
    {
        self.check()?;
        let permit = creation_reservation::claim_execution(Arc::clone(self))?;
        permit.require_owner(self)?;
        self.check()?;
        Ok(permit)
    }

    pub(super) fn creation_spec(&self) -> Result<creation_reservation::Spec, String> {
        self.check()?;
        self.sealed_creation_spec()
    }

    /// Immutable original association only, used for late cleanup integrity.
    /// It neither checks nor renews admission and has no effect-producing caller.
    pub(super) fn sealed_creation_spec(&self) -> Result<creation_reservation::Spec, String> {
        let journal = self.authorization.creation_journal.as_ref()
            .ok_or("native execution creation journal is absent")?;
        Ok(creation_reservation::Spec {
            journal_path: PathBuf::from(&journal.path), journal_device: journal.device,
            journal_inode: journal.inode, journal_namespace: journal.namespace.clone(),
            capability_id: self.authorization.capability.capability_id.clone(),
            scope_sha256: self.operation_sha256,
        })
    }
}

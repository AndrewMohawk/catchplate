//! Protected preparation for a separately authorized future native start.
//!
//! Retains actual originals and filesystem owners, not serialized successful
//! checks. There is deliberately no start/exec method or durable StartPermit:
//! native parent-proof joins, precreation/start journals, new-child creation,
//! network-owner handoff and independent guardian are still required.

use super::{filesystem::PreparedFilesystem, host, start_authority};
use super::super::{config, ensure, originals::{ArtifactV1, HeldOriginal}, OriginalClock};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Inputs {
    authority: ArtifactV1,
    authority_root: ArtifactV1,
    capability_token: ArtifactV1,
    execution_manifest: ArtifactV1,
}

impl Inputs {
    fn validate(&self) -> Result<(), String> {
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

/// This is admission preparation, not a live StartOwner or a transferable
/// execution permission. Only a later same-module owner may consume its fields.
pub(super) struct PreparedStart {
    clock: Arc<OriginalClock>,
    originals: RefCell<Vec<HeldOriginal>>,
    token: RefCell<HeldOriginal>,
    filesystem: PreparedFilesystem,
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
    pub(super) fn open(inputs: Inputs, clock: Arc<OriginalClock>) -> Result<Self, String> {
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
        let filesystem = PreparedFilesystem::open(&inputs.execution_manifest, Arc::clone(&clock))?;
        clock.check()?;
        let held_manifest = filesystem.manifest_sha256();
        ensure(format!("sha256:{}", held_manifest.iter().map(|byte| format!("{byte:02x}"))
            .collect::<String>()) == manifest_pin,
            "native start retained manifest differs from independently signed original")?;
        let prepared = Self { clock, originals: RefCell::new(originals), token: RefCell::new(token),
            filesystem, host: RefCell::new(observed_host), authorization,
            thread_id: owner_thread, stopped: Cell::new(false) };
        prepared.check()?;
        Ok(prepared)
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
        self.clock.check()?;
        self.host.try_borrow_mut().map_err(|_| "native start host already borrowed")?.check(&self.clock)?;
        self.clock.check()?;
        self.stopped.set(false);
        Ok(())
    }
}

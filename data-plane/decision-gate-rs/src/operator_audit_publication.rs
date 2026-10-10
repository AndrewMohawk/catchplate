//! Operator-only publication coordination. This grants no native authority.
//!
//! Python holds EX before its SQLite transaction through durable materialization.
//! Rust holds its operation's local lane, then SH, through synchronization and
//! the full audit ACK or credential response verification. No caller may enter
//! while holding a dispatch permit. Both lanes share this one pinned lock inode.
use super::{GateState, PolicyTrustRootSource};
use std::fs::{self, File, Metadata, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

pub(super) const LOCK_NAME: &str = ".operator-publication.lock";
const ACQUISITION_BUDGET: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);

fn refused() -> String {
    "operator publication coordination refused".to_owned()
}

pub(super) fn deadline() -> Instant {
    Instant::now() + ACQUISITION_BUDGET
}

pub(super) fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "operator publication coordination deadline expired".to_owned())
}

fn pause(deadline: Instant) -> Result<(), String> {
    std::thread::sleep(remaining(deadline)?.min(POLL));
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}

impl Identity {
    fn checked(metadata: &Metadata, directory: bool) -> Result<Self, String> {
        let mode = if directory { 0o700 } else { 0o600 };
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != mode
            || if directory {
                !metadata.is_dir()
            } else {
                !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != 0
            }
        {
            return Err(refused());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode,
        })
    }
}

pub(super) struct Owner {
    policy_path: PathBuf,
    directory: PathBuf,
    directory_identity: Identity,
    directory_pin: File,
    path: PathBuf,
    identity: Identity,
    // Retain the inode, but never flock this open-file description. Each permit
    // owns an independently opened description, so dropping one cannot unlock another.
    pin: File,
    serial: Mutex<()>,
    // Credential leaders use a separate bounded lane from audit delivery. Both
    // lanes hold the same publication SH lock; policy/cache mutations keep
    // their existing dispatch-authority serialization.
    credential_serial: Mutex<()>,
    #[cfg(test)]
    test_hook: Option<std::sync::Arc<dyn Fn(TestPhase) + Send + Sync>>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestPhase {
    BeforeSharedLock,
    AckVerified,
}

impl Owner {
    pub(super) fn open(policy_path: &Path) -> Result<Self, String> {
        let directory = policy_path.parent().ok_or_else(refused)?.to_path_buf();
        if !policy_path.is_absolute()
            || policy_path.file_name().is_none()
            || fs::canonicalize(&directory).map_err(|_| refused())? != directory
        {
            return Err(refused());
        }
        let directory_pin = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(&directory)
            .map_err(|_| refused())?;
        let directory_identity =
            Identity::checked(&directory_pin.metadata().map_err(|_| refused())?, true)?;
        let path = directory.join(LOCK_NAME);
        let pin = Self::open_file(&path)?;
        let identity = Identity::checked(&pin.metadata().map_err(|_| refused())?, false)?;
        let owner = Self {
            policy_path: policy_path.to_path_buf(),
            directory,
            directory_identity,
            directory_pin,
            path,
            identity,
            pin,
            serial: Mutex::new(()),
            credential_serial: Mutex::new(()),
            #[cfg(test)]
            test_hook: None,
        };
        owner.check_identity(&owner.pin)?;
        Ok(owner)
    }

    fn open_file(path: &Path) -> Result<File, String> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| refused())
    }

    fn check_identity(&self, descriptor: &File) -> Result<(), String> {
        if fs::canonicalize(&self.directory).map_err(|_| refused())? != self.directory
            || Identity::checked(
                &fs::symlink_metadata(&self.directory).map_err(|_| refused())?,
                true,
            )? != self.directory_identity
            || Identity::checked(&self.directory_pin.metadata().map_err(|_| refused())?, true)?
                != self.directory_identity
            || Identity::checked(
                &fs::symlink_metadata(&self.path).map_err(|_| refused())?,
                false,
            )? != self.identity
            || Identity::checked(&self.pin.metadata().map_err(|_| refused())?, false)?
                != self.identity
            || Identity::checked(&descriptor.metadata().map_err(|_| refused())?, false)?
                != self.identity
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn acquire(&self, deadline: Instant) -> Result<Permit<'_>, String> {
        self.acquire_in_lane(&self.serial, deadline, deadline)
    }

    fn acquire_credential(&self, operation_deadline: Instant) -> Result<Permit<'_>, String> {
        let acquisition_deadline = deadline().min(operation_deadline);
        self.acquire_in_lane(
            &self.credential_serial,
            acquisition_deadline,
            operation_deadline,
        )
    }

    fn acquire_in_lane<'a>(
        &'a self,
        lane: &'a Mutex<()>,
        acquisition_deadline: Instant,
        operation_deadline: Instant,
    ) -> Result<Permit<'a>, String> {
        let serial = loop {
            remaining(acquisition_deadline)?;
            match lane.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => pause(acquisition_deadline)?,
                Err(TryLockError::Poisoned(_)) => return Err(refused()),
            }
        };
        let descriptor = Self::open_file(&self.path)?;
        self.check_identity(&descriptor)?;
        #[cfg(test)]
        self.test_checkpoint(TestPhase::BeforeSharedLock);
        loop {
            remaining(acquisition_deadline)?;
            if unsafe { libc::flock(descriptor.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
                break;
            }
            let code = std::io::Error::last_os_error().raw_os_error();
            if code != Some(libc::EWOULDBLOCK)
                && code != Some(libc::EAGAIN)
                && code != Some(libc::EINTR)
            {
                return Err(refused());
            }
            pause(acquisition_deadline)?;
        }
        remaining(acquisition_deadline)?;
        let permit = Permit {
            owner: self,
            descriptor,
            _serial: serial,
            deadline: operation_deadline,
        };
        permit.check()?;
        Ok(permit)
    }

    #[cfg(test)]
    pub(super) fn with_test_hook(
        mut self,
        hook: std::sync::Arc<dyn Fn(TestPhase) + Send + Sync>,
    ) -> Self {
        self.test_hook = Some(hook);
        self
    }

    #[cfg(test)]
    fn test_checkpoint(&self, phase: TestPhase) {
        if let Some(hook) = self.test_hook.as_ref() {
            hook(phase);
        }
    }
}

pub(super) struct Permit<'a> {
    owner: &'a Owner,
    descriptor: File,
    _serial: MutexGuard<'a, ()>,
    deadline: Instant,
}

impl Permit<'_> {
    #[cfg(test)]
    pub(super) fn test_checkpoint(&self, phase: TestPhase) {
        self.owner.test_checkpoint(phase);
    }

    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) fn check(&self) -> Result<(), String> {
        remaining(self.deadline)?;
        self.owner.check_identity(&self.descriptor)?;
        remaining(self.deadline)?;
        Ok(())
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        // Closing the independently owned descriptor also releases this flock
        // if an interrupted explicit unlock fails. No untrusted error is logged.
        unsafe {
            libc::flock(self.descriptor.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn selected(state: &GateState) -> Result<bool, String> {
    let operator = state.policy_shadow.is_operator_demo();
    if operator != state.operator_audit_publication.is_some() {
        return Err(refused());
    }
    if operator
        && (state.is_production
            || state.measured_audit.is_some()
            || state.native_serving_privileges.is_some()
            || state.native_secret_broker.is_some()
            || state.native_policy_bytes.is_some()
            || state.native_runtime_lifetime.is_some()
            || state.measured_canary_delivery.is_some()
            || state.policy_shadow_generation_control.is_some()
            || state.atomic_release_authorization_enabled)
    {
        return Err(refused());
    }
    if operator {
        require_local_verifier(&state.policy_trust_root_source)?;
    }
    Ok(operator)
}

/// This local development profile uses the existing in-process dev signature
/// verifier. External commands cannot run while publication ownership is held:
/// the general command helper does not bound a child that never reads stdin.
pub(super) fn require_local_verifier(source: &PolicyTrustRootSource) -> Result<(), String> {
    if matches!(
        source,
        PolicyTrustRootSource::AttestedControlPlane {
            verifier: Some(_),
            ..
        }
    ) {
        return Err(
            "operator publication does not admit external attestation verifiers".to_owned(),
        );
    }
    Ok(())
}

pub(super) fn acquire(state: &GateState) -> Result<Option<Permit<'_>>, String> {
    if !selected(state)? {
        return Ok(None);
    }
    let owner = state
        .operator_audit_publication
        .as_ref()
        .ok_or_else(refused)?;
    if owner.policy_path != Path::new(&state.policy_path) {
        return Err(refused());
    }
    owner.acquire(deadline()).map(Some)
}

/// Only an elected background credential leader may use this lane. Waiting for
/// its lane or the shared publication lock spends at most five seconds of the
/// original task budget. The permit retains that original operation deadline,
/// rather than shortening subsequently verified material to the lock budget.
pub(super) fn acquire_credential_on_deadline(
    state: &GateState,
    original_deadline: Instant,
) -> Result<Option<Permit<'_>>, String> {
    if !selected(state)? {
        return Ok(None);
    }
    let owner = state
        .operator_audit_publication
        .as_ref()
        .ok_or_else(refused)?;
    if owner.policy_path != Path::new(&state.policy_path) {
        return Err(refused());
    }
    owner.acquire_credential(original_deadline).map(Some)
}

pub(super) fn require_permit(
    state: &GateState,
    permit: Option<&Permit<'_>>,
) -> Result<Option<Instant>, String> {
    match (selected(state)?, permit) {
        (false, None) => Ok(None),
        (true, Some(permit))
            if state
                .operator_audit_publication
                .as_ref()
                .is_some_and(|owner| std::ptr::eq(owner.as_ref(), permit.owner)) =>
        {
            permit.check()?;
            Ok(Some(permit.deadline))
        }
        _ => Err(refused()),
    }
}

#[cfg(test)]
#[path = "operator_audit_publication_tests.rs"]
mod tests;

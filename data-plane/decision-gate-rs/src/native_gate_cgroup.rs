//! One fresh, source-fixed gate cgroup under the original native startup owner.
//! This is local process containment, not attestation or Reserve permission.
mod filesystem;

use crate::native_serving_privileges::{Association, Owner as Serving, Prepared as Privileged};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

pub const CGROUP_ID: &str = "serverware-native-gate";
pub const PROC_CGROUP: &[u8] = b"0::/serverware-native-gate\n";
pub const PATH: &str = "/sys/fs/cgroup/serverware-native-gate";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration { api_version: String }
impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        require(self.api_version == "serverware.nativeGateCgroup/v1", "gate cgroup profile differs")
    }
}

pub fn proc_cgroup_sha256() -> String { format!("sha256:{:x}", Sha256::digest(PROC_CGROUP)) }

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}
fn live(deadline: u64) -> Result<(), String> {
    let mut sample: libc::timespec = unsafe { std::mem::zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } == 0
        && sample.tv_sec >= 0 && (0..1_000_000_000).contains(&sample.tv_nsec), "gate cgroup clock unavailable")?;
    let now = (sample.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(sample.tv_nsec as u64)).ok_or("gate cgroup clock overflow")?;
    require(now < deadline, "gate cgroup original lifetime expired")
}

pub struct Prepared {
    originals: Option<filesystem::Originals>,
    association: Association,
    pid: libc::pid_t,
    deadline: u64,
    attach_attempted: bool,
}
pub struct Attached {
    originals: filesystem::Originals,
    association: Association,
    pid: libc::pid_t,
    deadline: u64,
}
pub struct Owner {
    originals: filesystem::Originals,
    association: Association,
    serving: Arc<Serving>,
    pid: libc::pid_t,
    deadline: u64,
    poisoned: AtomicBool,
}

impl Prepared {
    /// Only this explicit profile may mount/create anything. Construction is
    /// before the cohort's real StateCas cgroup observer, but does not migrate
    /// the gate: all subsequent fixed child launches remain outside the leaf.
    pub fn open(configuration: Configuration, privileged: &Privileged) -> Result<Self, String> {
        configuration.validate()?;
        privileged.check()?;
        let association = Association::capture(privileged)?;
        let pid = unsafe { libc::getpid() };
        let originals = filesystem::Originals::prepare(privileged.deadline())?;
        let owner = Self { originals: Some(originals), association, pid,
            deadline: privileged.deadline(), attach_attempted: false };
        owner.check_empty(privileged)?;
        Ok(owner)
    }
    fn check_empty(&self, privileged: &Privileged) -> Result<(), String> {
        self.association.require_preparation(privileged)?;
        require(!self.attach_attempted && unsafe { libc::getpid() } == self.pid
            && self.deadline == privileged.deadline(), "gate cgroup preparation owner differs")?;
        self.originals.as_ref().ok_or("gate cgroup originals consumed")?.check(false, self.pid, self.deadline)
    }
    /// Call after the LAST privileged child creation, immediately before the
    /// permanent serving drop. There is one write attempt, never a retry or
    /// move-back. Uncertain writes retain the fresh leaf as a tombstone.
    pub fn attach_gate(mut self, privileged: &Privileged) -> Result<Attached, String> {
        self.check_empty(privileged)?;
        self.attach_attempted = true;
        self.originals.as_ref().ok_or("gate cgroup originals consumed")?.attach(self.pid, self.deadline)?;
        privileged.check()?;
        let originals = self.originals.take().ok_or("gate cgroup originals consumed")?;
        Ok(Attached { originals, association: Association::capture(privileged)?, pid: self.pid, deadline: self.deadline })
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        // Only a still-empty, never-attempted leaf can be removed. No mount is
        // torn down; StateCas may already retain that actual hierarchy.
        if !self.attach_attempted && unsafe { libc::getpid() } == self.pid
            && unsafe { libc::geteuid() } == 0 && live(self.deadline).is_ok() {
            if let Some(originals) = &self.originals { let _ = originals.remove_empty(self.pid, self.deadline); }
        }
    }
}
impl Attached {
    pub fn bind(self, serving: Arc<Serving>) -> Result<Arc<Owner>, String> {
        self.association.require(&serving)?;
        require(unsafe { libc::getpid() } == self.pid && serving.deadline() == self.deadline,
            "gate cgroup final serving origin differs")?;
        let owner = Arc::new(Owner { originals: self.originals, association: self.association,
            serving, pid: self.pid, deadline: self.deadline, poisoned: AtomicBool::new(false) });
        owner.check()?;
        Ok(owner)
    }
}
impl Owner {
    pub fn deadline(&self) -> u64 { self.deadline }
    pub fn require_serving(&self, serving: &Serving) -> Result<(), String> {
        self.association.require(serving)?;
        require(std::ptr::eq(Arc::as_ptr(&self.serving), serving), "gate cgroup serving owner substituted")?;
        self.check()
    }
    pub fn check(&self) -> Result<(), String> {
        let result = (|| {
            require(!self.poisoned.load(Ordering::Acquire) && unsafe { libc::getpid() } == self.pid,
                "gate cgroup owner crossed process or is poisoned")?;
            self.association.require(&self.serving)?;
            self.originals.check(true, self.pid, self.deadline)
        })();
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }
}
// Dropping Attached/Owner closes read-only descriptors only. A live gate can
// neither empty its own leaf nor truthfully report its own death. The leaf is
// never reused, removed or unmounted after attach; guest teardown is required.

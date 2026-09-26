//! Complete initial maps acquisition while the actual supervisor remains stopped.
//!
//! Original procfs bytes, every parsed row and executable backing custody remain
//! together with the stopped owner. This unsigned, non-cloneable owner is not a
//! runtime-evidence conversion, multi-process/transient history, or authority for
//! zero-inode special mappings. There is deliberately no ready/resume method.

use super::body_observer_mapping_files_v12::{
    ExecutableMappingFileBindingV12, HeldExecutableMappingFilesV12,
};
use super::body_observer_maps_v12::{parse_maps_original, ProcMappingV12, MAX_MAPS_BYTES, MAX_MAPPINGS};
use super::StoppedBodyObserverLaunchV12;
use crate::plan_protocol::body_observer_contract_v12::BodyObserverLaunchV12;
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const PROC_MAGIC: libc::c_long = 0x9fa0;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn now(deadline: u64) -> PlanResult<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(invalid("initial mapping observation clock is invalid"));
    }
    let sampled = (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| invalid("initial mapping observation clock overflows"))?;
    if sampled >= deadline { return Err(invalid("initial mapping observation deadline expired")); }
    Ok(sampled)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct MapsNode {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
}

fn maps_node(fd: RawFd, proc_fd: RawFd, deadline: u64) -> PlanResult<MapsNode> {
    now(deadline)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    let mut parent: libc::stat = unsafe { std::mem::zeroed() };
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0
        || unsafe { libc::fstat(proc_fd, &mut parent) } != 0
        || unsafe { libc::fstatfs(fd, &mut filesystem) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if filesystem.f_type != PROC_MAGIC as _ || value.st_mode & libc::S_IFMT != libc::S_IFREG
        || parent.st_mode & libc::S_IFMT != libc::S_IFDIR || value.st_dev != parent.st_dev
        || value.st_ino == 0 || value.st_nlink != 1
        || descriptor_flags < 0 || descriptor_flags & libc::FD_CLOEXEC == 0
        || status_flags < 0 || status_flags & libc::O_ACCMODE != libc::O_RDONLY
        || status_flags & libc::O_NONBLOCK == 0 {
        return Err(invalid("initial maps descriptor is not the held read-only procfs original"));
    }
    now(deadline)?;
    Ok(MapsNode { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid, links: value.st_nlink })
}

fn open_maps(proc_fd: RawFd, deadline: u64) -> PlanResult<OwnedFd> {
    now(deadline)?;
    let raw = unsafe { libc::openat(proc_fd, c"maps".as_ptr(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    // The acquisition owner retains this descriptor before fallible admission.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn read_original(fd: RawFd, deadline: u64) -> PlanResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(4096.min(MAX_MAPS_BYTES));
    let mut buffer = [0u8; 16 * 1024];
    loop {
        now(deadline)?;
        let wanted = (MAX_MAPS_BYTES - bytes.len()).min(buffer.len()).max(1);
        let count = unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(), wanted, bytes.len() as libc::off_t) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        now(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { return Ok(bytes); }
        if count as usize > MAX_MAPS_BYTES - bytes.len() {
            return Err(invalid("initial maps original exceeds its source byte bound"));
        }
        bytes.extend_from_slice(&buffer[..count as usize]);
    }
}

pub(crate) struct StoppedBodyMappingSnapshotV12 {
    // Rust drops fields in declaration order. Fail-closed stopped custody must
    // run before maps/backing descriptors are released, including on failure
    // while these private acquisition slots are still being populated.
    stopped: StoppedBodyObserverLaunchV12,
    maps: Option<OwnedFd>,
    maps_identity: Option<MapsNode>,
    original: Vec<u8>,
    rows: Vec<ProcMappingV12>,
    backing: Option<HeldExecutableMappingFilesV12>,
    observation_started: u64,
    observation_finished: u64,
}

impl StoppedBodyMappingSnapshotV12 {
    pub(crate) fn acquire(stopped: StoppedBodyObserverLaunchV12) -> PlanResult<Self> {
        // Move the actual stopped owner before any fallible observation. No
        // external maps, parsed rows or successful measurement DTO is accepted.
        let mut held = Self { stopped, maps: None, maps_identity: None, original: Vec::new(),
            rows: Vec::new(), backing: None, observation_started: 0, observation_finished: 0 };
        let deadline = held.stopped.deadline;
        held.observation_started = now(deadline)?;
        if held.observation_started < held.stopped.stop.observed_at_boottime_ns {
            return Err(invalid("initial mapping observation predates the actual stop"));
        }
        held.stopped.verify_stopped(deadline)?;
        held.maps = Some(open_maps(held.stopped.target.proc_fd(), deadline)?);
        let maps_fd = held.maps_fd()?;
        held.maps_identity = Some(maps_node(maps_fd, held.stopped.target.proc_fd(), deadline)?);
        held.original = read_original(maps_fd, deadline)?;
        held.rows = parse_maps_original(&held.original)?;
        if held.rows.is_empty() || held.rows.len() > MAX_MAPPINGS {
            return Err(invalid("initial maps lacks a complete bounded task inventory"));
        }
        held.stopped.verify_stopped(deadline)?;
        held.verify_original(deadline)?;
        held.backing = Some(HeldExecutableMappingFilesV12::acquire(
            held.stopped.target.proc_fd(), &held.rows, deadline,
        )?);
        // Bracket backing acquisition with the same full maps bytes and real
        // stopped target, then retain the actual observation interval.
        held.verify_custody(deadline)?;
        held.observation_finished = now(deadline)?;
        if held.observation_finished < held.observation_started {
            return Err(invalid("initial mapping observation clock moved backwards"));
        }
        Ok(held)
    }

    fn maps_fd(&self) -> PlanResult<RawFd> {
        self.maps.as_ref().map(AsRawFd::as_raw_fd)
            .ok_or_else(|| invalid("initial mapping acquisition has no retained maps descriptor"))
    }

    fn backing(&self) -> PlanResult<&HeldExecutableMappingFilesV12> {
        self.backing.as_ref().ok_or_else(|| invalid("initial mapping acquisition has no retained backing owner"))
    }

    fn verify_original(&self, deadline: u64) -> PlanResult<()> {
        let expected = self.maps_identity.as_ref()
            .ok_or_else(|| invalid("initial mapping acquisition has no admitted maps identity"))?;
        let proc_fd = self.stopped.target.proc_fd();
        let maps_fd = self.maps_fd()?;
        if maps_node(maps_fd, proc_fd, deadline)? != *expected {
            return Err(invalid("retained initial maps descriptor changed"));
        }
        // A fresh name join is necessary: a retained proc maps FD alone must
        // not substitute an old address space for the stopped task's current one.
        let named = open_maps(proc_fd, deadline)?;
        if maps_node(named.as_raw_fd(), proc_fd, deadline)? != *expected
            || read_original(maps_fd, deadline)? != self.original
            || read_original(named.as_raw_fd(), deadline)? != self.original
            || maps_node(named.as_raw_fd(), proc_fd, deadline)? != *expected
            || maps_node(maps_fd, proc_fd, deadline)? != *expected {
            return Err(invalid("complete initial maps original or named identity changed"));
        }
        now(deadline)?;
        Ok(())
    }

    fn verify_custody(&self, deadline: u64) -> PlanResult<()> {
        self.stopped.verify_stopped(deadline)?;
        self.verify_original(deadline)?;
        let backing = self.backing()?;
        if backing.deadline() != self.stopped.deadline {
            return Err(invalid("initial backing custody changed the original observation deadline"));
        }
        backing.verify(self.stopped.target.proc_fd(), &self.rows, deadline)?;
        self.verify_original(deadline)?;
        self.stopped.verify_stopped(deadline)
    }

    pub(crate) fn verify(&self, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.stopped.deadline);
        let sampled = now(deadline)?;
        if self.observation_started < self.stopped.stop.observed_at_boottime_ns
            || self.observation_finished < self.observation_started
            || self.observation_finished >= self.stopped.deadline || sampled < self.observation_finished {
            return Err(invalid("initial mapping observation interval differs from its original stop/window"));
        }
        self.verify_custody(deadline)
    }

    pub(crate) fn abort(self, deadline: u64) -> PlanResult<()> {
        // Partial move is intentional: abort/reap the stopped owner before the
        // remaining mapping/backing fields drop. No fresh cleanup window exists.
        self.stopped.abort(deadline)
    }

    pub(crate) fn original_maps(&self) -> &[u8] { &self.original }
    pub(super) fn mappings(&self) -> &[ProcMappingV12] { &self.rows }
    pub(super) fn executable_bindings(&self) -> PlanResult<&[ExecutableMappingFileBindingV12]> {
        Ok(self.backing()?.bindings())
    }
    pub(crate) fn observation_interval(&self) -> (u64, u64) {
        (self.observation_started, self.observation_finished)
    }
    pub(crate) fn launch(&self) -> &BodyObserverLaunchV12 { &self.stopped.launch }
    pub(crate) fn deadline(&self) -> u64 { self.stopped.deadline }
    pub(crate) fn context_sha256(&self) -> Digest { self.stopped.stop.context_sha256 }
    pub(crate) fn target_host_pid(&self) -> u32 { self.stopped.target.host_pid() }
    pub(crate) fn target_start_ticks(&self) -> u64 { self.stopped.stop.target_start_ticks }
    pub(crate) fn target_pidfd_inode(&self) -> u64 { self.stopped.stop.target_pidfd_inode }
    pub(crate) fn target_pid_namespace_inode(&self) -> u64 { self.stopped.stop.target_pid_namespace_inode }
    pub(crate) fn worker_host_pid(&self) -> u32 { self.stopped.worker.worker_pid() }
}

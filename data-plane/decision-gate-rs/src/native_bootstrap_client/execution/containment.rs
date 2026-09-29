//! Claim-before-mkdir ownership of one new native execution cgroup leaf.
//!
//! This owner never migrates a task. Its one-use child admission exposes only
//! the actual leaf to the source-owned clone path; cleanup borrows are sealed.
//! Its
//! cleanup capability is sealed to the actual created directory, independently
//! of admission expiry. Empty-leaf observations are not leader-reap receipts.

use super::{start::StartOwner, start_reservation::StartPermit};
use serverware_decision_gate::cgroup_control_v1::{self, DirectoryObservationV1, EventsV1};
use std::cell::Cell;
use std::ffi::CString;
use std::mem::zeroed;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;

const STATX_MNT_ID: libc::c_uint = 0x0000_1000;
const MAX_CONTROL_BYTES: usize = 4096;
const SECOND: u64 = 1_000_000_000;

fn require(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.to_owned()) }
}

fn boottime() -> Result<u64, String> {
    let mut value: libc::timespec = unsafe { zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } == 0
        && value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "native containment boottime is unavailable")?;
    (value.tv_sec as u64).checked_mul(SECOND)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .filter(|value| *value != 0).ok_or_else(|| "native containment boottime overflow".to_owned())
}

fn privileged_process(pid: u32) -> Result<(), String> {
    require(std::process::id() == pid && unsafe { libc::getuid() } == 0
        && unsafe { libc::geteuid() } == 0 && unsafe { libc::getgid() } == 0
        && unsafe { libc::getegid() } == 0,
        "native containment process or privileged identity changed")
}

fn descriptor_flags(fd: BorrowedFd<'_>, access: Option<libc::c_int>) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    let status = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    require(flags >= 0 && status >= 0 && flags & libc::FD_CLOEXEC != 0
        && access.map_or(true, |expected| status & (libc::O_ACCMODE | libc::O_NONBLOCK
            | libc::O_APPEND | libc::O_ASYNC) == expected),
        "native containment descriptor flags changed")
}

fn duplicate(fd: BorrowedFd<'_>) -> Result<OwnedFd, String> {
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    require(result >= 0, "native containment parent descriptor duplication failed")?;
    Ok(unsafe { OwnedFd::from_raw_fd(result) })
}

fn directory(fd: BorrowedFd<'_>) -> Result<DirectoryObservationV1, String> {
    descriptor_flags(fd, None)?;
    let identity = cgroup_control_v1::verify_directory(fd).map_err(|error| error.to_string())?;
    require(identity.uid() == 0 && identity.gid() == 0,
        "native containment directory is not root-owned")?;
    Ok(identity)
}

#[derive(PartialEq, Eq)]
struct FileIdentity { device: u64, inode: u64, mount: u64, mode: u32, uid: u32, gid: u32 }

fn statx_identity(value: &libc::statx) -> Result<FileIdentity, String> {
    require(value.stx_mask & libc::STATX_BASIC_STATS == libc::STATX_BASIC_STATS
        && value.stx_mask & STATX_MNT_ID != 0 && value.stx_ino != 0
        && u32::from(value.stx_mode) & libc::S_IFMT == libc::S_IFREG
        && value.stx_nlink == 1 && value.stx_uid == 0 && value.stx_gid == 0
        && value.stx_mode & 0o022 == 0,
        "native containment control is not a protected original regular file")?;
    Ok(FileIdentity { device: libc::makedev(value.stx_dev_major, value.stx_dev_minor),
        inode: value.stx_ino, mount: value.stx_mnt_id, mode: u32::from(value.stx_mode),
        uid: value.stx_uid, gid: value.stx_gid })
}

fn file_identity(fd: BorrowedFd<'_>) -> Result<FileIdentity, String> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut value: libc::statx = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } == 0
        && unsafe { libc::statx(fd.as_raw_fd(), b"\0".as_ptr().cast(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BASIC_STATS | STATX_MNT_ID, &mut value) } == 0,
        "native containment control identity cannot be read")?;
    let identity = statx_identity(&value)?;
    require(stat.st_dev == identity.device && stat.st_ino == identity.inode
        && stat.st_mode == identity.mode && stat.st_uid == identity.uid
        && stat.st_gid == identity.gid && stat.st_nlink == 1,
        "native containment control stat association differs")?;
    Ok(identity)
}

#[derive(Clone, Copy)]
enum Kind { Type, Subtree, Stat, Procs, Memory, Swap, Pids, Cpu, Kill }
impl Kind {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Type => b"cgroup.type\0", Self::Subtree => b"cgroup.subtree_control\0",
            Self::Stat => b"cgroup.stat\0", Self::Procs => b"cgroup.procs\0", Self::Memory => b"memory.max\0",
            Self::Swap => b"memory.swap.max\0", Self::Pids => b"pids.max\0",
            Self::Cpu => b"cpu.max\0", Self::Kill => b"cgroup.kill\0",
        }
    }
    fn access(self) -> libc::c_int {
        libc::O_NONBLOCK | match self {
            Self::Type | Self::Subtree | Self::Stat | Self::Procs => libc::O_RDONLY,
            Self::Kill => libc::O_WRONLY,
            _ => libc::O_RDWR,
        }
    }
}

struct Control { file: OwnedFd, identity: FileIdentity, kind: Kind }
impl Control {
    fn open(leaf: BorrowedFd<'_>, identity: &DirectoryObservationV1, kind: Kind)
        -> Result<Self, String>
    {
        let raw = unsafe { libc::openat(leaf.as_raw_fd(), kind.name().as_ptr().cast(),
            libc::O_CLOEXEC | libc::O_NOFOLLOW | kind.access()) };
        require(raw >= 0, "native containment fixed control cannot be opened")?;
        let file = unsafe { OwnedFd::from_raw_fd(raw) };
        let result = Self { identity: file_identity(file.as_fd())?, file, kind };
        result.check(leaf, identity)?;
        Ok(result)
    }

    fn check(&self, leaf: BorrowedFd<'_>, identity: &DirectoryObservationV1) -> Result<(), String> {
        descriptor_flags(self.file.as_fd(), Some(self.kind.access()))?;
        let mut named: libc::statx = unsafe { zeroed() };
        require(unsafe { libc::statx(leaf.as_raw_fd(), self.kind.name().as_ptr().cast(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BASIC_STATS | STATX_MNT_ID, &mut named) } == 0,
            "native containment named control cannot be rechecked")?;
        require(file_identity(self.file.as_fd())? == self.identity
            && statx_identity(&named)? == self.identity
            && self.identity.device == identity.device() && self.identity.mount == identity.mount_id(),
            "native containment fixed control association changed")
    }

    fn read(&self, leaf: BorrowedFd<'_>, identity: &DirectoryObservationV1) -> Result<Vec<u8>, String> {
        self.check(leaf, identity)?;
        let raw = read_bounded(self.file.as_fd())?;
        self.check(leaf, identity)?;
        Ok(raw)
    }
}

// At most two reads, no EINTR/EAGAIN retries. A partial or changing seq-file
// record is refused rather than borrowing a fresh deadline to finish it.
fn read_bounded(fd: BorrowedFd<'_>) -> Result<Vec<u8>, String> {
    read_with_bound(fd, MAX_CONTROL_BYTES)
}

fn read_with_bound(fd: BorrowedFd<'_>, maximum: usize) -> Result<Vec<u8>, String> {
    require(matches!(maximum, MAX_CONTROL_BYTES | 65_536), "native containment read bound is not source-fixed")?;
    let mut raw = vec![0u8; maximum];
    let count = unsafe { libc::pread(fd.as_raw_fd(), raw.as_mut_ptr().cast(), raw.len(), 0) };
    require(count >= 0 && (count as usize) < raw.len(),
        "native containment control read failed or exceeds its bound")?;
    let count = count as usize;
    let mut tail = 0u8;
    require(unsafe { libc::pread(fd.as_raw_fd(), (&mut tail as *mut u8).cast(), 1,
        count as libc::off_t) } == 0, "native containment control original was partial or changed")?;
    require(raw[..count].is_ascii(), "native containment control is not ASCII")?;
    Ok(raw[..count].to_vec())
}

fn populated(events: &EventsV1) -> Result<bool, String> {
    populated_original(events).map(|(live, _)| live)
}

fn populated_original(events: &EventsV1) -> Result<(bool, Vec<u8>), String> {
    events.check().map_err(|error| error.to_string())?;
    let raw = read_bounded(events.poll_fd())?;
    require(raw.last() == Some(&b'\n'), "native containment events record is incomplete")?;
    let text = std::str::from_utf8(&raw).map_err(|_| "native containment events are not ASCII")?;
    let mut result = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next().ok_or("native containment events lack a field")?;
        let value = fields.next().ok_or("native containment events lack a value")?;
        require(fields.next().is_none(), "native containment events have extra fields")?;
        if name == "populated" {
            require(result.is_none() && matches!(value, "0" | "1"),
                "native containment populated field is invalid")?;
            result = Some(value == "1");
        }
    }
    events.check().map_err(|error| error.to_string())?;
    Ok((result.ok_or_else(|| "native containment events lack populated".to_owned())?, raw))
}

struct Leaf {
    parent: OwnedFd,
    parent_identity: DirectoryObservationV1,
    directory: OwnedFd,
    identity: DirectoryObservationV1,
    name: CString,
    kill: Control,
    pid: u32,
    kill_attempted: Cell<bool>,
    kill_acknowledged: Cell<bool>,
}
impl Leaf {
    // No current admission proof, journal, wall clock or deadline is consulted
    // here. Only the original task-created leaf and fixed control can be used.
    fn check(&self) -> Result<(), String> {
        privileged_process(self.pid)?;
        require(directory(self.parent.as_fd())? == self.parent_identity
            && directory(self.directory.as_fd())? == self.identity,
            "native containment held parent or leaf changed")?;
        let raw = unsafe { libc::openat(self.parent.as_raw_fd(), self.name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        require(raw >= 0, "native containment named leaf is unavailable")?;
        let named = unsafe { OwnedFd::from_raw_fd(raw) };
        require(directory(named.as_fd())? == self.identity,
            "native containment named leaf no longer matches its held original")?;
        self.kill.check(self.directory.as_fd(), &self.identity)
    }

    fn kill_once(&self) -> Result<bool, String> {
        self.check()?;
        if self.kill_attempted.replace(true) { return Ok(self.kill_acknowledged.get()); }
        // Mark before the sole write. EINTR/short write/errors are uncertainty,
        // never permission to issue another effect, including during Drop.
        let written = unsafe { libc::write(self.kill.file.as_raw_fd(), b"1".as_ptr().cast(), 1) };
        self.kill_acknowledged.set(written == 1);
        self.check()?;
        Ok(written == 1)
    }
}
impl Drop for Leaf {
    fn drop(&mut self) {
        // Emergency best effort only; no waiting, rmdir, journal completion or
        // successful cleanup assertion is possible from this destructor.
        if !self.kill_attempted.get() { let _ = self.kill_once(); }
    }
}

struct Limit { control: Control, expected: Vec<u8> }

pub(super) struct ContainmentOwner {
    // Fields drop in declaration order: emergency termination must retain the
    // durable claim/lock and genuine owner until the Leaf destructor has run.
    leaf: Leaf,
    permit: StartPermit,
    owner: Arc<StartOwner>,
    domain: Control,
    subtree: Control,
    stat: Control,
    procs: Control,
    limits: Vec<Limit>,
    events: EventsV1,
    cleanup_deadline: u64,
    admission_stopped: Cell<bool>,
    child_attempted: Cell<bool>,
    cleanup_finished: Cell<bool>,
    retirement_attempted: Cell<bool>,
}

/// Data-only evidence that this held leaf had no live tasks before its bound.
/// Neither a leader reap nor a successful exec/exit/kill/guardian receipt.
pub(super) struct LeafEmpty { observed_boottime_ns: u64, kill_acknowledged: bool, original: Vec<u8> }

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CgroupRemoval {
    parent_device: u64, parent_inode: u64, device: u64, inode: u64,
    name: String, observed_boottime_ns: u64,
}
impl LeafEmpty {
    pub(super) fn observed_boottime_ns(&self) -> u64 { self.observed_boottime_ns }
    pub(super) fn kill_acknowledged(&self) -> bool { self.kill_acknowledged }
    pub(super) fn original(&self) -> &[u8] { &self.original }
}

impl ContainmentOwner {
    pub(super) fn create(owner: Arc<StartOwner>, permit: StartPermit) -> Result<Self, String> {
        owner.check_admission()?;
        permit.require_owner(&owner)?;
        let pid = std::process::id();
        privileged_process(pid)?;
        let signed = &owner.constraints().containment;
        require(signed.profile == "cgroup-v2-new-leaf-kill-v1"
            && signed.guardian_profile == "independent-cgroup-guardian-v1"
            && !signed.child_name.is_empty() && signed.child_name.len() <= 80
            && signed.child_name.bytes().all(|byte| byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-'))
            && !matches!(signed.child_name.as_str(), "." | ".."),
            "native containment signed child profile is invalid")?;
        let name = CString::new(signed.child_name.as_bytes()).map_err(|_| "invalid cgroup child name")?;
        let parent = duplicate(owner.containment_parent())?;
        let parent_identity = directory(parent.as_fd())?;
        require(parent_identity.device() == signed.parent_device
            && parent_identity.inode() == signed.parent_inode,
            "native containment parent differs from the signed original")?;
        let cleanup_deadline = owner.cleanup_boottime_ns();
        require(cleanup_deadline > boottime()?, "native containment cleanup interval already ended")?;
        let resources = &owner.constraints().resources;
        let expected = [
            (Kind::Memory, format!("{}\n", resources.memory_max_bytes).into_bytes()),
            (Kind::Swap, format!("{}\n", resources.memory_swap_max_bytes).into_bytes()),
            (Kind::Pids, format!("{}\n", resources.pids_max).into_bytes()),
            (Kind::Cpu, format!("{} {}\n", resources.cpu_max_quota_us,
                resources.cpu_max_period_us).into_bytes()),
        ];
        // The actual pointer-matched durable claim must exist before this first
        // effect. An existing leaf is never opened, reused, repaired or removed.
        owner.check_admission()?;
        permit.require_owner(&owner)?;
        require(directory(parent.as_fd())? == parent_identity,
            "native containment parent changed before creation")?;
        require(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0,
            "native containment exclusive leaf creation failed; claim remains consumed")?;
        let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        require(raw >= 0, "native containment created leaf cannot be retained; outcome uncertain")?;
        let held = unsafe { OwnedFd::from_raw_fd(raw) };
        let identity = directory(held.as_fd())?;
        require(identity.mode() & 0o7777 == 0o700
            && identity.device() == parent_identity.device()
            && identity.mount_id() == parent_identity.mount_id()
            && identity.inode() != parent_identity.inode(),
            "native containment created leaf identity is invalid")?;
        let kill = Control::open(held.as_fd(), &identity, Kind::Kill)?;
        let leaf = Leaf { parent, parent_identity, directory: held, identity, name, kill, pid,
            kill_attempted: Cell::new(false), kill_acknowledged: Cell::new(false) };
        leaf.check()?;
        let domain = Control::open(leaf.directory.as_fd(), &leaf.identity, Kind::Type)?;
        let subtree = Control::open(leaf.directory.as_fd(), &leaf.identity, Kind::Subtree)?;
        let stat = Control::open(leaf.directory.as_fd(), &leaf.identity, Kind::Stat)?;
        let procs = Control::open(leaf.directory.as_fd(), &leaf.identity, Kind::Procs)?;
        let events = EventsV1::open(leaf.directory.as_fd()).map_err(|error| error.to_string())?;
        let mut limits = Vec::with_capacity(4);
        for (kind, expected) in expected {
            limits.push(Limit { control: Control::open(leaf.directory.as_fd(), &leaf.identity, kind)?, expected });
        }
        let result = Self { owner, permit, leaf, domain, subtree, stat, procs, limits, events,
            cleanup_deadline, admission_stopped: Cell::new(false), child_attempted: Cell::new(false),
            cleanup_finished: Cell::new(false), retirement_attempted: Cell::new(false) };
        result.check_unpopulated_domain()?;
        for limit in &result.limits {
            result.owner.check_admission()?;
            result.permit.require_owner(&result.owner)?;
            result.leaf.check()?;
            limit.control.check(result.leaf.directory.as_fd(), &result.leaf.identity)?;
            require(unsafe { libc::write(limit.control.file.as_raw_fd(), limit.expected.as_ptr().cast(),
                limit.expected.len()) } == limit.expected.len() as isize,
                "native containment limit write failed or is uncertain; no retry")?;
            require(limit.control.read(result.leaf.directory.as_fd(), &result.leaf.identity)? == limit.expected,
                "native containment limit readback differs from its signed value")?;
            result.leaf.check()?;
            result.owner.check_admission()?;
            result.permit.require_owner(&result.owner)?;
        }
        result.check_admission()?;
        Ok(result)
    }

    fn check_domain(&self, require_empty: bool) -> Result<(), String> {
        self.leaf.check()?;
        require(self.domain.read(self.leaf.directory.as_fd(), &self.leaf.identity)? == b"domain\n",
            "native containment leaf is not a domain")?;
        let subtree = self.subtree.read(self.leaf.directory.as_fd(), &self.leaf.identity)?;
        require(subtree.is_empty() || subtree == b"\n",
            "native containment leaf has enabled child controllers")?;
        let stat = self.stat.read(self.leaf.directory.as_fd(), &self.leaf.identity)?;
        require(stat.last() == Some(&b'\n'), "native containment cgroup.stat is incomplete")?;
        let text = std::str::from_utf8(&stat).map_err(|_| "native containment cgroup.stat is invalid")?;
        let mut descendants = None;
        let mut dying = None;
        for line in text.lines() {
            let mut fields = line.split_ascii_whitespace();
            let name = fields.next().ok_or("native containment cgroup.stat lacks a name")?;
            let value = fields.next().ok_or("native containment cgroup.stat lacks a value")?;
            require(fields.next().is_none(), "native containment cgroup.stat has extra fields")?;
            let target = match name { "nr_descendants" => Some(&mut descendants),
                "nr_dying_descendants" => Some(&mut dying), _ => None };
            if let Some(target) = target {
                require(target.is_none() && value == "0", "native containment leaf has descendants")?;
                *target = Some(());
            }
        }
        require(descendants.is_some() && dying.is_some(),
            "native containment leaf has child cgroups")?;
        if require_empty {
            require(!populated(&self.events)?, "native containment new leaf is not empty")?;
        }
        self.leaf.check()
    }

    fn check_unpopulated_domain(&self) -> Result<(), String> { self.check_domain(true) }

    pub(super) fn check_admission(&self) -> Result<(), String> {
        require(!self.child_attempted.get(), "native containment child creation was already attempted")?;
        self.check_retained_admission(true)
    }

    fn check_retained_admission(&self, require_empty: bool) -> Result<(), String> {
        require(!self.admission_stopped.replace(true) && !self.leaf.kill_attempted.get(),
            "native containment admission is permanently stopped")?;
        self.owner.check_admission()?;
        self.permit.require_owner(&self.owner)?;
        self.check_domain(require_empty)?;
        for limit in &self.limits {
            require(limit.control.read(self.leaf.directory.as_fd(), &self.leaf.identity)? == limit.expected,
                "native containment admitted resource limit changed")?;
            self.owner.check_admission()?;
        }
        self.leaf.check()?;
        self.permit.require_owner(&self.owner)?;
        self.owner.check_admission()?;
        self.admission_stopped.set(false);
        Ok(())
    }

    pub(super) fn owner(&self) -> &Arc<StartOwner> { &self.owner }
    pub(super) fn outcome_permit(&self) -> Result<&StartPermit, String> {
        require(self.cleanup_finished.get() && self.retirement_attempted.get(),
            "native outcome lacks consumed cleanup and retirement")?;
        self.permit.check_cleanup_integrity()?;
        Ok(&self.permit)
    }

    /// Only the consuming BlockedChild constructor uses this one-shot borrow.
    /// The attempt is consumed before clone3, including syscall failure.
    pub(super) fn begin_child(&self) -> Result<BorrowedFd<'_>, String> {
        self.check_admission()?;
        require(!self.child_attempted.replace(true), "native containment child attempt is consumed")?;
        self.leaf.check()?;
        Ok(self.leaf.directory.as_fd())
    }

    pub(super) fn check_child_admission(&self, leader: libc::pid_t) -> Result<(), String> {
        require(self.child_attempted.get(), "native containment has no child attempt")?;
        self.check_retained_admission(false)?;
        require(leader > 0 && self.procs.read(self.leaf.directory.as_fd(), &self.leaf.identity)?
            == format!("{leader}\n").as_bytes(),
            "native blocked child is not the sole actual member of its retained leaf")?;
        self.leaf.check()
    }

    /// Observation only after the child owner's positively observed execution.
    /// It cannot claim, clone, alter a limit, or renew any admission allowance.
    pub(super) fn check_continuation(&self, leader: libc::pid_t) -> Result<(), String> {
        require(self.child_attempted.get() && !self.cleanup_finished.get()
            && !self.leaf.kill_attempted.get(), "native containment continuation is stopped")?;
        self.owner.check_cleanup_scope()?;
        self.permit.check_cleanup_integrity()?;
        require(boottime()? < self.owner.stop_boottime_ns(),
            "native containment signed stop boundary ended")?;
        self.check_domain(false)?;
        for limit in &self.limits {
            require(limit.control.read(self.leaf.directory.as_fd(), &self.leaf.identity)? == limit.expected,
                "native running resource limit differs from its signed original")?;
        }
        // Up to 4096 admitted tasks can exceed the scalar-control bound.
        self.procs.check(self.leaf.directory.as_fd(), &self.leaf.identity)?;
        let members = read_with_bound(self.procs.file.as_fd(), 65_536)?;
        self.procs.check(self.leaf.directory.as_fd(), &self.leaf.identity)?;
        require(leader > 0 && members.last() == Some(&b'\n'),
            "native running leaf member observation is incomplete")?;
        let text = std::str::from_utf8(&members).map_err(|_| "native running leaf member is not ASCII")?;
        let mut found = false;
        let mut count = 0u32;
        for line in text.lines() {
            let pid = line.parse::<libc::pid_t>().map_err(|_| "native running leaf member is invalid")?;
            require(pid > 0 && line == pid.to_string(), "native running leaf member is noncanonical")?;
            count = count.checked_add(1).ok_or("native running member count overflow")?;
            require(count <= self.owner.constraints().resources.pids_max,
                "native running leaf exceeds its signed task bound")?;
            found |= pid == leader;
        }
        require(found, "native running leader left its retained leaf")?;
        self.leaf.check()?;
        self.permit.check_cleanup_integrity()?;
        require(boottime()? < self.owner.stop_boottime_ns(),
            "native running observation missed its signed stop boundary")
    }

    pub(super) fn cleanup_borrow(&self) -> Result<ContainmentCleanupBorrow<'_>, String> {
        let result = self.cleanup_view();
        result.check()?;
        Ok(result)
    }

    // Reborrowing an already sealed owner does not assert current validity.
    // Guardian::arm must check this view before duplicating its fixed controls.
    pub(super) fn cleanup_view(&self) -> ContainmentCleanupBorrow<'_> {
        ContainmentCleanupBorrow { owner: self }
    }

    pub(super) fn attempt_emergency_kill(&self) -> Result<bool, String> { self.leaf.kill_once() }

    pub(super) fn check_retirement(&self) -> Result<(), String> {
        self.owner.check_cleanup_scope()?;
        require(self.owner.constraints().containment.retirement_profile.as_deref()
            == Some("remove-empty-owned-leaf-v1") && self.cleanup_finished.get()
            && self.child_attempted.get() && !self.retirement_attempted.get(),
            "native cgroup retirement lacks its signed one-use cleanup scope")?;
        self.permit.check_cleanup_integrity()?;
        require(boottime()? < self.cleanup_deadline, "native cgroup retirement deadline missed")?;
        self.check_domain(true)?;
        require(self.procs.read(self.leaf.directory.as_fd(), &self.leaf.identity)?.is_empty(),
            "native cgroup retirement still has processes")?;
        self.leaf.check()?;
        self.permit.check_cleanup_integrity()?;
        require(boottime()? < self.cleanup_deadline, "native cgroup closing retirement deadline missed")
    }

    /// Only the exact new leaf may be removed, once, after genuine cleanup.
    /// No recursive deletion, adoption, retry, journal reset or Drop removal.
    pub(super) fn retire(&self) -> Result<CgroupRemoval, String> {
        self.check_retirement()?;
        self.retirement_attempted.set(true);
        let removed = unsafe { libc::unlinkat(self.leaf.parent.as_raw_fd(), self.leaf.name.as_ptr(), libc::AT_REMOVEDIR) };
        require(removed == 0, "native owned cgroup removal failed or is uncertain; no retry")?;
        // Removal is a namespace event, not synchronous memory reclamation.
        // Keep the original directory FD while proving the exact name absent.
        self.owner.check_cleanup_scope()?;
        self.permit.check_cleanup_integrity()?;
        require(directory(self.leaf.parent.as_fd())? == self.leaf.parent_identity
            && directory(self.leaf.directory.as_fd())? == self.leaf.identity,
            "native cgroup held parent or leaf changed during removal")?;
        let mut named: libc::stat = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::fstatat(self.leaf.parent.as_raw_fd(), self.leaf.name.as_ptr(),
            &mut named, libc::AT_SYMLINK_NOFOLLOW) };
        let error = std::io::Error::last_os_error();
        require(result == -1 && error.raw_os_error() == Some(libc::ENOENT),
            "native removed cgroup name is not independently absent")?;
        let observed = boottime()?;
        require(observed < self.cleanup_deadline, "native cgroup removed but closing deadline missed")?;
        Ok(CgroupRemoval { parent_device: self.leaf.parent_identity.device(),
            parent_inode: self.leaf.parent_identity.inode(), device: self.leaf.identity.device(),
            inode: self.leaf.identity.inode(),
            name: self.leaf.name.to_str().map_err(|_| "native cgroup retained name invalid")?.to_owned(),
            observed_boottime_ns: observed })
    }

    pub(super) fn kill_and_wait_empty(&self) -> Result<LeafEmpty, String> {
        self.admission_stopped.set(true);
        // Admission revocation/expiry, journal damage and a passed cleanup bound
        // cannot prevent this first exact-descriptor emergency kill attempt.
        let acknowledged = self.leaf.kill_once()?;
        require(!self.cleanup_finished.replace(true), "native containment cleanup observation was already consumed")?;
        let integrity = self.permit.check_cleanup_integrity();
        let mut last = boottime()?;
        loop {
            require(last < self.cleanup_deadline,
                "native containment cleanup deadline missed; kill attempted, outcome not confirmed")?;
            self.leaf.check()?;
            let (live, original) = populated_original(&self.events)?;
            self.leaf.check()?;
            let now = boottime()?;
            require(now >= last && now < self.cleanup_deadline,
                "native containment cleanup clock ended or moved backwards")?;
            if !live {
                integrity?;
                self.permit.check_cleanup_integrity()?;
                self.leaf.check()?;
                let closed = boottime()?;
                require(closed >= now && closed < self.cleanup_deadline,
                    "native containment closing empty observation missed its deadline")?;
                return Ok(LeafEmpty { observed_boottime_ns: closed, kill_acknowledged: acknowledged, original });
            }
            let remaining = self.cleanup_deadline - now;
            let timeout = ((remaining.min(100_000_000) + 999_999) / 1_000_000) as libc::c_int;
            let mut poll = libc::pollfd { fd: self.events.poll_fd().as_raw_fd(), events: libc::POLLPRI, revents: 0 };
            let ready = unsafe { libc::poll(&mut poll, 1, timeout) };
            require(ready >= 0 && poll.revents & (libc::POLLHUP | libc::POLLNVAL) == 0
                && (poll.revents & libc::POLLERR == 0 || poll.revents & libc::POLLPRI != 0),
                "native containment cleanup poll failed; kill is not retried")?;
            self.leaf.check()?;
            last = boottime()?;
            require(last >= now, "native containment cleanup boottime moved backwards")?;
        }
    }
}

/// Nonconstructible outside this module. A guardian may duplicate these exact
/// originals before its fork; neither a digest nor an arbitrary FD creates it.
/// Integrity is deliberately independent of current admission/deadline so an
/// expired grant never disables emergency termination of the retained leaf.
pub(super) struct ContainmentCleanupBorrow<'owner> { owner: &'owner ContainmentOwner }
impl ContainmentCleanupBorrow<'_> {
    pub(super) fn check(&self) -> Result<(), String> {
        self.owner.leaf.check()?;
        self.owner.events.check().map_err(|error| error.to_string())?;
        self.owner.permit.check_cleanup_integrity()?;
        self.owner.leaf.check()
    }
    pub(super) fn directory(&self) -> BorrowedFd<'_> { self.owner.leaf.directory.as_fd() }
    pub(super) fn kill(&self) -> BorrowedFd<'_> { self.owner.leaf.kill.file.as_fd() }
    pub(super) fn events(&self) -> BorrowedFd<'_> { self.owner.events.poll_fd() }
}

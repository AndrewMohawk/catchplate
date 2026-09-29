//! Irreversible, source-fixed native serving identity, not release admission.
//! Prepared resources share an actual private origin; no caller UID, FD,
//! successful-check DTO or deadline renewal can substitute for this owner.

use std::fs;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

pub const UID: libc::uid_t = 65534;
pub const GID: libc::gid_t = 65534;
const CAP_VERSION: u32 = 0x2008_0522;
const SECUREBITS: libc::c_ulong = 0xef; // NOROOT, NO_SETUID_FIXUP, locked KEEP_CAPS off, no ambient raise; all locked.
const PR_CAP_AMBIENT: libc::c_int = 47;
const AMBIENT_IS_SET: libc::c_ulong = 1;
const AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

#[repr(C)]
struct CapHeader { version: u32, pid: libc::c_int }
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData { effective: u32, permitted: u32, inheritable: u32 }

struct Origin { pid: libc::pid_t, deadline: u64, last_capability: u32 }
pub struct Prepared { origin: Arc<Origin> }
pub struct Owner { origin: Arc<Origin>, poisoned: AtomicBool }
pub(crate) struct Association { origin: Arc<Origin> }

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native permanent serving identity is unavailable".to_owned()) }
}
fn now() -> Result<u64, String> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } == 0
        && value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec))?;
    (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| "native privilege clock overflow".to_owned())
}
fn ids() -> Result<([libc::uid_t; 3], [libc::gid_t; 3]), String> {
    let mut uid = [0; 3]; let mut gid = [0; 3];
    require(unsafe { libc::getresuid(uid.as_mut_ptr(), uid.as_mut_ptr().add(1), uid.as_mut_ptr().add(2)) } == 0
        && unsafe { libc::getresgid(gid.as_mut_ptr(), gid.as_mut_ptr().add(1), gid.as_mut_ptr().add(2)) } == 0)?;
    Ok((uid, gid))
}
fn only_thread(pid: libc::pid_t) -> Result<(), String> {
    require(unsafe { libc::syscall(libc::SYS_gettid) } == pid as libc::c_long)?;
    let mut tasks = fs::read_dir("/proc/self/task").map_err(|_| "native task inventory unavailable")?;
    let task = tasks.next().ok_or("native task inventory empty")?
        .map_err(|_| "native task inventory unavailable")?;
    require(task.file_name() == pid.to_string().as_str() && tasks.next().is_none())
}
fn last_capability() -> Result<u32, String> {
    // Finite ABI inventory, including future contiguous capabilities through
    // 63. An unknown wider ABI fails rather than retaining an unchecked bit.
    for capability in 0u32..=64 {
        let value = unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability as libc::c_ulong, 0, 0, 0) };
        if value < 0 {
            require(capability > 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL))?;
            return Ok(capability - 1);
        }
        require(value == 0 || value == 1)?;
    }
    Err("native capability ABI exceeds fixed inventory".to_owned())
}
fn capabilities_zero() -> Result<(), String> {
    let mut header = CapHeader { version: CAP_VERSION, pid: 0 };
    let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
    require(unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } == 0
        && header.version == CAP_VERSION
        && data.iter().all(|entry| entry.effective == 0 && entry.permitted == 0 && entry.inheritable == 0))
}

impl Prepared {
    pub fn open(deadline: u64) -> Result<Self, String> {
        let pid = unsafe { libc::getpid() };
        require(pid > 0 && deadline > now()? && ids()? == ([0; 3], [0; 3]))?;
        only_thread(pid)?;
        let owner = Self { origin: Arc::new(Origin { pid, deadline, last_capability: last_capability()? }) };
        owner.check()?;
        Ok(owner)
    }
    pub fn check(&self) -> Result<(), String> {
        require(unsafe { libc::getpid() } == self.origin.pid && now()? < self.origin.deadline
            && ids()? == ([0; 3], [0; 3]) && last_capability()? == self.origin.last_capability)?;
        only_thread(self.origin.pid)
    }
    pub fn deadline(&self) -> u64 { self.origin.deadline }

    /// One-way transition. Any error aborts cold startup; there is no restore,
    /// rejoin or old-profile fallback after a partially applied syscall.
    pub fn drop_permanently(self) -> Result<Arc<Owner>, String> {
        self.check()?;
        require(unsafe { libc::setgroups(0, std::ptr::null()) } == 0
            && unsafe { libc::prctl(PR_CAP_AMBIENT, AMBIENT_CLEAR_ALL, 0, 0, 0) } == 0)?;
        for capability in 0..=self.origin.last_capability {
            require(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability as libc::c_ulong, 0, 0, 0) } == 0)?;
        }
        require(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, SECUREBITS, 0, 0, 0) } == 0
            && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0
            && unsafe { libc::setresgid(GID, GID, GID) } == 0
            && unsafe { libc::setresuid(UID, UID, UID) } == 0)?;
        let header = CapHeader { version: CAP_VERSION, pid: 0 };
        let data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
        require(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } == 0
            && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0)?;
        let owner = Arc::new(Owner { origin: self.origin, poisoned: AtomicBool::new(false) });
        owner.check()?;
        only_thread(owner.origin.pid)?;
        Ok(owner)
    }
}

impl Owner {
    pub fn deadline(&self) -> u64 { self.origin.deadline }
    pub fn check(&self) -> Result<(), String> {
        // PID first: never acquire inherited userspace synchronization after a
        // fork. Every serving thread independently checks its own credentials.
        let result = (|| {
            require(!self.poisoned.load(Ordering::Acquire)
                && unsafe { libc::getpid() } == self.origin.pid
                && now()? < self.origin.deadline && ids()? == ([UID; 3], [GID; 3]))?;
            require(unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 0
                && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1
                && unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0
                && unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } == SECUREBITS as libc::c_int)?;
            capabilities_zero()?;
            require(last_capability()? == self.origin.last_capability)?;
            for capability in 0..=self.origin.last_capability {
                require(unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability as libc::c_ulong, 0, 0, 0) } == 0
                    && unsafe { libc::prctl(PR_CAP_AMBIENT, AMBIENT_IS_SET, capability as libc::c_ulong, 0, 0) } == 0)?;
            }
            require(now()? < self.origin.deadline)
        })();
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }
}

impl Association {
    pub(crate) fn capture(prepared: &Prepared) -> Result<Self, String> {
        prepared.check()?;
        Ok(Self { origin: Arc::clone(&prepared.origin) })
    }
    pub(crate) fn require(&self, owner: &Owner) -> Result<(), String> {
        require(Arc::ptr_eq(&self.origin, &owner.origin))?;
        owner.check()
    }
}

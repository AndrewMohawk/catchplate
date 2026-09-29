//! Fixed post-clone guardian. No allocation, path selected by a caller, exec,
//! descriptor transfer, task creation or admission renewal occurs in this loop.

use std::mem::zeroed;
use std::os::fd::RawFd;

pub(super) const LEAF: usize = 0;
pub(super) const KILL: usize = 1;
pub(super) const EVENTS: usize = 2;
pub(super) const PARENT: usize = 3;
pub(super) const LEADER: usize = 4;
pub(super) const CHANNEL: usize = 5;
pub(super) const STOP: usize = 6;
pub(super) const CLEANUP: usize = 7;
pub(super) const FRAME_BYTES: usize = 64;
const MAGIC: &[u8; 8] = b"SWNGAR1\0";
const STATX_MNT_ID: u32 = 0x1000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Identity {
    device: u64, inode: u64, mount: u64, mode: u32, uid: u32, gid: u32,
}

// Only the parent guardian owner constructs this, from a genuine child borrow.
// Inherited scalar data does not grant anyone a constructor for an owner.
pub(super) struct Snapshot {
    pub(super) fds: [RawFd; 8],
    pub(super) identities: [Identity; 3],
    pub(super) operation: [u8; 32],
    pub(super) stop: u64,
    pub(super) cleanup: u64,
}

pub(super) fn now() -> Option<u64> {
    let mut value: libc::timespec = unsafe { zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0
        || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) { return None; }
    (value.tv_sec as u64).checked_mul(1_000_000_000)?
        .checked_add(value.tv_nsec as u64).filter(|value| *value != 0)
}

pub(super) fn identity(fd: RawFd, name: Option<&[u8]>) -> Option<Identity> {
    let mut value: libc::statx = unsafe { zeroed() };
    let (path, flags) = match name {
        Some(name) => (name.as_ptr(), libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT),
        None => (b"\0".as_ptr(), libc::AT_EMPTY_PATH),
    };
    if unsafe { libc::statx(fd, path.cast(), flags | libc::AT_STATX_SYNC_AS_STAT,
        libc::STATX_BASIC_STATS | STATX_MNT_ID, &mut value) } != 0
        || value.stx_mask & libc::STATX_BASIC_STATS != libc::STATX_BASIC_STATS
        || value.stx_mask & STATX_MNT_ID == 0 || value.stx_ino == 0
        || value.stx_uid != 0 || value.stx_gid != 0 || value.stx_mode & 0o022 != 0
    { return None; }
    Some(Identity { device: libc::makedev(value.stx_dev_major, value.stx_dev_minor),
        inode: value.stx_ino, mount: value.stx_mnt_id, mode: u32::from(value.stx_mode),
        uid: value.stx_uid, gid: value.stx_gid })
}

pub(super) fn controls(snapshot: &Snapshot) -> bool {
    let leaf = snapshot.fds[LEAF];
    let expected = &snapshot.identities;
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(leaf, &mut filesystem) } != 0
        || filesystem.f_type != 0x6367_7270
        || expected[LEAF].mode & libc::S_IFMT != libc::S_IFDIR
        || identity(leaf, None) != Some(expected[LEAF]) { return false; }
    for (index, name, access) in [(KILL, &b"cgroup.kill\0"[..], libc::O_WRONLY),
        (EVENTS, &b"cgroup.events\0"[..], libc::O_RDONLY)] {
        let fd = snapshot.fds[index];
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let fdflags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || flags & libc::O_ACCMODE != access
            || flags & (libc::O_APPEND | libc::O_ASYNC) != 0
            || fdflags < 0 || fdflags & libc::FD_CLOEXEC == 0
            || expected[index].mode & libc::S_IFMT != libc::S_IFREG
            || expected[index].device != expected[LEAF].device
            || expected[index].mount != expected[LEAF].mount
            || identity(fd, None) != Some(expected[index])
            || identity(leaf, Some(name)) != Some(expected[index]) { return false; }
    }
    true
}

pub(super) fn live(fd: RawFd) -> bool {
    let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    (unsafe { libc::poll(&mut poll, 1, 0) }) == 0 && poll.revents == 0
}

// A cgroup events read is bounded to two preads and a fixed stack buffer. No
// retry means a partial/interrupted/changed record is uncertainty, not empty.
fn empty(snapshot: &Snapshot) -> Option<bool> {
    if !controls(snapshot) { return None; }
    let mut buffer = [0u8; 4096];
    let count = unsafe { libc::pread(snapshot.fds[EVENTS], buffer.as_mut_ptr().cast(),
        buffer.len(), 0) };
    if count <= 0 || count as usize >= buffer.len() { return None; }
    let count = count as usize;
    let mut tail = 0u8;
    if unsafe { libc::pread(snapshot.fds[EVENTS], (&mut tail as *mut u8).cast(),
        1, count as libc::off_t) } != 0 || buffer[count - 1] != b'\n' { return None; }
    let mut result = None;
    for line in buffer[..count].split(|byte| *byte == b'\n') {
        if line.is_empty() { continue; }
        if !line.is_ascii() { return None; }
        let mut fields = line.split(|byte| byte.is_ascii_whitespace()).filter(|part| !part.is_empty());
        let name = fields.next()?;
        let value = fields.next()?;
        if fields.next().is_some() { return None; }
        if name == b"populated" {
            if result.is_some() { return None; }
            result = match value { b"0" => Some(true), b"1" => Some(false), _ => return None };
        }
    }
    if !controls(snapshot) { return None; }
    result
}

pub(super) fn frame(operation: &[u8; 32], kind: u8, flags: u8, observed: u64)
    -> [u8; FRAME_BYTES]
{
    let mut raw = [0u8; FRAME_BYTES];
    raw[..8].copy_from_slice(MAGIC);
    raw[8..40].copy_from_slice(operation);
    raw[40] = kind;
    raw[41] = flags;
    raw[48..56].copy_from_slice(&observed.to_be_bytes());
    raw
}

pub(super) fn decode(raw: &[u8; FRAME_BYTES], operation: &[u8; 32], kind: u8)
    -> Option<(u8, u64)>
{
    if &raw[..8] != MAGIC || &raw[8..40] != operation || raw[40] != kind
        || raw[42..48].iter().chain(raw[56..].iter()).any(|value| *value != 0)
        || (kind == 1 && raw[41] != 0) || (kind == 2 && raw[41] & !3 != 0) { return None; }
    let observed = u64::from_be_bytes(raw[48..56].try_into().ok()?);
    if observed == 0 { return None; }
    Some((raw[41], observed))
}

fn send(snapshot: &Snapshot, kind: u8, flags: u8, observed: u64) -> bool {
    let raw = frame(&snapshot.operation, kind, flags, observed);
    (unsafe { libc::send(snapshot.fds[CHANNEL], raw.as_ptr().cast(), raw.len(),
        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) }) == raw.len() as isize
}

fn close_except(fds: &[RawFd; 8]) -> bool {
    // Sorting a fixed stack array allocates nothing. Closing gaps never closes
    // a retained control, and no inherited signing/token/journal FD survives.
    let mut sorted = *fds;
    sorted.sort_unstable();
    if sorted[0] < 3 || sorted.windows(2).any(|pair| pair[0] == pair[1]) { return false; }
    let mut first = 0u32;
    for fd in sorted {
        if first < fd as u32 && unsafe { libc::syscall(libc::SYS_close_range,
            first, fd as u32 - 1, 0u32) } != 0 { return false; }
        first = fd as u32 + 1;
    }
    (unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32) }) == 0
}

fn terminate(snapshot: &Snapshot) -> ! {
    // No current admission/journal check or deadline gates the emergency
    // attempt. Only the exact inherited leaf/control association is consulted.
    let acknowledged = controls(snapshot) && unsafe {
        libc::write(snapshot.fds[KILL], b"1".as_ptr().cast(), 1)
    } == 1;
    let mut previous = now();
    while let Some(instant) = previous {
        if instant >= snapshot.cleanup { break; }
        match empty(snapshot) {
            Some(true) => {
                if let Some(closed) = now() {
                    if closed >= instant && closed < snapshot.cleanup {
                        let _ = send(snapshot, 2, 2 | u8::from(acknowledged), closed);
                        unsafe { libc::_exit(0) }
                    }
                }
                break;
            }
            Some(false) => {}
            None => break,
        }
        let mut polls = [
            libc::pollfd { fd: snapshot.fds[CLEANUP], events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: snapshot.fds[EVENTS], events: libc::POLLPRI, revents: 0 },
        ];
        // The absolute timer remains authoritative across suspend. The bounded
        // poll also detects errors without introducing a fresh timeout grant.
        let result = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 100) };
        if result < 0 || polls[0].revents != 0
            || polls[1].revents & (libc::POLLHUP | libc::POLLNVAL) != 0
            || (polls[1].revents & libc::POLLERR != 0 && polls[1].revents & libc::POLLPRI == 0) { break; }
        previous = now().filter(|value| *value >= instant);
    }
    if let Some(observed) = now() { let _ = send(snapshot, 2, u8::from(acknowledged), observed); }
    unsafe { libc::_exit(125) }
}

pub(super) fn run(snapshot: &Snapshot) -> ! {
    // Parent death must not kill this guardian: it is precisely what this
    // independently scheduled process must survive long enough to clean up.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || !close_except(&snapshot.fds) { terminate(snapshot); }
    let mut previous = match now() { Some(value) => value, None => terminate(snapshot) };
    if previous >= snapshot.stop || !controls(snapshot)
        || !live(snapshot.fds[PARENT]) || !live(snapshot.fds[LEADER])
        || !send(snapshot, 1, 0, previous) { terminate(snapshot); }
    loop {
        let mut polls = [
            libc::pollfd { fd: snapshot.fds[PARENT], events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: snapshot.fds[LEADER], events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: snapshot.fds[CHANNEL], events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: snapshot.fds[STOP], events: libc::POLLIN, revents: 0 },
        ];
        let result = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 100) };
        // Every channel message, EOF, pidfd terminal event, timer readiness,
        // signal interruption or poll error is a stop, never a command to exec.
        if result != 0 || polls.iter().any(|item| item.revents != 0) { terminate(snapshot); }
        let instant = match now() { Some(value) => value, None => terminate(snapshot) };
        if instant < previous || instant >= snapshot.stop || !controls(snapshot) { terminate(snapshot); }
        previous = instant;
    }
}

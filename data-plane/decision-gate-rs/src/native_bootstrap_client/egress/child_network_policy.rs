//! Fixed child-only controls for the separately signed manual-network profile.
//!
//! Called only on the syscall-only post-CLONE_NEWNET trampoline, after the
//! durable creation claim. No paths, values, descriptors or operations are
//! accepted from configuration. Failure exits that never-executed child.

use std::os::fd::RawFd;

const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;

unsafe fn close(fd: RawFd) { libc::syscall(libc::SYS_close, fd); }

unsafe fn proc_object(fd: RawFd, directory: bool) -> bool {
    let mut fs: libc::statfs = std::mem::zeroed();
    let mut stat: libc::stat = std::mem::zeroed();
    if libc::syscall(libc::SYS_fstatfs, fd, &mut fs as *mut libc::statfs) != 0
        || libc::syscall(libc::SYS_fstat, fd, &mut stat as *mut libc::stat) != 0 {
        return false;
    }
    fs.f_type as u64 == PROC_SUPER_MAGIC as u64 && stat.st_uid == 0 && stat.st_gid == 0
        && stat.st_mode & 0o022 == 0
        && stat.st_mode & libc::S_IFMT == if directory { libc::S_IFDIR } else { libc::S_IFREG }
}

unsafe fn directory(parent: RawFd, name: &'static [u8]) -> RawFd {
    let fd = libc::syscall(libc::SYS_openat, parent, name.as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0) as RawFd;
    if fd < 0 { return -1; }
    if !proc_object(fd, true) { close(fd); return -1; }
    fd
}

unsafe fn zero(parent: RawFd, name: &'static [u8]) -> bool {
    let fd = libc::syscall(libc::SYS_openat, parent, name.as_ptr(),
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0) as RawFd;
    if fd < 0 { return false; }
    let mut bytes = [0u8; 16];
    let ok = proc_object(fd, false)
        && libc::syscall(libc::SYS_write, fd, b"0\n".as_ptr(), 2usize) == 2
        && libc::syscall(libc::SYS_lseek, fd, 0, libc::SEEK_SET) == 0
        && libc::syscall(libc::SYS_read, fd, bytes.as_mut_ptr(), bytes.len()) == 2
        && bytes[0] == b'0' && bytes[1] == b'\n'
        && proc_object(fd, false);
    close(fd);
    ok
}

unsafe fn family(net: RawFd, name: &'static [u8], ipv6: bool) -> bool {
    let family = directory(net, name);
    if family < 0 { return false; }
    // IPv4 ip_forward can reset other IPv4 settings; set it first, then set
    // every admitted all/default value explicitly under this child's netns.
    if !ipv6 && !zero(family, b"ip_forward\0") { close(family); return false; }
    let conf = directory(family, b"conf\0");
    close(family);
    if conf < 0 { return false; }
    for scope in [b"all\0".as_slice(), b"default\0".as_slice()] {
        let scoped = directory(conf, scope);
        if scoped < 0 { close(conf); return false; }
        let mut ok = zero(scoped, b"forwarding\0") && zero(scoped, b"accept_redirects\0");
        if ipv6 {
            ok = ok && zero(scoped, b"accept_ra\0") && zero(scoped, b"autoconf\0")
                && zero(scoped, b"router_solicitations\0") && zero(scoped, b"use_tempaddr\0");
        } else {
            ok = ok && zero(scoped, b"secure_redirects\0") && zero(scoped, b"send_redirects\0");
        }
        close(scoped);
        if !ok { close(conf); return false; }
    }
    close(conf);
    true
}

/// This is not a host sysctl API. The actual signed launch owner alone selects
/// it for the fresh child; the old never-started profile does not invoke it.
pub(super) unsafe fn apply() -> bool {
    let proc = directory(libc::AT_FDCWD, b"/proc\0");
    if proc < 0 { return false; }
    let sys = directory(proc, b"sys\0");
    close(proc);
    if sys < 0 { return false; }
    let net = directory(sys, b"net\0");
    close(sys);
    if net < 0 { return false; }
    let ok = family(net, b"ipv4\0", false) && family(net, b"ipv6\0", true);
    close(net);
    ok
}

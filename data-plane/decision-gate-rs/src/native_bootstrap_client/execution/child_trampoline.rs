//! Syscall-only post-clone path. Never allocate, unwind, log, acquire an
//! inherited runtime lock or drop parent Rust owners in this process.

use std::os::fd::RawFd;

/// Constructed from the retained filesystem/claim by child.rs before clone.
pub(super) struct Spec {
    pub(super) root: RawFd,
    pub(super) cwd: RawFd,
    pub(super) entry: RawFd,
    pub(super) gate: RawFd,
    pub(super) parent: RawFd,
    pub(super) stdin: RawFd,
    pub(super) stdout: RawFd,
    pub(super) stderr: RawFd,
    pub(super) keep: [RawFd; 8],
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) argv: *const *const libc::c_char,
    pub(super) envp: *const *const libc::c_char,
    pub(super) application_port: u16,
}

pub(super) const READY: &[u8; 8] = b"SWNEBLK1";

#[repr(C)]
struct Rights { header: libc::cmsghdr, descriptors: [RawFd; 2] }

unsafe fn application_listener(gate: RawFd, port: u16) -> bool {
    if port < 1024 { return false; }
    let control=libc::syscall(libc::SYS_socket,libc::AF_INET,libc::SOCK_DGRAM|libc::SOCK_CLOEXEC,0) as RawFd;
    if control<0 { return false; }
    let mut request:libc::ifreq=std::mem::zeroed();
    request.ifr_name[0]=b'l' as libc::c_char; request.ifr_name[1]=b'o' as libc::c_char;
    if libc::syscall(libc::SYS_ioctl,control,libc::SIOCGIFFLAGS,&mut request as *mut libc::ifreq)!=0
        || request.ifr_ifru.ifru_flags & libc::IFF_UP as i16 !=0
        || request.ifr_ifru.ifru_flags & libc::IFF_LOOPBACK as i16 ==0 { return false; }
    request.ifr_ifru.ifru_flags |=libc::IFF_UP as i16;
    if libc::syscall(libc::SYS_ioctl,control,libc::SIOCSIFFLAGS,&request as *const libc::ifreq)!=0
        || libc::syscall(libc::SYS_ioctl,control,libc::SIOCGIFFLAGS,&mut request as *mut libc::ifreq)!=0
        || request.ifr_ifru.ifru_flags & libc::IFF_UP as i16 ==0
        || libc::syscall(libc::SYS_close,control)!=0 { return false; }
    let listener=libc::syscall(libc::SYS_socket,libc::AF_INET,
        libc::SOCK_STREAM|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK,libc::IPPROTO_TCP) as RawFd;
    if listener<0 { return false; }
    let address=libc::sockaddr_in {sin_family:libc::AF_INET as u16,sin_port:port.to_be(),
        sin_addr:libc::in_addr{s_addr:u32::from_ne_bytes([127,0,0,1])},sin_zero:[0;8]};
    if libc::syscall(libc::SYS_bind,listener,&address as *const libc::sockaddr_in,std::mem::size_of::<libc::sockaddr_in>())!=0
        || libc::syscall(libc::SYS_listen,listener,1)!=0 { return false; }
    let mut control=[0usize;3];
    let header=control.as_mut_ptr().cast::<libc::cmsghdr>();
    (*header).cmsg_len=std::mem::size_of::<libc::cmsghdr>()+std::mem::size_of::<RawFd>();
    (*header).cmsg_level=libc::SOL_SOCKET;(*header).cmsg_type=libc::SCM_RIGHTS;
    *control.as_mut_ptr().cast::<u8>().add(std::mem::size_of::<libc::cmsghdr>()).cast::<RawFd>()=listener;
    let mut iov=libc::iovec{iov_base:super::child_network::LISTENER.as_ptr().cast_mut().cast(),iov_len:8};
    let mut message:libc::msghdr=std::mem::zeroed();message.msg_iov=&mut iov;message.msg_iovlen=1;
    message.msg_control=control.as_mut_ptr().cast();message.msg_controllen=std::mem::size_of_val(&control);
    let sent=libc::syscall(libc::SYS_sendmsg,gate,&message as *const libc::msghdr,libc::MSG_NOSIGNAL);
    sent==8 && libc::syscall(libc::SYS_close,listener)==0
}

unsafe fn network_originals(gate: RawFd) -> bool {
    let filter = libc::syscall(libc::SYS_socket, libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, libc::NETLINK_NETFILTER) as RawFd;
    let route = libc::syscall(libc::SYS_socket, libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, libc::NETLINK_ROUTE) as RawFd;
    if filter < 0 || route < 0 { return false; }
    let mut address: libc::sockaddr_nl = std::mem::zeroed();
    address.nl_family = libc::AF_NETLINK as u16;
    if libc::syscall(libc::SYS_bind, filter, &address as *const libc::sockaddr_nl,
        std::mem::size_of::<libc::sockaddr_nl>()) != 0
        || libc::syscall(libc::SYS_bind, route, &address as *const libc::sockaddr_nl,
            std::mem::size_of::<libc::sockaddr_nl>()) != 0 { return false; }
    let mut rights = Rights { header: libc::cmsghdr {
        cmsg_len: std::mem::size_of::<Rights>(), cmsg_level: libc::SOL_SOCKET, cmsg_type: libc::SCM_RIGHTS,
    }, descriptors: [filter, route] };
    let mut iov = libc::iovec { iov_base: super::child_network::SOCKETS.as_ptr().cast_mut().cast(), iov_len: 8 };
    let mut message: libc::msghdr = std::mem::zeroed();
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = (&mut rights as *mut Rights).cast();
    message.msg_controllen = std::mem::size_of::<Rights>();
    let sent = libc::syscall(libc::SYS_sendmsg, gate, &message as *const libc::msghdr, libc::MSG_NOSIGNAL);
    let closed_filter = libc::syscall(libc::SYS_close, filter);
    let closed_route = libc::syscall(libc::SYS_close, route);
    // These privileged sockets never reach the unprivileged gate or ELF.
    sent == 8 && closed_filter == 0 && closed_route == 0
}

unsafe fn die() -> ! {
    loop {
        libc::syscall(libc::SYS_exit_group, 127);
        libc::syscall(libc::SYS_exit, 127);
    }
}

unsafe fn parent_alive(fd: RawFd) -> bool {
    let mut descriptor = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let timeout = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    libc::syscall(libc::SYS_ppoll, &mut descriptor as *mut libc::pollfd, 1usize,
        &timeout as *const libc::timespec, std::ptr::null::<u64>(), 8usize) == 0
        && descriptor.revents == 0
}

unsafe fn parent_death(fd: RawFd) -> bool {
    // The pidfd names the actual creating THREAD, not a numeric PID hint.
    // Poll closes the set-PDEATHSIG-after-parent-death race even in NEWPID.
    let mut observed = 0i32;
    libc::syscall(libc::SYS_prctl, libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == 0
        && libc::syscall(libc::SYS_prctl, libc::PR_GET_PDEATHSIG, &mut observed as *mut i32,
            0, 0, 0) == 0 && observed == libc::SIGKILL
        && parent_alive(fd)
}

unsafe fn close_except(keep: *const RawFd, count: usize) -> bool {
    let mut first = 3u32;
    let mut index = 0usize;
    while index < count {
        let retained = *keep.add(index);
        if retained < 3 || (index != 0 && retained <= *keep.add(index - 1)) { return false; }
        let fd = retained as u32;
        if first < fd && libc::syscall(libc::SYS_close_range, first, fd - 1, 0u32) != 0 {
            return false;
        }
        first = fd + 1;
        index += 1;
    }
    libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32) == 0
}

#[repr(C)]
struct SignalAction { handler: usize, flags: usize, restorer: usize, mask: u64 }

unsafe fn reset_signals() -> bool {
    // Linux x86_64/aarch64 kernel rt_sigaction ABI. No inherited ignored
    // disposition or userspace handler may survive into the new program.
    let action = SignalAction { handler: 0, flags: 0, restorer: 0, mask: 0 };
    let mut signal = 1;
    while signal <= 64 {
        if signal != libc::SIGKILL && signal != libc::SIGSTOP
            && libc::syscall(libc::SYS_rt_sigaction, signal, &action as *const SignalAction,
                std::ptr::null_mut::<SignalAction>(), 8usize) != 0 { return false; }
        signal += 1;
    }
    let disabled = libc::stack_t { ss_sp: std::ptr::null_mut(), ss_flags: libc::SS_DISABLE, ss_size: 0 };
    libc::syscall(libc::SYS_sigaltstack, &disabled as *const libc::stack_t,
        std::ptr::null_mut::<libc::stack_t>()) == 0
}

#[repr(C)]
struct CapHeader { version: u32, pid: i32 }
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData { effective: u32, permitted: u32, inheritable: u32 }

unsafe fn restrict_identity(spec: &Spec) -> bool {
    // Fixed supported capability set through Linux CAP_CHECKPOINT_RESTORE.
    // A kernel adding another capability is refused rather than leaving it.
    if libc::syscall(libc::SYS_prctl, libc::PR_CAPBSET_READ, 41, 0, 0, 0) >= 0 { return false; }
    let mut capability = 0;
    while capability <= 40 {
        if libc::syscall(libc::SYS_prctl, libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0
            || libc::syscall(libc::SYS_prctl, libc::PR_CAPBSET_READ, capability, 0, 0, 0) != 0 {
            return false;
        }
        capability += 1;
    }
    const SECUREBITS: u32 = 1 | 2 | 4 | 8 | 32 | 64 | 128;
    if libc::syscall(libc::SYS_prctl, libc::PR_CAP_AMBIENT, 4, 0, 0, 0) != 0
        || libc::syscall(libc::SYS_prctl, libc::PR_SET_SECUREBITS, SECUREBITS, 0, 0, 0) != 0
        || libc::syscall(libc::SYS_setgroups, 0usize, std::ptr::null::<u32>()) != 0
        || libc::syscall(libc::SYS_setresgid, spec.gid, spec.gid, spec.gid) != 0
        || libc::syscall(libc::SYS_setresuid, spec.uid, spec.uid, spec.uid) != 0 { return false; }
    let header = CapHeader { version: 0x2008_0522, pid: 0 };
    let empty = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
    let mut observed = empty;
    if libc::syscall(libc::SYS_capset, &header as *const CapHeader, empty.as_ptr()) != 0
        || libc::syscall(libc::SYS_capget, &header as *const CapHeader, observed.as_mut_ptr()) != 0
        || observed[0].effective != 0 || observed[0].permitted != 0 || observed[0].inheritable != 0
        || observed[1].effective != 0 || observed[1].permitted != 0 || observed[1].inheritable != 0
        || libc::syscall(libc::SYS_prctl, libc::PR_GET_SECUREBITS, 0, 0, 0, 0) != SECUREBITS as libc::c_long
        || libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        || libc::syscall(libc::SYS_prctl, libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
        || libc::syscall(libc::SYS_prctl, libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
        || libc::syscall(libc::SYS_prctl, libc::PR_GET_DUMPABLE, 0, 0, 0, 0) != 0
        || libc::syscall(libc::SYS_getgroups, 0usize, std::ptr::null::<u32>()) != 0 { return false; }
    capability = 0;
    while capability <= 40 {
        if libc::syscall(libc::SYS_prctl, libc::PR_CAP_AMBIENT, 1, capability, 0, 0) != 0 {
            return false;
        }
        capability += 1;
    }
    let mut real = 0u32;
    let mut effective = 0u32;
    let mut saved = 0u32;
    if libc::syscall(libc::SYS_getresuid, &mut real as *mut u32, &mut effective as *mut u32,
        &mut saved as *mut u32) != 0 || real != spec.uid || effective != spec.uid || saved != spec.uid {
        return false;
    }
    if libc::syscall(libc::SYS_getresgid, &mut real as *mut u32, &mut effective as *mut u32,
        &mut saved as *mut u32) != 0 || real != spec.gid || effective != spec.gid || saved != spec.gid {
        return false;
    }
    // setresuid/setresgid can clear PDEATHSIG. Reset and recheck only AFTER
    // all credential changes; creator-thread pidfd cannot be PID-reused.
    parent_death(spec.parent)
}

pub(super) unsafe fn run(spec: &Spec) -> ! {
    if !parent_death(spec.parent) || !reset_signals() { die(); }
    // Sources are preduplicated above stdio before clone; no collision can
    // destroy a still-needed source. Only these three survive successful exec.
    if libc::syscall(libc::SYS_dup3, spec.stdin, 0, 0) != 0
        || libc::syscall(libc::SYS_dup3, spec.stdout, 1, 0) != 1
        || libc::syscall(libc::SYS_dup3, spec.stderr, 2, 0) != 2
        || !close_except(spec.keep.as_ptr(), spec.keep.len()) { die(); }
    if !super::child_network_policy::apply() || !network_originals(spec.gate)
        || (spec.application_port!=0 && !application_listener(spec.gate,spec.application_port))
        || libc::syscall(libc::SYS_sethostname, b"workload".as_ptr(), 8usize) != 0
        || libc::syscall(libc::SYS_setdomainname, b"\0".as_ptr(), 0usize) != 0 { die(); }
    // The detached tree is nonrecursive and already readonly/nosuid/nodev.
    // Attach only inside NEWNS, pivot without a writable staging directory,
    // detach the entire old root, then select the genuine held in-image cwd.
    if libc::syscall(libc::SYS_mount, std::ptr::null::<u8>(), b"/\0".as_ptr(),
        std::ptr::null::<u8>(), (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
        std::ptr::null::<u8>()) != 0
        || libc::syscall(libc::SYS_move_mount, spec.root, b"\0".as_ptr(), libc::AT_FDCWD,
            b"/\0".as_ptr(), 0x0000_0004u32) != 0
        || libc::syscall(libc::SYS_fchdir, spec.root) != 0
        || libc::syscall(libc::SYS_pivot_root, b".\0".as_ptr(), b".\0".as_ptr()) != 0
        || libc::syscall(libc::SYS_umount2, b".\0".as_ptr(), libc::MNT_DETACH) != 0
        || libc::syscall(libc::SYS_fchdir, spec.cwd) != 0 { die(); }
    let mut root: libc::statfs = std::mem::zeroed();
    if libc::syscall(libc::SYS_fstatfs, spec.root, &mut root as *mut libc::statfs) != 0
        || root.f_type != 0xe0f5_e1e2 || root.f_flags & 7 != 7 || root.f_flags & 8 != 0 { die(); }
    libc::syscall(libc::SYS_umask, 0o077u32);
    let core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if libc::syscall(libc::SYS_prlimit64, 0, libc::RLIMIT_CORE, &core as *const libc::rlimit,
        std::ptr::null_mut::<libc::rlimit>()) != 0 || !restrict_identity(spec) { die(); }
    // All original root/image/cgroup/TLS/key/namespace/socket owners are gone
    // in the child. Entry, gate and parent pidfd are CLOEXEC and fixed-purpose.
    let mut keep = [spec.entry, spec.gate, spec.parent];
    // Fixed three-element sorting, no library/allocator/panic path.
    if keep[0] > keep[1] { let old = keep[0]; keep[0] = keep[1]; keep[1] = old; }
    if keep[1] > keep[2] { let old = keep[1]; keep[1] = keep[2]; keep[2] = old; }
    if keep[0] > keep[1] { let old = keep[0]; keep[0] = keep[1]; keep[1] = old; }
    if !close_except(keep.as_ptr(), 3) || !parent_alive(spec.parent) { die(); }
    let empty_mask = 0u64;
    if libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK, &empty_mask as *const u64,
        std::ptr::null_mut::<u64>(), 8usize) != 0
        || libc::syscall(libc::SYS_sendto, spec.gate, READY.as_ptr(), READY.len(), libc::MSG_NOSIGNAL,
            std::ptr::null::<libc::sockaddr>(), 0u32) != READY.len() as libc::c_long { die(); }
    // There is deliberately NO sender of this command in the current source.
    // Guardian READY is not this command; networking has no substitute token.
    let mut command = [0u8; 2];
    if libc::syscall(libc::SYS_recvfrom, spec.gate, command.as_mut_ptr(), command.len(), 0,
        std::ptr::null_mut::<libc::sockaddr>(), std::ptr::null_mut::<libc::socklen_t>()) != 1
        || command[0] != b'X' || !parent_alive(spec.parent) { die(); }
    if !close_except(&spec.entry as *const RawFd, 1) { die(); }
    // A successful return is impossible. Parent acknowledgement must be the
    // genuine PTRACE_EVENT_EXEC stop, never gate EOF or disappearance of fd.
    libc::syscall(libc::SYS_execveat, spec.entry, b"\0".as_ptr(), spec.argv, spec.envp,
        libc::AT_EMPTY_PATH);
    die();
}

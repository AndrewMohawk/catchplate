//! Purpose-fixed, same-guest process inspection child. The private parent
//! launch is part of the TCB: sealed metadata is consistency, not authority.
mod confinement;
mod wire;
pub(crate) mod client;

use super::{guest_delivery, peer_measurement as peer};
use std::{fs::File, io, mem::{size_of, size_of_val, zeroed}, os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::{fs::{FileExt, MetadataExt}}, path::Path};
use wire::{require, Bootstrap, Phase, Request};

pub(crate) const INSPECTOR_ID: u32 = 64990;
const GATE_ID: u32 = 65534;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
const SO_PASSPIDFD: i32 = 76;
const SCM_PIDFD: i32 = 4;

fn other(error: impl std::fmt::Display) -> io::Error { io::Error::other(error.to_string()) }
fn now() -> io::Result<u64> { super::recovery::boottime_ns().map_err(other) }
fn option(fd: RawFd, name: i32) -> io::Result<i32> {
    let mut value = 0;
    let mut len = size_of::<i32>() as libc::socklen_t;
    require(unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name, (&mut value as *mut i32).cast(), &mut len) } == 0
        && len as usize == size_of::<i32>(), "inspect private socket option")?;
    Ok(value)
}
fn socket(fd: RawFd) -> io::Result<()> {
    require(option(fd, libc::SO_DOMAIN)? == libc::AF_UNIX
        && option(fd, libc::SO_TYPE)? == libc::SOCK_SEQPACKET
        && option(fd, libc::SO_PROTOCOL)? == 0
        && option(fd, libc::SO_ACCEPTCONN)? == 0, "inspector endpoint is not a connected Unix seqpacket socket")?;
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_un>() as libc::socklen_t;
    require(unsafe { libc::getpeername(fd, (&mut address as *mut libc::sockaddr_un).cast(), &mut len) } == 0
        && address.sun_family as i32 == libc::AF_UNIX, "private inspection endpoint has no peer")
}
fn prepare_channel(fd: RawFd) -> io::Result<()> {
    socket(fd)?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    require(flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0
        && unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0, "protect private inspection channel")
}
fn same_file(left: RawFd, right: RawFd) -> io::Result<bool> {
    let mut a: libc::stat = unsafe { zeroed() }; let mut b: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(left, &mut a) } == 0 && unsafe { libc::fstat(right, &mut b) } == 0,
        "inspect channel descriptor identity")?;
    Ok(a.st_dev == b.st_dev && a.st_ino == b.st_ino)
}

struct Parent {
    channel: OwnedFd,
    pidfd: OwnedFd,
    pid: libc::pid_t,
    process: peer::StableProcessIdentity,
}
impl Parent {
    fn open(channel: OwnedFd) -> io::Result<Self> {
        prepare_channel(channel.as_raw_fd())?;
        let pid = unsafe { libc::getppid() };
        require(pid > 0 && peer::socket_peer_credentials(channel.as_raw_fd())?.pid == pid,
            "lifetime endpoint was not created by actual launch parent")?;
        let pidfd = peer::open_peer_pidfd(channel.as_raw_fd())?;
        let process = peer::capture_pidfd_process_identity(&pidfd, pid)?;
        let result = Self { channel, pidfd, pid, process };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> io::Result<()> {
        require(unsafe { libc::getppid() } == self.pid
            && peer::capture_pidfd_process_identity(&self.pidfd, self.pid)? == self.process,
            "original gate parent changed")?;
        let mut fd = libc::pollfd { fd:self.channel.as_raw_fd(), events:libc::POLLIN, revents:0 };
        require(unsafe { libc::poll(&mut fd, 1, 0) } == 0 && fd.revents == 0,
            "lifetime channel closed or unexpected parent command")?;
        peer::ensure_pidfd_alive(&self.pidfd)
    }
    fn require_gate(&self, connection: &OwnedFd, sender: Option<&OwnedFd>) -> io::Result<()> {
        self.check()?;
        require(peer::prove_pidfds_same_process(&self.pidfd, connection, self.pid)? == self.process,
            "inspection target is not the one original gate")?;
        if let Some(sender) = sender {
            require(peer::prove_pidfds_same_process(&self.pidfd, sender, self.pid)? == self.process,
                "packet target is not the one original gate")?;
        }
        Ok(())
    }
}

struct HeldBootstrap { file: File, original: Vec<u8>, identity: (u64,u64,u64,u32,u32,u32), value: Bootstrap }
impl HeldBootstrap {
    fn open(file: File) -> io::Result<Self> {
        require(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0, "protect bootstrap descriptor")?;
        let m = file.metadata()?;
        require(m.is_file() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o600
            && m.nlink() == 0 && m.len() > 0 && m.len() <= wire::MAX_BOOTSTRAP as u64
            && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS,
            "bootstrap must be the private sealed original")?;
        let mut original = vec![0; m.len() as usize]; file.read_exact_at(&mut original, 0)?;
        let value: Bootstrap = crate::decode_canonical_json(&original).map_err(other)?;
        value.validate()?;
        let held = Self { file, original, identity:(m.dev(),m.ino(),m.len(),m.mode(),m.uid(),m.gid()), value };
        held.check()?;
        Ok(held)
    }
    fn check(&self) -> io::Result<()> {
        let m = self.file.metadata()?;
        require((m.dev(),m.ino(),m.len(),m.mode(),m.uid(),m.gid()) == self.identity && m.nlink() == 0
            && unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS,
            "sealed bootstrap original changed")?;
        let mut bytes = vec![0; self.original.len()]; self.file.read_exact_at(&mut bytes, 0)?;
        require(bytes == self.original, "bootstrap bytes changed")
    }
}

struct Packet { bytes: Vec<u8>, files: Vec<OwnedFd>, sender: OwnedFd, credentials: libc::ucred }
fn receive(fd: RawFd) -> io::Result<Packet> {
    let mut bytes = vec![0; wire::MAX_FRAME + 1];
    let mut ancillary = [0usize; 128];
    let mut vector = libc::iovec { iov_base:bytes.as_mut_ptr().cast(), iov_len:bytes.len() };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector; message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&ancillary).try_into()
        .map_err(|_| other("inspector receive control capacity exceeds ABI"))?;
    let count = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
    if count < 0 { return Err(io::Error::last_os_error()); }
    // Own every received descriptor before reporting ANY malformed metadata.
    // Kernel-truncated excess descriptors are closed by recvmsg itself.
    let mut files = Vec::new(); let mut senders = Vec::new(); let mut credentials = Vec::new();
    let mut invalid = false; let mut rights_count = 0;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let h = unsafe { &*header };
        let base = unsafe { libc::CMSG_LEN(0) } as usize;
        let header_length = h.cmsg_len as usize;
        if header_length < base { invalid = true; break; }
        let length = header_length - base;
        let data = unsafe { libc::CMSG_DATA(header) };
        if h.cmsg_level == libc::SOL_SOCKET && (h.cmsg_type == libc::SCM_RIGHTS || h.cmsg_type == SCM_PIDFD) {
            if length % size_of::<RawFd>() != 0 { invalid = true; }
            if h.cmsg_type == libc::SCM_RIGHTS { rights_count += 1; }
            if h.cmsg_type == SCM_PIDFD && length != size_of::<RawFd>() { invalid = true; }
            for index in 0..length / size_of::<RawFd>() {
                let raw = unsafe { std::ptr::read_unaligned(data.add(index * size_of::<RawFd>()).cast::<RawFd>()) };
                if raw < 0 { invalid = true; continue; }
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                if !peer::received_fd_is_cloexec(raw) { invalid = true; }
                if h.cmsg_type == SCM_PIDFD { senders.push(owned); } else { files.push(owned); }
            }
        } else if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_CREDENTIALS
            && length == size_of::<libc::ucred>() {
            credentials.push(unsafe { std::ptr::read_unaligned(data.cast::<libc::ucred>()) });
        } else { invalid = true; }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    require(!invalid && count > 0 && count as usize <= wire::MAX_FRAME
        && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
        && rights_count == 1 && (files.len() == 2 || files.len() == 3)
        && senders.len() == 1 && credentials.len() == 1, "invalid private inspection packet")?;
    bytes.truncate(count as usize);
    Ok(Packet { bytes, files, sender:senders.pop().unwrap(), credentials:credentials.pop().unwrap() })
}
fn send(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    require(!bytes.is_empty() && bytes.len() <= wire::MAX_FRAME, "inspection output bound")?;
    let count = unsafe { libc::sendto(fd, bytes.as_ptr().cast(), bytes.len(),
        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL, std::ptr::null(), 0) };
    require(count == bytes.len() as isize, "inspection result was not delivered exactly once")
}

struct Router { pidfd: OwnedFd, credentials: libc::ucred, process: peer::StableProcessIdentity }
impl Router {
    fn open(packet: &Packet, uid: u32, gid: u32) -> io::Result<Self> {
        require(packet.credentials.pid > 1 && packet.credentials.uid == uid
            && packet.credentials.gid == gid, "actual router packet credentials differ from signed role")?;
        let process = peer::capture_pidfd_process_identity(&packet.sender, packet.credentials.pid)?;
        // Retain a duplicate of this actual kernel ancillary original, never
        // pidfd_open from a caller-supplied target.
        let raw = unsafe { libc::fcntl(packet.sender.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 6) };
        if raw < 0 { return Err(io::Error::last_os_error()); }
        Ok(Self { pidfd:unsafe { OwnedFd::from_raw_fd(raw) }, credentials:packet.credentials, process })
    }
    fn check(&self, packet: &Packet) -> io::Result<()> {
        require(packet.credentials.pid == self.credentials.pid && packet.credentials.uid == self.credentials.uid
            && packet.credentials.gid == self.credentials.gid
            && peer::prove_pidfds_same_process(&self.pidfd, &packet.sender, self.credentials.pid)? == self.process,
            "private router process changed")
    }
}

struct Worker {
    parent: Parent, router_channel: OwnedFd, bootstrap: HeldBootstrap,
    originals: guest_delivery::InspectionOriginals, confinement: confinement::Owner,
    lifetime: u64, next: u64, router: Option<Router>, cache: peer::ExecutableMeasurementCache,
}
impl Worker {
    fn check(&self, deadline: u64) -> io::Result<()> {
        require(now()? < deadline && deadline <= self.lifetime, "inspection original allowance ended")?;
        self.confinement.check()?; self.parent.check()?; self.bootstrap.check()?;
        self.originals.check().map_err(other)?;
        require(now()? < deadline, "inspection allowance ended while checking originals")
    }
    fn wait(&self) -> io::Result<()> {
        self.check(self.lifetime)?;
        let mut fds = [
            libc::pollfd { fd:self.router_channel.as_raw_fd(), events:libc::POLLIN, revents:0 },
            libc::pollfd { fd:self.parent.channel.as_raw_fd(), events:libc::POLLIN, revents:0 },
            libc::pollfd { fd:self.parent.pidfd.as_raw_fd(), events:libc::POLLIN, revents:0 }];
        loop {
            let remaining = self.lifetime.checked_sub(now()?).ok_or_else(|| other("inspection lifetime ended"))?;
            require(remaining > 0, "inspection lifetime ended")?;
            let timeout = ((remaining / 1_000_000).max(1)).min(100) as i32;
            let value = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
            if value < 0 { return Err(io::Error::last_os_error()); }
            require(fds[1].revents == 0 && fds[2].revents == 0
                && fds[0].revents & !libc::POLLIN == 0, "private inspector owner ended")?;
            self.check(self.lifetime)?;
            if fds[0].revents == libc::POLLIN { return Ok(()); }
        }
    }
    fn inspect(&mut self, packet: Packet) -> io::Result<()> {
        let binding = self.originals.binding();
        if self.router.is_none() { self.router = Some(Router::open(&packet, binding.router_uid, binding.router_gid)?); }
        self.router.as_ref().unwrap().check(&packet)?;
        let request: Request = crate::decode_canonical_json(&packet.bytes).map_err(other)?;
        let deadline = request.validate(&self.bootstrap.value.channel_nonce, self.next, self.lifetime, now()?)?;
        self.check(deadline)?;
        require(packet.files.len() == if request.phase == Phase::Connection { 2 } else { 3 },
            "measurement phase descriptor count differs")?;
        let socket_fd = packet.files[0].as_raw_fd();
        socket(socket_fd)?;
        require(!same_file(socket_fd, self.router_channel.as_raw_fd())?
            && !same_file(socket_fd, self.parent.channel.as_raw_fd())?, "private channel is not an inspection target")?;
        let connection = &packet.files[1];
        let sender = packet.files.get(2);
        self.parent.require_gate(connection, sender)?;
        let credentials = peer::socket_peer_credentials(socket_fd)?;
        require(credentials.pid == self.parent.pid && credentials.uid == GATE_ID && credentials.gid == GATE_ID,
            "gate has not reached its fixed serving identity")?;
        // Bind the SOCKET's actual process before the core reads any target
        // executable/cgroup/label; supplied matching PIDFDs alone are not enough.
        let socket_pidfd = peer::open_peer_pidfd(socket_fd)?;
        self.parent.require_gate(&socket_pidfd, sender)?;
        let (actual_connection, mut measured) = peer::capture_connection(socket_fd, GATE_ID, &self.cache)?;
        self.parent.require_gate(&actual_connection, sender)?;
        require(peer::prove_pidfds_same_process(&actual_connection, connection, self.parent.pid)? == self.parent.process,
            "supplied connection original differs from actual accepted socket")?;
        if let Some(sender) = sender {
            measured = peer::capture_packet(socket_fd, connection, sender, &measured, &self.cache)?;
        }
        let measurement = wire::Measurement {
            process_binding_sha256:measured.process_binding_sha256(), uid:credentials.uid, gid:credentials.gid,
            cgroup_sha256:measured.cgroup_sha256().to_owned(),
            security_label_sha256:measured.security_label_sha256().to_owned(),
            executable_sha256:measured.executable_sha256().to_owned(),
        };
        let response = wire::ResultFrame { api_version:"catchplate.responseV2.guestInspectorResult/v1", request:&request, measurement };
        let bytes = crate::canonical_json_bytes(&response).map_err(other)?;
        self.router.as_ref().unwrap().check(&packet)?;
        self.parent.require_gate(connection, sender)?;
        self.check(deadline)?;
        send(self.router_channel.as_raw_fd(), &bytes)?;
        self.check(deadline)?;
        self.next = self.next.checked_add(1).ok_or_else(|| other("inspection sequence exhausted"))?;
        Ok(())
    }
}

fn arm_lifetime(deadline: u64) -> io::Result<()> {
    let mut event: libc::sigevent = unsafe { zeroed() };
    event.sigev_notify = libc::SIGEV_SIGNAL; event.sigev_signo = libc::SIGKILL;
    let mut timer: libc::timer_t = unsafe { zeroed() };
    require(unsafe { libc::timer_create(libc::CLOCK_BOOTTIME, &mut event, &mut timer) } == 0,
        "create fixed inspection lifetime timer")?;
    let schedule = libc::itimerspec {
        it_interval:libc::timespec { tv_sec:0, tv_nsec:0 },
        it_value:libc::timespec { tv_sec:(deadline / 1_000_000_000) as libc::time_t,
            tv_nsec:(deadline % 1_000_000_000) as libc::c_long } };
    require(unsafe { libc::timer_settime(timer, libc::TIMER_ABSTIME, &schedule, std::ptr::null_mut()) } == 0,
        "arm original inspection lifetime")?;
    // Deliberately never renewed/deleted. The process exits on any error; the
    // filter denies timer syscalls after admission, including disarming.
    Ok(())
}

/// Fixed child entrypoint, not a caller-supplied target or public verifier.
/// Only the privileged measured launcher may provide these private originals.
pub fn run_guest_inspector() -> Result<(), String> {
    run().map_err(|_| "guest inspector stopped; no measurement may be reused".to_owned())
}
fn run() -> io::Result<()> {
    confinement::single_thread()?;
    require(unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0, "root preparation required")?;
    // Close unrelated inherited descriptors before opening any original.
    require(unsafe { libc::syscall(libc::SYS_close_range, 6u32, u32::MAX, 0u32) } == 0, "close inherited descriptors")?;
    for fd in 0..3 { unsafe { libc::close(fd); } }
    let parent = Parent::open(unsafe { OwnedFd::from_raw_fd(3) })?;
    let router_channel = unsafe { OwnedFd::from_raw_fd(4) };
    prepare_channel(router_channel.as_raw_fd())?;
    require(!same_file(parent.channel.as_raw_fd(), router_channel.as_raw_fd())?, "inspection channels alias")?;
    for name in [libc::SO_PASSCRED, SO_PASSPIDFD] {
        let one: i32 = 1;
        require(unsafe { libc::setsockopt(router_channel.as_raw_fd(), libc::SOL_SOCKET, name,
            (&one as *const i32).cast(), size_of::<i32>() as libc::socklen_t) } == 0, "enable actual router packet identity")?;
    }
    let bootstrap = HeldBootstrap::open(unsafe { File::from_raw_fd(5) })?;
    let lifetime = wire::ns(&bootstrap.value.gate_lifetime_deadline_boottime_ns)?;
    require(now()? < lifetime, "original gate lifetime already ended")?;
    let preparation = guest_delivery::ListenerPreparation::open(Path::new(&bootstrap.value.configuration_path),
        Path::new(&bootstrap.value.delivery_path), &bootstrap.value.delivery_sha256).map_err(other)?;
    require(preparation.binding().configuration_sha256 == bootstrap.value.configuration_sha256
        && preparation.binding().delivery_sha256 == bootstrap.value.delivery_sha256,
        "sealed consistency differs from actual signed delivery")?;
    parent.check()?;
    let originals = preparation.into_inspection().map_err(other)?;
    arm_lifetime(lifetime)?;
    let confinement = confinement::enter(parent.pid)?;
    let mut worker = Worker { parent, router_channel, bootstrap, originals, confinement, lifetime,
        next:1, router:None, cache:peer::ExecutableMeasurementCache::new(peer::EXECUTABLE_CACHE_ENTRIES_PER_WORKER) };
    worker.check(lifetime)?;
    let bootstrap_sha256 = wire::digest(&worker.bootstrap.original);
    let initialized = wire::Initialized { api_version:"catchplate.responseV2.guestInspectorInitialized/v1",
        channel_nonce:&worker.bootstrap.value.channel_nonce, bootstrap_sha256:&bootstrap_sha256 };
    let bytes = crate::canonical_json_bytes(&initialized).map_err(other)?;
    // Parent must enable PASSCRED/PASSPIDFD and compare the kernel-generated
    // sender to its actual child PIDFD. These bytes alone prove no custody.
    send(worker.parent.channel.as_raw_fd(), &bytes)?;
    loop {
        worker.wait()?;
        let packet = receive(worker.router_channel.as_raw_fd())?;
        worker.inspect(packet)?;
    }
}

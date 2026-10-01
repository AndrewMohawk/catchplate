//! Root-only, non-signing inspection of one independently admitted service peer.
//! The helper never loads service keys and never returns an executable or a
//! transferable verdict. Its only caller is the genuine pre-drop C9 entry.
use super::*;
use super::native_guest::retrieval_peer as packet;
use super::super::common::{AuthenticatedInheritedSeqpacket, ExpectedPeerCredentials};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

#[path="guest_ordinary_inspection_client.rs"]
pub(in crate::policy_shadow::policy_custody::services) mod client;
#[path="guest_ordinary_inspection_wire.rs"]
pub(in crate::policy_shadow::policy_custody::services) mod wire;
#[path="guest_ordinary_inspection_reap.rs"]
mod reap;
pub(super) use reap::ReapedWorker;

pub(super) const CREDENTIAL: &str = "peer-inspection-policy";
const POLICY: &str = "serverware.custodyOrdinaryPeerInspection/v1";
fn require(value: bool) -> Result<(), ServiceRunnerError> {
    if value { Ok(()) } else { Err(fail("ordinary inspection refused")) }
}
fn now() -> Result<u64, ServiceRunnerError> {
    boottime_now_nanos().map_err(|_| fail("ordinary inspection clock unavailable"))
}
fn measured<T>(value: Result<T, crate::policy_shadow::ShadowError>) -> Result<T, ServiceRunnerError> {
    value.map_err(|_| fail("ordinary inspection kernel identity unavailable"))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Policy {
    api_version: String, purpose: String, runtime_configuration_sha256: Sha256Digest,
    service_role: Role, uid: u32, gid: u32,
    startup_deadline_boottime_ns: String, lifetime_deadline_boottime_ns: String,
}

fn process_start(pid: i32) -> Result<u64, ServiceRunnerError> {
    let mut raw = String::new();
    std::fs::File::open(format!("/proc/{pid}/stat"))?.take(16385).read_to_string(&mut raw)?;
    require(raw.len() <= 16384 && raw.starts_with(&format!("{pid} (")))?;
    raw.rsplit_once(") ").and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .ok_or_else(|| fail("inspection process stat invalid"))?.parse()
        .map_err(|_| fail("inspection process start invalid"))
}
fn socket_identity(fd: BorrowedFd<'_>) -> Result<(u64,u64), ServiceRunnerError> {
    let stat = descriptor_stat(fd)?;
    require(stat.st_mode & libc::S_IFMT == libc::S_IFSOCK && stat.st_ino != 0)?;
    Ok((stat.st_dev, stat.st_ino))
}
fn socket_path(fd: BorrowedFd<'_>, path: &Path) -> Result<(), ServiceRunnerError> {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    require(unsafe { libc::getsockname(fd.as_raw_fd(), (&mut address as *mut libc::sockaddr_un).cast(), &mut length) } == 0)?;
    let expected = path.as_os_str().as_bytes();
    let offset = std::ptr::addr_of!(address.sun_path) as usize - std::ptr::addr_of!(address) as usize;
    require(address.sun_family == libc::AF_UNIX as libc::sa_family_t && path.is_absolute()
        && !expected.is_empty() && !expected.contains(&0) && expected.len() < address.sun_path.len()
        && length as usize == offset + expected.len() + 1)?;
    let observed = unsafe { std::slice::from_raw_parts(address.sun_path.as_ptr().cast::<u8>(), expected.len()+1) };
    require(&observed[..expected.len()] == expected && observed[expected.len()] == 0)
}

/// Only these retained descriptors survive in the helper. In particular every
/// service seed, business journal, generation grant and operator channel closes.
fn close_except(mut retained: Vec<i32>) -> Result<(), ServiceRunnerError> {
    retained.sort_unstable(); retained.dedup();
    require(retained.iter().all(|fd| *fd >= 0))?;
    let mut lower = 0u32;
    for fd in retained {
        let fd = fd as u32;
        if lower < fd { require(unsafe { libc::syscall(libc::SYS_close_range, lower, fd-1, 0) } == 0)?; }
        lower = fd.checked_add(1).ok_or_else(|| fail("inspection descriptor overflow"))?;
    }
    require(unsafe { libc::syscall(libc::SYS_close_range, lower, u32::MAX, 0) } == 0)
}

#[repr(C)]
#[derive(Default)]
struct CloneArgs { flags:u64,pidfd:u64,child_tid:u64,parent_tid:u64,exit_signal:u64,
    stack:u64,stack_size:u64,tls:u64,set_tid:u64,set_tid_size:u64,cgroup:u64 }

/// Independent stop capability is required: after drop the service cannot
/// signal its root child. Closing it wakes the helper, then the actual child is
/// reaped by PIDFD. Parent death and the original absolute timer also kill it.
pub(super) struct Worker { child:reap::Child }
impl Worker {
    pub(super) fn check(&self) -> Result<(), ServiceRunnerError> {
        require(self.child.available() && unsafe { libc::getpid() } == self.child.parent
            && now()? < self.child.lifetime)?;
        measured(packet::same_process(self.child.pidfd.as_fd(), self.child.pid))?;
        require(process_start(self.child.pid)? == self.child.start)
    }

    pub(super) fn stop_and_reap(&mut self) -> Result<ReapedWorker, ServiceRunnerError> {
        self.child.stop_and_reap().map_err(Into::into)
    }
}

pub(super) fn prepare(delivery: &PreparedGuestServiceDelivery) -> Result<Worker, ServiceRunnerError> {
    delivery.owner.check_originals()?;
    require(unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
        && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0
        && now()? < delivery.owner.startup)?;
    let mut tasks = std::fs::read_dir("/proc/self/task")?;
    require(tasks.next().transpose()?.is_some() && tasks.next().transpose()?.is_none())?;
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    require(unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } == 0
        && action.sa_sigaction == libc::SIG_DFL && action.sa_flags & libc::SA_NOCLDWAIT == 0)?;
    let (entry, original) = delivery.owner.credentials.get(CREDENTIAL)
        .ok_or_else(|| fail("separate signed peer inspection policy missing"))?;
    require(entry.signing.is_none() && entry.length <= wire::MAX_IPC as u64)?;
    let raw = original.read(wire::MAX_IPC)?;
    require(raw.len() as u64 == entry.length)?;
    let policy: Policy = exact(&raw)?;
    require(policy.api_version == POLICY && policy.purpose == "ordinary-service-peer-inspection"
        && policy.runtime_configuration_sha256 == delivery.owner.payload.runtime_config.sha256
        && policy.service_role == delivery.owner.payload.service_role
        && policy.service_role != Role::ProductionBridge && policy.uid == delivery.role_uid() && policy.gid == delivery.role_gid()
        && ns(&policy.startup_deadline_boottime_ns)? == delivery.owner.startup
        && ns(&policy.lifetime_deadline_boottime_ns)? == delivery.owner.lifetime)?;
    let runtime: serde_json::Value = exact(&delivery.owner.runtime.read(MAX_CONFIG_BYTES)?)?;
    let header: RuntimeConfigHeaderV3 = serde_json::from_value(runtime.get("runtime").cloned()
        .ok_or_else(|| fail("ordinary inspection runtime missing"))?).map_err(|_| fail("ordinary inspection runtime invalid"))?;
    header.validate()?;
    let expected = header.expected_peer.checked()?;
    let listener = delivery.activation.get("listener").ok_or_else(|| fail("ordinary listener missing"))?;
    validate_listener(listener.as_fd(), &header.listener_socket_path)?;
    let (service_pid, service_start, _) = delivery.owner.process.native_binding()?;
    let raw_parent = unsafe { libc::syscall(libc::SYS_pidfd_open, service_pid, 0) };
    require(raw_parent >= 0)?;
    let service_pidfd = unsafe { OwnedFd::from_raw_fd(raw_parent as i32) };
    measured(packet::same_process(service_pidfd.as_fd(), service_pid))?;
    let mut channels = [-1;2];
    require(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, channels.as_mut_ptr()) } == 0)?;
    let parent_channel = unsafe { OwnedFd::from_raw_fd(channels[0]) };
    let child_channel = unsafe { OwnedFd::from_raw_fd(channels[1]) };
    measured(packet::configure(parent_channel.as_fd()))?; measured(packet::configure(child_channel.as_fd()))?;
    let mut pipe = [-1;2];
    require(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == 0)?;
    let stop_read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let stop_write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let mut child_pidfd = -1i32;
    let clone = CloneArgs { flags:libc::CLONE_PIDFD as u64, pidfd:(&mut child_pidfd as *mut i32) as u64,
        exit_signal:libc::SIGCHLD as u64, ..CloneArgs::default() };
    let pid = unsafe { libc::syscall(libc::SYS_clone3, &clone, std::mem::size_of::<CloneArgs>()) };
    if pid == 0 {
        // No parent-owned destructor may run after closing its inherited FDs.
        let result = (|| {
            close_except(vec![child_channel.as_raw_fd(),stop_read.as_raw_fd(),listener.as_raw_fd(),
                service_pidfd.as_raw_fd(),original.descriptor().as_raw_fd()])?;
            serve(child_channel.as_fd(), stop_read.as_fd(), listener.as_fd(), service_pidfd.as_fd(),
                service_pid, service_start, original, &policy, &header, expected.clone())
        })();
        unsafe { libc::_exit(if result.is_ok() {0} else {1}) }
    }
    require(pid > 1)?;
    if child_pidfd < 0 { unsafe { libc::_exit(1) } }
    let pidfd = unsafe { OwnedFd::from_raw_fd(child_pidfd) };
    let mut guard = Worker { child:reap::Child::new(pid as i32,pidfd,stop_write,service_pid,delivery.owner.lifetime) };
    guard.child.start = process_start(guard.child.pid)?;
    drop(child_channel); drop(stop_read); guard.check()?;
    client::install(parent_channel, measured(packet::duplicate(guard.child.pidfd.as_fd()))?, guard.child.pid, expected, Arc::clone(&delivery.owner))?;
    guard.check()?; Ok(guard)
}

#[allow(clippy::too_many_arguments)]
fn serve(channel:BorrowedFd<'_>, stop:BorrowedFd<'_>, listener:BorrowedFd<'_>, parent:BorrowedFd<'_>,
    parent_pid:i32, parent_start:u64, original:&Original, policy:&Policy, header:&RuntimeConfigHeaderV3,
    expected:ExpectedPeerCredentials) -> Result<(),ServiceRunnerError> {
    require(unsafe { libc::getppid() } == parent_pid
        && unsafe { libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL) } == 0
        && unsafe { libc::getppid() } == parent_pid
        && unsafe { libc::prctl(libc::PR_SET_DUMPABLE,0) } == 0
        && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0) } == 0)?;
    // This fixed inspection code needs cross-UID read/ptrace access. These
    // capabilities are powerful host privileges, not a read-only sandbox.
    // Drop every other bounding/effective bit; expose no general ptrace RPC.
    require(unsafe {libc::setgroups(0,std::ptr::null())}==0 && unsafe {libc::prctl(47,4,0,0,0)}==0)?;
    for capability in 0..64 {
        let present=unsafe {libc::prctl(libc::PR_CAPBSET_READ,capability,0,0,0)};
        if present<0 {require(std::io::Error::last_os_error().raw_os_error()==Some(libc::EINVAL))?;continue;}
        if [2,19].contains(&capability) {require(present==1)?;}
        else if present==1 {require(unsafe {libc::prctl(libc::PR_CAPBSET_DROP,capability,0,0,0)}==0)?;}
    }
    #[repr(C)]struct CapHeader {version:u32,pid:i32}
    #[repr(C)]struct CapData {effective:u32,permitted:u32,inheritable:u32}
    let cap_header=CapHeader{version:0x2008_0522,pid:0};
    let mask=(1u32<<2)|(1u32<<19);
    let cap_data=[CapData{effective:mask,permitted:mask,inheritable:0},CapData{effective:0,permitted:0,inheritable:0}];
    require(unsafe {libc::syscall(libc::SYS_capset,&cap_header,cap_data.as_ptr())}==0)?;
    let lifetime = ns(&policy.lifetime_deadline_boottime_ns)?;
    let startup = ns(&policy.startup_deadline_boottime_ns)?;
    let timer = super::ordinary::Timer::arm(lifetime)?;
    let process = Process::capture()?;
    let mut sequence = 0u64;
    let mut retained: Option<(AuthenticatedInheritedSeqpacket,(u64,u64))> = None;
    let check = || -> Result<(),ServiceRunnerError> {
        process.check()?; timer.check()?; original.check()?;
        measured(packet::same_process(parent,parent_pid))?;
        require(unsafe { libc::getppid() } == parent_pid && process_start(parent_pid)? == parent_start
            && unsafe { libc::getuid() } == 0 && unsafe { libc::getgid() } == 0)?;
        validate_listener(listener,&header.listener_socket_path)?;
        let mut signal=0;
        require(unsafe { libc::prctl(libc::PR_GET_PDEATHSIG,&mut signal) } == 0 && signal == libc::SIGKILL)
    };
    loop {
        check()?;
        if retained.is_none() { require(now()? < startup)?; }
        let mut polled = [libc::pollfd{fd:channel.as_raw_fd(),events:libc::POLLIN,revents:0},
            libc::pollfd{fd:stop.as_raw_fd(),events:libc::POLLIN,revents:0}];
        let count = unsafe { libc::poll(polled.as_mut_ptr(),2,1) };
        require(count >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR))?;
        if polled[1].revents != 0 { return Ok(()); }
        require(polled[0].revents & (libc::POLLERR|libc::POLLHUP|libc::POLLNVAL) == 0)?;
        let Some(mut received) = measured(packet::receive(channel,wire::MAX_IPC,2))? else { continue; };
        require(received.credentials.pid == parent_pid && received.credentials.uid == policy.uid && received.credentials.gid == policy.gid)?;
        measured(packet::same_process(received.pidfd.as_fd(),parent_pid))?;
        let request: wire::Request = exact(&received.bytes)?;
        let deadline = ns(&request.deadline_boottime_ns)?;
        require(request.api_version == wire::API && request.sequence == sequence.checked_add(1).ok_or_else(||fail("inspection sequence exhausted"))?
            && request.process_identity_sha256 == expected.process_identity_sha256
            && request.runtime_configuration_sha256 == policy.runtime_configuration_sha256
            && deadline <= lifetime && now()? < deadline)?;
        let peer_pidfd = received.rights.pop().ok_or_else(||fail("inspection peer PIDFD missing"))?;
        let connection = received.rights.pop().ok_or_else(||fail("inspection connection missing"))?;
        let identity = socket_identity(connection.as_fd())?;
        require(identity == (request.socket_device,request.socket_inode))?;
        socket_path(connection.as_fd(),&header.listener_socket_path)?;
        if let Some((_,prior)) = &retained { require(*prior == identity)?; }
        else {
            require(deadline <= startup && now()? < startup)?;
            let direct = AuthenticatedInheritedSeqpacket::from_inherited_direct(connection,expected.clone())?;
            retained = Some((direct,identity));
        }
        let (direct,_) = retained.as_ref().ok_or_else(||fail("inspection session absent"))?;
        direct.revalidate_packet_pidfd(peer_pidfd.as_fd())?;
        check()?; require(now()? < deadline)?;
        let reply = wire::Reply { api_version:wire::API.into(),sequence:request.sequence,
            request_sha256:Sha256Digest::compute(&received.bytes),process_identity_sha256:expected.process_identity_sha256.clone() };
        let bytes = canonical_json_bytes(&reply).map_err(|_|fail("inspection reply encoding failed"))?;
        require(bytes.len() <= wire::MAX_IPC)?;
        loop {
            check()?; require(now()? < deadline)?;
            direct.revalidate_packet_pidfd(peer_pidfd.as_fd())?;
            if measured(packet::send(channel,&bytes,&[]))? { break; }
            let mut poll=libc::pollfd{fd:channel.as_raw_fd(),events:libc::POLLOUT,revents:0};
            let count=unsafe {libc::poll(&mut poll,1,1)};
            require((count>=0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))
                && poll.revents&(libc::POLLERR|libc::POLLHUP|libc::POLLNVAL)==0)?;
        }
        sequence=request.sequence;
    }
}

/// Re-listen under the actual dropped service credentials. Linux updates the
/// listener's stored peer credentials; already queued old-credential sessions
/// are not repaired and fail the existing client peer admission.
pub(super) fn final_role_listening(delivery:&PreparedGuestServiceDelivery, worker:&Worker) -> Result<(),ServiceRunnerError> {
    delivery.owner.check_startup()?; worker.check()?;
    let runtime:serde_json::Value=exact(&delivery.owner.runtime.read(MAX_CONFIG_BYTES)?)?;
    let header:RuntimeConfigHeaderV3=serde_json::from_value(runtime.get("runtime").cloned()
        .ok_or_else(||fail("ordinary runtime absent"))?).map_err(|_|fail("ordinary runtime invalid"))?;
    header.validate()?;
    let listener=delivery.activation.get("listener").ok_or_else(||fail("ordinary listener absent"))?;
    validate_listener(listener.as_fd(),&header.listener_socket_path)?;
    require(unsafe {libc::listen(listener.as_raw_fd(),1)}==0)?;
    validate_listener(listener.as_fd(),&header.listener_socket_path)?;
    delivery.owner.check_startup()?; worker.check()?;
    #[derive(Serialize)] #[serde(rename_all="camelCase")]
    struct Notice<'a> {api_version:&'static str,delivery_sha256:&'a Sha256Digest,
        service_role:Role,invocation_id:&'a str,phase:&'static str}
    let notice=Notice{api_version:"serverware.custodyOrdinaryListening/v1",delivery_sha256:&delivery.owner.delivery_sha256,
        service_role:delivery.owner.payload.service_role,invocation_id:&delivery.owner.payload.invocation_id,phase:"final-role-listening"};
    let bytes=canonical_json_bytes(&notice).map_err(|_|fail("ordinary listening notice encoding failed"))?;
    delivery.owner.parent.send(&bytes,delivery.owner.startup)?;
    // This notice does not disarm startup or set Delivery.ready.
    worker.check()
}

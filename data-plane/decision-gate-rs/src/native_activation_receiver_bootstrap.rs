//! Service-enclave bootstrap, not a parent-VM storage or authority adapter.
//! The journal and encrypted credentials must already exist in this kernel.
//! Only public observation/completion bytes cross the one parent connection.
use crate::enclave_vsock_v1::VsockStreamV1;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{ffi::CString, fs::File, io, os::fd::{AsRawFd, FromRawFd, OwnedFd}, os::unix::fs::{FileExt, MetadataExt}};

const PORT: u32 = 9103;
const COLD: &str = "/etc/catchplate/native-shadow-activation-receiver.json";
const DELIVERY: &str = "/etc/catchplate/native-activation-delivery.json";
const JOURNAL: &str = "/var/lib/catchplate/native-activation";
const SUPERVISOR: &str = "/opt/catchplate/catchplate-native-shadow-guest-supervisor";
const MAX_COMPLETION: usize = 1024 * 1024;
fn require(ok: bool) -> Result<(), String> { if ok { Ok(()) } else { Err("activation bootstrap original or framing differs".into()) } }
fn err(_: impl std::fmt::Display) -> String { "activation bootstrap acquisition or IO failed; no retry".into() }
fn now() -> Result<u64, String> { crate::native_canary_evidence_v1::now_boot() }
fn sha(bytes: &[u8]) -> String { format!("sha256:{}", hex::encode(Sha256::digest(bytes))) }
fn canonical(value: &serde_json::Value) -> Result<Vec<u8>, String> { crate::native_response_profile_v1::canonical_ascii_bytes(value) }

#[derive(Clone, PartialEq, Eq)]
struct Identity { dev: u64, ino: u64, mode: u32, uid: u32, gid: u32, links: u64, length: u64, mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64 }
fn identity(file: &File) -> Result<Identity, String> {
    let m = file.metadata().map_err(err)?;
    Ok(Identity { dev: m.dev(), ino: m.ino(), mode: m.mode(), uid: m.uid(), gid: m.gid(), links: m.nlink(),
        length: m.len(), mtime: m.mtime(), mtime_ns: m.mtime_nsec(), ctime: m.ctime(), ctime_ns: m.ctime_nsec() })
}
// Every caller supplies one source constant. No incoming path is opened.
fn fixed(path: &str, directory: bool) -> Result<File, String> {
    let mut file = File::open("/").map_err(err)?;
    let components: Vec<_> = path.split('/').skip(1).collect();
    for (index, component) in components.iter().enumerate() {
        let m = file.metadata().map_err(err)?;
        require(m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0)?;
        let name = CString::new(*component).map_err(err)?;
        let fd = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC
            | libc::O_NOFOLLOW | libc::O_NONBLOCK | if directory || index + 1 < components.len() { libc::O_DIRECTORY } else { 0 }) };
        require(fd >= 0)?; file = unsafe { File::from_raw_fd(fd) };
    }
    Ok(file)
}
struct Public { file: File, identity: Identity, bytes: Vec<u8> }
impl Public {
    fn open(path: &str) -> Result<Self, String> {
        let file = fixed(path, false)?; let before = identity(&file)?;
        require(before.mode == libc::S_IFREG | 0o400 && before.uid == 0 && before.gid == 0
            && before.links == 1 && before.length > 0 && before.length <= 65536)?;
        let mut bytes = vec![0; before.length as usize]; file.read_exact_at(&mut bytes, 0).map_err(err)?;
        require(identity(&file)? == before && bytes.is_ascii())?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(err)?;
        require(canonical(&value)? == bytes)?;
        Ok(Self { file, identity: before, bytes })
    }
    fn check(&self) -> Result<(), String> { require(identity(&self.file)? == self.identity) }
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authority { public_key_base64url: String, key_id: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pin { path: String, sha256: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Cold { api_version: String, delivery_configuration: Pin, installation_authority: Authority }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Delivery { api_version: String, authority: Authority, service_role: String, uid: u32, gid: u32 }
struct Resources { cold: Public, delivery: Public, journal: File, journal_identity: Identity, executable: File, executable_identity: Identity }
impl Resources {
    fn open() -> Result<Self, String> {
        let cold = Public::open(COLD)?; let delivery = Public::open(DELIVERY)?;
        let c: Cold = serde_json::from_slice(&cold.bytes).map_err(err)?;
        let d: Delivery = serde_json::from_slice(&delivery.bytes).map_err(err)?;
        require(c.api_version == "catchplate.nativeShadowActivationReceiverConfiguration/v2"
            && c.delivery_configuration.path == DELIVERY && c.delivery_configuration.sha256 == sha(&delivery.bytes)
            && c.installation_authority == d.authority && d.api_version == "catchplate.policyCustodyGuestConfiguration/v1"
            && d.service_role == "production-bridge" && d.uid > 0 && d.gid > 0)?;
        let journal = fixed(JOURNAL, true)?; let ji = identity(&journal)?;
        require(ji.mode == libc::S_IFDIR | 0o700 && ji.uid == d.uid && ji.gid == d.gid)?;
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        let mut flags: libc::statvfs = unsafe { std::mem::zeroed() };
        require(unsafe { libc::fstatfs(journal.as_raw_fd(), &mut fs) } == 0
            && matches!(fs.f_type as u64, 0xef53 | 0x5846_5342 | 0x9123_683e)
            && unsafe { libc::fstatvfs(journal.as_raw_fd(), &mut flags) } == 0 && flags.f_flag & libc::ST_RDONLY == 0)?;
        // No contents are read or initialized here. The actual final-role
        // Journal still admits its lock, original state and signed state pin.
        let executable = fixed(SUPERVISOR, false)?; let ei = identity(&executable)?;
        require(ei.mode == libc::S_IFREG | 0o555 && ei.uid == 0 && ei.gid == 0 && ei.links == 1
            && ei.length > 0 && ei.length <= 64 * 1024 * 1024)?;
        let mut magic = [0; 4]; executable.read_exact_at(&mut magic, 0).map_err(err)?; require(magic == *b"\x7fELF")?;
        let result = Self { cold, delivery, journal, journal_identity: ji, executable, executable_identity: ei };
        result.check()?; Ok(result)
    }
    fn check(&self) -> Result<(), String> {
        self.cold.check()?; self.delivery.check()?;
        require(identity(&self.executable)? == self.executable_identity)?;
        let actual = identity(&self.journal)?; let expected = &self.journal_identity;
        // Children legitimately update this directory only after admission.
        require((actual.dev, actual.ino, actual.mode, actual.uid, actual.gid)
            == (expected.dev, expected.ino, expected.mode, expected.uid, expected.gid))
    }
}
fn duplicate(fd: i32) -> Result<OwnedFd, String> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 128) }; require(raw >= 128)?;
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
fn pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1; 2]; require(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == 0)?;
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}
#[repr(C)]
#[derive(Default)]
struct CloneArgs { flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64, exit_signal: u64, stack: u64,
    stack_size: u64, tls: u64, set_tid: u64, set_tid_size: u64, cgroup: u64 }
#[repr(C)]
struct Action { handler: usize, flags: usize, restorer: usize, mask: u64 }
struct Child { pidfd: OwnedFd, pid: i32, parent: i32, reaped: bool }
impl Child {
    fn spawn(resources: &Resources, input: &OwnedFd, output: &OwnedFd) -> Result<Self, String> {
        let stdin = duplicate(input.as_raw_fd())?; let stdout = duplicate(output.as_raw_fd())?; let stderr = duplicate(2)?;
        let journal = duplicate(resources.journal.as_raw_fd())?; let executable = duplicate(resources.executable.as_raw_fd())?;
        let parent = unsafe { libc::getpid() }; let mut pidfd = -1;
        let args = CloneArgs { flags: libc::CLONE_PIDFD as u64, pidfd: (&mut pidfd as *mut i32) as u64,
            exit_signal: libc::SIGCHLD as u64, ..CloneArgs::default() };
        let pid = unsafe { libc::syscall(libc::SYS_clone3, &args, std::mem::size_of::<CloneArgs>()) };
        if pid == 0 {
            // Async-signal-safe trampoline only; no allocation or fallback.
            let mut good = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == 0
                && unsafe { libc::getppid() } == parent;
            good &= unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) } == 0;
            for (source, target) in [(stdin.as_raw_fd(), 0), (stdout.as_raw_fd(), 1), (stderr.as_raw_fd(), 2), (journal.as_raw_fd(), 6)] {
                good &= unsafe { libc::dup3(source, target, 0) } == target;
            }
            let action = Action { handler: 0, flags: 0, restorer: 0, mask: 0 };
            for signal in 1..=64 { if signal != libc::SIGKILL && signal != libc::SIGSTOP {
                good &= unsafe { libc::syscall(libc::SYS_rt_sigaction, signal, &action, std::ptr::null::<u8>(), 8usize) } == 0;
            } }
            let mask = 0u64;
            good &= unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK, &mask, std::ptr::null::<u8>(), 8usize) } == 0;
            good &= unsafe { libc::chdir(c"/".as_ptr()) } == 0;
            if good {
                let argv = [c"catchplate-native-shadow-guest-supervisor".as_ptr(), c"--activation-receiver".as_ptr(), std::ptr::null()];
                let env: [*const libc::c_char; 1] = [std::ptr::null()];
                unsafe { libc::syscall(libc::SYS_execveat, executable.as_raw_fd(), c"".as_ptr(), argv.as_ptr(), env.as_ptr(), libc::AT_EMPTY_PATH); }
            }
            unsafe { libc::_exit(127); }
        }
        if pid > 0 && pidfd < 0 { unsafe { libc::_exit(1); } }
        require(pid > 0 && pidfd >= 0)?;
        Ok(Self { pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) }, pid: pid as i32, parent, reaped: false })
    }
    fn terminal(&mut self, consume: bool) -> Result<Option<(i32, i32)>, String> {
        require(unsafe { libc::getpid() } == self.parent && !self.reaped)?;
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let flags = libc::WEXITED | libc::WNOHANG | if consume { 0 } else { libc::WNOWAIT };
        require(unsafe { libc::waitid(libc::P_PIDFD, self.pidfd.as_raw_fd() as _, &mut info, flags) } == 0)?;
        if unsafe { info.si_pid() } == 0 { return Ok(None); }
        require(unsafe { info.si_pid() } == self.pid && info.si_signo == libc::SIGCHLD
            && matches!(info.si_code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED))?;
        if consume { self.reaped = true; }
        Ok(Some((info.si_code, unsafe { info.si_status() })))
    }
    fn live(&mut self) -> Result<(), String> { require(self.terminal(false)?.is_none()) }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.reaped { return; }
        let killed = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.pidfd.as_raw_fd(), libc::SIGKILL, std::ptr::null::<libc::siginfo_t>(), 0) };
        if killed != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) { unsafe { libc::_exit(1); } }
        // Cleanup alone has a one-second local ceiling; it grants no IO or
        // service permission. Never return to execution with an unreaped child.
        let until = now().ok().and_then(|v| v.checked_add(1_000_000_000)).unwrap_or(0);
        loop {
            if matches!(self.terminal(true), Ok(Some(_))) { break; }
            if now().map_or(true, |v| v >= until) { unsafe { libc::_exit(1); } }
            pause();
        }
    }
}
fn pause() { unsafe { libc::poll(std::ptr::null_mut(), 0, 10); } }
struct Transport(VsockStreamV1);
impl Drop for Transport { fn drop(&mut self) { let _ = self.0.shutdown(); } }
fn live(resources: &Resources, child: &mut Child, transport: &Transport, deadline: u64) -> Result<(), String> {
    resources.check()?; child.live()?; require(now()? < deadline)?;
    transport.0.verify_connected_original(deadline).map_err(err)
}
fn pipe_read(fd: i32, out: &mut [u8]) -> Result<Option<usize>, String> {
    let n = unsafe { libc::read(fd, out.as_mut_ptr().cast(), out.len()) };
    if n >= 0 { return Ok(Some(n as usize)); }
    require(matches!(io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)))?; Ok(None)
}
fn pipe_exact(fd: i32, mut out: &mut [u8], resources: &Resources, child: &mut Child, transport: &Transport, deadline: u64) -> Result<(), String> {
    while !out.is_empty() { live(resources, child, transport, deadline)?;
        if let Some(n) = pipe_read(fd, out)? { require(n > 0)?; out = &mut out[n..]; } else { pause(); }
    } live(resources, child, transport, deadline)
}
fn send(transport: &mut Transport, mut bytes: &[u8], resources: &Resources, child: &mut Child, deadline: u64) -> Result<(), String> {
    while !bytes.is_empty() { live(resources, child, transport, deadline)?;
        match transport.0.try_write(bytes) { Ok(n) if n > 0 => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => pause(), _ => return Err(err("send")) }
    } live(resources, child, transport, deadline)
}
fn receive(transport: &mut Transport, out: &mut [u8], resources: &Resources, child: &mut Child, deadline: u64) -> Result<usize, String> {
    loop { live(resources, child, transport, deadline)?;
        match transport.0.try_read(out) { Ok(n) => { live(resources, child, transport, deadline)?; return Ok(n); },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => pause(), _ => return Err(err("receive")) }
    }
}
fn receive_exact(transport: &mut Transport, mut out: &mut [u8], resources: &Resources, child: &mut Child, deadline: u64) -> Result<(), String> {
    while !out.is_empty() { let n = receive(transport, out, resources, child, deadline)?; require(n > 0)?; out = &mut out[n..]; } Ok(())
}

/// One fixed bootstrap. It never constructs a journal, a private credential,
/// a signed original, or a successful admission/readiness acknowledgement.
pub fn run() -> Result<(), String> {
    require(cfg!(target_arch = "x86_64") && unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
        && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0)?;
    let status = std::fs::read_to_string("/proc/self/status").map_err(err)?;
    let threads: Vec<_> = status.lines().filter_map(|v| v.strip_prefix("Threads:")).collect();
    require(threads.len() == 1 && threads[0].trim() == "1")?;
    let entries = std::fs::read_dir("/proc/self/fd").map_err(err)?.map(|v| v.map_err(err)
        .and_then(|v| v.file_name().to_str().ok_or_else(|| err("fd")).and_then(|v| v.parse::<i32>().map_err(err))))
        .collect::<Result<Vec<_>, _>>()?;
    let mut inherited = std::collections::BTreeSet::new();
    for fd in entries { let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 { inherited.insert(fd); } else { require(io::Error::last_os_error().raw_os_error() == Some(libc::EBADF))?; }
    }
    require(inherited == std::collections::BTreeSet::from([0, 1, 2]))?;
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() }; action.sa_sigaction = libc::SIG_IGN;
    require(unsafe { libc::sigemptyset(&mut action.sa_mask) } == 0 && unsafe { libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut()) } == 0)?;
    action.sa_sigaction = libc::SIG_DFL;
    require(unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } == 0)?;
    let resources = Resources::open()?;
    // Preauthority has no setup expiry. The library independently bounds the
    // single connect attempt to three seconds; it never reconnects.
    let mut transport = Transport(VsockStreamV1::connect_parent(PORT, u64::MAX).map_err(err)?);
    let (input, writer) = pipe()?; let (reader, output) = pipe()?;
    let mut child = Child::spawn(&resources, &input, &output)?; drop(input); drop(output);
    let mut header = [0; 4]; pipe_exact(reader.as_raw_fd(), &mut header, &resources, &mut child, &transport, u64::MAX)?;
    let count = u32::from_be_bytes(header) as usize; require(count > 0 && count <= 8192)?;
    let mut observation = vec![0; count]; pipe_exact(reader.as_raw_fd(), &mut observation, &resources, &mut child, &transport, u64::MAX)?;
    let observed: serde_json::Value = serde_json::from_slice(&observation).map_err(err)?;
    require(canonical(&observed)? == observation && observed["apiVersion"] == "catchplate.nativeShadowActivationReceiverObservation/v1"
        && observed["okForAction"] == false && observed["processId"].as_i64() == Some(child.pid as i64)
        && observed["configurationSha256"] == sha(&resources.cold.bytes)
        && observed["deliveryConfigurationSha256"] == sha(&resources.delivery.bytes))?;
    let stamp = observed["observedAtBoottimeNs"].as_str().ok_or_else(|| err("clock"))?;
    let observed_at = stamp.parse::<u64>().map_err(err)?;
    require(observed_at > 0 && observed_at.to_string() == stamp && observed_at <= now()?)?;
    // This is only a restrictive transport ceiling from the actual same-kernel
    // child sample, NOT signed permission. C9 admission retains its own deadline.
    let deadline = observed_at.checked_add(30_000_000_000).ok_or_else(|| err("clock"))?;
    send(&mut transport, &header, &resources, &mut child, deadline)?;
    send(&mut transport, &observation, &resources, &mut child, deadline)?;
    transport.0.finish_write().map_err(err)?;
    receive_exact(&mut transport, &mut header, &resources, &mut child, deadline)?;
    let length = u32::from_be_bytes(header) as usize; require(length > 0 && length <= MAX_COMPLETION)?;
    let mut completion = vec![0; length]; receive_exact(&mut transport, &mut completion, &resources, &mut child, deadline)?;
    require(receive(&mut transport, &mut [0], &resources, &mut child, deadline)? == 0)?;
    let value: serde_json::Value = serde_json::from_slice(&completion).map_err(err)?;
    require(canonical(&value)? == completion && value["apiVersion"] == "catchplate.nativeShadowActivationReceiverCompletion/v2"
        && value["installation"]["payload"]["observationSha256"] == sha(&observation))?;
    let mut frame = header.to_vec(); frame.extend_from_slice(&completion); let mut offset = 0;
    while offset < frame.len() { live(&resources, &mut child, &transport, deadline)?;
        let n = unsafe { libc::write(writer.as_raw_fd(), frame[offset..].as_ptr().cast(), (frame.len() - offset).min(65536)) };
        if n > 0 { offset += n as usize; } else { require(n < 0 && matches!(io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)))?; pause(); }
    }
    live(&resources, &mut child, &transport, deadline)?; drop(writer); drop(transport);
    // No success ACK and no transport ceiling on actual service execution.
    // Its existing signed owner/timers govern the final child lifetime.
    loop { resources.check()?;
        if let Some(result) = child.terminal(false)? {
            require(child.terminal(true)? == Some(result))?;
            require(pipe_read(reader.as_raw_fd(), &mut [0])? == Some(0))?;
            return require(result == (libc::CLD_EXITED, 0));
        }
        if let Some(n) = pipe_read(reader.as_raw_fd(), &mut [0])? { require(n == 0)?; }
        pause();
    }
}

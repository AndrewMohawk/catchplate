//! The private child and its immutable runtime image, never an external RPC.
use super::{ensure, live, now, Configuration};
use super::image::Image;
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

fn io_error(_: io::Error) -> String { "native broker protected process I/O failed".to_owned() }

#[repr(C)]
struct CapabilityHeader { version: u32, pid: i32 }
#[repr(C)]
struct CapabilityData { effective: u32, permitted: u32, inheritable: u32 }

pub(super) struct Process {
    image: Image, child: Child, pidfd: OwnedFd, channel: UnixStream,
    creator: libc::pid_t, deadline: u64, last: u64, poisoned: bool,
}

impl Process {
    pub(super) fn spawn(config: &Configuration, deadline: u64) -> Result<Self, String> {
        live(deadline)?;
        ensure(unsafe { libc::geteuid() } == 0, "native broker immutable child needs its fixed launch privilege")?;
        let image = Image::open(&config.helper_image, deadline)?;
        let (channel, child_channel) = UnixStream::pair().map_err(io_error)?;
        channel.set_nonblocking(true).map_err(io_error)?;
        let child_channel_fd = child_channel.as_raw_fd();
        let root_fd = image.root.as_raw_fd();
        let executable_fd = image.interpreter.as_raw_fd();
        let parent = unsafe { libc::getpid() };
        let arguments = [CString::new(super::INTERPRETER_PATH).map_err(|_| "interpreter NUL")?,
            CString::new("-I").unwrap(), CString::new("-B").unwrap(),
            CString::new(super::HELPER_PATH).map_err(|_| "helper NUL")?];
        let mut command = Command::new("/native-broker-exec-is-source-owned");
        let last = now()?;
        command.env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                // No heap allocation or lock-taking after fork. The held ELF
                // and detached immutable root select the entire Python TCB.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
                    || libc::fchdir(root_fd) != 0 || libc::chroot(b".\0".as_ptr().cast()) != 0
                    || libc::chdir(b"/\0".as_ptr().cast()) != 0 || libc::dup2(child_channel_fd, 3) != 3
                    || libc::fcntl(3, libc::F_SETFD, 0) != 0 || libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                for capability in 0..=40 {
                    if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 { return Err(io::Error::last_os_error()); }
                }
                for (resource, limit) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_FSIZE, 0),
                    (libc::RLIMIT_NPROC, 1), (libc::RLIMIT_NOFILE, 64), (libc::RLIMIT_AS, 512 * 1024 * 1024)] {
                    let bound = libc::rlimit { rlim_cur: limit, rlim_max: limit };
                    if libc::setrlimit(resource, &bound) != 0 { return Err(io::Error::last_os_error()); }
                }
                if libc::setresgid(65534, 65534, 65534) != 0 || libc::setresuid(65534, 65534, 65534) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                    // Linux clears PDEATHSIG when credentials change.
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent {
                    return Err(io::Error::last_os_error());
                }
                let header = CapabilityHeader { version: 0x2008_0522, pid: 0 };
                let data = [CapabilityData { effective: 0, permitted: 0, inheritable: 0 },
                    CapabilityData { effective: 0, permitted: 0, inheritable: 0 }];
                if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
                    // CLOEXEC, not CLOSE: preserve Command's actual exec-error
                    // handshake on failure and the held ELF until execveat.
                    || libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 4u32) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let argv = [arguments[0].as_ptr(), arguments[1].as_ptr(), arguments[2].as_ptr(),
                    arguments[3].as_ptr(), std::ptr::null()];
                let env: [*const libc::c_char; 1] = [std::ptr::null()];
                libc::syscall(libc::SYS_execveat, executable_fd, b"\0".as_ptr().cast::<libc::c_char>(),
                    argv.as_ptr(), env.as_ptr(), libc::AT_EMPTY_PATH);
                Err(io::Error::last_os_error())
            });
        }
        let mut child = command.spawn().map_err(io_error)?;
        drop(child_channel);
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) as RawFd };
        if fd < 0 { let _ = child.kill(); let _ = child.wait(); return Err("native broker child pidfd unavailable".to_owned()); }
        let mut owner = Self { image, child, pidfd: unsafe { OwnedFd::from_raw_fd(fd) },
            channel, creator: parent, deadline, last, poisoned: false };
        owner.check(deadline)?;
        Ok(owner)
    }

    fn tick(&mut self, deadline: u64) -> Result<(), String> {
        ensure(!self.poisoned && unsafe { libc::getpid() } == self.creator,
            "native broker child crossed its owner or is poisoned")?;
        let current = now()?;
        ensure(current >= self.last && current < deadline.min(self.deadline), "native broker original clock expired")?;
        self.last = current;
        ensure(self.child.try_wait().map_err(io_error)?.is_none(), "native broker child exited")
    }

    pub(super) fn check(&mut self, deadline: u64) -> Result<(), String> {
        let result = self.tick(deadline).and_then(|_| self.image.check(deadline.min(self.deadline)));
        if result.is_err() { self.poisoned = true; }
        result
    }

    fn wait(&mut self, events: i16, deadline: u64) -> Result<(), String> {
        self.tick(deadline)?;
        let mut poll = libc::pollfd { fd: self.channel.as_raw_fd(), events, revents: 0 };
        let result = unsafe { libc::poll(&mut poll, 1, 25) };
        ensure(result >= 0 || io::Error::last_os_error().kind() == io::ErrorKind::Interrupted,
            "native broker channel poll failed")?;
        ensure(poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
            "native broker channel closed")?;
        self.tick(deadline)
    }

    fn write(&mut self, bytes: &[u8], deadline: u64) -> Result<(), String> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.tick(deadline)?;
            match self.channel.write(&bytes[offset..bytes.len().min(offset + 65536)]) {
                Ok(0) => return Err("native broker channel write ended".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait(libc::POLLOUT, deadline)?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
                Err(error) => return Err(io_error(error)),
            }
        }
        self.tick(deadline)
    }

    fn read(&mut self, bytes: &mut [u8], deadline: u64) -> Result<(), String> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.tick(deadline)?;
            let end = bytes.len().min(offset + 65536);
            match self.channel.read(&mut bytes[offset..end]) {
                Ok(0) => return Err("native broker channel read ended".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait(libc::POLLIN, deadline)?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
                Err(error) => return Err(io_error(error)),
            }
        }
        self.tick(deadline)
    }

    pub(super) fn exchange(&mut self, original: &[u8], deadline: u64) -> Result<Vec<u8>, String> {
        let result = (|| {
            self.check(deadline)?;
            ensure(!original.is_empty() && original.len() <= super::MAX_FRAME, "native broker request frame bound")?;
            self.write(&(original.len() as u32).to_be_bytes(), deadline)?;
            self.write(original, deadline)?;
            let mut size = [0u8; 4]; self.read(&mut size, deadline)?;
            let size = u32::from_be_bytes(size) as usize;
            ensure(size > 0 && size <= super::MAX_FRAME, "native broker response frame bound")?;
            let mut response = vec![0; size]; self.read(&mut response, deadline)?;
            self.check(deadline)?;
            Ok(response)
        })();
        if result.is_err() { self.poisoned = true; self.terminate(); }
        result
    }

    pub(super) fn terminate(&mut self) {
        self.poisoned = true;
        if unsafe { libc::getpid() } == self.creator {
            let _ = self.channel.shutdown(std::net::Shutdown::Both);
            unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.pidfd.as_raw_fd(), libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(), 0); }
            let _ = self.child.wait();
        }
    }
}
impl Drop for Process { fn drop(&mut self) { self.terminate(); } }

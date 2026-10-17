//! Fixed protected originals and actual external supervisor identity.
use super::ensure;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Identity {
    device: u64, inode: u64, mode: u32, uid: u32, gid: u32, links: u64,
    length: i64, modified: (i64, i64), changed: (i64, i64),
}
pub(super) fn stat(fd: RawFd) -> Result<libc::stat, String> {
    let mut info = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstat(fd, &mut info) } == 0, "verifier original stat failed")?;
    Ok(info)
}
pub(super) fn identity(fd: RawFd) -> Result<Identity, String> { Ok(from_stat(stat(fd)?)) }
fn from_stat(info: libc::stat) -> Identity {
    Identity { device: info.st_dev, inode: info.st_ino, mode: info.st_mode, uid: info.st_uid, gid: info.st_gid,
        links: info.st_nlink, length: info.st_size, modified: (info.st_mtime, info.st_mtime_nsec),
        changed: (info.st_ctime, info.st_ctime_nsec) }
}
pub(super) fn owned(fd: RawFd) -> Result<File, String> {
    ensure(fd >= 0, "verifier descriptor unavailable")?;
    let input = unsafe { OwnedFd::from_raw_fd(fd) };
    let copied = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) };
    ensure(copied >= 0, "verifier descriptor retention failed")?;
    Ok(unsafe { File::from_raw_fd(copied) })
}
pub(super) fn protected_directory(fd: RawFd) -> Result<(), String> {
    let info = stat(fd)?;
    ensure(info.st_mode & libc::S_IFMT == libc::S_IFDIR && info.st_uid == 0 && info.st_gid == 0
        && info.st_mode & 0o022 == 0, "verifier protected directory differs")
}
pub(super) fn read(fd: RawFd, maximum: usize) -> Result<Vec<u8>, String> {
    let before = identity(fd)?;
    ensure(before.length > 0 && before.length as u64 <= maximum as u64, "verifier original byte bound")?;
    let mut result = vec![0; before.length as usize + 1];
    let mut offset = 0;
    while offset < result.len() {
        let count = unsafe { libc::pread(fd, result[offset..].as_mut_ptr().cast(), result.len() - offset, offset as i64) };
        ensure(count >= 0, "verifier original read failed")?;
        if count == 0 { break; }
        offset += count as usize;
    }
    ensure(offset == before.length as usize && identity(fd)? == before, "verifier original changed while reading")?;
    result.truncate(offset);
    Ok(result)
}

struct Ancestor { file: File, identity: Identity, name: CString }
pub(crate) struct Original {
    root: File, root_identity: Identity, ancestors: Vec<Ancestor>, leaf: CString,
    pub(super) file: File, identity: Identity, pub(crate) bytes: Vec<u8>,
}
impl Original {
    pub(super) fn retain(&self) -> Result<Self, String> {
        self.check()?;
        let copy = |file: &File| file.try_clone().map_err(|_| "verifier original duplication failed".to_owned());
        let owner = Self { root:copy(&self.root)?, root_identity:self.root_identity,
            ancestors:self.ancestors.iter().map(|a| Ok(Ancestor { file:copy(&a.file)?, identity:a.identity, name:a.name.clone() }))
                .collect::<Result<Vec<_>,String>>()?,
            leaf:self.leaf.clone(),file:copy(&self.file)?,identity:self.identity,bytes:self.bytes.clone() };
        owner.check()?; self.check()?; Ok(owner)
    }
    pub(crate) fn open(name: &'static str, maximum: usize) -> Result<Self, String> {
        ensure(matches!(name, "native-shadow-verifier-launch.json" | "native-shadow-nitro-verifier.json"
            | "native-shadow-verifier-transport.json" | "native-shadow-time-issuer-launch.json"
            | "native-shadow-guest-time-issuer.json" | "native-generation-origin-issuer-launch.json"
            | "native-generation-origin-issuer.json"
            | "setup-native-hardware-verifier-launch.json" | "setup-native-hardware-verifier.json"
            | "setup-native-proxy-verifier-launch.json" | "setup-native-proxy-verifier.json"
            | "setup-native-final-authority-launch.json" | "setup-native-final-authority.json"),
            "verifier original name is not a fixed purpose")?;
        let root = owned(unsafe { libc::open(b"/\0".as_ptr().cast(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
        protected_directory(root.as_raw_fd())?;
        let root_identity = identity(root.as_raw_fd())?;
        let mut ancestors = Vec::new();
        let mut parent = root.as_raw_fd();
        for component in ["etc", "catchplate"] {
            let name = CString::new(component).unwrap();
            let file = owned(unsafe { libc::openat(parent, name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY
                | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
            protected_directory(file.as_raw_fd())?;
            let observed = identity(file.as_raw_fd())?;
            parent = file.as_raw_fd();
            ancestors.push(Ancestor { file, identity: observed, name });
        }
        let leaf = CString::new(name).unwrap();
        let file = owned(unsafe { libc::openat(parent, leaf.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW
            | libc::O_CLOEXEC | libc::O_NONBLOCK) })?;
        let info = stat(file.as_raw_fd())?;
        ensure(info.st_mode & libc::S_IFMT == libc::S_IFREG && info.st_mode & 0o7777 == 0o400
            && info.st_uid == 0 && info.st_gid == 0 && info.st_nlink == 1,
            "verifier configuration must be a protected root0400 singly linked original")?;
        let observed = identity(file.as_raw_fd())?;
        let bytes = read(file.as_raw_fd(), maximum)?;
        let owner = Self { root, root_identity, ancestors, leaf, file, identity: observed, bytes };
        owner.check()?;
        Ok(owner)
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        ensure(identity(self.root.as_raw_fd())? == self.root_identity, "verifier original root changed")?;
        let mut parent = self.root.as_raw_fd();
        for ancestor in &self.ancestors {
            let mut named = unsafe { std::mem::zeroed() };
            ensure(unsafe { libc::fstatat(parent, ancestor.name.as_ptr(), &mut named, libc::AT_SYMLINK_NOFOLLOW) } == 0
                && from_stat(named) == ancestor.identity && identity(ancestor.file.as_raw_fd())? == ancestor.identity,
                "verifier original ancestor changed")?;
            parent = ancestor.file.as_raw_fd();
        }
        let mut named = unsafe { std::mem::zeroed() };
        ensure(unsafe { libc::fstatat(parent, self.leaf.as_ptr(), &mut named, libc::AT_SYMLINK_NOFOLLOW) } == 0
            && from_stat(named) == self.identity && identity(self.file.as_raw_fd())? == self.identity
            && read(self.file.as_raw_fd(), self.bytes.len())? == self.bytes,
            "verifier named/held configuration differs")
    }
}

fn proc_text(path: &str, maximum: usize) -> Result<String, String> {
    use std::io::Read;
    let file = File::open(path).map_err(|_| "verifier kernel original unavailable")?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x9fa0,
        "verifier original is not genuine procfs")?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes).map_err(|_| "verifier kernel original read failed")?;
    ensure(bytes.len() <= maximum && bytes.is_ascii(), "verifier kernel original bound")?;
    String::from_utf8(bytes).map_err(|_| "verifier kernel original encoding".to_owned())
}
pub(super) fn mount_id(fd: RawFd) -> Result<u64, String> {
    let raw = proc_text(&format!("/proc/self/fdinfo/{fd}"), 4096)?;
    let values: Vec<_> = raw.lines().filter_map(|line| line.strip_prefix("mnt_id:\t")).collect();
    ensure(values.len() == 1, "verifier mount ID is ambiguous")?;
    values[0].parse().map_err(|_| "verifier mount ID invalid".to_owned())
}
pub(super) fn process(pid: libc::pid_t) -> Result<(libc::pid_t, u64), String> {
    ensure(pid > 0, "verifier process identity invalid")?;
    let raw = proc_text(&format!("/proc/{pid}/stat"), 4096)?;
    let (prefix, tail) = raw.rsplit_once(") ").ok_or("verifier process stat shape")?;
    ensure(prefix.split_once(" (").is_some_and(|(value, _)| value == pid.to_string()), "verifier stat PID differs")?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    ensure(fields.len() >= 20, "verifier stat is incomplete")?;
    Ok((fields[1].parse().map_err(|_| "verifier parent PID invalid")?,
        fields[19].parse().map_err(|_| "verifier process start invalid")?))
}
pub(super) fn pidfd(pidfd: RawFd, pid: libc::pid_t) -> Result<(), String> {
    let raw = proc_text(&format!("/proc/self/fdinfo/{pidfd}"), 4096)?;
    let values: Vec<_> = raw.lines().filter(|line| line.starts_with("Pid:")).collect();
    ensure(values.len() == 1 && values[0] == format!("Pid:\t{pid}"),
        "verifier PIDFD is not the actual selected process")
}
pub(super) fn namespace(name: &'static str) -> Result<File, String> {
    ensure(matches!(name, "time" | "pid" | "mnt"), "verifier namespace purpose differs")?;
    let file = File::open(format!("/proc/self/ns/{name}")).map_err(|_| "verifier namespace unavailable")?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x6e73_6673,
        "verifier namespace original type differs")?;
    Ok(file)
}
fn boot() -> Result<String, String> {
    let raw = proc_text("/proc/sys/kernel/random/boot_id", 64)?;
    ensure(raw.len() == 37 && raw.ends_with('\n'), "verifier boot original differs")?;
    let value = &raw[..36];
    ensure([8, 13, 18, 23].iter().all(|index| value.as_bytes()[*index] == b'-')
        && value.bytes().enumerate().all(|(index, byte)| [8,13,18,23].contains(&index)
            || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "verifier boot spelling differs")?;
    let bytes = hex::decode(value.replace('-', "")).map_err(|_| "verifier boot decode failed")?;
    ensure(bytes.len() == 16 && bytes.iter().any(|byte| *byte != 0), "verifier boot is empty")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub(crate) struct Origin {
    pub(super) pid: libc::pid_t, start: u64, pidfd: File, pidfd_identity: Identity,
    time: File, time_identity: Identity, pid_namespace: File, pid_identity: Identity,
    pub(super) boot: String,
}
impl Origin {
    pub(super) fn retain(&self) -> Result<Self, String> {
        self.check()?;
        let copy = |file: &File| file.try_clone().map_err(|_| "verifier origin duplication failed".to_owned());
        let owner=Self { pid:self.pid,start:self.start,pidfd:copy(&self.pidfd)?,pidfd_identity:self.pidfd_identity,
            time:copy(&self.time)?,time_identity:self.time_identity,pid_namespace:copy(&self.pid_namespace)?,
            pid_identity:self.pid_identity,boot:self.boot.clone() };
        owner.check()?; self.check()?; Ok(owner)
    }
    pub(crate) fn capture() -> Result<Self, String> {
        root_identity()?;
        let pid = unsafe { libc::getpid() };
        let tasks = std::fs::read_dir("/proc/self/task").map_err(|_| "verifier task inventory unavailable")?
            .collect::<Result<Vec<_>, _>>().map_err(|_| "verifier task inventory changed")?;
        ensure(tasks.len() == 1 && tasks[0].file_name().to_str() == Some(pid.to_string().as_str()),
            "verifier root preparation must precede threads")?;
        let descriptor = owned(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd })?;
        pidfd(descriptor.as_raw_fd(), pid)?;
        let time = namespace("time")?; let pid_namespace = namespace("pid")?;
        Ok(Self { pid, start: process(pid)?.1, pidfd_identity: identity(descriptor.as_raw_fd())?, pidfd: descriptor,
            time_identity: identity(time.as_raw_fd())?, pid_identity: identity(pid_namespace.as_raw_fd())?,
            time, pid_namespace, boot: boot()? })
    }
    pub(super) fn time_identity(&self) -> Result<(u64,u64), String> {
        let info = stat(self.time.as_raw_fd())?; Ok((info.st_dev, info.st_ino))
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        root_identity()?;
        ensure(unsafe { libc::getpid() } == self.pid && process(self.pid)?.1 == self.start && boot()? == self.boot,
            "verifier preparation crossed process/boot/root identity")?;
        pidfd(self.pidfd.as_raw_fd(), self.pid)?;
        ensure(identity(self.pidfd.as_raw_fd())? == self.pidfd_identity
            && identity(self.time.as_raw_fd())? == self.time_identity
            && identity(namespace("time")?.as_raw_fd())? == self.time_identity
            && identity(self.pid_namespace.as_raw_fd())? == self.pid_identity
            && identity(namespace("pid")?.as_raw_fd())? == self.pid_identity,
            "verifier retained PIDFD/time/PID namespace differs")
    }
}
fn root_identity() -> Result<(), String> {
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    ensure(unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } == 0
        && unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } == 0
        && [real_uid, effective_uid, saved_uid, real_gid, effective_gid, saved_gid] == [0; 6],
        "external verifier preparation requires retained real/effective/saved root identity")
}

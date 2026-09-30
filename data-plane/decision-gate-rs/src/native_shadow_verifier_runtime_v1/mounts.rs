//! Purpose-fixed private root attachments, retained until actual child reap.
use super::{ensure, within, Profile, originals::{self, identity, owned, protected_directory, stat, Original}};
use crate::native_secret_broker_v1::image::Image;
use ring::rand::{SecureRandom, SystemRandom};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};

const FLAGS: libc::c_ulong = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
#[repr(C)]
struct OpenHow { flags: u64, mode: u64, resolve: u64 }
fn fixed(root: &File, name: &'static str, directory: bool) -> Result<File, String> {
    ensure(matches!(name, "/proc" | "/etc/serverware/native-shadow-nitro-verifier.json"
        | "/etc/serverware/native-shadow-guest-time-issuer.json"), "verifier mount target differs")?;
    let name = CString::new(name).unwrap();
    let how = OpenHow { flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        | if directory { libc::O_DIRECTORY } else { 0 }) as u64, mode: 0, resolve: 0x10 | 2 | 4 };
    owned(unsafe { libc::syscall(libc::SYS_openat2, root.as_raw_fd(), name.as_ptr(), &how,
        std::mem::size_of::<OpenHow>()) as RawFd })
}
fn target(root: &File, name: &str) -> CString { CString::new(format!("/proc/self/fd/{}{name}", root.as_raw_fd())).unwrap() }
fn mount_id(file: &File) -> Result<u64, String> {
    originals::mount_id(file.as_raw_fd())
}
struct Mount { file: File, device: u64, inode: u64, id: u64 }
impl Mount {
    fn capture(file: File) -> Result<Self, String> {
        let info = stat(file.as_raw_fd())?;
        Ok(Self { device: info.st_dev, inode: info.st_ino, id: mount_id(&file)?, file })
    }
    fn matches(&self, other: &File) -> Result<(), String> {
        let info = stat(other.as_raw_fd())?; let held = stat(self.file.as_raw_fd())?;
        ensure(info.st_dev == self.device && info.st_ino == self.inode && mount_id(other)? == self.id
            && held.st_dev == self.device && held.st_ino == self.inode && mount_id(&self.file)? == self.id,
            "verifier original mount association changed")
    }
    fn restricted(&self, filesystem: Option<libc::c_long>) -> Result<(), String> {
        let mut flags: libc::statvfs = unsafe { std::mem::zeroed() };
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        ensure(unsafe { libc::fstatvfs(self.file.as_raw_fd(), &mut flags) } == 0
            && flags.f_flag & 15 == 15 && unsafe { libc::fstatfs(self.file.as_raw_fd(), &mut fs) } == 0
            && filesystem.is_none_or(|expected| fs.f_type == expected), "verifier readonly mount flags/type differ")
    }
}

pub(super) struct Namespace {
    original: File, current: File, identity: originals::Identity, creator: libc::pid_t,
    pub(super) automatic: bool, restored: bool,
}
impl Namespace {
    pub(super) fn enter() -> Result<Self, String> {
        let original = originals::namespace("mnt")?;
        ensure(unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0, "verifier private mount namespace unavailable")?;
        let opened = (|| { let current = originals::namespace("mnt")?;
            Ok::<_, String>((identity(current.as_raw_fd())?, current)) })();
        let (identity, current) = match opened {
            Ok(value) => value,
            Err(error) => {
                if unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
                    return Err(format!("{error}; original mount namespace restoration also failed"));
                }
                return Err(error);
            }
        };
        let owner = Self { original, identity, current,
            creator: unsafe { libc::getpid() }, automatic: true, restored: false };
        ensure(unsafe { libc::mount(std::ptr::null(), b"/\0".as_ptr().cast(), std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC, std::ptr::null()) } == 0, "verifier namespace propagation is not private")?;
        owner.check()?; Ok(owner)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.restored && unsafe { libc::getpid() } == self.creator
            && identity(self.current.as_raw_fd())? == self.identity
            && identity(originals::namespace("mnt")?.as_raw_fd())? == self.identity,
            "verifier root crossed its actual private mount namespace")
    }
    pub(super) fn restore(&mut self) -> Result<(), String> {
        if self.restored { return Ok(()); }
        self.check()?;
        ensure(unsafe { libc::setns(self.original.as_raw_fd(), libc::CLONE_NEWNS) } == 0,
            "verifier original mount namespace restore failed")?;
        self.restored = true; Ok(())
    }
}
impl Drop for Namespace { fn drop(&mut self) { if self.automatic { let _ = self.restore(); } } }

pub(super) struct Mounts {
    parent: File, directory: File, name: CString, directory_identity: originals::Identity,
    underlying: File, underlying_identity: originals::Identity, mount_path: CString,
    root: Option<Mount>, policy: Option<Mount>, procfs: Option<Mount>,
    root_mounted: bool, policy_mounted: bool, proc_mounted: bool, root_removed: bool, removed: bool,
    creator: libc::pid_t, configuration_path: &'static str, pub(super) automatic: bool,
}
impl Mounts {
    pub(super) fn install(image: &Image, configuration: &Original, issued: u64, deadline: u64, profile: Profile) -> Result<Self, String> {
        within(issued, deadline)?;
        let root = owned(unsafe { libc::open(b"/\0".as_ptr().cast(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
        protected_directory(root.as_raw_fd())?;
        let run = owned(unsafe { libc::openat(root.as_raw_fd(), b"run\0".as_ptr().cast(), libc::O_RDONLY
            | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
        protected_directory(run.as_raw_fd())?;
        let base: &[u8] = match profile {
            Profile::Verifier => b"serverware-native-shadow-verifier\0",
            Profile::TimeIssuer => b"serverware-native-shadow-time-issuer\0",
        };
        let configuration_path = profile.configuration_path();
        within(issued, deadline)?;
        let created = unsafe { libc::mkdirat(run.as_raw_fd(), base.as_ptr().cast(), 0o700) };
        ensure(created == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST), "verifier workspace parent unavailable")?;
        let parent = owned(unsafe { libc::openat(run.as_raw_fd(), base.as_ptr().cast(), libc::O_RDONLY
            | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
        protected_directory(parent.as_raw_fd())?;
        ensure(stat(parent.as_raw_fd())?.st_mode & 0o7777 == 0o700, "verifier workspace parent mode differs")?;
        let mut nonce = [0u8;16]; SystemRandom::new().fill(&mut nonce).map_err(|_| "verifier workspace entropy unavailable")?;
        let name = CString::new(hex::encode(nonce)).unwrap();
        within(issued, deadline)?;
        ensure(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0, "verifier fresh workspace unavailable")?;
        let directory = owned(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), libc::O_RDONLY
            | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
        within(issued, deadline)?;
        ensure(unsafe { libc::mkdirat(directory.as_raw_fd(), b"root\0".as_ptr().cast(), 0o700) } == 0,
            "verifier fresh root target unavailable")?;
        let underlying = owned(unsafe { libc::openat(directory.as_raw_fd(), b"root\0".as_ptr().cast(), libc::O_RDONLY
            | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
        let mount_path = CString::new(format!("/proc/self/fd/{}/root", directory.as_raw_fd())).unwrap();
        let mut owner = Self { directory_identity: identity(directory.as_raw_fd())?, underlying_identity: identity(underlying.as_raw_fd())?,
            parent, directory, name, underlying, mount_path, root: None, policy: None, procfs: None,
            root_mounted: false, policy_mounted: false, proc_mounted: false, root_removed: false, removed: false,
            creator: unsafe { libc::getpid() }, configuration_path, automatic: true };
        let placeholder = fixed(&image.root, configuration_path, false)?;
        let info = stat(placeholder.as_raw_fd())?;
        ensure(info.st_uid == 0 && info.st_gid == 0 && info.st_mode & libc::S_IFMT == libc::S_IFREG
            && info.st_mode & 0o7777 == 0o400 && info.st_size == 0, "verifier policy placeholder is not the fixed empty file")?;
        let proc_placeholder = fixed(&image.root, "/proc", true)?;
        let info = stat(proc_placeholder.as_raw_fd())?;
        ensure(info.st_uid == 0 && info.st_gid == 0 && info.st_mode & 0o7777 == 0o555
            && std::fs::read_dir(format!("/proc/self/fd/{}", proc_placeholder.as_raw_fd()))
                .map_err(|_| "verifier proc placeholder unavailable")?.next().is_none(), "verifier proc target is not empty")?;
        // Capture the real detached mount before moving it. A later failure
        // cannot authorize detaching a newly looked-up, unrelated mount.
        owner.root = Some(Mount::capture(owned(unsafe { libc::fcntl(image.root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) })?)?);
        within(issued, deadline)?;
        ensure(unsafe { libc::syscall(libc::SYS_move_mount, image.root.as_raw_fd(), b"\0".as_ptr().cast::<libc::c_char>(),
            libc::AT_FDCWD, owner.mount_path.as_ptr(), 4u32) } == 0, "verifier immutable root attachment failed")?;
        owner.root_mounted = true;
        let source = CString::new(format!("/proc/self/fd/{}", configuration.file.as_raw_fd())).unwrap();
        let policy_target = target(&image.root, configuration_path);
        configuration.check()?; within(issued, deadline)?;
        ensure(unsafe { libc::mount(source.as_ptr(), policy_target.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) } == 0,
            "verifier original policy bind failed")?;
        owner.policy_mounted = true;
        owner.policy = Some(Mount::capture(fixed(&image.root, configuration_path, false)?)?);
        within(issued, deadline)?;
        ensure(unsafe { libc::mount(std::ptr::null(), policy_target.as_ptr(), std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | FLAGS, std::ptr::null()) } == 0, "verifier policy bind is not readonly")?;
        let proc_target = target(&image.root, "/proc");
        within(issued, deadline)?;
        ensure(unsafe { libc::mount(b"proc\0".as_ptr().cast(), proc_target.as_ptr(), b"proc\0".as_ptr().cast(),
            FLAGS, std::ptr::null()) } == 0, "verifier genuine readonly procfs mount failed")?;
        owner.proc_mounted = true;
        owner.procfs = Some(Mount::capture(fixed(&image.root, "/proc", true)?)?);
        within(issued, deadline)?;
        owner.check(image, configuration)?; Ok(owner)
    }
    fn workspace(&self) -> Result<(), String> {
        protected_directory(self.parent.as_raw_fd())?; protected_directory(self.directory.as_raw_fd())?;
        let named = owned(unsafe { libc::openat(self.parent.as_raw_fd(), self.name.as_ptr(), libc::O_RDONLY
            | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
        let actual = stat(named.as_raw_fd())?; let held = stat(self.directory.as_raw_fd())?;
        ensure(actual.st_dev == held.st_dev && actual.st_ino == held.st_ino
            && actual.st_mode & 0o7777 == 0o700 && held.st_mode & 0o7777 == 0o700
            && (self.root_removed || identity(named.as_raw_fd())? == self.directory_identity
                && identity(self.directory.as_raw_fd())? == self.directory_identity),
            "verifier fresh named/held workspace changed")
    }
    fn named_root(&self) -> Result<File, String> {
        owned(unsafe { libc::openat(self.directory.as_raw_fd(), b"root\0".as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) })
    }
    pub(super) fn check(&self, image: &Image, configuration: &Original) -> Result<(), String> {
        ensure(unsafe { libc::getpid() } == self.creator && !self.removed
            && self.root_mounted && self.policy_mounted && self.proc_mounted,
            "verifier prepared root is not wholly retained")?;
        self.workspace()?;
        self.root.as_ref().ok_or("verifier root original absent")?.matches(&image.root)?;
        self.root.as_ref().unwrap().matches(&self.named_root()?)?;
        let policy = self.policy.as_ref().ok_or("verifier policy mount original absent")?;
        policy.matches(&fixed(&image.root, self.configuration_path, false)?)?;
        policy.restricted(None)?;
        ensure(identity(policy.file.as_raw_fd())? == identity(configuration.file.as_raw_fd())?, "verifier FD3 and named policy differ")?;
        let procfs = self.procfs.as_ref().ok_or("verifier proc mount original absent")?;
        procfs.matches(&fixed(&image.root, "/proc", true)?)?; procfs.restricted(Some(0x9fa0))?;
        ensure(policy.id != procfs.id && policy.id != self.root.as_ref().unwrap().id
            && procfs.id != self.root.as_ref().unwrap().id, "verifier mount identities alias")
    }
    pub(super) fn retire(&mut self) -> Result<(), String> {
        ensure(unsafe { libc::getpid() } == self.creator, "verifier mount owner crossed process")?;
        if self.removed { return Ok(()); }
        self.workspace()?;
        if self.proc_mounted {
            let root = self.root.as_ref().ok_or("verifier cleanup root original absent")?;
            root.matches(&self.named_root()?)?;
            let procfs = self.procfs.as_ref().ok_or("verifier proc mount original was not captured")?;
            procfs.matches(&fixed(&root.file, "/proc", true)?)?;
            ensure(unsafe { libc::umount2(target(&root.file, "/proc").as_ptr(), libc::MNT_DETACH) } == 0,
                "verifier proc detach failed")?;
            self.proc_mounted = false;
        }
        if self.policy_mounted {
            let root = self.root.as_ref().ok_or("verifier cleanup root original absent")?;
            root.matches(&self.named_root()?)?;
            let policy = self.policy.as_ref().ok_or("verifier policy mount original was not captured")?;
            policy.matches(&fixed(&root.file, self.configuration_path, false)?)?;
            ensure(unsafe { libc::umount2(target(&root.file, self.configuration_path).as_ptr(), libc::MNT_DETACH) } == 0,
                "verifier policy detach failed")?;
            self.policy_mounted = false;
        }
        if self.root_mounted {
            self.root.as_ref().ok_or("verifier cleanup root original absent")?.matches(&self.named_root()?)?;
            ensure(unsafe { libc::umount2(self.mount_path.as_ptr(), libc::MNT_DETACH) } == 0, "verifier root detach failed")?;
            self.root_mounted = false;
        }
        if !self.root_removed {
            let named = self.named_root()?;
            ensure(identity(named.as_raw_fd())? == self.underlying_identity
                && identity(self.underlying.as_raw_fd())? == self.underlying_identity,
                "verifier cleanup target differs from its fresh original")?;
            ensure(unsafe { libc::unlinkat(self.directory.as_raw_fd(), b"root\0".as_ptr().cast(), libc::AT_REMOVEDIR) } == 0,
                "verifier empty root target removal failed")?;
            self.root_removed = true;
        }
        // Own unlink changed directory timestamps; retries still select the
        // exact retained device/inode and never a replacement pathname.
        self.workspace()?;
        ensure(unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), libc::AT_REMOVEDIR) } == 0,
            "verifier empty workspace removal failed")?;
        self.removed = true; Ok(())
    }
}
impl Drop for Mounts { fn drop(&mut self) { if self.automatic { let _ = self.retire(); } } }

//! Immutable in-enclave runtime: full pinned copy -> sealed memfd -> readonly
//! loop -> SquashFS. No fs-verity-on-initramfs or hash-only closure assumption.
use super::{ensure, live, ImageConfiguration, HELPER_PATH, IMAGE_PATH, INTERPRETER_PATH};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const MAX_IMAGE: u64 = 512 * 1024 * 1024;
const ALL_SEALS: libc::c_int = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const LOOP_CONFIGURE: libc::c_ulong = 0x4c0a;
const LOOP_GET_STATUS64: libc::c_ulong = 0x4c05;
const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4c82;
const BLKROGET: libc::c_ulong = 0x125e;
const LOOP_FLAGS: u32 = 1 | 4; // READ_ONLY | AUTOCLEAR

#[repr(C)]
struct LoopInfo {
    device: u64, inode: u64, rdevice: u64, offset: u64, size_limit: u64,
    number: u32, encrypt_type: u32, encrypt_key_size: u32, flags: u32,
    file_name: [u8; 64], crypt_name: [u8; 64], encrypt_key: [u8; 32], init: [u64; 2],
}
#[repr(C)]
struct LoopConfiguration { fd: u32, block_size: u32, info: LoopInfo, reserved: [u64; 8] }
#[repr(C)]
struct OpenHow { flags: u64, mode: u64, resolve: u64 }

fn owned(fd: RawFd) -> Result<File, String> {
    ensure(fd >= 0, "native broker image descriptor unavailable")?;
    let original = unsafe { OwnedFd::from_raw_fd(fd) };
    let copied = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    ensure(copied >= 0, "native broker image descriptor retention failed")?;
    Ok(unsafe { File::from_raw_fd(copied) })
}
fn stat(file: &File) -> Result<libc::stat, String> {
    let mut result = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstat(file.as_raw_fd(), &mut result) } == 0, "native broker image stat failed")?;
    Ok(result)
}
fn protected(file: &File) -> Result<(), String> {
    let info = stat(file)?;
    ensure(info.st_uid == 0 && info.st_gid == 0 && info.st_mode & 0o022 == 0,
        "native broker image path ownership differs")
}
fn path(path: &str, directory: bool, write: bool) -> Result<File, String> {
    super::path(path)?;
    let mut current = owned(unsafe { libc::open(b"/\0".as_ptr().cast(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
    protected(&current)?;
    let parts: Vec<_> = path[1..].split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        let component = CString::new(*part).map_err(|_| "native broker path NUL")?;
        current = owned(unsafe { libc::openat(current.as_raw_fd(), component.as_ptr(),
            libc::O_NOFOLLOW | libc::O_CLOEXEC | if last && write { libc::O_RDWR } else { libc::O_RDONLY }
                | if !last || directory { libc::O_DIRECTORY } else { 0 }) })?;
        protected(&current)?;
    }
    Ok(current)
}

fn image_file(root: &File, path: &str, executable: bool, pin: &str, deadline: u64) -> Result<File, String> {
    let path = CString::new(path).map_err(|_| "native broker fixed image path NUL")?;
    let how = OpenHow { flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0, resolve: 0x10 | 1 | 2 | 4 }; // IN_ROOT|NO_XDEV|NO_MAGICLINKS|NO_SYMLINKS
    let file = owned(unsafe { libc::syscall(libc::SYS_openat2, root.as_raw_fd(), path.as_ptr(),
        &how, std::mem::size_of::<OpenHow>()) as RawFd })?;
    let info = stat(&file)?;
    ensure(info.st_mode & libc::S_IFMT == libc::S_IFREG && info.st_uid == 0 && info.st_gid == 0
        && info.st_mode & 0o7022 == 0 && (!executable || info.st_mode & 0o111 != 0)
        && info.st_size > 0 && info.st_size <= 128 * 1024 * 1024,
        "native broker executable/helper original metadata differs")?;
    let mut hash = Sha256::new(); let mut offset = 0; let mut buffer = [0u8; 65536];
    while offset < info.st_size {
        live(deadline)?;
        let length = buffer.len().min((info.st_size - offset) as usize);
        let read = unsafe { libc::pread(file.as_raw_fd(), buffer.as_mut_ptr().cast(), length, offset) };
        ensure(read > 0, "native broker executable/helper read failed")?;
        if offset == 0 && executable { ensure(read >= 4 && &buffer[..4] == b"\x7fELF", "native broker interpreter is not ELF")?; }
        hash.update(&buffer[..read as usize]); offset += read as i64;
    }
    ensure(format!("sha256:{}", hex::encode(hash.finalize())) == pin, "native broker executable/helper pin differs")?;
    live(deadline)?;
    Ok(file)
}

// Own only these newly created random paths. No wildcard cleanup, supplied
// directory deletion, mount reuse or retry exists. Detached roots own the loop
// mount independently after the construction mount has been removed.
struct Workspace { parent: File, directory: File, name: CString, mount_path: CString, mounted: bool, creator: libc::pid_t }
impl Workspace {
    fn create(purpose: &Purpose) -> Result<Self, String> {
        let run = path("/run", true, false)?;
        let (name, parent_path): (&[u8], &str) = if matches!(purpose, Purpose::ExternalShadowVerifier) {
            (b"serverware-native-shadow-verifier\0", "/run/serverware-native-shadow-verifier")
        } else { (b"serverware-native-broker\0", "/run/serverware-native-broker") };
        let result = unsafe { libc::mkdirat(run.as_raw_fd(), name.as_ptr().cast(), 0o700) };
        ensure(result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST),
            "native broker private parent creation failed")?;
        let parent = path(parent_path, true, false)?;
        ensure(stat(&parent)?.st_mode & 0o7777 == 0o700, "native broker private parent mode differs")?;
        let mut nonce = [0u8; 16]; SystemRandom::new().fill(&mut nonce).map_err(|_| "native broker workspace entropy unavailable")?;
        let name = CString::new(hex::encode(nonce)).unwrap();
        ensure(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0,
            "native broker unique workspace creation failed")?;
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        let directory = match owned(fd) { Ok(file) => file, Err(error) => {
            unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR); } return Err(error);
        }};
        let mount_path = CString::new(format!("/proc/self/fd/{}/root", directory.as_raw_fd())).unwrap();
        let owner = Self { parent, directory, name, mount_path, mounted: false, creator: unsafe { libc::getpid() } };
        ensure(unsafe { libc::mkdirat(owner.directory.as_raw_fd(), b"root\0".as_ptr().cast(), 0o700) } == 0,
            "native broker construction mount directory failed")?;
        Ok(owner)
    }
    fn unmount(&mut self) -> Result<(), String> {
        if self.mounted {
            ensure(unsafe { libc::umount2(self.mount_path.as_ptr(), libc::MNT_DETACH) } == 0,
                "native broker construction mount detach failed")?;
            self.mounted = false;
        }
        Ok(())
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } != self.creator { return; }
        let _ = self.unmount();
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), b"loop\0".as_ptr().cast(), 0);
            libc::unlinkat(self.directory.as_raw_fd(), b"root\0".as_ptr().cast(), libc::AT_REMOVEDIR);
            libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), libc::AT_REMOVEDIR);
        }
    }
}

// Closed source purposes share only immutable image custody, never a child,
// key, serving phase or caller-selected executable/helper path.
pub(crate) enum Purpose { Broker, RoleKeyProvisioner, ShadowCustody, ShadowKeyDelivery, ExternalShadowVerifier }
impl Purpose {
    fn paths(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Broker => (IMAGE_PATH, INTERPRETER_PATH, HELPER_PATH),
            Self::RoleKeyProvisioner => ("/opt/serverware/native-role-key-provisioner-runtime.squashfs",
                INTERPRETER_PATH, "/opt/serverware/serverware/native_role_key_provisioner.py"),
            Self::ShadowCustody => (super::shadow_image::IMAGE_PATH,
                super::shadow_image::EXECUTABLE_PATH, super::shadow_image::SECCOMP_PATH),
            Self::ShadowKeyDelivery => (super::shadow_key_delivery::IMAGE_PATH,
                INTERPRETER_PATH, super::shadow_key_delivery::HELPER_PATH),
            Self::ExternalShadowVerifier => (crate::native_shadow_verifier_runtime_v1::IMAGE_PATH,
                crate::native_shadow_verifier_runtime_v1::INTERPRETER_PATH,
                crate::native_shadow_verifier_runtime_v1::ENTRYPOINT_PATH),
        }
    }
}
pub(crate) struct Image {
    pub(crate) root: File,
    pub(crate) interpreter: File,
    _helper: File,
    block: File,
    image: File,
    _original: File,
    root_device: libc::dev_t,
    root_inode: libc::ino_t,
    image_device: libc::dev_t,
    image_inode: libc::ino_t,
    image_length: u64,
    loop_number: u32,
}

impl Image {
    pub(super) fn open(config: &ImageConfiguration, deadline: u64) -> Result<Self, String> {
        Self::open_for(config, deadline, Purpose::Broker)
    }
    pub(crate) fn open_for(config: &ImageConfiguration, deadline: u64, purpose: Purpose) -> Result<Self, String> {
        live(deadline)?;
        let (image_path, executable_path, helper_path) = purpose.paths();
        ensure(config.profile == "sealed-memfd-squashfs-v1" && config.image_path == image_path,
            "native broker image source profile differs")?;
        let original = path(image_path, false, false)?;
        let before = stat(&original)?;
        ensure(before.st_mode & libc::S_IFMT == libc::S_IFREG && before.st_size > 0
            && before.st_size as u64 <= MAX_IMAGE, "native broker full image size/type invalid")?;
        let image = owned(unsafe { libc::syscall(libc::SYS_memfd_create,
            b"serverware-native-broker-image\0".as_ptr().cast::<libc::c_char>(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as RawFd })?;
        ensure(unsafe { libc::fchmod(image.as_raw_fd(), 0o600) } == 0, "native broker sealed image protection failed")?;
        let mut hash = Sha256::new(); let mut offset = 0i64; let mut buffer = [0u8; 65536];
        while offset < before.st_size {
            live(deadline)?;
            let length = buffer.len().min((before.st_size - offset) as usize);
            let read = unsafe { libc::pread(original.as_raw_fd(), buffer.as_mut_ptr().cast(), length, offset) };
            ensure(read > 0, "native broker source image read failed")?;
            let mut written = 0usize;
            while written < read as usize {
                live(deadline)?;
                let count = unsafe { libc::pwrite(image.as_raw_fd(), buffer[written..].as_ptr().cast(), read as usize - written, offset + written as i64) };
                ensure(count > 0, "native broker owned image copy failed")?; written += count as usize;
            }
            hash.update(&buffer[..read as usize]); offset += read as i64;
        }
        ensure(format!("sha256:{}", hex::encode(hash.finalize())) == config.image_sha256
            && unsafe { libc::fcntl(image.as_raw_fd(), libc::F_ADD_SEALS, ALL_SEALS) } == 0,
            "native broker full-image commitment or immutable seals failed")?;
        let image_info = stat(&image)?;
        ensure(image_info.st_size == before.st_size, "native broker sealed copy length differs")?;
        Self::seals(&image, image_info.st_dev, image_info.st_ino, image_info.st_size as u64)?;
        let control = path("/dev/loop-control", false, true)?;
        let control_stat = stat(&control)?;
        ensure(control_stat.st_mode & libc::S_IFMT == libc::S_IFCHR && control_stat.st_rdev == libc::makedev(10, 237),
            "native broker loop control device differs")?;
        let number = unsafe { libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) };
        ensure((0..=1_048_575).contains(&number), "native broker unused loop index unavailable")?;
        let mut workspace = Workspace::create(&purpose)?;
        ensure(unsafe { libc::mknodat(workspace.directory.as_raw_fd(), b"loop\0".as_ptr().cast(),
            libc::S_IFBLK | 0o600, libc::makedev(7, number as u32)) } == 0, "native broker private loop node creation failed")?;
        let block = owned(unsafe { libc::openat(workspace.directory.as_raw_fd(), b"loop\0".as_ptr().cast(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
        let mut configuration: LoopConfiguration = unsafe { std::mem::zeroed() };
        configuration.fd = image.as_raw_fd() as u32;
        configuration.info.flags = LOOP_FLAGS;
        configuration.info.size_limit = image_info.st_size as u64;
        ensure(unsafe { libc::ioctl(block.as_raw_fd(), LOOP_CONFIGURE, &configuration) } == 0,
            "native broker one-shot readonly loop configuration failed")?;
        Self::mapping(&block, image_info.st_dev, image_info.st_ino, image_info.st_size as u64, number as u32)?;
        let source = CString::new(format!("/proc/self/fd/{}", block.as_raw_fd())).unwrap();
        ensure(unsafe { libc::mount(source.as_ptr(), workspace.mount_path.as_ptr(), b"squashfs\0".as_ptr().cast(),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV, std::ptr::null()) } == 0,
            "native broker readonly SquashFS mount failed")?;
        workspace.mounted = true;
        ensure(unsafe { libc::mount(std::ptr::null(), workspace.mount_path.as_ptr(), std::ptr::null(),
            libc::MS_PRIVATE, std::ptr::null()) } == 0, "native broker construction mount private propagation failed")?;
        let root = owned(unsafe { libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, workspace.mount_path.as_ptr(),
            1u32 | libc::O_CLOEXEC as u32) as RawFd })?; // nonrecursive OPEN_TREE_CLONE
        workspace.unmount()?;
        let root_info = stat(&root)?;
        let interpreter = image_file(&root, executable_path, true, &config.interpreter_sha256, deadline)?;
        let helper = image_file(&root, helper_path, false, &config.helper_sha256, deadline)?;
        let owner = Self { root, interpreter, _helper: helper, block, image, _original: original,
            root_device: root_info.st_dev, root_inode: root_info.st_ino,
            image_device: image_info.st_dev, image_inode: image_info.st_ino, image_length: image_info.st_size as u64,
            loop_number: number as u32 };
        owner.check(deadline)?;
        Ok(owner)
    }

    fn seals(image: &File, device: libc::dev_t, inode: libc::ino_t, length: u64) -> Result<(), String> {
        let info = stat(image)?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        ensure(unsafe { libc::fcntl(image.as_raw_fd(), libc::F_GET_SEALS) } == ALL_SEALS
            && unsafe { libc::fstatfs(image.as_raw_fd(), &mut filesystem) } == 0 && filesystem.f_type == 0x0102_1994
            && info.st_dev == device && info.st_ino == inode && info.st_nlink == 0
            && info.st_size as u64 == length && info.st_uid == 0 && info.st_gid == 0 && info.st_mode & 0o7777 == 0o600,
            "native broker sealed image owner changed")
    }

    fn mapping(block: &File, device: libc::dev_t, inode: libc::ino_t, length: u64, number: u32) -> Result<(), String> {
        let mut info: LoopInfo = unsafe { std::mem::zeroed() };
        let mut readonly: libc::c_int = 0;
        let metadata = stat(block)?;
        ensure(metadata.st_mode & libc::S_IFMT == libc::S_IFBLK && metadata.st_uid == 0
            && metadata.st_rdev == libc::makedev(7, number)
            && unsafe { libc::ioctl(block.as_raw_fd(), LOOP_GET_STATUS64, &mut info) } == 0
            && unsafe { libc::ioctl(block.as_raw_fd(), BLKROGET, &mut readonly) } == 0 && readonly == 1
            && info.device == device && info.inode == inode && info.offset == 0 && info.size_limit == length
            && info.number == number && info.flags == LOOP_FLAGS && info.encrypt_type == 0 && info.encrypt_key_size == 0,
            "native broker readonly loop backing association changed")
    }

    pub(crate) fn check(&self, deadline: u64) -> Result<(), String> {
        live(deadline)?;
        Self::seals(&self.image, self.image_device, self.image_inode, self.image_length)?;
        Self::mapping(&self.block, self.image_device, self.image_inode, self.image_length, self.loop_number)?;
        let root = stat(&self.root)?;
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        let mut flags: libc::statvfs = unsafe { std::mem::zeroed() };
        ensure(root.st_mode & libc::S_IFMT == libc::S_IFDIR && root.st_uid == 0 && root.st_gid == 0
            && root.st_dev == self.root_device && root.st_ino == self.root_inode
            && root.st_dev == libc::makedev(7, self.loop_number)
            && unsafe { libc::fstatfs(self.root.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x7371_7368
            && unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut flags) } == 0
            && flags.f_flag & (libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV)
                == libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV,
            "native broker detached readonly SquashFS owner changed")?;
        // Seals, full-image pin and this exact block/mount association preserve
        // already checked interpreter/helper bytes without a hot-path rescan.
        Self::seals(&self.image, self.image_device, self.image_inode, self.image_length)?;
        Self::mapping(&self.block, self.image_device, self.image_inode, self.image_length, self.loop_number)?;
        live(deadline)
    }

    pub(crate) fn retain_artifact(&self, path: &str, pin: &str, deadline: u64) -> Result<File, String> {
        self.check(deadline)?;
        image_file(&self.root, path, false, pin, deadline)
    }
}

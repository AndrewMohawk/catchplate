//! Fixed-name kernel/filesystem originals. No public FD, path, PID or write API.
use super::{live, require, CGROUP_ID, PROC_CGROUP};
use crate::cgroup_control_v1::{verify_directory, DirectoryObservationV1};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, RawFd};

const ROOT: &str = "/sys/fs/cgroup";
const CGROUP2: libc::c_long = 0x6367_7270;
const SYSFS: libc::c_long = 0x6265_6572;
const NSFS: libc::c_long = 0x6e73_6673;
const PROCFS: libc::c_long = 0x9fa0;
const MNT_ID: u32 = 0x1000;
const MOUNT_LIMIT: usize = 256 * 1024;
const READ_FLAGS: i32 = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

#[derive(PartialEq, Eq)]
struct Node { device: u64, inode: u64, mount: u64, mode: u32, uid: u32, gid: u32 }
fn owned(fd: RawFd) -> Result<File, String> {
    require(fd >= 0, "gate cgroup fixed descriptor unavailable")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn node(file: &File) -> Result<Node, String> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let mut statx: libc::statx = unsafe { std::mem::zeroed() };
    require(unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } == 0
        && unsafe { libc::statx(file.as_raw_fd(), b"\0".as_ptr().cast(), libc::AT_EMPTY_PATH | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BASIC_STATS | MNT_ID, &mut statx) } == 0
        && statx.stx_mask & (libc::STATX_BASIC_STATS | MNT_ID) == (libc::STATX_BASIC_STATS | MNT_ID)
        && stat.st_ino == statx.stx_ino && stat.st_dev == libc::makedev(statx.stx_dev_major, statx.stx_dev_minor)
        && stat.st_mode == u32::from(statx.stx_mode) && stat.st_uid == statx.stx_uid && stat.st_gid == statx.stx_gid,
        "gate cgroup descriptor identity differs")?;
    Ok(Node { device: stat.st_dev, inode: stat.st_ino, mount: statx.stx_mnt_id,
        mode: stat.st_mode, uid: stat.st_uid, gid: stat.st_gid })
}
fn fs_type(file: &File) -> Result<libc::c_long, String> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    require(unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0, "gate cgroup filesystem unavailable")?;
    Ok(stat.f_type)
}
fn protected(file: &File, directory: bool) -> Result<(), String> {
    let value = node(file)?;
    require(value.uid == 0 && value.gid == 0 && value.mode & 0o022 == 0 && value.inode != 0
        && value.mode & libc::S_IFMT == if directory { libc::S_IFDIR } else { libc::S_IFREG },
        "gate cgroup fixed path is not protected")
}
fn open_at(parent: &File, name: &str, flags: i32) -> Result<File, String> {
    let name = CString::new(name).map_err(|_| "gate cgroup fixed name invalid")?;
    owned(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) })
}
fn directory(path: &str) -> Result<File, String> {
    let mut current = owned(unsafe { libc::open(b"/\0".as_ptr().cast(), READ_FLAGS | libc::O_DIRECTORY) })?;
    protected(&current, true)?;
    for part in path[1..].split('/') {
        current = open_at(&current, part, READ_FLAGS | libc::O_DIRECTORY)?;
        protected(&current, true)?;
    }
    Ok(current)
}
fn proc_file(path: &str) -> Result<File, String> {
    let path = CString::new(path).map_err(|_| "gate cgroup fixed proc path invalid")?;
    let file = owned(unsafe { libc::open(path.as_ptr(), READ_FLAGS) })?;
    require(fs_type(&file)? == PROCFS && node(&file)?.mode & libc::S_IFMT == libc::S_IFREG,
        "gate cgroup observation is not an actual proc file")?;
    Ok(file)
}
fn namespace(name: &str) -> Result<(File, Node), String> {
    // The two source-fixed proc namespace symlinks intentionally resolve to
    // actual NSFS handles; no caller namespace FD or path is accepted.
    let path = CString::new(format!("/proc/self/ns/{name}")).unwrap();
    let file = owned(unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) })?;
    require(fs_type(&file)? == NSFS, "gate cgroup namespace is not NSFS")?;
    let value = node(&file)?;
    Ok((file, value))
}
fn read(file: &File, maximum: usize, deadline: u64) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        live(deadline)?;
        let size = buffer.len().min(maximum.saturating_sub(result.len()) + 1);
        let count = unsafe { libc::pread(file.as_raw_fd(), buffer.as_mut_ptr().cast(), size, result.len() as libc::off_t) };
        if count < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
        require(count >= 0, "gate cgroup original read failed")?;
        if count == 0 { return Ok(result); }
        require(result.len() + count as usize <= maximum, "gate cgroup original exceeds its bound")?;
        result.extend_from_slice(&buffer[..count as usize]);
    }
}

struct Mount { id: u64, root: String, point: String, options: String, filesystem: String, super_options: String, private: bool }
fn mounts(deadline: u64) -> Result<Vec<Mount>, String> {
    let bytes = read(&proc_file("/proc/self/mountinfo")?, MOUNT_LIMIT, deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "gate cgroup mount table encoding")?;
    require(text.is_ascii() && text.ends_with('\n'), "gate cgroup mount table is not bounded ASCII")?;
    let mut result = Vec::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let separator = fields.iter().position(|value| *value == "-").ok_or("gate cgroup mount record incomplete")?;
        require(separator >= 6 && fields.len() == separator + 4 && result.len() < 4096,
            "gate cgroup mount record bound or shape differs")?;
        let id: u64 = fields[0].parse().map_err(|_| "gate cgroup mount ID spelling")?;
        require(id > 0 && id.to_string() == fields[0] && !result.iter().any(|v: &Mount| v.id == id),
            "gate cgroup mount ID repeats")?;
        result.push(Mount { id, root: fields[3].into(), point: fields[4].into(), options: fields[5].into(),
            filesystem: fields[separator + 1].into(), super_options: fields[separator + 3].into(), private: separator == 6 });
    }
    Ok(result)
}
fn require_mount(root: &File, deadline: u64) -> Result<(), String> {
    let table = mounts(deadline)?;
    let current = node(root)?;
    let matching: Vec<_> = table.iter().filter(|v| v.filesystem == "cgroup2" || v.point == ROOT).collect();
    require(matching.len() == 1, "gate cgroup hierarchy is duplicated or overmounted")?;
    let entry = matching[0];
    require(entry.id == current.mount && entry.root == "/" && entry.point == ROOT && entry.private
        && entry.filesystem == "cgroup2" && entry.super_options == "rw"
        && ["rw", "nosuid", "nodev", "noexec"].iter().all(|flag| entry.options.split(',').any(|v| v == *flag))
        && !entry.options.split(',').any(|v| v == "ro") && fs_type(root)? == CGROUP2,
        "gate cgroup requires one private protected writable hierarchy root")
}
fn hierarchy(deadline: u64) -> Result<File, String> {
    let target = directory(ROOT)?;
    if fs_type(&target)? != CGROUP2 {
        let table = mounts(deadline)?;
        let original = node(&target)?;
        let backing: Vec<_> = table.iter().filter(|v| v.id == original.mount).collect();
        require(fs_type(&target)? == SYSFS && backing.len() == 1 && backing[0].private
            && backing[0].filesystem == "sysfs" && backing[0].root == "/" && backing[0].point == "/sys"
            && !table.iter().any(|v| v.filesystem == "cgroup2" || v.point == ROOT),
            "gate cgroup mountpoint is not the genuine private sysfs original")?;
        // Use the held mountpoint, not a caller path. The private parent mount
        // check precedes mount(), so creation cannot propagate to a peer mount.
        let path = CString::new(format!("/proc/self/fd/{}", target.as_raw_fd())).unwrap();
        require(unsafe { libc::mount(b"none\0".as_ptr().cast(), path.as_ptr(), b"cgroup2\0".as_ptr().cast(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, std::ptr::null()) } == 0,
            "gate cgroup source-fixed hierarchy mount failed")?;
    }
    let root = directory(ROOT)?;
    require_mount(&root, deadline)?;
    verify_directory(root.as_fd()).map_err(|error| error.to_string())?;
    Ok(root)
}

struct ReadOriginal { name: &'static str, file: File, node: Node }
impl ReadOriginal {
    fn open(leaf: &File, name: &'static str) -> Result<Self, String> {
        let file = open_at(leaf, name, READ_FLAGS)?;
        protected(&file, false)?;
        let original = node(&file)?;
        let parent = node(leaf)?;
        require(original.mount == parent.mount && original.device == parent.device, "gate cgroup control mount differs")?;
        Ok(Self { name, file, node: original })
    }
    fn check(&self, leaf: &File) -> Result<(), String> {
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        let fd_flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFD) };
        require(flags >= 0 && fd_flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY && fd_flags & libc::FD_CLOEXEC != 0
            && node(&self.file)? == self.node && node(&open_at(leaf, self.name, READ_FLAGS)?)? == self.node,
            "gate cgroup readonly control original changed")
    }
}

pub(super) struct Originals {
    root: File, root_identity: DirectoryObservationV1,
    leaf: File, leaf_identity: DirectoryObservationV1,
    procs: ReadOriginal, kind: ReadOriginal, stat: ReadOriginal,
    proc_cgroup: File,
    cgroup_namespace: (File, Node), mount_namespace: (File, Node),
}
impl Originals {
    pub(super) fn prepare(deadline: u64) -> Result<Self, String> {
        live(deadline)?;
        require(read(&proc_file("/proc/self/cgroup")?, 65536, deadline)? == b"0::/\n",
            "gate cgroup preparation requires the actual unified hierarchy root")?;
        let cgroup_namespace = namespace("cgroup")?;
        let mount_namespace = namespace("mnt")?;
        let root = hierarchy(deadline)?;
        let root_identity = verify_directory(root.as_fd()).map_err(|error| error.to_string())?;
        let name = CString::new(CGROUP_ID).unwrap();
        require(unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o755) } == 0,
            "gate cgroup leaf already exists or cannot be created; no reuse")?;
        // Failures after creation leave a never-reused tombstone unless a full
        // prepared owner can subsequently prove the original still empty.
        let leaf = open_at(&root, CGROUP_ID, READ_FLAGS | libc::O_DIRECTORY)?;
        require(unsafe { libc::fchmod(leaf.as_raw_fd(), 0o755) } == 0,
            "gate cgroup fresh leaf mode could not be fixed")?;
        let leaf_identity = verify_directory(leaf.as_fd()).map_err(|error| error.to_string())?;
        require(leaf_identity.gid() == 0 && leaf_identity.mode() & 0o7777 == 0o755
            && leaf_identity.device() == root_identity.device() && leaf_identity.mount_id() == root_identity.mount_id(),
            "gate cgroup fresh leaf identity or protection differs")?;
        Ok(Self { procs: ReadOriginal::open(&leaf, "cgroup.procs")?, kind: ReadOriginal::open(&leaf, "cgroup.type")?,
            stat: ReadOriginal::open(&leaf, "cgroup.stat")?, proc_cgroup: proc_file("/proc/self/cgroup")?,
            root, root_identity, leaf, leaf_identity, cgroup_namespace, mount_namespace })
    }
    pub(super) fn check(&self, attached: bool, pid: libc::pid_t, deadline: u64) -> Result<(), String> {
        live(deadline)?;
        require(unsafe { libc::getpid() } == pid, "gate cgroup creator differs")?;
        for (name, original) in [("cgroup", &self.cgroup_namespace), ("mnt", &self.mount_namespace)] {
            require(node(&original.0)? == original.1 && namespace(name)?.1 == original.1,
                "gate cgroup namespace original changed")?;
        }
        require_mount(&self.root, deadline)?;
        require(verify_directory(self.root.as_fd()).map_err(|e|e.to_string())? == self.root_identity
            && verify_directory(directory(ROOT)?.as_fd()).map_err(|e|e.to_string())? == self.root_identity
            && verify_directory(self.leaf.as_fd()).map_err(|e|e.to_string())? == self.leaf_identity
            && verify_directory(open_at(&self.root, CGROUP_ID, READ_FLAGS | libc::O_DIRECTORY)?.as_fd())
                .map_err(|e|e.to_string())? == self.leaf_identity, "gate cgroup directory original changed")?;
        for control in [&self.procs, &self.kind, &self.stat] { control.check(&self.leaf)?; }
        require(read(&self.kind.file, 64, deadline)? == b"domain\n", "gate cgroup is not a domain leaf")?;
        let statistics = read(&self.stat.file, 4096, deadline)?;
        let statistics = std::str::from_utf8(&statistics).map_err(|_| "gate cgroup stat encoding")?;
        for name in ["nr_descendants", "nr_dying_descendants"] {
            let prefix = format!("{name} ");
            let values: Vec<_> = statistics.lines().filter_map(|line| line.strip_prefix(prefix.as_str())).collect();
            require(values == ["0"], "gate cgroup acquired a descendant")?;
        }
        let expected = if attached { format!("{pid}\n").into_bytes() } else { Vec::new() };
        require(read(&self.procs.file, 65536, deadline)? == expected, "gate cgroup is not exclusively the original gate")?;
        let expected = if attached { PROC_CGROUP } else { b"0::/\n" };
        require(read(&self.proc_cgroup, 65536, deadline)? == expected
            && read(&proc_file("/proc/self/cgroup")?, 65536, deadline)? == expected,
            "gate cgroup actual proc membership changed")?;
        live(deadline)
    }
    pub(super) fn attach(&self, pid: libc::pid_t, deadline: u64) -> Result<(), String> {
        self.check(false, pid, deadline)?;
        let writer = open_at(&self.leaf, "cgroup.procs", libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC)?;
        require(node(&writer)? == self.procs.node, "gate cgroup migration target differs")?;
        let bytes = format!("{pid}\n");
        live(deadline)?;
        let count = unsafe { libc::write(writer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        drop(writer); // No writable descriptor survives even an uncertain write.
        require(count == bytes.len() as isize, "gate cgroup one-use migration failed or is uncertain")?;
        self.check(true, pid, deadline)
    }
    pub(super) fn remove_empty(&self, pid: libc::pid_t, deadline: u64) -> Result<(), String> {
        self.check(false, pid, deadline)?;
        let name = CString::new(CGROUP_ID).unwrap();
        require(unsafe { libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == 0,
            "gate cgroup original empty-leaf removal failed")
    }
}

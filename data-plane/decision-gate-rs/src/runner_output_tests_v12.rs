//! Small real-FD component tests, not privileged lifecycle or Docker evidence.

use super::{create_runner_output_v12, open_directory_fd_v12, read_runner_result_v12};
use crate::plan_protocol::RunnerExecutionBoundsV12;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const REPORT: &str = "terminal.json";
const PRIVATE_FILE_ERROR: &str =
    "runner result is not its owned bounded private regular file";

struct CreatedEntry {
    path: PathBuf,
    device: u64,
    inode: u64,
    directory: bool,
}

struct SmallTaskDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    entries: Vec<CreatedEntry>,
}

impl SmallTaskDirectory {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        for _ in 0..32 {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "catchplate-runner-output-{}-{stamp}-{sequence}",
                std::process::id(),
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    let uid = unsafe { libc::geteuid() };
                    let gid = unsafe { libc::getegid() };
                    let metadata = fs::symlink_metadata(&path).unwrap();
                    let task = Self {
                        path,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        uid,
                        gid,
                        entries: Vec::new(),
                    };
                    assert!(metadata.is_dir());
                    assert_eq!(metadata.uid(), uid);
                    // Arm exact-inode cleanup before fallible setup. A
                    // restrictive caller umask must not alter the fixture.
                    fs::set_permissions(&task.path, fs::Permissions::from_mode(0o700)).unwrap();
                    // A setgid temporary parent may supply a different group.
                    // The owner can select its actual effective group without
                    // privilege; never substitute a fabricated privileged UID.
                    let directory = File::open(&task.path).unwrap();
                    assert_eq!(unsafe {
                        libc::fchown(directory.as_raw_fd(), libc::uid_t::MAX, gid)
                    }, 0);
                    let metadata = directory.metadata().unwrap();
                    assert_eq!(metadata.gid(), gid);
                    return task;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create exclusive small task directory: {error}"),
            }
        }
        panic!("exclusive small task directory name attempts exhausted");
    }

    fn path_for(&self, name: &str) -> PathBuf {
        assert!(!name.is_empty() && !name.contains('/') && !name.contains('\0'));
        assert!(!matches!(name, "." | ".."));
        self.path.join(name)
    }

    fn record_created(&mut self, path: PathBuf) {
        assert_eq!(path.parent(), Some(self.path.as_path()));
        let metadata = fs::symlink_metadata(&path).unwrap();
        self.entries.push(CreatedEntry {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            directory: metadata.is_dir(),
        });
    }

    fn file(&mut self, name: &str, bytes: &[u8]) -> PathBuf {
        assert!(bytes.len() <= 1024);
        let path = self.path_for(name);
        let mut file = OpenOptions::new().write(true).create_new(true)
            .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path).unwrap();
        self.record_created(path.clone());
        file.set_permissions(fs::Permissions::from_mode(0o600)).unwrap();
        file.write_all(bytes).unwrap();
        drop(file);
        path
    }

    fn fd(&self) -> OwnedFd {
        open_directory_fd_v12(&self.path).unwrap()
    }

    fn read(&self, directory: &OwnedFd, name: &str, maximum: u64)
        -> super::Result<Vec<u8>>
    {
        read_runner_result_v12(directory.as_raw_fd(), name, self.uid, self.gid, maximum)
    }
}

fn same_inode(metadata: &Metadata, device: u64, inode: u64) -> bool {
    metadata.dev() == device && metadata.ino() == inode
}

impl Drop for SmallTaskDirectory {
    fn drop(&mut self) {
        let Ok(root) = fs::symlink_metadata(&self.path) else { return; };
        if !root.is_dir() || root.uid() != self.uid
            || !same_inode(&root, self.device, self.inode)
        {
            return;
        }
        // Never recurse, follow a symlink, or remove a path not created here.
        for entry in self.entries.iter().rev() {
            if entry.path.parent() != Some(self.path.as_path()) {
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(&entry.path) else { continue; };
            if !same_inode(&metadata, entry.device, entry.inode)
                || metadata.is_dir() != entry.directory
            {
                continue;
            }
            if entry.directory {
                let _ = fs::remove_dir(&entry.path);
            } else {
                let _ = fs::remove_file(&entry.path);
            }
        }
        let Ok(root) = fs::symlink_metadata(&self.path) else { return; };
        if root.is_dir() && same_inode(&root, self.device, self.inode) {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

#[test]
fn runner_output_reads_exact_owned_bytes_at_the_bound() {
    let mut task = SmallTaskDirectory::new();
    task.file(REPORT, b"{\"ok\":true}");
    let directory = task.fd();
    assert_eq!(task.read(&directory, REPORT, 11).unwrap(), b"{\"ok\":true}");
    assert_eq!(task.read(&directory, REPORT, 12).unwrap(), b"{\"ok\":true}");
}

#[test]
fn runner_output_rejects_missing_empty_oversize_and_zero_bound() {
    let mut task = SmallTaskDirectory::new();
    let directory = task.fd();
    assert!(matches!(task.read(&directory, REPORT, 16),
        Err(super::ControllerError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound));
    task.file("empty.json", b"");
    task.file(REPORT, b"123456789");
    for (name, maximum) in [("empty.json", 16), (REPORT, 8), (REPORT, 0)] {
        assert_eq!(task.read(&directory, name, maximum).unwrap_err().to_string(),
            PRIVATE_FILE_ERROR);
    }
}

#[test]
fn runner_output_rejects_symlinks_and_hardlinks() {
    let mut task = SmallTaskDirectory::new();
    let original = task.file("original.json", b"{}");
    let symlink = task.path_for(REPORT);
    std::os::unix::fs::symlink(&original, &symlink).unwrap();
    task.record_created(symlink);
    let directory = task.fd();
    assert!(matches!(task.read(&directory, REPORT, 2),
        Err(super::ControllerError::Io(error)) if error.raw_os_error() == Some(libc::ELOOP)));
    let hardlink = task.path_for("hardlink.json");
    fs::hard_link(&original, &hardlink).unwrap();
    task.record_created(hardlink);
    for name in ["original.json", "hardlink.json"] {
        assert_eq!(task.read(&directory, name, 2).unwrap_err().to_string(),
            PRIVATE_FILE_ERROR);
    }
}

#[test]
fn runner_output_rejects_directory_and_fifo_without_a_writer() {
    let mut task = SmallTaskDirectory::new();
    let child = task.path_for("directory.json");
    fs::DirBuilder::new().mode(0o700).create(&child).unwrap();
    task.record_created(child.clone());
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    let fifo = task.path_for("fifo.json");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    task.record_created(fifo.clone());
    fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
    let directory = task.fd();
    // The real reader's O_NONBLOCK open must not await a FIFO writer.
    for name in ["directory.json", "fifo.json"] {
        assert_eq!(task.read(&directory, name, 1024).unwrap_err().to_string(),
            PRIVATE_FILE_ERROR);
    }
}

#[test]
fn runner_output_requires_both_exact_owner_ids() {
    let mut task = SmallTaskDirectory::new();
    task.file(REPORT, b"{}");
    let directory = task.fd();
    task.read(&directory, REPORT, 2).unwrap();
    for (uid, gid) in [(task.uid ^ 1, task.gid), (task.uid, task.gid ^ 1)] {
        assert_eq!(read_runner_result_v12(directory.as_raw_fd(), REPORT, uid, gid, 2)
            .unwrap_err().to_string(), PRIVATE_FILE_ERROR);
    }
}

#[test]
fn runner_output_rejects_group_or_other_file_permissions() {
    let mut task = SmallTaskDirectory::new();
    let report = task.file(REPORT, b"{}");
    let directory = task.fd();
    for mode in [0o640, 0o620, 0o610, 0o604, 0o602, 0o601] {
        fs::set_permissions(&report, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(task.read(&directory, REPORT, 2).unwrap_err().to_string(),
            PRIVATE_FILE_ERROR);
    }
    fs::set_permissions(&report, fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(task.read(&directory, REPORT, 2).unwrap(), b"{}");
}

#[test]
fn runner_output_rechecks_retained_directory_permissions() {
    let mut task = SmallTaskDirectory::new();
    task.file(REPORT, b"{}");
    let directory = task.fd();
    for mode in [0o770, 0o702] {
        fs::set_permissions(&task.path, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(task.read(&directory, REPORT, 2).unwrap_err().to_string(),
            "private DinD retained CAS descriptor is not a sealed directory");
    }
    fs::set_permissions(&task.path, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(task.read(&directory, REPORT, 2).unwrap(), b"{}");
}

#[test]
fn runner_output_requires_one_filename_before_opening() {
    let mut task = SmallTaskDirectory::new();
    task.file(REPORT, b"{}");
    let directory = task.fd();
    for name in ["", ".", "..", "../terminal.json", "sub/terminal.json", "/terminal.json"] {
        assert_eq!(task.read(&directory, name, 2).unwrap_err().to_string(),
            "runner result is not one fixed filename");
    }
    assert_eq!(task.read(&directory, "terminal\0.json", 2).unwrap_err().to_string(),
        "runner result name contains NUL");
}

#[test]
fn runner_output_rejects_standard_and_regular_file_directory_fds() {
    let mut task = SmallTaskDirectory::new();
    let report = task.file(REPORT, b"{}");
    assert_eq!(read_runner_result_v12(0, REPORT, task.uid, task.gid, 2)
        .unwrap_err().to_string(),
        "private DinD retained directory aliases a standard descriptor");
    let regular = File::open(report).unwrap();
    assert_eq!(read_runner_result_v12(regular.as_raw_fd(), REPORT, task.uid, task.gid, 2)
        .unwrap_err().to_string(),
        "private DinD retained CAS descriptor is not a sealed directory");
}

#[test]
fn runner_output_creation_rejects_unsafe_parent_without_creating_child() {
    let task = SmallTaskDirectory::new();
    let child = task.path_for("must-not-exist");
    let bounds = RunnerExecutionBoundsV12 {
        user_uid: 1000, user_gid: 1000,
        cpu_quota_micros: 1000, cpu_period_micros: 100_000,
        memory_bytes: 256 * 1024 * 1024, pids: 16, open_files: 64,
        shm_bytes: 16 * 1024 * 1024, run_tmpfs_bytes: 1024 * 1024,
        tmp_tmpfs_bytes: 16 * 1024 * 1024, private_data_bytes: 16 * 1024 * 1024,
        output_bytes: 16 * 1024 * 1024, output_inodes: 64,
    };
    for mode in [0o755, 0o770, 0o777] {
        fs::set_permissions(&task.path, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(create_runner_output_v12(&task.path, &child, &bounds)
            .err().unwrap().to_string(),
            "runner output lacks a privileged private generation parent");
        assert!(matches!(fs::symlink_metadata(&child),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound));
    }
    fs::set_permissions(&task.path, fs::Permissions::from_mode(0o700)).unwrap();
}

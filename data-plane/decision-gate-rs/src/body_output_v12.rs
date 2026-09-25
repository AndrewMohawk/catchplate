//! Controller-owned stream capture and exact retained-FD payload collection.
//!
//! Streams and manifest are excluded from the payload manifest, not from the
//! signed tmpfs byte/inode capacities. Capture receipts are compared to actual
//! originals; neither those receipts nor this ordinary result assert runtime,
//! signature, courier, destruction or durable-host-storage authority.

use super::{sha256, ControllerError, Digest, Result, MAX_BODY_RESULT_BYTES_V12,
    PRIVATE_DIND_BODY_RESULT_V12};
use super::body_output_files_v12::{live, Directory, Leaf, Policy};
use crate::plan_protocol::{LogicalLane, RunnerExecutionBoundsV12};
use crate::plan_protocol::body_output_contract_v12::{self as contract,
    OutputFileV12, CONTROL_DIRECTORY, STDOUT_NAME, STDERR_NAME, MANIFEST_NAME};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

pub(super) struct BodyOutputCollectionV12 {
    pub(super) stdout_sha256: Digest,
    pub(super) stderr_sha256: Digest,
    pub(super) output_manifest_sha256: Digest,
    pub(super) terminal_file_sha256: Digest,
    pub(super) terminal_file_bytes: u64,
    pub(super) files: Vec<OutputFileV12>,
}

pub(super) struct CaptureOutputsV12 {
    root: Directory,
    controls: Directory,
    stdout: Leaf,
    stderr: Leaf,
    writers: Option<(File, File)>,
    uid: u32,
    gid: u32,
    deadline: u64,
}

fn rejected(message: &'static str) -> ControllerError {
    ControllerError::Rejected(message)
}

fn contract_error(error: crate::plan_protocol::PlanProtocolError) -> ControllerError {
    ControllerError::InvalidOwned(error.to_string())
}

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn exclusive_file(directory: &Directory, name: &str, deadline: u64) -> Result<File> {
    directory.verify_anchor(deadline)?;
    // Every call site supplies one of the three source-fixed control names.
    if !matches!(name, STDOUT_NAME | STDERR_NAME | MANIFEST_NAME) {
        return Err(rejected("controller output filename is not source-fixed"));
    }
    let name = CString::new(name).map_err(|_| rejected("controller output filename has NUL"))?;
    let raw = unsafe { libc::openat(directory.fd(), name.as_ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW
            | libc::O_NONBLOCK | libc::O_CLOEXEC, 0o600) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let file = unsafe { File::from_raw_fd(raw) };
    // Set only the newly, exclusively created inode; never adopt a prior file.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)?;
    Ok(file)
}

fn terminal_name_is_fixed(name: &str) -> bool {
    name == PRIVATE_DIND_BODY_RESULT_V12
        || [LogicalLane::Build, LogicalLane::Unit, LogicalLane::Integration,
            LogicalLane::E2e, LogicalLane::Attestation].iter().any(|lane| {
                name == format!("{}-{}.json", PRIVATE_DIND_BODY_RESULT_V12, lane.ordinal())
            })
}

fn split_parent(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn expected_tree(paths: &[String], terminal_name: &str)
    -> BTreeMap<String, BTreeSet<String>> {
    let mut tree = BTreeMap::new();
    tree.insert(String::new(), [CONTROL_DIRECTORY.to_owned(), terminal_name.to_owned()]
        .into_iter().collect::<BTreeSet<_>>());
    for path in paths {
        let mut parent = String::new();
        let components: Vec<_> = path.split('/').collect();
        for (index, component) in components.iter().enumerate() {
            tree.entry(parent.clone()).or_insert_with(BTreeSet::new)
                .insert((*component).to_owned());
            if index + 1 < components.len() {
                if !parent.is_empty() { parent.push('/'); }
                parent.push_str(component);
                tree.entry(parent.clone()).or_insert_with(BTreeSet::new);
            }
        }
    }
    tree
}

fn checked_add(total: &mut u64, bytes: u64, maximum: u64) -> Result<()> {
    *total = total.checked_add(bytes).filter(|total| *total <= maximum)
        .ok_or_else(|| rejected("complete body output exceeds its signed logical byte capacity"))?;
    Ok(())
}

impl CaptureOutputsV12 {
    pub(super) fn create(output_root: RawFd, uid: u32, gid: u32,
        deadline: u64) -> Result<Self> {
        live(deadline)?;
        if uid == 0 || gid == 0 || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getegid() } != 0 {
            return Err(rejected("body capture requires a root controller and nonroot payload owner"));
        }
        let mut root = Directory::root(output_root, Policy::Output { uid, gid }, deadline)?;
        // Fresh lane output only. Partial or prior capture custody is not reused.
        root.inventory(&[], deadline)?;
        let control_name = CString::new(CONTROL_DIRECTORY)
            .map_err(|_| rejected("controller directory source name has NUL"))?;
        if unsafe { libc::mkdirat(root.fd(), control_name.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        root.snapshot_after_writes(deadline)?;
        let mut controls = root.child_with_policy(CONTROL_DIRECTORY, Policy::Controller, deadline)?;
        let stdout_file = exclusive_file(&controls, STDOUT_NAME, deadline)?;
        let stderr_file = exclusive_file(&controls, STDERR_NAME, deadline)?;
        controls.snapshot_after_writes(deadline)?;
        let stdout = Leaf::open(&controls, STDOUT_NAME, 0, 0, deadline)?;
        let stderr = Leaf::open(&controls, STDERR_NAME, 0, 0, deadline)?;
        stdout.matches_descriptor(stdout_file.as_raw_fd(), deadline)?;
        stderr.matches_descriptor(stderr_file.as_raw_fd(), deadline)?;
        controls.inventory(&names(&[STDOUT_NAME, STDERR_NAME]), deadline)?;
        root.inventory(&names(&[CONTROL_DIRECTORY]), deadline)?;
        controls.sync(deadline)?;
        root.sync(deadline)?;
        Ok(Self { root, controls, stdout, stderr,
            writers: Some((stdout_file, stderr_file)), uid, gid, deadline })
    }

    pub(super) fn take_streams(&mut self) -> Result<(File, File)> {
        self.root.verify_anchor(self.deadline)?;
        self.controls.verify(self.deadline)?;
        self.stdout.verify(self.deadline)?;
        self.stderr.verify(self.deadline)?;
        self.writers.take().ok_or_else(|| rejected("body capture writers were already taken"))
    }

    pub(super) fn finish(mut self, expected_paths: &[String], terminal_name: &str,
        bounds: &RunnerExecutionBoundsV12, stdout: (Digest, u64), stderr: (Digest, u64),
        deadline: u64) -> Result<BodyOutputCollectionV12> {
        let deadline = deadline.min(self.deadline);
        live(deadline)?;
        bounds.validate().map_err(contract_error)?;
        contract::validate_output_paths(expected_paths).map_err(contract_error)?;
        if self.writers.is_some() || bounds.user_uid != self.uid || bounds.user_gid != self.gid
            || !terminal_name_is_fixed(terminal_name) {
            return Err(rejected("body collection differs from its captured owner or fixed terminal"));
        }
        let stream_limit = contract::stream_byte_limit(bounds.output_bytes).map_err(contract_error)?;
        let stream_limit = usize::try_from(stream_limit)
            .map_err(|_| rejected("body stream limit exceeds usize"))?;
        self.root.snapshot_after_writes(deadline)?;
        self.controls.verify(deadline)?;
        self.controls.inventory(&names(&[STDOUT_NAME, STDERR_NAME]), deadline)?;
        self.stdout.finish_controller_write(stream_limit, deadline)?;
        self.stderr.finish_controller_write(stream_limit, deadline)?;
        let (stdout_sha256, _) = self.stdout.read(false, deadline)?;
        let (stderr_sha256, _) = self.stderr.read(false, deadline)?;
        if (stdout_sha256, self.stdout.byte_count()) != stdout
            || (stderr_sha256, self.stderr.byte_count()) != stderr {
            return Err(rejected("actual body streams differ from completed controller capture"));
        }
        let mut total = 0;
        checked_add(&mut total, self.stdout.byte_count(), bounds.output_bytes)?;
        checked_add(&mut total, self.stderr.byte_count(), bounds.output_bytes)?;
        let tree = expected_tree(expected_paths, terminal_name);
        // tree includes the payload root; controls add a directory and three
        // files, and the selected terminal is one separate root file.
        let inodes = (tree.len() as u64).checked_add(expected_paths.len() as u64)
            .and_then(|count| count.checked_add(5))
            .ok_or_else(|| rejected("body output inode count overflows"))?;
        if inodes > bounds.output_inodes {
            return Err(rejected("complete body output exceeds its signed inode capacity"));
        }
        let root_names: Vec<_> = tree.get("").ok_or_else(|| rejected("body tree root is absent"))?
            .iter().cloned().collect();
        self.root.inventory(&root_names, deadline)?;
        let mut directories: BTreeMap<String, Directory> = BTreeMap::new();
        // Lexical order visits every parent before its descendants. Unknown
        // entries are denied by each bounded inventory before any descent.
        for (path, children) in tree.iter().filter(|(path, _)| !path.is_empty()) {
            let (parent, name) = split_parent(path);
            let parent = if parent.is_empty() { &self.root } else {
                directories.get(parent).ok_or_else(|| rejected("body directory parent is absent"))?
            };
            let directory = parent.child(name, deadline)?;
            directory.inventory(&children.iter().cloned().collect::<Vec<_>>(), deadline)?;
            directories.insert(path.clone(), directory);
        }
        let mut terminal = Leaf::open(&self.root, terminal_name, 1,
            MAX_BODY_RESULT_BYTES_V12, deadline)?;
        checked_add(&mut total, terminal.byte_count(), bounds.output_bytes)?;
        let (terminal_file_sha256, _) = terminal.read(false, deadline)?;
        let terminal_file_bytes = terminal.byte_count();
        let mut retained = Vec::with_capacity(expected_paths.len());
        let mut files = Vec::with_capacity(expected_paths.len());
        for path in expected_paths {
            let (parent, name) = split_parent(path);
            let parent = if parent.is_empty() { &self.root } else {
                directories.get(parent).ok_or_else(|| rejected("body file parent is absent"))?
            };
            let remaining = usize::try_from(bounds.output_bytes - total)
                .map_err(|_| rejected("body logical byte capacity exceeds usize"))?;
            let mut file = Leaf::open(parent, name, 0, remaining, deadline)?;
            checked_add(&mut total, file.byte_count(), bounds.output_bytes)?;
            let (digest, _) = file.read(false, deadline)?;
            files.push(OutputFileV12 { path: path.clone(), sha256: digest, bytes: file.byte_count() });
            retained.push(file);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        live(deadline)?;
        let manifest = contract::manifest_bytes(expected_paths, &files, bounds.output_bytes)
            .map_err(contract_error)?;
        live(deadline)?;
        checked_add(&mut total, manifest.len() as u64, bounds.output_bytes)?;
        let output_manifest_sha256 = sha256(&manifest);
        let mut published = exclusive_file(&self.controls, MANIFEST_NAME, deadline)?;
        for chunk in manifest.chunks(64 * 1024) {
            live(deadline)?;
            published.write_all(chunk)?;
        }
        live(deadline)?;
        published.sync_all()?;
        live(deadline)?;
        self.controls.snapshot_after_writes(deadline)?;
        let mut manifest_file = Leaf::open(&self.controls, MANIFEST_NAME,
            manifest.len(), manifest.len(), deadline)?;
        manifest_file.matches_descriptor(published.as_raw_fd(), deadline)?;
        let (actual_manifest_digest, actual_manifest) = manifest_file.read(true, deadline)?;
        if actual_manifest_digest != output_manifest_sha256 || actual_manifest != manifest {
            return Err(rejected("controller manifest publication differs from measured outputs"));
        }
        drop(published);
        self.controls.sync(deadline)?;
        self.root.sync(deadline)?;
        for file in &retained { file.verify(deadline)?; }
        terminal.verify(deadline)?;
        self.stdout.verify(deadline)?;
        self.stderr.verify(deadline)?;
        manifest_file.verify(deadline)?;
        for (path, directory) in directories.iter().rev() {
            let expected: Vec<_> = tree.get(path)
                .ok_or_else(|| rejected("body directory inventory disappeared"))?
                .iter().cloned().collect();
            directory.inventory(&expected, deadline)?;
        }
        self.controls.inventory(&names(&[STDOUT_NAME, STDERR_NAME, MANIFEST_NAME]), deadline)?;
        self.root.inventory(&root_names, deadline)?;
        self.root.verify(deadline)?;
        live(deadline)?;
        Ok(BodyOutputCollectionV12 { stdout_sha256, stderr_sha256,
            output_manifest_sha256, terminal_file_sha256, terminal_file_bytes, files })
    }
}

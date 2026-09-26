//! Privileged fixed-lane output tmpfs ownership, never a host-directory fallback.
//!
//! A root-only sidecar precedes mounting and remains on every failed setup.
//! Recovery checks that exact mount source and custody before strict unmount;
//! no recursive removal or lazy detach is performed here. The caller must first
//! stop/reap processes and remove their cgroups, and must reject any residual
//! generation mounts before its separate recursive generation cleanup.

use super::{
    boottime_now_ns_v11, c_path, canonical_plan_bytes, digest_hex,
    directory_fd_identity_sha256_v12, open_directory_fd_v12,
    require_absolute_normalized, sha256, ControllerError, Digest, LogicalLane,
    Result,
};
use crate::plan_protocol::RunnerExecutionBoundsV12;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MIB: u64 = 1024 * 1024;
const MAX_MOUNTINFO_BYTES: u64 = 8 * MIB;
const MAX_MOUNTINFO_LINES: usize = 65_536;
const MAX_MOUNTINFO_LINE_BYTES: usize = 16 * 1024;
const MAX_RECORD_BYTES: u64 = 4096;
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
const RECORD_VERSION: &str = "serverware/runner-output-storage/v12";
const LANES: [LogicalLane; 5] = [LogicalLane::Build, LogicalLane::Unit,
    LogicalLane::Integration, LogicalLane::E2e, LogicalLane::Attestation];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    version: String,
    generation_device: u64,
    generation_inode: u64,
    mountpoint_device: u64,
    mountpoint_inode: u64,
    lane: u8,
    uid: u32,
    gid: u32,
    output_bytes: u64,
    output_inodes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct RunnerOutputStorageV12 {
    custody: Custody,
    mount_id: u64,
    mounted_device: u64,
    mounted_inode: u64,
    pub(super) directory_identity_sha256: Digest,
}

#[derive(Debug)]
struct Mount {
    id: u64,
    root: Vec<u8>,
    options: Vec<String>,
    optional: Vec<String>,
    filesystem: String,
    source: String,
    super_options: Vec<String>,
}

fn rejected(message: &'static str) -> ControllerError {
    ControllerError::Rejected(message)
}

fn deadline(bound: u64) -> Result<()> {
    if boottime_now_ns_v11()? >= bound {
        return Err(rejected("runner output teardown exceeded its original deadline"));
    }
    Ok(())
}

fn bounded_read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new().read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW).open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(rejected("runner output kernel observation exceeds its bound"));
    }
    Ok(bytes)
}

fn decoded_path(encoded: &str) -> Result<Vec<u8>> {
    if encoded.len() > 16 * 1024 {
        return Err(rejected("runner output mount path exceeds its bound"));
    }
    let raw = encoded.as_bytes();
    let mut result = Vec::with_capacity(raw.len());
    let mut offset = 0;
    while offset < raw.len() {
        if raw[offset] == b'\\' {
            let escape = raw.get(offset + 1..offset + 4)
                .ok_or_else(|| rejected("runner output mount escape is truncated"))?;
            let value = match escape {
                b"040" => b' ', b"011" => b'\t', b"012" => b'\n', b"134" => b'\\',
                _ => return Err(rejected("runner output mount escape is not kernel canonical")),
            };
            result.push(value);
            offset += 4;
        } else {
            result.push(raw[offset]);
            offset += 1;
        }
        if result.len() > 4096 {
            return Err(rejected("runner output decoded mount path exceeds its bound"));
        }
    }
    Ok(result)
}

fn at_or_under(observed: &[u8], expected: &[u8]) -> bool {
    observed == expected || (observed.starts_with(expected)
        && (expected == b"/" || observed.get(expected.len()) == Some(&b'/')))
}

fn mountinfo() -> Result<String> {
    let raw = bounded_read(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO_BYTES)?;
    String::from_utf8(raw).map_err(|_| rejected("runner output mountinfo is not UTF-8"))
}

fn mount_lines(text: &str) -> Result<Vec<&str>> {
    let mut lines = Vec::new();
    for line in text.lines() {
        if line.len() > MAX_MOUNTINFO_LINE_BYTES || lines.len() >= MAX_MOUNTINFO_LINES {
            return Err(rejected("runner output mountinfo structure exceeds its bound"));
        }
        lines.push(line);
    }
    Ok(lines)
}

pub(super) fn contains_mount_under(path: &Path) -> Result<bool> {
    require_absolute_normalized(path)?;
    let text = mountinfo()?;
    let mut found = false;
    for line in mount_lines(&text)? {
        let encoded = line.split(' ').nth(4)
            .ok_or_else(|| rejected("runner output mountinfo line is malformed"))?;
        let observed = decoded_path(encoded)?;
        found |= at_or_under(&observed, path.as_os_str().as_bytes());
    }
    Ok(found)
}

fn one_mount(path: &Path) -> Result<Option<Mount>> {
    let text = mountinfo()?;
    let target = path.as_os_str().as_bytes();
    let mut found = None;
    for line in mount_lines(&text)? {
        let encoded = line.split(' ').nth(4)
            .ok_or_else(|| rejected("runner output mountinfo line is malformed"))?;
        let observed = decoded_path(encoded)?;
        if !at_or_under(&observed, target) { continue; }
        if observed != target || found.is_some() {
            return Err(rejected("runner output has an unexpected descendant or stacked mount"));
        }
        let (head, tail) = line.split_once(" - ")
            .ok_or_else(|| rejected("runner output mountinfo separator is absent"))?;
        let fields: Vec<_> = head.split(' ').collect();
        let trailer: Vec<_> = tail.split(' ').collect();
        if fields.len() < 6 || fields.len() > 32 || trailer.len() != 3 {
            return Err(rejected("runner output mountinfo fields differ"));
        }
        let id = fields[0].parse::<u64>()
            .map_err(|_| rejected("runner output mount identity is invalid"))?;
        if id == 0 { return Err(rejected("runner output mount identity is zero")); }
        found = Some(Mount { id, root: decoded_path(fields[3])?,
            options: fields[5].split(',').map(str::to_owned).collect(),
            optional: fields[6..].iter().map(|part| (*part).to_owned()).collect(),
            filesystem: trailer[0].to_owned(), source: trailer[1].to_owned(),
            super_options: trailer[2].split(',').map(str::to_owned).collect() });
    }
    Ok(found)
}

pub(super) fn fd_mount_id(directory: RawFd) -> Result<u64> {
    if directory < 3 { return Err(rejected("runner output descriptor aliases stdio")); }
    let raw = bounded_read(&PathBuf::from(format!("/proc/self/fdinfo/{directory}")), 16 * 1024)?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| rejected("runner output descriptor metadata is not text"))?;
    let mut found = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("mnt_id:") {
            if found.is_some() { return Err(rejected("runner output descriptor mount identity duplicates")); }
            let id = value.trim().parse::<u64>()
                .map_err(|_| rejected("runner output descriptor mount identity is invalid"))?;
            if id == 0 { return Err(rejected("runner output descriptor mount identity is zero")); }
            found = Some(id);
        }
    }
    found.ok_or_else(|| rejected("runner output descriptor mount identity is absent"))
}

fn directory_stat(directory: RawFd) -> Result<libc::stat> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if directory < 3 || unsafe { libc::fstat(directory, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(rejected("runner output descriptor is not a directory"));
    }
    Ok(value)
}

fn lane_path(generation_root: &Path, path: &Path) -> Result<u8> {
    require_absolute_normalized(generation_root)?;
    require_absolute_normalized(path)?;
    for lane in LANES {
        if path == generation_root.join(format!("runner-output-{}", lane.ordinal())) {
            return Ok(lane.ordinal());
        }
    }
    Err(rejected("runner output is not a source-fixed lane path"))
}

fn record_path(generation_root: &Path, lane: u8) -> PathBuf {
    generation_root.join(format!("runner-output-{lane}.storage-v12.json"))
}

fn record_bytes(record: &Custody) -> Result<Vec<u8>> {
    canonical_plan_bytes(record).map_err(|error| ControllerError::InvalidOwned(error.to_string()))
}

fn source(record: &Custody) -> Result<CString> {
    CString::new(format!("serverware-runner-output-v12-{}", digest_hex(&sha256(&record_bytes(record)?))))
        .map_err(|_| rejected("runner output mount source contains NUL"))
}

fn validate_record(generation_root: &Path, lane: u8, record: &Custody) -> Result<()> {
    let parent = std::fs::symlink_metadata(generation_root)?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o7777 != 0o700
        || record.version != RECORD_VERSION || record.lane != lane
        || (record.generation_device, record.generation_inode) != (parent.dev(), parent.ino())
        || record.mountpoint_inode == 0 || !(1000..=2_147_483_647).contains(&record.uid)
        || !(1000..=2_147_483_647).contains(&record.gid)
        || !(16 * MIB..=1024 * MIB).contains(&record.output_bytes)
        || record.output_bytes % MIB != 0 || !(64..=65_536).contains(&record.output_inodes)
    {
        return Err(rejected("runner output custody differs from fixed generation and capacity"));
    }
    Ok(())
}

fn read_record(generation_root: &Path, lane: u8) -> Result<Custody> {
    let mut file = OpenOptions::new().read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW).open(record_path(generation_root, lane))?;
    let before = file.metadata()?;
    if !before.is_file() || before.uid() != 0 || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1 || before.len() == 0 || before.len() > MAX_RECORD_BYTES {
        return Err(rejected("runner output custody record is not private bounded root data"));
    }
    let mut raw = Vec::new();
    (&mut file).take(MAX_RECORD_BYTES + 1).read_to_end(&mut raw)?;
    let after = file.metadata()?;
    if raw.len() as u64 != before.len() || before.dev() != after.dev() || before.ino() != after.ino()
        || before.len() != after.len() || before.mode() != after.mode() || before.uid() != after.uid()
        || before.gid() != after.gid() || before.nlink() != after.nlink()
        || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() {
        return Err(rejected("runner output custody record changed while read"));
    }
    let record: Custody = serde_json::from_slice(&raw)
        .map_err(|_| rejected("runner output custody record is not closed JSON"))?;
    validate_record(generation_root, lane, &record)?;
    if record_bytes(&record)? != raw { return Err(rejected("runner output custody is not canonical")); }
    Ok(record)
}

fn verify_mount(directory: RawFd, path: &Path, record: &Custody) -> Result<(u64, u64, u64)> {
    let mounted = one_mount(path)?.ok_or_else(|| rejected("runner output tmpfs is absent"))?;
    let expected_source = source(record)?;
    if mounted.filesystem != "tmpfs" || mounted.root.as_slice() != b"/" || !mounted.optional.is_empty()
        || mounted.source.as_bytes() != expected_source.as_bytes()
        || ["rw", "nosuid", "nodev", "noexec"].iter()
            .any(|required| !mounted.options.iter().any(|value| value.as_str() == *required))
        || !mounted.super_options.iter().any(|value| value == "noswap") {
        return Err(rejected("runner output mount is not its private bounded noswap tmpfs"));
    }
    let stat = directory_stat(directory)?;
    if stat.st_uid != record.uid || stat.st_gid != record.gid || stat.st_mode & 0o7777 != 0o700
        || fd_mount_id(directory)? != mounted.id {
        return Err(rejected("runner output directory ownership or mount identity changed"));
    }
    let path_fd = open_directory_fd_v12(path)?;
    let path_stat = directory_stat(path_fd.as_raw_fd())?;
    if (stat.st_dev, stat.st_ino) != (path_stat.st_dev, path_stat.st_ino)
        || fd_mount_id(path_fd.as_raw_fd())? != mounted.id {
        return Err(rejected("runner output retained descriptor differs from its mounted path"));
    }
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory, &mut filesystem) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if filesystem.f_type != TMPFS_MAGIC as _ || filesystem.f_bsize <= 0
        || filesystem.f_blocks.checked_mul(filesystem.f_bsize as u64) != Some(record.output_bytes)
        || filesystem.f_files != record.output_inodes || filesystem.f_bfree > filesystem.f_blocks
        || filesystem.f_bavail > filesystem.f_bfree || filesystem.f_ffree > filesystem.f_files {
        return Err(rejected("runner output actual tmpfs byte or inode capacity changed"));
    }
    Ok((mounted.id, stat.st_dev, stat.st_ino))
}

pub(super) fn create(generation_root: &Path, path: &Path,
    bounds: &RunnerExecutionBoundsV12) -> Result<RunnerOutputStorageV12> {
    // Preserve this check before any child creation, including in negative
    // source fixtures that do not have mount privilege.
    let parent = std::fs::symlink_metadata(generation_root)?;
    if path.parent() != Some(generation_root) || !parent.is_dir() || parent.uid() != 0
        || parent.mode() & 0o7777 != 0o700 {
        return Err(rejected("runner output lacks a privileged private generation parent"));
    }
    let lane = lane_path(generation_root, path)?;
    bounds.validate().map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
    if unsafe { libc::geteuid() } != 0 { return Err(rejected("runner output mounting requires root")); }
    if contains_mount_under(path)? || record_path(generation_root, lane).try_exists()? {
        return Err(rejected("runner output already has mount or custody state"));
    }
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    let underlying = open_directory_fd_v12(path)?;
    let stat = directory_stat(underlying.as_raw_fd())?;
    if stat.st_uid != 0 || stat.st_mode & 0o7777 != 0o700 {
        return Err(rejected("runner output underlying mountpoint is not private root custody"));
    }
    let record = Custody { version: RECORD_VERSION.to_owned(),
        generation_device: parent.dev(), generation_inode: parent.ino(),
        mountpoint_device: stat.st_dev, mountpoint_inode: stat.st_ino, lane,
        uid: bounds.user_uid, gid: bounds.user_gid,
        output_bytes: bounds.output_bytes, output_inodes: bounds.output_inodes };
    validate_record(generation_root, lane, &record)?;
    let bytes = record_bytes(&record)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES { return Err(rejected("runner output custody exceeds its bound")); }
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW).open(record_path(generation_root, lane))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(generation_root)?.sync_all()?;
    if read_record(generation_root, lane)? != record {
        return Err(rejected("runner output custody publication changed"));
    }
    let target = c_path(path)?;
    let filesystem = CString::new("tmpfs").unwrap();
    let mount_source = source(&record)?;
    let options = CString::new(format!("size={},nr_inodes={},mode=0700,uid={},gid={},noswap",
        record.output_bytes, record.output_inodes, record.uid, record.gid))
        .map_err(|_| rejected("runner output mount options contain NUL"))?;
    if unsafe { libc::mount(mount_source.as_ptr(), target.as_ptr(), filesystem.as_ptr(),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, options.as_ptr().cast()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // No noswap fallback. Setup failures retain the fixed record and mount for
    // the same strict recovery path, never anonymous cleanup via lazy detach.
    if unsafe { libc::mount(std::ptr::null(), target.as_ptr(), std::ptr::null(),
        libc::MS_PRIVATE, std::ptr::null()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let directory = open_directory_fd_v12(path)?;
    let (mount_id, mounted_device, mounted_inode) = verify_mount(directory.as_raw_fd(), path, &record)?;
    if (mounted_device, mounted_inode) == (record.mountpoint_device, record.mountpoint_inode) {
        return Err(rejected("runner output tmpfs aliases its underlying mountpoint"));
    }
    let expected = RunnerOutputStorageV12 { custody: record, mount_id, mounted_device,
        mounted_inode, directory_identity_sha256: directory_fd_identity_sha256_v12(directory.as_raw_fd())? };
    verify(directory.as_raw_fd(), path, &expected)?;
    Ok(expected)
}

pub(super) fn verify(directory: RawFd, path: &Path, expected: &RunnerOutputStorageV12) -> Result<()> {
    let generation_root = path.parent().ok_or_else(|| rejected("runner output lacks its generation"))?;
    let lane = lane_path(generation_root, path)?;
    validate_record(generation_root, lane, &expected.custody)?;
    if read_record(generation_root, lane)? != expected.custody
        || verify_mount(directory, path, &expected.custody)?
            != (expected.mount_id, expected.mounted_device, expected.mounted_inode)
        || directory_fd_identity_sha256_v12(directory)? != expected.directory_identity_sha256 {
        return Err(rejected("runner output differs from its retained complete storage identity"));
    }
    Ok(())
}

pub(super) fn teardown(generation_root: &Path, bound: u64) -> Result<()> {
    require_absolute_normalized(generation_root)?;
    deadline(bound)?;
    let parent = match std::fs::symlink_metadata(generation_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if contains_mount_under(generation_root)? {
                return Err(rejected("absent runner generation retains an unexpected mount"));
            }
            deadline(bound)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o7777 != 0o700
        || unsafe { libc::geteuid() } != 0 {
        return Err(rejected("runner output teardown lacks privileged generation custody"));
    }
    for lane in LANES {
        deadline(bound)?;
        let ordinal = lane.ordinal();
        let path = generation_root.join(format!("runner-output-{ordinal}"));
        let storage_record = record_path(generation_root, ordinal);
        let record = match std::fs::symlink_metadata(&storage_record) {
            Ok(_) => Some(read_record(generation_root, ordinal)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if one_mount(&path)?.is_some() {
            let owned = record.as_ref().ok_or_else(|| rejected("runner output mount has no root custody record"))?;
            {
                let directory = open_directory_fd_v12(&path)?;
                verify_mount(directory.as_raw_fd(), &path, owned)?;
            }
            deadline(bound)?;
            let target = c_path(&path)?;
            if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            deadline(bound)?;
        }
        if contains_mount_under(&path)? {
            return Err(rejected("runner output still has a mount before underlying cleanup"));
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700
                    || record.as_ref().is_some_and(|owned|
                        (metadata.dev(), metadata.ino()) != (owned.mountpoint_device, owned.mountpoint_inode)) {
                    return Err(rejected("runner output underlying mountpoint identity changed"));
                }
                // Only the now-unmounted empty underlying directory. Unknown
                // legacy runner-owned host directories fail closed above;
                // never traverse their files or retained partial data.
                std::fs::remove_dir(&path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
        if record.is_some() { std::fs::remove_file(&storage_record)?; }
        File::open(generation_root)?.sync_all()?;
        deadline(bound)?;
    }
    Ok(())
}

//! Retained-descriptor Linux launcher for policy-custody workers and helpers.
//!
//! The launcher accepts only narrow, already verified protocol capabilities
//! before any untrusted invocation bytes exist.

use super::boottime::{
    boottime_now_nanos, poll_until, BoottimeDeadline, BoottimeDomain,
    BoottimeError, DeadlineOperationError, PollInterest, PollTarget,
    WaitOutcome,
};
use super::endpoint_clients::{
    current_endpoint_trust_until, require_same_current_checkpoint,
    verify_watchdog_ownership_ack_with_current_provider,
    verify_watchdog_ownership_query_confirmation,
    CurrentEndpointTrustProvider, EndpointTrustPin,
    VerifiedCurrentKeyEndpointAuthorization,
    VerifiedWatchdogOwnershipAck,
};
use super::protocol::{
    PolicyCustodyEndpointRole, PolicyCustodyOperation,
    ProtocolBoottimeDeadline, SignedWatchdogOwnershipAckV3,
    WatchdogLeaseV3, WatchdogOwnershipQueryReplyV3,
    WatchdogOwnershipQueryV3, WatchdogProcessIdentityV3,
    WatchdogRegistrationFdRole, WatchdogRegistrationV3,
    WatchdogRetainedFdIdentityV3,
    WatchdogRetainedCgroupIdentityV3,
    POLICY_CUSTODY_WATCHDOG_REGISTRATION_VERSION,
};
use super::super::{canonical_json_bytes, Sha256Digest};
use crate::policy_shadow::linux_statx;
use serverware_decision_gate::erofs_loop_v1::{
    self, DescriptorObservationV1, ErofsLoopErrorV1,
    ErofsLoopExpectationV1, ErofsLoopObservationV1,
};
use serverware_decision_gate::cgroup_control_v1::{
    self, EventsV1, PreparedKillV1,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fmt;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::ptr;

const CLONE_PIDFD_FLAG: u64 = 0x0000_1000;
const CLONE_INTO_CGROUP_FLAG: u64 = 0x2_0000_0000;
const AT_EMPTY_PATH_FLAG: libc::c_int = 0x1000;
const AT_RECURSIVE_FLAG: libc::c_int = 0x8000;
const OPEN_TREE_CLONE_FLAG: libc::c_uint = 1;
const OPEN_TREE_CLOEXEC_FLAG: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;
const MOVE_MOUNT_F_EMPTY_PATH_FLAG: libc::c_uint = 0x0000_0004;
const MOUNT_ATTR_RDONLY_FLAG: u64 = 0x0000_0001;
const MOUNT_ATTR_NOSUID_FLAG: u64 = 0x0000_0002;
const MOUNT_ATTR_NODEV_FLAG: u64 = 0x0000_0004;
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const REQUIRED_NAMESPACE_FLAGS: u64 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWNET) as u64;
const FORBIDDEN_CLONE_NAMESPACE_FLAGS: u32 = (libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWTIME
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWUTS) as u32;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const GRND_NONBLOCK_FLAG: libc::c_uint = 0x0001;
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;
const SECCOMP_DATA_ARGS: u32 = 16;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JA_K: u16 = 0x05;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;
const MAX_BOOTSTRAP_FILTER_INSTRUCTIONS: usize = 256;
const MAX_EXACT_FILTER_INSTRUCTIONS: usize = 4096;
const MAX_ARGUMENTS: usize = 64;
const MAX_ENVIRONMENT: usize = 64;
const MAX_INHERITED_FDS: usize = 32;
const MAX_PIDFD_INFO_BYTES: usize = 4096;
const MAX_PROC_MAPS_BYTES: usize = 1024 * 1024;
const MAX_ELF_PROGRAM_HEADERS: usize = 256;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const ELF_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const ELF64_DYNAMIC_ENTRY_BYTES: usize = 16;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const ST_RDONLY_FLAG: libc::c_ulong = 1;
const BLKROGET: libc::Ioctl = 0x125e;
const DM_IOCTL_TYPE: u64 = 0xfd;
const DM_TABLE_STATUS_COMMAND: u64 = 12;
const DM_STATUS_TABLE_FLAG: u32 = 1 << 4;
const DM_BUFFER_FULL_FLAG: u32 = 1 << 8;
const DM_ACTIVE_PRESENT_FLAG: u32 = 1 << 5;
const DM_INACTIVE_PRESENT_FLAG: u32 = 1 << 6;
const DM_SUSPEND_FLAG: u32 = 1 << 1;
const DM_READONLY_FLAG: u32 = 1;
const P_PIDFD_IDTYPE: libc::c_uint = 3;
const CHILD_FAILURE_ROOTFS: u8 = 101;
const CHILD_FAILURE_FD_SETUP: u8 = 102;
const CHILD_FAILURE_PRIVILEGE: u8 = 103;
const CHILD_FAILURE_PARENT: u8 = 104;
const CHILD_FAILURE_FILTER: u8 = 105;
const CHILD_FAILURE_RELEASE: u8 = 106;
const READY_PROOF_BYTES: usize = 32;
const WATCHDOG_NONCE_BYTES: usize = 32;
const MAX_WATCHDOG_PROTOCOL_FRAME_BYTES: usize = 256 * 1024;
const WATCHDOG_CLEANUP_BYTES: usize = 168;
const WATCHDOG_CLEANUP_ACK_BYTES: usize = 72;
const WATCHDOG_PROTOCOL_VERSION: u8 = 1;
const WATCHDOG_CLEANUP_KIND: u8 = 3;
const WATCHDOG_CLEANUP_ACK_KIND: u8 = 4;
const HARD_UNREADY_MESSAGE_BYTES: usize = 72;
const REQUIRED_MEMFD_SEALS: libc::c_int = libc::F_SEAL_SEAL
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_GROW
    | libc::F_SEAL_WRITE;

#[derive(Debug)]
pub(super) enum LauncherError {
    Io(io::Error),
    Boottime(BoottimeError),
    Invalid(&'static str),
    Unsupported(&'static str),
    Deadline(&'static str),
    ChildSetup(u8),
    ChildTerminated {
        ready_proved: bool,
        si_code: libc::c_int,
        status: libc::c_int,
    },
}

impl fmt::Display for LauncherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Boottime(error) => fmt::Display::fmt(error, formatter),
            Self::Invalid(message)
            | Self::Unsupported(message)
            | Self::Deadline(message) => formatter.write_str(message),
            Self::ChildSetup(code) => {
                write!(formatter, "launcher child setup failed with code {code}")
            }
            Self::ChildTerminated {
                ready_proved,
                si_code,
                status,
            } => write!(
                formatter,
                "launcher child terminated (filter-ready={ready_proved}, si_code={si_code}, status={status})"
            ),
        }
    }
}

impl std::error::Error for LauncherError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Boottime(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for LauncherError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ErofsLoopErrorV1> for LauncherError {
    fn from(error: ErofsLoopErrorV1) -> Self {
        match error {
            ErofsLoopErrorV1::Io(error) => Self::Io(error),
            ErofsLoopErrorV1::Invalid(message) => Self::Invalid(message),
        }
    }
}

impl From<BoottimeError> for LauncherError {
    fn from(error: BoottimeError) -> Self {
        Self::Boottime(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecutableArchitecture {
    X86_64,
    Aarch64,
}

impl ExecutableArchitecture {
    fn elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => EM_X86_64,
            Self::Aarch64 => EM_AARCH64,
        }
    }

    fn audit_arch(self) -> u32 {
        match self {
            Self::X86_64 => AUDIT_ARCH_X86_64,
            Self::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    fn host() -> Result<Self, LauncherError> {
        #[cfg(target_arch = "x86_64")]
        {
            Ok(Self::X86_64)
        }
        #[cfg(target_arch = "aarch64")]
        {
            Ok(Self::Aarch64)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(LauncherError::Unsupported(
                "policy-custody launcher supports only x86_64 and aarch64",
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StaticPiePolicy {
    Forbid,
    AllowStaticPie,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LaunchRole {
    Worker,
    Helper,
    Watchdog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescriptorIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
    mode: libc::mode_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    length: u64,
    modified_seconds: libc::time_t,
    modified_nanoseconds: libc::c_long,
    changed_seconds: libc::time_t,
    changed_nanoseconds: libc::c_long,
    mount_id: u64,
}

fn erofs_root_identity(observed: &DescriptorObservationV1) -> DescriptorIdentity {
    DescriptorIdentity {
        device: observed.device(), inode: observed.inode(), mode: observed.mode(),
        uid: observed.uid(), gid: observed.gid(), length: observed.length(),
        modified_seconds: observed.modified_seconds(),
        modified_nanoseconds: observed.modified_nanoseconds(),
        changed_seconds: observed.changed_seconds(),
        changed_nanoseconds: observed.changed_nanoseconds(), mount_id: observed.mount_id(),
    }
}

// The mechanism deliberately does not own this signed static-custody identity.
// Keep the domain, field order, native scalar widths and u64BE framing unchanged.
fn erofs_identity_sha256(observed: &ErofsLoopObservationV1) -> [u8; 32] {
    hash_frames(&[
        b"serverware.policyCustodyRootfs.erofs/v1",
        &observed.root().device().to_be_bytes(),
        &observed.root().inode().to_be_bytes(),
        &observed.root().mount_id().to_be_bytes(),
        &observed.block_rdev().to_be_bytes(),
        &observed.image().device().to_be_bytes(),
        &observed.image().inode().to_be_bytes(),
        &observed.image().length().to_be_bytes(),
        &observed.image_fs_verity_sha256(),
        &observed.loop_offset().to_be_bytes(),
        &observed.loop_size_limit().to_be_bytes(),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ElfValidation {
    architecture: ExecutableArchitecture,
    static_pie: bool,
    entry: u64,
    load_segments: u16,
    file_sha256: [u8; 32],
}

pub(super) struct VerifiedExecutable {
    retained_fd: OwnedFd,
    identity: DescriptorIdentity,
    rootfs_identity_sha256: [u8; 32],
    validation: ElfValidation,
}

impl VerifiedExecutable {
    pub(super) fn open_in_rootfs(
        rootfs: &VerifiedRootfs,
        relative_path: &Path,
        expected_file_sha256: [u8; 32],
        architecture: ExecutableArchitecture,
        static_pie_policy: StaticPiePolicy,
    ) -> Result<Self, LauncherError> {
        if architecture != ExecutableArchitecture::host()? {
            return Err(LauncherError::Unsupported(
                "executable architecture does not match the launcher host",
            ));
        }
        let retained_fd = open_beneath(
            rootfs.root_fd.as_raw_fd(),
            relative_path,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )?;
        let identity = immutable_regular_file_identity(retained_fd.as_raw_fd())?;
        if identity.device != rootfs.mount_identity.device {
            return Err(LauncherError::Invalid(
                "executable is not on the verified root filesystem",
            ));
        }
        let file_sha256 = sha256_descriptor(retained_fd.as_raw_fd())?;
        if file_sha256 != expected_file_sha256 {
            return Err(LauncherError::Invalid(
                "executable content digest mismatch",
            ));
        }
        let validation = validate_static_elf(
            retained_fd.as_raw_fd(),
            identity.length,
            architecture,
            static_pie_policy,
            file_sha256,
        )?;
        Ok(Self {
            retained_fd,
            identity,
            rootfs_identity_sha256: rootfs.identity_sha256,
            validation,
        })
    }

    pub(super) fn validation(&self) -> &ElfValidation {
        &self.validation
    }

    pub(super) fn retained_fd(&self) -> RawFd {
        self.retained_fd.as_raw_fd()
    }

    fn revalidate(&self, rootfs: &VerifiedRootfs) -> Result<(), LauncherError> {
        if self.rootfs_identity_sha256 != rootfs.identity_sha256
            || descriptor_identity(self.retained_fd.as_raw_fd())?
                != self.identity
            || sha256_descriptor(self.retained_fd.as_raw_fd())?
                != self.validation.file_sha256
        {
            return Err(LauncherError::Invalid(
                "retained executable identity changed",
            ));
        }
        validate_static_elf(
            self.retained_fd.as_raw_fd(),
            self.identity.length,
            self.validation.architecture,
            if self.validation.static_pie {
                StaticPiePolicy::AllowStaticPie
            } else {
                StaticPiePolicy::Forbid
            },
            self.validation.file_sha256,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ErofsExpectation {
    pub(super) image_fs_verity_sha256: [u8; 32],
    pub(super) loop_offset: u64,
    pub(super) loop_size_limit: u64,
    pub(super) identity_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DmVerityExpectation {
    pub(super) filesystem_magic: libc::c_long,
    pub(super) table_sha256: [u8; 32],
    pub(super) root_hash_sha256: [u8; 32],
    pub(super) dm_uuid_sha256: [u8; 32],
    pub(super) identity_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum VerifiedRootfsKind {
    Erofs {
        image_fs_verity_sha256: [u8; 32],
        loop_offset: u64,
        loop_size_limit: u64,
    },
    DmVerity {
        table_sha256: [u8; 32],
        root_hash_sha256: [u8; 32],
        dm_uuid_sha256: [u8; 32],
    },
}

pub(super) struct VerifiedRootfs {
    root_fd: OwnedFd,
    source_block_fd: OwnedFd,
    source_proof_fd: OwnedFd,
    mount_identity: DescriptorIdentity,
    filesystem_magic: libc::c_long,
    identity_sha256: [u8; 32],
    kind: VerifiedRootfsKind,
}

impl VerifiedRootfs {
    pub(super) fn verify_erofs_loop_mount(
        root_fd: OwnedFd,
        loop_block_fd: OwnedFd,
        image_fd: OwnedFd,
        expected: &ErofsExpectation,
    ) -> Result<Self, LauncherError> {
        let observed = erofs_loop_v1::verify(root_fd.as_fd(), loop_block_fd.as_fd(), image_fd.as_fd(),
            &ErofsLoopExpectationV1 {
                image_fs_verity_sha256: expected.image_fs_verity_sha256,
                loop_offset: expected.loop_offset, loop_size_limit: expected.loop_size_limit,
            })?;
        let mount_identity = erofs_root_identity(observed.root());
        let filesystem_magic = observed.filesystem_magic();
        let identity_sha256 = erofs_identity_sha256(&observed);
        if identity_sha256 != expected.identity_sha256 {
            return Err(LauncherError::Invalid(
                "EROFS root identity binding mismatch",
            ));
        }
        Ok(Self {
            root_fd,
            source_block_fd: loop_block_fd,
            source_proof_fd: image_fd,
            mount_identity,
            filesystem_magic,
            identity_sha256,
            kind: VerifiedRootfsKind::Erofs {
                image_fs_verity_sha256: observed.image_fs_verity_sha256(),
                loop_offset: observed.loop_offset(),
                loop_size_limit: observed.loop_size_limit(),
            },
        })
    }

    pub(super) fn verify_dm_verity_mount(
        root_fd: OwnedFd,
        dm_block_fd: OwnedFd,
        dm_control_fd: OwnedFd,
        expected: &DmVerityExpectation,
    ) -> Result<Self, LauncherError> {
        let (mount_identity, filesystem_magic) =
            verify_read_only_mount_root(root_fd.as_raw_fd())?;
        if filesystem_magic != expected.filesystem_magic {
            return Err(LauncherError::Invalid(
                "dm-verity filesystem type mismatch",
            ));
        }
        let block = verify_read_only_block_device(dm_block_fd.as_raw_fd())?;
        if mount_identity.device != block.rdev {
            return Err(LauncherError::Invalid(
                "dm-verity mount device does not match retained block device",
            ));
        }
        verify_dm_control_descriptor(dm_control_fd.as_raw_fd())?;
        let table = query_dm_verity_table(
            dm_control_fd.as_raw_fd(),
            block.rdev,
        )?;
        if table.table_sha256 != expected.table_sha256
            || table.root_hash_sha256 != expected.root_hash_sha256
            || table.dm_uuid_sha256 != expected.dm_uuid_sha256
        {
            return Err(LauncherError::Invalid(
                "dm-verity table, root hash, or UUID mismatch",
            ));
        }
        let identity_sha256 = hash_frames(&[
            b"serverware.policyCustodyRootfs.dmVerity/v1",
            &mount_identity.device.to_be_bytes(),
            &mount_identity.inode.to_be_bytes(),
            &mount_identity.mount_id.to_be_bytes(),
            &block.rdev.to_be_bytes(),
            &filesystem_magic.to_be_bytes(),
            &table.table_sha256,
            &table.root_hash_sha256,
            &table.dm_uuid_sha256,
        ]);
        if identity_sha256 != expected.identity_sha256 {
            return Err(LauncherError::Invalid(
                "dm-verity root identity binding mismatch",
            ));
        }
        Ok(Self {
            root_fd,
            source_block_fd: dm_block_fd,
            source_proof_fd: dm_control_fd,
            mount_identity,
            filesystem_magic,
            identity_sha256,
            kind: VerifiedRootfsKind::DmVerity {
                table_sha256: table.table_sha256,
                root_hash_sha256: table.root_hash_sha256,
                dm_uuid_sha256: table.dm_uuid_sha256,
            },
        })
    }

    pub(super) fn identity_sha256(&self) -> [u8; 32] {
        self.identity_sha256
    }

    pub(super) fn kind(&self) -> &VerifiedRootfsKind {
        &self.kind
    }

    fn revalidate(&self) -> Result<(), LauncherError> {
        let (mount_identity, filesystem_magic) =
            verify_read_only_mount_root(self.root_fd.as_raw_fd())?;
        let block =
            verify_read_only_block_device(self.source_block_fd.as_raw_fd())?;
        if mount_identity != self.mount_identity
            || filesystem_magic != self.filesystem_magic
            || mount_identity.device != block.rdev
        {
            return Err(LauncherError::Invalid(
                "verified root filesystem identity changed",
            ));
        }
        match &self.kind {
            VerifiedRootfsKind::Erofs {
                image_fs_verity_sha256,
                loop_offset,
                loop_size_limit,
            } => {
                let observed = erofs_loop_v1::verify(self.root_fd.as_fd(), self.source_block_fd.as_fd(),
                    self.source_proof_fd.as_fd(), &ErofsLoopExpectationV1 {
                        image_fs_verity_sha256: *image_fs_verity_sha256,
                        loop_offset: *loop_offset, loop_size_limit: *loop_size_limit,
                    })?;
                if erofs_root_identity(observed.root()) != mount_identity
                    || observed.filesystem_magic() != filesystem_magic
                    || observed.block_rdev() != block.rdev
                    || erofs_identity_sha256(&observed) != self.identity_sha256 {
                    return Err(LauncherError::Invalid(
                        "EROFS root identity no longer matches its binding",
                    ));
                }
            }
            VerifiedRootfsKind::DmVerity {
                table_sha256,
                root_hash_sha256,
                dm_uuid_sha256,
            } => {
                let table = query_dm_verity_table(
                    self.source_proof_fd.as_raw_fd(),
                    block.rdev,
                )?;
                if table.table_sha256 != *table_sha256
                    || table.root_hash_sha256 != *root_hash_sha256
                    || table.dm_uuid_sha256 != *dm_uuid_sha256
                {
                    return Err(LauncherError::Invalid(
                        "dm-verity mapping changed",
                    ));
                }
                let current_identity = hash_frames(&[
                    b"serverware.policyCustodyRootfs.dmVerity/v1",
                    &mount_identity.device.to_be_bytes(),
                    &mount_identity.inode.to_be_bytes(),
                    &mount_identity.mount_id.to_be_bytes(),
                    &block.rdev.to_be_bytes(),
                    &filesystem_magic.to_be_bytes(),
                    table_sha256,
                    root_hash_sha256,
                    dm_uuid_sha256,
                ]);
                if current_identity != self.identity_sha256 {
                    return Err(LauncherError::Invalid(
                        "dm-verity root identity no longer matches its binding",
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(super) struct VerifiedSeccompProgram {
    retained_fd: OwnedFd,
    identity: DescriptorIdentity,
    rootfs_identity_sha256: [u8; 32],
    sha256: [u8; 32],
    instruction_count: u16,
    architecture: ExecutableArchitecture,
    instructions: Box<[libc::sock_filter]>,
}

impl VerifiedSeccompProgram {
    pub(super) fn open_in_rootfs(
        rootfs: &VerifiedRootfs,
        relative_path: &Path,
        expected_sha256: [u8; 32],
        expected_instruction_count: u16,
        architecture: ExecutableArchitecture,
    ) -> Result<Self, LauncherError> {
        if expected_instruction_count == 0
            || usize::from(expected_instruction_count)
                > MAX_EXACT_FILTER_INSTRUCTIONS
            || architecture != ExecutableArchitecture::host()?
        {
            return Err(LauncherError::Invalid(
                "exact seccomp instruction metadata is invalid",
            ));
        }
        let retained_fd = open_beneath(
            rootfs.root_fd.as_raw_fd(),
            relative_path,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )?;
        let identity = immutable_regular_file_identity(retained_fd.as_raw_fd())?;
        let expected_length = usize::from(expected_instruction_count)
            .checked_mul(size_of::<libc::sock_filter>())
            .ok_or(LauncherError::Invalid(
                "exact seccomp byte length overflow",
            ))?;
        if identity.device != rootfs.mount_identity.device
            || identity.length
                != u64::try_from(expected_length).map_err(|_| {
                    LauncherError::Invalid(
                        "exact seccomp byte length is invalid",
                    )
                })?
        {
            return Err(LauncherError::Invalid(
                "exact seccomp descriptor identity mismatch",
            ));
        }
        let sha256 = sha256_descriptor(retained_fd.as_raw_fd())?;
        if sha256 != expected_sha256 {
            return Err(LauncherError::Invalid(
                "exact seccomp digest mismatch",
            ));
        }
        let mut filters = vec![
            EMPTY_FILTER;
            usize::from(expected_instruction_count)
        ];
        pread_exact(
            retained_fd.as_raw_fd(),
            filters.as_mut_ptr() as *mut u8,
            expected_length,
            0,
        )?;
        validate_exact_filter(
            &filters,
            architecture.audit_arch(),
        )?;
        Ok(Self {
            retained_fd,
            identity,
            rootfs_identity_sha256: rootfs.identity_sha256,
            sha256,
            instruction_count: expected_instruction_count,
            architecture,
            instructions: filters.into_boxed_slice(),
        })
    }

    pub(super) fn retained_fd(&self) -> RawFd {
        self.retained_fd.as_raw_fd()
    }

    pub(super) fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(super) fn instruction_count(&self) -> u16 {
        self.instruction_count
    }

    fn instructions(&self) -> &[libc::sock_filter] {
        &self.instructions
    }

    fn revalidate(&self, rootfs: &VerifiedRootfs) -> Result<(), LauncherError> {
        if self.rootfs_identity_sha256 != rootfs.identity_sha256
            || descriptor_identity(self.retained_fd.as_raw_fd())?
                != self.identity
            || sha256_descriptor(self.retained_fd.as_raw_fd())?
                != self.sha256
        {
            return Err(LauncherError::Invalid(
                "retained seccomp program identity changed",
            ));
        }
        let mut filters = [EMPTY_FILTER; MAX_EXACT_FILTER_INSTRUCTIONS];
        let length = usize::from(self.instruction_count)
            * size_of::<libc::sock_filter>();
        pread_exact(
            self.retained_fd.as_raw_fd(),
            filters.as_mut_ptr() as *mut u8,
            length,
            0,
        )?;
        validate_exact_filter(
            &filters[..usize::from(self.instruction_count)],
            self.architecture.audit_arch(),
        )?;
        if filters[..usize::from(self.instruction_count)]
            .iter()
            .zip(self.instructions.iter())
            .any(|(observed, retained)| {
                observed.code != retained.code
                    || observed.jt != retained.jt
                    || observed.jf != retained.jf
                    || observed.k != retained.k
            })
        {
            return Err(LauncherError::Invalid(
                "retained seccomp program differs from its immutable in-memory copy",
            ));
        }
        Ok(())
    }
}

pub(super) struct RootSwitchTarget {
    staging_parent_fd: OwnedFd,
    staging_name: CString,
    old_root_name: CString,
    old_root_absolute: CString,
    staging_parent_identity: DescriptorIdentity,
    staging_identity: DescriptorIdentity,
    old_root_identity: DescriptorIdentity,
    rootfs_identity_sha256: [u8; 32],
}

impl RootSwitchTarget {
    pub(super) fn verify(
        rootfs: &VerifiedRootfs,
        staging_parent_fd: OwnedFd,
        staging_name: &str,
        old_root_name: &str,
    ) -> Result<Self, LauncherError> {
        validate_single_component(staging_name)?;
        validate_single_component(old_root_name)?;
        let parent = directory_identity(staging_parent_fd.as_raw_fd())?;
        if parent.uid != 0 || parent.mode & 0o077 != 0 {
            return Err(LauncherError::Invalid(
                "root-switch staging parent must be root-owned and private",
            ));
        }
        let staging_name_c = CString::new(staging_name).map_err(|_| {
            LauncherError::Invalid("staging mountpoint contains NUL")
        })?;
        let staging_fd = openat_directory(
            staging_parent_fd.as_raw_fd(),
            &staging_name_c,
        )?;
        let staging = directory_identity(staging_fd.as_raw_fd())?;
        if staging.uid != 0
            || staging.mode & 0o077 != 0
            || !directory_is_empty(staging_fd.as_raw_fd())?
        {
            return Err(LauncherError::Invalid(
                "root-switch mountpoint must be an empty private root directory",
            ));
        }
        let old_root_path = Path::new(old_root_name);
        let old_root_fd = open_beneath(
            rootfs.root_fd.as_raw_fd(),
            old_root_path,
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC,
        )?;
        if !directory_is_empty(old_root_fd.as_raw_fd())? {
            return Err(LauncherError::Invalid(
                "verified rootfs old-root directory must be empty",
            ));
        }
        let old_root_name = CString::new(old_root_name).map_err(|_| {
            LauncherError::Invalid("old-root component contains NUL")
        })?;
        let old_root_absolute =
            CString::new(format!("/{old_root_name_text}", old_root_name_text = old_root_name.to_string_lossy()))
                .map_err(|_| LauncherError::Invalid(
                    "old-root absolute path contains NUL",
                ))?;
        Ok(Self {
            staging_parent_fd,
            staging_name: staging_name_c,
            old_root_name,
            old_root_absolute,
            staging_parent_identity: parent,
            staging_identity: staging,
            old_root_identity: directory_identity(
                old_root_fd.as_raw_fd(),
            )?,
            rootfs_identity_sha256: rootfs.identity_sha256,
        })
    }

    fn revalidate(&self, rootfs: &VerifiedRootfs) -> Result<(), LauncherError> {
        if self.rootfs_identity_sha256 != rootfs.identity_sha256
            || directory_identity(self.staging_parent_fd.as_raw_fd())?
                != self.staging_parent_identity
        {
            return Err(LauncherError::Invalid(
                "root-switch parent or rootfs identity changed",
            ));
        }
        let staging = openat_directory(
            self.staging_parent_fd.as_raw_fd(),
            &self.staging_name,
        )?;
        if directory_identity(staging.as_raw_fd())?
                != self.staging_identity
            || !directory_is_empty(staging.as_raw_fd())?
        {
            return Err(LauncherError::Invalid(
                "root-switch staging mountpoint changed",
            ));
        }
        let old_root = open_beneath(
            rootfs.root_fd.as_raw_fd(),
            Path::new(self.old_root_name.to_str().map_err(|_| {
                LauncherError::Invalid("old-root name is not UTF-8")
            })?),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC,
        )?;
        if directory_identity(old_root.as_raw_fd())?
                != self.old_root_identity
            || !directory_is_empty(old_root.as_raw_fd())?
        {
            return Err(LauncherError::Invalid(
                "verified rootfs old-root directory changed",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InheritedDescriptorKind {
    SealedMemfd,
    UnixSocket,
    ReadPipe,
    WritePipe,
}

pub(super) struct InheritedDescriptor {
    fd: OwnedFd,
    kind: InheritedDescriptorKind,
}

impl InheritedDescriptor {
    pub(super) fn verify(
        fd: OwnedFd,
        kind: InheritedDescriptorKind,
    ) -> Result<Self, LauncherError> {
        if fd.as_raw_fd() < 3 {
            return Err(LauncherError::Invalid(
                "inherited descriptors must not alias standard I/O",
            ));
        }
        let mut stat: libc::stat = unsafe { zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        match kind {
            InheritedDescriptorKind::SealedMemfd => {
                let seals =
                    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
                if stat.st_mode & libc::S_IFMT != libc::S_IFREG
                    || seals < 0
                    || seals & REQUIRED_MEMFD_SEALS
                        != REQUIRED_MEMFD_SEALS
                {
                    return Err(LauncherError::Invalid(
                        "inherited invocation data is not a fully sealed memfd",
                    ));
                }
            }
            InheritedDescriptorKind::UnixSocket => {
                verify_unix_socket(fd.as_raw_fd(), &stat)?;
            }
            InheritedDescriptorKind::ReadPipe => {
                verify_pipe_access(fd.as_raw_fd(), &stat, libc::O_RDONLY)?;
            }
            InheritedDescriptorKind::WritePipe => {
                verify_pipe_access(fd.as_raw_fd(), &stat, libc::O_WRONLY)?;
            }
        }
        Ok(Self { fd, kind })
    }

    pub(super) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub(super) fn kind(&self) -> InheritedDescriptorKind {
        self.kind
    }
}

pub(super) struct StandardIo {
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
}

impl StandardIo {
    pub(super) fn new(
        stdin: OwnedFd,
        stdout: OwnedFd,
        stderr: OwnedFd,
    ) -> Result<Self, LauncherError> {
        verify_standard_io(stdin.as_raw_fd(), true)?;
        verify_standard_io(stdout.as_raw_fd(), false)?;
        verify_standard_io(stderr.as_raw_fd(), false)?;
        Ok(Self {
            stdin,
            stdout,
            stderr,
        })
    }
}

#[repr(C)]
pub(super) struct StaticEntryInvocation {
    pub(super) role: LaunchRole,
    pub(super) argv: *const *const libc::c_char,
    pub(super) environment: *const *const libc::c_char,
    pub(super) inherited_fds: *const RawFd,
    pub(super) inherited_fds_len: usize,
}

pub(super) type StaticEntryPoint =
    unsafe extern "C" fn(*const StaticEntryInvocation) -> !;

/// A symbol in the already-running, verified static launcher image.
///
/// No exec transition occurs. The child reaches this symbol only after the
/// bootstrap and assignment-bound filters are stacked and the parent releases
/// the watchdog-owned workload.
pub(super) struct TrustedStaticEntry {
    entry: StaticEntryPoint,
    image_sha256: [u8; 32],
    architecture: ExecutableArchitecture,
}

impl TrustedStaticEntry {
    pub(super) fn bind_running_image(
        executable: &VerifiedExecutable,
        entry: StaticEntryPoint,
    ) -> Result<Self, LauncherError> {
        verify_running_static_stub(executable, entry)?;
        Ok(Self {
            entry,
            image_sha256: executable.validation.file_sha256,
            architecture: executable.validation.architecture,
        })
    }

    fn revalidate(
        &self,
        executable: &VerifiedExecutable,
    ) -> Result<(), LauncherError> {
        if self.image_sha256 != executable.validation.file_sha256
            || self.architecture != executable.validation.architecture
        {
            return Err(LauncherError::Invalid(
                "trusted entry binding differs from the verified executable",
            ));
        }
        verify_running_static_stub(executable, self.entry)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExternalSeccompAuthorization {
    authority_key_id_sha256: [u8; 32],
    authorization_receipt_sha256: [u8; 32],
    semantics_sha256: [u8; 32],
    binding_sha256: [u8; 32],
    current_key_checkpoint_sha256: [u8; 32],
    revocation_generation: u64,
    revocation_root_sha256: [u8; 32],
}

impl ExternalSeccompAuthorization {
    /// Endpoint verification is the only constructor for `verified`; caller
    /// assertions cannot mint this launch capability.
    fn from_current_key_verified_endpoint(
        program: &VerifiedSeccompProgram,
        rootfs: &VerifiedRootfs,
        semantics_sha256: [u8; 32],
        verified: &VerifiedCurrentKeyEndpointAuthorization,
    ) -> Result<Self, LauncherError> {
        if verified.endpoint_role()
            != PolicyCustodyEndpointRole::FenceAuthority
        {
            return Err(LauncherError::Invalid(
                "seccomp authorization was not issued by the fence authority",
            ));
        }
        let authority_key_id_sha256 =
            digest_raw_bytes(verified.authority_key_id())?;
        let authorization_receipt_sha256 =
            sha256_bytes(verified.exact_signed_envelope_bytes());
        let current_key_checkpoint_sha256 =
            digest_raw_bytes(verified.checkpoint_sha256())?;
        let revocation_root_sha256 =
            digest_raw_bytes(verified.revocation_root_sha256())?;
        if semantics_sha256 == [0; 32]
            || authority_key_id_sha256 == [0; 32]
            || authorization_receipt_sha256 == [0; 32]
            || current_key_checkpoint_sha256 == [0; 32]
            || verified.revocation_generation() == 0
            || revocation_root_sha256 == [0; 32]
        {
            return Err(LauncherError::Invalid(
                "current-key seccomp authorization identifiers must be nonzero",
            ));
        }
        let binding_sha256 = seccomp_authorization_binding(
            program,
            rootfs,
            semantics_sha256,
            authority_key_id_sha256,
            authorization_receipt_sha256,
        );
        if digest_from_raw(binding_sha256)?
            != *verified.exact_binding_sha256()
        {
            return Err(LauncherError::Invalid(
                "signed current-key seccomp authorization binding mismatch",
            ));
        }
        Ok(Self {
            authority_key_id_sha256,
            authorization_receipt_sha256,
            semantics_sha256,
            binding_sha256,
            current_key_checkpoint_sha256,
            revocation_generation: verified.revocation_generation(),
            revocation_root_sha256,
        })
    }

    fn revalidate(
        &self,
        program: &VerifiedSeccompProgram,
        rootfs: &VerifiedRootfs,
    ) -> Result<(), LauncherError> {
        let binding = seccomp_authorization_binding(
            program,
            rootfs,
            self.semantics_sha256,
            self.authority_key_id_sha256,
            self.authorization_receipt_sha256,
        );
        if binding != self.binding_sha256
            || self.current_key_checkpoint_sha256 == [0; 32]
            || self.revocation_generation == 0
            || self.revocation_root_sha256 == [0; 32]
        {
            return Err(LauncherError::Invalid(
                "seccomp authorization no longer binds the exact program",
            ));
        }
        Ok(())
    }

    fn revalidate_current_head(
        &self,
        current: &EndpointTrustPin,
    ) -> Result<(), LauncherError> {
        current.validate().map_err(|_| {
            LauncherError::Invalid(
                "current seccomp authority head is invalid",
            )
        })?;
        if current.endpoint_role
                != PolicyCustodyEndpointRole::FenceAuthority
            || digest_raw_bytes(
                &current
                    .current_key_authorization
                    .signing_key_id,
            )? != self.authority_key_id_sha256
            || digest_raw_bytes(
                &current
                    .current_key_authorization
                    .exact_checkpoint_sha256,
            )? != self.current_key_checkpoint_sha256
            || current
                .current_key_authorization
                .exact_revocation_generation_high_water
                != self.revocation_generation
            || digest_raw_bytes(
                &current
                    .current_key_authorization
                    .exact_revocation_root_sha256,
            )? != self.revocation_root_sha256
        {
            return Err(LauncherError::Invalid(
                "seccomp authorization is not bound to the exact current key and revocation head",
            ));
        }
        Ok(())
    }
}

pub(super) fn authorize_external_seccomp_for_current_key(
    program: &VerifiedSeccompProgram,
    rootfs: &VerifiedRootfs,
    semantics_sha256: [u8; 32],
    verified: &VerifiedCurrentKeyEndpointAuthorization,
) -> Result<ExternalSeccompAuthorization, LauncherError> {
    ExternalSeccompAuthorization::from_current_key_verified_endpoint(
        program,
        rootfs,
        semantics_sha256,
        verified,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WatchdogPeerIdentity {
    pub(super) pid: libc::pid_t,
    pub(super) uid: libc::uid_t,
    pub(super) gid: libc::gid_t,
}

pub(super) struct WatchdogEndpoint {
    fd: OwnedFd,
    identity: DescriptorIdentity,
    peer: WatchdogPeerIdentity,
}

impl WatchdogEndpoint {
    pub(super) fn verify(
        fd: OwnedFd,
        expected_peer: WatchdogPeerIdentity,
    ) -> Result<Self, LauncherError> {
        let identity = verify_watchdog_endpoint(fd.as_raw_fd(), expected_peer)?;
        Ok(Self {
            fd,
            identity,
            peer: expected_peer,
        })
    }

    fn revalidate(&self) -> Result<(), LauncherError> {
        if descriptor_identity(self.fd.as_raw_fd())? != self.identity {
            return Err(LauncherError::Invalid(
                "watchdog endpoint descriptor identity changed",
            ));
        }
        verify_watchdog_endpoint(self.fd.as_raw_fd(), self.peer).map(|_| ())
    }
}

pub(super) struct HardUnreadyChannel {
    fd: OwnedFd,
    identity: DescriptorIdentity,
}

impl HardUnreadyChannel {
    pub(super) fn verify(fd: OwnedFd) -> Result<Self, LauncherError> {
        let identity = descriptor_identity(fd.as_raw_fd())?;
        let mut stat: libc::stat = unsafe { zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        verify_pipe_access(fd.as_raw_fd(), &stat, libc::O_WRONLY)?;
        set_nonblocking(fd.as_raw_fd())?;
        Ok(Self { fd, identity })
    }

    fn revalidate(&self) -> Result<(), LauncherError> {
        if descriptor_identity(self.fd.as_raw_fd())? != self.identity {
            return Err(LauncherError::Invalid(
                "hard-unready channel descriptor identity changed",
            ));
        }
        let mut stat: libc::stat = unsafe { zeroed() };
        if unsafe { libc::fstat(self.fd.as_raw_fd(), &mut stat) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        verify_pipe_access(self.fd.as_raw_fd(), &stat, libc::O_WRONLY)
    }
}

pub(super) struct LaunchSpec<'a> {
    pub(super) role: LaunchRole,
    pub(super) executable: &'a VerifiedExecutable,
    pub(super) static_entry: &'a TrustedStaticEntry,
    pub(super) rootfs: &'a VerifiedRootfs,
    pub(super) exact_seccomp: &'a VerifiedSeccompProgram,
    pub(super) seccomp_authorization: &'a ExternalSeccompAuthorization,
    pub(super) root_switch: &'a RootSwitchTarget,
    pub(super) cgroup_fd: &'a OwnedFd,
    pub(super) watchdog_endpoint: WatchdogEndpoint,
    pub(super) hard_unready: HardUnreadyChannel,
    pub(super) parent_pidfd: &'a OwnedFd,
    pub(super) parent_pid: libc::pid_t,
    pub(super) parent_pidfd_inode: libc::ino_t,
    pub(super) parent_watchdog_identity: WatchdogProcessIdentityV3,
    pub(super) supervisor_pidfd: &'a OwnedFd,
    pub(super) supervisor_watchdog_identity: WatchdogProcessIdentityV3,
    pub(super) operation_cgroup_identity:
        WatchdogRetainedCgroupIdentityV3,
    pub(super) supervisor_heartbeat_eventfd: &'a OwnedFd,
    pub(super) watchdog_heartbeat_eventfd: &'a OwnedFd,
    pub(super) watchdog_lease: WatchdogLeaseV3,
    pub(super) watchdog_trust_provider:
        &'a mut dyn CurrentEndpointTrustProvider,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) supervisor_capability_sha256: Sha256Digest,
    pub(super) fence_token_sha256: Sha256Digest,
    pub(super) worker_uid: libc::uid_t,
    pub(super) worker_gid: libc::gid_t,
    pub(super) argv: &'a [CString],
    pub(super) environment: &'a [CString],
    pub(super) inherited: &'a [InheritedDescriptor],
    pub(super) stdio: &'a StandardIo,
    pub(super) authority_boottime_domain: BoottimeDomain,
    pub(super) deadline: BoottimeDeadline,
    pub(super) cleanup_authority_boottime_domain: BoottimeDomain,
    pub(super) cleanup_deadline: BoottimeDeadline,
}

impl LaunchSpec<'_> {
    fn validate(&self) -> Result<(), LauncherError> {
        if self.worker_uid == 0 || self.worker_gid == 0 {
            return Err(LauncherError::Invalid(
                "custody workers and helpers must use non-root credentials",
            ));
        }
        if self.argv.is_empty()
            || self.argv.len() > MAX_ARGUMENTS
            || self.environment.len() > MAX_ENVIRONMENT
            || self.inherited.len() > MAX_INHERITED_FDS
            || self.argv.iter().any(|value| value.as_bytes().is_empty())
            || self.environment.iter().any(|value| {
                let bytes = value.as_bytes();
                bytes.is_empty()
                    || !bytes.contains(&b'=')
                    || bytes.first() == Some(&b'=')
            })
        {
            return Err(LauncherError::Invalid(
                "launch argument or environment bounds are invalid",
            ));
        }
        self.deadline
            .require_expected_domain(self.authority_boottime_domain)?;
        self.deadline.require_live()?;
        self.cleanup_deadline.require_expected_domain(
            self.cleanup_authority_boottime_domain,
        )?;
        self.cleanup_authority_boottime_domain
            .require_same_current(self.authority_boottime_domain)?;
        self.cleanup_deadline.require_live()?;
        if self.cleanup_deadline.absolute_nanos()
            <= self.deadline.absolute_nanos()
        {
            return Err(LauncherError::Invalid(
                "cleanup deadline must reserve time beyond launch authority",
            ));
        }
        self.rootfs.revalidate()?;
        self.executable.revalidate(self.rootfs)?;
        self.static_entry.revalidate(self.executable)?;
        self.exact_seccomp.revalidate(self.rootfs)?;
        self.seccomp_authorization
            .revalidate(self.exact_seccomp, self.rootfs)?;
        self.root_switch.revalidate(self.rootfs)?;
        verify_cgroup2_descriptor(self.cgroup_fd.as_raw_fd())?;
        verify_cgroup_kill_available(self.cgroup_fd.as_raw_fd())?;
        if cgroup_populated_now(self.cgroup_fd.as_raw_fd())? {
            return Err(LauncherError::Invalid(
                "launch cgroup contains pre-existing processes",
            ));
        }
        self.watchdog_endpoint.revalidate()?;
        self.hard_unready.revalidate()?;
        self.parent_watchdog_identity.validate().map_err(|_| {
            LauncherError::Invalid(
                "parent watchdog process identity is invalid",
            )
        })?;
        self.supervisor_watchdog_identity
            .validate()
            .map_err(|_| {
                LauncherError::Invalid(
                    "supervisor watchdog process identity is invalid",
                )
            })?;
        self.operation_cgroup_identity.validate().map_err(|_| {
            LauncherError::Invalid(
                "watchdog retained cgroup identity is invalid",
            )
        })?;
        self.watchdog_lease.validate().map_err(|_| {
            LauncherError::Invalid("watchdog heartbeat lease is invalid")
        })?;
        verify_parent_pidfd(
            self.parent_pidfd.as_raw_fd(),
            self.parent_pid,
            self.parent_pidfd_inode,
        )?;
        verify_process_pidfd_identity(
            self.parent_pidfd.as_raw_fd(),
            &self.parent_watchdog_identity,
        )?;
        verify_process_pidfd_identity(
            self.supervisor_pidfd.as_raw_fd(),
            &self.supervisor_watchdog_identity,
        )?;
        let cgroup_descriptor =
            descriptor_identity(self.cgroup_fd.as_raw_fd())?;
        if self.parent_watchdog_identity.pid != self.parent_pid
            || self.parent_watchdog_identity.pidfd_inode
                != self.parent_pidfd_inode as u64
            || self.operation_cgroup_identity.mount_id
                != cgroup_descriptor.mount_id
            || self.operation_cgroup_identity.inode
                != cgroup_descriptor.inode as u64
            || self
                .operation_cgroup_identity
                .retained_fd_stat_sha256
                != descriptor_identity_protocol_sha256(
                    cgroup_descriptor,
                )?
            || digest_is_zero(&self.operation_id_sha256)
            || digest_is_zero(&self.durable_request_sha256)
            || digest_is_zero(&self.request_sha256)
            || digest_is_zero(&self.supervisor_capability_sha256)
            || digest_is_zero(&self.fence_token_sha256)
        {
            return Err(LauncherError::Invalid(
                "watchdog registration authority or retained identity is incomplete",
            ));
        }
        let mut seen = [RawFd::MIN; MAX_INHERITED_FDS + 9];
        let mut seen_len = 0;
        for fd in self
            .inherited
            .iter()
            .map(InheritedDescriptor::raw_fd)
            .chain([
                self.parent_pidfd.as_raw_fd(),
                self.supervisor_pidfd.as_raw_fd(),
                self.cgroup_fd.as_raw_fd(),
                self.supervisor_heartbeat_eventfd.as_raw_fd(),
                self.watchdog_heartbeat_eventfd.as_raw_fd(),
                self.watchdog_endpoint.fd.as_raw_fd(),
                self.hard_unready.fd.as_raw_fd(),
            ])
        {
            if fd < 3 || seen[..seen_len].contains(&fd) {
                return Err(LauncherError::Invalid(
                    "launch inherited descriptor set is not unique",
                ));
            }
            seen[seen_len] = fd;
            seen_len += 1;
        }
        Ok(())
    }
}

#[must_use = "a launched child must be reaped by exact pidfd"]
pub(super) struct LaunchedProcess {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    cgroup_fd: OwnedFd,
    cgroup_identity_sha256: [u8; 32],
    leader_receipt: Option<ReapReceipt>,
    cleanup_complete: bool,
    role: LaunchRole,
    authority_boottime_domain: BoottimeDomain,
    deadline: BoottimeDeadline,
    cleanup_authority_boottime_domain: BoottimeDomain,
    cleanup_deadline: BoottimeDeadline,
    watchdog_endpoint: WatchdogEndpoint,
    watchdog_ownership: Option<WatchdogOwnership>,
    hard_unready: HardUnreadyChannel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReapReceipt {
    pub(super) pid: libc::pid_t,
    pub(super) si_code: libc::c_int,
    pub(super) status: libc::c_int,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CleanupReceipt {
    pub(super) leader: ReapReceipt,
    pub(super) cgroup_identity_sha256: [u8; 32],
    pub(super) cleanup_deadline: BoottimeDeadline,
    pub(super) receipt_sha256: [u8; 32],
}

#[derive(Debug, Clone)]
struct WatchdogOwnership {
    registration_sha256: [u8; 32],
    ownership_receipt_sha256: [u8; 32],
    ownership_state_sha256: [u8; 32],
    verified_acknowledgement: VerifiedWatchdogOwnershipAck,
}

impl LaunchedProcess {
    pub(super) fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub(super) fn role(&self) -> LaunchRole {
        self.role
    }

    pub(super) fn deadline(&self) -> BoottimeDeadline {
        self.deadline
    }

    pub(super) fn duplicate_pidfd(&self) -> Result<OwnedFd, LauncherError> {
        duplicate_fd_cloexec(self.pidfd.as_raw_fd())
    }

    pub(super) fn wait_until(
        &mut self,
    ) -> Result<ReapReceipt, LauncherError> {
        if self.leader_receipt.is_some() || self.cleanup_complete {
            return Err(LauncherError::Invalid(
                "child was already reaped",
            ));
        }
        self.deadline
            .require_expected_domain(self.authority_boottime_domain)?;
        wait_pidfd_until(self.pidfd.as_raw_fd(), self.deadline)?;
        let receipt = reap_pidfd_exact(self.pid, self.pidfd.as_raw_fd())?;
        self.leader_receipt = Some(receipt);
        self.deadline.require_live()?;
        self.finish_graceful_cleanup()
    }

    fn finish_graceful_cleanup(
        &mut self,
    ) -> Result<ReapReceipt, LauncherError> {
        self.cleanup_deadline.require_expected_domain(
            self.cleanup_authority_boottime_domain,
        )?;
        if cgroup_identity_sha256(self.cgroup_fd.as_raw_fd())?
            != self.cgroup_identity_sha256
        {
            return Err(LauncherError::Invalid(
                "retained launch cgroup identity changed",
            ));
        }
        if self.leader_receipt.is_none() {
            wait_pidfd_until(
                self.pidfd.as_raw_fd(),
                self.cleanup_deadline,
            )?;
            self.leader_receipt = Some(reap_pidfd_exact(
                self.pid,
                self.pidfd.as_raw_fd(),
            )?);
        }
        wait_cgroup_empty_until(
            self.cgroup_fd.as_raw_fd(),
            self.cleanup_deadline,
        )?;
        let leader = self.leader_receipt.ok_or(
            LauncherError::Invalid(
                "cleanup lacks an exact leader reap receipt",
            ),
        )?;
        let receipt_sha256 = cleanup_receipt_sha256(
            leader,
            self.cgroup_identity_sha256,
            self.cleanup_deadline,
        );
        let receipt = CleanupReceipt {
            leader,
            cgroup_identity_sha256: self.cgroup_identity_sha256,
            cleanup_deadline: self.cleanup_deadline,
            receipt_sha256,
        };
        if let Some(ownership) = self.watchdog_ownership.take() {
            watchdog_disarm_until(
                &self.watchdog_endpoint,
                ownership,
                receipt,
                self.cleanup_deadline,
            )?;
        }
        self.cleanup_deadline.require_live()?;
        self.cleanup_complete = true;
        Ok(leader)
    }
}

impl Drop for LaunchedProcess {
    fn drop(&mut self) {
        if !self.cleanup_complete
            && self.finish_graceful_cleanup().is_err()
        {
            hard_unready_and_exit(
                &self.hard_unready,
                self.pid,
                self.cgroup_identity_sha256,
                self.watchdog_ownership.clone(),
            );
        }
    }
}

pub(super) fn launch_retained(
    mut spec: LaunchSpec<'_>,
) -> Result<LaunchedProcess, LauncherError> {
    spec.validate()?;
    let seccomp_head_before = current_endpoint_trust_until(
        &mut *spec.watchdog_trust_provider,
        PolicyCustodyEndpointRole::FenceAuthority,
        spec.deadline,
    )
    .map_err(|_| {
        LauncherError::Invalid(
            "current seccomp authority head is unavailable",
        )
    })?;
    spec.seccomp_authorization
        .revalidate_current_head(&seccomp_head_before)?;
    let bootstrap_filter = bootstrap_filter(
        spec.executable.validation.architecture.audit_arch(),
    )?;
    let final_baseline = mandatory_baseline_filter(
        spec.executable.validation.architecture.audit_arch(),
    )?;
    let mut argv = spec
        .argv
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    argv.push(ptr::null());
    let mut environment = spec
        .environment
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    environment.push(ptr::null());
    let inherited_fds = spec
        .inherited
        .iter()
        .map(InheritedDescriptor::raw_fd)
        .collect::<Vec<_>>();
    let (error_read, error_write) = create_nonblocking_pipe()?;
    let (ready_read, ready_write) = create_nonblocking_pipe()?;
    let (release_read, release_write) = create_nonblocking_pipe()?;
    let child_deadline_timer =
        create_absolute_boottime_timer(spec.deadline)?;
    let mut ready_nonce = [0_u8; READY_PROOF_BYTES];
    fill_random_exact(&mut ready_nonce)?;
    let ready_proof = ready_proof_sha256(
        ready_nonce,
        spec.role,
        spec.executable.validation.file_sha256,
        spec.seccomp_authorization.binding_sha256,
        spec.authority_boottime_domain,
        spec.deadline,
    );
    let mut pass_fds = inherited_fds.clone();
    pass_fds.extend_from_slice(&[
        spec.parent_pidfd.as_raw_fd(),
        error_write.as_raw_fd(),
        ready_write.as_raw_fd(),
        release_read.as_raw_fd(),
        child_deadline_timer.as_raw_fd(),
    ]);
    pass_fds.sort_unstable();
    if pass_fds.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LauncherError::Invalid(
            "child retained descriptor set is not unique",
        ));
    }
    let cgroup_fd = duplicate_fd_cloexec(spec.cgroup_fd.as_raw_fd())?;
    let cgroup_identity_sha256 =
        cgroup_identity_sha256(cgroup_fd.as_raw_fd())?;
    let invocation = StaticEntryInvocation {
        role: spec.role,
        argv: argv.as_ptr(),
        environment: environment.as_ptr(),
        inherited_fds: inherited_fds.as_ptr(),
        inherited_fds_len: inherited_fds.len(),
    };
    let raw = RawChildSpec {
        entry: spec.static_entry.entry,
        invocation,
        exact_filter: spec.exact_seccomp.instructions().as_ptr(),
        exact_filter_len: spec.exact_seccomp.instructions().len(),
        rootfs_fd: spec.rootfs.root_fd.as_raw_fd(),
        staging_parent_fd: spec.root_switch.staging_parent_fd.as_raw_fd(),
        staging_name: spec.root_switch.staging_name.as_ptr(),
        old_root_name: spec.root_switch.old_root_name.as_ptr(),
        old_root_absolute: spec.root_switch.old_root_absolute.as_ptr(),
        parent_pidfd: spec.parent_pidfd.as_raw_fd(),
        parent_pid: spec.parent_pid,
        parent_pidfd_inode: spec.parent_pidfd_inode,
        worker_uid: spec.worker_uid,
        worker_gid: spec.worker_gid,
        pass_fds: pass_fds.as_ptr(),
        pass_fds_len: pass_fds.len(),
        stdin_fd: spec.stdio.stdin.as_raw_fd(),
        stdout_fd: spec.stdio.stdout.as_raw_fd(),
        stderr_fd: spec.stdio.stderr.as_raw_fd(),
        error_fd: error_write.as_raw_fd(),
        ready_fd: ready_write.as_raw_fd(),
        release_fd: release_read.as_raw_fd(),
        deadline_timer_fd: child_deadline_timer.as_raw_fd(),
        ready_proof: ready_proof.as_ptr(),
        ready_proof_len: ready_proof.len(),
        bootstrap_filter: bootstrap_filter.instructions.as_ptr(),
        bootstrap_filter_len: bootstrap_filter.len,
        final_baseline: final_baseline.instructions.as_ptr(),
        final_baseline_len: final_baseline.len,
    };
    let mut child_pidfd = -1;
    let mut clone_arguments = CloneArguments {
        flags: CLONE_PIDFD_FLAG
            | CLONE_INTO_CGROUP_FLAG
            | REQUIRED_NAMESPACE_FLAGS,
        pidfd: (&mut child_pidfd as *mut RawFd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: spec.cgroup_fd.as_raw_fd() as u64,
        ..CloneArguments::default()
    };
    verify_single_threaded_launcher()?;
    if cgroup_populated_now(spec.cgroup_fd.as_raw_fd())? {
        return Err(LauncherError::Invalid(
            "launch cgroup was populated before clone3",
        ));
    }
    let clone_token = spec.deadline.mutation_token()?;
    let clone_operation = clone_token
        .execute_nonblocking(|| {
            let child = unsafe {
                libc::syscall(
                    libc::SYS_clone3,
                    &mut clone_arguments as *mut CloneArguments,
                    size_of::<CloneArguments>(),
                ) as libc::pid_t
            };
            if child < 0 {
                return Err(io::Error::last_os_error());
            }
            if child == 0 {
                unsafe { child_main_raw(&raw) }
            }
            Ok(child)
        })
        .map_err(map_deadline_operation_error)?;
    let clone_completed_before_deadline =
        clone_operation.completed_before_deadline();
    let child = clone_operation.into_value();
    drop(error_write);
    drop(ready_write);
    drop(release_read);
    drop(child_deadline_timer);
    if child_pidfd < 0 {
        hard_unready_and_exit(
            &spec.hard_unready,
            child,
            cgroup_identity_sha256,
            None,
        );
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(child_pidfd) };
    let worker_watchdog_identity =
        observe_worker_watchdog_identity(
            child,
            pidfd.as_raw_fd(),
            spec.executable.validation.file_sha256,
        )?;
    let mut registration_nonce = [0_u8; WATCHDOG_NONCE_BYTES];
    fill_random_exact(&mut registration_nonce)?;
    let watchdog_rights = [
        spec.parent_pidfd.as_raw_fd(),
        spec.supervisor_pidfd.as_raw_fd(),
        pidfd.as_raw_fd(),
        cgroup_fd.as_raw_fd(),
        spec.supervisor_heartbeat_eventfd.as_raw_fd(),
        spec.watchdog_heartbeat_eventfd.as_raw_fd(),
    ];
    let fd_roles = [
        WatchdogRegistrationFdRole::ParentPidfd,
        WatchdogRegistrationFdRole::SupervisorPidfd,
        WatchdogRegistrationFdRole::WorkerPidfd,
        WatchdogRegistrationFdRole::OperationCgroup,
        WatchdogRegistrationFdRole::SupervisorHeartbeatEventfd,
        WatchdogRegistrationFdRole::WatchdogHeartbeatEventfd,
    ];
    let retained_fds = fd_roles
        .into_iter()
        .zip(watchdog_rights)
        .map(|(role, fd)| retained_watchdog_fd_identity(role, fd))
        .collect::<Result<Vec<_>, _>>()?;
    let watchdog_registration = WatchdogRegistrationV3 {
        api_version:
            POLICY_CUSTODY_WATCHDOG_REGISTRATION_VERSION.to_string(),
        parent: spec.parent_watchdog_identity.clone(),
        supervisor: spec.supervisor_watchdog_identity.clone(),
        worker: worker_watchdog_identity,
        cgroup: spec.operation_cgroup_identity.clone(),
        operation: spec.operation,
        operation_id_sha256: spec.operation_id_sha256.clone(),
        durable_request_sha256:
            spec.durable_request_sha256.clone(),
        request_sha256: spec.request_sha256.clone(),
        supervisor_capability_sha256:
            spec.supervisor_capability_sha256.clone(),
        fence_token_sha256: spec.fence_token_sha256.clone(),
        seccomp_binding_sha256:
            digest_from_raw(spec.seccomp_authorization.binding_sha256)?,
        filter_ready_proof_sha256: digest_from_raw(ready_proof)?,
        retained_fds,
        fd_manifest_sha256:
            Sha256Digest::compute(b"watchdog-fd-manifest-pending"),
        lease: spec.watchdog_lease.clone(),
        registration_nonce_sha256:
            Sha256Digest::compute(&registration_nonce),
        operation_deadline:
            ProtocolBoottimeDeadline::from_runtime(spec.deadline),
        cleanup_deadline:
            ProtocolBoottimeDeadline::from_runtime(
                spec.cleanup_deadline,
            ),
        registration_sha256:
            Sha256Digest::compute(b"watchdog-registration-pending"),
    }
    .finalize_manifest_and_registration()
    .map_err(|_| {
        LauncherError::Invalid(
            "watchdog registration or retained descriptor manifest is invalid",
        )
    })?;
    let mut launched = LaunchedProcess {
        pid: child,
        pidfd,
        cgroup_fd,
        cgroup_identity_sha256,
        leader_receipt: None,
        cleanup_complete: false,
        role: spec.role,
        authority_boottime_domain: spec.authority_boottime_domain,
        deadline: spec.deadline,
        cleanup_authority_boottime_domain:
            spec.cleanup_authority_boottime_domain,
        cleanup_deadline: spec.cleanup_deadline,
        watchdog_endpoint: spec.watchdog_endpoint,
        watchdog_ownership: None,
        hard_unready: spec.hard_unready,
    };
    if !clone_completed_before_deadline {
        return fail_launch(
            launched,
            LauncherError::Deadline(
                "clone3 crossed its launch deadline",
            ),
        );
    }
    let registration = watchdog_register_until(
        &launched.watchdog_endpoint,
        &watchdog_registration,
        &watchdog_rights,
        launched.pidfd.as_raw_fd(),
        &mut *spec.watchdog_trust_provider,
        spec.deadline,
    );
    match registration {
        Ok(ownership) => launched.watchdog_ownership = Some(ownership),
        Err(error) => return fail_launch(launched, error),
    }
    if let Err(error) = wait_for_filter_ready(
        error_read.as_raw_fd(),
        ready_read.as_raw_fd(),
        launched.pidfd.as_raw_fd(),
        ready_proof,
        launched.deadline,
    ) {
        return fail_launch(launched, error);
    }
    require_retained_watchdog_fds(
        &watchdog_registration,
        &watchdog_rights,
    )?;
    launched.watchdog_endpoint.revalidate()?;
    let seccomp_head_pre_release = current_endpoint_trust_until(
        &mut *spec.watchdog_trust_provider,
        PolicyCustodyEndpointRole::FenceAuthority,
        launched.deadline,
    )
    .map_err(|_| {
        LauncherError::Invalid(
            "current seccomp authority head is unavailable before release",
        )
    })?;
    require_same_current_checkpoint(
        &seccomp_head_before,
        &seccomp_head_pre_release,
    )
    .map_err(|_| {
        LauncherError::Invalid(
            "seccomp authority head changed before release",
        )
    })?;
    spec.seccomp_authorization
        .revalidate_current_head(&seccomp_head_pre_release)?;
    watchdog_reconfirm_until(
        &launched.watchdog_endpoint,
        &watchdog_registration,
        launched
            .watchdog_ownership
            .as_ref()
            .ok_or(LauncherError::Invalid(
                "watchdog ownership is absent before release",
            ))?,
        launched.pidfd.as_raw_fd(),
        &mut *spec.watchdog_trust_provider,
        launched.deadline,
    )?;
    let release_token = launched.deadline.release_token()?;
    let release = release_token
        .execute_nonblocking(|| {
            write_one_nonblocking(release_write.as_raw_fd(), 1)
        })
        .map_err(map_deadline_operation_error);
    match release {
        Ok(operation) if operation.completed_before_deadline() => {}
        Ok(_) => {
            return fail_launch(
                launched,
                LauncherError::Deadline(
                    "workload release crossed its launch deadline",
                ),
            );
        }
        Err(error) => {
            if let Some((si_code, status)) =
                observe_pidfd_terminal(launched.pidfd.as_raw_fd())?
            {
                return fail_launch(
                    launched,
                    LauncherError::ChildTerminated {
                        ready_proved: true,
                        si_code,
                        status,
                    },
                );
            }
            return fail_launch(launched, error);
        }
    }
    let seccomp_head_after_release = current_endpoint_trust_until(
        &mut *spec.watchdog_trust_provider,
        PolicyCustodyEndpointRole::FenceAuthority,
        launched.deadline,
    )
    .map_err(|_| {
        LauncherError::Invalid(
            "current seccomp authority head is unavailable after release",
        )
    })?;
    require_same_current_checkpoint(
        &seccomp_head_pre_release,
        &seccomp_head_after_release,
    )
    .map_err(|_| {
        LauncherError::Invalid(
            "seccomp authority head changed across release",
        )
    })?;
    spec.seccomp_authorization
        .revalidate_current_head(&seccomp_head_after_release)?;
    drop(release_write);
    Ok(launched)
}

#[repr(C)]
#[derive(Default)]
struct CloneArguments {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

struct RawChildSpec {
    entry: StaticEntryPoint,
    invocation: StaticEntryInvocation,
    exact_filter: *const libc::sock_filter,
    exact_filter_len: usize,
    rootfs_fd: RawFd,
    staging_parent_fd: RawFd,
    staging_name: *const libc::c_char,
    old_root_name: *const libc::c_char,
    old_root_absolute: *const libc::c_char,
    parent_pidfd: RawFd,
    parent_pid: libc::pid_t,
    parent_pidfd_inode: libc::ino_t,
    worker_uid: libc::uid_t,
    worker_gid: libc::gid_t,
    pass_fds: *const RawFd,
    pass_fds_len: usize,
    stdin_fd: RawFd,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    error_fd: RawFd,
    ready_fd: RawFd,
    release_fd: RawFd,
    deadline_timer_fd: RawFd,
    ready_proof: *const u8,
    ready_proof_len: usize,
    bootstrap_filter: *const libc::sock_filter,
    bootstrap_filter_len: usize,
    final_baseline: *const libc::sock_filter,
    final_baseline_len: usize,
}

#[repr(C)]
struct MountAttribute {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

unsafe fn child_main_raw(spec: &RawChildSpec) -> ! {
    if libc::syscall(
        libc::SYS_prctl,
        libc::PR_SET_PDEATHSIG,
        libc::SIGKILL,
        0,
        0,
        0,
    ) != 0
        || libc::syscall(libc::SYS_getppid)
            != libc::c_long::from(spec.parent_pid)
    {
        child_fail(spec.error_fd, CHILD_FAILURE_PARENT);
    }
    if libc::syscall(
        libc::SYS_prctl,
        libc::PR_SET_NO_NEW_PRIVS,
        1,
        0,
        0,
        0,
    ) != 0
        || install_filter_raw(
            spec.bootstrap_filter,
            spec.bootstrap_filter_len,
        ) != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_FILTER);
    }
    if libc::syscall(
        libc::SYS_mount,
        ptr::null::<libc::c_char>(),
        b"/\0".as_ptr() as *const libc::c_char,
        ptr::null::<libc::c_char>(),
        libc::MS_REC | libc::MS_PRIVATE,
        ptr::null::<libc::c_void>(),
    ) != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_ROOTFS);
    }
    let tree_fd = libc::syscall(
        libc::SYS_open_tree,
        spec.rootfs_fd,
        b"\0".as_ptr() as *const libc::c_char,
        OPEN_TREE_CLONE_FLAG
            | OPEN_TREE_CLOEXEC_FLAG
            | AT_EMPTY_PATH_FLAG as libc::c_uint,
    ) as RawFd;
    if tree_fd < 0 {
        child_fail(spec.error_fd, CHILD_FAILURE_ROOTFS);
    }
    let mount_attribute = MountAttribute {
        attr_set: MOUNT_ATTR_RDONLY_FLAG
            | MOUNT_ATTR_NOSUID_FLAG
            | MOUNT_ATTR_NODEV_FLAG,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    if libc::syscall(
        libc::SYS_mount_setattr,
        tree_fd,
        b"\0".as_ptr() as *const libc::c_char,
        AT_EMPTY_PATH_FLAG | AT_RECURSIVE_FLAG,
        &mount_attribute as *const MountAttribute,
        size_of::<MountAttribute>(),
    ) != 0
        || libc::syscall(
            libc::SYS_move_mount,
            tree_fd,
            b"\0".as_ptr() as *const libc::c_char,
            spec.staging_parent_fd,
            spec.staging_name,
            MOVE_MOUNT_F_EMPTY_PATH_FLAG,
        ) != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_ROOTFS);
    }
    let new_root_fd = libc::syscall(
        libc::SYS_openat,
        spec.staging_parent_fd,
        spec.staging_name,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) as RawFd;
    if new_root_fd < 0
        || libc::syscall(libc::SYS_fchdir, new_root_fd) != 0
        || libc::syscall(
            libc::SYS_pivot_root,
            b".\0".as_ptr() as *const libc::c_char,
            spec.old_root_name,
        ) != 0
        || libc::syscall(
            libc::SYS_chdir,
            b"/\0".as_ptr() as *const libc::c_char,
        ) != 0
        || libc::syscall(
            libc::SYS_umount2,
            spec.old_root_absolute,
            libc::MNT_DETACH,
        ) != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_ROOTFS);
    }
    libc::syscall(libc::SYS_close, tree_fd);
    libc::syscall(libc::SYS_close, new_root_fd);

    if setup_stdio_raw(
        spec.stdin_fd,
        spec.stdout_fd,
        spec.stderr_fd,
    ) != 0
        || close_all_except_raw(spec.pass_fds, spec.pass_fds_len) != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_FD_SETUP);
    }
    let mut index = 0;
    while index < spec.pass_fds_len {
        let fd = *spec.pass_fds.add(index);
        if libc::syscall(libc::SYS_fcntl, fd, libc::F_SETFD, 0) != 0 {
            child_fail(spec.error_fd, CHILD_FAILURE_FD_SETUP);
        }
        index += 1;
    }

    const SECBIT_NOROOT: libc::c_ulong = 1;
    const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
    const SECBIT_KEEP_CAPS_LOCKED: libc::c_ulong = 1 << 5;
    let securebits = SECBIT_NOROOT
        | SECBIT_NOROOT_LOCKED
        | SECBIT_KEEP_CAPS_LOCKED;
    if libc::syscall(
        libc::SYS_prctl,
        libc::PR_SET_SECUREBITS,
        securebits,
        0,
        0,
        0,
    ) != 0
        || libc::syscall(
            libc::SYS_prctl,
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) != 0
        || libc::syscall(
            libc::SYS_setgroups,
            0_usize,
            ptr::null::<libc::gid_t>(),
        ) != 0
        || libc::syscall(
            libc::SYS_setresgid,
            spec.worker_gid,
            spec.worker_gid,
            spec.worker_gid,
        ) != 0
        || libc::syscall(
            libc::SYS_setresuid,
            spec.worker_uid,
            spec.worker_uid,
            spec.worker_uid,
        ) != 0
        || libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_NO_NEW_PRIVS,
            1,
            0,
            0,
            0,
        ) != 0
        || libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_DUMPABLE,
            0,
            0,
            0,
            0,
        ) != 0
        || libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0,
            0,
            0,
        ) != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_PRIVILEGE);
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let mut capability_header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut capability_data = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if libc::syscall(
        libc::SYS_capset,
        &capability_header as *const CapabilityHeader,
        capability_data.as_ptr(),
    ) != 0
        || libc::syscall(
            libc::SYS_capget,
            &mut capability_header as *mut CapabilityHeader,
            capability_data.as_mut_ptr(),
        ) != 0
        || capability_data[0].effective != 0
        || capability_data[0].permitted != 0
        || capability_data[0].inheritable != 0
        || capability_data[1].effective != 0
        || capability_data[1].permitted != 0
        || capability_data[1].inheritable != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_PRIVILEGE);
    }
    let mut parent_stat: libc::stat = zeroed();
    if libc::syscall(libc::SYS_geteuid)
            != libc::c_long::from(spec.worker_uid)
        || libc::syscall(libc::SYS_getegid)
            != libc::c_long::from(spec.worker_gid)
        || parent_pidfd_alive_raw(
            spec.parent_pidfd,
            spec.parent_pid,
        ) != 1
        || libc::syscall(
            libc::SYS_fstat,
            spec.parent_pidfd,
            &mut parent_stat as *mut libc::stat,
        ) != 0
        || parent_stat.st_ino != spec.parent_pidfd_inode
    {
        child_fail(spec.error_fd, CHILD_FAILURE_PARENT);
    }
    if install_filter_raw(
        spec.final_baseline,
        spec.final_baseline_len,
    ) != 0
        || install_filter_raw(
            spec.exact_filter,
            spec.exact_filter_len,
        ) != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_FILTER);
    }
    if child_write_all_raw(
        spec.ready_fd,
        spec.ready_proof,
        spec.ready_proof_len,
    ) != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_FILTER);
    }
    if child_wait_for_release_raw(
        spec.release_fd,
        spec.parent_pidfd,
        spec.deadline_timer_fd,
    ) != 0
    {
        child_fail(spec.error_fd, CHILD_FAILURE_RELEASE);
    }
    libc::syscall(libc::SYS_close, spec.parent_pidfd);
    libc::syscall(libc::SYS_close, spec.error_fd);
    libc::syscall(libc::SYS_close, spec.ready_fd);
    libc::syscall(libc::SYS_close, spec.release_fd);
    libc::syscall(libc::SYS_close, spec.deadline_timer_fd);
    (spec.entry)(&spec.invocation as *const StaticEntryInvocation);
}

unsafe fn dup_to_stdio(source: RawFd, target: RawFd) -> libc::c_long {
    if source == target {
        libc::syscall(libc::SYS_fcntl, target, libc::F_SETFD, 0)
    } else {
        libc::syscall(libc::SYS_dup3, source, target, 0)
    }
}

unsafe fn setup_stdio_raw(
    stdin_fd: RawFd,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
) -> libc::c_long {
    let sources = [stdin_fd, stdout_fd, stderr_fd];
    let targets = [
        libc::STDIN_FILENO,
        libc::STDOUT_FILENO,
        libc::STDERR_FILENO,
    ];
    let mut temporary = [-1; 3];
    let mut index = 0_usize;
    while index < sources.len() {
        if sources[index] != targets[index] {
            temporary[index] = libc::syscall(
                libc::SYS_fcntl,
                sources[index],
                libc::F_DUPFD_CLOEXEC,
                3,
            ) as RawFd;
            if temporary[index] < 0 {
                return -1;
            }
        }
        index += 1;
    }
    index = 0;
    while index < sources.len() {
        let source = if temporary[index] >= 0 {
            temporary[index]
        } else {
            sources[index]
        };
        if dup_to_stdio(source, targets[index]) != 0 {
            return -1;
        }
        index += 1;
    }
    for fd in temporary {
        if fd >= 0 {
            libc::syscall(libc::SYS_close, fd);
        }
    }
    0
}

unsafe fn close_all_except_raw(
    sorted_fds: *const RawFd,
    length: usize,
) -> libc::c_long {
    if sorted_fds.is_null() || length == 0 {
        return -1;
    }
    let mut first = 3_u32;
    let mut index = 0_usize;
    while index < length {
        let retained = *sorted_fds.add(index);
        if retained < 3
            || index > 0 && retained <= *sorted_fds.add(index - 1)
        {
            return -1;
        }
        let retained_u32 = retained as u32;
        if first < retained_u32
            && libc::syscall(
                libc::SYS_close_range,
                first,
                retained_u32 - 1,
                0_u32,
            ) != 0
        {
            return -1;
        }
        first = retained_u32.saturating_add(1);
        index += 1;
    }
    if first < u32::MAX
        && libc::syscall(
            libc::SYS_close_range,
            first,
            u32::MAX,
            0_u32,
        ) != 0
    {
        return -1;
    }
    0
}

unsafe fn parent_pidfd_alive_raw(
    parent_pidfd: RawFd,
    expected_parent_pid: libc::pid_t,
) -> libc::c_int {
    let mut descriptor = libc::pollfd {
        fd: parent_pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let zero_timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        let ready = libc::syscall(
            libc::SYS_ppoll,
            &mut descriptor as *mut libc::pollfd,
            1_usize,
            &zero_timeout as *const libc::timespec,
            ptr::null::<libc::sigset_t>(),
            0_usize,
        );
        if ready == 0 {
            return if descriptor.revents == 0
                && libc::syscall(libc::SYS_getppid)
                    == libc::c_long::from(expected_parent_pid)
            {
                1
            } else {
                0
            };
        }
        if ready > 0 {
            return 0;
        }
        let error = *libc::__errno_location();
        if error != libc::EINTR {
            return 0;
        }
    }
}

unsafe fn child_write_all_raw(
    fd: RawFd,
    bytes: *const u8,
    length: usize,
) -> libc::c_long {
    if bytes.is_null() || length == 0 || length > 4096 {
        return -1;
    }
    loop {
        let written = libc::syscall(
            libc::SYS_write,
            fd,
            bytes as *const libc::c_void,
            length,
        );
        if written == length as libc::c_long {
            return 0;
        }
        if written >= 0 {
            return -1;
        }
        if *libc::__errno_location() != libc::EINTR {
            return -1;
        }
    }
}

unsafe fn child_wait_for_release_raw(
    release_fd: RawFd,
    parent_pidfd: RawFd,
    deadline_timer_fd: RawFd,
) -> libc::c_long {
    let mut descriptors = [
        libc::pollfd {
            fd: parent_pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: deadline_timer_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: release_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        for descriptor in &mut descriptors {
            descriptor.revents = 0;
        }
        let ready = libc::syscall(
            libc::SYS_ppoll,
            descriptors.as_mut_ptr(),
            descriptors.len(),
            ptr::null::<libc::timespec>(),
            ptr::null::<libc::sigset_t>(),
            0_usize,
        );
        if ready < 0 {
            if *libc::__errno_location() == libc::EINTR {
                continue;
            }
            return -1;
        }
        if descriptors[0].revents != 0 || descriptors[1].revents != 0 {
            return -1;
        }
        if descriptors[2].revents
            & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
            != 0
        {
            return -1;
        }
        if descriptors[2].revents & libc::POLLIN != 0 {
            let mut release = 0_u8;
            let read = libc::syscall(
                libc::SYS_read,
                release_fd,
                &mut release as *mut u8 as *mut libc::c_void,
                1_usize,
            );
            return if read == 1 && release == 1 { 0 } else { -1 };
        }
    }
}

unsafe fn child_fail(error_fd: RawFd, code: u8) -> ! {
    libc::syscall(
        libc::SYS_write,
        error_fd,
        &code as *const u8 as *const libc::c_void,
        1,
    );
    loop {
        libc::syscall(libc::SYS_exit_group, 127);
    }
}

#[derive(Clone, Copy)]
struct FixedFilter {
    instructions: [libc::sock_filter; MAX_BOOTSTRAP_FILTER_INSTRUCTIONS],
    len: usize,
}

const EMPTY_FILTER: libc::sock_filter = libc::sock_filter {
    code: 0,
    jt: 0,
    jf: 0,
    k: 0,
};

impl FixedFilter {
    fn new() -> Self {
        Self {
            instructions: [EMPTY_FILTER; MAX_BOOTSTRAP_FILTER_INSTRUCTIONS],
            len: 0,
        }
    }

    fn push(
        &mut self,
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    ) -> Result<(), LauncherError> {
        if self.len >= self.instructions.len() {
            return Err(LauncherError::Invalid(
                "mandatory seccomp baseline exceeds fixed capacity",
            ));
        }
        self.instructions[self.len] = libc::sock_filter {
            code,
            jt,
            jf,
            k,
        };
        self.len += 1;
        Ok(())
    }
}

fn bootstrap_filter(
    audit_arch: u32,
) -> Result<FixedFilter, LauncherError> {
    let mut filter = FixedFilter::new();
    filter.push(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH)?;
    filter.push(BPF_JMP_JEQ_K, 1, 0, audit_arch)?;
    filter.push(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS)?;
    filter.push(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR)?;
    for syscall in [
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_process_madvise,
        libc::SYS_process_mrelease,
        libc::SYS_kcmp,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        libc::SYS_io_uring_setup,
        libc::SYS_kexec_load,
        libc::SYS_finit_module,
        libc::SYS_init_module,
        libc::SYS_delete_module,
    ] {
        push_unconditional_errno(&mut filter, syscall)?;
    }
    push_legacy_uselib_errno(&mut filter)?;
    push_executable_memory_denials(&mut filter)?;
    push_masked_errno(
        &mut filter,
        libc::SYS_clone,
        0,
        FORBIDDEN_CLONE_NAMESPACE_FLAGS,
    )?;
    filter.push(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)?;
    Ok(filter)
}

fn mandatory_baseline_filter(
    audit_arch: u32,
) -> Result<FixedFilter, LauncherError> {
    let mut filter = FixedFilter::new();
    filter.push(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH)?;
    filter.push(BPF_JMP_JEQ_K, 1, 0, audit_arch)?;
    filter.push(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS)?;
    filter.push(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR)?;

    for syscall in [
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_process_madvise,
        libc::SYS_process_mrelease,
        libc::SYS_kcmp,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fsconfig,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_clone3,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        libc::SYS_io_uring_setup,
        libc::SYS_kexec_load,
        libc::SYS_finit_module,
        libc::SYS_init_module,
        libc::SYS_delete_module,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_acct,
    ] {
        push_unconditional_errno(&mut filter, syscall)?;
    }
    push_legacy_uselib_errno(&mut filter)?;
    push_executable_memory_denials(&mut filter)?;
    push_masked_errno(
        &mut filter,
        libc::SYS_clone,
        0,
        FORBIDDEN_CLONE_NAMESPACE_FLAGS,
    )?;
    filter.push(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)?;
    Ok(filter)
}

fn push_executable_memory_denials(
    filter: &mut FixedFilter,
) -> Result<(), LauncherError> {
    push_masked_errno(
        filter,
        libc::SYS_mmap,
        2,
        libc::PROT_EXEC as u32,
    )?;
    push_masked_errno(
        filter,
        libc::SYS_mprotect,
        2,
        libc::PROT_EXEC as u32,
    )?;
    push_masked_errno(
        filter,
        libc::SYS_pkey_mprotect,
        2,
        libc::PROT_EXEC as u32,
    )?;
    push_masked_errno(
        filter,
        libc::SYS_shmat,
        2,
        libc::SHM_EXEC as u32,
    )
}

#[cfg(target_arch = "x86_64")]
fn push_legacy_uselib_errno(
    filter: &mut FixedFilter,
) -> Result<(), LauncherError> {
    const X86_64_SYS_USELIB: libc::c_long = 134;
    push_unconditional_errno(filter, X86_64_SYS_USELIB)
}

#[cfg(not(target_arch = "x86_64"))]
fn push_legacy_uselib_errno(
    _filter: &mut FixedFilter,
) -> Result<(), LauncherError> {
    Ok(())
}

fn push_unconditional_errno(
    filter: &mut FixedFilter,
    syscall: libc::c_long,
) -> Result<(), LauncherError> {
    let syscall = u32::try_from(syscall).map_err(|_| {
        LauncherError::Invalid("negative syscall number in seccomp baseline")
    })?;
    filter.push(BPF_JMP_JEQ_K, 0, 1, syscall)?;
    filter.push(
        BPF_RET_K,
        0,
        0,
        SECCOMP_RET_ERRNO | libc::EPERM as u32,
    )
}

fn push_masked_errno(
    filter: &mut FixedFilter,
    syscall: libc::c_long,
    argument_index: u32,
    forbidden_mask: u32,
) -> Result<(), LauncherError> {
    let syscall = u32::try_from(syscall).map_err(|_| {
        LauncherError::Invalid("negative syscall number in seccomp baseline")
    })?;
    let offset = SECCOMP_DATA_ARGS
        .checked_add(argument_index.checked_mul(8).ok_or(
            LauncherError::Invalid("seccomp argument offset overflow"),
        )?)
        .ok_or(LauncherError::Invalid(
            "seccomp argument offset overflow",
        ))?;
    filter.push(BPF_JMP_JEQ_K, 0, 3, syscall)?;
    filter.push(BPF_LD_W_ABS, 0, 0, offset)?;
    filter.push(BPF_JMP_JSET_K, 0, 1, forbidden_mask)?;
    filter.push(
        BPF_RET_K,
        0,
        0,
        SECCOMP_RET_ERRNO | libc::EPERM as u32,
    )?;
    filter.push(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR)
}

unsafe fn install_filter_raw(
    filters: *const libc::sock_filter,
    length: usize,
) -> libc::c_long {
    if filters.is_null()
        || length == 0
        || length > u16::MAX as usize
    {
        return -1;
    }
    let mut program = libc::sock_fprog {
        len: length as u16,
        filter: filters as *mut libc::sock_filter,
    };
    libc::syscall(
        libc::SYS_seccomp,
        SECCOMP_SET_MODE_FILTER,
        0_u32,
        &mut program as *mut libc::sock_fprog,
    )
}

fn validate_exact_filter(
    filters: &[libc::sock_filter],
    audit_arch: u32,
) -> Result<(), LauncherError> {
    if filters.len() < 4
        || filters.len() > MAX_EXACT_FILTER_INSTRUCTIONS
        || filters[0].code != BPF_LD_W_ABS
        || filters[0].k != SECCOMP_DATA_ARCH
        || filters[1].code != BPF_JMP_JEQ_K
        || filters[1].k != audit_arch
        || filters[1].jt != 1
        || filters[1].jf != 0
        || filters[2].code != BPF_RET_K
        || filters[2].k != SECCOMP_RET_KILL_PROCESS
        || filters.last().is_none_or(|instruction| {
            instruction.code != BPF_RET_K
                || instruction.k == SECCOMP_RET_ALLOW
        })
    {
        return Err(LauncherError::Invalid(
            "exact seccomp program lacks a closed architecture-gated shape",
        ));
    }
    for (index, instruction) in filters.iter().enumerate() {
        let class = instruction.code & 0x07;
        if class == 0x05 {
            if instruction.code == BPF_JMP_JA_K {
                let target = index
                    .checked_add(1)
                    .and_then(|value| {
                        value.checked_add(instruction.k as usize)
                    })
                    .ok_or(LauncherError::Invalid(
                        "seccomp absolute jump overflow",
                    ))?;
                if target >= filters.len() {
                    return Err(LauncherError::Invalid(
                        "seccomp absolute jump leaves the exact program",
                    ));
                }
                continue;
            }
            let true_target = index
                .checked_add(1 + usize::from(instruction.jt))
                .ok_or(LauncherError::Invalid(
                    "seccomp true jump overflow",
                ))?;
            let false_target = index
                .checked_add(1 + usize::from(instruction.jf))
                .ok_or(LauncherError::Invalid(
                    "seccomp false jump overflow",
                ))?;
            if true_target >= filters.len() || false_target >= filters.len() {
                return Err(LauncherError::Invalid(
                    "seccomp jump leaves the exact program",
                ));
            }
        }
    }
    Ok(())
}

fn validate_static_elf(
    fd: RawFd,
    file_length: u64,
    architecture: ExecutableArchitecture,
    pie_policy: StaticPiePolicy,
    file_sha256: [u8; 32],
) -> Result<ElfValidation, LauncherError> {
    if file_length < ELF_HEADER_BYTES as u64
        || file_length > MAX_EXECUTABLE_BYTES
    {
        return Err(LauncherError::Invalid(
            "ELF length is outside the launcher bound",
        ));
    }
    let mut header = [0_u8; ELF_HEADER_BYTES];
    pread_exact(fd, header.as_mut_ptr(), header.len(), 0)?;
    if header[..4] != [0x7f, b'E', b'L', b'F']
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
    {
        return Err(LauncherError::Invalid(
            "worker is not a little-endian ELF64 image",
        ));
    }
    let object_type = little_u16(&header[16..18]);
    let machine = little_u16(&header[18..20]);
    let entry = little_u64(&header[24..32]);
    let program_header_offset = little_u64(&header[32..40]);
    let elf_header_size = little_u16(&header[52..54]);
    let program_header_size = little_u16(&header[54..56]);
    let program_header_count = little_u16(&header[56..58]);
    let static_pie = object_type == ET_DYN;
    if machine != architecture.elf_machine()
        || elf_header_size != ELF_HEADER_BYTES as u16
        || program_header_size != ELF64_PROGRAM_HEADER_BYTES as u16
        || program_header_count == 0
        || usize::from(program_header_count) > MAX_ELF_PROGRAM_HEADERS
        || !matches!(object_type, ET_EXEC | ET_DYN)
        || static_pie && pie_policy != StaticPiePolicy::AllowStaticPie
    {
        return Err(LauncherError::Invalid(
            "ELF architecture, type, or program-header contract mismatch",
        ));
    }
    let table_length = u64::from(program_header_size)
        .checked_mul(u64::from(program_header_count))
        .ok_or(LauncherError::Invalid(
            "ELF program-header length overflow",
        ))?;
    if program_header_offset
        .checked_add(table_length)
        .is_none_or(|end| end > file_length)
    {
        return Err(LauncherError::Invalid(
            "ELF program-header table exceeds the file",
        ));
    }
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 || !(page_size as u64).is_power_of_two() {
        return Err(LauncherError::Invalid(
            "host page size is unavailable for ELF overlap validation",
        ));
    }
    let page_size = page_size as u64;
    let page_mask = page_size - 1;
    let mut load_ranges =
        [(0_u64, 0_u64, 0_u64, 0_u64, 0_u32); MAX_ELF_PROGRAM_HEADERS];
    let mut load_count = 0_usize;
    let mut entry_in_executable_load = false;
    let mut dynamic_seen = false;
    let mut gnu_stack_count = 0_u8;
    for index in 0..usize::from(program_header_count) {
        let offset = program_header_offset
            + u64::try_from(index * ELF64_PROGRAM_HEADER_BYTES)
                .map_err(|_| LauncherError::Invalid(
                    "ELF program-header offset overflow",
                ))?;
        let mut program = [0_u8; ELF64_PROGRAM_HEADER_BYTES];
        pread_exact(fd, program.as_mut_ptr(), program.len(), offset)?;
        let kind = little_u32(&program[0..4]);
        let flags = little_u32(&program[4..8]);
        let file_offset = little_u64(&program[8..16]);
        let virtual_address = little_u64(&program[16..24]);
        let file_size = little_u64(&program[32..40]);
        let memory_size = little_u64(&program[40..48]);
        let alignment = little_u64(&program[48..56]);
        if file_size > memory_size
            || file_offset
                .checked_add(file_size)
                .is_none_or(|end| end > file_length)
            || virtual_address.checked_add(memory_size).is_none()
            || alignment > 1
                && (!alignment.is_power_of_two()
                    || virtual_address % alignment != file_offset % alignment)
        {
            return Err(LauncherError::Invalid(
                "ELF segment bounds or alignment are invalid",
            ));
        }
        match kind {
            PT_INTERP => {
                return Err(LauncherError::Invalid(
                    "static custody executable contains PT_INTERP",
                ));
            }
            PT_GNU_STACK => {
                gnu_stack_count = gnu_stack_count.checked_add(1).ok_or(
                    LauncherError::Invalid(
                        "ELF contains too many PT_GNU_STACK headers",
                    ),
                )?;
                if gnu_stack_count != 1 || flags & PF_X != 0 {
                    return Err(LauncherError::Invalid(
                        "custody executable must declare one non-executable stack",
                    ));
                }
            }
            PT_LOAD => {
                if memory_size == 0 || flags & (PF_W | PF_X) == (PF_W | PF_X) {
                    return Err(LauncherError::Invalid(
                        "ELF load segment is empty or writable-executable",
                    ));
                }
                let end = virtual_address + memory_size;
                let rounded_start = virtual_address & !page_mask;
                let rounded_end = end
                    .checked_add(page_mask)
                    .map(|value| value & !page_mask)
                    .ok_or(LauncherError::Invalid(
                        "page-rounded ELF load range overflow",
                    ))?;
                for (
                    start,
                    prior_end,
                    prior_rounded_start,
                    prior_rounded_end,
                    prior_flags,
                ) in &load_ranges[..load_count]
                {
                    if virtual_address < *prior_end && *start < end {
                        return Err(LauncherError::Invalid(
                            "ELF load segments overlap",
                        ));
                    }
                    if rounded_start < *prior_rounded_end
                        && *prior_rounded_start < rounded_end
                        && (flags | *prior_flags) & (PF_W | PF_X)
                            == (PF_W | PF_X)
                    {
                        return Err(LauncherError::Invalid(
                            "page-rounded ELF loads create writable-executable overlap",
                        ));
                    }
                }
                load_ranges[load_count] = (
                    virtual_address,
                    end,
                    rounded_start,
                    rounded_end,
                    flags,
                );
                load_count += 1;
                if flags & PF_X != 0
                    && entry >= virtual_address
                    && entry < end
                {
                    entry_in_executable_load = true;
                }
            }
            PT_DYNAMIC => {
                if dynamic_seen
                    || file_size == 0
                    || file_size % ELF64_DYNAMIC_ENTRY_BYTES as u64 != 0
                {
                    return Err(LauncherError::Invalid(
                        "ELF dynamic table shape is invalid",
                    ));
                }
                dynamic_seen = true;
                validate_static_dynamic_table(fd, file_offset, file_size)?;
            }
            _ => {}
        }
    }
    if load_count == 0
        || entry == 0
        || !entry_in_executable_load
        || gnu_stack_count != 1
    {
        return Err(LauncherError::Invalid(
            "ELF entry or non-executable stack contract is invalid",
        ));
    }
    Ok(ElfValidation {
        architecture,
        static_pie,
        entry,
        load_segments: u16::try_from(load_count).map_err(|_| {
            LauncherError::Invalid("ELF load-segment count overflow")
        })?,
        file_sha256,
    })
}

fn validate_static_dynamic_table(
    fd: RawFd,
    offset: u64,
    length: u64,
) -> Result<(), LauncherError> {
    let entries = length / ELF64_DYNAMIC_ENTRY_BYTES as u64;
    let mut found_null = false;
    for index in 0..entries {
        let mut entry = [0_u8; ELF64_DYNAMIC_ENTRY_BYTES];
        pread_exact(
            fd,
            entry.as_mut_ptr(),
            entry.len(),
            offset + index * ELF64_DYNAMIC_ENTRY_BYTES as u64,
        )?;
        let tag = little_i64(&entry[..8]);
        if tag == DT_NEEDED {
            return Err(LauncherError::Invalid(
                "static custody executable contains DT_NEEDED",
            ));
        }
        if tag == DT_NULL {
            found_null = true;
            break;
        }
    }
    if !found_null {
        return Err(LauncherError::Invalid(
            "ELF dynamic table has no DT_NULL terminator",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct BlockIdentity {
    rdev: libc::dev_t,
}

fn verify_read_only_mount_root(
    fd: RawFd,
) -> Result<(DescriptorIdentity, libc::c_long), LauncherError> {
    let identity = directory_identity(fd)?;
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(fd, &mut filesystem) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut mount: libc::statvfs = unsafe { zeroed() };
    if unsafe { libc::fstatvfs(fd, &mut mount) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if mount.f_flag as libc::c_ulong & ST_RDONLY_FLAG == 0 {
        return Err(LauncherError::Invalid(
            "verified root filesystem is not mounted read-only",
        ));
    }
    Ok((identity, filesystem.f_type as libc::c_long))
}

fn verify_read_only_block_device(fd: RawFd) -> Result<BlockIdentity, LauncherError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut read_only: libc::c_int = 0;
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFBLK
        || stat.st_uid != 0
        || stat.st_rdev == 0
        || unsafe {
            libc::ioctl(
                fd,
                BLKROGET,
                &mut read_only as *mut libc::c_int,
            )
        } != 0
        || read_only != 1
    {
        return Err(LauncherError::Invalid(
            "retained rootfs block device is not root-owned and read-only",
        ));
    }
    Ok(BlockIdentity {
        rdev: stat.st_rdev,
    })
}

fn verify_dm_control_descriptor(fd: RawFd) -> Result<(), LauncherError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFCHR || stat.st_uid != 0 {
        return Err(LauncherError::Invalid(
            "device-mapper control descriptor is not a root-owned character device",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct DmVerityTableEvidence {
    table_sha256: [u8; 32],
    root_hash_sha256: [u8; 32],
    dm_uuid_sha256: [u8; 32],
}

fn query_dm_verity_table(
    dm_control_fd: RawFd,
    device: libc::dev_t,
) -> Result<DmVerityTableEvidence, LauncherError> {
    let mut storage = [0_u64; 1024];
    let buffer = storage.as_mut_ptr() as *mut u8;
    let capacity = size_of::<u64>() * storage.len();
    unsafe { ptr::write_bytes(buffer, 0, capacity) };
    let header = buffer as *mut DmIoctl;
    unsafe {
        (*header).version = [4, 0, 0];
        (*header).data_size = u32::try_from(capacity).map_err(|_| {
            LauncherError::Invalid("device-mapper query buffer is too large")
        })?;
        (*header).data_start =
            u32::try_from(size_of::<DmIoctl>()).map_err(|_| {
                LauncherError::Invalid(
                    "device-mapper header length overflow",
                )
            })?;
        (*header).flags = DM_STATUS_TABLE_FLAG;
        (*header).dev = device;
    }
    let request = u32::try_from(ioctl_read_write(
        DM_IOCTL_TYPE,
        DM_TABLE_STATUS_COMMAND,
        size_of::<DmIoctl>() as u64,
    )).map_err(|_| LauncherError::Invalid("device-mapper request exceeds ioctl ABI"))?
        as libc::Ioctl;
    if unsafe { libc::ioctl(dm_control_fd, request, header) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let header_ref = unsafe { &*header };
    if header_ref.flags & DM_BUFFER_FULL_FLAG != 0
        || header_ref.flags & DM_ACTIVE_PRESENT_FLAG == 0
        || header_ref.flags & DM_INACTIVE_PRESENT_FLAG != 0
        || header_ref.flags & DM_SUSPEND_FLAG != 0
        || header_ref.flags & DM_READONLY_FLAG == 0
        || header_ref.target_count != 1
        || usize::try_from(header_ref.data_size)
            .ok()
            .is_none_or(|size| size > capacity)
        || usize::try_from(header_ref.data_start)
            .ok()
            .is_none_or(|start| {
                start < size_of::<DmIoctl>()
                    || start + size_of::<DmTargetSpec>() > capacity
            })
    {
        return Err(LauncherError::Invalid(
            "device-mapper table response is incomplete or ambiguous",
        ));
    }
    let uuid = nul_terminated_slice(&header_ref.uuid)?;
    if uuid.is_empty() {
        return Err(LauncherError::Invalid(
            "device-mapper UUID is empty",
        ));
    }
    let target_offset = usize::try_from(header_ref.data_start).map_err(|_| {
        LauncherError::Invalid("device-mapper target offset overflow")
    })?;
    let target = unsafe { &*(buffer.add(target_offset) as *const DmTargetSpec) };
    if target.sector_start != 0
        || target.length == 0
        || nul_terminated_slice(&target.target_type)? != b"verity"
    {
        return Err(LauncherError::Invalid(
            "device-mapper root is not one complete verity target",
        ));
    }
    let params_start = target_offset + size_of::<DmTargetSpec>();
    let response_size = usize::try_from(header_ref.data_size).map_err(|_| {
        LauncherError::Invalid("device-mapper response length overflow")
    })?;
    if params_start >= response_size {
        return Err(LauncherError::Invalid(
            "device-mapper verity parameters are missing",
        ));
    }
    let params_region =
        unsafe { std::slice::from_raw_parts(buffer.add(params_start), response_size - params_start) };
    let params = nul_terminated_slice(params_region)?;
    let params_text = std::str::from_utf8(params).map_err(|_| {
        LauncherError::Invalid("device-mapper verity table is not UTF-8")
    })?;
    let fields = params_text.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() < 10
        || fields[0] != "1"
        || fields[7] != "sha256"
        || fields[1].is_empty()
        || fields[2].is_empty()
    {
        return Err(LauncherError::Invalid(
            "device-mapper verity parameters are unsupported",
        ));
    }
    let root_hash = hex::decode(fields[8]).map_err(|_| {
        LauncherError::Invalid("device-mapper root hash is not hexadecimal")
    })?;
    let root_hash_sha256: [u8; 32] =
        root_hash.try_into().map_err(|_| {
            LauncherError::Invalid(
                "device-mapper root hash is not SHA-256",
            )
        })?;
    Ok(DmVerityTableEvidence {
        table_sha256: hash_frames(&[
            b"serverware.policyCustodyDmVerityTable/v1",
            params,
        ]),
        root_hash_sha256,
        dm_uuid_sha256: hash_frames(&[
            b"serverware.policyCustodyDmUuid/v1",
            uuid,
        ]),
    })
}

fn ioctl_read_write(kind: u64, number: u64, size: u64) -> libc::c_ulong {
    const IOC_NRBITS: u64 = 8;
    const IOC_TYPEBITS: u64 = 8;
    const IOC_SIZEBITS: u64 = 14;
    const IOC_NRSHIFT: u64 = 0;
    const IOC_TYPESHIFT: u64 = IOC_NRSHIFT + IOC_NRBITS;
    const IOC_SIZESHIFT: u64 = IOC_TYPESHIFT + IOC_TYPEBITS;
    const IOC_DIRSHIFT: u64 = IOC_SIZESHIFT + IOC_SIZEBITS;
    const IOC_READ_WRITE: u64 = 3;
    ((IOC_READ_WRITE << IOC_DIRSHIFT)
        | (kind << IOC_TYPESHIFT)
        | (number << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)) as libc::c_ulong
}

fn immutable_regular_file_identity(fd: RawFd) -> Result<DescriptorIdentity, LauncherError> {
    immutable_regular_file_identity_with_limit(fd, MAX_EXECUTABLE_BYTES)
}

fn immutable_regular_file_identity_with_limit(
    fd: RawFd,
    maximum_length: u64,
) -> Result<DescriptorIdentity, LauncherError> {
    let identity = descriptor_identity(fd)?;
    if identity.mode & libc::S_IFMT != libc::S_IFREG
        || identity.uid != 0
        || identity.mode & 0o022 != 0
        || identity.length == 0
        || identity.length > maximum_length
    {
        return Err(LauncherError::Invalid(
            "descriptor is not immutable root-owned regular data",
        ));
    }
    Ok(identity)
}

fn directory_identity(fd: RawFd) -> Result<DescriptorIdentity, LauncherError> {
    let identity = descriptor_identity(fd)?;
    if identity.mode & libc::S_IFMT != libc::S_IFDIR
        || identity.inode == 0
    {
        return Err(LauncherError::Invalid(
            "descriptor is not a directory",
        ));
    }
    Ok(identity)
}

fn descriptor_identity(fd: RawFd) -> Result<DescriptorIdentity, LauncherError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut statx: linux_statx::Statx = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || linux_statx::statx(
            fd,
            c"",
            libc::AT_EMPTY_PATH | linux_statx::SYNC_AS_STAT,
            linux_statx::BASIC_STATS | linux_statx::MNT_ID,
            &mut statx,
        ) != 0
        || statx.stx_mask & linux_statx::BASIC_STATS
            != linux_statx::BASIC_STATS
        || statx.stx_mask & linux_statx::MNT_ID == 0
        || statx.stx_ino != stat.st_ino
        || statx.stx_size != stat.st_size as u64
        || u32::from(statx.stx_mode) != stat.st_mode
    {
        return Err(LauncherError::Invalid(
            "fstat/statx descriptor identity mismatch",
        ));
    }
    Ok(DescriptorIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        uid: stat.st_uid,
        gid: stat.st_gid,
        length: stat.st_size as u64,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
        mount_id: statx.stx_mnt_id,
    })
}

fn open_beneath(
    root_fd: RawFd,
    relative_path: &Path,
    flags: libc::c_int,
) -> Result<OwnedFd, LauncherError> {
    validate_relative_path(relative_path)?;
    let path = CString::new(relative_path.as_os_str().as_bytes()).map_err(|_| {
        LauncherError::Invalid("retained descriptor path contains NUL")
    })?;
    let how = OpenHow {
        flags: u64::try_from(flags).map_err(|_| {
            LauncherError::Invalid("openat2 flags are invalid")
        })?,
        mode: 0,
        resolve: RESOLVE_NO_XDEV
            | RESOLVE_NO_MAGICLINKS
            | RESOLVE_NO_SYMLINKS
            | RESOLVE_BENEATH,
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd,
            path.as_ptr(),
            &how as *const OpenHow,
            size_of::<OpenHow>(),
        ) as RawFd
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn openat_directory(parent_fd: RawFd, name: &CString) -> Result<OwnedFd, LauncherError> {
    let raw = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn validate_relative_path(path: &Path) -> Result<(), LauncherError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(LauncherError::Invalid(
            "retained descriptor path must be normalized and relative",
        ));
    }
    Ok(())
}

fn validate_single_component(value: &str) -> Result<(), LauncherError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.as_bytes().contains(&b'/')
        || value.as_bytes().contains(&0)
    {
        return Err(LauncherError::Invalid(
            "root-switch name must be one normalized component",
        ));
    }
    Ok(())
}

fn directory_is_empty(fd: RawFd) -> Result<bool, LauncherError> {
    let duplicate = duplicate_fd_cloexec(fd)?;
    let mut buffer = [0_u8; 4096];
    loop {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                duplicate.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            ) as isize
        };
        if read < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if read == 0 {
            return Ok(true);
        }
        let mut offset = 0_usize;
        let read = usize::try_from(read).map_err(|_| {
            LauncherError::Invalid("getdents64 length conversion failed")
        })?;
        while offset < read {
            if read - offset < 19 {
                return Err(LauncherError::Invalid(
                    "getdents64 record is truncated",
                ));
            }
            let record_length = u16::from_ne_bytes([
                buffer[offset + 16],
                buffer[offset + 17],
            ]) as usize;
            if record_length < 20 || offset + record_length > read {
                return Err(LauncherError::Invalid(
                    "getdents64 record length is invalid",
                ));
            }
            let name_region = &buffer[offset + 19..offset + record_length];
            let name_end =
                name_region.iter().position(|byte| *byte == 0).ok_or(
                    LauncherError::Invalid(
                        "getdents64 record has no name terminator",
                    ),
                )?;
            let name = &name_region[..name_end];
            if name != b"." && name != b".." {
                return Ok(false);
            }
            offset += record_length;
        }
    }
}

fn sha256_descriptor(fd: RawFd) -> Result<[u8; 32], LauncherError> {
    let identity = descriptor_identity(fd)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;
    while offset < identity.length {
        let remaining = identity.length - offset;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| LauncherError::Invalid(
                "descriptor digest length overflow",
            ))?;
        let read = unsafe {
            libc::pread(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                wanted,
                offset as libc::off_t,
            )
        };
        if read < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if read == 0 {
            return Err(LauncherError::Invalid(
                "descriptor shortened while hashing",
            ));
        }
        let read = usize::try_from(read).map_err(|_| {
            LauncherError::Invalid("descriptor read length overflow")
        })?;
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or(LauncherError::Invalid(
                "descriptor digest offset overflow",
            ))?;
    }
    let after = descriptor_identity(fd)?;
    if after != identity {
        return Err(LauncherError::Invalid(
            "descriptor changed while hashing",
        ));
    }
    Ok(hasher.finalize().into())
}

fn pread_exact(
    fd: RawFd,
    destination: *mut u8,
    length: usize,
    initial_offset: u64,
) -> Result<(), LauncherError> {
    let mut completed = 0_usize;
    while completed < length {
        let offset = initial_offset
            .checked_add(completed as u64)
            .ok_or(LauncherError::Invalid("pread offset overflow"))?;
        let read = unsafe {
            libc::pread(
                fd,
                destination.add(completed) as *mut libc::c_void,
                length - completed,
                offset as libc::off_t,
            )
        };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error.into());
        }
        if read == 0 {
            return Err(LauncherError::Invalid(
                "retained descriptor ended before expected length",
            ));
        }
        completed = completed
            .checked_add(usize::try_from(read).map_err(|_| {
                LauncherError::Invalid("pread length conversion failed")
            })?)
            .ok_or(LauncherError::Invalid("pread length overflow"))?;
    }
    Ok(())
}

fn wait_for_filter_ready(
    error_fd: RawFd,
    ready_fd: RawFd,
    pidfd: RawFd,
    expected_ready_proof: [u8; READY_PROOF_BYTES],
    deadline: BoottimeDeadline,
) -> Result<(), LauncherError> {
    let ready_descriptor = unsafe { BorrowedFd::borrow_raw(ready_fd) };
    let error_descriptor = unsafe { BorrowedFd::borrow_raw(error_fd) };
    let pid_descriptor = unsafe { BorrowedFd::borrow_raw(pidfd) };
    let targets = [
        PollTarget::socket(
            ready_descriptor,
            PollInterest::READABLE,
        ),
        PollTarget::socket(
            error_descriptor,
            PollInterest::READABLE,
        ),
        PollTarget::pidfd(pid_descriptor),
    ];
    loop {
        if try_read_ready_proof(ready_fd, expected_ready_proof)? {
            if let Some((si_code, status)) =
                observe_pidfd_terminal(pidfd)?
            {
                return Err(LauncherError::ChildTerminated {
                    ready_proved: true,
                    si_code,
                    status,
                });
            }
            deadline.require_live()?;
            return Ok(());
        }
        if let Some(code) = try_read_child_error(error_fd)? {
            return Err(LauncherError::ChildSetup(code));
        }
        if let Some((si_code, status)) = observe_pidfd_terminal(pidfd)? {
            return Err(LauncherError::ChildTerminated {
                ready_proved: false,
                si_code,
                status,
            });
        }
        match poll_until(deadline, &targets)? {
            WaitOutcome::DeadlineExpired => {
                return Err(LauncherError::Deadline(
                    "child did not prove final-filter readiness before the CLOCK_BOOTTIME deadline",
                ));
            }
            WaitOutcome::Progress(_) => {}
        }
    }
}

fn try_read_ready_proof(
    fd: RawFd,
    expected: [u8; READY_PROOF_BYTES],
) -> Result<bool, LauncherError> {
    let mut observed = [0_u8; READY_PROOF_BYTES];
    loop {
        let read = unsafe {
            libc::read(
                fd,
                observed.as_mut_ptr() as *mut libc::c_void,
                observed.len(),
            )
        };
        if read == observed.len() as isize {
            if observed != expected {
                return Err(LauncherError::Invalid(
                    "child final-filter readiness proof is not authentic",
                ));
            }
            return Ok(true);
        }
        if read == 0 {
            return Err(LauncherError::Invalid(
                "child readiness channel closed without a proof",
            ));
        }
        if read > 0 {
            return Err(LauncherError::Invalid(
                "child readiness proof was truncated",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(false),
            _ => return Err(error.into()),
        }
    }
}

fn try_read_child_error(fd: RawFd) -> Result<Option<u8>, LauncherError> {
    let mut code = 0_u8;
    loop {
        let read = unsafe {
            libc::read(
                fd,
                &mut code as *mut u8 as *mut libc::c_void,
                1,
            )
        };
        if read == 1 {
            return Ok(Some(code));
        }
        if read == 0 {
            return Err(LauncherError::Invalid(
                "child setup channel closed without readiness",
            ));
        }
        if read > 0 {
            return Err(LauncherError::Invalid(
                "child setup channel returned an invalid record",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(None),
            _ => return Err(error.into()),
        }
    }
}

fn observe_pidfd_terminal(
    pidfd: RawFd,
) -> Result<Option<(libc::c_int, libc::c_int)>, LauncherError> {
    let mut descriptor = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready == 0 {
            return Ok(None);
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error.into());
        }
        if descriptor.revents
            & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)
            == 0
        {
            return Err(LauncherError::Invalid(
                "pidfd poll returned an invalid terminal event",
            ));
        }
        let mut information: libc::siginfo_t = unsafe { zeroed() };
        if unsafe {
            libc::syscall(
                libc::SYS_waitid,
                P_PIDFD_IDTYPE,
                pidfd as libc::id_t,
                &mut information as *mut libc::siginfo_t,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                ptr::null_mut::<libc::rusage>(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if unsafe { information.si_pid() } <= 0 {
            return Err(LauncherError::Invalid(
                "readable pidfd lacks terminal child status",
            ));
        }
        return Ok(Some((
            information.si_code,
            unsafe { information.si_status() },
        )));
    }
}

fn create_nonblocking_pipe() -> Result<(OwnedFd, OwnedFd), LauncherError> {
    let mut pipe = [-1; 2];
    if unsafe {
        libc::pipe2(
            pipe.as_mut_ptr(),
            libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(pipe[0]),
            OwnedFd::from_raw_fd(pipe[1]),
        )
    })
}

fn create_absolute_boottime_timer(
    deadline: BoottimeDeadline,
) -> Result<OwnedFd, LauncherError> {
    deadline.require_live()?;
    let raw = unsafe {
        libc::timerfd_create(
            libc::CLOCK_BOOTTIME,
            libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let timer = unsafe { OwnedFd::from_raw_fd(raw) };
    let seconds = deadline.absolute_nanos() / 1_000_000_000;
    let nanoseconds = deadline.absolute_nanos() % 1_000_000_000;
    let specification = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: libc::time_t::try_from(seconds).map_err(|_| {
                LauncherError::Invalid(
                    "boottime timer deadline seconds overflow",
                )
            })?,
            tv_nsec: libc::c_long::try_from(nanoseconds).map_err(|_| {
                LauncherError::Invalid(
                    "boottime timer deadline nanoseconds overflow",
                )
            })?,
        },
    };
    loop {
        if unsafe {
            libc::timerfd_settime(
                timer.as_raw_fd(),
                libc::TFD_TIMER_ABSTIME,
                &specification,
                ptr::null_mut(),
            )
        } == 0
        {
            deadline.require_live()?;
            return Ok(timer);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error.into());
        }
    }
}

fn fill_random_exact(bytes: &mut [u8]) -> Result<(), LauncherError> {
    let mut completed = 0_usize;
    while completed < bytes.len() {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                bytes[completed..].as_mut_ptr(),
                bytes.len() - completed,
                GRND_NONBLOCK_FLAG,
            )
        };
        if read > 0 {
            completed = completed.checked_add(read as usize).ok_or(
                LauncherError::Invalid("getrandom length overflow"),
            )?;
            continue;
        }
        if read == 0 {
            return Err(LauncherError::Invalid(
                "getrandom returned no entropy",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error.into());
        }
    }
    Ok(())
}

fn write_one_nonblocking(
    fd: RawFd,
    value: u8,
) -> Result<(), io::Error> {
    loop {
        let written = unsafe {
            libc::write(
                fd,
                &value as *const u8 as *const libc::c_void,
                1,
            )
        };
        if written == 1 {
            return Ok(());
        }
        if written >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "release pipe write was truncated",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

fn map_deadline_operation_error(
    error: DeadlineOperationError<io::Error>,
) -> LauncherError {
    match error {
        DeadlineOperationError::Authority(error) => {
            LauncherError::Boottime(error)
        }
        DeadlineOperationError::Action(error) => LauncherError::Io(error),
    }
}

fn fail_launch(
    launched: LaunchedProcess,
    _error: LauncherError,
) -> Result<LaunchedProcess, LauncherError> {
    hard_unready_and_exit(
        &launched.hard_unready,
        launched.pid,
        launched.cgroup_identity_sha256,
        launched.watchdog_ownership.clone(),
    )
}

fn watchdog_register_until(
    endpoint: &WatchdogEndpoint,
    registration: &WatchdogRegistrationV3,
    retained_rights: &[RawFd; 6],
    worker_pidfd: RawFd,
    trust_provider: &mut dyn CurrentEndpointTrustProvider,
    authorization_deadline: BoottimeDeadline,
) -> Result<WatchdogOwnership, LauncherError> {
    endpoint.revalidate()?;
    registration.validate().map_err(|_| {
        LauncherError::Invalid("watchdog registration failed validation")
    })?;
    if registration.operation_deadline
            != ProtocolBoottimeDeadline::from_runtime(
                authorization_deadline,
            )
        || retained_rights.iter().any(|fd| *fd < 0)
    {
        return Err(LauncherError::Invalid(
            "watchdog registration deadline or retained descriptor set mismatch",
        ));
    }
    require_retained_watchdog_fds(registration, retained_rights)?;
    let request = canonical_protocol_frame(registration)?;
    send_seqpacket_until(
        endpoint.fd.as_raw_fd(),
        &request,
        retained_rights,
        Some(worker_pidfd),
        false,
        authorization_deadline,
    )?;
    let acknowledgement: SignedWatchdogOwnershipAckV3 =
        receive_canonical_protocol_frame_until(
            endpoint.fd.as_raw_fd(),
            Some(worker_pidfd),
            false,
            authorization_deadline,
        )?;
    let protocol_deadline =
        ProtocolBoottimeDeadline::from_runtime(authorization_deadline);
    let initially_verified =
        verify_watchdog_ownership_ack_with_current_provider(
            trust_provider,
            registration,
            &acknowledgement,
            &protocol_deadline,
        )
        .map_err(|_| {
            LauncherError::Invalid(
                "watchdog ownership acknowledgement failed current-key verification",
            )
        })?;
    let mut query_nonce = [0_u8; WATCHDOG_NONCE_BYTES];
    fill_random_exact(&mut query_nonce)?;
    let query = WatchdogOwnershipQueryV3::fresh(
        registration.registration_sha256.clone(),
        initially_verified
            .acknowledgement()
            .ownership
            .ownership_id_sha256
            .clone(),
        initially_verified
            .acknowledgement()
            .ownership
            .state_sha256
            .clone(),
        Sha256Digest::compute(&query_nonce),
        boottime_now_nanos()?,
        protocol_deadline.clone(),
    )
    .map_err(|_| {
        LauncherError::Invalid(
            "watchdog ownership query is invalid",
        )
    })?;
    let query_frame = canonical_protocol_frame(&query)?;
    send_seqpacket_until(
        endpoint.fd.as_raw_fd(),
        &query_frame,
        &[],
        Some(worker_pidfd),
        false,
        authorization_deadline,
    )?;
    let query_reply: WatchdogOwnershipQueryReplyV3 =
        receive_canonical_protocol_frame_until(
            endpoint.fd.as_raw_fd(),
            Some(worker_pidfd),
            false,
            authorization_deadline,
        )?;
    query_reply
        .validate_exact_fresh_binding(&query)
        .map_err(|_| {
            LauncherError::Invalid(
                "watchdog ownership query reply is not freshly bound",
            )
        })?;
    let confirmed =
        verify_watchdog_ownership_query_confirmation(
            trust_provider,
            registration,
            &initially_verified,
            &query,
            &query_reply,
            &protocol_deadline,
        )
        .map_err(|_| {
            LauncherError::Invalid(
                "watchdog ownership Query did not confirm durable state",
            )
        })?;
    require_retained_watchdog_fds(registration, retained_rights)?;
    authorization_deadline.require_live()?;
    Ok(WatchdogOwnership {
        registration_sha256:
            digest_raw_bytes(&registration.registration_sha256)?,
        ownership_receipt_sha256: digest_raw_bytes(
            &confirmed.acknowledgement().envelope_sha256,
        )?,
        ownership_state_sha256: digest_raw_bytes(
            &confirmed.acknowledgement().ownership.state_sha256,
        )?,
        verified_acknowledgement: confirmed,
    })
}

fn watchdog_reconfirm_until(
    endpoint: &WatchdogEndpoint,
    registration: &WatchdogRegistrationV3,
    ownership: &WatchdogOwnership,
    worker_pidfd: RawFd,
    trust_provider: &mut dyn CurrentEndpointTrustProvider,
    deadline: BoottimeDeadline,
) -> Result<(), LauncherError> {
    endpoint.revalidate()?;
    let mut query_nonce = [0_u8; WATCHDOG_NONCE_BYTES];
    fill_random_exact(&mut query_nonce)?;
    let query = WatchdogOwnershipQueryV3::fresh(
        registration.registration_sha256.clone(),
        ownership
            .verified_acknowledgement
            .acknowledgement()
            .ownership
            .ownership_id_sha256
            .clone(),
        ownership
            .verified_acknowledgement
            .acknowledgement()
            .ownership
            .state_sha256
            .clone(),
        Sha256Digest::compute(&query_nonce),
        boottime_now_nanos()?,
        ProtocolBoottimeDeadline::from_runtime(deadline),
    )
    .map_err(|_| {
        LauncherError::Invalid(
            "watchdog ownership reconfirmation query is invalid",
        )
    })?;
    send_seqpacket_until(
        endpoint.fd.as_raw_fd(),
        &canonical_protocol_frame(&query)?,
        &[],
        Some(worker_pidfd),
        false,
        deadline,
    )?;
    let reply: WatchdogOwnershipQueryReplyV3 =
        receive_canonical_protocol_frame_until(
            endpoint.fd.as_raw_fd(),
            Some(worker_pidfd),
            false,
            deadline,
        )?;
    reply
        .validate_exact_fresh_binding(&query)
        .map_err(|_| {
            LauncherError::Invalid(
                "watchdog ownership reconfirmation reply is not freshly bound",
            )
        })?;
    verify_watchdog_ownership_query_confirmation(
        trust_provider,
        registration,
        &ownership.verified_acknowledgement,
        &query,
        &reply,
        &ProtocolBoottimeDeadline::from_runtime(deadline),
    )
    .map_err(|_| {
        LauncherError::Invalid(
            "watchdog ownership authority did not reconfirm durable state before release",
        )
    })?;
    deadline.require_live()?;
    Ok(())
}

fn watchdog_disarm_until(
    endpoint: &WatchdogEndpoint,
    ownership: WatchdogOwnership,
    cleanup: CleanupReceipt,
    deadline: BoottimeDeadline,
) -> Result<(), LauncherError> {
    endpoint.revalidate()?;
    let cleanup_binding = hash_frames(&[
        b"serverware.policyCustody.watchdogCleanup/v1",
        &ownership.registration_sha256,
        &ownership.ownership_receipt_sha256,
        &ownership.ownership_state_sha256,
        &cleanup.receipt_sha256,
    ]);
    let mut request = [0_u8; WATCHDOG_CLEANUP_BYTES];
    request[0] = WATCHDOG_PROTOCOL_VERSION;
    request[1] = WATCHDOG_CLEANUP_KIND;
    request[8..40].copy_from_slice(&ownership.registration_sha256);
    request[40..72]
        .copy_from_slice(&ownership.ownership_receipt_sha256);
    request[72..104].copy_from_slice(&cleanup.receipt_sha256);
    request[104..136].copy_from_slice(
        &ownership.ownership_state_sha256,
    );
    request[136..168].copy_from_slice(&cleanup_binding);
    send_seqpacket_until(
        endpoint.fd.as_raw_fd(),
        &request,
        &[],
        None,
        true,
        deadline,
    )?;
    let acknowledgement =
        receive_seqpacket_until::<WATCHDOG_CLEANUP_ACK_BYTES>(
            endpoint.fd.as_raw_fd(),
            None,
            true,
            deadline,
        )?;
    if acknowledgement[0] != WATCHDOG_PROTOCOL_VERSION
        || acknowledgement[1] != WATCHDOG_CLEANUP_ACK_KIND
        || acknowledgement[2..8] != [0; 6]
        || acknowledgement[8..40] != ownership.registration_sha256
        || acknowledgement[40..72] != cleanup_binding
    {
        return Err(LauncherError::Invalid(
            "watchdog cleanup acknowledgement is not authentic",
        ));
    }
    deadline.require_live()?;
    Ok(())
}

#[repr(C, align(16))]
struct ScmRightsBuffer([u8; 128]);

fn send_seqpacket_until(
    socket_fd: RawFd,
    packet: &[u8],
    rights: &[RawFd],
    child_pidfd: Option<RawFd>,
    ready_proved: bool,
    deadline: BoottimeDeadline,
) -> Result<(), LauncherError> {
    if packet.is_empty() || rights.len() > 6 {
        return Err(LauncherError::Invalid(
            "watchdog packet or descriptor count is invalid",
        ));
    }
    loop {
        match send_seqpacket_once(socket_fd, packet, rights) {
            Ok(()) => {
                deadline.require_live()?;
                return Ok(());
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)
                ) => {}
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => {
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        let (socket_ready, child_terminal) = wait_socket_or_child(
            socket_fd,
            PollInterest::WRITABLE,
            child_pidfd,
            deadline,
        )?;
        if child_terminal && !socket_ready {
            return Err(terminal_child_error(
                child_pidfd.ok_or(LauncherError::Invalid(
                    "watchdog wait lost its child pidfd",
                ))?,
                ready_proved,
            ));
        }
    }
}

fn send_seqpacket_once(
    socket_fd: RawFd,
    packet: &[u8],
    rights: &[RawFd],
) -> Result<(), io::Error> {
    let mut io_vector = libc::iovec {
        iov_base: packet.as_ptr() as *mut libc::c_void,
        iov_len: packet.len(),
    };
    let mut control = ScmRightsBuffer([0; 128]);
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;
    if !rights.is_empty() {
        let invalid_length = || io::Error::new(io::ErrorKind::InvalidInput,
            "SCM_RIGHTS length exceeds its native ABI");
        let rights_bytes = rights.len().checked_mul(size_of::<RawFd>())
            .ok_or_else(invalid_length)?;
        let rights_bytes_u32 = libc::c_uint::try_from(rights_bytes)
            .map_err(|_| invalid_length())?;
        let control_length =
            unsafe { libc::CMSG_SPACE(rights_bytes_u32) }
                as usize;
        if control_length > control.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCM_RIGHTS control message exceeds its fixed buffer",
            ));
        }
        message.msg_control =
            control.0.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control_length.try_into()
            .map_err(|_| invalid_length())?;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCM_RIGHTS header is unavailable",
            ));
        }
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN(rights_bytes_u32).try_into()
                    .map_err(|_| invalid_length())?;
            ptr::copy_nonoverlapping(
                rights.as_ptr() as *const u8,
                libc::CMSG_DATA(header),
                rights_bytes,
            );
        }
    }
    let written = unsafe {
        libc::sendmsg(
            socket_fd,
            &message,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if written == packet.len() as isize {
        return Ok(());
    }
    if written >= 0 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "watchdog seqpacket send was truncated",
        ));
    }
    Err(io::Error::last_os_error())
}

fn canonical_protocol_frame<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, LauncherError> {
    let frame = canonical_json_bytes(value).map_err(|_| {
        LauncherError::Invalid(
            "watchdog protocol frame is not canonical",
        )
    })?;
    if frame.is_empty()
        || frame.len() > MAX_WATCHDOG_PROTOCOL_FRAME_BYTES
    {
        return Err(LauncherError::Invalid(
            "watchdog protocol frame exceeds its fixed bound",
        ));
    }
    Ok(frame)
}

fn receive_canonical_protocol_frame_until<T: DeserializeOwned + Serialize>(
    socket_fd: RawFd,
    child_pidfd: Option<RawFd>,
    ready_proved: bool,
    deadline: BoottimeDeadline,
) -> Result<T, LauncherError> {
    let frame = receive_seqpacket_frame_until(
        socket_fd,
        child_pidfd,
        ready_proved,
        deadline,
    )?;
    let value: T = serde_json::from_slice(&frame).map_err(|_| {
        LauncherError::Invalid(
            "watchdog protocol frame is not valid typed JSON",
        )
    })?;
    if canonical_protocol_frame(&value)? != frame {
        return Err(LauncherError::Invalid(
            "watchdog protocol frame has a noncanonical representation",
        ));
    }
    deadline.require_live()?;
    Ok(value)
}

fn receive_seqpacket_frame_until(
    socket_fd: RawFd,
    child_pidfd: Option<RawFd>,
    ready_proved: bool,
    deadline: BoottimeDeadline,
) -> Result<Vec<u8>, LauncherError> {
    loop {
        let mut packet =
            vec![0_u8; MAX_WATCHDOG_PROTOCOL_FRAME_BYTES];
        let received = unsafe {
            libc::recv(
                socket_fd,
                packet.as_mut_ptr() as *mut libc::c_void,
                packet.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if received > 0
            && received as usize <= packet.len()
        {
            packet.truncate(received as usize);
            deadline.require_live()?;
            return Ok(packet);
        }
        if received == 0 {
            return Err(LauncherError::Invalid(
                "watchdog endpoint closed before acknowledgement",
            ));
        }
        if received > packet.len() as isize {
            return Err(LauncherError::Invalid(
                "watchdog protocol frame exceeds its fixed bound",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if !matches!(
            error.raw_os_error(),
            Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)
        ) {
            return Err(error.into());
        }
        let (socket_ready, child_terminal) = wait_socket_or_child(
            socket_fd,
            PollInterest::READABLE,
            child_pidfd,
            deadline,
        )?;
        if child_terminal && !socket_ready {
            return Err(terminal_child_error(
                child_pidfd.ok_or(LauncherError::Invalid(
                    "watchdog wait lost its child pidfd",
                ))?,
                ready_proved,
            ));
        }
    }
}

fn receive_seqpacket_until<const N: usize>(
    socket_fd: RawFd,
    child_pidfd: Option<RawFd>,
    ready_proved: bool,
    deadline: BoottimeDeadline,
) -> Result<[u8; N], LauncherError> {
    loop {
        let mut packet = [0_u8; N];
        let received = unsafe {
            libc::recv(
                socket_fd,
                packet.as_mut_ptr() as *mut libc::c_void,
                packet.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if received == N as isize {
            deadline.require_live()?;
            return Ok(packet);
        }
        if received == 0 {
            return Err(LauncherError::Invalid(
                "watchdog endpoint closed before acknowledgement",
            ));
        }
        if received > 0 {
            return Err(LauncherError::Invalid(
                "watchdog acknowledgement has the wrong length",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if !matches!(
            error.raw_os_error(),
            Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)
        ) {
            return Err(error.into());
        }
        let (socket_ready, child_terminal) = wait_socket_or_child(
            socket_fd,
            PollInterest::READABLE,
            child_pidfd,
            deadline,
        )?;
        if child_terminal && !socket_ready {
            return Err(terminal_child_error(
                child_pidfd.ok_or(LauncherError::Invalid(
                    "watchdog wait lost its child pidfd",
                ))?,
                ready_proved,
            ));
        }
    }
}

fn wait_socket_or_child(
    socket_fd: RawFd,
    interest: PollInterest,
    child_pidfd: Option<RawFd>,
    deadline: BoottimeDeadline,
) -> Result<(bool, bool), LauncherError> {
    let socket = unsafe { BorrowedFd::borrow_raw(socket_fd) };
    if let Some(pidfd) = child_pidfd {
        let child = unsafe { BorrowedFd::borrow_raw(pidfd) };
        match poll_until(
            deadline,
            &[
                PollTarget::socket(socket, interest),
                PollTarget::pidfd(child),
            ],
        )? {
            WaitOutcome::Progress(progress) => Ok((
                progress.iter().any(|event| event.index() == 0),
                progress.iter().any(|event| event.index() == 1),
            )),
            WaitOutcome::DeadlineExpired => Err(LauncherError::Deadline(
                "watchdog handoff exceeded its CLOCK_BOOTTIME deadline",
            )),
        }
    } else {
        match poll_until(
            deadline,
            &[PollTarget::socket(socket, interest)],
        )? {
            WaitOutcome::Progress(_) => Ok((true, false)),
            WaitOutcome::DeadlineExpired => Err(LauncherError::Deadline(
                "watchdog cleanup exceeded its CLOCK_BOOTTIME deadline",
            )),
        }
    }
}

fn terminal_child_error(
    pidfd: RawFd,
    ready_proved: bool,
) -> LauncherError {
    match observe_pidfd_terminal(pidfd) {
        Ok(Some((si_code, status))) => LauncherError::ChildTerminated {
            ready_proved,
            si_code,
            status,
        },
        Ok(None) => LauncherError::Invalid(
            "pidfd readiness disappeared before terminal observation",
        ),
        Err(error) => error,
    }
}

fn wait_pidfd_until(
    pidfd: RawFd,
    deadline: BoottimeDeadline,
) -> Result<(), LauncherError> {
    let descriptor = unsafe { BorrowedFd::borrow_raw(pidfd) };
    match poll_until(deadline, &[PollTarget::pidfd(descriptor)])? {
        WaitOutcome::Progress(_) => {
            deadline.require_live()?;
            Ok(())
        }
        WaitOutcome::DeadlineExpired => Err(LauncherError::Deadline(
            "pidfd wait exceeded its CLOCK_BOOTTIME deadline",
        )),
    }
}

fn reap_pidfd_exact(
    pid: libc::pid_t,
    pidfd: RawFd,
) -> Result<ReapReceipt, LauncherError> {
    let mut information: libc::siginfo_t = unsafe { zeroed() };
    if unsafe {
        libc::syscall(
            libc::SYS_waitid,
            P_PIDFD_IDTYPE,
            pidfd as libc::id_t,
            &mut information as *mut libc::siginfo_t,
            libc::WEXITED | libc::WNOHANG,
            ptr::null_mut::<libc::rusage>(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let observed_pid = unsafe { information.si_pid() };
    if observed_pid != pid {
        return Err(LauncherError::Invalid(
            "pidfd became readable without an exact reapable child",
        ));
    }
    Ok(ReapReceipt {
        pid,
        si_code: information.si_code,
        status: unsafe { information.si_status() },
    })
}

fn cgroup_control_error(error: cgroup_control_v1::Error) -> LauncherError {
    match error {
        cgroup_control_v1::Error::Io(error) => LauncherError::Io(error),
        cgroup_control_v1::Error::Invalid(message) => LauncherError::Invalid(message),
    }
}

fn verify_cgroup2_descriptor(fd: RawFd) -> Result<(), LauncherError> {
    cgroup_control_v1::verify_directory(unsafe { BorrowedFd::borrow_raw(fd) })
        .map(|_| ()).map_err(cgroup_control_error)
}

fn cgroup_identity_sha256(
    fd: RawFd,
) -> Result<[u8; 32], LauncherError> {
    verify_cgroup2_descriptor(fd)?;
    let identity = directory_identity(fd)?;
    Ok(hash_frames(&[
        b"serverware.policyCustody.cgroup/v1",
        &identity.device.to_be_bytes(),
        &identity.inode.to_be_bytes(),
        &identity.mount_id.to_be_bytes(),
        &identity.mode.to_be_bytes(),
        &identity.uid.to_be_bytes(),
        &identity.gid.to_be_bytes(),
    ]))
}

fn prepare_cgroup_kill(fd: RawFd) -> Result<PreparedKillV1, LauncherError> {
    PreparedKillV1::open(unsafe { BorrowedFd::borrow_raw(fd) })
        .map_err(cgroup_control_error)
}

fn verify_cgroup_kill_available(fd: RawFd) -> Result<(), LauncherError> {
    prepare_cgroup_kill(fd).map(|_| ())
}

fn cgroup_populated_now(fd: RawFd) -> Result<bool, LauncherError> {
    EventsV1::open(unsafe { BorrowedFd::borrow_raw(fd) })
        .map_err(cgroup_control_error)?.populated().map_err(cgroup_control_error)
}

fn wait_cgroup_empty_until(
    cgroup_fd: RawFd,
    deadline: BoottimeDeadline,
) -> Result<(), LauncherError> {
    let mut events = EventsV1::open(unsafe { BorrowedFd::borrow_raw(cgroup_fd) })
        .map_err(cgroup_control_error)?;
    loop {
        if !events.populated().map_err(cgroup_control_error)? {
            deadline.require_live()?;
            return Ok(());
        }
        match poll_until(
            deadline,
            &[PollTarget::socket(
                events.poll_fd(),
                PollInterest::PRIORITY,
            )],
        )? {
            WaitOutcome::Progress(_) => {}
            WaitOutcome::DeadlineExpired => {
                return Err(LauncherError::Deadline(
                    "cgroup remained populated beyond its cleanup deadline",
                ));
            }
        }
    }
}

fn openat_control_file(
    parent_fd: RawFd,
    nul_terminated_name: &[u8],
    flags: libc::c_int,
) -> Result<OwnedFd, LauncherError> {
    if nul_terminated_name.last() != Some(&0) {
        return Err(LauncherError::Invalid(
            "control filename is not NUL terminated",
        ));
    }
    let raw = unsafe {
        libc::openat(
            parent_fd,
            nul_terminated_name.as_ptr() as *const libc::c_char,
            flags,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn verify_parent_pidfd(
    pidfd: RawFd,
    expected_pid: libc::pid_t,
    expected_inode: libc::ino_t,
) -> Result<(), LauncherError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    if expected_pid <= 1
        || expected_inode == 0
        || unsafe { libc::getpid() } != expected_pid
        || pidfd_process_id(pidfd)? != expected_pid
        || !pidfd_is_nonterminal(pidfd)?
        || unsafe { libc::fstat(pidfd, &mut stat) } != 0
        || stat.st_ino != expected_inode
    {
        return Err(LauncherError::Invalid(
            "supervisor pidfd identity is not live and exact",
        ));
    }
    Ok(())
}

fn verify_process_pidfd_identity(
    pidfd: RawFd,
    expected: &WatchdogProcessIdentityV3,
) -> Result<(), LauncherError> {
    expected.validate().map_err(|_| {
        LauncherError::Invalid("watchdog process identity is invalid")
    })?;
    let identity = descriptor_identity(pidfd)?;
    if pidfd_process_id(pidfd)? != expected.pid
        || !pidfd_is_nonterminal(pidfd)?
        || identity.inode as u64 != expected.pidfd_inode
        || descriptor_identity_protocol_sha256(identity)?
            != expected.pidfd_stat_sha256
    {
        return Err(LauncherError::Invalid(
            "retained pidfd does not match the exact watchdog process identity",
        ));
    }
    Ok(())
}

fn observe_worker_watchdog_identity(
    pid: libc::pid_t,
    pidfd: RawFd,
    executable_sha256: [u8; 32],
) -> Result<WatchdogProcessIdentityV3, LauncherError> {
    if pidfd_process_id(pidfd)? != pid || !pidfd_is_nonterminal(pidfd)? {
        return Err(LauncherError::Invalid(
            "worker pidfd is not live and exact",
        ));
    }
    let identity = descriptor_identity(pidfd)?;
    let start_time_ticks = proc_start_time_ticks(pid)?;
    let observed = WatchdogProcessIdentityV3 {
        pid,
        start_time_ticks,
        pidfd_inode: identity.inode as u64,
        pidfd_stat_sha256:
            descriptor_identity_protocol_sha256(identity)?,
        executable_sha256: digest_from_raw(executable_sha256)?,
    };
    verify_process_pidfd_identity(pidfd, &observed)?;
    if proc_start_time_ticks(pid)? != start_time_ticks {
        return Err(LauncherError::Invalid(
            "worker process identity changed during observation",
        ));
    }
    Ok(observed)
}

fn proc_start_time_ticks(
    pid: libc::pid_t,
) -> Result<u64, LauncherError> {
    let path = CString::new(format!("/proc/{pid}/stat")).map_err(|_| {
        LauncherError::Invalid("worker stat path contains NUL")
    })?;
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut bytes = [0_u8; 4096];
    let read = unsafe {
        libc::read(
            descriptor.as_raw_fd(),
            bytes.as_mut_ptr() as *mut libc::c_void,
            bytes.len(),
        )
    };
    if read <= 0 || read as usize == bytes.len() {
        return Err(LauncherError::Invalid(
            "worker stat is empty or exceeds its fixed bound",
        ));
    }
    let text = std::str::from_utf8(&bytes[..read as usize]).map_err(
        |_| LauncherError::Invalid("worker stat is not UTF-8"),
    )?;
    let command_end = text.rfind(')').ok_or(LauncherError::Invalid(
        "worker stat command field is malformed",
    ))?;
    let fields = text[command_end + 1..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if fields.len() <= 19 {
        return Err(LauncherError::Invalid(
            "worker stat lacks start-time field",
        ));
    }
    fields[19].parse::<u64>().map_err(|_| {
        LauncherError::Invalid("worker stat start time is invalid")
    })
}

fn descriptor_identity_protocol_sha256(
    identity: DescriptorIdentity,
) -> Result<Sha256Digest, LauncherError> {
    digest_from_raw(hash_frames(&[
        &identity.device.to_be_bytes(),
        &identity.inode.to_be_bytes(),
        &identity.mode.to_be_bytes(),
        &identity.uid.to_be_bytes(),
        &identity.gid.to_be_bytes(),
        &identity.length.to_be_bytes(),
        &identity.modified_seconds.to_be_bytes(),
        &identity.modified_nanoseconds.to_be_bytes(),
        &identity.changed_seconds.to_be_bytes(),
        &identity.changed_nanoseconds.to_be_bytes(),
        &identity.mount_id.to_be_bytes(),
    ]))
}

fn retained_watchdog_fd_identity(
    role: WatchdogRegistrationFdRole,
    fd: RawFd,
) -> Result<WatchdogRetainedFdIdentityV3, LauncherError> {
    let identity = descriptor_identity(fd)?;
    let retained = WatchdogRetainedFdIdentityV3 {
        role,
        device: identity.device as u64,
        inode: identity.inode as u64,
        mode: identity.mode as u32,
        uid: identity.uid,
        gid: identity.gid,
        mount_id: identity.mount_id,
        retained_fd_stat_sha256:
            descriptor_identity_protocol_sha256(identity)?,
    };
    retained.validate().map_err(|_| {
        LauncherError::Invalid(
            "watchdog retained descriptor identity is invalid",
        )
    })?;
    Ok(retained)
}

fn require_retained_watchdog_fds(
    registration: &WatchdogRegistrationV3,
    retained_rights: &[RawFd; 6],
) -> Result<(), LauncherError> {
    if registration.retained_fds.len() != retained_rights.len() {
        return Err(LauncherError::Invalid(
            "watchdog retained descriptor count changed",
        ));
    }
    for (expected, fd) in registration
        .retained_fds
        .iter()
        .zip(retained_rights)
    {
        if retained_watchdog_fd_identity(expected.role, *fd)?
            != *expected
        {
            return Err(LauncherError::Invalid(
                "watchdog retained descriptor identity changed",
            ));
        }
    }
    require_distinct_open_file_descriptions(retained_rights)?;
    Ok(())
}

fn require_distinct_open_file_descriptions(
    descriptors: &[RawFd; 6],
) -> Result<(), LauncherError> {
    const KCMP_FILE: libc::c_int = 0;
    let process = unsafe { libc::getpid() };
    for left in 0..descriptors.len() {
        for right in (left + 1)..descriptors.len() {
            let compared = unsafe {
                libc::syscall(
                    libc::SYS_kcmp,
                    process,
                    process,
                    KCMP_FILE,
                    descriptors[left],
                    descriptors[right],
                )
            };
            if compared == 0 {
                return Err(LauncherError::Invalid(
                    "watchdog retained descriptor roles alias one open file description",
                ));
            }
            if compared < 0 {
                return Err(LauncherError::Io(
                    io::Error::last_os_error(),
                ));
            }
        }
    }
    Ok(())
}

fn digest_from_raw(
    raw: [u8; 32],
) -> Result<Sha256Digest, LauncherError> {
    Sha256Digest::parse(format!("sha256:{}", hex::encode(raw))).map_err(
        |_| LauncherError::Invalid("SHA-256 digest encoding failed"),
    )
}

fn digest_raw_bytes(
    digest: &Sha256Digest,
) -> Result<[u8; 32], LauncherError> {
    let encoded = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(LauncherError::Invalid(
            "SHA-256 digest prefix is invalid",
        ))?;
    let decoded = hex::decode(encoded).map_err(|_| {
        LauncherError::Invalid("SHA-256 digest encoding is invalid")
    })?;
    decoded.try_into().map_err(|_| {
        LauncherError::Invalid("SHA-256 digest length is invalid")
    })
}

fn digest_is_zero(digest: &Sha256Digest) -> bool {
    digest.as_str()
        == "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn pidfd_is_nonterminal(pidfd: RawFd) -> Result<bool, LauncherError> {
    let mut descriptor = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready == 0 {
            return Ok(descriptor.revents == 0);
        }
        if ready > 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error.into());
        }
    }
}

fn pidfd_process_id(pidfd: RawFd) -> Result<libc::pid_t, LauncherError> {
    if pidfd < 0 {
        return Err(LauncherError::Invalid(
            "pidfd descriptor is negative",
        ));
    }
    let path = CString::new(format!("/proc/self/fdinfo/{pidfd}"))
        .map_err(|_| LauncherError::Invalid(
            "pidfd fdinfo path contains NUL",
        ))?;
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut bytes = [0_u8; MAX_PIDFD_INFO_BYTES];
    let mut length = 0_usize;
    loop {
        if length == bytes.len() {
            return Err(LauncherError::Invalid(
                "pidfd fdinfo exceeds its fixed bound",
            ));
        }
        let read = unsafe {
            libc::read(
                descriptor.as_raw_fd(),
                bytes[length..].as_mut_ptr() as *mut libc::c_void,
                bytes.len() - length,
            )
        };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error.into());
        }
        if read == 0 {
            break;
        }
        length = length
            .checked_add(usize::try_from(read).map_err(|_| {
                LauncherError::Invalid(
                    "pidfd fdinfo read length overflow",
                )
            })?)
            .ok_or(LauncherError::Invalid(
                "pidfd fdinfo length overflow",
            ))?;
    }
    let text = std::str::from_utf8(&bytes[..length]).map_err(|_| {
        LauncherError::Invalid("pidfd fdinfo is not UTF-8")
    })?;
    let mut observed = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Pid:") {
            if observed.is_some() {
                return Err(LauncherError::Invalid(
                    "pidfd fdinfo contains duplicate Pid fields",
                ));
            }
            observed = Some(
                value
                    .trim()
                    .parse::<libc::pid_t>()
                    .map_err(|_| LauncherError::Invalid(
                        "pidfd fdinfo Pid is invalid",
                    ))?,
            );
        }
    }
    observed
        .filter(|pid| *pid > 1)
        .ok_or(LauncherError::Invalid(
            "pidfd does not identify a live parent process",
        ))
}

fn verify_standard_io(fd: RawFd, input: bool) -> Result<(), LauncherError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFCHR => {
            if stat.st_rdev != unsafe { libc::makedev(1, 3) } {
                return Err(LauncherError::Invalid(
                    "standard I/O character descriptor is not /dev/null",
                ));
            }
        }
        libc::S_IFIFO => {
            verify_pipe_access(
                fd,
                &stat,
                if input { libc::O_RDONLY } else { libc::O_WRONLY },
            )?;
        }
        libc::S_IFSOCK => verify_unix_socket(fd, &stat)?,
        _ => {
            return Err(LauncherError::Invalid(
                "standard I/O must be /dev/null, a directional pipe, or a Unix socket",
            ));
        }
    }
    Ok(())
}

fn verify_pipe_access(
    fd: RawFd,
    stat: &libc::stat,
    required_access: libc::c_int,
) -> Result<(), LauncherError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if stat.st_mode & libc::S_IFMT != libc::S_IFIFO
        || flags < 0
        || flags & libc::O_ACCMODE != required_access
    {
        return Err(LauncherError::Invalid(
            "inherited pipe direction is not exact",
        ));
    }
    Ok(())
}

fn verify_unix_socket(
    fd: RawFd,
    stat: &libc::stat,
) -> Result<(), LauncherError> {
    let mut domain: libc::c_int = 0;
    let mut socket_type: libc::c_int = 0;
    let mut domain_length =
        size_of::<libc::c_int>() as libc::socklen_t;
    let mut type_length =
        size_of::<libc::c_int>() as libc::socklen_t;
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                &mut domain as *mut libc::c_int as *mut libc::c_void,
                &mut domain_length,
            )
        } != 0
        || unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut socket_type as *mut libc::c_int
                    as *mut libc::c_void,
                &mut type_length,
            )
        } != 0
        || domain != libc::AF_UNIX
        || !matches!(
            socket_type,
            libc::SOCK_STREAM | libc::SOCK_SEQPACKET | libc::SOCK_DGRAM
        )
    {
        return Err(LauncherError::Invalid(
            "inherited socket is not a supported Unix socket",
        ));
    }
    Ok(())
}

fn verify_watchdog_endpoint(
    fd: RawFd,
    expected_peer: WatchdogPeerIdentity,
) -> Result<DescriptorIdentity, LauncherError> {
    if expected_peer.pid <= 1 {
        return Err(LauncherError::Invalid(
            "watchdog peer PID must identify a supervisor process",
        ));
    }
    let identity = descriptor_identity(fd)?;
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut domain = 0;
    let mut socket_type = 0;
    let mut peer: libc::ucred = unsafe { zeroed() };
    let mut integer_length = size_of::<libc::c_int>() as libc::socklen_t;
    let mut peer_length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                &mut domain as *mut libc::c_int as *mut libc::c_void,
                &mut integer_length,
            )
        } != 0
        || domain != libc::AF_UNIX
    {
        return Err(LauncherError::Invalid(
            "watchdog endpoint is not a Unix socket",
        ));
    }
    integer_length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut socket_type as *mut libc::c_int as *mut libc::c_void,
            &mut integer_length,
        )
    } != 0
        || socket_type != libc::SOCK_SEQPACKET
        || unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut peer as *mut libc::ucred as *mut libc::c_void,
                &mut peer_length,
            )
        } != 0
        || peer_length != size_of::<libc::ucred>() as libc::socklen_t
        || peer.pid != expected_peer.pid
        || peer.uid != expected_peer.uid
        || peer.gid != expected_peer.gid
    {
        return Err(LauncherError::Invalid(
            "watchdog endpoint type or peer credentials mismatch",
        ));
    }
    set_nonblocking(fd)?;
    let mut pending = 0_u8;
    let read = unsafe {
        libc::recv(
            fd,
            &mut pending as *mut u8 as *mut libc::c_void,
            1,
            libc::MSG_DONTWAIT | libc::MSG_PEEK | libc::MSG_TRUNC,
        )
    };
    if read >= 0 {
        return Err(LauncherError::Invalid(
            "watchdog endpoint is closed or contains stale protocol data",
        ));
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)
    ) {
        return Err(error.into());
    }
    Ok(identity)
}

fn set_nonblocking(fd: RawFd) -> Result<(), LauncherError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0
        || unsafe {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK)
        } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn verify_running_static_stub(
    executable: &VerifiedExecutable,
    entry: StaticEntryPoint,
) -> Result<(), LauncherError> {
    verify_single_threaded_launcher()?;
    let raw = unsafe {
        libc::open(
            b"/proc/self/exe\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let running = unsafe { OwnedFd::from_raw_fd(raw) };
    let identity =
        immutable_regular_file_identity(running.as_raw_fd())?;
    let digest = sha256_descriptor(running.as_raw_fd())?;
    if digest != executable.validation.file_sha256 {
        return Err(LauncherError::Invalid(
            "running static entry image digest differs from the verified rootfs image",
        ));
    }
    let validation = validate_static_elf(
        running.as_raw_fd(),
        identity.length,
        executable.validation.architecture,
        if executable.validation.static_pie {
            StaticPiePolicy::AllowStaticPie
        } else {
            StaticPiePolicy::Forbid
        },
        digest,
    )?;
    if validation != executable.validation
        || !entry_is_in_running_executable(
            entry as usize,
            running.as_raw_fd(),
            identity,
        )?
    {
        return Err(LauncherError::Invalid(
            "trusted entry symbol is not in the verified running static image",
        ));
    }
    Ok(())
}

fn verify_single_threaded_launcher() -> Result<(), LauncherError> {
    let raw = unsafe {
        libc::open(
            b"/proc/self/task\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let tasks = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut buffer = [0_u8; 4096];
    let mut count = 0_u8;
    loop {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                tasks.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            ) as isize
        };
        if read < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if read == 0 {
            break;
        }
        let mut offset = 0_usize;
        let read = read as usize;
        while offset < read {
            if read - offset < 20 {
                return Err(LauncherError::Invalid(
                    "task directory record is truncated",
                ));
            }
            let record_length = u16::from_ne_bytes([
                buffer[offset + 16],
                buffer[offset + 17],
            ]) as usize;
            if record_length < 20 || offset + record_length > read {
                return Err(LauncherError::Invalid(
                    "task directory record length is invalid",
                ));
            }
            let name_region = &buffer[offset + 19..offset + record_length];
            let name_end =
                name_region.iter().position(|byte| *byte == 0).ok_or(
                    LauncherError::Invalid(
                        "task directory record lacks a terminator",
                    ),
                )?;
            let name = &name_region[..name_end];
            if name != b"." && name != b".." {
                if name.is_empty()
                    || name.iter().any(|byte| !byte.is_ascii_digit())
                {
                    return Err(LauncherError::Invalid(
                        "task directory contains a non-PID entry",
                    ));
                }
                count = count.checked_add(1).ok_or(
                    LauncherError::Invalid(
                        "task count exceeds its fixed bound",
                    ),
                )?;
                if count > 1 {
                    return Err(LauncherError::Invalid(
                        "retained-FD clone3 launcher must be single-threaded",
                    ));
                }
            }
            offset += record_length;
        }
    }
    if count != 1 {
        return Err(LauncherError::Invalid(
            "launcher task identity is not exact",
        ));
    }
    Ok(())
}

fn entry_is_in_running_executable(
    address: usize,
    executable_fd: RawFd,
    executable_identity: DescriptorIdentity,
) -> Result<bool, LauncherError> {
    let raw = unsafe {
        libc::open(
            b"/proc/self/maps\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let maps = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut bytes = vec![0_u8; MAX_PROC_MAPS_BYTES];
    let mut length = 0_usize;
    loop {
        if length == bytes.len() {
            return Err(LauncherError::Invalid(
                "/proc/self/maps exceeds its fixed bound",
            ));
        }
        let read = unsafe {
            libc::read(
                maps.as_raw_fd(),
                bytes[length..].as_mut_ptr() as *mut libc::c_void,
                bytes.len() - length,
            )
        };
        if read > 0 {
            length = length.checked_add(read as usize).ok_or(
                LauncherError::Invalid(
                    "/proc/self/maps length overflow",
                ),
            )?;
            continue;
        }
        if read == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error.into());
        }
    }
    let text = std::str::from_utf8(&bytes[..length]).map_err(|_| {
        LauncherError::Invalid("/proc/self/maps is not valid UTF-8")
    })?;
    let mut entry_verified = false;
    let mut executable_mapping_count = 0_usize;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let range = fields.next().ok_or(LauncherError::Invalid(
            "/proc/self/maps record lacks an address range",
        ))?;
        let permissions = fields.next().ok_or(LauncherError::Invalid(
            "/proc/self/maps record lacks permissions",
        ))?;
        let offset = fields.next().ok_or(LauncherError::Invalid(
            "/proc/self/maps record lacks an offset",
        ))?;
        let device = fields.next().ok_or(LauncherError::Invalid(
            "/proc/self/maps record lacks a device",
        ))?;
        let inode = fields.next().ok_or(LauncherError::Invalid(
            "/proc/self/maps record lacks an inode",
        ))?;
        let (start, end) = range.split_once('-').ok_or(
            LauncherError::Invalid(
                "/proc/self/maps address range is invalid",
            ),
        )?;
        let start = usize::from_str_radix(start, 16).map_err(|_| {
            LauncherError::Invalid(
                "/proc/self/maps range start is invalid",
            )
        })?;
        let end = usize::from_str_radix(end, 16).map_err(|_| {
            LauncherError::Invalid(
                "/proc/self/maps range end is invalid",
            )
        })?;
        let permission_bytes = permissions.as_bytes();
        if permission_bytes.len() < 4
            || (permission_bytes.get(1) == Some(&b'w')
                && permission_bytes.get(2) == Some(&b'x'))
        {
            return Err(LauncherError::Invalid(
                "running process contains an invalid or writable-executable mapping",
            ));
        }
        if permission_bytes.get(2) != Some(&b'x') {
            continue;
        }
        executable_mapping_count =
            executable_mapping_count.checked_add(1).ok_or(
                LauncherError::Invalid(
                    "executable mapping count overflow",
                ),
            )?;
        let offset = u64::from_str_radix(offset, 16).map_err(|_| {
            LauncherError::Invalid(
                "/proc/self/maps file offset is invalid",
            )
        })?;
        let (major, minor) = device.split_once(':').ok_or(
            LauncherError::Invalid(
                "/proc/self/maps device is invalid",
            ),
        )?;
        let major = u64::from_str_radix(major, 16).map_err(|_| {
            LauncherError::Invalid(
                "/proc/self/maps device major is invalid",
            )
        })?;
        let minor = u64::from_str_radix(minor, 16).map_err(|_| {
            LauncherError::Invalid(
                "/proc/self/maps device minor is invalid",
            )
        })?;
        let inode = inode.parse::<u64>().map_err(|_| {
            LauncherError::Invalid(
                "/proc/self/maps inode is invalid",
            )
        })?;
        let same_file = inode == executable_identity.inode as u64
            && major <= libc::c_uint::MAX as u64
            && minor <= libc::c_uint::MAX as u64
            && unsafe {
                libc::makedev(
                    major as libc::c_uint,
                    minor as libc::c_uint,
                )
            } == executable_identity.device;
        let mapping_length = u64::try_from(
            end.checked_sub(start).ok_or(LauncherError::Invalid(
                "/proc/self/maps executable range underflow",
            ))?,
        )
        .map_err(|_| {
            LauncherError::Invalid(
                "/proc/self/maps executable range is too large",
            )
        })?;
        if !same_file
            || !executable_mapping_matches_pt_load(
                executable_fd,
                executable_identity.length,
                offset,
                mapping_length,
            )?
        {
            return Err(LauncherError::Invalid(
                "current executable mapping is not backed by an executable PT_LOAD in the verified image",
            ));
        }
        if address >= start && address < end {
            entry_verified = true;
        }
    }
    Ok(entry_verified && executable_mapping_count > 0)
}

fn executable_mapping_matches_pt_load(
    executable_fd: RawFd,
    file_length: u64,
    mapping_offset: u64,
    mapping_length: u64,
) -> Result<bool, LauncherError> {
    let mut header = [0_u8; ELF_HEADER_BYTES];
    pread_exact(
        executable_fd,
        header.as_mut_ptr(),
        header.len(),
        0,
    )?;
    if header[..4] != [0x7f, b'E', b'L', b'F']
        || header[4] != 2
        || header[5] != 1
    {
        return Err(LauncherError::Invalid(
            "running executable ELF header is invalid",
        ));
    }
    let program_header_offset = little_u64(&header[32..40]);
    let program_header_size = little_u16(&header[54..56]);
    let program_header_count = little_u16(&header[56..58]);
    if program_header_size as usize != ELF64_PROGRAM_HEADER_BYTES
        || program_header_count == 0
        || usize::from(program_header_count)
            > MAX_ELF_PROGRAM_HEADERS
    {
        return Err(LauncherError::Invalid(
            "running executable program-header table is invalid",
        ));
    }
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(LauncherError::Invalid(
            "system page size is unavailable",
        ));
    }
    let page_mask = u64::try_from(page_size - 1).map_err(|_| {
        LauncherError::Invalid("system page size is invalid")
    })?;
    let mapping_end = mapping_offset
        .checked_add(mapping_length)
        .ok_or(LauncherError::Invalid(
            "executable mapping file range overflow",
        ))?;
    for index in 0..usize::from(program_header_count) {
        let offset = program_header_offset
            .checked_add(
                u64::try_from(index * ELF64_PROGRAM_HEADER_BYTES)
                    .map_err(|_| {
                        LauncherError::Invalid(
                            "program-header offset overflow",
                        )
                    })?,
            )
            .ok_or(LauncherError::Invalid(
                "program-header offset overflow",
            ))?;
        let mut program = [0_u8; ELF64_PROGRAM_HEADER_BYTES];
        pread_exact(
            executable_fd,
            program.as_mut_ptr(),
            program.len(),
            offset,
        )?;
        if little_u32(&program[0..4]) != PT_LOAD
            || little_u32(&program[4..8]) & PF_X == 0
        {
            continue;
        }
        let file_offset = little_u64(&program[8..16]);
        let file_size = little_u64(&program[32..40]);
        let memory_size = little_u64(&program[40..48]);
        let segment_start = file_offset & !page_mask;
        let segment_span = file_size.max(memory_size);
        let segment_end = file_offset
            .checked_add(segment_span)
            .and_then(|end| end.checked_add(page_mask))
            .map(|end| end & !page_mask)
            .ok_or(LauncherError::Invalid(
                "PT_LOAD file range overflow",
            ))?;
        if segment_end > file_length.checked_add(page_mask).ok_or(
            LauncherError::Invalid("ELF file length overflow"),
        )? {
            return Err(LauncherError::Invalid(
                "PT_LOAD executable range exceeds the verified file",
            ));
        }
        if mapping_offset >= segment_start
            && mapping_end <= segment_end
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn duplicate_fd_cloexec(fd: RawFd) -> Result<OwnedFd, LauncherError> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn seccomp_authorization_binding(
    program: &VerifiedSeccompProgram,
    rootfs: &VerifiedRootfs,
    semantics_sha256: [u8; 32],
    authority_key_id_sha256: [u8; 32],
    authorization_receipt_sha256: [u8; 32],
) -> [u8; 32] {
    let instruction_count = program.instruction_count.to_be_bytes();
    let architecture = [match program.architecture {
        ExecutableArchitecture::X86_64 => 1,
        ExecutableArchitecture::Aarch64 => 2,
    }];
    hash_frames(&[
        b"serverware.policyCustody.seccompAuthorization/v1",
        &program.sha256,
        &instruction_count,
        &architecture,
        &rootfs.identity_sha256,
        &semantics_sha256,
        &authority_key_id_sha256,
        &authorization_receipt_sha256,
    ])
}

fn ready_proof_sha256(
    nonce: [u8; READY_PROOF_BYTES],
    role: LaunchRole,
    executable_sha256: [u8; 32],
    seccomp_binding_sha256: [u8; 32],
    domain: BoottimeDomain,
    deadline: BoottimeDeadline,
) -> [u8; 32] {
    let role = [role as u8];
    let time_namespace_device =
        domain.time_namespace().device().to_be_bytes();
    let time_namespace_inode =
        domain.time_namespace().inode().to_be_bytes();
    let deadline_nanos = deadline.absolute_nanos().to_be_bytes();
    hash_frames(&[
        b"serverware.policyCustody.filterReady/v1",
        &nonce,
        &role,
        &executable_sha256,
        &seccomp_binding_sha256,
        &domain.authority_boot_id(),
        &time_namespace_device,
        &time_namespace_inode,
        &deadline_nanos,
    ])
}

fn cleanup_receipt_sha256(
    leader: ReapReceipt,
    cgroup_identity_sha256: [u8; 32],
    deadline: BoottimeDeadline,
) -> [u8; 32] {
    let pid = leader.pid.to_be_bytes();
    let si_code = leader.si_code.to_be_bytes();
    let status = leader.status.to_be_bytes();
    let deadline_nanos = deadline.absolute_nanos().to_be_bytes();
    let domain = deadline.domain();
    let time_namespace_device =
        domain.time_namespace().device().to_be_bytes();
    let time_namespace_inode =
        domain.time_namespace().inode().to_be_bytes();
    hash_frames(&[
        b"serverware.policyCustody.cleanupReceipt/v1",
        &pid,
        &si_code,
        &status,
        &cgroup_identity_sha256,
        &domain.authority_boot_id(),
        &time_namespace_device,
        &time_namespace_inode,
        &deadline_nanos,
        b"cgroup.populated=0",
    ])
}

fn hard_unready_and_exit(
    channel: &HardUnreadyChannel,
    pid: libc::pid_t,
    cgroup_identity_sha256: [u8; 32],
    ownership: Option<WatchdogOwnership>,
) -> ! {
    let mut message = [0_u8; HARD_UNREADY_MESSAGE_BYTES];
    message[0] = WATCHDOG_PROTOCOL_VERSION;
    message[1] = 0xff;
    message[4..8].copy_from_slice(&pid.to_be_bytes());
    message[8..40].copy_from_slice(&cgroup_identity_sha256);
    if let Some(ownership) = ownership {
        message[40..72]
            .copy_from_slice(&ownership.registration_sha256);
    }
    loop {
        let written = unsafe {
            libc::write(
                channel.fd.as_raw_fd(),
                message.as_ptr() as *const libc::c_void,
                message.len(),
            )
        };
        if written == message.len() as isize {
            break;
        }
        if written < 0
            && io::Error::last_os_error().raw_os_error()
                == Some(libc::EINTR)
        {
            continue;
        }
        break;
    }
    unsafe {
        loop {
            libc::syscall(libc::SYS_exit_group, 190);
        }
    }
}

fn hash_frames(frames: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for frame in frames {
        hasher.update((frame.len() as u64).to_be_bytes());
        hasher.update(frame);
    }
    hasher.finalize().into()
}

fn little_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn little_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn little_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        bytes[6], bytes[7],
    ])
}

fn little_i64(bytes: &[u8]) -> i64 {
    i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        bytes[6], bytes[7],
    ])
}

fn nul_terminated_slice(bytes: &[u8]) -> Result<&[u8], LauncherError> {
    let end = bytes.iter().position(|byte| *byte == 0).ok_or(
        LauncherError::Invalid("kernel ABI string is not NUL terminated"),
    )?;
    Ok(&bytes[..end])
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[repr(C)]
struct DmIoctl {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding: u32,
    dev: u64,
    name: [u8; 128],
    uuid: [u8; 129],
    data: [u8; 7],
}

#[repr(C)]
struct DmTargetSpec {
    sector_start: u64,
    length: u64,
    status: i32,
    next: u32,
    target_type: [u8; 16],
}

#[cfg(target_os = "linux")]
#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("catchplate-coder-controller-launcher: Linux is required");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().nth(1).as_deref()
        == Some("--absolute-path-bypass-canary")
    {
        std::process::exit(126);
    }
    if let Err(error) = linux::run() {
        eprintln!("catchplate-coder-controller-launcher: {error}");
        std::process::exit(125);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::coder_controller_v11::{
        now_unix_ms, sha256, sha256_exact_reader, ControllerError, LaunchContractV11,
        LaunchFileIdentityV11, Operation, Result, LAUNCHER_INSTALL_PATH,
        LAUNCH_CONTRACT_MAX_BYTES,
    };
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom};
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Component, Path, PathBuf};
    use std::time::{Duration, Instant};

    const FS_IOC_GETVERSION: libc::c_ulong = 0x80087601;
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x80086601;
    const FS_IMMUTABLE_FL: libc::c_uint = 0x00000010;
    const F_GET_SEALS_VALUE: libc::c_int = 1034;
    const F_SEAL_SEAL_VALUE: libc::c_int = 0x0001;
    const F_SEAL_SHRINK_VALUE: libc::c_int = 0x0002;
    const F_SEAL_GROW_VALUE: libc::c_int = 0x0004;
    const F_SEAL_WRITE_VALUE: libc::c_int = 0x0008;
    const REQUIRED_SEALS: libc::c_int = F_SEAL_SEAL_VALUE
        | F_SEAL_SHRINK_VALUE
        | F_SEAL_GROW_VALUE
        | F_SEAL_WRITE_VALUE;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const AT_RECURSIVE_VALUE: libc::c_int = 0x8000;
    const MOUNT_ATTR_RDONLY_VALUE: u64 = 0x0000_0001;
    const MOUNT_ATTR_NOSUID_VALUE: u64 = 0x0000_0002;
    const MOUNT_ATTR_NODEV_VALUE: u64 = 0x0000_0004;
    const MOUNT_ATTR_NOEXEC_VALUE: u64 = 0x0000_0008;
    const PR_CAP_AMBIENT_VALUE: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL_VALUE: libc::c_ulong = 4;
    const PR_SET_SECCOMP_VALUE: libc::c_int = 22;
    const SECCOMP_MODE_FILTER_VALUE: libc::c_ulong = 2;
    const SECCOMP_RET_KILL_PROCESS_VALUE: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO_VALUE: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW_VALUE: u32 = 0x7fff_0000;
    const LANDLOCK_CREATE_RULESET_VERSION_VALUE: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH_VALUE: u32 = 1;
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
    const SIOCGIFFLAGS_VALUE: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS_VALUE: libc::c_ulong = 0x8914;
    const IFF_UP_VALUE: libc::c_short = 0x1;
    const IFF_LOOPBACK_VALUE: libc::c_short = 0x8;
    const UNLISTED_EXEC_CANARY_PATH: &str =
        "/.catchplate-unlisted-executable-canary";
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
        reserved: u32,
    }

    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: libc::c_int,
    }

    #[repr(C)]
    struct InterfaceRequestFlags {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        padding: [u8; 22],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    struct OpenClosureMember {
        path: PathBuf,
        executable: bool,
        file: File,
        opath: OwnedFd,
    }

    pub fn run() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(ControllerError::Rejected(
                "launcher must begin with controller root authority",
            ));
        }
        let mut args = std::env::args();
        let _program = args.next().ok_or(ControllerError::Invalid(
            "launcher argv[0] is absent",
        ))?;
        let mode = args.next().ok_or(ControllerError::Invalid(
            "launcher mode is absent",
        ))?;
        if !matches!(mode.as_str(), "launch-v11" | "probe-v11")
            || args.next().is_some()
        {
            return Err(ControllerError::Invalid(
                "launcher accepts only launch-v11",
            ));
        }
        let contract_fd = std::env::var(
            "CATCHPLATE_CONTROLLER_LAUNCH_CONTRACT_FD",
        )
        .map_err(|_| ControllerError::Invalid("launch contract FD is absent"))?
        .parse::<RawFd>()
        .map_err(|_| ControllerError::Invalid("launch contract FD is invalid"))?;
        if contract_fd < 3 {
            return Err(ControllerError::Rejected(
                "launch contract FD aliases a standard descriptor",
            ));
        }
        let contract_bytes = read_sealed_contract(contract_fd)?;
        let contract = LaunchContractV11::decode(&contract_bytes)?;
        if now_unix_ms()? >= contract.deadline_unix_ms {
            return Err(ControllerError::Rejected(
                "launch contract expired before closure verification",
            ));
        }
        validate_contract_paths(&contract)?;
        let mut closure = open_and_verify_closure(&contract)?;
        if closure.len() != 1
            || !closure[0].executable
            || closure[0].path != contract.primary_executable
        {
            return Err(ControllerError::Rejected(
                "v11 launcher accepts only one exact static primary executable",
            ));
        }
        let primary_index = closure
            .iter()
            .position(|member| {
                member.executable && member.path == contract.primary_executable
            })
            .ok_or(ControllerError::Rejected(
                "verified closure lacks the primary executable",
            ))?;
        require_static_elf_primary(&mut closure[primary_index].file)?;
        let source = open_directory(&contract.source_root)?;
        let mut artifacts = Vec::with_capacity(contract.artifact_roots.len());
        for path in &contract.artifact_roots {
            artifacts.push((path.clone(), open_directory(path)?));
        }
        let launch_id = contract
            .command_identity_sha256
            .iter()
            .take(16)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let new_root = PathBuf::from(format!(
            "/run/catchplate/controller-launch-root-{}-{launch_id}",
            unsafe { libc::getpid() },
        ));
        create_private_mount_root(&new_root)?;
        construct_isolated_root(
            &contract,
            &closure,
            &source,
            &artifacts,
            &new_root,
        )?;
        pivot_to_isolated_root(&new_root)?;
        drop(source);
        drop(artifacts);
        for (index, member) in closure.iter_mut().enumerate() {
            if index != primary_index {
                let replacement = open_dev_null()?;
                let old = mem::replace(&mut member.file, replacement);
                drop(old);
            }
        }
        drop_contract_fd(contract_fd);
        drop_privileges(contract.peer_uid, contract.peer_gid)?;
        install_landlock(&contract, &closure)?;
        absolute_path_bypass_probe()?;
        if mode == "probe-v11" {
            return probe_exec_compatibility(
                &contract,
                closure[primary_index].file.as_raw_fd(),
            );
        }
        install_closure_seccomp()?;
        if now_unix_ms()? >= contract.deadline_unix_ms {
            return Err(ControllerError::Rejected(
                "launch contract expired before final exec",
            ));
        }
        final_exec(
            &contract,
            closure[primary_index].file.as_raw_fd(),
        )
    }

    fn read_sealed_contract(fd: RawFd) -> Result<Vec<u8>> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_size <= 0
            || stat.st_size as usize > LAUNCH_CONTRACT_MAX_BYTES
        {
            return Err(ControllerError::Rejected(
                "launch contract is not one bounded regular memfd",
            ));
        }
        let seals = unsafe { libc::fcntl(fd, F_GET_SEALS_VALUE) };
        if seals < 0 || seals & REQUIRED_SEALS != REQUIRED_SEALS {
            return Err(ControllerError::Rejected(
                "launch contract memfd is not write/grow/shrink/seal protected",
            ));
        }
        let duplicate = unsafe { libc::dup(fd) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(duplicate) };
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(stat.st_size as usize);
        file.take(LAUNCH_CONTRACT_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() != stat.st_size as usize {
            return Err(ControllerError::Rejected(
                "launch contract length changed during read",
            ));
        }
        Ok(bytes)
    }

    fn validate_contract_paths(contract: &LaunchContractV11) -> Result<()> {
        for path in std::iter::once(&contract.primary_executable)
            .chain(std::iter::once(&contract.cwd))
            .chain(std::iter::once(&contract.source_root))
            .chain(std::iter::once(
                &contract.controller_plan_api_socket,
            ))
            .chain(contract.artifact_roots.iter())
            .chain(contract.closure.iter().map(|member| &member.path))
        {
            if !path.is_absolute()
                || path.components().any(|component| {
                    matches!(
                        component,
                        Component::CurDir
                            | Component::ParentDir
                            | Component::Prefix(_)
                    )
                })
            {
                return Err(ControllerError::Rejected(
                    "launch contract contains a noncanonical path",
                ));
            }
        }
        if contract
            .closure
            .iter()
            .any(|member| member.path == Path::new(LAUNCHER_INSTALL_PATH))
        {
            return Err(ControllerError::Rejected(
                "workload closure must not contain its privileged launcher",
            ));
        }
        Ok(())
    }

    fn open_and_verify_closure(
        contract: &LaunchContractV11,
    ) -> Result<Vec<OpenClosureMember>> {
        let mut closure = Vec::with_capacity(contract.closure.len());
        for expected in &contract.closure {
            let mut file = open_regular(&expected.path)?;
            let identity = file_identity(file.as_raw_fd())?;
            if identity != expected.identity {
                return Err(ControllerError::Rejected(
                    "launcher closure identity differs from contract",
                ));
            }
            let digest =
                sha256_exact_reader(&mut file, expected.identity.size)?;
            if digest != expected.content_sha256 {
                return Err(ControllerError::Rejected(
                    "launcher closure content differs from contract",
                ));
            }
            file.seek(SeekFrom::Start(0))?;
            let opath = open_regular_opath(&expected.path)?;
            verify_opath_identity(opath.as_raw_fd(), &expected.identity)?;
            closure.push(OpenClosureMember {
                path: expected.path.clone(),
                executable: expected.executable,
                file,
                opath,
            });
        }
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"catchplate/executable-closure/v11\0");
        canonical.extend_from_slice(contract.lane.plan.as_label().as_bytes());
        canonical.push(0);
        for (expected, opened) in contract.closure.iter().zip(&closure) {
            canonical.push(u8::from(opened.executable));
            canonical.extend_from_slice(opened.path.as_os_str().as_bytes());
            canonical.push(0);
            append_identity(&mut canonical, &expected.identity);
            canonical.extend_from_slice(&expected.content_sha256);
        }
        if sha256(&canonical) != contract.executable_closure_sha256 {
            return Err(ControllerError::Rejected(
                "launcher closure aggregate digest differs from contract",
            ));
        }
        Ok(closure)
    }

    fn append_identity(output: &mut Vec<u8>, identity: &LaunchFileIdentityV11) {
        output.extend_from_slice(&identity.device.to_be_bytes());
        output.extend_from_slice(&identity.inode.to_be_bytes());
        output.extend_from_slice(&identity.generation.to_be_bytes());
        output.extend_from_slice(&identity.mode.to_be_bytes());
        output.extend_from_slice(&identity.owner_uid.to_be_bytes());
        output.extend_from_slice(&identity.size.to_be_bytes());
    }

    fn open_regular(path: &Path) -> Result<File> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("closure path contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn open_directory(path: &Path) -> Result<OwnedFd> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("directory path contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_PATH
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn open_regular_opath(path: &Path) -> Result<OwnedFd> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("closure path contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn verify_opath_identity(
        fd: RawFd,
        expected: &LaunchFileIdentityV11,
    ) -> Result<()> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_nlink != 1
            || stat.st_dev != expected.device
            || stat.st_ino != expected.inode
            || stat.st_mode != expected.mode
            || stat.st_uid != expected.owner_uid
            || stat.st_size < 0
            || stat.st_size as u64 != expected.size
        {
            return Err(ControllerError::Rejected(
                "retained closure O_PATH identity differs from measured file",
            ));
        }
        Ok(())
    }

    fn file_identity(fd: RawFd) -> Result<LaunchFileIdentityV11> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != 0
            || stat.st_mode & 0o022 != 0
            || stat.st_nlink != 1
        {
            return Err(ControllerError::Rejected(
                "closure member is not one regular file",
            ));
        }
        let mut generation: libc::c_int = 0;
        if unsafe { libc::ioctl(fd, FS_IOC_GETVERSION, &mut generation) } != 0 {
            return Err(ControllerError::Rejected(
                "closure member generation is unavailable",
            ));
        }
        let mut flags: libc::c_uint = 0;
        if unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) } != 0
            || flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::Rejected(
                "closure member is not filesystem immutable",
            ));
        }
        Ok(LaunchFileIdentityV11 {
            device: stat.st_dev,
            inode: stat.st_ino,
            generation: generation as u32 as u64,
            mode: stat.st_mode,
            owner_uid: stat.st_uid,
            size: stat.st_size as u64,
        })
    }

    fn require_static_elf_primary(file: &mut File) -> Result<()> {
        let mut header = [0u8; 64];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header)?;
        if header[0..4] != *b"\x7fELF"
            || header[4] != 2
            || header[5] != 1
            || header[6] != 1
        {
            return Err(ControllerError::Rejected(
                "primary executable must be canonical 64-bit little-endian ELF",
            ));
        }
        let program_offset = u64::from_le_bytes(
            header[32..40]
                .try_into()
                .map_err(|_| ControllerError::Invalid(
                    "invalid ELF program offset",
                ))?,
        );
        let program_entry_size = u16::from_le_bytes(
            header[54..56]
                .try_into()
                .map_err(|_| ControllerError::Invalid(
                    "invalid ELF program entry size",
                ))?,
        ) as u64;
        let program_count = u16::from_le_bytes(
            header[56..58]
                .try_into()
                .map_err(|_| ControllerError::Invalid(
                    "invalid ELF program count",
                ))?,
        ) as u64;
        if program_entry_size < 56
            || program_count == 0
            || program_count > 1024
        {
            return Err(ControllerError::Rejected(
                "primary ELF program table is invalid",
            ));
        }
        for index in 0..program_count {
            let offset = program_offset
                .checked_add(index.checked_mul(program_entry_size).ok_or(
                    ControllerError::Invalid(
                        "ELF program table multiplication overflow",
                    ),
                )?)
                .ok_or(ControllerError::Invalid(
                    "ELF program table offset overflow",
                ))?;
            let mut entry = [0u8; 56];
            pread_exact_at(file.as_raw_fd(), &mut entry, offset)?;
            if u32::from_le_bytes(
                entry[0..4]
                    .try_into()
                    .map_err(|_| ControllerError::Invalid(
                        "invalid ELF program type",
                    ))?,
            ) == 3
            {
                return Err(ControllerError::Rejected(
                    "interpreters and dynamic loaders are forbidden; plan ELF must have no PT_INTERP",
                ));
            }
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    fn pread_exact_at(
        fd: RawFd,
        bytes: &mut [u8],
        base_offset: u64,
    ) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let absolute = base_offset
                .checked_add(offset as u64)
                .ok_or(ControllerError::Invalid(
                    "ELF pread offset overflow",
                ))?;
            let absolute: libc::off_t = absolute.try_into().map_err(|_| {
                ControllerError::Invalid("ELF pread offset exceeds off_t")
            })?;
            let count = unsafe {
                libc::pread(
                    fd,
                    bytes[offset..].as_mut_ptr() as *mut libc::c_void,
                    bytes.len() - offset,
                    absolute,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error.into());
            }
            if count == 0 {
                return Err(ControllerError::Rejected(
                    "ELF program table is truncated",
                ));
            }
            offset += count as usize;
        }
        Ok(())
    }

    fn create_private_mount_root(path: &Path) -> Result<()> {
        std::fs::create_dir_all(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn construct_isolated_root(
        contract: &LaunchContractV11,
        closure: &[OpenClosureMember],
        source: &OwnedFd,
        artifacts: &[(PathBuf, OwnedFd)],
        new_root: &Path,
    ) -> Result<()> {
        if unsafe {
            libc::unshare(
                libc::CLONE_NEWNS
                    | libc::CLONE_NEWIPC
                    | libc::CLONE_NEWUTS
                    | libc::CLONE_NEWNET
                    | libc::CLONE_NEWCGROUP,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        bring_private_loopback_up()?;
        mount_private_root()?;
        mount_tmpfs(new_root, 0o700, false)?;
        create_directory(new_root, Path::new("/.oldroot"), 0o700)?;
        create_directory(new_root, Path::new("/proc"), 0o555)?;
        create_directory(new_root, Path::new("/tmp"), 0o1777)?;
        create_directory(new_root, Path::new("/run"), 0o755)?;
        create_directory(new_root, Path::new("/dev"), 0o755)?;
        create_regular_target(new_root, Path::new("/dev/null"), 0o666)?;
        bind_host_path(Path::new("/dev/null"), &inside(new_root, Path::new("/dev/null"))?, true)?;
        let canary_path = Path::new(UNLISTED_EXEC_CANARY_PATH);
        create_regular_target(new_root, canary_path, 0o555)?;
        bind_host_path(
            Path::new("/proc/self/exe"),
            &inside(new_root, canary_path)?,
            false,
        )?;
        mount_tmpfs(&inside(new_root, Path::new("/tmp"))?, 0o1777, true)?;
        mount_tmpfs(&inside(new_root, Path::new("/run"))?, 0o755, true)?;
        let run_user = PathBuf::from(format!("/run/user/{}", contract.peer_uid));
        create_directory(new_root, &run_user, 0o700)?;
        let run_user_host = inside(new_root, &run_user)?;
        let run_user_c = c_path(&run_user_host)?;
        if unsafe {
            libc::chown(
                run_user_c.as_ptr(),
                contract.peer_uid,
                contract.peer_gid,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        mount_proc(&inside(new_root, Path::new("/proc"))?)?;
        let plan_api_target =
            inside(new_root, &contract.controller_plan_api_socket)?;
        create_regular_target(
            new_root,
            &contract.controller_plan_api_socket,
            0o660,
        )?;
        bind_host_path(
            &contract.controller_plan_api_socket,
            &plan_api_target,
            true,
        )?;
        bind_directory_fd(
            source.as_raw_fd(),
            &inside(new_root, &contract.source_root)?,
            true,
            true,
        )?;
        let no_build = contract.lane.operation == Operation::RunNoBuild;
        for (path, fd) in artifacts {
            bind_directory_fd(
                fd.as_raw_fd(),
                &inside(new_root, path)?,
                no_build,
                true,
            )?;
        }
        for member in closure {
            let target = inside(new_root, &member.path)?;
            create_regular_target(new_root, &member.path, member.file.metadata()?.mode())?;
            bind_fd_file(
                member.file.as_raw_fd(),
                &target,
                !member.executable,
            )?;
        }
        if !inside(new_root, &contract.cwd)?.is_dir() {
            return Err(ControllerError::Rejected(
                "configured cwd is absent from the isolated root",
            ));
        }
        Ok(())
    }

    fn bring_private_loopback_up() -> Result<()> {
        let socket = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if socket < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(socket) };
        let mut request = InterfaceRequestFlags {
            name: [0; libc::IFNAMSIZ],
            flags: 0,
            padding: [0; 22],
        };
        for (slot, value) in request.name.iter_mut().zip(b"lo\0") {
            *slot = *value as libc::c_char;
        }
        if unsafe {
            libc::ioctl(
                socket.as_raw_fd(),
                SIOCGIFFLAGS_VALUE,
                &mut request,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if request.flags & IFF_LOOPBACK_VALUE == 0 {
            return Err(ControllerError::Rejected(
                "private network namespace lacks loopback identity",
            ));
        }
        request.flags |= IFF_UP_VALUE;
        if unsafe {
            libc::ioctl(
                socket.as_raw_fd(),
                SIOCSIFFLAGS_VALUE,
                &request,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn mount_private_root() -> Result<()> {
        let root = CString::new("/").unwrap();
        if unsafe {
            libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn mount_tmpfs(path: &Path, mode: u32, noexec: bool) -> Result<()> {
        let source = CString::new("tmpfs").unwrap();
        let target = c_path(path)?;
        let filesystem = CString::new("tmpfs").unwrap();
        let data = CString::new(format!(
            "mode={mode:o},size=1073741824,nr_inodes=262144"
        ))
        .map_err(|_| ControllerError::Invalid("tmpfs options contain NUL"))?;
        let flags = libc::MS_NOSUID
            | libc::MS_NODEV
            | if noexec { libc::MS_NOEXEC } else { 0 };
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                flags,
                data.as_ptr() as *const libc::c_void,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn mount_proc(path: &Path) -> Result<()> {
        let source = CString::new("proc").unwrap();
        let target = c_path(path)?;
        let filesystem = CString::new("proc").unwrap();
        let data = CString::new("hidepid=2,subset=pid").unwrap();
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                data.as_ptr() as *const libc::c_void,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn bind_directory_fd(
        fd: RawFd,
        target: &Path,
        read_only: bool,
        noexec: bool,
    ) -> Result<()> {
        std::fs::create_dir_all(target)?;
        let source = CString::new(format!("/proc/self/fd/{fd}"))
            .map_err(|_| ControllerError::Invalid("FD mount source contains NUL"))?;
        let target_c = c_path(target)?;
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        remount_bind(target, read_only, noexec, true)
    }

    fn bind_fd_file(fd: RawFd, target: &Path, noexec: bool) -> Result<()> {
        let source = CString::new(format!("/proc/self/fd/{fd}"))
            .map_err(|_| ControllerError::Invalid("FD mount source contains NUL"))?;
        let target_c = c_path(target)?;
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        remount_bind(target, true, noexec, false)
    }

    fn bind_host_path(source: &Path, target: &Path, noexec: bool) -> Result<()> {
        let source = c_path(source)?;
        let target_c = c_path(target)?;
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        remount_bind(target, true, noexec, false)
    }

    fn remount_bind(
        path: &Path,
        read_only: bool,
        noexec: bool,
        recursive: bool,
    ) -> Result<()> {
        let target = c_path(path)?;
        let flags = libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | if read_only { libc::MS_RDONLY } else { 0 }
            | if noexec { libc::MS_NOEXEC } else { 0 };
        if unsafe {
            libc::mount(
                std::ptr::null(),
                target.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let attributes = MountAttr {
            attr_set: MOUNT_ATTR_NOSUID_VALUE
                | MOUNT_ATTR_NODEV_VALUE
                | if read_only {
                    MOUNT_ATTR_RDONLY_VALUE
                } else {
                    0
                }
                | if noexec {
                    MOUNT_ATTR_NOEXEC_VALUE
                } else {
                    0
                },
            ..MountAttr::default()
        };
        if unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                libc::AT_FDCWD,
                target.as_ptr(),
                if recursive {
                    AT_RECURSIVE_VALUE
                } else {
                    0
                },
                &attributes,
                mem::size_of::<MountAttr>(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn create_directory(root: &Path, path: &Path, mode: u32) -> Result<()> {
        let target = inside(root, path)?;
        std::fs::create_dir_all(&target)?;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn create_regular_target(root: &Path, path: &Path, mode: u32) -> Result<()> {
        let target = inside(root, path)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !target.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode & 0o777)
                .open(&target)?;
        }
        Ok(())
    }

    fn inside(root: &Path, absolute: &Path) -> Result<PathBuf> {
        let relative = absolute.strip_prefix("/").map_err(|_| {
            ControllerError::Rejected("sandbox target path is not absolute")
        })?;
        Ok(root.join(relative))
    }

    fn pivot_to_isolated_root(new_root: &Path) -> Result<()> {
        let root = c_path(new_root)?;
        if unsafe { libc::chdir(root.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let dot = CString::new(".").unwrap();
        let old = CString::new(".oldroot").unwrap();
        if unsafe {
            libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), old.as_ptr())
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let slash = CString::new("/").unwrap();
        let old_root = CString::new("/.oldroot").unwrap();
        if unsafe { libc::chdir(slash.as_ptr()) } != 0
            || unsafe { libc::umount2(old_root.as_ptr(), libc::MNT_DETACH) } != 0
            || unsafe { libc::rmdir(old_root.as_ptr()) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn drop_privileges(uid: u32, gid: u32) -> Result<()> {
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
            || unsafe { libc::setresgid(gid, gid, gid) } != 0
            || unsafe { libc::setresuid(uid, uid, uid) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut header = CapUserHeader {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut capabilities = [
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            };
            2
        ];
        if unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut header,
                capabilities.as_mut_ptr(),
            )
        } != 0
            || unsafe {
                libc::prctl(
                    PR_CAP_AMBIENT_VALUE,
                    PR_CAP_AMBIENT_CLEAR_ALL_VALUE,
                    0,
                    0,
                    0,
                )
            } != 0
            || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn install_landlock(
        contract: &LaunchContractV11,
        closure: &[OpenClosureMember],
    ) -> Result<()> {
        let abi = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<LandlockRulesetAttr>(),
                0,
                LANDLOCK_CREATE_RULESET_VERSION_VALUE,
            ) as i32
        };
        if abi < 1 {
            return Err(ControllerError::Rejected("Landlock is unavailable"));
        }
        let mut writable_access = LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;
        if abi >= 2 {
            writable_access |= LANDLOCK_ACCESS_FS_REFER;
        }
        if abi >= 3 {
            writable_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
        if abi >= 5 {
            writable_access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        }
        let handled_access =
            writable_access | LANDLOCK_ACCESS_FS_EXECUTE;
        let attr = LandlockRulesetAttr {
            handled_access_fs: handled_access,
        };
        let ruleset = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr,
                mem::size_of::<LandlockRulesetAttr>(),
                0,
            ) as RawFd
        };
        if ruleset < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset) };
        let mut writable = vec![PathBuf::from("/tmp")];
        writable.push(PathBuf::from(format!(
            "/run/user/{}",
            contract.peer_uid
        )));
        if contract.lane.operation == Operation::Build {
            writable.extend(contract.artifact_roots.iter().cloned());
        }
        let mut retained = Vec::with_capacity(writable.len());
        for path in writable {
            let fd = open_directory(&path)?;
            let rule = LandlockPathBeneathAttr {
                allowed_access: writable_access,
                parent_fd: fd.as_raw_fd(),
                reserved: 0,
            };
            if unsafe {
                libc::syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    ruleset.as_raw_fd(),
                    LANDLOCK_RULE_PATH_BENEATH_VALUE,
                    &rule,
                    0,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            retained.push(fd);
        }
        for member in closure.iter().filter(|member| member.executable) {
            let rule = LandlockPathBeneathAttr {
                allowed_access: LANDLOCK_ACCESS_FS_EXECUTE,
                parent_fd: member.opath.as_raw_fd(),
                reserved: 0,
            };
            if unsafe {
                libc::syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    ruleset.as_raw_fd(),
                    LANDLOCK_RULE_PATH_BENEATH_VALUE,
                    &rule,
                    0,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        if unsafe {
            libc::syscall(
                SYS_LANDLOCK_RESTRICT_SELF,
                ruleset.as_raw_fd(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn install_closure_seccomp() -> Result<()> {
        let mut filter = Vec::<libc::sock_filter>::new();
        filter.push(statement(0x20, 0, 0, 4));
        filter.push(statement(0x15, 1, 0, AUDIT_ARCH_NATIVE));
        filter.push(statement(
            0x06,
            0,
            0,
            SECCOMP_RET_KILL_PROCESS_VALUE,
        ));
        filter.push(statement(0x20, 0, 0, 0));
        filter.push(statement(
            0x15,
            0,
            4,
            libc::SYS_clone as u32,
        ));
        filter.push(statement(0x20, 0, 0, 16));
        filter.push(statement(0x45, 0, 1, 0x7e02_0000));
        filter.push(statement(
            0x06,
            0,
            0,
            SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32,
        ));
        filter.push(statement(0x20, 0, 0, 0));
        for syscall in [
            libc::SYS_clone3,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_open_tree,
            libc::SYS_mount_setattr,
            libc::SYS_bpf,
            libc::SYS_ptrace,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_userfaultfd,
            libc::SYS_open_by_handle_at,
            libc::SYS_name_to_handle_at,
            libc::SYS_process_vm_writev,
            libc::SYS_pidfd_getfd,
            libc::SYS_memfd_create,
            libc::SYS_perf_event_open,
            libc::SYS_kexec_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
        ] {
            filter.push(statement(0x15, 0, 1, syscall as u32));
            filter.push(statement(
                0x06,
                0,
                0,
                SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32,
            ));
        }
        filter.push(statement(0x06, 0, 0, SECCOMP_RET_ALLOW_VALUE));
        let program = libc::sock_fprog {
            len: filter.len().try_into().map_err(|_| {
                ControllerError::Rejected("seccomp program exceeds u16")
            })?,
            filter: filter.as_mut_ptr(),
        };
        if unsafe {
            libc::prctl(
                PR_SET_SECCOMP_VALUE,
                SECCOMP_MODE_FILTER_VALUE,
                &program,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn statement(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    fn absolute_path_bypass_probe() -> Result<()> {
        let metadata = std::fs::metadata(UNLISTED_EXEC_CANARY_PATH)?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return Err(ControllerError::Rejected(
                "unlisted executable canary is not one existing executable file",
            ));
        }
        let path = CString::new(UNLISTED_EXEC_CANARY_PATH).unwrap();
        let arg0 = CString::new(UNLISTED_EXEC_CANARY_PATH).unwrap();
        let arg1 = CString::new("--absolute-path-bypass-canary").unwrap();
        let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        let result =
            unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        if result != -1 {
            return Err(ControllerError::Rejected(
                "unlisted executable canary unexpectedly returned",
            ));
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => Ok(()),
            _ => Err(ControllerError::Rejected(
                "existing unlisted executable was not mechanically denied",
            )),
        }
    }

    fn probe_exec_compatibility(
        contract: &LaunchContractV11,
        primary_fd: RawFd,
    ) -> Result<()> {
        let remaining_ms = contract
            .deadline_unix_ms
            .checked_sub(now_unix_ms()?)
            .ok_or(ControllerError::Rejected(
                "launch contract expired before compatibility exec",
            ))?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining_ms.min(5_000)))
            .ok_or(ControllerError::Rejected(
                "compatibility exec deadline overflow",
            ))?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if pid == 0 {
            let traced = unsafe {
                libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            if traced != 0 || install_closure_seccomp().is_err() {
                unsafe { libc::_exit(124) };
            }
            let _ = final_exec(contract, primary_fd);
            unsafe { libc::_exit(125) };
        }
        let mut status = 0;
        loop {
            let result =
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if result == pid {
                if libc::WIFSTOPPED(status)
                    && libc::WSTOPSIG(status) == libc::SIGTRAP
                {
                    break;
                }
                return Err(ControllerError::Rejected(
                    "plan compatibility exec failed before its post-exec trap",
                ));
            }
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error.into());
            }
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                reap_exact_probe(pid, probe_reap_deadline()?)?;
                return Err(ControllerError::Rejected(
                    "plan compatibility exec exceeded its bounded deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        reap_exact_probe(pid, probe_reap_deadline()?)
    }

    fn probe_reap_deadline() -> Result<Instant> {
        Instant::now()
            .checked_add(Duration::from_secs(1))
            .ok_or(ControllerError::Rejected(
                "compatibility probe reap deadline overflow",
            ))
    }

    fn reap_exact_probe(pid: libc::pid_t, deadline: Instant) -> Result<()> {
        let mut status = 0;
        loop {
            let result =
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if result == pid {
                return if libc::WIFSIGNALED(status)
                    && libc::WTERMSIG(status) == libc::SIGKILL
                {
                    Ok(())
                } else {
                    Err(ControllerError::Rejected(
                        "compatibility probe did not terminate by exact SIGKILL",
                    ))
                };
            }
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error.into());
            }
            if Instant::now() >= deadline {
                return Err(ControllerError::Rejected(
                    "compatibility probe exact-PID reap exceeded its deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn final_exec(contract: &LaunchContractV11, primary_fd: RawFd) -> Result<()> {
        let cwd = c_path(&contract.cwd)?;
        if unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let argv_values: Vec<CString> = contract
            .argv
            .iter()
            .map(|value| CString::new(value.clone()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| ControllerError::Invalid("argv contains NUL"))?;
        let env_values: Vec<CString> = contract
            .env
            .iter()
            .map(|value| CString::new(value.clone()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| ControllerError::Invalid("environment contains NUL"))?;
        let mut argv: Vec<*const libc::c_char> =
            argv_values.iter().map(|value| value.as_ptr()).collect();
        argv.push(std::ptr::null());
        let mut envp: Vec<*const libc::c_char> =
            env_values.iter().map(|value| value.as_ptr()).collect();
        envp.push(std::ptr::null());
        let empty = CString::new("").unwrap();
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                primary_fd,
                empty.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        Err(std::io::Error::last_os_error().into())
    }

    fn drop_contract_fd(fd: RawFd) {
        unsafe {
            libc::close(fd);
        }
    }

    fn open_dev_null() -> Result<File> {
        OpenOptions::new()
            .read(true)
            .open("/dev/null")
            .map_err(Into::into)
    }

    fn c_path(path: &Path) -> Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("path contains NUL"))
    }
}

//! Public signed generation coordination, never role seeds or raw CAS storage.
use super::{config::{CustodyServiceRole as Role, TRUSTED_HOST_SHARED_UDS_GID as GID},
    RootOwnedResponseObservationV2Config as Config, V2RuntimeError};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub(crate) const DIRECTORY: &str = "/run/catchplate-response-v2-public";
const LEAF: &str = "catchplate-response-v2-public";
const PROFILE: &str = "catchplate.responseV2.guestPublicArtifacts/v1";
fn fail(message: &str) -> V2RuntimeError {
    V2RuntimeError::new("guest_public_artifacts_refused", message)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Profile { api_version: String }
pub(crate) fn configuration_profile<'de, D: serde::Deserializer<'de>>(d: D)
    -> Result<Option<Profile>, D::Error> {
    Profile::deserialize(d).map(Some)
}
impl Profile {
    pub(crate) fn validate(&self, config: &Config) -> Result<(), V2RuntimeError> {
        if self.api_version != PROFILE || config.guest_listener.is_none()
            || config.guest_delivery_authority.is_none()
            || config.custody_topology.attestation_mode != super::config::CustodyAttestationProfile::TeeHardware {
            return Err(fail("public guest artifacts require explicit listener, signed delivery and TEE generation"));
        }
        for role in Role::ALL {
            let scoped = config.scoped_service_config(role)?;
            if scoped.process.uid == 0 || scoped.process.gid != GID {
                return Err(fail("public artifact owner differs from dedicated signed role"));
            }
            let process = &scoped.process;
            for path in [&process.state_directory, &process.socket_path,
                &process.readiness_socket_path, &process.readiness_record_path]
                .into_iter().chain(process.backend_socket_path.iter()) {
                require_private_path(path)?;
            }
            for key in &process.role_keys {
                require_private_path(&key.public_key_path)?;
                require_private_path(&key.secret_key_path)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn require_private_path(path: &Path) -> Result<(), V2RuntimeError> {
    if path.starts_with(DIRECTORY) {
        return Err(fail("public generation directory cannot contain private inputs, state or sockets"));
    }
    Ok(())
}

/// Used only for the three existing public generation artifact path getters.
/// The file's existing signature, exact owner and 0440 checks remain mandatory.
pub(crate) fn checked_directory(config: &Config, role: Role) -> Result<PathBuf, V2RuntimeError> {
    config.guest_public_artifacts.as_ref().ok_or_else(|| fail("public artifact profile absent"))?.validate(config)?;
    #[cfg(target_os = "linux")]
    {
        let scoped = config.scoped_service_config(role)?;
        let parents = kernel::Parents::open()?;
        let directory = kernel::Directory::open_at(&parents.public, role.as_str())?;
        directory.require(scoped.process.uid, GID, 0o750)?;
        parents.check()?;
        directory.check_at(&parents.public, role.as_str())?;
        Ok(Path::new(DIRECTORY).join(role.as_str()))
    }
    #[cfg(not(target_os = "linux"))]
    { let _ = role; Err(fail("public guest generation artifacts require Linux")) }
}

#[cfg(target_os = "linux")]
mod kernel {
    use super::*;
    use std::{ffi::CString, fs::{File, Metadata}, os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt}};

    // Directory contents, length, timestamps and link count change as genuine
    // services publish. Only the retained directory object and access policy
    // are invariant; do not confuse child publication with owner replacement.
    #[derive(PartialEq, Eq)]
    struct Identity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }
    impl Identity {
        fn of(m: &Metadata) -> Self {
            Self { device:m.dev(), inode:m.ino(), mode:m.mode(), uid:m.uid(), gid:m.gid() }
        }
    }
    pub(super) struct Directory { file: File, identity: Identity }
    impl Directory {
        fn from_file(file: File) -> Result<Self, V2RuntimeError> {
            let metadata = file.metadata().map_err(|_| fail("inspect directory original"))?;
            if !metadata.is_dir() { return Err(fail("public artifact parent is not a directory")); }
            Ok(Self { file, identity:Identity::of(&metadata) })
        }
        fn root() -> Result<Self, V2RuntimeError> {
            let name = c("/")?;
            let fd = unsafe { libc::open(name.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 { return Err(fail("open filesystem root original")); }
            Self::from_file(unsafe { File::from_raw_fd(fd) })
        }
        pub(super) fn open_at(parent: &Self, name: &str) -> Result<Self, V2RuntimeError> {
            let name = c(name)?;
            let fd = unsafe { libc::openat(parent.file.as_raw_fd(), name.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 { return Err(fail("open fixed public directory original")); }
            Self::from_file(unsafe { File::from_raw_fd(fd) })
        }
        fn fresh(parent: &Self, name: &str, uid: u32, mode: u32) -> Result<Self, V2RuntimeError> {
            let encoded = c(name)?;
            if unsafe { libc::mkdirat(parent.file.as_raw_fd(), encoded.as_ptr(), 0o700) } != 0 {
                return Err(fail("public directory must be freshly created; no reuse or repair"));
            }
            // Only this fresh root-created directory is opened for ownership
            // installation. O_PATH originals are retained afterward so the
            // gate needs no directory read permission after permanent drop.
            let fd = unsafe { libc::openat(parent.file.as_raw_fd(), encoded.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 { return Err(fail("open newly created directory")); }
            let file = unsafe { File::from_raw_fd(fd) };
            let before = Self::from_file(file)?;
            if before.identity.uid != 0 || before.identity.mode & 0o077 != 0 {
                return Err(fail("fresh public directory is not exclusively root controlled"));
            }
            if unsafe { libc::fchown(before.file.as_raw_fd(), uid, GID) } != 0
                || unsafe { libc::fchmod(before.file.as_raw_fd(), mode) } != 0 {
                return Err(fail("install exact public directory owner and access mode"));
            }
            let installed = Self::from_file(before.file)?;
            installed.require(uid, GID, mode)?;
            installed.check_at(parent, name)?;
            // Do not retain a readable directory descriptor across gate drop.
            let held = Self::open_at(parent, name)?;
            if held.identity != installed.identity { return Err(fail("fresh directory original changed")); }
            Ok(held)
        }
        pub(super) fn require(&self, uid: u32, gid: u32, mode: u32) -> Result<(), V2RuntimeError> {
            if self.identity.uid != uid || self.identity.gid != gid
                || self.identity.mode != (libc::S_IFDIR | mode) {
                return Err(fail("public directory signed owner or exact access mode differs"));
            }
            Ok(())
        }
        fn require_parent(&self) -> Result<(), V2RuntimeError> {
            if self.identity.uid != 0 || self.identity.mode & 0o022 != 0
                || self.identity.mode & 0o001 == 0 {
                return Err(fail("public layout parent must be root owned, nonwritable and traversable"));
            }
            Ok(())
        }
        fn check_held(&self) -> Result<(), V2RuntimeError> {
            if Identity::of(&self.file.metadata().map_err(|_| fail("inspect retained directory"))?) != self.identity {
                return Err(fail("retained public directory owner changed"));
            }
            Ok(())
        }
        pub(super) fn check_at(&self, parent: &Self, name: &str) -> Result<(), V2RuntimeError> {
            self.check_held()?;
            if Self::open_at(parent, name)?.identity != self.identity {
                return Err(fail("named public directory no longer matches held original"));
            }
            Ok(())
        }
    }
    fn c(name: &str) -> Result<CString, V2RuntimeError> {
        CString::new(name).map_err(|_| fail("fixed directory component contains NUL"))
    }

    pub(super) struct Parents { root: Directory, run: Directory, pub(super) public: Directory }
    impl Parents {
        fn base() -> Result<(Directory, Directory), V2RuntimeError> {
            let root = Directory::root()?;
            root.require_parent()?;
            let run = Directory::open_at(&root, "run")?;
            run.require_parent()?;
            Ok((root, run))
        }
        pub(super) fn open() -> Result<Self, V2RuntimeError> {
            let (root, run) = Self::base()?;
            let public = Directory::open_at(&run, LEAF)?;
            public.require(0, GID, 0o711)?;
            Ok(Self { root, run, public })
        }
        pub(super) fn check(&self) -> Result<(), V2RuntimeError> {
            self.root.check_held()?;
            if Directory::root()?.identity != self.root.identity { return Err(fail("filesystem root changed")); }
            self.run.check_at(&self.root, "run")?;
            self.public.check_at(&self.run, LEAF)
        }
    }

    pub(crate) struct Owner {
        parents: Parents, roles: Vec<(Role, Directory)>, pid: libc::pid_t, boot: String,
    }
    impl Owner {
        pub(crate) fn prepare(prepared: &crate::native_serving_privileges::Prepared,
            originals: &[&super::super::guest_delivery::PreparedRoleDelivery]) -> Result<Self, V2RuntimeError> {
            let recheck = || -> Result<(), V2RuntimeError> {
                prepared.check().map_err(|e| fail(&e))?;
                if originals.len() != Role::ALL.len() { return Err(fail("public layout needs all seven real role owners")); }
                let first = originals[0];
                let mut seen = std::collections::BTreeSet::new();
                for original in originals {
                    original.require_public_artifacts()?;
                    if !seen.insert(original.scoped().role)
                        || original.configuration_sha256() != first.configuration_sha256()
                        || original.boot_id() != first.boot_id()
                        || original.scoped().generation_id != first.scoped().generation_id
                        || original.scoped().generation != first.scoped().generation
                        || original.scoped().trust_checkpoint_sha256 != first.scoped().trust_checkpoint_sha256 {
                        return Err(fail("public layout role owners disagree on original cohort"));
                    }
                }
                if seen != Role::ALL.into_iter().collect() { return Err(fail("public layout role inventory differs")); }
                Ok(())
            };
            recheck()?;
            let (root, run) = Parents::base()?;
            let public = Directory::fresh(&run, LEAF, 0, 0o711)?;
            let parents = Parents { root, run, public };
            let mut roles = Vec::with_capacity(Role::ALL.len());
            for original in originals {
                recheck()?;
                parents.check()?;
                let scoped = original.scoped();
                let directory = Directory::fresh(&parents.public, scoped.role.as_str(), scoped.process.uid, 0o750)?;
                roles.push((scoped.role, directory));
            }
            recheck()?;
            let owner = Self { parents, roles, pid:unsafe { libc::getpid() }, boot:originals[0].boot_id().to_owned() };
            owner.check()?;
            Ok(owner)
        }
        pub(crate) fn check(&self) -> Result<(), V2RuntimeError> {
            if unsafe { libc::getpid() } != self.pid || super::super::recovery::kernel_boot_id()? != self.boot {
                return Err(fail("public directory originals crossed process or boot"));
            }
            self.parents.check()?;
            for (role, directory) in &self.roles { directory.check_at(&self.parents.public, role.as_str())?; }
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use kernel::Owner;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_profile_is_closed_and_null_is_not_omission() {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Cold {
            #[serde(default, deserialize_with = "configuration_profile")]
            guest_public_artifacts: Option<Profile>,
        }
        assert!(serde_json::from_str::<Cold>("{}").unwrap().guest_public_artifacts.is_none());
        let valid = r#"{"guestPublicArtifacts":{"apiVersion":"catchplate.responseV2.guestPublicArtifacts/v1"}}"#;
        assert_eq!(serde_json::from_str::<Cold>(valid).unwrap().guest_public_artifacts.unwrap().api_version, PROFILE);
        for rejected in [r#"{"guestPublicArtifacts":null}"#,
            r#"{"guestPublicArtifacts":{}}"#,
            r#"{"guestPublicArtifacts":{"apiVersion":"catchplate.responseV2.guestPublicArtifacts/v1","path":"/run/custom"}}"#] {
            assert!(serde_json::from_str::<Cold>(rejected).is_err());
        }
    }

    #[test]
    fn public_tree_cannot_be_a_private_input() {
        for path in [DIRECTORY, "/run/catchplate-response-v2-public/state-authority/seed"] {
            assert!(require_private_path(Path::new(path)).is_err());
        }
        assert!(require_private_path(Path::new("/run/catchplate-response-v2-public-private/seed")).is_ok());
        assert!(require_private_path(Path::new("/run/catchplate-private/seed")).is_ok());
    }
}

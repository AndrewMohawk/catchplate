#![cfg(target_os = "linux")]

use crate::plan_protocol::{
    canonical_bytes, sha256_bytes, CasSealingEvidenceV12,
    CasSealingPolicyV12, Digest, PlanProtocolError, PlanResult,
    SourceCasReference,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

const SOURCE_MANIFEST_VERSION: &str =
    "serverware/source-cas-manifest/v12";
const FILESYSTEM_MANIFEST_VERSION: &str =
    "serverware/filesystem-cas-manifest/v12";
const SOURCE_CAS_DOMAIN: &str = "serverware/source-cas/v12";
const SOURCE_METADATA_NAME: &str = ".serverware-source-cas-v12.json";
const PUBLICATION_CONTROL_VERSION: &str =
    "serverware/cas-publication-control/v12";
const PUBLICATION_JOURNAL_VERSION: &str =
    "serverware/cas-publication-journal/v12";
const PUBLICATION_JOURNAL_DIRECTORY: &str =
    ".serverware-cas-publication-journal-v12";
const MAX_ENTRIES: usize = 2_000_000;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024 * 1024;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RENAME_NOREPLACE: libc::c_uint = 1;
const CLONE_PIDFD: u64 = 0x0000_1000;
const MAX_DIRECTORY_DEPTH: usize = 128;
const MAX_REMOVE_ENTRIES: usize = 100_000;
const FS_VERITY_HASH_ALG_SHA256: u16 = 1;
const FS_VERITY_MAX_DIGEST_BYTES: usize = 64;
const FS_IOC_ENABLE_VERITY: libc::c_ulong =
    linux_iow(b'f', 133, mem::size_of::<FsVerityEnableArg>());
const FS_IOC_MEASURE_VERITY: libc::c_ulong =
    linux_iowr(b'f', 134, mem::size_of::<FsVerityDigestHeader>());

type CasError = PlanProtocolError;

const fn linux_ioc(
    direction: libc::c_ulong,
    ioctl_type: u8,
    number: u8,
    size: usize,
) -> libc::c_ulong {
    (direction << 30)
        | ((ioctl_type as libc::c_ulong) << 8)
        | (number as libc::c_ulong)
        | ((size as libc::c_ulong) << 16)
}

const fn linux_iow(
    ioctl_type: u8,
    number: u8,
    size: usize,
) -> libc::c_ulong {
    linux_ioc(1, ioctl_type, number, size)
}

const fn linux_iowr(
    ioctl_type: u8,
    number: u8,
    size: usize,
) -> libc::c_ulong {
    linux_ioc(3, ioctl_type, number, size)
}

#[repr(C)]
#[derive(Default)]
struct FsVerityEnableArg {
    version: u32,
    hash_algorithm: u32,
    block_size: u32,
    salt_size: u32,
    salt_ptr: u64,
    signature_size: u32,
    reserved1: u32,
    signature_ptr: u64,
    reserved2: [u64; 11],
}

#[repr(C)]
struct FsVerityDigestHeader {
    digest_algorithm: u16,
    digest_size: u16,
}

#[repr(C)]
struct FsVerityDigestBuffer {
    header: FsVerityDigestHeader,
    digest: [u8; FS_VERITY_MAX_DIGEST_BYTES],
}

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
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

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationControlV12 {
    pub sealing_policy: CasSealingPolicyV12,
    pub version: String,
    pub operation_id: Digest,
    pub owner_identity_sha256: Digest,
    pub deadline_boottime_ns: u64,
    pub cleanup_deadline_boottime_ns: u64,
    pub control_sha256: Digest,
}

impl PublicationControlV12 {
    pub fn new(
        sealing_policy: CasSealingPolicyV12,
        operation_id: Digest,
        owner_identity_sha256: Digest,
        deadline_boottime_ns: u64,
        cleanup_deadline_boottime_ns: u64,
    ) -> PlanResult<Self> {
        let mut control = Self {
            sealing_policy,
            version: PUBLICATION_CONTROL_VERSION.to_string(),
            operation_id,
            owner_identity_sha256,
            deadline_boottime_ns,
            cleanup_deadline_boottime_ns,
            control_sha256: [0; 32],
        };
        control.control_sha256 =
            sha256_bytes(&canonical_bytes(&control)?);
        control.validate()?;
        Ok(control)
    }

    pub fn validate(&self) -> PlanResult<()> {
        if self.version != PUBLICATION_CONTROL_VERSION
            || self.operation_id == [0; 32]
            || self.owner_identity_sha256 == [0; 32]
            || self.deadline_boottime_ns <= boottime_ns()?
            || self.cleanup_deadline_boottime_ns
                <= self.deadline_boottime_ns
            || self.control_sha256 == [0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "CAS publication control is invalid or expired",
            ));
        }
        let mut copy = self.clone();
        copy.control_sha256 = [0; 32];
        if sha256_bytes(&canonical_bytes(&copy)?)
            != self.control_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "CAS publication control digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum PublicationPhaseV12 {
    Prepared,
    Copying,
    Published,
    Failed,
    CleanupComplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PublicationJournalRecordV12 {
    version: String,
    control_sha256: Digest,
    operation_id: Digest,
    object_sha256: Digest,
    manifest_sha256: Digest,
    staging_name: String,
    phase: PublicationPhaseV12,
    prior_record_sha256: Option<Digest>,
    sealing_evidence: Option<CasSealingEvidenceV12>,
    record_sha256: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FilesystemEntryKind {
    Directory,
    RegularFile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FilesystemEntryV12 {
    pub relative_path: String,
    pub kind: FilesystemEntryKind,
    pub mode: u32,
    pub size: u64,
    pub content_sha256: Digest,
}

impl FilesystemEntryV12 {
    pub fn validate(&self) -> PlanResult<()> {
        validate_relative_path(&self.relative_path)?;
        match self.kind {
            FilesystemEntryKind::Directory => {
                if self.mode != 0o555
                    || self.size != 0
                    || self.content_sha256 != [0; 32]
                {
                    return Err(PlanProtocolError::Invalid(
                        "directory CAS entry is not canonical",
                    ));
                }
            }
            FilesystemEntryKind::RegularFile => {
                if !matches!(self.mode, 0o444 | 0o555)
                    || self.size > MAX_FILE_BYTES
                    || self.content_sha256 == [0; 32]
                {
                    return Err(PlanProtocolError::Invalid(
                        "regular-file CAS entry is not canonical",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FilesystemManifestV12 {
    pub version: String,
    pub domain: String,
    pub context_sha256: Digest,
    pub entries: Vec<FilesystemEntryV12>,
    pub manifest_sha256: Digest,
    pub signer_key_id: String,
    pub signature: Vec<u8>,
}

impl FilesystemManifestV12 {
    pub fn validate(
        &self,
        expected_domain: &str,
        control: &PublicationControlV12,
        trust: &ManifestTrustPolicy,
    ) -> PlanResult<()> {
        control.validate()?;
        if self.version != FILESYSTEM_MANIFEST_VERSION
            || self.domain != expected_domain
            || self.context_sha256 == [0; 32]
            || self.entries.is_empty()
            || self.entries.len() > MAX_ENTRIES
            || self.manifest_sha256 == [0; 32]
            || self.signature.len() != 64
        {
            return Err(PlanProtocolError::Invalid(
                "filesystem manifest envelope is invalid",
            ));
        }
        let mut prior: Option<&str> = None;
        let mut known_directories = BTreeSet::new();
        let mut total_bytes = 0u64;
        for entry in &self.entries {
            entry.validate()?;
            if prior.is_some_and(|path| path >= entry.relative_path.as_str()) {
                return Err(PlanProtocolError::Invalid(
                    "filesystem manifest entries are not strictly sorted",
                ));
            }
            require_declared_parent(
                &entry.relative_path,
                &known_directories,
            )?;
            if entry.kind == FilesystemEntryKind::Directory {
                known_directories.insert(entry.relative_path.clone());
            } else {
                total_bytes = total_bytes.checked_add(entry.size).ok_or(
                    PlanProtocolError::Invalid(
                        "filesystem manifest byte total overflow",
                    ),
                )?;
                if total_bytes > MAX_TOTAL_BYTES {
                    return Err(PlanProtocolError::Invalid(
                        "filesystem manifest byte total is excessive",
                    ));
                }
            }
            prior = Some(entry.relative_path.as_str());
        }
        let expected = filesystem_manifest_digest(self)?;
        if expected != self.manifest_sha256 {
            return Err(PlanProtocolError::Invalid(
                "filesystem manifest digest is not canonical",
            ));
        }
        trust.verify(
            &self.signer_key_id,
            &self.manifest_sha256,
            &self.signature,
        )
    }

    pub fn total_bytes(&self) -> PlanResult<u64> {
        self.entries.iter().try_fold(0u64, |total, entry| {
            total.checked_add(entry.size).ok_or(
                PlanProtocolError::Invalid(
                    "filesystem manifest byte total overflow",
                ),
            )
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceInputKind {
    CanonicalBundle,
    NativePointInTimeSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NativeSnapshotEvidenceV12 {
    pub provider: String,
    pub snapshot_id: String,
    pub snapshot_generation: u64,
    pub source_root_identity_sha256: Digest,
    pub provider_evidence_sha256: Digest,
    pub point_in_time: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceProvenanceV12 {
    pub input_kind: SourceInputKind,
    pub canonical_bundle_sha256: Option<Digest>,
    pub native_snapshot: Option<NativeSnapshotEvidenceV12>,
    pub provenance_sha256: Digest,
}

impl SourceProvenanceV12 {
    pub fn validate(&self) -> PlanResult<()> {
        match self.input_kind {
            SourceInputKind::CanonicalBundle => {
                if self
                    .canonical_bundle_sha256
                    .is_none_or(|digest| digest == [0; 32])
                    || self.native_snapshot.is_some()
                {
                    return Err(PlanProtocolError::Invalid(
                        "canonical source bundle provenance is invalid",
                    ));
                }
            }
            SourceInputKind::NativePointInTimeSnapshot => {
                let snapshot = self.native_snapshot.as_ref().ok_or(
                    PlanProtocolError::Invalid(
                        "native snapshot evidence is absent",
                    ),
                )?;
                if self.canonical_bundle_sha256.is_some()
                    || snapshot.provider.is_empty()
                    || snapshot.snapshot_id.is_empty()
                    || snapshot.snapshot_generation == 0
                    || snapshot.source_root_identity_sha256 == [0; 32]
                    || snapshot.provider_evidence_sha256 == [0; 32]
                    || !snapshot.point_in_time
                {
                    return Err(PlanProtocolError::Invalid(
                        "native point-in-time snapshot evidence is invalid",
                    ));
                }
            }
        }
        let mut copy = self.clone();
        copy.provenance_sha256 = [0; 32];
        if self.provenance_sha256 == [0; 32]
            || sha256_bytes(&canonical_bytes(&copy)?)
                != self.provenance_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "source provenance digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceManifestV12 {
    pub version: String,
    pub provenance: SourceProvenanceV12,
    pub filesystem: FilesystemManifestV12,
    pub source_object_sha256: Digest,
}

impl SourceManifestV12 {
    pub fn validate(
        &self,
        control: &PublicationControlV12,
        trust: &ManifestTrustPolicy,
    ) -> PlanResult<()> {
        if self.version != SOURCE_MANIFEST_VERSION {
            return Err(PlanProtocolError::Invalid(
                "source manifest version is not v12",
            ));
        }
        self.provenance.validate()?;
        if self.provenance.input_kind
            == SourceInputKind::CanonicalBundle
            && self.provenance.canonical_bundle_sha256
                != Some(filesystem_entries_digest(
                    &self.filesystem.entries,
                ))
        {
            return Err(PlanProtocolError::Invalid(
                "canonical bundle digest is not bound to its entries",
            ));
        }
        if self.filesystem.context_sha256
            != self.provenance.provenance_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "source filesystem manifest lost provenance binding",
            ));
        }
        self.filesystem
            .validate(SOURCE_CAS_DOMAIN, control, trust)?;
        let expected = source_object_digest(
            &self.filesystem.manifest_sha256,
            &self.provenance.provenance_sha256,
        );
        if self.source_object_sha256 != expected {
            return Err(PlanProtocolError::Invalid(
                "source object digest is not canonical",
            ));
        }
        Ok(())
    }

    pub fn reference(
        &self,
        sealing_evidence: CasSealingEvidenceV12,
    ) -> PlanResult<SourceCasReference> {
        Ok(SourceCasReference {
            manifest_sha256: self.filesystem.manifest_sha256,
            object_sha256: self.source_object_sha256,
            entry_count: self.filesystem.entries.len() as u64,
            total_bytes: self.filesystem.total_bytes()?,
            sealing_evidence,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizedManifestKey {
    pub key_id: String,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ManifestTrustPolicy {
    keys: BTreeMap<String, VerifyingKey>,
}

impl ManifestTrustPolicy {
    pub fn new(keys: Vec<AuthorizedManifestKey>) -> PlanResult<Self> {
        if keys.is_empty() || keys.len() > 32 {
            return Err(PlanProtocolError::Invalid(
                "manifest trust key set is empty or excessive",
            ));
        }
        let mut authorized = BTreeMap::new();
        for key in keys {
            if key.key_id.is_empty()
                || key.key_id.len() > 128
                || authorized.contains_key(&key.key_id)
            {
                return Err(PlanProtocolError::Invalid(
                    "manifest trust key ID is invalid or duplicated",
                ));
            }
            let verifying_key =
                VerifyingKey::from_bytes(&key.public_key).map_err(|_| {
                    PlanProtocolError::Invalid(
                        "manifest trust public key is invalid",
                    )
                })?;
            authorized.insert(key.key_id, verifying_key);
        }
        Ok(Self { keys: authorized })
    }

    fn verify(
        &self,
        key_id: &str,
        digest: &Digest,
        signature_bytes: &[u8],
    ) -> PlanResult<()> {
        self.verify_domain(
            b"serverware/filesystem-manifest-signature/v12\0",
            key_id,
            digest,
            signature_bytes,
        )
    }

    pub fn verify_domain(
        &self,
        domain: &[u8],
        key_id: &str,
        digest: &Digest,
        signature_bytes: &[u8],
    ) -> PlanResult<()> {
        if domain.is_empty()
            || domain.len() > 256
            || !domain.ends_with(&[0])
            || digest == &[0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "manifest signature domain or digest is invalid",
            ));
        }
        let key = self.keys.get(key_id).ok_or(
            PlanProtocolError::Invalid(
                "filesystem manifest signer is not authorized",
            ),
        )?;
        let signature_bytes: [u8; 64] =
            signature_bytes.try_into().map_err(|_| {
                PlanProtocolError::Invalid(
                    "filesystem manifest signature length is invalid",
                )
            })?;
        let signature = Signature::from_bytes(&signature_bytes);
        let mut signed = Vec::with_capacity(64);
        signed.extend_from_slice(domain);
        signed.extend_from_slice(digest);
        key.verify(&signed, &signature).map_err(|_| {
            PlanProtocolError::Invalid(
                "filesystem manifest signature is invalid",
            )
        })
    }
}

pub struct AuthenticatedDirectoryInput {
    root: OwnedFd,
}

impl AuthenticatedDirectoryInput {
    pub fn from_retained_fd(root: OwnedFd) -> PlanResult<Self> {
        require_secure_directory(root.as_raw_fd(), false)?;
        Ok(Self { root })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.root.as_raw_fd()
    }

    pub fn read_verified_file(
        &self,
        relative_path: &str,
        expected_size: u64,
        expected_sha256: &Digest,
        maximum_size: u64,
    ) -> PlanResult<Vec<u8>> {
        if expected_size > maximum_size
            || expected_sha256 == &[0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "verified CAS read bounds are invalid",
            ));
        }
        let file = open_relative_regular(
            self.root.as_raw_fd(),
            relative_path,
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        )?;
        let before = regular_identity(file.as_raw_fd())?;
        if before.size != expected_size || before.links != 1 {
            return Err(PlanProtocolError::Invalid(
                "verified CAS read identity differs",
            ));
        }
        let mut file = File::from(file);
        let mut bytes = Vec::with_capacity(
            expected_size.min(usize::MAX as u64) as usize,
        );
        std::io::Read::by_ref(&mut file)
            .take(maximum_size.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != expected_size
            || sha256_bytes(&bytes) != *expected_sha256
            || regular_identity(file.as_raw_fd())? != before
        {
            return Err(PlanProtocolError::Invalid(
                "verified CAS read content or identity changed",
            ));
        }
        Ok(bytes)
    }
}

pub struct PublishedDirectoryCas {
    pub object_fd: OwnedFd,
    pub object_sha256: Digest,
    pub manifest_sha256: Digest,
    pub sealing_evidence: CasSealingEvidenceV12,
    pub published_new: bool,
}

pub struct PublishedSourceCas {
    pub object_fd: OwnedFd,
    pub reference: SourceCasReference,
    pub manifest: SourceManifestV12,
    pub sealing_evidence: CasSealingEvidenceV12,
    pub published_new: bool,
}

fn boottime_ns() -> Result<u64, CasError> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
        return Err(CasError::Io(std::io::Error::last_os_error()));
    }
    u64::try_from(now.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|base| u64::try_from(now.tv_nsec).ok().and_then(|ns| base.checked_add(ns)))
        .ok_or_else(|| CasError::InvalidOwned("CLOCK_BOOTTIME value overflowed".into()))
}

fn append_publication_record(
    journal_root: &OwnedFd,
    control: &PublicationControlV12,
    object_sha256: Digest,
    manifest_sha256: Digest,
    staging_name: &str,
    phase: PublicationPhaseV12,
    prior_record_sha256: Option<Digest>,
    sealing_evidence: Option<&CasSealingEvidenceV12>,
) -> Result<Digest, CasError> {
    control.validate()?;
    validate_staging_name(staging_name, &control.operation_id)?;
    if object_sha256 == [0; 32] || manifest_sha256 == [0; 32] {
        return Err(CasError::Invalid(
            "publication journal object binding is empty",
        ));
    }
    let mut record = PublicationJournalRecordV12 {
        version: PUBLICATION_JOURNAL_VERSION.to_string(),
        control_sha256: control.control_sha256,
        operation_id: control.operation_id,
        object_sha256,
        manifest_sha256,
        staging_name: staging_name.to_string(),
        phase,
        prior_record_sha256,
        sealing_evidence: sealing_evidence.cloned(),
        record_sha256: [0; 32],
    };
    record.record_sha256 = sha256_bytes(&canonical_bytes(&record)?);
    write_publication_record(
        journal_root,
        &hex_digest(&control.operation_id),
        publication_phase_component(phase),
        &record,
    )?;
    Ok(record.record_sha256)
}

fn append_cleanup_record(
    journal_root: &OwnedFd,
    record: &PublicationCleanupRecordV12,
) -> Result<(), CasError> {
    write_publication_record(
        journal_root,
        &record.operation_id,
        &record.phase,
        record,
    )
}

fn write_publication_record<T: Serialize>(
    journal_root: &OwnedFd,
    operation_id: &str,
    phase: &str,
    record: &T,
) -> Result<(), CasError> {
    validate_component(operation_id)?;
    validate_component(phase)?;
    let file_name = format!("{operation_id}-{phase}.json");
    let file_name = std::ffi::CString::new(file_name)
        .map_err(|_| CasError::Invalid("publication journal name contains NUL"))?;
    let raw_fd = unsafe {
        libc::openat(
            journal_root.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW,
            0o400,
        )
    };
    if raw_fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            let existing_raw = unsafe {
                libc::openat(
                    journal_root.as_raw_fd(),
                    file_name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if existing_raw < 0 {
                return Err(CasError::Io(std::io::Error::last_os_error()));
            }
            let mut existing = unsafe { std::fs::File::from_raw_fd(existing_raw) };
            let mut actual = Vec::new();
            std::io::Read::read_to_end(&mut existing, &mut actual)?;
            let mut expected = serde_json::to_vec(record).map_err(|error| {
                CasError::InvalidOwned(format!(
                    "serialize publication retry record: {error}"
                ))
            })?;
            expected.push(b'\n');
            if actual != expected {
                return Err(CasError::InvalidOwned(
                    "publication journal retry differs from durable bytes".into(),
                ));
            }
            return Ok(());
        }
        return Err(CasError::Io(error));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    let bytes = serde_json::to_vec(record).map_err(|error| {
        CasError::InvalidOwned(format!(
            "serialize publication journal bytes: {error}"
        ))
    })?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o400) } != 0 {
        return Err(CasError::Io(std::io::Error::last_os_error()));
    }
    file.sync_all()?;
    fsync_fd(journal_root.as_raw_fd())?;
    Ok(())
}

fn create_named_staging_directory(
    root: &OwnedFd,
    staging_name: &str,
) -> Result<OwnedFd, CasError> {
    validate_relative_path(staging_name)?;
    match mkdir_at(root, staging_name, 0o700) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
            remove_tree_at(root, staging_name)?;
            mkdir_at(root, staging_name, 0o700)?;
        }
        Err(error) => return Err(CasError::Io(error)),
    }
    let fd = open_relative_directory(root.as_raw_fd(), staging_name)?;
    fsync_fd(root.as_raw_fd())?;
    Ok(fd)
}

fn wait_worker_pidfd(
    worker_pid: libc::pid_t,
    pidfd: &OwnedFd,
    deadline_boottime_ns: u64,
) -> Result<i32, CasError> {
    let timer_raw = unsafe {
        libc::timerfd_create(
            libc::CLOCK_BOOTTIME,
            libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
        )
    };
    if timer_raw < 0 {
        return Err(CasError::Io(std::io::Error::last_os_error()));
    }
    let timer = unsafe { OwnedFd::from_raw_fd(timer_raw) };
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: (deadline_boottime_ns / 1_000_000_000) as libc::time_t,
            tv_nsec: (deadline_boottime_ns % 1_000_000_000) as libc::c_long,
        },
    };
    if unsafe {
        libc::timerfd_settime(
            timer.as_raw_fd(),
            libc::TFD_TIMER_ABSTIME,
            &spec,
            std::ptr::null_mut(),
        )
    } != 0
    {
        return Err(CasError::Io(std::io::Error::last_os_error()));
    }

    let mut poll_fds = [
        libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: timer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        let rc = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, -1) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(CasError::Io(error));
        }
        if poll_fds[1].revents & libc::POLLIN != 0 {
            return Err(CasError::InvalidOwned(
                "CAS publication worker exceeded its boot-time deadline".into(),
            ));
        }
        if poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut status = 0;
            if unsafe { libc::waitpid(worker_pid, &mut status, 0) } != worker_pid {
                return Err(CasError::Io(std::io::Error::last_os_error()));
            }
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            return Err(CasError::InvalidOwned(
                "CAS publication worker terminated by signal".into(),
            ));
        }
    }
}

fn kill_pidfd(pidfd: &OwnedFd) -> Result<(), CasError> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if rc != 0 {
        return Err(CasError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicationLifecycleStateV12 {
    Unknown,
    Prepared,
    Copying,
    Published,
    Failed,
    CleanupComplete,
}

fn validate_cas_sealing_capability_v12(
    root: &OwnedFd,
    policy: &CasSealingPolicyV12,
) -> Result<(), CasError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(CasError::Io(std::io::Error::last_os_error()));
    }
    let stat = unsafe { stat.assume_init() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(CasError::InvalidOwned(
            "CAS sealing root is not a retained directory descriptor".into(),
        ));
    }
    match policy {
        CasSealingPolicyV12::UserspaceDigestOnly
        | CasSealingPolicyV12::RequiredFsVerity => Ok(()),
        CasSealingPolicyV12::RequiredImmutable => Err(CasError::InvalidOwned(
            "RequiredImmutable is fail-closed in TrustedHostNoTee: no externally verified \
             immutable-flag adapter is bound to this controller generation"
                .into(),
        )),
    }
}

fn collect_cas_sealing_evidence(
    object_root: RawFd,
    manifest: &FilesystemManifestV12,
    metadata_name: &str,
    metadata: &[u8],
    policy: &CasSealingPolicyV12,
    enable_fs_verity: bool,
) -> PlanResult<CasSealingEvidenceV12> {
    let mut userspace_evidence = Sha256::new();
    userspace_evidence.update(b"serverware/cas-userspace-sealing-evidence/v12\0");
    userspace_evidence.update(manifest.manifest_sha256);
    let mut fs_verity_evidence = Sha256::new();
    fs_verity_evidence.update(b"serverware/cas-fs-verity-evidence/v12\0");
    let mut measured_fs_verity = false;

    for entry in &manifest.entries {
        if entry.kind != FilesystemEntryKind::RegularFile {
            continue;
        }
        let file = open_relative_regular(
            object_root,
            &entry.relative_path,
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        )?;
        let digest = rehash_regular_file(
            &file,
            entry.size,
            &entry.content_sha256,
        )?;
        append_sealing_digest(
            &mut userspace_evidence,
            &entry.relative_path,
            entry.size,
            &digest,
        );
        if matches!(policy, CasSealingPolicyV12::RequiredFsVerity) {
            if enable_fs_verity {
                enable_fs_verity_sha256(&file)?;
            }
            let measured = measure_fs_verity_sha256(&file)?;
            append_sealing_digest(
                &mut fs_verity_evidence,
                &entry.relative_path,
                entry.size,
                &measured,
            );
            measured_fs_verity = true;
        }
    }

    let metadata_digest = sha256_bytes(metadata);
    let metadata_file = open_relative_regular(
        object_root,
        metadata_name,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    rehash_regular_file(
        &metadata_file,
        metadata.len() as u64,
        &metadata_digest,
    )?;
    append_sealing_digest(
        &mut userspace_evidence,
        metadata_name,
        metadata.len() as u64,
        &metadata_digest,
    );
    if matches!(policy, CasSealingPolicyV12::RequiredFsVerity) {
        if enable_fs_verity {
            enable_fs_verity_sha256(&metadata_file)?;
        }
        let measured = measure_fs_verity_sha256(&metadata_file)?;
        append_sealing_digest(
            &mut fs_verity_evidence,
            metadata_name,
            metadata.len() as u64,
            &measured,
        );
        measured_fs_verity = true;
    }

    Ok(CasSealingEvidenceV12 {
        policy: policy.clone(),
        userspace_manifest_sha256: userspace_evidence.finalize().into(),
        fs_verity_file_digests_sha256: measured_fs_verity
            .then(|| fs_verity_evidence.finalize().into()),
        immutable_file_set_sha256: None,
    })
}

fn append_sealing_digest(
    hasher: &mut Sha256,
    relative_path: &str,
    size: u64,
    digest: &Digest,
) {
    hasher.update(relative_path.as_bytes());
    hasher.update([0]);
    hasher.update(size.to_be_bytes());
    hasher.update(digest);
}

fn rehash_regular_file(
    fd: &OwnedFd,
    expected_size: u64,
    expected_sha256: &Digest,
) -> PlanResult<Digest> {
    if expected_size > MAX_FILE_BYTES || expected_sha256 == &[0; 32] {
        return Err(PlanProtocolError::Invalid(
            "CAS rehash bounds or expected digest are invalid",
        ));
    }
    let identity = regular_identity(fd.as_raw_fd())?;
    if identity.size != expected_size || identity.links != 1 {
        return Err(PlanProtocolError::Invalid(
            "CAS rehash file identity differs from its manifest",
        ));
    }
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(duplicate) };
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = expected_size;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    while remaining != 0 {
        let maximum = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| {
                PlanProtocolError::Invalid("CAS rehash byte count overflow")
            })?;
        let count = file.read(&mut buffer[..maximum])?;
        if count == 0 {
            return Err(PlanProtocolError::Invalid(
                "CAS file became short during rehash",
            ));
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(PlanProtocolError::Invalid(
            "CAS file grew during rehash",
        ));
    }
    let actual: Digest = hasher.finalize().into();
    if &actual != expected_sha256 {
        return Err(PlanProtocolError::Invalid(
            "CAS file digest differs from its manifest",
        ));
    }
    Ok(actual)
}

fn enable_fs_verity_sha256(fd: &OwnedFd) -> PlanResult<()> {
    let argument = FsVerityEnableArg {
        hash_algorithm: FS_VERITY_HASH_ALG_SHA256 as u32,
        ..FsVerityEnableArg::default()
    };
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_ENABLE_VERITY,
            &argument as *const FsVerityEnableArg,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(PlanProtocolError::InvalidOwned(format!(
                "RequiredFsVerity could not enable fs-verity: {error}"
            )));
        }
    }
    Ok(())
}

fn measure_fs_verity_sha256(fd: &OwnedFd) -> PlanResult<Digest> {
    let mut measured = FsVerityDigestBuffer {
        header: FsVerityDigestHeader {
            digest_algorithm: 0,
            digest_size: FS_VERITY_MAX_DIGEST_BYTES as u16,
        },
        digest: [0; FS_VERITY_MAX_DIGEST_BYTES],
    };
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_MEASURE_VERITY,
            &mut measured as *mut FsVerityDigestBuffer,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        return Err(PlanProtocolError::InvalidOwned(format!(
            "RequiredFsVerity could not measure fs-verity: {error}"
        )));
    }
    if measured.header.digest_algorithm != FS_VERITY_HASH_ALG_SHA256
        || measured.header.digest_size as usize != mem::size_of::<Digest>()
    {
        return Err(PlanProtocolError::Invalid(
            "fs-verity returned a non-SHA-256 measurement",
        ));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&measured.digest[..32]);
    if digest == [0; 32] {
        return Err(PlanProtocolError::Invalid(
            "fs-verity returned an empty measurement",
        ));
    }
    Ok(digest)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationCleanupRecordV12 {
    version: String,
    operation_id: String,
    owner_identity_sha256: Digest,
    phase: String,
    observed_state: PublicationLifecycleStateV12,
    cleanup_boottime_ns: u64,
}

pub struct DirectoryCasStore {
    root: OwnedFd,
    journal_root: OwnedFd,
}

impl DirectoryCasStore {
    pub fn open(path: &Path) -> PlanResult<Self> {
        let root = open_absolute_directory(path)?;
        require_secure_directory(root.as_raw_fd(), false)?;
        if directory_identity(root.as_raw_fd())?.owner
            != unsafe { libc::geteuid() }
        {
            return Err(PlanProtocolError::Invalid(
                "CAS root is not owned by the executor identity",
            ));
        }
        let journal_root = open_relative_directory(
            root.as_raw_fd(),
            PUBLICATION_JOURNAL_DIRECTORY,
        )?;
        require_secure_directory(journal_root.as_raw_fd(), false)?;
        if directory_identity(journal_root.as_raw_fd())?.owner
            != unsafe { libc::geteuid() }
        {
            return Err(PlanProtocolError::Invalid(
                "CAS publication journal is not executor-owned",
            ));
        }
        Ok(Self { root, journal_root })
    }

    pub fn publish(
        &self,
        control: &PublicationControlV12,
        input: &AuthenticatedDirectoryInput,
        manifest: &FilesystemManifestV12,
        expected_domain: &str,
        trust: &ManifestTrustPolicy,
        object_sha256: Digest,
        metadata_name: &str,
        metadata: &[u8],
    ) -> PlanResult<PublishedDirectoryCas> {
        control.validate()?;
        validate_cas_sealing_capability_v12(
            &self.root,
            &control.sealing_policy,
        )?;
        manifest.validate(expected_domain, control, trust)?;
        if object_sha256 == [0; 32]
            || metadata_name.is_empty()
            || metadata_name.contains('/')
            || metadata_name.as_bytes().contains(&0)
            || metadata.len() > 16 * 1024 * 1024
        {
            return Err(PlanProtocolError::Invalid(
                "CAS publication metadata is invalid",
            ));
        }
        let staging_name =
            format!(".pending-{}", hex_digest(&control.operation_id));
        let prepared = append_publication_record(
            &self.journal_root,
            control,
            object_sha256,
            manifest.manifest_sha256,
            &staging_name,
            PublicationPhaseV12::Prepared,
            None,
            None,
        )?;
        return self.publish_in_worker(
            control,
            input,
            manifest,
            object_sha256,
            metadata_name,
            metadata,
            &staging_name,
            prepared,
        );
    }

    pub fn open_published_metadata(
        &self,
        object_sha256: &Digest,
        metadata_name: &str,
        maximum_metadata_bytes: u64,
    ) -> PlanResult<(OwnedFd, Vec<u8>)> {
        if object_sha256 == &[0; 32]
            || metadata_name.is_empty()
            || metadata_name.contains('/')
            || maximum_metadata_bytes == 0
        {
            return Err(PlanProtocolError::Invalid(
                "published CAS lookup is invalid",
            ));
        }
        let object = open_relative_directory(
            self.root.as_raw_fd(),
            &hex_digest(object_sha256),
        )?;
        require_secure_directory(object.as_raw_fd(), false)?;
        if directory_identity(object.as_raw_fd())?.owner
            != unsafe { libc::geteuid() }
        {
            return Err(PlanProtocolError::Invalid(
                "published CAS object is not executor-owned",
            ));
        }
        let metadata = open_relative_regular(
            object.as_raw_fd(),
            metadata_name,
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        )?;
        let identity = regular_identity(metadata.as_raw_fd())?;
        if identity.links != 1
            || identity.size == 0
            || identity.size > maximum_metadata_bytes
            || identity.mode & 0o022 != 0
        {
            return Err(PlanProtocolError::Invalid(
                "published CAS metadata identity is invalid",
            ));
        }
        let mut file = File::from(metadata);
        let mut bytes = Vec::with_capacity(identity.size as usize);
        std::io::Read::by_ref(&mut file)
            .take(maximum_metadata_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != identity.size
            || regular_identity(file.as_raw_fd())? != identity
        {
            return Err(PlanProtocolError::Invalid(
                "published CAS metadata changed while read",
            ));
        }
        Ok((object, bytes))
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_in_worker(
        &self,
        control: &PublicationControlV12,
        input: &AuthenticatedDirectoryInput,
        manifest: &FilesystemManifestV12,
        object_sha256: Digest,
        metadata_name: &str,
        metadata: &[u8],
        staging_name: &str,
        prepared_record_sha256: Digest,
    ) -> PlanResult<PublishedDirectoryCas> {
        let final_name = hex_digest(&object_sha256);
        let mut pidfd: RawFd = -1;
        let mut arguments = CloneArgs {
            flags: CLONE_PIDFD,
            pidfd: (&mut pidfd as *mut RawFd) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        let pid = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &mut arguments,
                mem::size_of::<CloneArgs>(),
            ) as libc::pid_t
        };
        if pid < 0 {
            append_publication_record(
                &self.journal_root,
                control,
                object_sha256,
                manifest.manifest_sha256,
                staging_name,
                PublicationPhaseV12::Failed,
                Some(prepared_record_sha256),
                None,
            )?;
            return Err(std::io::Error::last_os_error().into());
        }
        if pid == 0 {
            let child_result: PlanResult<bool> = (|| {
                append_publication_record(
                    &self.journal_root,
                    control,
                    object_sha256,
                    manifest.manifest_sha256,
                    staging_name,
                    PublicationPhaseV12::Copying,
                    Some(prepared_record_sha256),
                    None,
                )?;
                let published_new = if let Ok(existing) = open_relative_directory(
                    self.root.as_raw_fd(),
                    &final_name,
                ) {
                    verify_published_object(
                        existing.as_raw_fd(),
                        manifest,
                        metadata_name,
                        metadata,
                    )?;
                    collect_cas_sealing_evidence(
                        existing.as_raw_fd(),
                        manifest,
                        metadata_name,
                        metadata,
                        &control.sealing_policy,
                        false,
                    )?;
                    false
                } else {
                    let staging = create_named_staging_directory(
                        &self.root,
                        staging_name,
                    )?;
                    copy_manifest_entries(
                        input.as_raw_fd(),
                        staging.as_raw_fd(),
                        manifest,
                    )?;
                    write_metadata_file(
                        staging.as_raw_fd(),
                        metadata_name,
                        metadata,
                    )?;
                    collect_cas_sealing_evidence(
                        staging.as_raw_fd(),
                        manifest,
                        metadata_name,
                        metadata,
                        &control.sealing_policy,
                        true,
                    )?;
                    finalize_directory_tree(
                        staging.as_raw_fd(),
                        manifest,
                    )?;
                    fsync_fd(staging.as_raw_fd())?;
                    let published_new = rename_noreplace(
                        self.root.as_raw_fd(),
                        staging_name,
                        &final_name,
                    )?;
                    if !published_new {
                        remove_staging_tree(
                            self.root.as_raw_fd(),
                            staging_name,
                            manifest,
                            metadata_name,
                        )?;
                    }
                    fsync_fd(self.root.as_raw_fd())?;
                    published_new
                };
                Ok(published_new)
            })();
            unsafe {
                libc::_exit(match child_result {
                    Ok(true) => 0,
                    Ok(false) => 10,
                    Err(_) => 125,
                });
            }
        }
        let pidfd = if pidfd >= 0 {
            unsafe { OwnedFd::from_raw_fd(pidfd) }
        } else {
            return Err(PlanProtocolError::Invalid(
                "CAS publication worker lacks pidfd",
            ));
        };
        let worker_result = wait_worker_pidfd(
            pid,
            &pidfd,
            control.deadline_boottime_ns,
        );
        let worker_status = match worker_result {
            Ok(status) if matches!(status, 0 | 10) => status,
            Ok(_) => {
                let _ = remove_staging_tree(
                    self.root.as_raw_fd(),
                    staging_name,
                    manifest,
                    metadata_name,
                );
                let _ = append_publication_record(
                    &self.journal_root,
                    control,
                    object_sha256,
                    manifest.manifest_sha256,
                    staging_name,
                    PublicationPhaseV12::Failed,
                    Some(prepared_record_sha256),
                    None,
                );
                return Err(PlanProtocolError::Invalid(
                    "CAS publication worker failed",
                ));
            }
            Err(worker_error) => {
                let _ = kill_pidfd(&pidfd);
                let _ = wait_worker_pidfd(
                    pid,
                    &pidfd,
                    control.cleanup_deadline_boottime_ns,
                );
                let _ = remove_staging_tree(
                    self.root.as_raw_fd(),
                    staging_name,
                    manifest,
                    metadata_name,
                );
                let _ = append_publication_record(
                    &self.journal_root,
                    control,
                    object_sha256,
                    manifest.manifest_sha256,
                    staging_name,
                    PublicationPhaseV12::Failed,
                    Some(prepared_record_sha256),
                    None,
                );
                return Err(worker_error);
            }
        };
        let published = open_relative_directory(
            self.root.as_raw_fd(),
            &final_name,
        )?;
        let copying_record_sha256 = append_publication_record(
            &self.journal_root,
            control,
            object_sha256,
            manifest.manifest_sha256,
            staging_name,
            PublicationPhaseV12::Copying,
            Some(prepared_record_sha256),
            None,
        )?;
        let sealing_evidence = match (|| {
            verify_published_object(
                published.as_raw_fd(),
                manifest,
                metadata_name,
                metadata,
            )?;
            collect_cas_sealing_evidence(
                published.as_raw_fd(),
                manifest,
                metadata_name,
                metadata,
                &control.sealing_policy,
                false,
            )
        })() {
            Ok(evidence) => evidence,
            Err(error) => {
                let _ = append_publication_record(
                    &self.journal_root,
                    control,
                    object_sha256,
                    manifest.manifest_sha256,
                    staging_name,
                    PublicationPhaseV12::Failed,
                    Some(copying_record_sha256),
                    None,
                );
                return Err(error);
            }
        };
        append_publication_record(
            &self.journal_root,
            control,
            object_sha256,
            manifest.manifest_sha256,
            staging_name,
            PublicationPhaseV12::Published,
            Some(copying_record_sha256),
            Some(&sealing_evidence),
        )?;
        Ok(PublishedDirectoryCas {
            object_fd: published,
            object_sha256,
            manifest_sha256: manifest.manifest_sha256,
            sealing_evidence,
            published_new: worker_status == 0,
        })
    }
}

impl DirectoryCasStore {
    pub fn query_publication(
        &self,
        operation_id: &str,
    ) -> Result<PublicationLifecycleStateV12, CasError> {
        validate_component(operation_id)?;
        for (phase, state) in [
            ("CLEANUP_COMPLETE", PublicationLifecycleStateV12::CleanupComplete),
            ("CleanupComplete", PublicationLifecycleStateV12::CleanupComplete),
            ("PUBLISHED", PublicationLifecycleStateV12::Published),
            ("Published", PublicationLifecycleStateV12::Published),
            ("FAILED", PublicationLifecycleStateV12::Failed),
            ("Failed", PublicationLifecycleStateV12::Failed),
            ("COPYING", PublicationLifecycleStateV12::Copying),
            ("Copying", PublicationLifecycleStateV12::Copying),
            ("PREPARED", PublicationLifecycleStateV12::Prepared),
            ("Prepared", PublicationLifecycleStateV12::Prepared),
        ] {
            if journal_phase_exists(&self.journal_root, operation_id, phase)? {
                return Ok(state);
            }
        }
        Ok(PublicationLifecycleStateV12::Unknown)
    }

    pub fn reconcile_publication(
        &self,
        operation_id: &str,
        owner_identity_sha256: &Digest,
        cleanup_deadline_boottime_ns: u64,
    ) -> Result<PublicationLifecycleStateV12, CasError> {
        validate_component(operation_id)?;
        if owner_identity_sha256 == &[0; 32] {
            return Err(CasError::Invalid(
                "publication cleanup owner identity is empty",
            ));
        }
        let now = boottime_ns()?;
        if now > cleanup_deadline_boottime_ns {
            return Err(CasError::InvalidOwned(
                "publication cleanup reserve deadline has expired".into(),
            ));
        }
        let observed_state = self.query_publication(operation_id)?;
        let staging_name = format!(".pending-{operation_id}");
        match remove_tree_at(&self.root, &staging_name) {
            Ok(()) => fsync_fd(self.root.as_raw_fd())?,
            Err(error)
                if matches!(
                    &error,
                    CasError::Io(io_error)
                        if io_error.raw_os_error() == Some(libc::ENOENT)
                ) => {}
            Err(error) => return Err(error),
        }
        append_cleanup_record(
            &self.journal_root,
            &PublicationCleanupRecordV12 {
                version: "serverware/cas-publication-cleanup/v12".into(),
                operation_id: operation_id.into(),
                owner_identity_sha256: owner_identity_sha256.clone(),
                phase: "CleanupComplete".into(),
                observed_state,
                cleanup_boottime_ns: now,
            },
        )?;
        Ok(PublicationLifecycleStateV12::CleanupComplete)
    }
}

fn journal_phase_exists(
    journal_root: &OwnedFd,
    operation_id: &str,
    phase: &str,
) -> Result<bool, CasError> {
    let name = std::ffi::CString::new(format!("{operation_id}-{phase}.json"))
        .map_err(|_| CasError::Invalid("publication journal name contains NUL"))?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            journal_root.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        let stat = unsafe { stat.assume_init() };
        return Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFREG);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Ok(false);
    }
    Err(CasError::Io(error))
}

pub struct SourceCasStore {
    directory_store: DirectoryCasStore,
    trust: ManifestTrustPolicy,
}

impl SourceCasStore {
    pub fn open(
        path: &Path,
        trust: ManifestTrustPolicy,
    ) -> PlanResult<Self> {
        Ok(Self {
            directory_store: DirectoryCasStore::open(path)?,
            trust,
        })
    }

    pub fn publish(
        &self,
        input: AuthenticatedDirectoryInput,
        manifest: SourceManifestV12,
        control: &PublicationControlV12,
    ) -> PlanResult<PublishedSourceCas> {
        manifest.validate(control, &self.trust)?;
        if let Some(snapshot) = &manifest.provenance.native_snapshot {
            if directory_identity_digest(input.as_raw_fd())?
                != snapshot.source_root_identity_sha256
            {
                return Err(PlanProtocolError::Invalid(
                    "native snapshot retained FD identity differs from evidence",
                ));
            }
        }
        let metadata = canonical_bytes(&manifest)?;
        let published = self.directory_store.publish(
            control,
            &input,
            &manifest.filesystem,
            SOURCE_CAS_DOMAIN,
            &self.trust,
            manifest.source_object_sha256,
            SOURCE_METADATA_NAME,
            &metadata,
        )?;
        Ok(PublishedSourceCas {
            object_fd: published.object_fd,
            reference: manifest.reference(
                published.sealing_evidence.clone(),
            )?,
            manifest,
            sealing_evidence: published.sealing_evidence,
            published_new: published.published_new,
        })
    }
}

pub fn filesystem_manifest_digest(
    manifest: &FilesystemManifestV12,
) -> PlanResult<Digest> {
    let mut copy = manifest.clone();
    copy.manifest_sha256 = [0; 32];
    copy.signature.clear();
    Ok(sha256_bytes(&canonical_bytes(&copy)?))
}

pub fn source_object_digest(
    manifest_sha256: &Digest,
    provenance_sha256: &Digest,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_CAS_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(manifest_sha256);
    hasher.update(provenance_sha256);
    hasher.finalize().into()
}

pub fn filesystem_entries_digest(
    entries: &[FilesystemEntryV12],
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"serverware/filesystem-cas-entries/v12\0");
    for entry in entries {
        hasher.update(entry.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update([match entry.kind {
            FilesystemEntryKind::Directory => 0,
            FilesystemEntryKind::RegularFile => 1,
        }]);
        hasher.update(entry.mode.to_be_bytes());
        hasher.update(entry.size.to_be_bytes());
        hasher.update(entry.content_sha256);
    }
    hasher.finalize().into()
}

pub fn directory_identity_digest(fd: RawFd) -> PlanResult<Digest> {
    let identity = directory_identity(fd)?;
    let mut hasher = Sha256::new();
    hasher.update(b"serverware/retained-directory-identity/v12\0");
    hasher.update(identity.device.to_be_bytes());
    hasher.update(identity.inode.to_be_bytes());
    hasher.update(identity.mode.to_be_bytes());
    hasher.update(identity.owner.to_be_bytes());
    hasher.update(identity.links.to_be_bytes());
    hasher.update(identity.modified_sec.to_be_bytes());
    hasher.update(identity.modified_nsec.to_be_bytes());
    hasher.update(identity.changed_sec.to_be_bytes());
    hasher.update(identity.changed_nsec.to_be_bytes());
    Ok(hasher.finalize().into())
}

fn copy_manifest_entries(
    source_root: RawFd,
    destination_root: RawFd,
    manifest: &FilesystemManifestV12,
) -> PlanResult<()> {
    for entry in &manifest.entries {
        match entry.kind {
            FilesystemEntryKind::Directory => {
                let source_directory = open_relative_directory(
                    source_root,
                    &entry.relative_path,
                )?;
                if directory_identity(source_directory.as_raw_fd())?
                    .mode
                    & 0o777
                    != entry.mode
                {
                    return Err(PlanProtocolError::Invalid(
                        "source directory mode differs from manifest",
                    ));
                }
                mkdir_relative(
                    destination_root,
                    &entry.relative_path,
                    0o700,
                )?;
            }
            FilesystemEntryKind::RegularFile => {
                copy_regular_file(
                    source_root,
                    destination_root,
                    entry,
                )?;
            }
        }
    }
    Ok(())
}

fn copy_regular_file(
    source_root: RawFd,
    destination_root: RawFd,
    entry: &FilesystemEntryV12,
) -> PlanResult<()> {
    let source = open_relative_regular(
        source_root,
        &entry.relative_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    let before = regular_identity(source.as_raw_fd())?;
    if before.size != entry.size
        || before.mode & 0o777 != entry.mode
        || before.links != 1
    {
        return Err(PlanProtocolError::Invalid(
            "source file identity differs from manifest",
        ));
    }
    let destination = create_relative_regular(
        destination_root,
        &entry.relative_path,
        0o600,
    )?;
    let mut source_file = File::from(source);
    let mut destination_file = File::from(destination);
    let mut hasher = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = source_file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied.checked_add(count as u64).ok_or(
            PlanProtocolError::Invalid("source copy byte count overflow"),
        )?;
        if copied > entry.size {
            return Err(PlanProtocolError::Invalid(
                "source file grew during CAS copy",
            ));
        }
        hasher.update(&buffer[..count]);
        destination_file.write_all(&buffer[..count])?;
    }
    if copied != entry.size
        || <[u8; 32]>::from(hasher.finalize())
            != entry.content_sha256
    {
        return Err(PlanProtocolError::Invalid(
            "source file content differs from manifest",
        ));
    }
    destination_file.flush()?;
    if unsafe {
        libc::fchmod(
            destination_file.as_raw_fd(),
            entry.mode as libc::mode_t,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    fsync_fd(destination_file.as_raw_fd())?;
    let after = regular_identity(source_file.as_raw_fd())?;
    if before != after {
        return Err(PlanProtocolError::Invalid(
            "source file identity changed during CAS copy",
        ));
    }
    Ok(())
}

fn write_metadata_file(
    destination_root: RawFd,
    metadata_name: &str,
    metadata: &[u8],
) -> PlanResult<()> {
    let destination =
        create_relative_regular(destination_root, metadata_name, 0o600)?;
    let mut file = File::from(destination);
    file.write_all(metadata)?;
    file.flush()?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    fsync_fd(file.as_raw_fd())
}

fn finalize_directory_tree(
    destination_root: RawFd,
    manifest: &FilesystemManifestV12,
) -> PlanResult<()> {
    for entry in manifest.entries.iter().rev() {
        if entry.kind == FilesystemEntryKind::Directory {
            let directory = open_relative_directory(
                destination_root,
                &entry.relative_path,
            )?;
            fsync_fd(directory.as_raw_fd())?;
            if unsafe { libc::fchmod(directory.as_raw_fd(), 0o555) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    if unsafe { libc::fchmod(destination_root, 0o555) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn verify_published_object(
    object_root: RawFd,
    manifest: &FilesystemManifestV12,
    metadata_name: &str,
    expected_metadata: &[u8],
) -> PlanResult<()> {
    require_secure_directory(object_root, false)?;
    let metadata = open_relative_regular(
        object_root,
        metadata_name,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    let mut metadata_file = File::from(metadata);
    let mut actual_metadata =
        Vec::with_capacity(expected_metadata.len());
    std::io::Read::by_ref(&mut metadata_file)
        .take(expected_metadata.len() as u64 + 1)
        .read_to_end(&mut actual_metadata)?;
    if actual_metadata != expected_metadata {
        return Err(PlanProtocolError::Invalid(
            "existing CAS object metadata differs",
        ));
    }
    for entry in &manifest.entries {
        match entry.kind {
            FilesystemEntryKind::Directory => {
                let directory = open_relative_directory(
                    object_root,
                    &entry.relative_path,
                )?;
                let identity =
                    directory_identity(directory.as_raw_fd())?;
                if identity.mode & 0o777 != entry.mode {
                    return Err(PlanProtocolError::Invalid(
                        "published CAS directory mode differs",
                    ));
                }
            }
            FilesystemEntryKind::RegularFile => {
                let file = open_relative_regular(
                    object_root,
                    &entry.relative_path,
                    libc::O_RDONLY | libc::O_CLOEXEC,
                    0,
                )?;
                let identity = regular_identity(file.as_raw_fd())?;
                if identity.size != entry.size
                    || identity.mode & 0o777 != entry.mode
                    || identity.links != 1
                {
                    return Err(PlanProtocolError::Invalid(
                        "published CAS file identity differs",
                    ));
                }
                let mut file = File::from(file);
                file.seek(SeekFrom::Start(0))?;
                let mut hasher = Sha256::new();
                let mut copied = 0u64;
                let mut buffer = vec![0u8; 1024 * 1024];
                loop {
                    let count = file.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    copied = copied.checked_add(count as u64).ok_or(
                        PlanProtocolError::Invalid(
                            "published CAS byte count overflow",
                        ),
                    )?;
                    hasher.update(&buffer[..count]);
                }
                if copied != entry.size
                    || <[u8; 32]>::from(hasher.finalize())
                        != entry.content_sha256
                {
                    return Err(PlanProtocolError::Invalid(
                        "published CAS file content differs",
                    ));
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    size: u64,
    links: u64,
    modified_sec: i64,
    modified_nsec: i64,
    changed_sec: i64,
    changed_nsec: i64,
}

fn regular_identity(fd: RawFd) -> PlanResult<FileIdentity> {
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_size < 0
    {
        return Err(PlanProtocolError::Invalid(
            "CAS source is not a regular file",
        ));
    }
    Ok(FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        owner: stat.st_uid,
        size: stat.st_size as u64,
        links: stat.st_nlink,
        modified_sec: stat.st_mtime,
        modified_nsec: stat.st_mtime_nsec,
        changed_sec: stat.st_ctime,
        changed_nsec: stat.st_ctime_nsec,
    })
}

fn directory_identity(fd: RawFd) -> PlanResult<FileIdentity> {
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
    {
        return Err(PlanProtocolError::Invalid(
            "CAS object is not a directory",
        ));
    }
    Ok(FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        owner: stat.st_uid,
        size: stat.st_size.max(0) as u64,
        links: stat.st_nlink,
        modified_sec: stat.st_mtime,
        modified_nsec: stat.st_mtime_nsec,
        changed_sec: stat.st_ctime,
        changed_nsec: stat.st_ctime_nsec,
    })
}

fn require_secure_directory(fd: RawFd, require_root_owner: bool) -> PlanResult<()> {
    let identity = directory_identity(fd)?;
    if identity.mode & 0o022 != 0
        || (require_root_owner && identity.owner != 0)
    {
        return Err(PlanProtocolError::Invalid(
            "CAS directory ownership or mode is unsafe",
        ));
    }
    Ok(())
}

fn create_staging_directory(root: RawFd) -> PlanResult<String> {
    for _ in 0..32 {
        let suffix = random_digest()?;
        let name = format!(".pending-{}", hex_digest(&suffix));
        let c_name = c_string(&name)?;
        let result =
            unsafe { libc::mkdirat(root, c_name.as_ptr(), 0o700) };
        if result == 0 {
            return Ok(name);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error.into());
        }
    }
    Err(PlanProtocolError::Invalid(
        "CAS staging namespace is exhausted",
    ))
}

fn open_absolute_directory(path: &Path) -> PlanResult<OwnedFd> {
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
        return Err(PlanProtocolError::Invalid(
            "CAS root path is not canonical",
        ));
    }
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        PlanProtocolError::Invalid("CAS root path contains NUL")
    })?;
    openat2(
        libc::AT_FDCWD,
        &path,
        libc::O_RDONLY
            | libc::O_DIRECTORY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW,
        0,
        RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    )
}

fn open_relative_directory(root: RawFd, path: &str) -> PlanResult<OwnedFd> {
    validate_relative_path(path)?;
    openat2(
        root,
        &c_string(path)?,
        libc::O_RDONLY
            | libc::O_DIRECTORY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW,
        0,
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    )
}

fn open_relative_regular(
    root: RawFd,
    path: &str,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> PlanResult<OwnedFd> {
    validate_relative_path(path)?;
    openat2(
        root,
        &c_string(path)?,
        flags | libc::O_NOFOLLOW,
        mode,
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    )
}

fn create_relative_regular(
    root: RawFd,
    path: &str,
    mode: libc::mode_t,
) -> PlanResult<OwnedFd> {
    open_relative_regular(
        root,
        path,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        mode,
    )
}

fn mkdir_relative(
    root: RawFd,
    path: &str,
    mode: libc::mode_t,
) -> PlanResult<()> {
    validate_relative_path(path)?;
    let path = c_string(path)?;
    if unsafe { libc::mkdirat(root, path.as_ptr(), mode) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn openat2(
    root: RawFd,
    path: &CString,
    flags: libc::c_int,
    mode: libc::mode_t,
    resolve: u64,
) -> PlanResult<OwnedFd> {
    let how = OpenHow {
        flags: flags as u64,
        mode: mode as u64,
        resolve,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root,
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

fn rename_noreplace(
    root: RawFd,
    old_name: &str,
    new_name: &str,
) -> PlanResult<bool> {
    let old_name = c_string(old_name)?;
    let new_name = c_string(new_name)?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            root,
            old_name.as_ptr(),
            root,
            new_name.as_ptr(),
            RENAME_NOREPLACE,
        )
    } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            return Ok(false);
        }
        return Err(error.into());
    }
    Ok(true)
}

fn remove_staging_tree(
    root: RawFd,
    staging_name: &str,
    manifest: &FilesystemManifestV12,
    metadata_name: &str,
) -> PlanResult<()> {
    let staging =
        open_relative_directory(root, staging_name)?;
    for entry in &manifest.entries {
        if entry.kind == FilesystemEntryKind::Directory {
            let directory = open_relative_directory(
                staging.as_raw_fd(),
                &entry.relative_path,
            )?;
            if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    if unsafe { libc::fchmod(staging.as_raw_fd(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let metadata = c_string(metadata_name)?;
    let _ = unsafe {
        libc::unlinkat(staging.as_raw_fd(), metadata.as_ptr(), 0)
    };
    for entry in manifest.entries.iter().rev() {
        let path = c_string(&entry.relative_path)?;
        let flags = if entry.kind == FilesystemEntryKind::Directory {
            libc::AT_REMOVEDIR
        } else {
            0
        };
        let _ =
            unsafe { libc::unlinkat(staging.as_raw_fd(), path.as_ptr(), flags) };
    }
    drop(staging);
    let staging_name = c_string(staging_name)?;
    if unsafe {
        libc::unlinkat(root, staging_name.as_ptr(), libc::AT_REMOVEDIR)
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn fsync_fd(fd: RawFd) -> PlanResult<()> {
    if unsafe { libc::fsync(fd) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn publication_phase_component(phase: PublicationPhaseV12) -> &'static str {
    match phase {
        PublicationPhaseV12::Prepared => "Prepared",
        PublicationPhaseV12::Copying => "Copying",
        PublicationPhaseV12::Published => "Published",
        PublicationPhaseV12::Failed => "Failed",
        PublicationPhaseV12::CleanupComplete => "CleanupComplete",
    }
}

fn validate_staging_name(
    staging_name: &str,
    operation_id: &Digest,
) -> PlanResult<()> {
    let expected = format!(".pending-{}", hex_digest(operation_id));
    if staging_name != expected {
        return Err(PlanProtocolError::Invalid(
            "CAS staging name is not operation-derived",
        ));
    }
    validate_relative_path(staging_name)
}

fn validate_component(value: &str) -> PlanResult<()> {
    if value.is_empty()
        || value.len() > 255
        || value.as_bytes().contains(&0)
        || Path::new(value).components().count() != 1
        || !matches!(
            Path::new(value).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(PlanProtocolError::Invalid(
            "CAS name is not a safe path component",
        ));
    }
    Ok(())
}

fn mkdir_at(
    root: &OwnedFd,
    name: &str,
    mode: libc::mode_t,
) -> std::io::Result<()> {
    validate_component(name).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
    })?;
    let name = CString::new(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CAS directory name contains NUL",
        )
    })?;
    if unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), mode) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn remove_tree_at(root: &OwnedFd, name: &str) -> PlanResult<()> {
    validate_component(name)?;
    let directory = open_relative_directory(root.as_raw_fd(), name)?;
    let mut removed_entries = 0usize;
    remove_directory_contents(
        &directory,
        0,
        &mut removed_entries,
    )?;
    drop(directory);
    let name = c_string(name)?;
    if unsafe {
        libc::unlinkat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn remove_directory_contents(
    directory: &OwnedFd,
    depth: usize,
    removed_entries: &mut usize,
) -> PlanResult<()> {
    if depth >= MAX_DIRECTORY_DEPTH {
        return Err(PlanProtocolError::Invalid(
            "CAS cleanup directory depth is excessive",
        ));
    }
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let duplicate = unsafe {
        libc::fcntl(
            directory.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            0,
        )
    };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let mut names = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                duplicate.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if count == 0 {
            break;
        }
        let count = usize::try_from(count).map_err(|_| {
            PlanProtocolError::Invalid("CAS cleanup byte count overflow")
        })?;
        let mut offset = 0usize;
        while offset < count {
            if count - offset < 20 {
                return Err(PlanProtocolError::Invalid(
                    "CAS cleanup received a truncated directory entry",
                ));
            }
            let record_length = u16::from_ne_bytes([
                buffer[offset + 16],
                buffer[offset + 17],
            ]) as usize;
            if record_length < 20 || record_length > count - offset {
                return Err(PlanProtocolError::Invalid(
                    "CAS cleanup directory entry length is invalid",
                ));
            }
            let name_bytes = &buffer[offset + 19..offset + record_length];
            let name = CStr::from_bytes_until_nul(name_bytes)
                .map_err(|_| {
                    PlanProtocolError::Invalid(
                        "CAS cleanup directory entry has no terminator",
                    )
                })?
                .to_str()
                .map_err(|_| {
                    PlanProtocolError::Invalid(
                        "CAS cleanup directory entry is not UTF-8",
                    )
                })?;
            if name != "." && name != ".." {
                validate_component(name)?;
                *removed_entries = removed_entries.checked_add(1).ok_or(
                    PlanProtocolError::Invalid(
                        "CAS cleanup entry count overflow",
                    ),
                )?;
                if *removed_entries > MAX_REMOVE_ENTRIES {
                    return Err(PlanProtocolError::Invalid(
                        "CAS cleanup entry count is excessive",
                    ));
                }
                names.push(name.to_string());
            }
            offset += record_length;
        }
    }
    drop(duplicate);

    for name in names {
        let c_name = c_string(&name)?;
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let child =
                open_relative_directory(directory.as_raw_fd(), &name)?;
            remove_directory_contents(
                &child,
                depth + 1,
                removed_entries,
            )?;
            drop(child);
            if unsafe {
                libc::unlinkat(
                    directory.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        } else if unsafe {
            libc::unlinkat(directory.as_raw_fd(), c_name.as_ptr(), 0)
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn random_digest() -> PlanResult<Digest> {
    let mut digest = [0u8; 32];
    let result = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            digest.as_mut_ptr(),
            digest.len(),
            0,
        )
    };
    if result != digest.len() as libc::c_long || digest == [0; 32] {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(digest)
}

fn c_string(value: &str) -> PlanResult<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        PlanProtocolError::Invalid("CAS relative path contains NUL")
    })
}

fn hex_digest(digest: &Digest) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_relative_path(value: &str) -> PlanResult<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
        })
    {
        return Err(PlanProtocolError::Invalid(
            "CAS path is not canonical and relative",
        ));
    }
    Ok(())
}

fn require_declared_parent(
    path: &str,
    directories: &BTreeSet<String>,
) -> PlanResult<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let parent = parent.to_str().ok_or(
                PlanProtocolError::Invalid(
                    "CAS parent path is not UTF-8",
                ),
            )?;
            if !directories.contains(parent) {
                return Err(PlanProtocolError::Invalid(
                    "CAS entry parent is not declared first",
                ));
            }
        }
    }
    Ok(())
}

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::io::{self, Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use super::config::{
    CustodyAttestationProfile, CustodyServiceRole,
    GenerationBootstrapCredentialPaths,
    GenerationPublicCredentialPaths,
    ServiceRoleKeyDescriptorV1, SignedCustodyTopologyV1,
    ROUTER_READINESS_LOGICAL_ROLE,
    TRUSTED_HOST_FAULT_DOMAIN, TRUSTED_HOST_QUORUM_MODE,
};
use super::attestation::RoleSigningKey;
use super::protocol::{
    CustodyReadinessRecordV1, ServiceOperationV1,
    SignedServiceHandshakeV1, SERVICE_HANDSHAKE_API_VERSION,
};
use super::state::PostgresUdsBackend;
use super::V2RuntimeError;
use super::super::state_authority::canonical::{
    canonical_jcs_bytes, decode_base64url, encode_base64url,
    sha256_digest, signature_message, STATE_AUTHORITY_SIGNATURE_DOMAIN,
};
use super::super::state_authority::contract::{
    BootDeadline as AuthorityBootDeadline,
    Digest as AuthorityDigest, Identifier, PROVIDER_GENERATION_API_VERSION,
    PROVIDER_GENERATION_KIND, SIGNATURE_ALGORITHM,
    STATE_AUTHORITY_API_VERSION, STATE_AUTHORITY_GENERATION_RPC_KIND,
    STATE_AUTHORITY_GENERATION_RESULT_KIND,
    STATE_AUTHORITY_SCHEMA_VERSION,
};
use super::super::state_authority::rpc::{
    derive_generation_readiness_scope, sign_authority_artifact,
    verify_authority_artifact,
    AuthorityResultSigner, AuthoritySignerIdentity, FrameAuthentication,
    GenerationInstallMutation,
    GenerationMutationPayload, GenerationReadyMutation,
    GenerationReconcileMutation, GenerationRpcRequest,
    GenerationRpcRequestFrame, NestedAuthorityPayload, ResultDisposition,
    RoleReadinessArtifact, SignedAuthorityArtifact,
    SignedGenerationOperationResult, StateQueryMutation,
    RouterTopologyAttestationArtifact,
};
use super::super::state_authority::lifecycle::{
    OperationKind, ReconciliationState,
};
use super::super::state_authority::reconciliation::
    ReconciliationDomain;
use super::super::state_authority::postgres::{
    PgValue, PostgresBackend,
};
use super::super::state_authority::topology::{
    GenerationStatus, LogicalRoleBinding, ProviderGeneration,
    RoleIdentity as AuthorityRoleIdentity,
    ServiceRole as AuthorityServiceRole, TrustedHostTopology,
};

const PROVIDER_GENERATION_SIGNATURE_DOMAIN_NAME: &str =
    "serverware.responseV2.providerGeneration.signature/v1";
const PROVIDER_GENERATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.responseV2.providerGeneration.signature/v1";
const TOPOLOGY_MANIFEST_API_VERSION: &str =
    "serverware.responseV2.topologyManifest/v1";
const TOPOLOGY_MANIFEST_KIND: &str =
    "ServerwareResponseV2TopologyManifest";
const TOPOLOGY_MANIFEST_SIGNATURE_DOMAIN_NAME: &str =
    "serverware.responseV2.topologyManifest.signature/v1";
const TOPOLOGY_MANIFEST_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.responseV2.topologyManifest.signature/v1";
const TEE_VERIFICATION_REQUEST_API_VERSION: &str =
    "serverware.responseObservationV2AttestationVerifyRequest/v2";
const TEE_VERIFICATION_RESULT_API_VERSION: &str =
    "serverware.responseObservationV2AttestationVerifyResult/v2";
const TEE_GENERATION_REPORT_DOMAIN: &[u8] =
    b"serverware.response-v2/tee-generation-report/v1\0";
const NITRO_EVIDENCE_FORMAT: &str =
    "serverware.teeEvidence.nitroDocumentBundle.cbor/v1";
const LOCAL_TEE_TOPOLOGY_PROFILE: &str =
    "local-single-node-1-of-1";
#[cfg(target_os = "linux")]
const MAX_TEE_GENERATION_VERIFIER_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(target_os = "linux")]
const TEE_GENERATION_VERIFIER_TIMEOUT: Duration =
    Duration::from_secs(10);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeeGenerationExpectedV2<'a> {
    challenge_nonce: &'a str,
    enclave_instance_id: &'a str,
    enclave_boot_id: &'a str,
    generation_id: &'a str,
    provider_generation: u64,
    generation_sha256: &'a str,
    custody_topology_sha256: &'a str,
    process_identity_root_sha256: &'a str,
    role_identity_root_sha256: &'a str,
    proof_pins_root_sha256: &'a str,
    source_commit_sha256: &'a str,
    source_tree_sha256: &'a str,
    schema_bundle_sha256: &'a str,
    migration_sha256: &'a str,
    release_transparency_proof_sha256: &'a str,
    release_source_commit_sha256: &'a str,
    release_source_tree_sha256: &'a str,
    release_executable_sha256: &'a str,
    release_configuration_sha256: &'a str,
    trust_checkpoint_sha256: &'a str,
    verifier_executable_sha256: &'a str,
    verifier_module_sha256: Option<&'a str>,
    expectations_sha256: &'a str,
    trust_roots_sha256: &'a str,
    eif_sha384: &'a str,
    pcrs: &'a super::config::NitroPcrSetV1,
    attestation_mode: &'static str,
    topology_profile: &'static str,
    fault_domain_count: u32,
    quorum_threshold: u32,
    external_witness_count: u32,
    fault_tolerance: u32,
    hardware_proof: bool,
    maximum_evidence_age_ms: u64,
    maximum_future_skew_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeeGenerationVerificationResultV2 {
    api_version: String,
    ok: bool,
    purpose: String,
    claims: TeeGenerationVerificationClaimsV2,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeeGenerationVerificationClaimsV2 {
    challenge_nonce: String,
    enclave_instance_id: String,
    enclave_boot_id: String,
    generation_id: String,
    provider_generation: u64,
    generation_sha256: String,
    custody_topology_sha256: String,
    process_identity_root_sha256: String,
    role_identity_root_sha256: String,
    proof_pins_root_sha256: String,
    source_commit_sha256: String,
    source_tree_sha256: String,
    schema_bundle_sha256: String,
    migration_sha256: String,
    release_transparency_proof_sha256: String,
    release_source_commit_sha256: String,
    release_source_tree_sha256: String,
    release_executable_sha256: String,
    release_configuration_sha256: String,
    trust_checkpoint_sha256: String,
    verifier_executable_sha256: String,
    verifier_module_sha256: Option<String>,
    expectations_sha256: String,
    trust_roots_sha256: String,
    attestation_evidence_format: String,
    attestation_evidence_sha256: String,
    eif_sha384: String,
    pcrs: super::config::NitroPcrSetV1,
    report_data_sha256: String,
    attestation_mode: String,
    topology_profile: String,
    fault_domain_count: u32,
    quorum_threshold: u32,
    external_witness_count: u32,
    fault_tolerance: u32,
    hardware_proof: bool,
    hardware_backed: bool,
    quote_verified: bool,
    debug: bool,
    evidence_issued_at_epoch_ms: u64,
    verified_at_epoch_ms: u64,
    expires_at_epoch_ms: u64,
}

#[derive(Clone, Debug)]
struct PinnedGenerationVerifierCommand {
    executable: PathBuf,
    arguments: Vec<String>,
    expected_sha256: String,
}

fn validate_pinned_generation_verifier_path(
    command: &PinnedGenerationVerifierCommand,
) -> Result<(), String> {
    if !command.executable.is_absolute()
        || !command.arguments.is_empty()
        || !command.executable.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir
                    | std::path::Component::Normal(_)
            )
        })
        || !is_sha256(&command.expected_sha256)
    {
        return Err(
            "TEE generation verifier must be one normalized absolute descriptor-pinned executable with no arguments"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn generation_verifier_elf_u16(
    bytes: &[u8],
    offset: usize,
) -> Result<u16, String> {
    let raw: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or("TEE generation verifier has a truncated ELF header")?
        .try_into()
        .map_err(|_| {
            "TEE generation verifier has an invalid ELF header"
                .to_owned()
        })?;
    Ok(u16::from_le_bytes(raw))
}

#[cfg(target_os = "linux")]
fn generation_verifier_elf_u32(
    bytes: &[u8],
    offset: usize,
) -> Result<u32, String> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or("TEE generation verifier has a truncated ELF header")?
        .try_into()
        .map_err(|_| {
            "TEE generation verifier has an invalid ELF header"
                .to_owned()
        })?;
    Ok(u32::from_le_bytes(raw))
}

#[cfg(target_os = "linux")]
fn generation_verifier_elf_u64(
    bytes: &[u8],
    offset: usize,
) -> Result<u64, String> {
    let raw: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or("TEE generation verifier has a truncated ELF header")?
        .try_into()
        .map_err(|_| {
            "TEE generation verifier has an invalid ELF header"
                .to_owned()
        })?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(target_os = "linux")]
fn validate_static_amd64_generation_verifier(
    bytes: &[u8],
) -> Result<(), String> {
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;

    if bytes.len() < 64
        || &bytes[0..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || !matches!(generation_verifier_elf_u16(bytes, 16)?, 2 | 3)
        || generation_verifier_elf_u16(bytes, 18)? != 62
        || generation_verifier_elf_u32(bytes, 20)? != 1
    {
        return Err(
            "TEE generation verifier must be a little-endian static x86-64 ELF"
                .to_owned(),
        );
    }
    let program_offset = usize::try_from(
        generation_verifier_elf_u64(bytes, 32)?,
    )
    .map_err(|_| {
        "TEE generation verifier ELF program table is out of range"
            .to_owned()
    })?;
    let program_entry_bytes =
        usize::from(generation_verifier_elf_u16(bytes, 54)?);
    let program_entries =
        usize::from(generation_verifier_elf_u16(bytes, 56)?);
    if program_entry_bytes != 56 || !(1..=256).contains(&program_entries) {
        return Err(
            "TEE generation verifier has an invalid ELF program table"
                .to_owned(),
        );
    }
    let program_bytes = program_entry_bytes
        .checked_mul(program_entries)
        .and_then(|size| program_offset.checked_add(size))
        .ok_or("TEE generation verifier ELF program table overflows")?;
    if program_bytes > bytes.len() {
        return Err(
            "TEE generation verifier ELF program table is truncated"
                .to_owned(),
        );
    }
    let mut load_segment_seen = false;
    for index in 0..program_entries {
        let offset = program_offset + index * program_entry_bytes;
        let program_type = generation_verifier_elf_u32(bytes, offset)?;
        if program_type == PT_INTERP {
            return Err(
                "TEE generation verifier must not use a runtime interpreter"
                    .to_owned(),
            );
        }
        if program_type == PT_LOAD {
            load_segment_seen = true;
        }
        if program_type != PT_DYNAMIC {
            continue;
        }
        let dynamic_offset = usize::try_from(
            generation_verifier_elf_u64(bytes, offset + 8)?,
        )
        .map_err(|_| {
            "TEE generation verifier dynamic segment is out of range"
                .to_owned()
        })?;
        let dynamic_bytes = usize::try_from(
            generation_verifier_elf_u64(bytes, offset + 32)?,
        )
        .map_err(|_| {
            "TEE generation verifier dynamic segment is out of range"
                .to_owned()
        })?;
        let dynamic_end = dynamic_offset
            .checked_add(dynamic_bytes)
            .ok_or(
                "TEE generation verifier dynamic segment overflows",
            )?;
        if dynamic_bytes % 16 != 0 || dynamic_end > bytes.len() {
            return Err(
                "TEE generation verifier dynamic segment is invalid"
                    .to_owned(),
            );
        }
        for entry in (dynamic_offset..dynamic_end).step_by(16) {
            let tag = generation_verifier_elf_u64(bytes, entry)?;
            if tag == DT_NEEDED {
                return Err(
                    "TEE generation verifier must not load shared libraries"
                        .to_owned(),
                );
            }
            if tag == DT_NULL {
                break;
            }
        }
    }
    if !load_segment_seen {
        return Err(
            "TEE generation verifier ELF has no loadable segment"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_authenticated_generation_verifier_bytes(
    command: &PinnedGenerationVerifierCommand,
) -> Result<Vec<u8>, String> {
    validate_pinned_generation_verifier_path(command)?;
    let path_metadata = fs::symlink_metadata(&command.executable)
        .map_err(|error| {
            format!("inspect TEE generation verifier executable: {error}")
        })?;
    if path_metadata.file_type().is_symlink() {
        return Err(
            "TEE generation verifier executable must not be a symlink"
                .to_owned(),
        );
    }
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(
            libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
        .open(&command.executable)
        .map_err(|error| {
            format!(
                "open TEE generation verifier executable without following symlinks: {error}"
            )
        })?;
    let before = executable.metadata().map_err(|error| {
        format!("inspect opened TEE generation verifier: {error}")
    })?;
    if !before.file_type().is_file() {
        return Err(
            "TEE generation verifier executable must be a regular file"
                .to_owned(),
        );
    }
    if before.permissions().mode() & 0o111 == 0 {
        return Err(
            "TEE generation verifier executable is not executable"
                .to_owned(),
        );
    }
    if before.len() == 0
        || before.len() > MAX_TEE_GENERATION_VERIFIER_BYTES
    {
        return Err(format!(
            "TEE generation verifier executable must contain 1-{MAX_TEE_GENERATION_VERIFIER_BYTES} bytes"
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).unwrap_or(0),
    );
    Read::by_ref(&mut executable)
        .take(MAX_TEE_GENERATION_VERIFIER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!("read opened TEE generation verifier: {error}")
        })?;
    let after = executable.metadata().map_err(|error| {
        format!("reinspect opened TEE generation verifier: {error}")
    })?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(
            "TEE generation verifier executable changed while it was read"
                .to_owned(),
        );
    }
    let actual_sha256 =
        format!("sha256:{:x}", Sha256::digest(&bytes));
    if actual_sha256 != command.expected_sha256 {
        return Err(
            "TEE generation verifier executable SHA-256 mismatch"
                .to_owned(),
        );
    }
    validate_static_amd64_generation_verifier(&bytes)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn sealed_authenticated_generation_verifier_snapshot(
    command: &PinnedGenerationVerifierCommand,
) -> Result<File, String> {
    let bytes = read_authenticated_generation_verifier_bytes(command)?;
    let name = CString::new("serverware-tee-generation-verifier")
        .expect("static memfd name contains no NUL");
    let fd = unsafe {
        libc::memfd_create(
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(format!(
            "create sealed TEE generation verifier snapshot: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: memfd_create returned a new descriptor owned here.
    let mut snapshot = unsafe { File::from_raw_fd(fd) };
    snapshot
        .set_permissions(fs::Permissions::from_mode(0o500))
        .map_err(|error| {
            format!("mark TEE generation verifier snapshot executable: {error}")
        })?;
    snapshot.write_all(&bytes).map_err(|error| {
        format!("write TEE generation verifier snapshot: {error}")
    })?;
    snapshot.seek(SeekFrom::Start(0)).map_err(|error| {
        format!("reset TEE generation verifier snapshot: {error}")
    })?;
    let seals = libc::F_SEAL_SEAL
        | libc::F_SEAL_SHRINK
        | libc::F_SEAL_GROW
        | libc::F_SEAL_WRITE;
    if unsafe {
        libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, seals)
    } != 0
    {
        return Err(format!(
            "seal TEE generation verifier snapshot: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(snapshot)
}

fn run_pinned_bounded_generation_verifier(
    config: &super::RootOwnedResponseObservationV2Config,
    command: &PinnedGenerationVerifierCommand,
    request: &serde_json::Value,
    maximum_output_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let original_deadline = super::guest_delivery::verifier_deadline(config)
        .map_err(|error| error.to_string())?;
    validate_pinned_generation_verifier_path(command)?;
    if maximum_output_bytes == 0
        || maximum_output_bytes > 8 * 1024 * 1024
    {
        return Err(
            "TEE generation verifier output limit is outside the fixed 1-8388608 byte bound"
                .to_owned(),
        );
    }
    #[cfg(target_os = "linux")]
    {
        let snapshot =
            sealed_authenticated_generation_verifier_snapshot(command)?;
        let result = run_bounded_generation_verifier_snapshot(
            command,
            request,
            snapshot.as_raw_fd(),
            maximum_output_bytes,
            original_deadline,
        );
        drop(snapshot);
        result
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (request, maximum_output_bytes);
        Err(
            "descriptor-pinned TEE generation verifier execution requires Linux"
                .to_owned(),
        )
    }
}

#[cfg(target_os = "linux")]
fn run_bounded_generation_verifier_snapshot(
    command: &PinnedGenerationVerifierCommand,
    request: &serde_json::Value,
    executable_fd: std::os::fd::RawFd,
    maximum_output_bytes: usize,
    original_deadline: Option<u64>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let check_original_deadline = || -> Result<(), String> {
        if let Some(deadline) = original_deadline {
            if super::recovery::boottime_ns().map_err(|e| e.to_string())? >= deadline {
                return Err("original guest generation verification deadline expired".to_owned());
            }
        }
        Ok(())
    };
    check_original_deadline()?;
    let request_wire = Zeroizing::new(
        canonical_jcs_bytes(request).map_err(|_| {
            "serialize TEE generation verifier request".to_owned()
        })?,
    );
    let mut process = Command::new("/proc/self/exe");
    process
        .args(&command.arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let argv = std::iter::once(
        command
            .executable
            .to_str()
            .ok_or("TEE generation verifier path is not UTF-8")?
            .to_owned(),
    )
    .chain(command.arguments.iter().cloned())
    .map(|value| {
        CString::new(value).map_err(|_| {
            "TEE generation verifier argument contains an embedded NUL"
                .to_owned()
        })
    })
    .collect::<Result<Vec<_>, _>>()?;
    let argv_pointers = argv
        .iter()
        .map(|value| value.as_ptr() as usize)
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let environment = ["LANG=C", "LC_ALL=C", "TZ=UTC"]
        .into_iter()
        .map(|value| {
            CString::new(value).expect("fixed environment contains no NUL")
        })
        .collect::<Vec<_>>();
    let environment_pointers = environment
        .iter()
        .map(|value| value.as_ptr() as usize)
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    unsafe {
        process.pre_exec(move || {
            let _keep_storage_alive = (&argv, &environment);
            if libc::fcntl(executable_fd, libc::F_SETFD, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::syscall(
                libc::SYS_execveat,
                executable_fd,
                c"".as_ptr(),
                argv_pointers.as_ptr()
                    as *const *const libc::c_char,
                environment_pointers.as_ptr()
                    as *const *const libc::c_char,
                libc::AT_EMPTY_PATH,
            );
            Err(io::Error::last_os_error())
        });
    }
    check_original_deadline()?;
    let mut child = process.spawn().map_err(|error| {
        format!("start TEE generation verifier: {error}")
    })?;
    let deadline = Instant::now() + TEE_GENERATION_VERIFIER_TIMEOUT;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        terminate_generation_verifier_process_group(&mut child);
        "TEE generation verifier stdout unavailable".to_owned()
    })?;
    let mut child_stdin = child.stdin.take().ok_or_else(|| {
        terminate_generation_verifier_process_group(&mut child);
        "TEE generation verifier stdin unavailable".to_owned()
    })?;
    if let Err(error) = set_generation_verifier_nonblocking(
        child_stdin.as_raw_fd(),
        "stdin",
    )
    .and_then(|_| {
        set_generation_verifier_nonblocking(stdout.as_raw_fd(), "stdout")
    }) {
        terminate_generation_verifier_process_group(&mut child);
        return Err(error);
    }
    let mut child_stdin = Some(child_stdin);

    let result = (|| {
        let mut input_offset = 0usize;
        let mut input_complete = request_wire.is_empty();
        if input_complete {
            child_stdin.take();
        }
        let mut output_complete = false;
        let mut output = Zeroizing::new(Vec::with_capacity(
            maximum_output_bytes.min(64 * 1024),
        ));
        let mut status = None;
        let mut buffer = [0u8; 16 * 1024];
        let status = loop {
            if !input_complete {
                match child_stdin
                    .as_mut()
                    .expect("incomplete input retains verifier stdin")
                    .write(&request_wire[input_offset..])
                {
                    Ok(0) => {
                        return Err(
                            "TEE generation verifier closed stdin before the request was written"
                                .to_owned(),
                        )
                    }
                    Ok(written) => {
                        input_offset = input_offset.saturating_add(written);
                        input_complete = input_offset == request_wire.len();
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            || error.kind()
                                == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        return Err(
                            "write TEE generation verifier request"
                                .to_owned(),
                        )
                    }
                }
                if input_complete {
                    child_stdin.take();
                }
            }
            if !output_complete {
                match stdout.read(&mut buffer) {
                    Ok(0) => output_complete = true,
                    Ok(read) => {
                        if output.len().saturating_add(read)
                            > maximum_output_bytes
                        {
                            return Err(
                                "TEE generation verifier output is too large"
                                    .to_owned(),
                            );
                        }
                        output.extend_from_slice(&buffer[..read]);
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            || error.kind()
                                == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        return Err(
                            "read TEE generation verifier output"
                                .to_owned(),
                        )
                    }
                }
            }
            if status.is_none() {
                match child.try_wait() {
                    Ok(observed) => status = observed,
                    Err(error) => {
                        return Err(format!(
                            "wait for TEE generation verifier: {error}"
                        ));
                    }
                }
            }
            check_original_deadline()?;
            if input_complete && output_complete {
                if let Some(status) = status {
                    break status;
                }
            }
            if Instant::now() >= deadline {
                return Err(
                    "TEE generation verifier command timed out"
                        .to_owned(),
                );
            }
            thread::sleep(Duration::from_millis(10));
        };
        if !status.success() {
            return Err(
                "TEE generation verifier rejected request".to_owned(),
            );
        }
        if output.is_empty() {
            return Err(
                "TEE generation verifier produced no output".to_owned(),
            );
        }
        Ok(output)
    })();
    terminate_generation_verifier_process_group(&mut child);
    result
}

#[cfg(target_os = "linux")]
fn set_generation_verifier_nonblocking(
    fd: std::os::fd::RawFd,
    stream: &str,
) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0
        || unsafe {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK)
        } != 0
    {
        return Err(format!(
            "configure TEE generation verifier {stream}: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn terminate_generation_verifier_process_group(
    child: &mut std::process::Child,
) {
    let process_group = -(child.id() as i32);
    unsafe {
        libc::kill(process_group, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn decode_tee_generation_verifier_result(
    bytes: &[u8],
) -> Result<TeeGenerationVerificationResultV2, serde_json::Error> {
    if contains_integer_negative_zero(bytes) {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "integer -0 is not permitted in strict JSON",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let result =
        TeeGenerationVerificationResultV2::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(result)
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum IntegerNegativeZeroState {
    #[default]
    None,
    Minus,
    NegativeZero,
}

#[derive(Default)]
struct IntegerNegativeZeroDetector {
    in_string: bool,
    escaped: bool,
    state: IntegerNegativeZeroState,
}

impl IntegerNegativeZeroDetector {
    fn scan(&mut self, input: &[u8]) -> bool {
        input.iter().copied().any(|byte| self.scan_byte(byte))
    }

    fn finish(&self) -> bool {
        !self.in_string
            && self.state == IntegerNegativeZeroState::NegativeZero
    }

    fn scan_byte(&mut self, byte: u8) -> bool {
        if self.in_string {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.in_string = false;
            }
            return false;
        }
        match self.state {
            IntegerNegativeZeroState::None => {
                self.scan_value_start(byte)
            }
            IntegerNegativeZeroState::Minus => {
                self.state = IntegerNegativeZeroState::None;
                if byte == b'0' {
                    self.state =
                        IntegerNegativeZeroState::NegativeZero;
                    false
                } else {
                    self.scan_value_start(byte)
                }
            }
            IntegerNegativeZeroState::NegativeZero => {
                self.state = IntegerNegativeZeroState::None;
                if matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
                    || matches!(byte, b',' | b']' | b'}')
                {
                    true
                } else if matches!(byte, b'.' | b'e' | b'E') {
                    false
                } else {
                    self.scan_value_start(byte)
                }
            }
        }
    }

    fn scan_value_start(&mut self, byte: u8) -> bool {
        if byte == b'"' {
            self.in_string = true;
            self.escaped = false;
        } else if byte == b'-' {
            self.state = IntegerNegativeZeroState::Minus;
        }
        false
    }
}

fn contains_integer_negative_zero(input: &[u8]) -> bool {
    let mut detector = IntegerNegativeZeroDetector::default();
    detector.scan(input) || detector.finish()
}

const ROLE_MANIFEST_API_VERSION: &str =
    "serverware.responseV2.roleManifest/v1";
const ROLE_MANIFEST_KIND: &str = "ServerwareResponseV2RoleManifest";
const ROLE_MANIFEST_SIGNATURE_DOMAIN_NAME: &str =
    "serverware.responseV2.roleManifest.signature/v1";
const ROLE_MANIFEST_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.responseV2.roleManifest.signature/v1";
const KEY_MANIFEST_API_VERSION: &str =
    "serverware.responseV2.keyManifest/v1";
const KEY_MANIFEST_KIND: &str = "ServerwareResponseV2KeyManifest";
const KEY_MANIFEST_SIGNATURE_DOMAIN_NAME: &str =
    "serverware.responseV2.keyManifest.signature/v1";
const KEY_MANIFEST_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.responseV2.keyManifest.signature/v1";
const BOOTSTRAP_READINESS_API_VERSION: &str =
    "serverware.responseV2.generationBootstrapReadiness/v1";
const GENERATION_ACTIVATION_CONTEXT_API_VERSION: &str =
    "serverware.responseV2.generationActivationContext/v2";
const GENERATION_ACTIVATION_CONTEXT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.responseV2.generationActivationContext.signature/v2";
const GENERATION_ACTIVATION_TIMEOUT_ENV: &str =
    "SERVERWARE_RESPONSE_V2_GENERATION_ACTIVATION_TIMEOUT_MS";
const DEFAULT_GENERATION_ACTIVATION_TIMEOUT_MS: u64 = 120_000;
const MAX_GENERATION_ACTIVATION_TIMEOUT_MS: u64 = 600_000;
const MAX_BOOTSTRAP_CREDENTIAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationManifestAuthenticationV1 {
    pub algorithm: String,
    pub trust_anchor_key_id: Identifier,
    pub trust_anchor_public_key_sha256: AuthorityDigest,
    pub signing_domain: String,
    pub signed_payload_sha256: AuthorityDigest,
    pub signature_base64url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignedProviderGenerationCredentialV1 {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub generation_sha256: AuthorityDigest,
    pub predecessor_generation_id: Option<Identifier>,
    pub source_commit_sha256: AuthorityDigest,
    pub source_tree_sha256: AuthorityDigest,
    pub schema_bundle_sha256: AuthorityDigest,
    pub migration_sha256: AuthorityDigest,
    pub topology: TrustedHostTopology,
    pub rollback_floor: u64,
    pub not_before_epoch_millis: u64,
    pub not_after_epoch_millis: u64,
    pub authentication: GenerationManifestAuthenticationV1,
}

impl SignedProviderGenerationCredentialV1 {
    fn inner_generation(&self) -> ProviderGeneration {
        ProviderGeneration {
            api_version: self.api_version.clone(),
            kind: self.kind.clone(),
            schema_version: self.schema_version.clone(),
            generation_id: self.generation_id.clone(),
            predecessor_generation_id:
                self.predecessor_generation_id.clone(),
            source_commit_sha256: self.source_commit_sha256.clone(),
            source_tree_sha256: self.source_tree_sha256.clone(),
            schema_bundle_sha256: self.schema_bundle_sha256.clone(),
            migration_sha256: self.migration_sha256.clone(),
            topology: self.topology.clone(),
            rollback_floor: self.rollback_floor,
            not_before_epoch_millis: self.not_before_epoch_millis,
            not_after_epoch_millis: self.not_after_epoch_millis,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedTopologyManifestV1 {
    api_version: String,
    kind: String,
    schema_version: String,
    generation_id: Identifier,
    provider_generation_sha256: AuthorityDigest,
    topology: TrustedHostTopology,
    authentication: GenerationManifestAuthenticationV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedTopologyManifestV1<'a> {
    api_version: &'a str,
    kind: &'a str,
    schema_version: &'a str,
    generation_id: &'a Identifier,
    provider_generation_sha256: &'a AuthorityDigest,
    topology: &'a TrustedHostTopology,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedRoleManifestV1 {
    api_version: String,
    kind: String,
    schema_version: String,
    generation_id: Identifier,
    provider_generation_sha256: AuthorityDigest,
    topology_manifest_sha256: AuthorityDigest,
    roles: Vec<AuthorityRoleIdentity>,
    authentication: GenerationManifestAuthenticationV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedRoleManifestV1<'a> {
    api_version: &'a str,
    kind: &'a str,
    schema_version: &'a str,
    generation_id: &'a Identifier,
    provider_generation_sha256: &'a AuthorityDigest,
    topology_manifest_sha256: &'a AuthorityDigest,
    roles: &'a [AuthorityRoleIdentity],
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoleKeyManifestEntryV1 {
    role: AuthorityServiceRole,
    role_id: Identifier,
    key_id: Option<Identifier>,
    public_key_base64url: Option<String>,
    public_key_sha256: Option<AuthorityDigest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedKeyManifestV1 {
    api_version: String,
    kind: String,
    schema_version: String,
    generation_id: Identifier,
    provider_generation_sha256: AuthorityDigest,
    role_manifest_sha256: AuthorityDigest,
    role_keys: Vec<RoleKeyManifestEntryV1>,
    logical_role_bindings: Vec<LogicalRoleBinding>,
    authentication: GenerationManifestAuthenticationV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedKeyManifestV1<'a> {
    api_version: &'a str,
    kind: &'a str,
    schema_version: &'a str,
    generation_id: &'a Identifier,
    provider_generation_sha256: &'a AuthorityDigest,
    role_manifest_sha256: &'a AuthorityDigest,
    role_keys: &'a [RoleKeyManifestEntryV1],
    logical_role_bindings: &'a [LogicalRoleBinding],
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationBootstrapReadinessProofV1 {
    api_version: String,
    generation_id: Identifier,
    generation_sha256: AuthorityDigest,
    reconciliation_cursors: BTreeMap<String, u64>,
    signed_query_result: SignedGenerationOperationResult,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationActivationContextV1 {
    api_version: String,
    generation_id: Identifier,
    generation_sha256: AuthorityDigest,
    custody_topology_sha256: AuthorityDigest,
    topology_sha256: AuthorityDigest,
    reconciliation_checkpoint_sha256: AuthorityDigest,
    reconciliation_high_water: u64,
    readiness_contract_sha256: AuthorityDigest,
    activation_operation_id: Identifier,
    artifact_scope_id: Identifier,
    artifact_scope_revision: u64,
    artifact_scope_fence_token: Identifier,
    boot_id: Identifier,
    deadline_boot_millis: u64,
    issued_at_epoch_millis: u64,
    expires_at_epoch_millis: u64,
    authentication: GenerationActivationAuthenticationV1,
}

impl GenerationActivationContextV1 {
    fn without_authentication(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.authentication.signature_base64url.clear();
        unsigned.authentication.signed_payload_sha256 =
            AuthorityDigest(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_owned(),
            );
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationActivationAuthenticationV1 {
    algorithm: String,
    key_id: Identifier,
    public_key_base64url: String,
    signed_payload_sha256: AuthorityDigest,
    signature_base64url: String,
}

pub(crate) struct GenerationBootstrapReadiness {
    pub reconciliation_high_water: u64,
    pub reconciliation_state_sha256: String,
}

struct ReadinessArtifactSigner<'a> {
    key: &'a RoleSigningKey,
    identity: AuthoritySignerIdentity,
}

impl AuthorityResultSigner for ReadinessArtifactSigner<'_> {
    fn role_id(&self) -> &Identifier {
        &self.identity.role_id
    }

    fn key_id(&self) -> &Identifier {
        &self.identity.key_id
    }

    fn identity(&self) -> &AuthoritySignerIdentity {
        &self.identity
    }

    fn sign_digest(
        &self,
        digest: &[u8; 32],
        deadline: &AuthorityBootDeadline,
    ) -> super::super::state_authority::contract::AuthorityResult<Vec<u8>> {
        let boot_id =
            super::recovery::kernel_boot_id().map_err(|error| {
                super::super::state_authority::contract::AuthorityError::
                    Authentication {
                        code: "readiness_signer_boot_id_unavailable",
                        reason: error.to_string(),
                    }
            })?;
        let boot_millis = super::recovery::boottime_ns()
            .map_err(|error| {
                super::super::state_authority::contract::AuthorityError::
                    Authentication {
                        code: "readiness_signer_boottime_unavailable",
                        reason: error.to_string(),
                    }
            })?
            / 1_000_000;
        if deadline.clock != "CLOCK_BOOTTIME"
            || deadline.boot_id.0 != boot_id
            || deadline.deadline_boot_millis <= boot_millis
        {
            return Err(
                super::super::state_authority::contract::AuthorityError::
                    Authentication {
                        code: "readiness_signer_deadline_invalid",
                        reason: "readiness signer received an expired or foreign-boot deadline"
                            .to_owned(),
                    },
            );
        }
        Ok(self.key.sign_digest_bytes(digest))
    }
}

pub(crate) fn provision_generation_from_systemd_credentials(
    config: &super::RootOwnedResponseObservationV2Config,
) -> Result<GenerationBootstrapReadiness, V2RuntimeError> {
    super::guest_delivery::check(config)?;
    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    if unsafe { libc::geteuid() } != scoped.process.uid
        || unsafe { libc::getegid() } != scoped.process.gid
    {
        return Err(V2RuntimeError::new(
            "generation_bootstrap_identity_mismatch",
            "generation provisioner must run as the signed state-authority UID/GID",
        ));
    }
    let paths =
        GenerationBootstrapCredentialPaths::for_config(
            config,
            &scoped,
        )?;
    let descriptor = scoped
        .process
        .role_keys
        .iter()
        .find(|key| key.logical_role == "linearizable-store")
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_authority_key_missing",
                "signed state-authority process omits its linearizable-store key",
            )
        })?;
    let generation_authority_key = if config.guest_delivery.is_some() {
        super::guest_delivery::role_key(config, &scoped, descriptor)?
    } else { RoleSigningKey::load(
        &ServiceRoleKeyDescriptorV1 {
            logical_role: descriptor.logical_role.clone(),
            key_id: descriptor.key_id.clone(),
            public_key_sha256: descriptor.public_key_sha256.clone(),
            public_key_path: paths.trust_anchor_public_key.clone(),
            secret_key_path:
                paths.generation_authority_secret_key.clone(),
        },
        scoped.process.uid,
        scoped.process.gid,
    )? };
    let result = bootstrap_state_authority_generation(
        config,
        &generation_authority_key,
    )?;
    super::guest_delivery::check(config)?;
    Ok(result)
}

pub(crate) fn publish_service_generation_readiness(
    config: &super::RootOwnedResponseObservationV2Config,
    role: CustodyServiceRole,
) -> Result<(), V2RuntimeError> {
    super::guest_delivery::check(config)?;
    super::services::check_readiness(config, role)?;
    let scoped = config.scoped_service_config(role)?;
    let context = wait_for_generation_activation_context(config)?;
    let context_is_current =
        generation_activation_context_is_current(&context)?;
    verify_generation_activation_context(
        config,
        &context,
        context_is_current,
    )?;
    if !context_is_current {
        read_shared_regular_file(
            &config.generation_role_readiness_artifact_path(role)?,
            scoped.process.uid,
            scoped.process.gid,
            MAX_BOOTSTRAP_CREDENTIAL_BYTES,
            0o440,
        )?;
        if role == CustodyServiceRole::CustodyRouter {
            read_shared_regular_file(
                &config.generation_router_topology_attestation_path()?,
                scoped.process.uid,
                scoped.process.gid,
                MAX_BOOTSTRAP_CREDENTIAL_BYTES,
                0o440,
            )?;
        }
        return Ok(());
    }
    let record = read_service_readiness_record(config, role)?;
    if record.reconciliation_high_water
        < context.reconciliation_high_water
        || !record.reconciliation_complete
    {
        return Err(V2RuntimeError::new(
            "generation_role_readiness_stale",
            "service readiness predates the authoritative reconciliation checkpoint",
        ));
    }
    let logical_role = local_readiness_signer(role);
    let descriptor = scoped
        .process
        .role_keys
        .iter()
        .find(|candidate| candidate.logical_role == logical_role)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_role_readiness_key_missing",
                "service readiness key is absent from the signed topology",
            )
        })?;
    let key = super::guest_delivery::role_key(config, &scoped, descriptor)?;
    let artifact = sign_role_readiness_artifact(
        config,
        role,
        role,
        &scoped,
        &key,
        &context,
        descriptor,
        "service",
    )?;
    publish_shared_canonical_file(
        &config.generation_role_readiness_artifact_path(role)?,
        scoped.process.uid,
        scoped.process.gid,
        &artifact,
    )?;
    if role == CustodyServiceRole::CustodyRouter {
        publish_router_topology_attestation(
            config,
            &scoped,
            &key,
            descriptor,
            &context,
        )?;
    }
    Ok(())
}

pub(crate) fn activate_generation_from_systemd_credentials(
    config: &super::RootOwnedResponseObservationV2Config,
) -> Result<(), V2RuntimeError> {
    super::guest_delivery::check(config)?;
    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    if unsafe { libc::geteuid() } != scoped.process.uid
        || unsafe { libc::getegid() } != scoped.process.gid
    {
        return Err(V2RuntimeError::new(
            "generation_activation_identity_mismatch",
            "generation activation must run as the signed state-authority UID/GID",
        ));
    }
    let paths =
        GenerationBootstrapCredentialPaths::for_config(
            config,
            &scoped,
        )?;
    let descriptor = scoped
        .process
        .role_keys
        .iter()
        .find(|key| key.logical_role == "linearizable-store")
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_authority_key_missing",
                "signed state-authority process omits its linearizable-store key",
            )
        })?;
    let generation_authority_key = if config.guest_delivery.is_some() {
        super::guest_delivery::role_key(config, &scoped, descriptor)?
    } else { RoleSigningKey::load(
        &ServiceRoleKeyDescriptorV1 {
            logical_role: descriptor.logical_role.clone(),
            key_id: descriptor.key_id.clone(),
            public_key_sha256: descriptor.public_key_sha256.clone(),
            public_key_path: paths.trust_anchor_public_key.clone(),
            secret_key_path:
                paths.generation_authority_secret_key.clone(),
        },
        scoped.process.uid,
        scoped.process.gid,
    )? };
    let manifests = load_and_verify_bootstrap_manifests(
        config,
        &scoped,
        &paths,
        &generation_authority_key,
    )?;
    let proof = read_bootstrap_readiness_proof(
        &paths.readiness_proof,
        scoped.process.uid,
        scoped.process.gid,
    )?;
    let readiness =
        verify_bootstrap_readiness_proof(&proof, &manifests.generation)?;
    verify_live_reconciliation_cursors(config, &proof)?;
    let already_ready =
        proof.signed_query_result.body.generation_status
            == GenerationStatus::Ready;
    let trust_anchor = read_generation_trust_anchor(
        config,
        &paths.trust_anchor_public_key,
        scoped.process.uid,
        scoped.process.gid,
    )?;
    let reconciliation_checkpoint_sha256 =
        authoritative_reconciliation_checkpoint_sha256(config)?;
    let context = match read_existing_activation_context(config)? {
        Some(existing) => {
            verify_generation_activation_context(
                config,
                &existing,
                !already_ready,
            )?;
            if existing.generation_sha256
                    != manifests.generation_sha256
                || existing.topology_sha256
                    != sha256_digest(
                        &canonical_jcs_bytes(
                            &manifests.generation.topology,
                        )
                        .map_err(authority_contract_error)?,
                    )
                || existing.reconciliation_checkpoint_sha256
                    != reconciliation_checkpoint_sha256
                || existing.reconciliation_high_water
                    != readiness.reconciliation_high_water
                || existing.readiness_contract_sha256
                    != manifests
                        .generation
                        .topology
                        .readiness_contract
                        .contract_sha256
            {
                return Err(V2RuntimeError::new(
                    "generation_activation_context_conflict",
                    "existing activation context is bound to a different generation or reconciliation checkpoint",
                ));
            }
            existing
        }
        None if already_ready => {
            return Err(V2RuntimeError::new(
                "generation_ready_evidence_missing",
                "generation is already READY but has no immutable activation context and role-readiness evidence",
            ))
        }
        None => {
            let mut context = new_generation_activation_context(
                config,
                &manifests.generation,
                &manifests.generation_sha256,
                &readiness,
                &reconciliation_checkpoint_sha256,
            )?;
            sign_generation_activation_context(
                &mut context,
                &generation_authority_key,
                &trust_anchor,
            )?;
            publish_shared_canonical_file(
                &config.generation_activation_context_path()?,
                scoped.process.uid,
                scoped.process.gid,
                &context,
            )?;
            context
        }
    };
    let (role_artifacts, router_attestation) =
        collect_and_verify_generation_readiness(
            config,
            &manifests.generation,
            &context,
        )?;
    if !already_ready {
        mark_generation_ready(
            config,
            &generation_authority_key,
            &manifests.generation,
            &paths.generation_authority_secret_key,
            &context,
            role_artifacts,
            router_attestation,
        )?;
    }
    let state_identity = manifests
        .generation
        .role(AuthorityServiceRole::StateAuthority)
        .map_err(authority_contract_error)?;
    let mut sequence = 10_000u64;
    let query = execute_query(
        config,
        &generation_authority_key,
        state_identity,
        &manifests.generation,
        &paths.generation_authority_secret_key,
        &mut sequence,
    )?;
    if query.body.generation_status != GenerationStatus::Ready
        || !query.body.blockers.is_empty()
    {
        return Err(V2RuntimeError::new(
            "generation_activation_not_committed",
            "state authority did not report READY after the verified activation mutation",
        ));
    }
    let final_proof = GenerationBootstrapReadinessProofV1 {
        api_version: BOOTSTRAP_READINESS_API_VERSION.to_owned(),
        generation_id: manifests.generation.generation_id.clone(),
        generation_sha256: manifests.generation_sha256,
        reconciliation_cursors: proof.reconciliation_cursors,
        signed_query_result: query,
    };
    verify_bootstrap_readiness_proof(
        &final_proof,
        &manifests.generation,
    )?;
    publish_bootstrap_readiness_proof(
        &paths.readiness_proof,
        scoped.process.uid,
        scoped.process.gid,
        &final_proof,
    )
}

pub(crate) fn generation_activation_timeout_ms(
) -> Result<u64, V2RuntimeError> {
    let value = match std::env::var(GENERATION_ACTIVATION_TIMEOUT_ENV) {
        Ok(value) => value.parse::<u64>().map_err(|_| {
            V2RuntimeError::new(
                "generation_activation_timeout_invalid",
                "generation activation timeout is not an unsigned integer",
            )
        })?,
        Err(std::env::VarError::NotPresent) => {
            DEFAULT_GENERATION_ACTIVATION_TIMEOUT_MS
        }
        Err(_) => {
            return Err(V2RuntimeError::new(
                "generation_activation_timeout_invalid",
                "generation activation timeout is not valid UTF-8",
            ))
        }
    };
    if value == 0 || value > MAX_GENERATION_ACTIVATION_TIMEOUT_MS {
        return Err(V2RuntimeError::new(
            "generation_activation_timeout_invalid",
            "generation activation timeout must be between 1 and 600000 milliseconds",
        ));
    }
    Ok(value)
}

pub(crate) fn activation_timeout_ms(
    config: &super::RootOwnedResponseObservationV2Config,
) -> Result<u64, V2RuntimeError> {
    if config.guest_delivery.is_some() {
        // The guest has no environment-provided timeout authority.
        super::guest_delivery::timeout_ms(config, MAX_GENERATION_ACTIVATION_TIMEOUT_MS)
    } else {
        super::guest_delivery::require_host(config)?;
        generation_activation_timeout_ms()
    }
}

fn wait_for_generation_activation_context(
    config: &super::RootOwnedResponseObservationV2Config,
) -> Result<GenerationActivationContextV1, V2RuntimeError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(
            activation_timeout_ms(config)?,
        ))
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_activation_deadline_overflow",
                "generation activation wait deadline overflowed",
            )
        })?;
    loop {
        super::guest_delivery::check(config)?;
        if let Some(context) = read_existing_activation_context(config)? {
            super::guest_delivery::check(config)?;
            return Ok(context);
        }
        if Instant::now() >= deadline {
            return Err(V2RuntimeError::new(
                "generation_activation_context_timeout",
                "generation activation authority did not publish a context before the bounded deadline",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn read_existing_activation_context(
    config: &super::RootOwnedResponseObservationV2Config,
) -> Result<Option<GenerationActivationContextV1>, V2RuntimeError> {
    let path = config.generation_activation_context_path()?;
    let authority =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let bytes = match read_shared_regular_file(
        &path,
        authority.process.uid,
        authority.process.gid,
        MAX_BOOTSTRAP_CREDENTIAL_BYTES,
        0o440,
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error.code() == "generation_shared_file_unavailable"
                && !path.exists() =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let context = crate::decode_canonical_json(&bytes).map_err(|_| {
        V2RuntimeError::new(
            "generation_activation_context_invalid",
            "generation activation context is not canonical closed JSON",
        )
    })?;
    Ok(Some(context))
}

fn verify_generation_activation_context(
    config: &super::RootOwnedResponseObservationV2Config,
    context: &GenerationActivationContextV1,
    require_current: bool,
) -> Result<(), V2RuntimeError> {
    if let Some(owner) = &config.guest_delivery {
        if owner.deadline_millis(context.deadline_boot_millis)? != context.deadline_boot_millis {
            return Err(V2RuntimeError::new("guest_activation_context_refused",
                "guest startup requires a current activation context within the original delivery deadline"));
        }
    }
    let require_current = require_current || config.guest_delivery.is_some();
    let topology = config.custody_topology();
    let authority =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let descriptor = authority
        .process
        .role_keys
        .iter()
        .find(|candidate| candidate.logical_role == "linearizable-store")
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_activation_signer_missing",
                "state-authority has no signed linearizable-store key",
            )
        })?;
    let current_boot_id = super::recovery::kernel_boot_id()?;
    let current_boot_millis = super::recovery::boottime_ns()? / 1_000_000;
    let now = system_time_epoch_ms()?;
    if context.api_version != GENERATION_ACTIVATION_CONTEXT_API_VERSION
        || context.generation_id.0 != topology.generation_id
        || context.custody_topology_sha256.0
            != topology_sha256(topology)?
        || !is_sha256(&context.topology_sha256.0)
        || context.reconciliation_high_water == 0
        || !is_sha256(
            &context.reconciliation_checkpoint_sha256.0,
        )
        || !is_sha256(&context.readiness_contract_sha256.0)
        || context.artifact_scope_id.0.is_empty()
        || context.artifact_scope_fence_token.0.is_empty()
        || context.issued_at_epoch_millis == 0
        || context.issued_at_epoch_millis > now
        || context.expires_at_epoch_millis
            <= context.issued_at_epoch_millis
        || (require_current
            && (context.boot_id.0 != current_boot_id
                || context.deadline_boot_millis <= current_boot_millis
                || context.expires_at_epoch_millis <= now))
        || context.authentication.algorithm != SIGNATURE_ALGORITHM
        || context.authentication.key_id.0 != descriptor.key_id
    {
        return Err(V2RuntimeError::new(
            "generation_activation_context_binding_invalid",
            "activation context is not bound to the current generation, topology, reconciliation checkpoint, boot, deadline, and authority key",
        ));
    }
    let public_key = decode_base64url(
        "generationActivation.authentication.publicKeyBase64url",
        &context.authentication.public_key_base64url,
    )
    .map_err(authority_contract_error)?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        V2RuntimeError::new(
            "generation_activation_signer_invalid",
            "activation context public key is not 32 bytes",
        )
    })?;
    if format!("sha256:{:x}", Sha256::digest(public_key))
        != descriptor.public_key_sha256
    {
        return Err(V2RuntimeError::new(
            "generation_activation_signer_mismatch",
            "activation context public key differs from the signed state-authority assignment",
        ));
    }
    let unsigned = context.without_authentication();
    let canonical =
        canonical_jcs_bytes(&unsigned).map_err(authority_contract_error)?;
    let signed_payload_sha256 = sha256_digest(&canonical);
    if context.authentication.signed_payload_sha256
        != signed_payload_sha256
    {
        return Err(V2RuntimeError::new(
            "generation_activation_digest_mismatch",
            "activation context signature digest does not cover the canonical context",
        ));
    }
    let signature = decode_base64url(
        "generationActivation.authentication.signatureBase64url",
        &context.authentication.signature_base64url,
    )
    .map_err(authority_contract_error)?;
    let signature = Signature::from_slice(&signature).map_err(|_| {
        V2RuntimeError::new(
            "generation_activation_signature_invalid",
            "activation context signature is not 64 bytes",
        )
    })?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_activation_signer_invalid",
                "activation context public key is invalid",
            )
        })?
        .verify(
            &signature_message(
                GENERATION_ACTIVATION_CONTEXT_SIGNATURE_DOMAIN,
                &canonical,
            ),
            &signature,
        )
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_activation_signature_invalid",
                "activation context signature did not verify",
            )
        })
}

fn generation_activation_context_is_current(
    context: &GenerationActivationContextV1,
) -> Result<bool, V2RuntimeError> {
    Ok(context.boot_id.0 == super::recovery::kernel_boot_id()?
        && context.deadline_boot_millis
            > super::recovery::boottime_ns()? / 1_000_000
        && context.expires_at_epoch_millis > system_time_epoch_ms()?)
}

fn sign_generation_activation_context(
    context: &mut GenerationActivationContextV1,
    key: &RoleSigningKey,
    public_key: &[u8; 32],
) -> Result<(), V2RuntimeError> {
    context.authentication = GenerationActivationAuthenticationV1 {
        algorithm: SIGNATURE_ALGORITHM.to_owned(),
        key_id: Identifier(key.key_id().to_owned()),
        public_key_base64url: encode_base64url(public_key),
        signed_payload_sha256: AuthorityDigest(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
        ),
        signature_base64url: String::new(),
    };
    let canonical = canonical_jcs_bytes(&context.without_authentication())
        .map_err(authority_contract_error)?;
    context.authentication.signed_payload_sha256 =
        sha256_digest(&canonical);
    context.authentication.signature_base64url = encode_base64url(
        &key.sign_digest_bytes(&signature_message(
            GENERATION_ACTIVATION_CONTEXT_SIGNATURE_DOMAIN,
            &canonical,
        )),
    );
    Ok(())
}

fn read_service_readiness_record(
    config: &super::RootOwnedResponseObservationV2Config,
    role: CustodyServiceRole,
) -> Result<CustodyReadinessRecordV1, V2RuntimeError> {
    let scoped = config.scoped_service_config(role)?;
    let bytes = read_shared_regular_file(
        &scoped.process.readiness_record_path,
        scoped.process.uid,
        scoped.process.gid,
        MAX_BOOTSTRAP_CREDENTIAL_BYTES,
        0o640,
    )?;
    let record: CustodyReadinessRecordV1 =
        crate::decode_canonical_json(&bytes).map_err(|_| {
            V2RuntimeError::new(
                "generation_service_readiness_invalid",
                "service readiness record is not canonical closed JSON",
            )
        })?;
    if record.service_role != role
        || record.service_id != scoped.process.service_id
        || record.generation_id != scoped.generation_id
        || record.generation != scoped.generation
        || record.topology_sha256
            != topology_sha256(config.custody_topology())?
        || !record.reconciliation_complete
        || record.reconciliation_high_water == 0
    {
        return Err(V2RuntimeError::new(
            "generation_service_readiness_binding_invalid",
            "service readiness record does not bind the exact generation and completed reconciliation",
        ));
    }
    if role == CustodyServiceRole::CustodyRouter {
        if record.service_handshake.is_some()
            || record.dependency_handshakes.len() != 6
        {
            return Err(V2RuntimeError::new(
                "generation_router_readiness_invalid",
                "router readiness must aggregate exactly six role-signed dependency handshakes",
            ));
        }
        for (dependency_role, handshake) in
            &record.dependency_handshakes
        {
            if *dependency_role == CustodyServiceRole::CustodyRouter
                || handshake.service_role != *dependency_role
            {
                return Err(V2RuntimeError::new(
                    "generation_router_dependency_invalid",
                    "router readiness contains an unexpected dependency role",
                ));
            }
            validate_selected_handshake(
                config,
                handshake,
            )?;
        }
    } else {
        let handshake =
            record.service_handshake.as_ref().ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_service_handshake_missing",
                    "service readiness omits its role-signed handshake",
                )
            })?;
        validate_selected_handshake(
            config,
            handshake,
        )?;
        if handshake.service_role != role
            || handshake.reconciliation_high_water
                != record.reconciliation_high_water
            || handshake.reconciliation_state_sha256
                != record.reconciliation_state_sha256
        {
            return Err(V2RuntimeError::new(
                "generation_service_handshake_mismatch",
                "service handshake differs from its durable readiness record",
            ));
        }
    }
    Ok(record)
}

fn sign_role_readiness_artifact(
    _config: &super::RootOwnedResponseObservationV2Config,
    role: CustodyServiceRole,
    _payload_role: CustodyServiceRole,
    scoped: &super::config::ScopedCustodyServiceConfig,
    key: &RoleSigningKey,
    context: &GenerationActivationContextV1,
    descriptor: &ServiceRoleKeyDescriptorV1,
    artifact_label: &str,
) -> Result<SignedAuthorityArtifact, V2RuntimeError> {
    let authority_role = authority_service_role(role);
    sign_generation_readiness_artifact(
        scoped,
        key,
        context,
        descriptor,
        artifact_label,
        NestedAuthorityPayload::RoleReadiness(
            RoleReadinessArtifact {
                role: authority_role,
                role_id: Identifier(scoped.process.service_id.clone()),
                process_id: Identifier(
                    scoped.process.service_id.clone(),
                ),
                key_id: Some(Identifier(descriptor.key_id.clone())),
                reconciled_generation_id:
                    context.generation_id.clone(),
                reconciliation_checkpoint_sha256:
                    context
                        .reconciliation_checkpoint_sha256
                        .clone(),
            },
        ),
    )
}

fn sign_generation_readiness_artifact(
    scoped: &super::config::ScopedCustodyServiceConfig,
    key: &RoleSigningKey,
    context: &GenerationActivationContextV1,
    descriptor: &ServiceRoleKeyDescriptorV1,
    artifact_label: &str,
    payload: NestedAuthorityPayload,
) -> Result<SignedAuthorityArtifact, V2RuntimeError> {
    let authority_role = authority_service_role(scoped.role);
    let signer = ReadinessArtifactSigner {
        key,
        identity: AuthoritySignerIdentity {
            role_id: Identifier(scoped.process.service_id.clone()),
            process_id: Identifier(
                scoped.process.service_id.clone(),
            ),
            service_role: authority_role,
            logical_role: Identifier(
                descriptor.logical_role.clone(),
            ),
            key_id: Identifier(descriptor.key_id.clone()),
            key_material_sha256: AuthorityDigest(
                descriptor.public_key_sha256.clone(),
            ),
            executable_sha256: AuthorityDigest(
                scoped.process.executable_sha256.clone(),
            ),
            configuration_sha256: AuthorityDigest(
                scoped.process.configuration_sha256.clone(),
            ),
            allowed_operations:
                super::super::state_authority::services::
                    service_contract(authority_role)
                    .operations
                    .to_vec(),
        },
    };
    let artifact_id = deterministic_identifier(
        artifact_label,
        &[
            context.generation_id.0.as_bytes(),
            scoped.role.as_str().as_bytes(),
            context.activation_operation_id.0.as_bytes(),
            context.artifact_scope_fence_token.0.as_bytes(),
        ],
    );
    sign_authority_artifact(
        &signer,
        &context.generation_id,
        artifact_id,
        OperationKind::GenerationReady,
        &context.activation_operation_id,
        &context.artifact_scope_id,
        context.artifact_scope_revision,
        &context.artifact_scope_fence_token,
        context.issued_at_epoch_millis,
        context.expires_at_epoch_millis,
        payload,
        &AuthorityBootDeadline {
            clock: "CLOCK_BOOTTIME".to_owned(),
            boot_id: context.boot_id.clone(),
            deadline_boot_millis: context.deadline_boot_millis,
        },
    )
    .map_err(authority_contract_error)
}

fn publish_router_topology_attestation(
    config: &super::RootOwnedResponseObservationV2Config,
    router: &super::config::ScopedCustodyServiceConfig,
    key: &RoleSigningKey,
    descriptor: &ServiceRoleKeyDescriptorV1,
    context: &GenerationActivationContextV1,
) -> Result<(), V2RuntimeError> {
    let router_record =
        read_service_readiness_record(
            config,
            CustodyServiceRole::CustodyRouter,
        )?;
    if router_record.reconciliation_high_water
        < context.reconciliation_high_water
    {
        return Err(V2RuntimeError::new(
            "generation_router_reconciliation_stale",
            "router topology observation predates the activation reconciliation checkpoint",
        ));
    }
    let role_artifacts = collect_unsigned_role_readiness_set(
        config,
        context,
    )?;
    let role_readiness_root_sha256 = sha256_digest(
        &canonical_jcs_bytes(&role_artifacts)
            .map_err(authority_contract_error)?,
    );
    let artifact = sign_generation_readiness_artifact(
        router,
        key,
        context,
        descriptor,
        "router-topology",
        NestedAuthorityPayload::RouterTopologyAttestation(
            RouterTopologyAttestationArtifact {
                router_role_id: Identifier(
                    router.process.service_id.clone(),
                ),
                router_process_id: Identifier(
                    router.process.service_id.clone(),
                ),
                router_key_id: Identifier(descriptor.key_id.clone()),
                reconciled_generation_id:
                    context.generation_id.clone(),
                topology_sha256: context.topology_sha256.clone(),
                readiness_contract_sha256:
                    context.readiness_contract_sha256.clone(),
                reconciliation_checkpoint_sha256:
                    context
                        .reconciliation_checkpoint_sha256
                        .clone(),
                role_readiness_root_sha256,
            },
        ),
    )?;
    publish_shared_canonical_file(
        &config.generation_router_topology_attestation_path()?,
        router.process.uid,
        router.process.gid,
        &artifact,
    )
}

fn collect_unsigned_role_readiness_set(
    config: &super::RootOwnedResponseObservationV2Config,
    context: &GenerationActivationContextV1,
) -> Result<Vec<SignedAuthorityArtifact>, V2RuntimeError> {
    let mut artifacts = Vec::with_capacity(
        CustodyServiceRole::ALL.len(),
    );
    let mut artifact_ids = BTreeSet::new();
    for role in CustodyServiceRole::ALL {
        let scoped = config.scoped_service_config(role)?;
        let artifact = wait_for_signed_readiness_artifact(
            config,
            &config.generation_role_readiness_artifact_path(role)?,
            scoped.process.uid,
            scoped.process.gid,
            context.deadline_boot_millis,
        )?;
        if artifact.body.generation_id != context.generation_id
            || artifact.body.operation != OperationKind::GenerationReady
            || artifact.body.operation_id
                != context.activation_operation_id
            || artifact.body.attempt_id != context.artifact_scope_id
            || artifact.body.attempt_revision
                != context.artifact_scope_revision
            || artifact.body.fence_token
                != context.artifact_scope_fence_token
            || !artifact_ids.insert(artifact.body.artifact_id.clone())
        {
            return Err(V2RuntimeError::new(
                "generation_router_readiness_set_invalid",
                "router observed a duplicated or incorrectly scoped readiness artifact",
            ));
        }
        match &artifact.body.payload {
            NestedAuthorityPayload::RoleReadiness(readiness)
                if readiness.role == authority_service_role(role)
                    && readiness.role_id.0
                        == scoped.process.service_id
                    && readiness.process_id.0
                        == scoped.process.service_id
                    && readiness.key_id.as_ref().map(|id| id.0.as_str())
                        == Some(artifact.body.key_id.0.as_str())
                    && readiness.reconciled_generation_id
                        == context.generation_id
                    && readiness.reconciliation_checkpoint_sha256
                        == context
                            .reconciliation_checkpoint_sha256 => {}
            _ => {
                return Err(V2RuntimeError::new(
                    "generation_router_readiness_set_invalid",
                    format!(
                        "{} readiness artifact does not bind its exact role and reconciliation checkpoint",
                        role.as_str()
                    ),
                ))
            }
        }
        artifacts.push(artifact);
    }
    Ok(artifacts)
}

fn wait_for_live_service(
    config: &super::RootOwnedResponseObservationV2Config,
    role: CustodyServiceRole,
    deadline_boot_millis: u64,
) -> Result<(), V2RuntimeError> {
    loop {
        super::guest_delivery::check(config)?;
        if config.guest_delivery.is_some() && super::recovery::boottime_ns()? / 1_000_000 >= deadline_boot_millis {
            return Err(V2RuntimeError::new("guest_readiness_timeout", "original activation deadline expired"));
        }
        match super::services::check_readiness(config, role) {
            Ok(()) => { super::guest_delivery::check(config)?; return Ok(()); }
            Err(error) => {
                if super::recovery::boottime_ns()? / 1_000_000
                    >= deadline_boot_millis
                {
                    return Err(V2RuntimeError::new(
                        "generation_service_readiness_timeout",
                        format!(
                            "{} did not become live before activation deadline: {}",
                            role.as_str(),
                            error
                        ),
                    ));
                }
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn authoritative_reconciliation_checkpoint_sha256(
    config: &super::RootOwnedResponseObservationV2Config,
) -> Result<AuthorityDigest, V2RuntimeError> {
    use super::super::state_authority::postgres::statements;

    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let backend_socket = scoped
        .process
        .backend_socket_path
        .as_deref()
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_activation_backend_missing",
                "state-authority process omits its signed PostgreSQL socket",
            )
        })?;
    let timeout_ms = super::guest_delivery::bounded_timeout_ms(config, scoped.process.request_timeout_ms)?;
    let backend = PostgresUdsBackend::from_signed_backend_socket(
        backend_socket,
        &scoped.process.service_id,
        Duration::from_millis(timeout_ms),
    )
    .map_err(authority_contract_error)?;
    let mut deadline = AuthorityBootDeadline {
        clock: "CLOCK_BOOTTIME".to_owned(),
        boot_id: Identifier(super::recovery::kernel_boot_id()?),
        deadline_boot_millis: (super::recovery::boottime_ns()?
            / 1_000_000)
            .checked_add(timeout_ms)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_activation_deadline_overflow",
                    "reconciliation checkpoint deadline overflowed",
                )
            })?,
    };
    if let Some(owner) = &config.guest_delivery {
        deadline.deadline_boot_millis = owner.deadline_millis(deadline.deadline_boot_millis)?;
    }
    let mut transaction = backend
        .begin_serializable(&deadline)
        .map_err(authority_contract_error)?;
    let rows = transaction
        .query_many(
            statements::GENERATION_RECONCILIATION_STATUS_SQL,
            &[PgValue::Text(scoped.generation_id)],
        )
        .map_err(authority_contract_error)?;
    let checkpoint = rows
        .iter()
        .map(|row| {
            Ok((
                row.require_text("domain")
                    .map_err(authority_contract_error)?,
                row.require_text("state")
                    .map_err(authority_contract_error)?,
                row.require_u64("authoritative_cursor")
                    .map_err(authority_contract_error)?,
                row.optional_text("blocker_code")
                    .map_err(authority_contract_error)?,
                row.optional_text("result_sha256")
                    .map_err(authority_contract_error)?,
            ))
        })
        .collect::<Result<Vec<_>, V2RuntimeError>>()?;
    if checkpoint.len() != ReconciliationDomain::REQUIRED.len()
        || checkpoint
            .iter()
            .any(|(_, state, cursor, blocker, result)| {
                state != "COMPLETE"
                    || *cursor == 0
                    || blocker.is_some()
                    || result.is_none()
            })
    {
        return Err(V2RuntimeError::new(
            "generation_activation_checkpoint_incomplete",
            "authoritative generation reconciliation rows are not the exact completed domain set",
        ));
    }
    let digest = sha256_digest(
        &canonical_jcs_bytes(&checkpoint)
            .map_err(authority_contract_error)?,
    );
    transaction
        .commit(&deadline)
        .map_err(authority_contract_error)?;
    Ok(digest)
}

fn new_generation_activation_context(
    config: &super::RootOwnedResponseObservationV2Config,
    generation: &ProviderGeneration,
    generation_sha256: &AuthorityDigest,
    readiness: &GenerationBootstrapReadiness,
    reconciliation_checkpoint_sha256: &AuthorityDigest,
) -> Result<GenerationActivationContextV1, V2RuntimeError> {
    let timeout_ms = activation_timeout_ms(config)?;
    let boot_id = Identifier(super::recovery::kernel_boot_id()?);
    let now_boot_millis = super::recovery::boottime_ns()? / 1_000_000;
    let deadline_boot_millis = now_boot_millis
        .checked_add(timeout_ms)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_activation_deadline_overflow",
                "generation activation CLOCK_BOOTTIME deadline overflowed",
            )
        })?;
    let deadline_boot_millis = match &config.guest_delivery {
        Some(owner) => owner.deadline_millis(deadline_boot_millis)?,
        None => deadline_boot_millis,
    };
    let timeout_ms = deadline_boot_millis.saturating_sub(now_boot_millis);
    let activation_operation_id = deterministic_identifier(
        "generation-activation-ready",
        &[generation.generation_id.0.as_bytes()],
    );
    let artifact_scope = derive_generation_readiness_scope(
        generation,
        reconciliation_checkpoint_sha256,
    )
    .map_err(authority_contract_error)?;
    let now = system_time_epoch_ms()?;
    let expires_at_epoch_millis =
        now.checked_add(timeout_ms).ok_or_else(|| {
            V2RuntimeError::new(
                "generation_activation_expiry_overflow",
                "generation activation wall-clock expiry overflowed",
            )
        })?;
    Ok(GenerationActivationContextV1 {
        api_version: GENERATION_ACTIVATION_CONTEXT_API_VERSION.to_owned(),
        generation_id: generation.generation_id.clone(),
        generation_sha256: generation_sha256.clone(),
        custody_topology_sha256: AuthorityDigest(topology_sha256(
            config.custody_topology(),
        )?),
        topology_sha256: sha256_digest(
            &canonical_jcs_bytes(&generation.topology)
                .map_err(authority_contract_error)?,
        ),
        reconciliation_checkpoint_sha256:
            reconciliation_checkpoint_sha256.clone(),
        reconciliation_high_water:
            readiness.reconciliation_high_water,
        readiness_contract_sha256:
            generation
                .topology
                .readiness_contract
                .contract_sha256
                .clone(),
        activation_operation_id,
        artifact_scope_id: artifact_scope.attempt_id,
        artifact_scope_revision: artifact_scope.attempt_revision,
        artifact_scope_fence_token: artifact_scope.fence_token,
        boot_id,
        deadline_boot_millis,
        issued_at_epoch_millis: now,
        expires_at_epoch_millis,
        authentication: GenerationActivationAuthenticationV1 {
            algorithm: String::new(),
            key_id: Identifier(String::new()),
            public_key_base64url: String::new(),
            signed_payload_sha256: AuthorityDigest(String::new()),
            signature_base64url: String::new(),
        },
    })
}

fn mark_generation_ready(
    config: &super::RootOwnedResponseObservationV2Config,
    key: &RoleSigningKey,
    generation: &ProviderGeneration,
    result_credential_path: &Path,
    context: &GenerationActivationContextV1,
    role_artifacts: Vec<SignedAuthorityArtifact>,
    router_topology_attestation: SignedAuthorityArtifact,
) -> Result<(), V2RuntimeError> {
    let caller = generation
        .role(AuthorityServiceRole::StateAuthority)
        .map_err(authority_contract_error)?;
    let mut expected_artifact_ids = role_artifacts
        .iter()
        .map(|artifact| artifact.body.artifact_id.clone())
        .collect::<BTreeSet<_>>();
    expected_artifact_ids.insert(
        router_topology_attestation.body.artifact_id.clone(),
    );
    let frame = signed_generation_activation_frame(
        key,
        caller,
        context,
        GenerationMutationPayload::MarkReady(
            GenerationReadyMutation {
                reconciliation_checkpoint_sha256:
                    context
                        .reconciliation_checkpoint_sha256
                        .clone(),
                role_readiness_artifacts: role_artifacts,
                router_topology_attestation,
            },
        ),
    )?;
    let exact = super::services::execute_generation_postgres(
        config,
        &frame,
        key,
        result_credential_path,
    )?;
    let result = verify_generation_result(
        &exact.canonical_bytes,
        &frame,
        generation,
        caller,
    )?;
    let result_artifact_ids = result
        .body
        .result_artifact_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if result.body.operation != OperationKind::GenerationReady
        || result.body.disposition != ResultDisposition::Applied
        || result.body.predecessor_generation_status
            != Some(GenerationStatus::Reconciling)
        || result.body.generation_status != GenerationStatus::Ready
        || !result.body.blockers.is_empty()
        || expected_artifact_ids.len()
            != CustodyServiceRole::ALL.len() + 1
        || result_artifact_ids != expected_artifact_ids
        || result.body.result_artifact_ids.len()
            != expected_artifact_ids.len()
    {
        return Err(V2RuntimeError::new(
            "generation_activation_result_invalid",
            "state authority did not commit the exact generation-scoped READY mutation and eight signed readiness artifacts",
        ));
    }
    Ok(())
}

fn signed_generation_activation_frame(
    key: &RoleSigningKey,
    caller: &AuthorityRoleIdentity,
    context: &GenerationActivationContextV1,
    payload: GenerationMutationPayload,
) -> Result<GenerationRpcRequestFrame, V2RuntimeError> {
    if caller
        .key_id
        .as_ref()
        .map(|key_id| key_id.0.as_str())
        != Some(key.key_id())
        || payload.operation() != OperationKind::GenerationReady
    {
        return Err(V2RuntimeError::new(
            "generation_activation_signer_mismatch",
            "generation READY frame signer or operation is not the installed state-authority assignment",
        ));
    }
    let request_id = deterministic_identifier(
        "generation-activation-ready-request",
        &[
            context.generation_id.0.as_bytes(),
            context.activation_operation_id.0.as_bytes(),
        ],
    );
    let request = GenerationRpcRequest {
        api_version: STATE_AUTHORITY_API_VERSION.to_owned(),
        kind: STATE_AUTHORITY_GENERATION_RPC_KIND.to_owned(),
        schema_version: STATE_AUTHORITY_SCHEMA_VERSION.to_owned(),
        generation_id: context.generation_id.clone(),
        request_id,
        operation_id: context.activation_operation_id.clone(),
        caller_role_id: caller.role_id.clone(),
        operation: OperationKind::GenerationReady,
        deadline: AuthorityBootDeadline {
            clock: "CLOCK_BOOTTIME".to_owned(),
            boot_id: context.boot_id.clone(),
            deadline_boot_millis: context.deadline_boot_millis,
        },
        payload,
    };
    request.validate().map_err(authority_contract_error)?;
    let canonical =
        canonical_jcs_bytes(&request).map_err(authority_contract_error)?;
    let signed_payload_sha256 = sha256_digest(&canonical);
    let signature = key.sign_digest_bytes(&signature_message(
        STATE_AUTHORITY_SIGNATURE_DOMAIN,
        &canonical,
    ));
    Ok(GenerationRpcRequestFrame {
        request,
        authentication: FrameAuthentication {
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            key_id: Identifier(key.key_id().to_owned()),
            signed_payload_sha256,
            signature_base64url: encode_base64url(&signature),
        },
    })
}

fn collect_and_verify_generation_readiness(
    config: &super::RootOwnedResponseObservationV2Config,
    generation: &ProviderGeneration,
    context: &GenerationActivationContextV1,
) -> Result<
    (Vec<SignedAuthorityArtifact>, SignedAuthorityArtifact),
    V2RuntimeError,
> {
    for role in CustodyServiceRole::ALL {
        wait_for_live_service(
            config,
            role,
            context.deadline_boot_millis,
        )?;
    }
    let mut artifacts = Vec::with_capacity(
        CustodyServiceRole::ALL.len(),
    );
    let mut artifact_ids = BTreeSet::new();
    for role in CustodyServiceRole::ALL {
        let scoped = config.scoped_service_config(role)?;
        let artifact = wait_for_signed_readiness_artifact(
            config,
            &config.generation_role_readiness_artifact_path(role)?,
            scoped.process.uid,
            scoped.process.gid,
            context.deadline_boot_millis,
        )?;
        verify_authority_artifact(
            &artifact,
            generation,
            authority_service_role(role),
            OperationKind::GenerationReady,
            &context.activation_operation_id,
            &context.artifact_scope_id,
            context.artifact_scope_revision,
            &context.artifact_scope_fence_token,
        )
        .map_err(authority_contract_error)?;
        match &artifact.body.payload {
            NestedAuthorityPayload::RoleReadiness(readiness)
                if readiness.role == authority_service_role(role)
                    && readiness.role_id.0
                        == scoped.process.service_id
                    && readiness.process_id.0
                        == scoped.process.service_id
                    && readiness.key_id.as_ref().map(|id| id.0.as_str())
                        == Some(artifact.body.key_id.0.as_str())
                    && readiness.reconciled_generation_id
                        == context.generation_id
                    && readiness.reconciliation_checkpoint_sha256
                        == context
                            .reconciliation_checkpoint_sha256
                    && artifact_ids
                        .insert(artifact.body.artifact_id.clone()) => {}
            _ => {
                return Err(V2RuntimeError::new(
                    "generation_role_readiness_payload_invalid",
                    format!(
                        "{} readiness artifact does not bind its installed role and reconciliation checkpoint",
                        role.as_str()
                    ),
                ))
            }
        }
        artifacts.push(artifact);
    }
    let router = config
        .scoped_service_config(CustodyServiceRole::CustodyRouter)?;
    let role_readiness_root_sha256 = sha256_digest(
        &canonical_jcs_bytes(&artifacts)
            .map_err(authority_contract_error)?,
    );
    let router_topology_attestation = wait_for_signed_readiness_artifact(
        config,
        &config.generation_router_topology_attestation_path()?,
        router.process.uid,
        router.process.gid,
        context.deadline_boot_millis,
    )?;
    verify_authority_artifact(
        &router_topology_attestation,
        generation,
        AuthorityServiceRole::CustodyRouter,
        OperationKind::GenerationReady,
        &context.activation_operation_id,
        &context.artifact_scope_id,
        context.artifact_scope_revision,
        &context.artifact_scope_fence_token,
    )
    .map_err(authority_contract_error)?;
    match &router_topology_attestation.body.payload {
        NestedAuthorityPayload::RouterTopologyAttestation(attestation)
            if attestation.router_role_id.0
                == router.process.service_id
                && attestation.router_process_id.0
                    == router.process.service_id
                && attestation.router_key_id
                    == router_topology_attestation.body.key_id
                && attestation.reconciled_generation_id
                    == context.generation_id
                && attestation.topology_sha256
                    == context.topology_sha256
                && attestation.readiness_contract_sha256
                    == context.readiness_contract_sha256
                && attestation.reconciliation_checkpoint_sha256
                    == context
                        .reconciliation_checkpoint_sha256
                && attestation.role_readiness_root_sha256
                    == role_readiness_root_sha256 => {}
        _ => {
            return Err(V2RuntimeError::new(
                "generation_router_topology_attestation_payload_invalid",
                "router topology attestation does not bind its key, exact seven-artifact root, topology, readiness contract, and reconciliation checkpoint",
            ))
        }
    }
    let router_record = read_service_readiness_record(
        config,
        CustodyServiceRole::CustodyRouter,
    )?;
    if router_record.reconciliation_high_water
        < context.reconciliation_high_water
        || router_record.dependency_handshakes.len()
            != CustodyServiceRole::ALL.len() - 1
    {
        return Err(V2RuntimeError::new(
            "generation_router_topology_invalid",
            "router topology does not aggregate the exact six post-reconciliation services",
        ));
    }
    Ok((artifacts, router_topology_attestation))
}

fn wait_for_signed_readiness_artifact(
    config: &super::RootOwnedResponseObservationV2Config,
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    deadline_boot_millis: u64,
) -> Result<SignedAuthorityArtifact, V2RuntimeError> {
    loop {
        super::guest_delivery::check(config)?;
        if config.guest_delivery.is_some() && super::recovery::boottime_ns()? / 1_000_000 >= deadline_boot_millis {
            return Err(V2RuntimeError::new("guest_readiness_timeout", "original artifact deadline expired"));
        }
        match read_shared_regular_file(
            path,
            expected_uid,
            expected_gid,
            MAX_BOOTSTRAP_CREDENTIAL_BYTES,
            0o440,
        ) {
            Ok(bytes) => {
                super::guest_delivery::check(config)?;
                return crate::decode_canonical_json(&bytes).map_err(
                    |_| {
                        V2RuntimeError::new(
                            "generation_readiness_artifact_invalid",
                            "role readiness artifact is not canonical closed JSON",
                        )
                    },
                )
            }
            Err(error)
                if error.code()
                    == "generation_shared_file_unavailable" =>
            {
                if super::recovery::boottime_ns()? / 1_000_000
                    >= deadline_boot_millis
                {
                    return Err(V2RuntimeError::new(
                        "generation_readiness_artifact_timeout",
                        format!(
                            "readiness artifact {} was not published before the activation deadline",
                            path.display()
                        ),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn publish_shared_canonical_file<T: Serialize>(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
    value: &T,
) -> Result<(), V2RuntimeError> {
    let parent = path.parent().ok_or_else(|| {
        V2RuntimeError::new(
            "generation_shared_file_path_invalid",
            "generation coordination file has no parent directory",
        )
    })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| {
        V2RuntimeError::new(
            "generation_shared_directory_unavailable",
            "inspect generation coordination directory",
        )
    })?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != owner_uid
        || parent_metadata.gid() != owner_gid
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(V2RuntimeError::new(
            "generation_shared_directory_unsafe",
            "generation coordination directory must be owned by its exact service identity and not group/world writable",
        ));
    }
    let bytes =
        canonical_jcs_bytes(value).map_err(authority_contract_error)?;
    if fs::symlink_metadata(path).is_ok() {
        let existing = read_shared_regular_file(
            path,
            owner_uid,
            owner_gid,
            MAX_BOOTSTRAP_CREDENTIAL_BYTES,
            0o440,
        )?;
        if existing == bytes {
            return Ok(());
        }
        return Err(V2RuntimeError::new(
            "generation_shared_file_conflict",
            "a different immutable generation coordination file is already published",
        ));
    }
    let temporary = parent.join(format!(
        ".generation-coordination.{}-{}.tmp",
        std::process::id(),
        super::recovery::boottime_ns()?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_shared_file_publish_failed",
                "create exclusive generation coordination staging file",
            )
        })?;
    let publish = (|| {
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| {
                V2RuntimeError::new(
                    "generation_shared_file_publish_failed",
                    "write and synchronize generation coordination file",
                )
            })?;
        let owner = unsafe {
            libc::fchown(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                owner_uid,
                owner_gid,
            )
        };
        if owner != 0 {
            return Err(V2RuntimeError::new(
                "generation_shared_file_owner_failed",
                "set generation coordination file ownership",
            ));
        }
        file.set_permissions(fs::Permissions::from_mode(0o440))
            .map_err(|_| {
                V2RuntimeError::new(
                    "generation_shared_file_publish_failed",
                    "seal generation coordination file permissions",
                )
            })?;
        fs::rename(&temporary, path).map_err(|_| {
            V2RuntimeError::new(
                "generation_shared_file_publish_failed",
                "atomically publish generation coordination file",
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| {
                V2RuntimeError::new(
                    "generation_shared_file_publish_failed",
                    "synchronize generation coordination directory",
                )
            })
    })();
    if publish.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    publish
}

fn read_shared_regular_file(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    maximum_bytes: u64,
    expected_mode: u32,
) -> Result<Vec<u8>, V2RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        V2RuntimeError::new(
            "generation_shared_file_unavailable",
            format!(
                "open generation coordination file {}",
                path.display()
            ),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o777 != expected_mode
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(V2RuntimeError::new(
            "generation_shared_file_unsafe",
            "generation coordination file has unsafe ownership, mode, links, type, or size",
        ));
    }
    fs::read(path).map_err(|_| {
        V2RuntimeError::new(
            "generation_shared_file_unreadable",
            "read generation coordination file",
        )
    })
}

fn read_bootstrap_readiness_proof(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<GenerationBootstrapReadinessProofV1, V2RuntimeError> {
    let bytes = read_owned_regular_file(
        path,
        expected_uid,
        expected_gid,
        MAX_BOOTSTRAP_CREDENTIAL_BYTES,
        0o400,
    )?;
    crate::decode_canonical_json(&bytes).map_err(|_| {
        V2RuntimeError::new(
            "generation_readiness_proof_invalid",
            "generation readiness proof is not canonical closed JSON",
        )
    })
}

fn deterministic_identifier(
    label: &str,
    parts: &[&[u8]],
) -> Identifier {
    Identifier(deterministic_digest(label, parts).0)
}

fn deterministic_digest(
    label: &str,
    parts: &[&[u8]],
) -> AuthorityDigest {
    let mut hasher = Sha256::new();
    frame(&mut hasher, label.as_bytes());
    for part in parts {
        frame(&mut hasher, part);
    }
    AuthorityDigest(format!("sha256:{:x}", hasher.finalize()))
}

pub(crate) fn topology_sha256(
    topology: &SignedCustodyTopologyV1,
) -> Result<String, V2RuntimeError> {
    let bytes = crate::canonical_json_bytes(topology).map_err(|_| {
        V2RuntimeError::new(
            "custody_topology_invalid",
            "signed custody topology cannot be canonicalized",
        )
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

pub(crate) fn logical_role_key_root_sha256(
    topology: &SignedCustodyTopologyV1,
    service_role: CustodyServiceRole,
) -> String {
    let mut roles = topology
        .logical_roles
        .iter()
        .filter(|binding| binding.service_role == service_role)
        .collect::<Vec<_>>();
    roles.sort_by(|left, right| {
        left.logical_role.cmp(&right.logical_role)
    });
    let mut hasher = Sha256::new();
    frame(
        &mut hasher,
        b"serverware.response-v2/logical-role-key-root/v1",
    );
    frame(&mut hasher, service_role.as_str().as_bytes());
    for role in roles {
        frame(&mut hasher, role.logical_role.as_bytes());
        frame(&mut hasher, role.key_id.as_bytes());
        frame(&mut hasher, role.public_key_sha256.as_bytes());
    }
    for operation in required_service_operations(service_role) {
        frame(&mut hasher, operation.as_str().as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub(crate) fn role_identity_root_sha256(
    topology: &SignedCustodyTopologyV1,
) -> String {
    let mut hasher = Sha256::new();
    frame(
        &mut hasher,
        b"serverware.response-v2/role-identity-root/v2",
    );
    for service_role in CustodyServiceRole::ALL {
        frame(&mut hasher, service_role.as_str().as_bytes());
        if let Some(process) = topology.process(service_role) {
            frame(&mut hasher, process.service_id.as_bytes());
            frame(&mut hasher, &process.uid.to_be_bytes());
            frame(&mut hasher, &process.gid.to_be_bytes());
            frame(&mut hasher, process.executable_sha256.as_bytes());
            frame(
                &mut hasher,
                process.configuration_sha256.as_bytes(),
            );
        }
        frame(
            &mut hasher,
            logical_role_key_root_sha256(topology, service_role)
                .as_bytes(),
        );
        for operation in required_service_operations(service_role) {
            frame(&mut hasher, operation.as_str().as_bytes());
        }
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub(crate) fn required_service_operations(
    role: CustodyServiceRole,
) -> BTreeSet<ServiceOperationV1> {
    use ServiceOperationV1::*;
    let operations: &[ServiceOperationV1] = match role {
        CustodyServiceRole::CustodyRouter => &[Readiness],
        CustodyServiceRole::StateAuthority => &[
            Readiness,
            StateCas,
            ConsumeReleaseAndRetrieveExact,
            ReplayResolve,
            Reconcile,
        ],
        CustodyServiceRole::CredentialTransport => &[Readiness],
        CustodyServiceRole::PolicyProofVerifier => &[
            Readiness,
            FinalEnvelopeVerify,
        ],
        CustodyServiceRole::ImmutableArtifactLedger => &[
            Readiness,
            InspectImmutableRaw,
        ],
        CustodyServiceRole::ReleaseAttestorPublisher => &[
            Readiness,
            AuthorizeRelease,
            Publish,
        ],
        CustodyServiceRole::CleanupWatchdog => &[
            Readiness,
            Reconcile,
            Cleanup,
        ],
    };
    operations.iter().copied().collect()
}

pub(crate) fn validate_post_reconciliation_handshake(
    topology: &SignedCustodyTopologyV1,
    handshake: &SignedServiceHandshakeV1,
) -> Result<(), V2RuntimeError> {
    validate_handshake_operations(topology,handshake,required_service_operations(handshake.service_role))
}

// Keep required_service_operations and the historical role/key root recipes
// unchanged. These extra effects require actual cold configuration selection.
pub(crate) fn selected_service_operations(
    config:&super::RootOwnedResponseObservationV2Config, role:CustodyServiceRole,
) -> BTreeSet<ServiceOperationV1> {
    let mut selected=required_service_operations(role);
    if role == CustodyServiceRole::CredentialTransport && config.target_dispatch.is_some() {
        selected.insert(ServiceOperationV1::TargetDispatch);
    }
    if role == CustodyServiceRole::ImmutableArtifactLedger && config.ledger_raw_persistence.is_some() {
        selected.insert(ServiceOperationV1::ImmutablePut);
    }
    selected
}
pub(crate) fn validate_selected_handshake(
    config:&super::RootOwnedResponseObservationV2Config, handshake:&SignedServiceHandshakeV1,
) -> Result<(),V2RuntimeError> {
    validate_handshake_operations(config.custody_topology(),handshake,
        selected_service_operations(config,handshake.service_role))
}
fn validate_handshake_operations(
    topology:&SignedCustodyTopologyV1, handshake:&SignedServiceHandshakeV1,
    required:BTreeSet<ServiceOperationV1>,
) -> Result<(),V2RuntimeError> {
    let process = topology
        .process(handshake.service_role)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_handshake_process_unknown",
                "service handshake names a process outside the signed topology",
            )
        })?;
    let implemented = handshake
        .implemented_operations
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if handshake.api_version != SERVICE_HANDSHAKE_API_VERSION
        || handshake.request_id.is_empty()
        || !is_sha256(&handshake.challenge_nonce)
        || handshake.service_id != process.service_id
        || handshake.generation_id != topology.generation_id
        || handshake.generation != topology.generation
        || handshake.fault_domain_id != TRUSTED_HOST_FAULT_DOMAIN
        || handshake.quorum_mode != TRUSTED_HOST_QUORUM_MODE
        || handshake.fault_domain_count != 1
        || handshake.external_witness_count != 0
        || handshake.hardware_proof != topology.hardware_proof
        || handshake.executable_sha256
            != process.executable_sha256
        || handshake.configuration_sha256
            != process.configuration_sha256
        || handshake.logical_role_key_root_sha256
            != logical_role_key_root_sha256(
                topology,
                handshake.service_role,
            )
        || implemented.len()
            != handshake.implemented_operations.len()
        || !handshake.ready_after_reconciliation
        || handshake.reconciliation_high_water == 0
        || !is_sha256(&handshake.reconciliation_state_sha256)
        || handshake.issued_at_epoch_ms == 0
        || handshake.expires_at_epoch_ms
            <= handshake.issued_at_epoch_ms
    {
        return Err(V2RuntimeError::new(
            "custody_handshake_binding_invalid",
            "service handshake is not bound to the exact signed generation, role keys, honest trust claim, and post-reconciliation state",
        ));
    }
    if implemented != required {
        return Err(V2RuntimeError::new(
            "custody_handshake_capability_mismatch",
            "service handshake must advertise exactly the operations implemented for its process role",
        ));
    }
    Ok(())
}

fn frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn bootstrap_state_authority_generation(
    config: &super::RootOwnedResponseObservationV2Config,
    generation_authority_key: &RoleSigningKey,
) -> Result<GenerationBootstrapReadiness, V2RuntimeError> {
    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let paths =
        GenerationBootstrapCredentialPaths::for_config(
            config,
            &scoped,
        )?;
    let manifests = load_and_verify_bootstrap_manifests(
        config,
        &scoped,
        &paths,
        generation_authority_key,
    )?;
    let state_identity = manifests
        .generation
        .role(AuthorityServiceRole::StateAuthority)
        .map_err(authority_contract_error)?;
    let mut sequence = 0u64;
    let mut query = execute_query(
        config,
        generation_authority_key,
        state_identity,
        &manifests.generation,
        &paths.generation_authority_secret_key,
        &mut sequence,
    );
    if query
        .as_ref()
        .err()
        .is_some_and(|error| {
            error.code() == "state_authority_generation_not_installed"
        })
    {
        let install = signed_generation_frame(
            config,
            generation_authority_key,
            state_identity,
            GenerationMutationPayload::Install(
                GenerationInstallMutation {
                    generation: manifests.generation.clone(),
                    canonical_generation_sha256:
                        manifests.generation_sha256.clone(),
                },
            ),
            "install",
            &mut sequence,
        )?;
        let exact = super::services::execute_generation_postgres(
            config,
            &install,
            generation_authority_key,
            &paths.generation_authority_secret_key,
        )?;
        verify_generation_result(
            &exact.canonical_bytes,
            &install,
            &manifests.generation,
            state_identity,
        )?;
        query = execute_query(
            config,
            generation_authority_key,
            state_identity,
            &manifests.generation,
            &paths.generation_authority_secret_key,
            &mut sequence,
        );
    }
    let mut query_result = query?;
    let mut states =
        reconciliation_states_from_query(&query_result)?;
    let mut cursors = BTreeMap::new();
    for domain in ReconciliationDomain::REQUIRED {
        let mut state = states
            .remove(&domain)
            .unwrap_or(ReconciliationState::Pending);
        if state == ReconciliationState::Complete {
            let live_cursor =
                super::services::
                    generation_reconciliation_cursor_postgres(
                        config,
                        domain,
                    )?;
            let checkpoint_cursor =
                super::services::
                    generation_reconciliation_checkpoint_postgres(
                        config,
                        domain,
                    )?;
            if live_cursor == 0 || checkpoint_cursor != live_cursor {
                return Err(V2RuntimeError::new(
                    "generation_reconciliation_checkpoint_stale",
                    format!(
                        "{} changed after its completed reconciliation checkpoint",
                        domain.as_str()
                    ),
                ));
            }
            cursors.insert(
                domain.as_str().to_owned(),
                checkpoint_cursor,
            );
            continue;
        }
        if state == ReconciliationState::Failed {
            return Err(V2RuntimeError::new(
                "generation_reconciliation_failed",
                format!(
                    "{} is durably failed and cannot be made ready by startup",
                    domain.as_str()
                ),
            ));
        }
        let cursor =
            super::services::
                generation_reconciliation_cursor_postgres(
                    config,
                    domain,
                )?;
        if cursor == 0 {
            return Err(V2RuntimeError::new(
                "generation_reconciliation_cursor_invalid",
                format!(
                    "{} produced a zero authoritative cursor",
                    domain.as_str()
                ),
            ));
        }
        if matches!(
            state,
            ReconciliationState::Pending | ReconciliationState::Blocked
        ) {
            execute_reconciliation_transition(
                config,
                generation_authority_key,
                state_identity,
                &manifests.generation,
                &paths.generation_authority_secret_key,
                domain,
                state,
                ReconciliationState::Running,
                cursor,
                &mut sequence,
            )?;
            state = ReconciliationState::Running;
        }
        execute_reconciliation_transition(
            config,
            generation_authority_key,
            state_identity,
            &manifests.generation,
            &paths.generation_authority_secret_key,
            domain,
            state,
            ReconciliationState::Complete,
            cursor,
            &mut sequence,
        )?;
        cursors.insert(domain.as_str().to_owned(), cursor);
    }
    query_result = execute_query(
        config,
        generation_authority_key,
        state_identity,
        &manifests.generation,
        &paths.generation_authority_secret_key,
        &mut sequence,
    )?;
    let proof = GenerationBootstrapReadinessProofV1 {
        api_version: BOOTSTRAP_READINESS_API_VERSION.to_owned(),
        generation_id: manifests.generation.generation_id.clone(),
        generation_sha256: manifests.generation_sha256,
        reconciliation_cursors: cursors,
        signed_query_result: query_result,
    };
    let readiness = verify_bootstrap_readiness_proof(
        &proof,
        &manifests.generation,
    )?;
    verify_live_reconciliation_cursors(config, &proof)?;
    publish_bootstrap_readiness_proof(
        &paths.readiness_proof,
        scoped.process.uid,
        scoped.process.gid,
        &proof,
    )?;
    Ok(readiness)
}

pub(crate) fn load_verified_bootstrap_readiness(
    config: &super::RootOwnedResponseObservationV2Config,
) -> Result<GenerationBootstrapReadiness, V2RuntimeError> {
    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let paths =
        GenerationPublicCredentialPaths::for_config(
            config,
            &scoped,
        )?;
    let generation_bytes = read_generation_credential(
        config,
        &paths.generation_manifest,
        scoped.process.uid,
        scoped.process.gid,
        MAX_BOOTSTRAP_CREDENTIAL_BYTES,
    )?;
    let signed: SignedProviderGenerationCredentialV1 =
        crate::decode_canonical_json(&generation_bytes).map_err(|_| {
            V2RuntimeError::new(
                "generation_manifest_invalid",
                "provider-generation credential is not canonical closed JSON",
            )
        })?;
    let trust_anchor = read_generation_trust_anchor(
        config,
        &paths.trust_anchor_public_key,
        scoped.process.uid,
        scoped.process.gid,
    )?;
    let generation = verify_signed_provider_generation(
        config,
        &signed,
        &trust_anchor,
    )?;
    let proof_bytes = read_owned_regular_file(
        &paths.readiness_proof,
        scoped.process.uid,
        scoped.process.gid,
        MAX_BOOTSTRAP_CREDENTIAL_BYTES,
        0o400,
    )?;
    let proof: GenerationBootstrapReadinessProofV1 =
        crate::decode_canonical_json(&proof_bytes).map_err(|_| {
            V2RuntimeError::new(
                "generation_readiness_proof_invalid",
                "generation readiness proof is not canonical closed JSON",
            )
        })?;
    let readiness =
        verify_bootstrap_readiness_proof(&proof, &generation)?;
    verify_live_reconciliation_cursors(config, &proof)?;
    Ok(readiness)
}

struct VerifiedBootstrapManifests {
    generation: ProviderGeneration,
    generation_sha256: AuthorityDigest,
}

fn load_and_verify_bootstrap_manifests(
    config: &super::RootOwnedResponseObservationV2Config,
    scoped: &super::config::ScopedCustodyServiceConfig,
    paths: &GenerationBootstrapCredentialPaths,
    generation_authority_key: &RoleSigningKey,
) -> Result<VerifiedBootstrapManifests, V2RuntimeError> {
    let generation_bytes = read_generation_credential(
        config,
        &paths.generation_manifest,
        scoped.process.uid,
        scoped.process.gid,
        MAX_BOOTSTRAP_CREDENTIAL_BYTES,
    )?;
    let topology_bytes = read_generation_credential(
        config,
        &paths.topology_manifest,
        scoped.process.uid,
        scoped.process.gid,
        MAX_BOOTSTRAP_CREDENTIAL_BYTES,
    )?;
    let role_bytes = read_generation_credential(
        config,
        &paths.role_manifest,
        scoped.process.uid,
        scoped.process.gid,
        MAX_BOOTSTRAP_CREDENTIAL_BYTES,
    )?;
    let key_bytes = read_generation_credential(
        config,
        &paths.key_manifest,
        scoped.process.uid,
        scoped.process.gid,
        MAX_BOOTSTRAP_CREDENTIAL_BYTES,
    )?;
    let trust_anchor = read_generation_trust_anchor(
        config,
        &paths.trust_anchor_public_key,
        scoped.process.uid,
        scoped.process.gid,
    )?;
    let signed_generation: SignedProviderGenerationCredentialV1 =
        crate::decode_canonical_json(&generation_bytes).map_err(|_| {
            V2RuntimeError::new(
                "generation_manifest_invalid",
                "provider-generation credential is not canonical closed JSON",
            )
        })?;
    let signed_topology: SignedTopologyManifestV1 =
        crate::decode_canonical_json(&topology_bytes).map_err(|_| {
            V2RuntimeError::new(
                "topology_manifest_invalid",
                "topology credential is not canonical closed JSON",
            )
        })?;
    let signed_roles: SignedRoleManifestV1 =
        crate::decode_canonical_json(&role_bytes).map_err(|_| {
            V2RuntimeError::new(
                "role_manifest_invalid",
                "role credential is not canonical closed JSON",
            )
        })?;
    let signed_keys: SignedKeyManifestV1 =
        crate::decode_canonical_json(&key_bytes).map_err(|_| {
            V2RuntimeError::new(
                "key_manifest_invalid",
                "key credential is not canonical closed JSON",
            )
        })?;
    let generation = verify_signed_provider_generation(
        config,
        &signed_generation,
        &trust_anchor,
    )?;
    verify_signed_topology_manifest(
        &signed_topology,
        &generation,
        &signed_generation.generation_sha256,
        &trust_anchor,
    )?;
    let topology_manifest_sha256 = sha256_digest(&topology_bytes);
    verify_signed_role_manifest(
        &signed_roles,
        &generation,
        &signed_generation.generation_sha256,
        &topology_manifest_sha256,
        &trust_anchor,
    )?;
    let role_manifest_sha256 = sha256_digest(&role_bytes);
    verify_signed_key_manifest(
        &signed_keys,
        &generation,
        &signed_generation.generation_sha256,
        &role_manifest_sha256,
        &trust_anchor,
    )?;
    if generation_authority_key.logical_role()
        != "linearizable-store"
        || generation_authority_key.key_id()
            != signed_generation
                .authentication
                .trust_anchor_key_id
                .0
    {
        return Err(V2RuntimeError::new(
            "generation_authority_key_mismatch",
            "InstallGeneration signer is not the pinned linearizable-store generation authority",
        ));
    }
    Ok(VerifiedBootstrapManifests {
        generation,
        generation_sha256: signed_generation.generation_sha256,
    })
}

fn verify_signed_provider_generation(
    config: &super::RootOwnedResponseObservationV2Config,
    signed: &SignedProviderGenerationCredentialV1,
    trust_anchor: &[u8; 32],
) -> Result<ProviderGeneration, V2RuntimeError> {
    if signed.api_version != PROVIDER_GENERATION_API_VERSION
        || signed.kind != PROVIDER_GENERATION_KIND
        || signed.schema_version != STATE_AUTHORITY_SCHEMA_VERSION
    {
        return Err(V2RuntimeError::new(
            "generation_manifest_version_invalid",
            "provider-generation credential has an unsupported version or kind",
        ));
    }
    let generation = signed.inner_generation();
    generation.validate().map_err(authority_contract_error)?;
    let canonical =
        canonical_jcs_bytes(&generation).map_err(authority_contract_error)?;
    let digest = sha256_digest(&canonical);
    if signed.generation_sha256 != digest {
        return Err(V2RuntimeError::new(
            "generation_manifest_digest_mismatch",
            "generationSha256 does not match the verified unsigned inner generation",
        ));
    }
    verify_manifest_authentication(
        &signed.authentication,
        PROVIDER_GENERATION_SIGNATURE_DOMAIN_NAME,
        PROVIDER_GENERATION_SIGNATURE_DOMAIN,
        &canonical,
        &digest,
        trust_anchor,
    )?;
    validate_local_generation_profile(config, &generation, trust_anchor)?;
    let now = system_time_epoch_ms()?;
    if now < generation.not_before_epoch_millis
        || now >= generation.not_after_epoch_millis
    {
        return Err(V2RuntimeError::new(
            "generation_manifest_outside_validity",
            "provider generation is outside its signed validity interval",
        ));
    }
    Ok(generation)
}

fn verify_signed_topology_manifest(
    signed: &SignedTopologyManifestV1,
    generation: &ProviderGeneration,
    generation_sha256: &AuthorityDigest,
    trust_anchor: &[u8; 32],
) -> Result<(), V2RuntimeError> {
    if signed.api_version != TOPOLOGY_MANIFEST_API_VERSION
        || signed.kind != TOPOLOGY_MANIFEST_KIND
        || signed.schema_version != STATE_AUTHORITY_SCHEMA_VERSION
        || signed.generation_id != generation.generation_id
        || &signed.provider_generation_sha256 != generation_sha256
        || signed.topology != generation.topology
    {
        return Err(V2RuntimeError::new(
            "topology_manifest_binding_invalid",
            "signed topology manifest does not exactly reproduce the verified provider generation",
        ));
    }
    let unsigned = UnsignedTopologyManifestV1 {
        api_version: &signed.api_version,
        kind: &signed.kind,
        schema_version: &signed.schema_version,
        generation_id: &signed.generation_id,
        provider_generation_sha256:
            &signed.provider_generation_sha256,
        topology: &signed.topology,
    };
    verify_auxiliary_manifest(
        &unsigned,
        &signed.authentication,
        TOPOLOGY_MANIFEST_SIGNATURE_DOMAIN_NAME,
        TOPOLOGY_MANIFEST_SIGNATURE_DOMAIN,
        trust_anchor,
    )
}

fn verify_signed_role_manifest(
    signed: &SignedRoleManifestV1,
    generation: &ProviderGeneration,
    generation_sha256: &AuthorityDigest,
    topology_manifest_sha256: &AuthorityDigest,
    trust_anchor: &[u8; 32],
) -> Result<(), V2RuntimeError> {
    if signed.api_version != ROLE_MANIFEST_API_VERSION
        || signed.kind != ROLE_MANIFEST_KIND
        || signed.schema_version != STATE_AUTHORITY_SCHEMA_VERSION
        || signed.generation_id != generation.generation_id
        || &signed.provider_generation_sha256 != generation_sha256
        || &signed.topology_manifest_sha256
            != topology_manifest_sha256
        || signed.roles != generation.topology.roles
    {
        return Err(V2RuntimeError::new(
            "role_manifest_binding_invalid",
            "signed role manifest does not chain to and reproduce the verified topology",
        ));
    }
    let unsigned = UnsignedRoleManifestV1 {
        api_version: &signed.api_version,
        kind: &signed.kind,
        schema_version: &signed.schema_version,
        generation_id: &signed.generation_id,
        provider_generation_sha256:
            &signed.provider_generation_sha256,
        topology_manifest_sha256:
            &signed.topology_manifest_sha256,
        roles: &signed.roles,
    };
    verify_auxiliary_manifest(
        &unsigned,
        &signed.authentication,
        ROLE_MANIFEST_SIGNATURE_DOMAIN_NAME,
        ROLE_MANIFEST_SIGNATURE_DOMAIN,
        trust_anchor,
    )
}

fn verify_signed_key_manifest(
    signed: &SignedKeyManifestV1,
    generation: &ProviderGeneration,
    generation_sha256: &AuthorityDigest,
    role_manifest_sha256: &AuthorityDigest,
    trust_anchor: &[u8; 32],
) -> Result<(), V2RuntimeError> {
    let expected_role_keys = generation
        .topology
        .roles
        .iter()
        .map(|role| RoleKeyManifestEntryV1 {
            role: role.role,
            role_id: role.role_id.clone(),
            key_id: role.key_id.clone(),
            public_key_base64url:
                role.public_key_base64url.clone(),
            public_key_sha256: role.public_key_sha256.clone(),
        })
        .collect::<Vec<_>>();
    if signed.api_version != KEY_MANIFEST_API_VERSION
        || signed.kind != KEY_MANIFEST_KIND
        || signed.schema_version != STATE_AUTHORITY_SCHEMA_VERSION
        || signed.generation_id != generation.generation_id
        || &signed.provider_generation_sha256 != generation_sha256
        || &signed.role_manifest_sha256 != role_manifest_sha256
        || signed.role_keys != expected_role_keys
        || signed.logical_role_bindings
            != generation.topology.logical_role_bindings
    {
        return Err(V2RuntimeError::new(
            "key_manifest_binding_invalid",
            "signed key manifest does not chain to and reproduce the exact role and logical-subkey assignments",
        ));
    }
    let unsigned = UnsignedKeyManifestV1 {
        api_version: &signed.api_version,
        kind: &signed.kind,
        schema_version: &signed.schema_version,
        generation_id: &signed.generation_id,
        provider_generation_sha256:
            &signed.provider_generation_sha256,
        role_manifest_sha256: &signed.role_manifest_sha256,
        role_keys: &signed.role_keys,
        logical_role_bindings: &signed.logical_role_bindings,
    };
    verify_auxiliary_manifest(
        &unsigned,
        &signed.authentication,
        KEY_MANIFEST_SIGNATURE_DOMAIN_NAME,
        KEY_MANIFEST_SIGNATURE_DOMAIN,
        trust_anchor,
    )
}

fn verify_auxiliary_manifest<T: Serialize>(
    unsigned: &T,
    authentication: &GenerationManifestAuthenticationV1,
    domain_name: &str,
    domain: &[u8],
    trust_anchor: &[u8; 32],
) -> Result<(), V2RuntimeError> {
    let canonical =
        canonical_jcs_bytes(unsigned).map_err(authority_contract_error)?;
    let digest = sha256_digest(&canonical);
    verify_manifest_authentication(
        authentication,
        domain_name,
        domain,
        &canonical,
        &digest,
        trust_anchor,
    )
}

fn verify_manifest_authentication(
    authentication: &GenerationManifestAuthenticationV1,
    expected_domain_name: &str,
    domain: &[u8],
    canonical: &[u8],
    expected_digest: &AuthorityDigest,
    trust_anchor: &[u8; 32],
) -> Result<(), V2RuntimeError> {
    let trust_anchor_sha256 =
        AuthorityDigest(format!("sha256:{:x}", Sha256::digest(trust_anchor)));
    if authentication.algorithm != SIGNATURE_ALGORITHM
        || authentication.signing_domain != expected_domain_name
        || &authentication.signed_payload_sha256 != expected_digest
        || authentication.trust_anchor_public_key_sha256
            != trust_anchor_sha256
        || authentication.trust_anchor_key_id.0
            != trust_anchor_sha256.0
    {
        return Err(V2RuntimeError::new(
            "generation_manifest_authentication_invalid",
            "manifest authentication is not bound to the pinned trust anchor, domain, and canonical payload digest",
        ));
    }
    let signature = decode_base64url(
        "generationManifest.authentication.signatureBase64url",
        &authentication.signature_base64url,
    )
    .map_err(authority_contract_error)?;
    let signature = Signature::from_slice(&signature).map_err(|_| {
        V2RuntimeError::new(
            "generation_manifest_signature_invalid",
            "manifest signature is not a 64-byte Ed25519 signature",
        )
    })?;
    let key = VerifyingKey::from_bytes(trust_anchor).map_err(|_| {
        V2RuntimeError::new(
            "generation_trust_anchor_invalid",
            "generation trust anchor is not an Ed25519 public key",
        )
    })?;
    key.verify(&signature_message(domain, canonical), &signature)
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_manifest_signature_invalid",
                "manifest signature did not verify under the pinned trust anchor",
            )
        })
}

fn validate_local_generation_profile(
    config: &super::RootOwnedResponseObservationV2Config,
    generation: &ProviderGeneration,
    trust_anchor: &[u8; 32],
) -> Result<(), V2RuntimeError> {
    let custody_topology = config.custody_topology();
    if generation.generation_id.0 != custody_topology.generation_id
        || generation.topology.attestation_mode
            != custody_topology.attestation_mode.generation_profile()
        || generation.topology.fault_domain_id.0
            != TRUSTED_HOST_FAULT_DOMAIN
        || generation.topology.fault_domain_count != 1
        || generation.topology.quorum_profile.as_str()
            != TRUSTED_HOST_QUORUM_MODE
        || generation.topology.external_witness_count != 0
        || generation.topology.hardware_proof
            != custody_topology.hardware_proof
    {
        return Err(V2RuntimeError::new(
            "generation_local_profile_mismatch",
            "provider generation does not exactly match the signed local-single-node attestation profile and hardware-proof claim",
        ));
    }
    for custody_role in CustodyServiceRole::ALL {
        let authority_role = authority_service_role(custody_role);
        let process = custody_topology
            .process(custody_role)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_local_process_missing",
                    "signed custody topology omits a required process",
                )
            })?;
        let identity = generation
            .role(authority_role)
            .map_err(authority_contract_error)?;
        if identity.role_id.0 != process.service_id
            || identity.process_id.0 != process.service_id
            || identity.unix_uid != process.uid
            || identity.unix_gid != process.gid
            || identity.fault_domain_id.0
                != TRUSTED_HOST_FAULT_DOMAIN
            || identity.executable_sha256.0
                != process.executable_sha256
            || identity.configuration_sha256.0
                != process.configuration_sha256
        {
            return Err(V2RuntimeError::new(
                "generation_local_process_mismatch",
                format!(
                    "{} identity differs from the root-owned signed local process profile",
                    custody_role.as_str()
                ),
            ));
        }
        let logical_role = local_readiness_signer(custody_role);
        let descriptor = process
            .role_keys
            .iter()
            .find(|key| key.logical_role == logical_role)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_role_key_missing",
                    format!(
                        "{} readiness key is absent from the signed local topology",
                        custody_role.as_str()
                    ),
                )
            })?;
        if identity.key_id.as_ref().map(|id| id.0.as_str())
            != Some(descriptor.key_id.as_str())
            || identity
                .public_key_sha256
                .as_ref()
                .map(|digest| digest.0.as_str())
                != Some(descriptor.public_key_sha256.as_str())
        {
            return Err(V2RuntimeError::new(
                "generation_role_key_mismatch",
                format!(
                    "{} authority key differs from the signed local readiness key",
                    custody_role.as_str()
                ),
            ));
        }
        let public_key = decode_base64url(
            "roleIdentity.publicKeyBase64url",
            identity
                .public_key_base64url
                .as_deref()
                .ok_or_else(|| {
                    V2RuntimeError::new(
                        "generation_role_key_missing",
                        "authority role omits its public key",
                    )
                })?,
        )
        .map_err(authority_contract_error)?;
        if public_key.len() != 32
            || format!(
                "sha256:{:x}",
                Sha256::digest(&public_key)
            ) != descriptor.public_key_sha256
        {
            return Err(V2RuntimeError::new(
                "generation_role_public_key_mismatch",
                "authority role public key does not match its signed digest",
            ));
        }
    }
    let state_identity = generation
        .role(AuthorityServiceRole::StateAuthority)
        .map_err(authority_contract_error)?;
    let trust_anchor_sha256 =
        format!("sha256:{:x}", Sha256::digest(trust_anchor));
    if state_identity
        .public_key_sha256
        .as_ref()
        .map(|digest| digest.0.as_str())
        != Some(trust_anchor_sha256.as_str())
        || state_identity
            .key_id
            .as_ref()
            .map(|identifier| identifier.0.as_str())
            != Some(trust_anchor_sha256.as_str())
    {
        return Err(V2RuntimeError::new(
            "generation_trust_anchor_profile_mismatch",
            "read-only generation trust anchor is not the signed state-authority generation key",
        ));
    }
    for binding in &generation.topology.logical_role_bindings {
        let custody_role =
            custody_service_role(binding.service_role);
        let process = custody_topology.process(custody_role).ok_or_else(
            || {
                V2RuntimeError::new(
                    "generation_logical_role_process_missing",
                    "logical role references an absent local process",
                )
            },
        )?;
        let local = process
            .role_keys
            .iter()
            .find(|key| key.logical_role == binding.logical_role.0)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_logical_role_missing",
                    format!(
                        "{} is absent from the signed local key assignment",
                        binding.logical_role.0
                    ),
                )
            })?;
        if binding.process_id.0 != process.service_id
            || binding.role_id.0 != process.service_id
            || binding.key_id.0 != local.key_id
            || binding.public_key_sha256.0
                != local.public_key_sha256
        {
            return Err(V2RuntimeError::new(
                "generation_logical_role_mismatch",
                "provider-generation logical role differs from the root-owned signed local key assignment",
            ));
        }
    }
    if custody_topology.attestation_mode
        == CustodyAttestationProfile::TeeHardware
    {
        verify_tee_hardware_generation(
            config,
            generation,
            custody_topology,
        )?;
    }
    Ok(())
}

fn verify_tee_hardware_generation(
    config: &super::RootOwnedResponseObservationV2Config,
    generation: &ProviderGeneration,
    custody_topology: &SignedCustodyTopologyV1,
) -> Result<(), V2RuntimeError> {
    let verifier = config
        .tee_hardware_generation_verifier
        .as_ref()
        .ok_or_else(|| {
            V2RuntimeError::new(
                "tee_generation_verifier_missing",
                "tee-hardware generation activation requires a descriptor-pinned independent verifier",
            )
        })?;
    verifier.validate()?;
    let challenge_nonce = super::recovery::random_challenge_nonce()?;
    let enclave_boot_id = super::recovery::kernel_boot_id()?;
    let now = system_time_epoch_ms()?;
    let generation_sha256 = sha256_digest(
        &canonical_jcs_bytes(generation).map_err(authority_contract_error)?,
    );
    let custody_topology_sha256 = topology_sha256(custody_topology)?;
    let process_identity_root_sha256 = sha256_digest(
        &canonical_jcs_bytes(
            &custody_topology
                .processes
                .iter()
                .map(|process| {
                    (
                        process.service_role,
                        process.service_id.as_str(),
                        process.uid,
                        process.gid,
                        process.executable_sha256.as_str(),
                        process.configuration_sha256.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .map_err(authority_contract_error)?,
    );
    let role_identity_root_sha256 = super::role_identity_root(config);
    let proof_pins_root_sha256 =
        super::proof_independent_pins_root(config);
    let pins = &config.proof_independent_pins;
    let expected = TeeGenerationExpectedV2 {
        challenge_nonce: &challenge_nonce,
        enclave_instance_id: &verifier.expected_enclave_instance_id,
        enclave_boot_id: &enclave_boot_id,
        generation_id: &custody_topology.generation_id,
        provider_generation: custody_topology.generation,
        generation_sha256: &generation_sha256.0,
        custody_topology_sha256: &custody_topology_sha256,
        process_identity_root_sha256:
            &process_identity_root_sha256.0,
        role_identity_root_sha256: &role_identity_root_sha256,
        proof_pins_root_sha256: &proof_pins_root_sha256,
        source_commit_sha256: &generation.source_commit_sha256.0,
        source_tree_sha256: &generation.source_tree_sha256.0,
        schema_bundle_sha256: &generation.schema_bundle_sha256.0,
        migration_sha256: &generation.migration_sha256.0,
        release_transparency_proof_sha256: &config
            .release_transparency_artifact
            .release_transparency_proof_sha256,
        release_source_commit_sha256:
            &pins.release_source_commit_sha256,
        release_source_tree_sha256: &pins.release_source_tree_sha256,
        release_executable_sha256: &pins.release_executable_sha256,
        release_configuration_sha256:
            &pins.release_configuration_sha256,
        trust_checkpoint_sha256: &pins.trust_checkpoint_sha256,
        verifier_executable_sha256: &verifier.executable_sha256,
        verifier_module_sha256: verifier
            .verifier_module
            .as_ref()
            .map(|module| module.sha256.as_str()),
        expectations_sha256: &verifier.expectations.sha256,
        trust_roots_sha256: &verifier.trust_roots.sha256,
        eif_sha384: &verifier.expected_eif_sha384,
        pcrs: &verifier.expected_pcrs,
        attestation_mode: "tee-hardware",
        topology_profile: LOCAL_TEE_TOPOLOGY_PROFILE,
        fault_domain_count: 1,
        quorum_threshold: 1,
        external_witness_count: 0,
        fault_tolerance: 0,
        hardware_proof: true,
        maximum_evidence_age_ms: verifier.maximum_evidence_age_ms,
        maximum_future_skew_ms: verifier.maximum_future_skew_ms,
    };
    let expected_bytes =
        canonical_jcs_bytes(&expected).map_err(authority_contract_error)?;
    let mut report_preimage = Vec::with_capacity(
        TEE_GENERATION_REPORT_DOMAIN.len() + expected_bytes.len(),
    );
    report_preimage.extend_from_slice(TEE_GENERATION_REPORT_DOMAIN);
    report_preimage.extend_from_slice(&expected_bytes);
    let expected_report_data_sha256 = sha256_digest(&report_preimage);
    let request = json!({
        "apiVersion":TEE_VERIFICATION_REQUEST_API_VERSION,
        "purpose":"generation",
        "expected":expected,
        "expectedReportDataSha256":expected_report_data_sha256,
        "verifierInputs":{
            "module":&verifier.verifier_module,
            "expectations":&verifier.expectations,
            "trustRoots":&verifier.trust_roots,
        },
    });
    let command = PinnedGenerationVerifierCommand {
        executable: verifier.executable.clone(),
        arguments: verifier.arguments.clone(),
        expected_sha256: verifier.executable_sha256.clone(),
    };
    let result = run_pinned_bounded_generation_verifier(
        config,
        &command,
        &request,
        128 * 1024,
    )
    .map_err(|error| {
        V2RuntimeError::new(
            "tee_generation_verifier_failed",
            error,
        )
    })?;
    let result = decode_tee_generation_verifier_result(&result)
        .map_err(|_| {
            V2RuntimeError::new(
                "tee_generation_verifier_result_invalid",
                "TEE generation verifier returned an open or invalid result contract",
            )
        })?;
    let claims = result.claims;
    let maximum_future = now.saturating_add(
        verifier.maximum_future_skew_ms,
    );
    if result.api_version != TEE_VERIFICATION_RESULT_API_VERSION
        || !result.ok
        || result.purpose != "generation"
        || claims.challenge_nonce != challenge_nonce
        || claims.enclave_instance_id
            != verifier.expected_enclave_instance_id
        || claims.enclave_boot_id != enclave_boot_id
        || claims.generation_id != custody_topology.generation_id
        || claims.provider_generation != custody_topology.generation
        || claims.generation_sha256 != generation_sha256.0
        || claims.custody_topology_sha256 != custody_topology_sha256
        || claims.process_identity_root_sha256
            != process_identity_root_sha256.0
        || claims.role_identity_root_sha256
            != role_identity_root_sha256
        || claims.proof_pins_root_sha256
            != proof_pins_root_sha256
        || claims.source_commit_sha256
            != generation.source_commit_sha256.0
        || claims.source_tree_sha256 != generation.source_tree_sha256.0
        || claims.schema_bundle_sha256
            != generation.schema_bundle_sha256.0
        || claims.migration_sha256 != generation.migration_sha256.0
        || claims.release_transparency_proof_sha256
            != config
                .release_transparency_artifact
                .release_transparency_proof_sha256
        || claims.release_source_commit_sha256
            != pins.release_source_commit_sha256
        || claims.release_source_tree_sha256
            != pins.release_source_tree_sha256
        || claims.release_executable_sha256
            != pins.release_executable_sha256
        || claims.release_configuration_sha256
            != pins.release_configuration_sha256
        || claims.trust_checkpoint_sha256
            != pins.trust_checkpoint_sha256
        || claims.verifier_executable_sha256
            != verifier.executable_sha256
        || claims.verifier_module_sha256.as_deref()
            != verifier
                .verifier_module
                .as_ref()
                .map(|module| module.sha256.as_str())
        || claims.expectations_sha256 != verifier.expectations.sha256
        || claims.trust_roots_sha256 != verifier.trust_roots.sha256
        || claims.attestation_evidence_format != NITRO_EVIDENCE_FORMAT
        || !is_sha256(&claims.attestation_evidence_sha256)
        || claims.eif_sha384 != verifier.expected_eif_sha384
        || claims.pcrs != verifier.expected_pcrs
        || claims.report_data_sha256
            != expected_report_data_sha256.0
        || claims.attestation_mode != "tee-hardware"
        || claims.topology_profile != LOCAL_TEE_TOPOLOGY_PROFILE
        || claims.fault_domain_count != 1
        || claims.quorum_threshold != 1
        || claims.external_witness_count != 0
        || claims.fault_tolerance != 0
        || !claims.hardware_proof
        || !claims.hardware_backed
        || !claims.quote_verified
        || claims.debug
        || claims.evidence_issued_at_epoch_ms == 0
        || claims.evidence_issued_at_epoch_ms > maximum_future
        || claims.verified_at_epoch_ms
            < claims.evidence_issued_at_epoch_ms
        || claims.verified_at_epoch_ms > maximum_future
        || now.saturating_sub(claims.evidence_issued_at_epoch_ms)
            > verifier.maximum_evidence_age_ms
        || claims.expires_at_epoch_ms <= now
        || claims.expires_at_epoch_ms
            <= claims.verified_at_epoch_ms
        || claims
            .expires_at_epoch_ms
            .saturating_sub(claims.verified_at_epoch_ms)
            > verifier.maximum_evidence_age_ms
    {
        return Err(V2RuntimeError::new(
            "tee_generation_evidence_invalid",
            "independently verified TEE evidence is absent, stale, debug-enabled, or not bound to the exact Nitro measurement, enclave boot/instance, generation, runtime, release, role/process, and local 1-of-1 topology",
        ));
    }
    Ok(())
}

fn execute_query(
    config: &super::RootOwnedResponseObservationV2Config,
    result_signer: &RoleSigningKey,
    caller: &AuthorityRoleIdentity,
    generation: &ProviderGeneration,
    result_credential_path: &Path,
    sequence: &mut u64,
) -> Result<SignedGenerationOperationResult, V2RuntimeError> {
    let projection = canonical_jcs_bytes(&(
        generation.generation_id.clone(),
        "GENERATION_STATUS",
    ))
    .map_err(authority_contract_error)?;
    let frame = signed_generation_frame(
        config,
        result_signer,
        caller,
        GenerationMutationPayload::Query(StateQueryMutation {
            query_sha256: sha256_digest(&projection),
        }),
        "query",
        sequence,
    )?;
    let exact =
        super::services::execute_generation_postgres(
            config,
            &frame,
            result_signer,
            result_credential_path,
        )?;
    verify_generation_result(
        &exact.canonical_bytes,
        &frame,
        generation,
        caller,
    )
}

fn execute_reconciliation_transition(
    config: &super::RootOwnedResponseObservationV2Config,
    result_signer: &RoleSigningKey,
    caller: &AuthorityRoleIdentity,
    generation: &ProviderGeneration,
    result_credential_path: &Path,
    domain: ReconciliationDomain,
    predecessor: ReconciliationState,
    successor: ReconciliationState,
    cursor: u64,
    sequence: &mut u64,
) -> Result<(), V2RuntimeError> {
    let job_id =
        Identifier(format!("reconciliation:{}", domain.as_str()));
    let blocker_code: Option<Identifier> = None;
    let result_sha256 = sha256_digest(
        &canonical_jcs_bytes(&(
            generation.generation_id.clone(),
            job_id.clone(),
            domain,
            predecessor,
            successor,
            cursor,
            blocker_code.clone(),
        ))
        .map_err(authority_contract_error)?,
    );
    let frame = signed_generation_frame(
        config,
        result_signer,
        caller,
        GenerationMutationPayload::Reconcile(
            GenerationReconcileMutation {
                reconciliation_job_id: job_id,
                domain,
                predecessor_state: predecessor,
                successor_state: successor,
                authoritative_cursor: cursor,
                blocker_code,
                result_sha256,
            },
        ),
        domain.as_str(),
        sequence,
    )?;
    let exact =
        super::services::execute_generation_postgres(
            config,
            &frame,
            result_signer,
            result_credential_path,
        )?;
    verify_generation_result(
        &exact.canonical_bytes,
        &frame,
        generation,
        generation
            .role(AuthorityServiceRole::StateAuthority)
            .map_err(authority_contract_error)?,
    )?;
    Ok(())
}

fn signed_generation_frame(
    config: &super::RootOwnedResponseObservationV2Config,
    signer: &RoleSigningKey,
    caller: &AuthorityRoleIdentity,
    payload: GenerationMutationPayload,
    scope: &str,
    sequence: &mut u64,
) -> Result<GenerationRpcRequestFrame, V2RuntimeError> {
    if caller
        .key_id
        .as_ref()
        .map(|key_id| key_id.0.as_str())
        != Some(signer.key_id())
    {
        return Err(V2RuntimeError::new(
            "generation_bootstrap_signer_mismatch",
            "generation frame signer does not match its signed caller identity",
        ));
    }
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        V2RuntimeError::new(
            "generation_bootstrap_sequence_overflow",
            "generation bootstrap request sequence overflowed",
        )
    })?;
    let now_boot_millis = super::recovery::boottime_ns()? / 1_000_000;
    let timeout = config
        .scoped_service_config(CustodyServiceRole::StateAuthority)?
        .process
        .request_timeout_ms;
    let timeout = super::guest_delivery::timeout_ms(config, timeout)?;
    let deadline_boot_millis = now_boot_millis
        .checked_add(timeout)
        .filter(|deadline| *deadline <= MAX_SAFE_INTEGER)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_bootstrap_deadline_overflow",
                "generation bootstrap deadline overflowed",
            )
        })?;
    let deadline_boot_millis = match &config.guest_delivery {
        Some(owner) => owner.deadline_millis(deadline_boot_millis)?,
        None => deadline_boot_millis,
    };
    let operation = payload.operation();
    let boot_id = super::recovery::kernel_boot_id()?;
    let request_seed = canonical_jcs_bytes(&(
        config.custody_topology().generation_id.as_str(),
        caller.role_id.0.as_str(),
        operation.as_str(),
        scope,
        *sequence,
        boot_id.as_str(),
        deadline_boot_millis,
    ))
    .map_err(authority_contract_error)?;
    let request_id = Identifier(format!(
        "bootstrap-{:x}",
        Sha256::digest(&request_seed)
    ));
    let request = GenerationRpcRequest {
        api_version: STATE_AUTHORITY_API_VERSION.to_owned(),
        kind: STATE_AUTHORITY_GENERATION_RPC_KIND.to_owned(),
        schema_version: STATE_AUTHORITY_SCHEMA_VERSION.to_owned(),
        generation_id: Identifier(
            config.custody_topology().generation_id.clone(),
        ),
        request_id: request_id.clone(),
        operation_id: request_id,
        caller_role_id: caller.role_id.clone(),
        operation,
        deadline: super::super::state_authority::BootDeadline {
            clock: "CLOCK_BOOTTIME".to_owned(),
            boot_id: Identifier(boot_id),
            deadline_boot_millis,
        },
        payload,
    };
    request.validate().map_err(authority_contract_error)?;
    let canonical =
        canonical_jcs_bytes(&request).map_err(authority_contract_error)?;
    let signed_payload_sha256 = sha256_digest(&canonical);
    let signature = signer.sign_digest_bytes(&signature_message(
        STATE_AUTHORITY_SIGNATURE_DOMAIN,
        &canonical,
    ));
    if signature.len() != 64 {
        return Err(V2RuntimeError::new(
            "generation_bootstrap_signature_invalid",
            "generation frame signer did not produce a 64-byte Ed25519 signature",
        ));
    }
    Ok(GenerationRpcRequestFrame {
        request,
        authentication: FrameAuthentication {
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            key_id: Identifier(signer.key_id().to_owned()),
            signed_payload_sha256,
            signature_base64url: encode_base64url(&signature),
        },
    })
}

fn verify_generation_result(
    exact_bytes: &[u8],
    request: &GenerationRpcRequestFrame,
    generation: &ProviderGeneration,
    result_signer: &AuthorityRoleIdentity,
) -> Result<SignedGenerationOperationResult, V2RuntimeError> {
    let result: SignedGenerationOperationResult =
        crate::decode_canonical_json(exact_bytes).map_err(|_| {
            V2RuntimeError::new(
                "generation_operation_result_invalid",
                "state authority returned a noncanonical generation result",
            )
        })?;
    let canonical_request =
        canonical_jcs_bytes(request).map_err(authority_contract_error)?;
    let canonical_body =
        canonical_jcs_bytes(&result.body).map_err(authority_contract_error)?;
    let body_sha256 = sha256_digest(&canonical_body);
    if result.body.api_version != STATE_AUTHORITY_API_VERSION
        || result.body.kind != STATE_AUTHORITY_GENERATION_RESULT_KIND
        || result.body.schema_version != STATE_AUTHORITY_SCHEMA_VERSION
        || result.body.generation_id != generation.generation_id
        || result.body.request_id != request.request.request_id
        || result.body.operation_id != request.request.operation_id
        || result.body.operation != request.request.operation
        || result.body.exact_request_sha256
            != sha256_digest(&canonical_request)
        || result.body.generation_sha256
            != sha256_digest(
                &canonical_jcs_bytes(generation)
                    .map_err(authority_contract_error)?,
            )
        || result.body.disposition != ResultDisposition::Applied
        || result.authentication.algorithm != SIGNATURE_ALGORITHM
        || result.authentication.signed_payload_sha256 != body_sha256
        || result.authentication.key_id
            != result_signer.key_id.clone().ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_result_signer_missing",
                    "state-authority result identity has no key ID",
                )
            })?
    {
        return Err(V2RuntimeError::new(
            "generation_operation_result_binding_invalid",
            "generation result does not bind the exact request, generation, disposition, and state-authority signer",
        ));
    }
    let public_key = decode_base64url(
        "generationResult.signer.publicKeyBase64url",
        result_signer
            .public_key_base64url
            .as_deref()
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_result_signer_missing",
                    "state-authority result identity has no public key",
                )
            })?,
    )
    .map_err(authority_contract_error)?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        V2RuntimeError::new(
            "generation_result_signer_invalid",
            "state-authority result public key is not 32 bytes",
        )
    })?;
    let signature = decode_base64url(
        "generationResult.authentication.signatureBase64url",
        &result.authentication.signature_base64url,
    )
    .map_err(authority_contract_error)?;
    let signature = Signature::from_slice(&signature).map_err(|_| {
        V2RuntimeError::new(
            "generation_result_signature_invalid",
            "state-authority generation result signature is not 64 bytes",
        )
    })?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_result_signer_invalid",
                "state-authority generation result key is invalid",
            )
        })?
        .verify(
            &signature_message(
                STATE_AUTHORITY_SIGNATURE_DOMAIN,
                &canonical_body,
            ),
            &signature,
        )
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_result_signature_invalid",
                "state-authority generation result signature did not verify",
            )
        })?;
    Ok(result)
}

fn reconciliation_states_from_query(
    query: &SignedGenerationOperationResult,
) -> Result<BTreeMap<ReconciliationDomain, ReconciliationState>, V2RuntimeError>
{
    let completed = query
        .body
        .completed_domains
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if completed.len() != query.body.completed_domains.len() {
        return Err(V2RuntimeError::new(
            "generation_query_domain_duplicate",
            "generation query duplicated a completed reconciliation domain",
        ));
    }
    let mut states = ReconciliationDomain::REQUIRED
        .into_iter()
        .map(|domain| {
            let state = if completed.contains(&domain) {
                ReconciliationState::Complete
            } else {
                ReconciliationState::Pending
            };
            (domain, state)
        })
        .collect::<BTreeMap<_, _>>();
    for blocker in &query.body.blockers {
        let Some(rest) = blocker.0.strip_prefix("reconciliation:")
        else {
            continue;
        };
        let Some((domain_name, state_name)) = rest.rsplit_once(':')
        else {
            return Err(V2RuntimeError::new(
                "generation_query_blocker_invalid",
                "reconciliation blocker is not a domain/state binding",
            ));
        };
        let domain = ReconciliationDomain::REQUIRED
            .into_iter()
            .find(|candidate| candidate.as_str() == domain_name)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_query_domain_invalid",
                    "generation query named an unknown reconciliation domain",
                )
            })?;
        let state = match state_name {
            "Pending" | "PENDING" | "MISSING" => {
                ReconciliationState::Pending
            }
            "Running" | "RUNNING" => ReconciliationState::Running,
            "Blocked" | "BLOCKED" => ReconciliationState::Blocked,
            "Complete" | "COMPLETE" => {
                ReconciliationState::Complete
            }
            "Failed" | "FAILED" => ReconciliationState::Failed,
            _ => {
                return Err(V2RuntimeError::new(
                    "generation_query_state_invalid",
                    "generation query named an unknown reconciliation state",
                ))
            }
        };
        states.insert(domain, state);
    }
    Ok(states)
}

fn verify_bootstrap_readiness_proof(
    proof: &GenerationBootstrapReadinessProofV1,
    generation: &ProviderGeneration,
) -> Result<GenerationBootstrapReadiness, V2RuntimeError> {
    let state_identity = generation
        .role(AuthorityServiceRole::StateAuthority)
        .map_err(authority_contract_error)?;
    let query_bytes = canonical_jcs_bytes(&proof.signed_query_result)
        .map_err(authority_contract_error)?;
    let query_frame_digest =
        proof.signed_query_result.body.exact_request_sha256.clone();
    if proof.api_version != BOOTSTRAP_READINESS_API_VERSION
        || proof.generation_id != generation.generation_id
        || proof.generation_sha256
            != sha256_digest(
                &canonical_jcs_bytes(generation)
                    .map_err(authority_contract_error)?,
            )
        || proof.signed_query_result.body.operation
            != OperationKind::StateQuery
        || proof.signed_query_result.body.disposition
            != ResultDisposition::Applied
        || !matches!(
            proof.signed_query_result.body.generation_status,
            GenerationStatus::Reconciling | GenerationStatus::Ready
        )
        || !proof.signed_query_result.body.blockers.is_empty()
    {
        return Err(V2RuntimeError::new(
            "generation_readiness_proof_binding_invalid",
            "bootstrap readiness proof is not a successful reconciled exact-generation state query",
        ));
    }
    verify_signed_generation_result_without_request(
        &proof.signed_query_result,
        generation,
        state_identity,
    )?;
    let completed = proof
        .signed_query_result
        .body
        .completed_domains
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let required =
        ReconciliationDomain::REQUIRED.into_iter().collect::<BTreeSet<_>>();
    let cursor_domains = proof
        .reconciliation_cursors
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required_names = ReconciliationDomain::REQUIRED
        .into_iter()
        .map(ReconciliationDomain::as_str)
        .collect::<BTreeSet<_>>();
    if completed != required
        || proof.signed_query_result.body.completed_domains.len()
            != ReconciliationDomain::REQUIRED.len()
        || cursor_domains != required_names
        || proof.reconciliation_cursors.values().any(|cursor| *cursor == 0)
    {
        return Err(V2RuntimeError::new(
            "generation_readiness_domain_set_invalid",
            "service readiness requires exactly every signed reconciliation domain with a nonzero authoritative cursor",
        ));
    }
    let high_water = proof
        .reconciliation_cursors
        .values()
        .copied()
        .min()
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_readiness_domain_set_invalid",
                "bootstrap readiness proof has no reconciliation cursors",
            )
        })?;
    let state_sha256 = sha256_digest(
        &canonical_jcs_bytes(&(
            &proof.generation_sha256,
            &proof.reconciliation_cursors,
            sha256_digest(&query_bytes),
            query_frame_digest,
        ))
        .map_err(authority_contract_error)?,
    );
    Ok(GenerationBootstrapReadiness {
        reconciliation_high_water: high_water,
        reconciliation_state_sha256: state_sha256.0,
    })
}

fn verify_live_reconciliation_cursors(
    config: &super::RootOwnedResponseObservationV2Config,
    proof: &GenerationBootstrapReadinessProofV1,
) -> Result<(), V2RuntimeError> {
    for domain in ReconciliationDomain::REQUIRED {
        let expected = proof
            .reconciliation_cursors
            .get(domain.as_str())
            .copied()
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_readiness_cursor_missing",
                    format!(
                        "{} is absent from the bootstrap readiness proof",
                        domain.as_str()
                    ),
                )
            })?;
        let current =
            super::services::generation_reconciliation_cursor_postgres(
                config,
                domain,
            )?;
        let checkpoint =
            super::services::
                generation_reconciliation_checkpoint_postgres(
                    config,
                    domain,
                )?;
        if expected == 0
            || current != expected
            || checkpoint != expected
        {
            return Err(V2RuntimeError::new(
                "generation_readiness_cursor_changed",
                format!(
                    "{} changed after its signed reconciliation transition",
                    domain.as_str()
                ),
            ));
        }
    }
    Ok(())
}

fn verify_signed_generation_result_without_request(
    result: &SignedGenerationOperationResult,
    generation: &ProviderGeneration,
    result_signer: &AuthorityRoleIdentity,
) -> Result<(), V2RuntimeError> {
    let canonical_body =
        canonical_jcs_bytes(&result.body).map_err(authority_contract_error)?;
    let body_sha256 = sha256_digest(&canonical_body);
    if result.body.api_version != STATE_AUTHORITY_API_VERSION
        || result.body.kind != STATE_AUTHORITY_GENERATION_RESULT_KIND
        || result.body.schema_version != STATE_AUTHORITY_SCHEMA_VERSION
        || result.body.generation_id != generation.generation_id
        || result.body.generation_sha256
            != sha256_digest(
                &canonical_jcs_bytes(generation)
                    .map_err(authority_contract_error)?,
            )
        || result.authentication.algorithm != SIGNATURE_ALGORITHM
        || result.authentication.signed_payload_sha256 != body_sha256
        || result.authentication.key_id
            != result_signer.key_id.clone().ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_result_signer_missing",
                    "state-authority result identity has no key ID",
                )
            })?
    {
        return Err(V2RuntimeError::new(
            "generation_result_authentication_invalid",
            "saved generation result is not bound to the exact generation and state-authority signer",
        ));
    }
    let public_key = decode_base64url(
        "generationResult.signer.publicKeyBase64url",
        result_signer
            .public_key_base64url
            .as_deref()
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_result_signer_missing",
                    "state-authority result identity has no public key",
                )
            })?,
    )
    .map_err(authority_contract_error)?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        V2RuntimeError::new(
            "generation_result_signer_invalid",
            "state-authority result public key is not 32 bytes",
        )
    })?;
    let signature = decode_base64url(
        "generationResult.authentication.signatureBase64url",
        &result.authentication.signature_base64url,
    )
    .map_err(authority_contract_error)?;
    let signature = Signature::from_slice(&signature).map_err(|_| {
        V2RuntimeError::new(
            "generation_result_signature_invalid",
            "state-authority generation result signature is not 64 bytes",
        )
    })?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_result_signer_invalid",
                "state-authority generation result key is invalid",
            )
        })?
        .verify(
            &signature_message(
                STATE_AUTHORITY_SIGNATURE_DOMAIN,
                &canonical_body,
            ),
            &signature,
        )
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_result_signature_invalid",
                "saved state-authority generation result signature did not verify",
            )
        })
}

fn publish_bootstrap_readiness_proof(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    proof: &GenerationBootstrapReadinessProofV1,
) -> Result<(), V2RuntimeError> {
    let parent = path.parent().ok_or_else(|| {
        V2RuntimeError::new(
            "generation_readiness_path_invalid",
            "generation readiness proof path has no parent",
        )
    })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| {
        V2RuntimeError::new(
            "generation_readiness_directory_unavailable",
            "inspect generation readiness proof directory",
        )
    })?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != expected_uid
        || parent_metadata.gid() != expected_gid
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(V2RuntimeError::new(
            "generation_readiness_directory_unsafe",
            "generation readiness proof directory must be owned by the exact service identity and not group/world writable",
        ));
    }
    let bytes =
        canonical_jcs_bytes(proof).map_err(authority_contract_error)?;
    let temporary = parent.join(format!(
        ".generation-bootstrap-readiness.{}-{}.tmp",
        std::process::id(),
        super::recovery::boottime_ns()?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_readiness_publish_failed",
                "create exclusive generation readiness proof",
            )
        })?;
    let publish = (|| {
        file.write_all(&bytes).map_err(|_| {
            V2RuntimeError::new(
                "generation_readiness_publish_failed",
                "write generation readiness proof",
            )
        })?;
        file.sync_all().map_err(|_| {
            V2RuntimeError::new(
                "generation_readiness_publish_failed",
                "sync generation readiness proof",
            )
        })?;
        file.set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(|_| {
                V2RuntimeError::new(
                    "generation_readiness_publish_failed",
                    "seal generation readiness proof permissions",
                )
            })?;
        fs::rename(&temporary, path).map_err(|_| {
            V2RuntimeError::new(
                "generation_readiness_publish_failed",
                "atomically publish generation readiness proof",
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| {
                V2RuntimeError::new(
                    "generation_readiness_publish_failed",
                    "sync generation readiness proof directory",
                )
            })
    })();
    if publish.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    publish
}

fn read_trust_anchor(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<[u8; 32], V2RuntimeError> {
    let bytes = read_credential(
        path,
        expected_uid,
        expected_gid,
        32,
    )?;
    bytes.try_into().map_err(|_| {
        V2RuntimeError::new(
            "generation_trust_anchor_invalid",
            "generation trust-anchor credential must contain exactly 32 raw Ed25519 public-key bytes",
        )
    })
}

fn read_generation_credential(
    config: &super::RootOwnedResponseObservationV2Config,
    path: &Path,
    uid: u32,
    gid: u32,
    maximum: u64,
) -> Result<Vec<u8>, V2RuntimeError> {
    if let Some(owner) = &config.guest_delivery {
        let bytes = owner.credential(path)?;
        if bytes.len() as u64 > maximum {
            return Err(V2RuntimeError::new("guest_credential_bound", "retained credential exceeds consumer bound"));
        }
        return Ok(bytes);
    }
    super::guest_delivery::require_host(config)?;
    read_credential(path, uid, gid, maximum)
}

fn read_generation_trust_anchor(
    config: &super::RootOwnedResponseObservationV2Config,
    path: &Path,
    uid: u32,
    gid: u32,
) -> Result<[u8; 32], V2RuntimeError> {
    if config.guest_delivery.is_none() {
        super::guest_delivery::require_host(config)?;
        return read_trust_anchor(path, uid, gid);
    }
    read_generation_credential(config, path, uid, gid, 32)?.try_into().map_err(|_| {
        V2RuntimeError::new("generation_trust_anchor_invalid", "retained generation root must be exactly32 bytes")
    })
}

pub(crate) fn verify_guest_generation(
    config: &super::RootOwnedResponseObservationV2Config,
    original: &[u8],
    trust_anchor: &[u8; 32],
) -> Result<String, V2RuntimeError> {
    let signed: SignedProviderGenerationCredentialV1 = crate::decode_canonical_json(original)
        .map_err(|_| V2RuntimeError::new("generation_manifest_invalid", "invalid original signed generation"))?;
    verify_signed_provider_generation(config, &signed, trust_anchor)?;
    super::guest_delivery::check(config)?;
    Ok(signed.generation_sha256.0)
}

fn read_credential(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, V2RuntimeError> {
    read_owned_regular_file(
        path,
        expected_uid,
        expected_gid,
        maximum_bytes,
        0o400,
    )
}

fn read_owned_regular_file(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    maximum_bytes: u64,
    expected_mode: u32,
) -> Result<Vec<u8>, V2RuntimeError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_credential_unavailable",
                format!("open {}", path.display()),
            )
        })?;
    let metadata = file.metadata().map_err(|_| {
        V2RuntimeError::new(
            "generation_credential_unavailable",
            format!("inspect {}", path.display()),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o777 != expected_mode
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(V2RuntimeError::new(
            "generation_credential_unsafe",
            format!(
                "{} must be a bounded owner-only single-link systemd credential",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|_| {
        V2RuntimeError::new(
            "generation_credential_unreadable",
            format!("read {}", path.display()),
        )
    })?;
    if bytes.len() as u64 != metadata.len() {
        return Err(V2RuntimeError::new(
            "generation_credential_changed",
            "credential changed while it was being read",
        ));
    }
    Ok(bytes)
}

fn authority_service_role(
    role: CustodyServiceRole,
) -> AuthorityServiceRole {
    match role {
        CustodyServiceRole::CustodyRouter => {
            AuthorityServiceRole::CustodyRouter
        }
        CustodyServiceRole::StateAuthority => {
            AuthorityServiceRole::StateAuthority
        }
        CustodyServiceRole::CredentialTransport => {
            AuthorityServiceRole::CredentialTransport
        }
        CustodyServiceRole::PolicyProofVerifier => {
            AuthorityServiceRole::PolicyProofVerifier
        }
        CustodyServiceRole::ImmutableArtifactLedger => {
            AuthorityServiceRole::ImmutableArtifactLedger
        }
        CustodyServiceRole::ReleaseAttestorPublisher => {
            AuthorityServiceRole::ReleaseAttestorPublisher
        }
        CustodyServiceRole::CleanupWatchdog => {
            AuthorityServiceRole::CleanupWatchdog
        }
    }
}

fn custody_service_role(
    role: AuthorityServiceRole,
) -> CustodyServiceRole {
    match role {
        AuthorityServiceRole::CustodyRouter => {
            CustodyServiceRole::CustodyRouter
        }
        AuthorityServiceRole::StateAuthority => {
            CustodyServiceRole::StateAuthority
        }
        AuthorityServiceRole::CredentialTransport => {
            CustodyServiceRole::CredentialTransport
        }
        AuthorityServiceRole::PolicyProofVerifier => {
            CustodyServiceRole::PolicyProofVerifier
        }
        AuthorityServiceRole::ImmutableArtifactLedger => {
            CustodyServiceRole::ImmutableArtifactLedger
        }
        AuthorityServiceRole::ReleaseAttestorPublisher => {
            CustodyServiceRole::ReleaseAttestorPublisher
        }
        AuthorityServiceRole::CleanupWatchdog => {
            CustodyServiceRole::CleanupWatchdog
        }
    }
}

fn local_readiness_signer(
    role: CustodyServiceRole,
) -> &'static str {
    match role {
        CustodyServiceRole::CustodyRouter => {
            ROUTER_READINESS_LOGICAL_ROLE
        }
        CustodyServiceRole::StateAuthority => "linearizable-store",
        CustodyServiceRole::CredentialTransport => "mutation-supervisor",
        CustodyServiceRole::PolicyProofVerifier => "evidence-trust",
        CustodyServiceRole::ImmutableArtifactLedger => "persistence",
        CustodyServiceRole::ReleaseAttestorPublisher => "attester",
        CustodyServiceRole::CleanupWatchdog => {
            "emergency-cleanup-executor"
        }
    }
}

fn system_time_epoch_ms() -> Result<u64, V2RuntimeError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| {
            V2RuntimeError::new(
                "generation_wall_clock_invalid",
                "system wall clock precedes the Unix epoch",
            )
        })?
        .as_millis();
    u64::try_from(millis)
        .ok()
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_wall_clock_invalid",
                "system wall clock exceeds the interoperable integer range",
            )
        })
}

fn authority_contract_error(
    error: super::super::state_authority::AuthorityError,
) -> V2RuntimeError {
    V2RuntimeError::new(
        "generation_bootstrap_contract_invalid",
        error.to_string(),
    )
}

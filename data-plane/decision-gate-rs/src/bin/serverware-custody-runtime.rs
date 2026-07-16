use serverware_decision_gate::{
    read_frame, write_frame, CustodyRuntime, IO_DEADLINE, MAX_CONCURRENT_CONNECTIONS,
};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::mem::{size_of, MaybeUninit};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const DEFAULT_SOCKET_PATH: &str = "/run/serverware-custody/custody.sock";
const EXPECTED_CLIENT_UID_ENV: &str = "SERVERWARE_CUSTODY_EXPECTED_CLIENT_UID";
const ATTEMPT_LEDGER_DIRECTORY_ENV: &str = "SERVERWARE_CUSTODY_ATTEMPT_LEDGER_DIRECTORY";
const SOCKET_DIRECTORY_MODE: u32 = 0o710;
const SOCKET_MODE: u32 = 0o660;

#[derive(Clone, Copy)]
struct ExpectedClient {
    uid: libc::uid_t,
    runtime_uid: libc::uid_t,
    shared_gid: libc::gid_t,
}

fn main() -> Result<(), Box<dyn Error>> {
    let (socket_path, initialize_attempt_ledger) = parse_runtime_arguments(env::args().skip(1))?;
    let attempt_ledger_directory =
        parse_attempt_ledger_directory(env::var_os(ATTEMPT_LEDGER_DIRECTORY_ENV))?;
    if initialize_attempt_ledger {
        CustodyRuntime::initialize_attempt_ledger_directory(&attempt_ledger_directory)?;
        eprintln!(
            "serverware custody attempt ledger initialized directory={}",
            attempt_ledger_directory.display()
        );
        return Ok(());
    }
    run(&socket_path, &attempt_ledger_directory)
}

fn parse_runtime_arguments<I>(mut arguments: I) -> Result<(PathBuf, bool), String>
where
    I: Iterator<Item = String>,
{
    let mut socket_path = env::var_os("SERVERWARE_CUSTODY_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH));
    let mut initialize_attempt_ledger = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--socket" => {
                socket_path = arguments
                    .next()
                    .map(PathBuf::from)
                    .ok_or("--socket requires a path")?;
            }
            "--initialize-attempt-ledger" if !initialize_attempt_ledger => {
                initialize_attempt_ledger = true;
            }
            "--initialize-attempt-ledger" => {
                return Err("--initialize-attempt-ledger may be specified only once".to_string());
            }
            "--help" | "-h" => {
                return Err(format!(
                    "usage: serverware-custody-runtime [--socket PATH] [--initialize-attempt-ledger]\n\
                     environment: SERVERWARE_CUSTODY_SOCKET, {EXPECTED_CLIENT_UID_ENV}\n\
                     required: {ATTEMPT_LEDGER_DIRECTORY_ENV}\n\
                     default: {DEFAULT_SOCKET_PATH}"
                ));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if socket_path.as_os_str().is_empty() {
        return Err("custody socket path must not be empty".to_string());
    }
    Ok((socket_path, initialize_attempt_ledger))
}

fn parse_attempt_ledger_directory(configured: Option<OsString>) -> Result<PathBuf, String> {
    let path =
        PathBuf::from(configured.ok_or_else(|| {
            format!("{ATTEMPT_LEDGER_DIRECTORY_ENV} must be explicitly configured")
        })?);
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(format!(
            "{ATTEMPT_LEDGER_DIRECTORY_ENV} must be a non-empty absolute path"
        ));
    }
    Ok(path)
}

fn run(socket_path: &Path, attempt_ledger_directory: &Path) -> Result<(), Box<dyn Error>> {
    let expected_client = configured_expected_client()?;
    validate_socket_directory(socket_path, expected_client)?;
    let runtime = Arc::new(CustodyRuntime::generate(attempt_ledger_directory)?);
    remove_stale_socket(socket_path)?;
    let umask = UmaskGuard::restrict();
    let listener = UnixListener::bind(socket_path)?;
    drop(umask);
    fs::set_permissions(socket_path, fs::Permissions::from_mode(SOCKET_MODE))?;
    validate_bound_socket(socket_path, expected_client)?;
    let _socket_cleanup = SocketCleanup::new(socket_path)?;
    let active_connections = Arc::new(AtomicUsize::new(0));

    eprintln!(
        "serverware custody runtime listening socket={} transport=uds-development hardwareProof=false rollbackProtection=filesystem-development bootId={} expectedClientUid={} sharedGid={} attemptLedger={}",
        socket_path.display(),
        runtime.boot_id(),
        expected_client.uid,
        expected_client.shared_gid,
        attempt_ledger_directory.display(),
    );

    for accepted in listener.incoming() {
        let stream = match accepted {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("custody runtime accept failed: {error}");
                continue;
            }
        };
        if let Err(error) = authenticate_client_peer(&stream, expected_client.uid) {
            eprintln!("custody runtime rejected connection: {error}");
            drop(stream);
            continue;
        }
        let Some(permit) = ConnectionPermit::try_acquire(Arc::clone(&active_connections)) else {
            eprintln!(
                "custody runtime rejected connection: max concurrent connections ({MAX_CONCURRENT_CONNECTIONS}) reached"
            );
            drop(stream);
            continue;
        };
        let runtime = Arc::clone(&runtime);
        if let Err(error) = thread::Builder::new()
            .name("serverware-custody-client".to_string())
            .spawn(move || {
                let _permit = permit;
                if let Err(error) = serve_connection(stream, &runtime) {
                    eprintln!("custody runtime rejected request: {error}");
                }
            })
        {
            eprintln!("custody runtime rejected connection: worker spawn failed: {error}");
        }
    }
    Ok(())
}

fn configured_expected_client() -> Result<ExpectedClient, String> {
    // SAFETY: geteuid has no memory-safety preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    // SAFETY: getegid has no memory-safety preconditions.
    let effective_gid = unsafe { libc::getegid() };
    Ok(ExpectedClient {
        uid: parse_expected_client_uid(env::var_os(EXPECTED_CLIENT_UID_ENV))?,
        runtime_uid: effective_uid,
        shared_gid: effective_gid,
    })
}

fn parse_expected_client_uid(configured: Option<OsString>) -> Result<libc::uid_t, String> {
    let configured = configured
        .ok_or_else(|| format!("{EXPECTED_CLIENT_UID_ENV} must be explicitly configured"))?;
    let configured = configured
        .into_string()
        .map_err(|_| format!("{EXPECTED_CLIENT_UID_ENV} must be a valid UTF-8 decimal UID"))?;
    if configured.is_empty() || !configured.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "{EXPECTED_CLIENT_UID_ENV} must be a valid decimal UID"
        ));
    }
    configured.parse::<libc::uid_t>().map_err(|_| {
        format!("{EXPECTED_CLIENT_UID_ENV} must be a valid decimal UID in the platform UID range")
    })
}

fn validate_socket_directory(socket_path: &Path, expected: ExpectedClient) -> io::Result<()> {
    let directory = socket_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "custody socket path must have a parent directory",
        )
    })?;
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected.runtime_uid
        || metadata.gid() != expected.shared_gid
        || metadata.mode() & 0o7777 != SOCKET_DIRECTORY_MODE
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "custody socket directory {} must be a non-symlink directory owned by UID {} and GID {} with mode {:04o}",
                directory.display(),
                expected.runtime_uid,
                expected.shared_gid,
                SOCKET_DIRECTORY_MODE,
            ),
        ));
    }
    Ok(())
}

fn validate_bound_socket(socket_path: &Path, expected: ExpectedClient) -> io::Result<()> {
    let metadata = fs::symlink_metadata(socket_path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected.runtime_uid
        || metadata.gid() != expected.shared_gid
        || metadata.mode() & 0o7777 != SOCKET_MODE
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "custody socket {} must be a Unix socket owned by UID {} and GID {} with mode {:04o}",
                socket_path.display(),
                expected.runtime_uid,
                expected.shared_gid,
                SOCKET_MODE,
            ),
        ));
    }
    Ok(())
}

fn authenticate_client_peer(stream: &UnixStream, expected_uid: libc::uid_t) -> io::Result<()> {
    let peer_uid = peer_effective_uid(stream).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("could not authenticate custody client peer UID: {error}"),
        )
    })?;
    if peer_uid != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "custody client peer UID {peer_uid} does not match expected UID {expected_uid}"
            ),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_effective_uid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let mut credentials = MaybeUninit::<libc::ucred>::uninit();
    let mut credentials_length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the output pointers describe one ucred structure and its initialized size.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut credentials_length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if credentials_length as usize != size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SO_PEERCRED returned an unexpected credential size",
        ));
    }
    // SAFETY: successful getsockopt initialized the full ucred structure checked above.
    Ok(unsafe { credentials.assume_init() }.uid)
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "aix",
    target_os = "cygwin",
    target_os = "nto"
))]
fn peer_effective_uid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the output pointers reference initialized uid_t and gid_t storage.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "aix",
    target_os = "cygwin",
    target_os = "nto"
)))]
fn peer_effective_uid(_stream: &UnixStream) -> io::Result<libc::uid_t> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix peer UID authentication is unavailable on this platform",
    ))
}

fn serve_connection(
    mut stream: UnixStream,
    runtime: &CustodyRuntime,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let request = read_frame(&mut stream, IO_DEADLINE)?;
    let response = runtime.handle_canonical_request(&request)?;
    write_frame(&mut stream, &response, IO_DEADLINE)?;
    Ok(())
}

fn remove_stale_socket(socket_path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            match UnixStream::connect(socket_path) {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("custody socket {} is already active", socket_path.display()),
                )),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    fs::remove_file(socket_path)
                }
                Err(error) => Err(error),
            }
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to replace non-socket path {}",
                socket_path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn try_acquire(active: Arc<AtomicUsize>) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_CONCURRENT_CONNECTIONS).then_some(current + 1)
            })
            .ok()?;
        Some(Self { active })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn restrict() -> Self {
        // The runtime has not started worker threads yet, so this process-wide change is scoped
        // to the socket bind and immediately restored by the guard.
        Self(unsafe { libc::umask(0o117) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.0);
        }
    }
}

struct SocketCleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketCleanup {
    fn new(path: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use serde_json::{json, Value};
    use serverware_decision_gate::{
        canonical_json_bytes, decode_canonical_json, read_frame, write_frame, HELLO_OPERATION,
        MAX_FRAME_BYTES, PROTOCOL_API_VERSION, RESPONSE_PROOF_SIGN_OPERATION,
        STREAMING_RESPONSE_PROOF_SIGN_OPERATION,
    };
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const CONTROL_PLANE_RESPONSE_SIGNING_SEED: [u8; 32] = [19u8; 32];

    fn request_id(byte: u8) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])
    }

    fn digest(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn control_plane_response_signing_key() -> SigningKey {
        SigningKey::from_bytes(&CONTROL_PLANE_RESPONSE_SIGNING_SEED)
    }

    fn control_plane_response_signing_key_id() -> String {
        const ED25519_SPKI_PREFIX: [u8; 12] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let verifying_key = control_plane_response_signing_key().verifying_key();
        let mut spki = Vec::from(ED25519_SPKI_PREFIX);
        spki.extend_from_slice(verifying_key.as_bytes());
        format!("sha256:{}", hex::encode(Sha256::digest(spki)))
    }

    fn test_ledger_directory(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "serverware-custody-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create test ledger directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("protect test ledger directory");
        fs::canonicalize(directory).expect("canonical test ledger directory")
    }

    fn test_runtime(label: &str) -> (CustodyRuntime, PathBuf) {
        let directory = test_ledger_directory(label);
        CustodyRuntime::initialize_attempt_ledger_directory(&directory)
            .expect("initialize test ledger");
        let runtime = CustodyRuntime::generate_with_control_plane_response_public_key(
            control_plane_response_signing_key().verifying_key(),
            &control_plane_response_signing_key_id(),
            &directory,
        )
        .expect("test runtime");
        (runtime, directory)
    }

    fn response_proof_sign_request(runtime: &CustodyRuntime) -> (Vec<u8>, String) {
        let issued_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let dispatch_started_at_epoch_ms = issued_at_unix * 1000;
        let dispatch_expires_at_epoch_ms = dispatch_started_at_epoch_ms + 30_000;
        let client_request_digest = digest(1);
        let request_digest = digest(2);
        let operation_digest = digest(3);
        let policy_digest = digest(4);
        let body_digest = digest(5);
        let runtime_manifest_digest = digest(6);
        let control_plane_runtime_manifest_digest = digest(19);
        let release_digest = digest(8);
        let upstream_body_digest = digest(10);
        let attempt_id = digest(11);
        let principal_id = "agent:custody-runtime-test";
        let route_id = "route:custody-runtime-test";
        let authorization_binding = json!({
            "attempt_id":attempt_id,
            "flow_id":attempt_id,
            "principal_id":principal_id,
            "route_id":route_id,
            "credential_id":"credential:custody-runtime-test",
            "credential_version":7,
            "policy_hash":policy_digest,
            "request_digest":request_digest,
            "operation_digest":operation_digest,
            "operation_context":{"operation":"custody.test"},
            "require_jit_grant":true,
            "shared_quotas":[],
        });
        let binding_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_bytes(&authorization_binding).expect("authorization binding")
            ))
        );
        let release_authority = json!({
            "authority_mode":"atomic",
            "grant_id":"grant:custody-runtime-test",
            "approval_id":"approval:custody-runtime-test",
            "credential_ref":"credential:custody-runtime-test",
            "credential_version":7,
            "request_digest":request_digest,
            "operation_digest":operation_digest,
            "attempt_id":attempt_id,
            "consumption_identity_digest":binding_digest,
            "authorization_state_at_upstream_dispatch":"dispatching",
            "authorization_state_observed_at_epoch_ms":dispatch_started_at_epoch_ms,
            "reservation_expires_at_epoch_ms":dispatch_expires_at_epoch_ms,
            "dispatch_expires_at_epoch_ms":dispatch_expires_at_epoch_ms,
        });
        let dispatch_response_body = canonical_json_bytes(&json!({
            "apiVersion":"serverware.releaseAuthorization/v1",
            "ok":true,
            "authorized":true,
            "state":"dispatching",
            "reason":"dispatching",
            "attemptId":attempt_id,
            "bindingDigest":binding_digest,
            "idempotentReplay":false,
            "grantId":"grant:custody-runtime-test",
            "approvalRequestId":"approval:custody-runtime-test",
            "reservationExpiresAtEpochMs":dispatch_expires_at_epoch_ms,
            "dispatchStartedAtEpochMs":dispatch_started_at_epoch_ms,
            "dispatchExpiresAtEpochMs":dispatch_expires_at_epoch_ms,
            "completionOutcome":null,
            "retryAfterSeconds":0,
            "quotas":[],
            "store":{"backend":"sqlite","ha":false},
        }))
        .expect("dispatch response body");
        let response_nonce = general_purpose::URL_SAFE_NO_PAD.encode([13u8; 32]);
        let response_signing_key_id = control_plane_response_signing_key_id();
        let signed_response_statement = canonical_json_bytes(&json!({
            "version":"serverware.responseSignature/v1",
            "issued_at_ms":dispatch_started_at_epoch_ms,
            "request":{
                "method":"POST",
                "path":"/api/data-plane/release-authorizations/dispatch",
                "query":"",
            },
            "status_code":200,
            "body_sha256":format!(
                "sha256:{}",
                hex::encode(Sha256::digest(&dispatch_response_body))
            ),
            "nonce":response_nonce,
            "response_signing_key_id":response_signing_key_id,
            "context":{
                "runtime_manifest_digest":control_plane_runtime_manifest_digest,
                "policy_bundle_digest":policy_digest,
                "provenance_digest":release_digest,
                "image_signatures_digest":digest(17),
                "source_tree_digest":digest(18),
            },
        }))
        .expect("signed response statement");
        let signed_response_signature = control_plane_response_signing_key()
            .sign(&signed_response_statement)
            .to_bytes();
        let dispatch_request_body = canonical_json_bytes(&json!({
            "apiVersion":"serverware.releaseAuthorizationDispatch/v1",
            "attemptId":attempt_id,
            "bindingDigest":binding_digest,
        }))
        .expect("dispatch request body");
        let dispatch_response_body_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(&dispatch_response_body))
        );
        let selected_headers = json!({
            "content-length":"17",
            "content-type":"application/json",
            "x-serverware-client-request-digest":client_request_digest,
            "x-serverware-operation-digest":operation_digest,
            "x-serverware-policy-hash":policy_digest,
            "x-serverware-request-digest":request_digest,
            "x-serverware-response-body-sha256":body_digest,
        });
        let selected_headers_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_bytes(&selected_headers).expect("selected headers")
            ))
        );
        let selected_raw_policy_headers_b64 = json!({
            "content-encoding":[],
            "content-length":[general_purpose::URL_SAFE_NO_PAD.encode(b"17")],
            "content-type":[general_purpose::URL_SAFE_NO_PAD.encode(b"application/json")],
        });
        let upstream_canonical_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_bytes(&json!({
                    "status":200,
                    "selected_raw_policy_headers_b64":selected_raw_policy_headers_b64,
                    "body_digest":upstream_body_digest,
                }))
                .expect("upstream response binding")
            ))
        );
        let server_instance_id = "spiffe://dev.serverware/decision-gate/runtime-test";
        let statement = json!({
            "apiVersion":"serverware.proxyResponseStatement/v2",
            "issued_at_unix":issued_at_unix,
            "client_nonce":general_purpose::URL_SAFE_NO_PAD.encode([11u8; 32]),
            "client_request_digest":client_request_digest,
            "principal_id":principal_id,
            "route_id":route_id,
            "request_digest":request_digest,
            "operation_digest":operation_digest,
            "release_authority":release_authority,
            "control_plane_authorization_receipt":{
                "apiVersion":"serverware.controlPlaneAuthorizationReceipt/v1",
                "kind":"ControlPlaneAuthorizationReceipt",
                "principal_id":principal_id,
                "route_id":route_id,
                "release_authority":release_authority,
                "request":{
                    "method":"POST",
                    "path":"/api/data-plane/release-authorizations/dispatch",
                    "query":"",
                    "nonce":response_nonce,
                    "body_b64":general_purpose::URL_SAFE_NO_PAD.encode(&dispatch_request_body),
                    "body_sha256":format!(
                        "sha256:{}",
                        hex::encode(Sha256::digest(&dispatch_request_body))
                    ),
                },
                "response":{
                    "status":200,
                    "body_b64":general_purpose::URL_SAFE_NO_PAD.encode(&dispatch_response_body),
                    "body_sha256":dispatch_response_body_digest,
                    "response_signing_key_id":response_signing_key_id,
                    "statement_b64":general_purpose::URL_SAFE_NO_PAD.encode(&signed_response_statement),
                    "statement_sha256":format!(
                        "sha256:{}",
                        hex::encode(Sha256::digest(&signed_response_statement))
                    ),
                    "signature":format!(
                        "ed25519:{}",
                        general_purpose::URL_SAFE_NO_PAD.encode(signed_response_signature)
                    ),
                },
            },
            "upstream_response":{
                "status":200,
                "selected_raw_policy_headers_b64":selected_raw_policy_headers_b64,
                "body_digest":upstream_body_digest,
                "canonical_digest":upstream_canonical_digest,
            },
            "response":{
                "status":200,
                "selected_headers":selected_headers,
                "selected_headers_digest":selected_headers_digest,
                "body_digest":body_digest,
            },
            "policy_digest":policy_digest,
            "runtime_manifest_digest":runtime_manifest_digest,
            "data_plane_binary_digest":digest(7),
            "release_digest":release_digest,
            "server_instance":{
                "id":server_instance_id,
                "identity_digest":format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(server_instance_id.as_bytes()))
                ),
            },
            "tls_channel_binding":{
                "type":"tls-exporter",
                "value":general_purpose::URL_SAFE_NO_PAD.encode([12u8; 32]),
            },
        });
        let statement_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_bytes(&statement).expect("canonical statement")
            ))
        );
        let request = canonical_json_bytes(&json!({
            "apiVersion":PROTOCOL_API_VERSION,
            "bootId":runtime.boot_id(),
            "operation":RESPONSE_PROOF_SIGN_OPERATION,
            "params":{
                "statement":statement,
                "authorization_binding":authorization_binding,
            },
            "requestId":request_id(2),
        }))
        .expect("sign request");
        (request, statement_digest)
    }

    fn streaming_response_proof_sign_request(
        runtime: &CustodyRuntime,
    ) -> (Vec<u8>, Vec<u8>, String) {
        let (buffered_request, _) = response_proof_sign_request(runtime);
        let buffered: Value =
            decode_canonical_json(&buffered_request).expect("canonical buffered fixture");
        let authorization_binding = buffered["params"]["authorization_binding"].clone();
        let mut statement = buffered["params"]["statement"].clone();

        let binding_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_bytes(&authorization_binding).expect("authorization binding")
            ))
        );
        let operation_context_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_bytes(&authorization_binding["operation_context"])
                    .expect("operation context")
            ))
        );
        let binding_commitment = json!({
            "attempt_id":authorization_binding["attempt_id"],
            "flow_id":authorization_binding["flow_id"],
            "principal_id":authorization_binding["principal_id"],
            "route_id":authorization_binding["route_id"],
            "credential_id":authorization_binding["credential_id"],
            "credential_version":authorization_binding["credential_version"],
            "policy_hash":authorization_binding["policy_hash"],
            "request_digest":authorization_binding["request_digest"],
            "operation_digest":authorization_binding["operation_digest"],
            "operation_context_digest":operation_context_digest,
            "require_jit_grant":authorization_binding["require_jit_grant"],
            "shared_quotas":authorization_binding["shared_quotas"],
        });
        let receipt_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_bytes(&statement["control_plane_authorization_receipt"])
                    .expect("authorization receipt")
            ))
        );
        let upstream_body_bytes = 17;
        let upstream_canonical = json!({
            "status":statement["upstream_response"]["status"],
            "selected_raw_policy_headers_b64":statement["upstream_response"]["selected_raw_policy_headers_b64"],
            "body_digest":statement["upstream_response"]["body_digest"],
            "body_bytes":upstream_body_bytes,
        });
        let upstream_canonical_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_bytes(&upstream_canonical).expect("streaming upstream response")
            ))
        );
        let selected_wire_headers = json!({
            "connection":"close",
            "content-type":"application/json",
            "trailer":"X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256",
            "transfer-encoding":"chunked",
        });
        let selected_wire_headers_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_bytes(&selected_wire_headers).expect("streaming wire headers")
            ))
        );
        let released_body_digest = statement["response"]["body_digest"].clone();

        statement["apiVersion"] =
            Value::String("serverware.streamingResponseStatement/v1".to_string());
        statement["authorization_binding_validation"] = json!({
            "status":"validated",
            "binding_commitment":binding_commitment,
            "binding_digest":binding_digest,
        });
        statement["control_plane_authorization_receipt_sha256"] = Value::String(receipt_digest);
        statement["upstream_response"]["body_bytes"] = json!(upstream_body_bytes);
        statement["upstream_response"]["canonical_digest"] =
            Value::String(upstream_canonical_digest);
        statement["released_response"] = json!({
            "status":200,
            "content_type":"application/json",
            "selected_wire_headers":selected_wire_headers,
            "selected_wire_headers_digest":selected_wire_headers_digest,
            "body_digest":released_body_digest,
            "body_bytes":17,
            "framing":"http1.1-chunked-trailers",
            "completion":"normal-eof",
            "trailer_names":[
                "X-Serverware-Stream-Proof-B64",
                "X-Serverware-Stream-Proof-SHA256"
            ],
        });
        statement["tls_channel_binding"]["exporter_label"] =
            Value::String("EXPORTER-Serverware-Proxy-Stream-v1".to_string());
        statement
            .as_object_mut()
            .expect("streaming statement object")
            .remove("response");

        let canonical_statement =
            canonical_json_bytes(&statement).expect("canonical streaming statement");
        let statement_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(&canonical_statement))
        );
        let request = canonical_json_bytes(&json!({
            "apiVersion":PROTOCOL_API_VERSION,
            "bootId":runtime.boot_id(),
            "operation":STREAMING_RESPONSE_PROOF_SIGN_OPERATION,
            "params":{
                "statement":statement,
                "authorization_binding":authorization_binding,
            },
            "requestId":request_id(3),
        }))
        .expect("streaming sign request");
        (request, canonical_statement, statement_digest)
    }

    fn response_signing_key_over_a_unix_socket(runtime: &Arc<CustodyRuntime>) -> VerifyingKey {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let server_runtime = Arc::clone(runtime);
        let worker = thread::spawn(move || serve_connection(server, &server_runtime));
        let request = canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": request_id(4),
        }))
        .expect("hello request");
        write_frame(&mut client, &request, Duration::from_secs(1)).expect("write hello request");
        let response =
            read_frame(&mut client, Duration::from_secs(1)).expect("read hello response");
        worker
            .join()
            .expect("worker join")
            .expect("serve hello connection");
        let response: Value = decode_canonical_json(&response).expect("canonical hello response");
        VerifyingKey::from_public_key_pem(
            response["result"]["publicKeyPem"]
                .as_str()
                .expect("response signing public key PEM"),
        )
        .expect("Ed25519 response signing public key")
    }

    #[test]
    fn serves_a_canonical_hello_frame_over_a_unix_socket() {
        let (runtime, ledger_directory) = test_runtime("hello");
        let runtime = Arc::new(runtime);
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let server_runtime = Arc::clone(&runtime);
        let worker = thread::spawn(move || serve_connection(server, &server_runtime));
        let request = canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": request_id(1),
        }))
        .expect("request");
        write_frame(&mut client, &request, Duration::from_secs(1)).expect("write request");
        worker
            .join()
            .expect("worker join")
            .expect("serve connection");
        let response = read_frame(&mut client, Duration::from_secs(1)).expect("read response");
        let response: Value = decode_canonical_json(&response).expect("canonical response");
        assert_eq!(response["ok"], true);
        assert_eq!(response["result"]["hardwareProof"], false);
        assert_eq!(
            response["result"]["controlPlaneResponseSigningKeyId"],
            control_plane_response_signing_key_id()
        );
        drop(runtime);
        fs::remove_dir_all(ledger_directory).expect("remove hello ledger directory");
    }

    #[test]
    fn repeated_hello_frames_return_the_exact_pinned_liveness_response() {
        let (runtime, ledger_directory) = test_runtime("liveness");
        let runtime = Arc::new(runtime);
        let request = canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": request_id(17),
        }))
        .expect("canonical liveness request");
        let mut pinned_response = None;

        for _ in 0..3 {
            let (mut client, server) = UnixStream::pair().expect("socket pair");
            let server_runtime = Arc::clone(&runtime);
            let worker = thread::spawn(move || serve_connection(server, &server_runtime));
            write_frame(&mut client, &request, Duration::from_secs(1))
                .expect("write liveness request");
            let response =
                read_frame(&mut client, Duration::from_secs(1)).expect("read liveness response");
            worker
                .join()
                .expect("worker join")
                .expect("serve liveness request");
            let decoded: Value =
                decode_canonical_json(&response).expect("canonical liveness response");
            assert_eq!(decoded["ok"], true);
            assert_eq!(decoded["bootId"], runtime.boot_id());
            assert_eq!(
                decoded["result"]["controlPlaneResponseSigningKeyId"],
                control_plane_response_signing_key_id()
            );
            if let Some(expected) = pinned_response.as_ref() {
                assert_eq!(&response, expected, "pinned hello response changed");
            } else {
                pinned_response = Some(response);
            }
        }

        drop(runtime);
        fs::remove_dir_all(ledger_directory).expect("remove liveness ledger directory");
    }

    #[test]
    fn serves_a_response_proof_sign_v2_round_trip_over_a_unix_socket() {
        let (runtime, ledger_directory) = test_runtime("sign");
        let runtime = Arc::new(runtime);
        let (request, expected_statement_digest) = response_proof_sign_request(&runtime);
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let server_runtime = Arc::clone(&runtime);
        let worker = thread::spawn(move || serve_connection(server, &server_runtime));

        write_frame(&mut client, &request, Duration::from_secs(1)).expect("write sign request");
        let response = read_frame(&mut client, Duration::from_secs(1)).expect("read sign response");
        worker
            .join()
            .expect("worker join")
            .expect("serve sign connection");
        let response: Value = decode_canonical_json(&response).expect("canonical sign response");
        assert_eq!(response["ok"], true, "unexpected response: {response}");
        assert_eq!(
            response["result"]["statementDigest"],
            expected_statement_digest
        );
        assert!(response["result"]["signature"]
            .as_str()
            .expect("signature")
            .starts_with("ed25519:"));
        drop(runtime);
        fs::remove_dir_all(ledger_directory).expect("remove sign ledger directory");
    }

    #[test]
    fn serves_a_streaming_response_proof_sign_v1_round_trip_over_a_unix_socket() {
        let (runtime, ledger_directory) = test_runtime("streaming-sign");
        let runtime = Arc::new(runtime);
        let verifying_key = response_signing_key_over_a_unix_socket(&runtime);
        let (request, canonical_statement, expected_statement_digest) =
            streaming_response_proof_sign_request(&runtime);
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let server_runtime = Arc::clone(&runtime);
        let worker = thread::spawn(move || serve_connection(server, &server_runtime));

        write_frame(&mut client, &request, Duration::from_secs(1))
            .expect("write streaming sign request");
        let response =
            read_frame(&mut client, Duration::from_secs(1)).expect("read streaming sign response");
        worker
            .join()
            .expect("worker join")
            .expect("serve streaming sign connection");
        let response: Value =
            decode_canonical_json(&response).expect("canonical streaming sign response");
        assert_eq!(response["ok"], true, "unexpected response: {response}");
        assert_eq!(
            response["operation"],
            STREAMING_RESPONSE_PROOF_SIGN_OPERATION
        );
        assert_eq!(
            response["result"]["statementDigest"],
            expected_statement_digest
        );
        let encoded_signature = response["result"]["signature"]
            .as_str()
            .and_then(|value| value.strip_prefix("ed25519:"))
            .expect("streaming statement signature");
        let signature_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .expect("canonical signature base64url");
        let signature = Signature::from_slice(&signature_bytes).expect("Ed25519 signature");
        verifying_key
            .verify_strict(&canonical_statement, &signature)
            .expect("signature covers the exact canonical streaming statement");
        drop(runtime);
        fs::remove_dir_all(ledger_directory).expect("remove streaming sign ledger directory");
    }

    #[test]
    fn rejects_oversized_and_truncated_frames() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client
            .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .expect("write oversized length");
        assert!(read_frame(&mut server, Duration::from_secs(1))
            .expect_err("oversized frame")
            .to_string()
            .contains("exceeds"));

        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client.write_all(&8u32.to_be_bytes()).expect("write length");
        client.write_all(b"abc").expect("write partial payload");
        client.shutdown(Shutdown::Write).expect("shutdown writer");
        assert!(read_frame(&mut server, Duration::from_secs(1))
            .expect_err("truncated frame")
            .to_string()
            .contains("truncated frame"));
    }

    #[test]
    fn rejects_a_slow_partial_frame_on_the_absolute_deadline() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client.write_all(&8u32.to_be_bytes()).expect("write length");
        client.write_all(b"a").expect("write first byte");
        let started = std::time::Instant::now();
        let error =
            read_frame(&mut server, Duration::from_millis(75)).expect_err("slow partial frame");
        assert!(error.to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn concurrency_permits_are_strictly_bounded_and_released() {
        let active = Arc::new(AtomicUsize::new(0));
        let permits = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|_| ConnectionPermit::try_acquire(Arc::clone(&active)).expect("permit"))
            .collect::<Vec<_>>();
        assert!(ConnectionPermit::try_acquire(Arc::clone(&active)).is_none());
        drop(permits);
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert!(ConnectionPermit::try_acquire(active).is_some());
    }

    #[test]
    fn expected_client_uid_configuration_is_explicit_and_rejects_invalid_values() {
        assert!(parse_expected_client_uid(None).is_err());
        assert_eq!(
            parse_expected_client_uid(Some(OsString::from("1001"))).expect("configured UID"),
            1001
        );

        for invalid in ["", "-1", "+1", " 1", "1 ", "1.0"] {
            assert!(parse_expected_client_uid(Some(OsString::from(invalid))).is_err());
        }
        assert!(parse_expected_client_uid(Some(OsString::from("4294967296"))).is_err());
        assert!(parse_expected_client_uid(Some(OsString::from_vec(vec![0xff]))).is_err());
    }

    #[test]
    fn attempt_ledger_directory_configuration_is_explicit_and_absolute() {
        assert!(parse_attempt_ledger_directory(None).is_err());
        for invalid in [OsString::from(""), OsString::from("relative/ledger")] {
            assert!(parse_attempt_ledger_directory(Some(invalid)).is_err());
        }
        assert_eq!(
            parse_attempt_ledger_directory(Some(OsString::from("/var/lib/serverware-custody")))
                .expect("absolute ledger directory"),
            PathBuf::from("/var/lib/serverware-custody")
        );
        let non_utf8 = OsString::from_vec(vec![b'/', 0xff]);
        assert!(parse_attempt_ledger_directory(Some(non_utf8)).is_ok());
    }

    #[test]
    fn attempt_ledger_initialization_mode_is_explicit_and_one_shot() {
        let (socket, initialize) = parse_runtime_arguments(
            [
                "--socket".to_string(),
                "/tmp/custody-test.sock".to_string(),
                "--initialize-attempt-ledger".to_string(),
            ]
            .into_iter(),
        )
        .expect("initialization arguments");
        assert_eq!(socket, PathBuf::from("/tmp/custody-test.sock"));
        assert!(initialize);
        assert!(parse_runtime_arguments(
            [
                "--initialize-attempt-ledger".to_string(),
                "--initialize-attempt-ledger".to_string(),
            ]
            .into_iter(),
        )
        .is_err());
    }

    #[test]
    fn shared_group_socket_setup_requires_exact_directory_and_socket_invariants() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory =
            PathBuf::from("/tmp").join(format!("sw-custody-{}-{unique:x}", std::process::id()));
        fs::create_dir(&directory).expect("create socket directory");
        fs::set_permissions(
            &directory,
            fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE),
        )
        .expect("set socket directory mode");
        // SAFETY: credential getters have no memory-safety preconditions.
        let expected = ExpectedClient {
            uid: unsafe { libc::geteuid() }.wrapping_add(1),
            runtime_uid: unsafe { libc::geteuid() },
            shared_gid: unsafe { libc::getegid() },
        };
        let directory_c = std::ffi::CString::new(directory.as_os_str().as_bytes())
            .expect("socket directory C path");
        // SAFETY: the path is NUL-terminated and points to the test-owned directory.
        assert_eq!(
            unsafe {
                libc::chown(
                    directory_c.as_ptr(),
                    expected.runtime_uid,
                    expected.shared_gid,
                )
            },
            0,
            "set socket directory ownership: {}",
            io::Error::last_os_error()
        );
        let socket_path = directory.join("custody.sock");
        validate_socket_directory(&socket_path, expected).expect("valid socket directory");

        let listener = UnixListener::bind(&socket_path).expect("bind fixture socket");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(SOCKET_MODE))
            .expect("set fixture socket mode");
        validate_bound_socket(&socket_path, expected).expect("valid shared-group socket");

        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .expect("set wrong socket mode");
        assert_eq!(
            validate_bound_socket(&socket_path, expected)
                .expect_err("socket mode mismatch")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(SOCKET_MODE))
            .expect("restore socket mode");

        let wrong_owner = ExpectedClient {
            runtime_uid: expected.runtime_uid.wrapping_add(1),
            ..expected
        };
        assert_eq!(
            validate_socket_directory(&socket_path, wrong_owner)
                .expect_err("directory owner mismatch")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            validate_bound_socket(&socket_path, wrong_owner)
                .expect_err("socket owner mismatch")
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        drop(listener);
        fs::remove_file(socket_path).expect("remove fixture socket");
        fs::remove_dir(directory).expect("remove fixture directory");
    }

    #[test]
    fn rejects_a_peer_uid_mismatch_without_reading_client_data() {
        let path = env::temp_dir().join(format!(
            "serverware-custody-runtime-peer-test-{}",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).expect("bind peer credential fixture");
        let mut client = UnixStream::connect(&path).expect("connect peer credential fixture");
        let (mut server, _) = listener.accept().expect("accept peer credential fixture");
        drop(listener);
        fs::remove_file(path).expect("remove peer credential fixture socket");

        client
            .write_all(b"pending-frame-data")
            .expect("write pending client data");
        let peer_uid = peer_effective_uid(&server).expect("peer UID");
        // SAFETY: geteuid has no memory-safety preconditions.
        assert_eq!(peer_uid, unsafe { libc::geteuid() });
        let error = authenticate_client_peer(&server, peer_uid.wrapping_add(1))
            .expect_err("mismatched peer UID must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("does not match expected UID"));

        let mut pending = [0u8; 18];
        server
            .read_exact(&mut pending)
            .expect("peer authentication must not consume client data");
        assert_eq!(&pending, b"pending-frame-data");
    }

    #[test]
    fn refuses_to_replace_a_non_socket_path() {
        let path = env::temp_dir().join(format!(
            "serverware-custody-runtime-test-{}",
            std::process::id()
        ));
        fs::write(&path, b"not a socket").expect("write fixture");
        let error = remove_stale_socket(&path).expect_err("non-socket path");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn refuses_to_replace_an_active_socket() {
        let path = env::temp_dir().join(format!(
            "serverware-custody-runtime-active-test-{}",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).expect("bind fixture socket");
        let error = remove_stale_socket(&path).expect_err("active socket");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        drop(listener);
        fs::remove_file(path).expect("remove fixture socket");
    }
}

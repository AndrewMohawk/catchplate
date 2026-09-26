//! The same custody protocol over an actual in-process native owner.
//!
//! This is not a second signer or a production activation switch. Authorization,
//! attempt claims and observation reservations remain in CustodyRuntime. Native
//! custody is within the gate's address space, not a separate UID boundary; an
//! original NSM quote is not independent release or rollback admission.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) enum CustodySignerTransport {
    Unix { socket_path: PathBuf, expected_uid: libc::uid_t },
    Native(Arc<NativeCustodyTransport>),
}

pub(super) struct NativeCustodyTransport {
    runtime: CustodyRuntime,
    active: AtomicUsize,
}

impl std::fmt::Debug for CustodySignerTransport {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix { socket_path, expected_uid } => output.debug_struct("Unix")
                .field("socket_path", socket_path).field("expected_uid", expected_uid).finish(),
            Self::Native(_) => output.debug_struct("Native")
                .field("independently_admitted", &false).finish(),
        }
    }
}

struct NativeOperationPermit<'a>(&'a AtomicUsize);
impl Drop for NativeOperationPermit<'_> {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::AcqRel); }
}

impl CustodySignerTransport {
    pub(super) fn mode(&self) -> &'static str {
        match self { Self::Unix { .. } => "custody-uds", Self::Native(_) => "custody-native" }
    }

    pub(super) fn probe_assurance(&self) -> &'static str {
        match self {
            Self::Unix { .. } => "hello-pinned-boot-key-peer-uid",
            Self::Native(_) => "hello-pinned-boot-key-native-owner-unadmitted",
        }
    }

    pub(super) fn verify_live(&self) -> Result<(), String> {
        match self {
            Self::Unix { .. } => Ok(()), // Existing UDS health and peer checks remain authoritative here.
            Self::Native(owner) => owner.runtime.verify_native_live().map_err(|error| error.to_string()),
        }
    }

    pub(super) fn require_native(&self) -> Result<(), String> {
        match self {
            Self::Native(_) => self.verify_live(),
            Self::Unix { .. } => Err("native bootstrap requires its actual native custody owner".to_owned()),
        }
    }

    pub(super) fn verify_native_identity(&self, identity: &mut EnclaveRuntimeIdentityV1,
        deadline: u64) -> Result<(), String> {
        match self {
            Self::Native(owner) => owner.runtime.verify_native_identity(identity, deadline)
                .map_err(|error| error.to_string()),
            Self::Unix { .. } => Err("a UDS signer cannot establish native key custody".to_owned()),
        }
    }

    pub(super) fn manifest(&self) -> Value {
        match self {
            Self::Unix { expected_uid, .. } => json!({
                "kind":"unix-domain-socket", "peer_authentication":"uid", "expected_uid":expected_uid,
            }),
            Self::Native(owner) => json!({
                "kind":"in-process-native-owner",
                "peer_authentication":"retained-object",
                "isolation":"shared-gate-address-space",
                "hardware_proof":false,
                "quote_assurance":"unverified-original",
                "quote_sha256":owner.runtime.native_quote().map(|quote| sha256_prefixed(quote.document())),
                "rollback_protection":"filesystem-development",
            }),
        }
    }

    pub(super) fn exchange(&self, request: &CustodyRequest, deadline: Instant)
        -> Result<Zeroizing<Vec<u8>>, String> {
        self.verify_live()?;
        match self {
            Self::Unix { socket_path, expected_uid } => {
                let mut stream = connect_custody_socket(socket_path, *expected_uid, deadline)
                    .map_err(|error| match error {
                        CustodyHelloAttemptError::Retryable(error) | CustodyHelloAttemptError::Fatal(error) => error,
                    })?;
                custody_exchange(&mut stream, request, deadline)
            }
            Self::Native(owner) => {
                owner.active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                    |active| (active < CUSTODY_MAX_CONCURRENT_CONNECTIONS).then_some(active + 1))
                    .map_err(|_| "native custody concurrency limit reached".to_owned())?;
                let _permit = NativeOperationPermit(&owner.active);
                custody_deadline_remaining(deadline, "native request encoding")?;
                let bytes = Zeroizing::new(custody_canonical_json_bytes(request)
                    .map_err(|_| "encode canonical native custody request".to_owned())?);
                if bytes.is_empty() || bytes.len() > CUSTODY_MAX_FRAME_BYTES {
                    return Err("native custody request exceeds its protocol frame bound".to_owned());
                }
                self.verify_live()?;
                custody_deadline_remaining(deadline, "native operation")?;
                let response = Zeroizing::new(owner.runtime.handle_canonical_request(&bytes)
                    .map_err(|error| error.to_string())?);
                self.verify_live()?;
                custody_deadline_remaining(deadline, "native response")?;
                if response.is_empty() || response.len() > CUSTODY_MAX_FRAME_BYTES {
                    return Err("native custody response exceeds its protocol frame bound".to_owned());
                }
                Ok(response)
            }
        }
    }

    pub(super) fn hello(&self, deadline: Instant) -> Result<CustodyResponseProofSigner, String> {
        match self {
            Self::Unix { socket_path, expected_uid } => custody_hello_once(socket_path, *expected_uid, deadline)
                .map_err(|error| match error {
                    CustodyHelloAttemptError::Retryable(error) | CustodyHelloAttemptError::Fatal(error) => error,
                }),
            Self::Native(owner) => {
                let request_id = canonical_custody_request_id()?;
                let request = CustodyRequest {
                    api_version: CUSTODY_PROTOCOL_API_VERSION.to_owned(), request_id: request_id.clone(),
                    boot_id: None, operation: CUSTODY_HELLO_OPERATION.to_owned(), params: json!({}),
                };
                let response = self.exchange(&request, deadline)?;
                validate_custody_hello_response_for_transport(&response, &request_id,
                    Self::Native(Arc::clone(owner)), deadline)
            }
        }
    }
}

/// Consume a runtime generated by the native constructor, never a development
/// key, host socket, raw seed or caller-supplied metadata pretending to be one.
/// Startup separately joins this owner to the actual retained TLS identity.
pub(super) fn initialize_native_response_proof_signer(runtime: CustodyRuntime)
    -> Result<ResponseProofSigningMaterial, String> {
    if !runtime.is_native() || runtime.native_quote().is_none() {
        return Err("native proof signer requires generated and quoted native custody".to_owned());
    }
    runtime.verify_native_live().map_err(|error| error.to_string())?;
    let transport = CustodySignerTransport::Native(Arc::new(NativeCustodyTransport {
        runtime, active: AtomicUsize::new(0),
    }));
    let signer = transport.hello(custody_deadline_after(CUSTODY_IO_DEADLINE)?)?;
    signer.transport.verify_live()?;
    Ok(ResponseProofSigningMaterial {
        public_key_pem: signer.public_key_pem.clone(), key_id: signer.key_id.clone(),
        signer: ResponseProofSigner::Custody(signer),
    })
}

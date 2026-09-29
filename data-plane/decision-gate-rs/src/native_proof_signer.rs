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
    pub(super) fn is_native(&self) -> bool { matches!(self, Self::Native(_)) }

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

    pub(super) fn quote_native_signed_statement(&self, identity: &mut EnclaveRuntimeIdentityV1,
        statement: &[u8], signature: &str, client_nonce: &[u8], deadline: u64)
        -> Result<Value, String> {
        let Self::Native(owner) = self else {
            return Err("fresh native proof attestation requires its actual native signer".to_owned());
        };
        self.verify_live()?;
        owner.active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < CUSTODY_MAX_CONCURRENT_CONNECTIONS).then_some(active + 1))
            .map_err(|_| "native custody concurrency limit reached".to_owned())?;
        let _permit = NativeOperationPermit(&owner.active);
        let evidence = owner.runtime.quote_native_signed_statement(
            identity, statement, signature, client_nonce, deadline,
        ).map_err(|error| error.to_string())?;
        self.verify_live()?;
        Ok(evidence)
    }

    pub(super) fn currentness_evidence(&self, identity: &mut EnclaveRuntimeIdentityV1,
        prepared: &credential_currentness::PreparedEvidence, deadline: u64) -> Result<Value, String> {
        let Self::Native(owner) = self else { return Err("currentness refuses unmeasured UDS custody".to_owned()); };
        self.verify_live()?;
        owner.active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < CUSTODY_MAX_CONCURRENT_CONNECTIONS).then_some(active + 1))
            .map_err(|_| "native custody concurrency limit reached".to_owned())?;
        let _permit = NativeOperationPermit(&owner.active);
        let evidence = owner.runtime.sign_native_currentness(identity, prepared.statement(), deadline)
            .map_err(|error| error.to_string())?;
        self.verify_live()?;
        Ok(evidence)
    }

    pub(super) fn audit_evidence(&self, identity:&mut EnclaveRuntimeIdentityV1,
        prepared:&native_audit_owner::Prepared, deadline:u64)->Result<Value,String> {
        let Self::Native(owner)=self else{return Err("audit refuses unmeasured UDS custody".into());};
        self.verify_live()?;
        owner.active.fetch_update(Ordering::AcqRel,Ordering::Acquire,
            |active|(active<CUSTODY_MAX_CONCURRENT_CONNECTIONS).then_some(active+1))
            .map_err(|_|"native audit custody concurrency bound")?;
        let _permit=NativeOperationPermit(&owner.active);
        let value=owner.runtime.sign_native_audit(identity,prepared.statement(),deadline).map_err(|e|e.to_string())?;
        self.verify_live()?; Ok(value)
    }

    pub(super) fn target_dispatch_evidence(&self,identity:&mut EnclaveRuntimeIdentityV1,
        prepared:&native_target_dispatch::Prepared<'_>,deadline:u64)
        ->Result<serverware_decision_gate::native_target_dispatch_v1::NativeCaptureEnvelope,String> {
        let Self::Native(owner)=self else {return Err("target dispatch refuses unmeasured UDS custody".into());};
        self.verify_live()?;
        owner.active.fetch_update(Ordering::AcqRel,Ordering::Acquire,
            |active|(active<CUSTODY_MAX_CONCURRENT_CONNECTIONS).then_some(active+1))
            .map_err(|_|"target dispatch custody concurrency bound")?;
        let _permit=NativeOperationPermit(&owner.active);
        let result=owner.runtime.sign_native_target_dispatch(identity,prepared.statement()?,deadline).map_err(|e|e.to_string())?;
        prepared.statement()?;self.verify_live()?;Ok(result)
    }

    pub(super) fn refresh_evidence(&self, identity: &mut EnclaveRuntimeIdentityV1,
        prepared: &serverware_decision_gate::native_oauth_refresh_v1::Prepared,
        binary: &str, deadline: u64) -> Result<Value, String> {
        let Self::Native(owner) = self else { return Err("refresh refuses unmeasured UDS custody".to_owned()); };
        self.verify_live()?;
        owner.active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < CUSTODY_MAX_CONCURRENT_CONNECTIONS).then_some(active + 1))
            .map_err(|_| "native refresh custody concurrency bound")?;
        let _permit = NativeOperationPermit(&owner.active);
        let result = owner.runtime.sign_native_refresh(identity, prepared, binary, deadline).map_err(|error|error.to_string())?;
        self.verify_live()?; Ok(result)
    }

    pub(super) fn exchange_evidence(&self, identity: &mut EnclaveRuntimeIdentityV1,
        prepared: &serverware_decision_gate::native_oauth_exchange_v1::Prepared,
        binary: &str, deadline: u64) -> Result<Value,String> {
        let Self::Native(owner) = self else { return Err("initial issuance refuses unmeasured custody".to_owned()); };
        self.verify_live()?;
        owner.active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < CUSTODY_MAX_CONCURRENT_CONNECTIONS).then_some(active + 1)).map_err(|_|"initial custody concurrency")?;
        let _permit = NativeOperationPermit(&owner.active);
        let result = owner.runtime.sign_native_exchange(identity, prepared, binary, deadline).map_err(|error|error.to_string())?;
        self.verify_live()?; Ok(result)
    }

    pub(super) fn cleanup_evidence(&self, identity: &mut EnclaveRuntimeIdentityV1,
        prepared: &serverware_decision_gate::native_oauth_cleanup_v1::Prepared,
        binary: &str, deadline: u64) -> Result<Value, String> {
        let Self::Native(owner) = self else { return Err("cleanup refuses unmeasured custody".to_owned()); };
        self.verify_live()?;
        owner.active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < CUSTODY_MAX_CONCURRENT_CONNECTIONS).then_some(active + 1))
            .map_err(|_|"native cleanup custody concurrency bound")?;
        let _permit = NativeOperationPermit(&owner.active);
        let result = owner.runtime.sign_native_cleanup(identity, prepared, binary, deadline).map_err(|error|error.to_string())?;
        self.verify_live()?; Ok(result)
    }

    pub(super) fn currentness_lease(&self, prepared: &credential_currentness::PreparedLease<'_>) -> Result<String, String> {
        let Self::Native(owner) = self else { return Err("currentness refuses unmeasured UDS custody".to_owned()); };
        self.verify_live()?;
        let (holder, epoch, registration, request) = prepared.parts();
        let signature = if prepared.broker() {
            owner.runtime.sign_native_broker_currentness_lease(holder, epoch, registration, request)
        } else { owner.runtime.sign_native_currentness_lease(holder, epoch, registration, request) }
            .map_err(|error| error.to_string())?;
        self.verify_live()?;
        Ok(signature)
    }

    /// Native bootstrap only, over the same actual runtime/ledger owner. The
    /// caller retains real policy/configuration guards; the library repeats
    /// original verification and claims durably before generating a key.
    pub(super) fn sign_native_bootstrap_enrollment(&self,
        identity: &mut EnclaveRuntimeIdentityV1,
        ingress: &serverware_decision_gate::enclave_runtime_identity_v1::QuotedMutualTlsIngressV1,
        connection: &rustls::ServerConnection, packet_original: &[u8],
        delegation_pem: &[u8], delegation_pem_sha256: &str,
        setup_pem: &[u8], setup_pem_sha256: &str, challenge: [u8; 32], deadline: u64)
        -> Result<serverware_decision_gate::enclave_runtime_identity_v1::BootstrapEnrollmentOriginalV1, String> {
        let Self::Native(owner) = self else {
            return Err("bootstrap enrollment requires its actual native custody runtime".to_owned());
        };
        self.verify_live()?;
        owner.active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < CUSTODY_MAX_CONCURRENT_CONNECTIONS).then_some(active + 1))
            .map_err(|_| "native custody concurrency limit reached".to_owned())?;
        let _permit = NativeOperationPermit(&owner.active);
        let original = identity.sign_bootstrap_enrollment_once(&owner.runtime, ingress,
            connection, packet_original, delegation_pem, delegation_pem_sha256,
            setup_pem, setup_pem_sha256, challenge, deadline)?;
        self.verify_live()?;
        Ok(original)
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
                "response_attestation_profile":"serverware.nativeResponseRuntimeProof/v1",
                "response_attestation_admission":"independent-client-profile-required",
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
        self.hello_profile(if self.is_native() { ReleaseProfile::Native } else { ReleaseProfile::Legacy }, deadline)
    }

    pub(super) fn hello_profile(&self, profile: ReleaseProfile, deadline: Instant)
        -> Result<CustodyResponseProofSigner, String> {
        if profile.is_native() != self.is_native() {
            return Err("cold release profile differs from actual custody transport".to_owned());
        }
        let request_id = canonical_custody_request_id()?;
        let request = CustodyRequest {
            api_version: CUSTODY_PROTOCOL_API_VERSION.to_owned(), request_id: request_id.clone(),
            boot_id: None, operation: CUSTODY_HELLO_OPERATION.to_owned(), params: json!({}),
        };
        let response = self.exchange(&request, deadline)?;
        let retained_transport = match self {
            Self::Unix { socket_path, expected_uid } => Self::Unix {
                socket_path: socket_path.clone(), expected_uid: *expected_uid,
            },
            Self::Native(owner) => Self::Native(Arc::clone(owner)),
        };
        validate_custody_hello_response_for_transport_profile(&response, &request_id,
            retained_transport, deadline, profile)
    }
}

/// Consume a runtime generated by the native constructor, never a development
/// key, host socket, raw seed or caller-supplied metadata pretending to be one.
/// Startup separately joins this owner to the actual retained TLS identity.
pub(super) fn initialize_native_response_proof_signer(runtime: CustodyRuntime)
    -> Result<ResponseProofSigningMaterial, String> {
    if env::var_os(RESPONSE_PROOF_RELEASE_PROFILE_ENV).is_some() {
        return Err("ordinary response release profile cannot override native custody".to_owned());
    }
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

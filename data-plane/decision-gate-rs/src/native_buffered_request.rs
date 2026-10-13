//! Borrowed CONNECT originals for the native buffered release path.
//!
//! This retains actual transport/request owners; it is NOT library admission,
//! a signing permit, or a replacement for purpose-specific original verification.
use super::*;

fn require(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("native buffered request originals differ".to_owned()) }
}

fn request_deadline(opening: Instant, remaining: Duration, connection: Option<Instant>)
    -> Result<Instant, String> {
    let deadline = opening.checked_add(remaining.min(Duration::from_secs(30)))
        .ok_or("native buffered request deadline overflow")?;
    Ok(connection.map_or(deadline, |cap| cap.min(deadline)))
}

/// Sampled BEFORE one inner request's head intake, never installed on the
/// persistent keep-alive socket and never reconstructed at reserve time.
pub(super) struct Context<'a> {
    authentication: &'a ConnectAuthentication,
    deadline: Instant,
}

impl<'a> Context<'a> {
    pub(super) fn open(state: &GateState, stream: &DirectProxyStream,
        authentication: &'a ConnectAuthentication) -> Result<Option<Self>, String> {
        if !state.response_proof_signer.release_profile().is_native() { return Ok(None); }
        let opening = Instant::now();
        let remaining = native_service_remaining(state)?
            .ok_or("native buffered request cohort is absent")?;
        let connection = match stream {
            DirectProxyStream::DevelopmentRaw(io) => io.operation_deadline,
            DirectProxyStream::MutualTls(tls) => tls.stream.sock.operation_deadline,
        };
        let context = Self { authentication,
            deadline: request_deadline(opening, remaining, connection)? };
        custody_deadline_remaining(context.deadline, "native buffered request intake")?;
        Ok(Some(context))
    }
}

/// A buffered proof does not lend its writer to the inner forwarding function;
/// otherwise borrow that function's existing writer only during the decision.
pub(super) enum Ingress<'a> {
    FromWriter(&'a Context<'a>),
    Borrowed(&'a Context<'a>, Option<&'a RetainedProxyIngressTls>),
}

impl<'a> Ingress<'a> {
    pub(super) fn originals<'b>(&'b self, writer: Option<&'b dyn TerminalDeadlineWrite>)
        -> (&'b Context<'a>, Option<&'b RetainedProxyIngressTls>) {
        match self {
            Self::FromWriter(context) => (context, writer.and_then(|io| io.retained_proxy_ingress())),
            Self::Borrowed(context, tls) => (context, *tls),
        }
    }
}

/// Created inside the forwarding function AFTER IncomingRequest has moved
/// there. All references end before that same writer is used for a response.
/// No Clone/Deserialize or caller-produced authorization verdict is accepted.
pub(super) struct BorrowedRequest<'a> {
    context: &'a Context<'a>,
    tls: &'a RetainedProxyIngressTls,
    request: &'a IncomingRequest,
    snapshot: &'a Arc<Snapshot>,
    client_request_digest: Option<&'a str>,
}

impl<'a> BorrowedRequest<'a> {
    pub(super) fn retain(context: &'a Context<'a>, tls: &'a RetainedProxyIngressTls,
        request: &'a IncomingRequest, snapshot: &'a Arc<Snapshot>,
        client_request_digest: Option<&'a str>) -> Self {
        Self { context, tls, request, snapshot, client_request_digest }
    }

    pub(super) fn deadline(&self) -> Instant { self.context.deadline }

    pub(super) fn check(&self, state: &GateState, snapshot: &Arc<Snapshot>,
        principal_id: &str) -> Result<(), String> {
        custody_deadline_remaining(self.deadline(), "native buffered request")?;
        require(state.response_proof_signer.release_profile().is_native()
            && Arc::ptr_eq(snapshot, self.snapshot) && snapshot_is_active(state, self.snapshot))?;
        native_service_remaining(state)?.ok_or("native buffered request cohort is absent")?;
        self.tls.stream.sock.check_operation_deadline()
            .map_err(|_| "native buffered request connection expired")?;
        let configuration = &self.tls.configuration;
        let ingress = configuration.native_owner.as_ref()
            .ok_or("native buffered request has no generated ingress owner")?;
        let generated = ingress.tls();
        require(Arc::ptr_eq(&configuration.server_config, &generated.server_config())
            && configuration.client_trust_bundle_original.is_none()
            && configuration.workload_identity_trust.is_none()
            && configuration.client_trust_certificates.len() == generated.client_trust_certificates().len()
            && configuration.client_trust_certificates.iter().zip(generated.client_trust_certificates())
                .all(|(actual, original)| actual.as_ref() == original.as_slice())
            && !self.tls.stream.conn.is_handshaking()
            && self.tls.stream.conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3))?;
        let original = self.context.authentication.trusted_mtls_evidence.as_ref()
            .ok_or("native buffered request original peer is absent")?;
        let chain = self.tls.stream.conn.peer_certificates()
            .ok_or("native buffered request actual peer is absent")?;
        let repeated = trusted_mtls_evidence_from_verified_peer(chain,
            &configuration.client_trust_certificates)?;
        require(original.identity_digest() == repeated.identity_digest()
            && original.is_live_at(now_epoch_ms()))?;
        let principal = self.context.authentication.revalidate(snapshot)
            .map_err(|_| "native buffered request caller changed")?;
        require(principal.id == principal_id
            && self.request.client_ip == self.context.authentication.client_ip)?;
        require(snapshot_is_active(state, self.snapshot))?;
        custody_deadline_remaining(self.deadline(), "native buffered request checked")?;
        Ok(())
    }

    fn check_stable_request(&self, request: &DecisionRequest) -> Result<(), String> {
        require(request.client_ip == self.request.client_ip
            && request.method == self.request.method && request.url == self.request.target
            && request.body_sha256.as_deref() == Some(body_sha_bytes(&self.request.body).as_str())
            && request.forwarded_body_length == Some(self.request.body.len() as u64)
            && request.forwarded_body_utf8_valid == Some(std::str::from_utf8(&self.request.body).is_ok())
            && request.client_request_digest.as_deref() == self.client_request_digest)?;
        // Gzip's actual retained wire owner is already constructed by the
        // reviewed request parser. Never replace it with a caller assertion.
        match request.npm_install_audit_body.as_ref() {
            Some(body) => require(body.matches_wire(&self.request.body) && body.decoded_text() == request.body),
            None => require(std::str::from_utf8(&self.request.body).unwrap_or_default() == request.body),
        }
    }

    /// Called once at the actual decision entrance BEFORE authorized header
    /// stripping, credential metadata hydration or active proof selection.
    pub(super) fn begin(&self, request: &DecisionRequest) -> Result<DecisionOriginals<'_>, String> {
        self.check_stable_request(request)?;
        require(request.headers == self.request.headers
            && request.credential_metadata.is_empty() && request.gmail_proofs.is_empty())?;
        Ok(DecisionOriginals { original: self })
    }
}

pub(super) struct DecisionOriginals<'a> {
    original: &'a BorrowedRequest<'a>,
}

impl DecisionOriginals<'_> {
    /// Retain the actual trusted pipeline's final projection by immutable
    /// borrow, not a re-created caller DTO or a detached success marker.
    pub(super) fn retain_release<'a>(&'a self, request: &'a DecisionRequest,
        route: &'a Route, canonical: &'a Value) -> Result<ReleaseOriginals<'a>, String> {
        self.original.check_stable_request(request)?;
        Ok(ReleaseOriginals { original: self.original, request, route, canonical })
    }
}

pub(super) struct ReleaseOriginals<'a> {
    original: &'a BorrowedRequest<'a>,
    request: &'a DecisionRequest,
    route: &'a Route,
    canonical: &'a Value,
}

impl ReleaseOriginals<'_> {
    pub(super) fn deadline(&self) -> Instant { self.original.deadline() }

    fn check_projection(&self, request: &DecisionRequest, route: &Route, canonical: &Value)
        -> Result<(), String> {
        require(std::ptr::eq(self.request, request) && std::ptr::eq(self.route, route)
            && std::ptr::eq(self.canonical, canonical))?;
        self.original.check_stable_request(request)
    }
}

pub(super) fn check_release(profile: ReleaseProfile, require_jit: bool,
    original: Option<&ReleaseOriginals<'_>>, state: &GateState, snapshot: &Arc<Snapshot>,
    principal_id: &str, request: &DecisionRequest, route: &Route, canonical: &Value) -> Result<(), String> {
    if profile.is_native() && require_jit && original.is_none() {
        return Err("native JIT requires original buffered CONNECT request".to_owned());
    }
    if let Some(original) = original {
        original.check_projection(request, route, canonical)?;
        original.original.check(state, snapshot, principal_id)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_buffered_request_tests.rs"]
mod tests;

//! One purpose-fixed cold commissioning run, before any policy load exists.
//! The normal bridge cannot bootstrap itself from a receipt it has not issued.
use super::*;
use super::ledger_spool_values::{invalid, sha};
use super::guest::native_guest::{self as native_guest, retrieval_peer::EndpointKind};
use super::publication_genesis as fixed;
use super::spool_head_values::RoleKey;
use super::publication_genesis_service::{Grant, Command, Action, Reply};
use super::production::{ProductionAuthorityEndpointIdentityV4 as EndpointIdentity,
    ProductionAuthorityEndpointRequestBodyV4 as Body, ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionAuthorityEndpointRequestV4 as Request, ProductionAuthorityEndpointReplyV4 as Response,
    ProductionProofEndpointKindV4 as Proof};
use crate::policy_shadow::PolicyShadowCustodySignerRole as Signer;

pub(super) const RUNTIME: &str = "serverware.nativePublicationGenesisCoordinatorRuntime/v1";
pub(super) const RESULT_FD: &str = "publication-genesis-result";
pub(super) const RESULT_PARENT_FD: &str = "publication-genesis-result-parent";
pub(super) const MAX_CONFIGURATION: usize = 4 * 1024 * 1024;
const MAX_GRANT: usize = 256 * 1024;

fn require(value: bool) -> Result<(), ServiceError> {
    if value { Ok(()) } else { Err(invalid()) }
}
fn roles() -> BTreeSet<TrustedHostServiceRoleV3> {
    BTreeSet::from([TrustedHostServiceRoleV3::DurableRecoveryStore,
        TrustedHostServiceRoleV3::CurrentSignatureAuthority])
}
pub(super) fn kinds() -> BTreeSet<EndpointKind> {
    BTreeSet::from([EndpointKind::PublicationReconciliation, EndpointKind::Retrieval])
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct History {
    pub(super) service_role: TrustedHostServiceRoleV3,
    pub(super) runtime_original: String,
    pub(super) history_original: String,
    pub(super) root_key_id: Sha256Digest,
    pub(super) root_key_spki_sha256: Sha256Digest,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct ServiceSession {
    pub(super) service_role: TrustedHostServiceRoleV3,
    pub(super) activation_fd_name: String,
    pub(super) expected_socket_path: PathBuf,
    pub(super) expected_peer: ExpectedPeerCredentialV3,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Endpoint {
    pub(super) kind: EndpointKind,
    pub(super) activation_fd_name: String,
    pub(super) expected_peer: ExpectedPeerCredentialV3,
    pub(super) expected_socket_path: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Configuration {
    pub(super) api_version: String,
    pub(super) scope: fixed::Scope,
    pub(super) durable_grant_original: String,
    pub(super) current_grant_original: String,
    pub(super) histories: Vec<History>,
    pub(super) service_sessions: Vec<ServiceSession>,
    pub(super) native_endpoints: Vec<Endpoint>,
    pub(super) result_peer: ExpectedPeerCredentialV3,
}
impl Configuration {
    pub(super) fn validate(&self) -> Result<(), ServiceRunnerError> {
        require(self.api_version == RUNTIME
            && encode_canonical_frame(self)?.len() <= MAX_CONFIGURATION
            && self.histories.len() == 2 && self.service_sessions.len() == 2
            && self.native_endpoints.len() == 2
            && self.histories.iter().map(|v| v.service_role).collect::<BTreeSet<_>>() == roles()
            && self.service_sessions.iter().map(|v| v.service_role).collect::<BTreeSet<_>>() == roles()
            && self.native_endpoints.iter().map(|v| v.kind).collect::<BTreeSet<_>>() == kinds())?;
        self.scope.validate()?;
        self.result_peer.checked()?;
        require(self.result_peer.uid == 0 && self.result_peer.gid == 0)?;
        for raw in [&self.durable_grant_original, &self.current_grant_original] {
            require(!raw.is_empty() && raw.is_ascii() && raw.len() <= MAX_GRANT)?;
            let _: Grant = decode_canonical_frame(raw.as_bytes())?;
        }
        let mut names = BTreeSet::from([RESULT_FD.to_owned(), RESULT_PARENT_FD.to_owned()]);
        let mut peers = BTreeSet::new();
        for entry in &self.service_sessions {
            let expected = match entry.service_role {
                TrustedHostServiceRoleV3::DurableRecoveryStore => "publication-genesis-durable-session",
                TrustedHostServiceRoleV3::CurrentSignatureAuthority => "publication-genesis-current-session",
                _ => return Err(invalid().into()),
            };
            entry.expected_peer.checked()?;
            require(entry.activation_fd_name == expected && entry.expected_socket_path.is_absolute()
                && entry.expected_peer.uid > 0 && entry.expected_peer.gid > 0
                && peers.insert(entry.expected_peer.uid) && names.insert(entry.activation_fd_name.clone()))?;
        }
        for entry in &self.native_endpoints {
            let expected = match entry.kind {
                EndpointKind::PublicationReconciliation => "publication-genesis-native-session",
                EndpointKind::Retrieval => "publication-genesis-retrieval-session",
                _ => return Err(invalid().into()),
            };
            entry.expected_peer.checked()?;
            require(entry.activation_fd_name == expected
                && entry.expected_socket_path == PathBuf::from(entry.kind.socket_path())
                && entry.expected_peer.uid > 0 && entry.expected_peer.gid > 0
                && peers.insert(entry.expected_peer.uid) && names.insert(entry.activation_fd_name.clone())
                && names.insert(entry.kind.peer_directory_name().to_owned()))?;
        }
        for entry in &self.histories {
            require(!entry.runtime_original.is_empty() && entry.runtime_original.is_ascii()
                && entry.runtime_original.len() <= MAX_CONFIGURATION
                && !entry.history_original.is_empty() && entry.history_original.is_ascii()
                && entry.history_original.len() <= 1024 * 1024)?;
        }
        Ok(())
    }

    fn histories(&self, owner: &native_guest::AdmittedGuest)
        -> Result<BTreeMap<TrustedHostServiceRoleV3, RuntimeAuthorityHistory>, ServiceRunnerError> {
        self.validate()?;
        owner.check().map_err(|_| invalid())?;
        let guest = owner.guest_binding();
        self.scope.guest(&guest)?;
        require(sha(self)? == guest.runtime_configuration_sha256)?;
        let mut result = BTreeMap::new();
        let mut coordinator_peer = None;
        for member in &self.histories {
            let header = super::publication_genesis_handoff::header(member)?;
            header.validate()?;
            require(header.api_version == super::publication_genesis_service::RUNTIME
                && header.authority_history_root_key_id == member.root_key_id
                && header.authority_history_root_key_spki_sha256 == member.root_key_spki_sha256
                && header.expected_peer.uid == guest.uid && header.expected_peer.gid == guest.gid
                && header.expected_peer.pid == unsafe { libc::getpid() })?;
            let peer = sha(&header.expected_peer)?;
            if let Some(expected) = &coordinator_peer { require(expected == &peer)?; }
            else { coordinator_peer = Some(peer); }
            let history = header.history_from_original(member.history_original.as_bytes(), member.service_role)?;
            require(result.insert(member.service_role, history).is_none())?;
        }
        Ok(result)
    }
}

fn check(owner: &native_guest::AdmittedGuest, scope: &fixed::Scope) -> Result<u64, ServiceError> {
    owner.check().map_err(|_| invalid())?;
    let now = boottime_now_nanos().map_err(|_| invalid())?;
    scope.live(now)?;
    Ok(now)
}

fn ordinary(owner: &native_guest::AdmittedGuest, scope: &fixed::Scope,
    session: &AuthenticatedInheritedSeqpacket, action: Action) -> Result<Reply, ServiceError> {
    let command = Command { api_version: super::publication_genesis_service::API.into(), scope: scope.clone(), action };
    let raw = encode_canonical_frame(&command)?;
    require(raw.len() <= MAX_SERVICE_FRAME_BYTES && command.deadline()? == scope.expires_at_boottime_nanos)?;
    let deadline = scope.expires_at_boottime_nanos;
    session.revalidate_peer()?;
    loop {
        check(owner, scope)?;
        if session.try_send(&raw, &[], 0)? { break; }
        wait_for_fd(session.progress_fd().as_raw_fd(), libc::POLLOUT, Some(deadline)).map_err(|_| invalid())?;
    }
    let packet = loop {
        check(owner, scope)?;
        if let Some(packet) = session.try_receive(0)? { break packet; }
        wait_for_fd(session.progress_fd().as_raw_fd(), libc::POLLIN, Some(deadline)).map_err(|_| invalid())?;
    };
    require(packet.rights.is_empty())?;
    session.revalidate_peer()?;
    check(owner, scope)?;
    decode_canonical_frame(&packet.frame)
}

fn native(owner: &native_guest::AdmittedGuest, scope: &fixed::Scope,
    session: &native_guest::proof_client::Session, endpoint: EndpointIdentity,
    key: &RoleKey, body: Body) -> Result<ResultBody, ServiceError> {
    use super::super::production_dispatch::PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION;
    let started = check(owner, scope)?;
    let deadline = scope.expires_at_boottime_nanos;
    let mut request = Request { api_version: PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.into(), endpoint,
        replay_id_sha256: scope.commissioning_id_sha256.clone(), deadline_boottime_nanos: deadline,
        request: body, request_sha256: Sha256Digest::compute(&[]) };
    request.request_sha256 = request.computed_request_sha256().map_err(|_| invalid())?;
    let raw = encode_canonical_frame(&request)?;
    require(raw.len() <= MAX_SERVICE_FRAME_BYTES)?;
    loop {
        check(owner, scope)?;
        if session.send(&raw, deadline).map_err(|_| invalid())? { break; }
        wait_for_fd(session.progress_fd().as_raw_fd(), libc::POLLOUT, Some(deadline)).map_err(|_| invalid())?;
    }
    let packet = loop {
        check(owner, scope)?;
        if let Some(packet) = session.receive(deadline).map_err(|_| invalid())? { break packet; }
        wait_for_fd(session.progress_fd().as_raw_fd(), libc::POLLIN, Some(deadline)).map_err(|_| invalid())?;
    };
    require(packet.rights.is_empty())?;
    let response: Response = decode_canonical_frame(&packet.bytes)?;
    let now = check(owner, scope)?;
    require(response.api_version == request.api_version && response.endpoint == request.endpoint
        && response.request_sha256 == request.request_sha256 && response.replay_id_sha256 == request.replay_id_sha256
        && response.completed_at_boottime_nanos >= started && response.completed_at_boottime_nanos <= now
        && response.completed_at_boottime_nanos < deadline && response.authority_key_id == key.key_id
        && response.authority_key_spki_sha256 == key.key_spki_sha256
        && response.result_sha256 == crate::policy_shadow::hash_domain_frames(
            b"serverware.policyCustodyProductionAuthorityEndpointResponse/v4", &[&encode_canonical_frame(&response.result)?]))?;
    let signature = URL_SAFE_NO_PAD.decode(&response.signature_base64).map_err(|_| invalid())?;
    require(signature.len() == 64 && URL_SAFE_NO_PAD.encode(&signature) == response.signature_base64)?;
    key.material()?.verify_strict(&super::super::protocol::domain_separated_signature_preimage(
        b"serverware.policyCustodyProductionAuthorityEndpointSignature/v4",
        &response.signature_payload().map_err(|_| invalid())?)?,
        &Signature::from_slice(&signature).map_err(|_| invalid())?).map_err(|_| invalid())?;
    session.after_verify(&packet, deadline).map_err(|_| invalid())?;
    check(owner, scope)?;
    Ok(response.result)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Handoff {
    pub(super) api_version: String, pub(super) commissioning_id_sha256: Sha256Digest, pub(super) scope_sha256: Sha256Digest,
    pub(super) bundle_original: String, pub(super) bundle_sha256: Sha256Digest,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Acknowledgment { pub(super) api_version: String, pub(super) handoff_sha256: Sha256Digest }

/// Pure acceptance of originals; the real parent separately owns and checks
/// the child/socket/PIDFD association before calling this receiver.
pub(super) fn admit_handoff(raw: &[u8], configuration: &Configuration)
    -> Result<(Vec<u8>, Vec<u8>), ServiceRunnerError> {
    super::publication_genesis_handoff::admit(raw, configuration)
}

/// Called once by the explicitly admitted cold coordinator guest. Each map
/// owns real connected sessions; no host-only fallback or generic dispatcher.
pub(super) fn run(configuration: Configuration, owner: Arc<native_guest::AdmittedGuest>,
    native_sessions: BTreeMap<EndpointKind, native_guest::proof_client::Session>,
    ordinary_sessions: BTreeMap<TrustedHostServiceRoleV3, AuthenticatedInheritedSeqpacket>,
    result: native_guest::genesis_client::ResultChannel) -> Result<(), ServiceRunnerError> {
    let histories = configuration.histories(&owner)?;
    require(native_sessions.keys().copied().collect::<BTreeSet<_>>() == kinds()
        && ordinary_sessions.keys().copied().collect::<BTreeSet<_>>() == roles())?;
    let durable: Grant = decode_canonical_frame(configuration.durable_grant_original.as_bytes())?;
    let current: Grant = decode_canonical_frame(configuration.current_grant_original.as_bytes())?;
    let d = &durable.payload;
    let c = &current.payload;
    let drs = histories.get(&TrustedHostServiceRoleV3::DurableRecoveryStore).ok_or_else(invalid)?;
    let csa = histories.get(&TrustedHostServiceRoleV3::CurrentSignatureAuthority).ok_or_else(invalid)?;
    let (durable_key, current_key) = durable.verify(drs)?;
    let (other_durable, other_current) = current.verify(csa)?;
    require(durable_key == other_durable && current_key == other_current
        && drs.root_authority_key() != csa.root_authority_key()
        && d.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore
        && c.service_role == TrustedHostServiceRoleV3::CurrentSignatureAuthority
        && d.scope == configuration.scope && c.scope == configuration.scope
        && d.native == c.native && d.retrieval == c.retrieval
        && d.durable_authority_epoch == c.durable_authority_epoch
        && d.current_authority_epoch == c.current_authority_epoch
        && d.durable_public_key_base64url == c.durable_public_key_base64url
        && d.current_public_key_base64url == c.current_public_key_base64url
        && d.durable_authority_epoch == drs.current_epoch().map_err(|_| invalid())?.epoch_reference()
        && d.current_authority_epoch == csa.current_epoch().map_err(|_| invalid())?.epoch_reference()
        && &durable_key == drs.current_epoch().map_err(|_| invalid())?.service_signing_key()
        && &current_key == csa.current_epoch().map_err(|_| invalid())?.service_signing_key()
        && d.guest.uid != c.guest.uid && d.guest.gid != c.guest.gid)?;
    let own = owner.guest_binding();
    for grant in [&durable, &current] {
        let p = &grant.payload;
        configuration.scope.guest(&p.guest)?;
        let member = configuration.histories.iter().find(|v| v.service_role == p.service_role).ok_or_else(invalid)?;
        let session = configuration.service_sessions.iter().find(|v| v.service_role == p.service_role).ok_or_else(invalid)?;
        let history = histories.get(&p.service_role).ok_or_else(invalid)?;
        let header = super::publication_genesis_handoff::header(member)?;
        super::initial_history::require_genesis_guest(member.history_original.as_bytes(), &header, p.service_role, &p.guest)?;
        super::initial_history::require_genesis_window(member.history_original.as_bytes(), &header, p.service_role,
            p.scope.issued_at_boottime_nanos, p.scope.expires_at_boottime_nanos)?;
        require(p.runtime_configuration_sha256 == Sha256Digest::compute(member.runtime_original.as_bytes())
            && p.guest.uid != own.uid && p.guest.gid != own.gid
            && p.guest.uid == session.expected_peer.uid && p.guest.gid == session.expected_peer.gid
            && session.expected_peer.process_identity_sha256
                == history.current_epoch().map_err(|_| invalid())?.epoch_reference().endpoint_process_identity_sha256)?;
    }
    for peer in &configuration.native_endpoints {
        require(peer.expected_peer.uid != own.uid && peer.expected_peer.gid != own.gid)?;
    }
    let scope = &configuration.scope;
    let deadline = scope.expires_at_boottime_nanos;
    let durable_digest = sha(&durable)?;
    let current_digest = sha(&current)?;
    let drs_session = ordinary_sessions.get(&TrustedHostServiceRoleV3::DurableRecoveryStore).ok_or_else(invalid)?;
    let csa_session = ordinary_sessions.get(&TrustedHostServiceRoleV3::CurrentSignatureAuthority).ok_or_else(invalid)?;
    let publication_session = native_sessions.get(&EndpointKind::PublicationReconciliation).ok_or_else(invalid)?;
    let retrieval_session = native_sessions.get(&EndpointKind::Retrieval).ok_or_else(invalid)?;
    result.check().map_err(|_| invalid())?;
    check(&owner, scope)?;
    // No automatic retry after any contact. Durable owners retain exact
    // outcomes; restarting or adopting them needs a separate approved path.
    let Reply::Genesis(genesis) = ordinary(&owner, scope, drs_session, Action::Initialize)?
        else { return Err(invalid().into()); };
    genesis.verify(scope, &d.durable_authority_epoch, &durable_key)?;
    require(genesis.grant_sha256 == durable_digest)?;
    let endpoint = EndpointIdentity::ParentSigner(Signer::PublicationReconciliation);
    let ResultBody::InitialPublicationPrepared(prepared) = native(&owner, scope, publication_session,
        endpoint, &d.native, Body::PrepareInitialPublication { genesis: genesis.clone() })?
        else { return Err(invalid().into()); };
    prepared.verify(scope, &d.native, &d.durable_authority_epoch, &durable_key)?;
    require(prepared.core.genesis == genesis)?;
    let ResultBody::InitialPublicationCoreStored(stored) = native(&owner, scope, retrieval_session,
        EndpointIdentity::Proof(Proof::Retrieval), &d.retrieval,
        Body::StoreInitialPublicationCore { prepared: prepared.clone() })?
        else { return Err(invalid().into()); };
    fixed::stored_verify(&stored, &prepared, scope, &d.retrieval)?;
    let peer = configuration.native_endpoints.iter().find(|v| v.kind == EndpointKind::Retrieval).ok_or_else(invalid)?;
    require(stored.payload.guest.uid == peer.expected_peer.uid && stored.payload.guest.gid == peer.expected_peer.gid)?;
    let ResultBody::InitialPublicationCompleted(completion) = native(&owner, scope, publication_session,
        endpoint, &d.native, Body::CompleteInitialPublication { prepared: prepared.clone(), stored: stored.clone() })?
        else { return Err(invalid().into()); };
    completion.verify(scope, &d.native, &d.retrieval, &d.durable_authority_epoch, &durable_key)?;
    require(completion.prepared == prepared && completion.stored == stored)?;
    let Reply::Finalized(durable_witness) = ordinary(&owner, scope, drs_session,
        Action::Finalize { completion: completion.clone() })? else { return Err(invalid().into()); };
    durable_witness.verify(scope, &completion, &sha(&genesis)?, &d.durable_authority_epoch, &durable_key)?;
    require(durable_witness.grant_sha256 == durable_digest)?;
    let Reply::Mirrored(current_witness) = ordinary(&owner, scope, csa_session,
        Action::Mirror { completion: completion.clone(), durable: durable_witness.clone() })?
        else { return Err(invalid().into()); };
    require(current_witness.grant_sha256 == current_digest)?;
    let bundle = fixed::Bundle { completion, durable: durable_witness, current: current_witness };
    bundle.verify(scope, &d.native, &d.retrieval, &d.durable_authority_epoch, &durable_key,
        &d.current_authority_epoch, &current_key)?;
    let bundle_raw = encode_canonical_frame(&bundle)?;
    let handoff = Handoff { api_version: "serverware.nativePublicationGenesisHandoff/v1".into(),
        commissioning_id_sha256: scope.commissioning_id_sha256.clone(), scope_sha256: sha(scope)?,
        bundle_sha256: Sha256Digest::compute(&bundle_raw),
        bundle_original: String::from_utf8(bundle_raw).map_err(|_| invalid())? };
    let raw = encode_canonical_frame(&handoff)?;
    require(raw.len() <= MAX_SERVICE_FRAME_BYTES)?;
    loop {
        check(&owner, scope)?;
        result.check().map_err(|_| invalid())?;
        if result.send(&raw, deadline).map_err(|_| invalid())? { break; }
        wait_for_fd(result.progress_fd().as_raw_fd(), libc::POLLOUT, Some(deadline)).map_err(|_| invalid())?;
    }
    let reply = loop {
        check(&owner, scope)?;
        if let Some(reply) = result.receive(deadline).map_err(|_| invalid())? { break reply; }
        wait_for_fd(result.progress_fd().as_raw_fd(), libc::POLLIN, Some(deadline)).map_err(|_| invalid())?;
    };
    let ack: Acknowledgment = decode_canonical_frame(&reply)?;
    require(ack.api_version == "serverware.nativePublicationGenesisHandoffAck/v1"
        && ack.handoff_sha256 == Sha256Digest::compute(&raw))?;
    result.check().map_err(|_| invalid())?;
    check(&owner, scope)?;
    // Transport acknowledgment is not a policy installation or cleanup proof.
    Ok(())
}

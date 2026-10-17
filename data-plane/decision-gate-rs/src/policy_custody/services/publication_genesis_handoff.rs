//! Parent-side admission of the cold coordinator's exact public originals.
//! The caller separately retains the genuine child, socket and PIDFD. This
//! module neither constructs an owner nor grants installation or readiness.
use super::*;
use super::ledger_spool_values::sha;
use super::publication_genesis::{self as fixed, invalid, require};
use super::publication_genesis_client::{Acknowledgment, Configuration, Handoff};
use super::publication_genesis_service::Grant;

pub(super) fn header(member: &super::publication_genesis_client::History)
    -> Result<RuntimeConfigHeaderV3, ServiceRunnerError> {
    // Decode the real, closed ordinary runtime type, not a selected JSON
    // subobject that could hide a different top-level service grammar.
    Ok(match member.service_role {
        TrustedHostServiceRoleV3::DurableRecoveryStore =>
            decode_canonical_frame::<DurableRecoveryStoreRuntimeConfigV3>(
                member.runtime_original.as_bytes())?.runtime,
        TrustedHostServiceRoleV3::CurrentSignatureAuthority =>
            decode_canonical_frame::<CurrentSignatureAuthorityRuntimeConfigV3>(
                member.runtime_original.as_bytes())?.runtime,
        _ => return Err(invalid().into()),
    })
}

pub(super) fn admit(raw: &[u8], configuration: &Configuration)
    -> Result<(Vec<u8>, Vec<u8>), ServiceRunnerError> {
    require(!raw.is_empty() && raw.len() <= MAX_SERVICE_FRAME_BYTES)?;
    configuration.validate()?;
    let scope = &configuration.scope;
    scope.live(boottime_now_nanos().map_err(|_| invalid())?)?;
    let handoff: Handoff = decode_canonical_frame(raw)?;
    require(handoff.api_version == "catchplate.nativePublicationGenesisHandoff/v1"
        && handoff.commissioning_id_sha256 == scope.commissioning_id_sha256
        && handoff.scope_sha256 == sha(scope)?
        && !handoff.bundle_original.is_empty() && handoff.bundle_original.is_ascii()
        && handoff.bundle_original.len() <= MAX_SERVICE_FRAME_BYTES
        && handoff.bundle_sha256 == Sha256Digest::compute(handoff.bundle_original.as_bytes()))?;
    let bundle: fixed::Bundle = decode_canonical_frame(handoff.bundle_original.as_bytes())?;
    let durable: Grant = decode_canonical_frame(configuration.durable_grant_original.as_bytes())?;
    let current: Grant = decode_canonical_frame(configuration.current_grant_original.as_bytes())?;
    let mut histories = BTreeMap::new();
    let mut coordinator_peer = None;
    for grant in [&durable, &current] {
        let p = &grant.payload;
        require(p.scope == *scope)?;
        scope.guest(&p.guest)?;
        let member = configuration.histories.iter().find(|v| v.service_role == p.service_role)
            .ok_or_else(invalid)?;
        let session = configuration.service_sessions.iter().find(|v| v.service_role == p.service_role)
            .ok_or_else(invalid)?;
        let runtime = header(member)?;
        runtime.validate()?;
        require(runtime.api_version == super::publication_genesis_service::RUNTIME
            && runtime.authority_history_root_key_id == member.root_key_id
            && runtime.authority_history_root_key_spki_sha256 == member.root_key_spki_sha256
            && p.runtime_configuration_sha256 == Sha256Digest::compute(member.runtime_original.as_bytes())
            && p.guest.uid == session.expected_peer.uid && p.guest.gid == session.expected_peer.gid)?;
        let peer = sha(&runtime.expected_peer)?;
        if let Some(expected) = &coordinator_peer { require(expected == &peer)?; }
        else { coordinator_peer = Some(peer); }
        // Retained evidence verification does not reopen initial admission.
        // Original checkpoint/lifetime bounds still apply to the whole scope.
        let history = super::initial_history::load_retained_genesis_witness(
            member.history_original.as_bytes(), &runtime, p.service_role, &p.guest,
            scope.issued_at_boottime_nanos, scope.expires_at_boottime_nanos)?;
        grant.verify(&history)?;
        require(session.expected_peer.process_identity_sha256
            == history.current_epoch().map_err(|_| invalid())?.epoch_reference().endpoint_process_identity_sha256
            && histories.insert(p.service_role, history).is_none())?;
    }
    let d = &durable.payload;
    let c = &current.payload;
    let drs = histories.get(&TrustedHostServiceRoleV3::DurableRecoveryStore).ok_or_else(invalid)?;
    let csa = histories.get(&TrustedHostServiceRoleV3::CurrentSignatureAuthority).ok_or_else(invalid)?;
    let (durable_key, current_key) = durable.verify(drs)?;
    let (other_durable, other_current) = current.verify(csa)?;
    require(d.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore
        && c.service_role == TrustedHostServiceRoleV3::CurrentSignatureAuthority
        && d.native == c.native && d.retrieval == c.retrieval
        && d.durable_authority_epoch == c.durable_authority_epoch
        && d.current_authority_epoch == c.current_authority_epoch
        && d.durable_public_key_base64url == c.durable_public_key_base64url
        && d.current_public_key_base64url == c.current_public_key_base64url
        && durable_key == other_durable && current_key == other_current
        && drs.root_authority_key() != csa.root_authority_key()
        && d.guest.uid != c.guest.uid && d.guest.gid != c.guest.gid
        && d.durable_authority_epoch == drs.current_epoch().map_err(|_| invalid())?.epoch_reference()
        && d.current_authority_epoch == csa.current_epoch().map_err(|_| invalid())?.epoch_reference()
        && &durable_key == drs.current_epoch().map_err(|_| invalid())?.service_signing_key()
        && &current_key == csa.current_epoch().map_err(|_| invalid())?.service_signing_key())?;
    bundle.verify(scope, &d.native, &d.retrieval, &d.durable_authority_epoch, &durable_key,
        &d.current_authority_epoch, &current_key)?;
    let durable_sha = Sha256Digest::compute(configuration.durable_grant_original.as_bytes());
    require(bundle.completion.prepared.core.genesis.grant_sha256 == durable_sha
        && bundle.durable.grant_sha256 == durable_sha
        && bundle.current.grant_sha256 == Sha256Digest::compute(configuration.current_grant_original.as_bytes()))?;
    let retrieval = configuration.native_endpoints.iter().find(|v|
        v.kind == super::guest::native_guest::retrieval_peer::EndpointKind::Retrieval).ok_or_else(invalid)?;
    require(bundle.completion.stored.payload.guest.uid == retrieval.expected_peer.uid
        && bundle.completion.stored.payload.guest.gid == retrieval.expected_peer.gid)?;
    // The full history-window check above makes this final original Scope
    // check also bracket the authenticated checkpoint and guest lifetimes.
    let now = boottime_now_nanos().map_err(|_| invalid())?;
    scope.live(now)?;
    require(bundle.current.completed_at_boottime_nanos <= now)?;
    let ack = encode_canonical_frame(&Acknowledgment {
        api_version: "catchplate.nativePublicationGenesisHandoffAck/v1".into(),
        handoff_sha256: Sha256Digest::compute(raw),
    })?;
    require(ack.len() <= MAX_SERVICE_FRAME_BYTES)?;
    Ok((handoff.bundle_original.into_bytes(), ack))
}

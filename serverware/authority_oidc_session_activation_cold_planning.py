"""Root-original-bound activation planning with fresh no-pending head admission.

The complete vector is an authenticated launch snapshot. A fresh nonce-bound
signed state observation must independently match it with no pending action;
observed database roots must also match before a plan can be signed. No request
selects roots, policy or keys, and no result carrier replaces original bootstrap,
query or observation bytes. A separately root-pinned key/store retain first-exact
encrypted export bytes. This is not atomic action-time admission or SQL.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from serverware import authority_current_root_head as head
from serverware import authority_current_root_transport as state_transport
from serverware import authority_oidc_session_activation_plan_owner as owner_module
from serverware import authority_oidc_session_activation_state as activation_state
from serverware import authority_oidc_session_activation_execution_export as execution_export
from serverware import authority_oidc_session_activation_execution_store as execution_storage


plan, registration, evidence = owner_module.plan, owner_module.registration, owner_module.evidence
clock, assertion = owner_module.clock, owner_module.assertion
OPERATION = plan.contract.OPERATION


class OidcSessionActivationColdPlanningError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class PreparedActivationExport:
    """Original output bytes only, never admission or execution authority."""

    plan: owner_module.PreparedActivationPlan
    encrypted_originals_bytes: bytes
    expires_at_epoch_ns: int


def _fail(message):
    raise OidcSessionActivationColdPlanningError(message)


def _project_on_work(*, vector_bytes, expected_vector_digest, work):
    """Validate the full original vector before deriving this operation's roots."""
    return activation_state._project_on_work(vector_bytes=vector_bytes,
        expected_vector_digest=expected_vector_digest, work=work)


def _snapshot(owner, expected, work):
    observed = evidence.production._callback(work,
        lambda: owner_module.OidcSessionActivationPlanOwner._snapshot_configuration(owner))
    if observed is not expected:
        _fail("activation cold plan owner changed during original admission")
    return observed


def _key_digest(original, work):
    if type(original) is not bytes or len(original) != 32:
        _fail("activation cold owner key is not an exact private original")
    work.charge(hashes=1, input_bytes=len(original))
    return evidence.production._callback(work,
        lambda: "sha256:" + hashlib.sha256(original).hexdigest())


def _store_snapshot(store, expected, work):
    observed = evidence.production._callback(work,
        lambda: execution_storage.ActivationExecutionBundleStore._snapshot_configuration(store))
    if observed is not expected:
        _fail("activation execution store changed during original admission")
    return observed


def _join_store(configured, owner_configuration, material, bundle_key, work):
    launch = material.launch
    registration._same((configured[0], configured[1], configured[3], configured[4], configured[5]),
        (plan.contract.authority.SOURCE_REVISION, material.configuration_digest,
            (launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"],
                launch["serviceUid"], launch["serviceGid"]),
            launch["executionStoreMaximumRecords"], launch["executionStoreQuotaBytes"]),
        work, "root-signed activation execution-store scope")
    work.charge(input_bytes=6 * execution_storage.bundle.KEY_BYTES)
    if (configured[2] != bundle_key or bundle_key == owner_configuration[10]
            or bundle_key == owner_configuration[4][2]
            or configured[3][:2] == owner_configuration[4][4][:2]):
        _fail("activation execution store key or directory is not separately bound")
    registration._same(_key_digest(bundle_key, work), material.bundle_key_digest,
        work, "root-signed activation execution-bundle key")


def _join_owner(configured, material, root_public_key, work):
    """Join the actual held owners to this call's genuinely verified original."""
    fixed = owner_module._fixed_scope(configured, work)
    expected = {"rpId": material.rp_id, "origin": material.origin,
        "authenticationPolicy": material.authn_policy, "trustPolicy": material.trust_policy,
        "configurationDigest": material.configuration_digest,
        "plannerIdentity": material.planner_identity, "plannerSpkiDigest": material.planner_spki_digest,
        "maximumPlanAgeNs": material.maximum_plan_age_ns,
        "maximumClockSkewNs": material.maximum_clock_skew_ns}
    registration._same(fixed, expected, work, "root-signed activation owner configuration")
    registration._same(configured[2], material.reader_configuration, work,
        "root-signed activation reader configuration")
    registration._same(configured[17], material.delivery_ttl_seconds, work,
        "root-signed activation delivery lifetime")
    evidence.keys._public_binding(configured[6], material.planner_spki_digest, work)
    journal = configured[4]
    launch = material.launch
    registration._same((journal[0], journal[1], journal[4], journal[5], journal[6]),
        (plan.contract.authority.SOURCE_REVISION, material.configuration_digest,
            (launch["journalDirectoryDevice"], launch["journalDirectoryInode"],
                launch["serviceUid"], launch["serviceGid"]),
            launch["journalMaximumRecords"], launch["journalQuotaBytes"]),
        work, "root-signed activation journal scope")
    work.charge(input_bytes=64)
    if configured[10] != journal[3]:
        _fail("activation cold owner and journal delivery keys differ")
    registration._same(_key_digest(configured[10], work), material.delivery_key_digest,
        work, "root-signed activation delivery key")
    registration._same(_key_digest(journal[2], work), material.journal_key_digest,
        work, "root-signed activation journal key")
    for actual, expected, label in ((configured[18], material.state_enrollment_bytes, "state enrollment"),
            (configured[20], material.complete_root_vector_bytes, "complete vector")):
        work.charge(input_bytes=len(actual) + len(expected))
        if actual != expected:
            _fail("activation cold owner " + label + " differs from the root-signed original")
    registration._same(evidence.keys._spki_on_work(configured[19], work),
        evidence.keys._spki_on_work(root_public_key, work), work, "independent activation state root key")


def _prepare_on_work(owner, *, execution_store, bundle_key, bootstrap_bytes, root_public_key, assertion_bytes,
        old_token_bytes, expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id, live_window,
        transport_deadline_ns, work):
    """Reauthenticate launch originals and a fresh matching no-pending head.

    The cold service constructs the actual owner once and retains the original
    bootstrap/root key. This function accepts no bootstrap material or proof
    result, generates no key copy or replacement work/window, and never retries.
    """
    from serverware import oidc_session_activation_planner_bootstrap as bootstrap

    ledger = evidence.capture._SharedLedger(work)
    if (type(owner) is not owner_module.OidcSessionActivationPlanOwner
            or type(owner._configured) is not tuple or len(owner._configured) != 21
            or type(execution_store) is not execution_storage.ActivationExecutionBundleStore
            or type(execution_store._configuration) is not tuple or len(execution_store._configuration) != 6
            or type(bundle_key) is not bytes or len(bundle_key) != execution_storage.bundle.KEY_BYTES
            or type(bootstrap_bytes) is not bytes or not 2 <= len(bootstrap_bytes) <= bootstrap.MAX_BYTES
            or type(assertion_bytes) is not bytes
            or not 2 <= len(assertion_bytes) <= assertion.MAX_ASSERTION_BYTES):
        _fail("activation cold preparation requires actual owners and bounded originals")
    configured = owner._configured
    store_configuration, held_bundle_key = execution_store._configuration, bundle_key
    original_bootstrap, original_assertion = bootstrap_bytes, assertion_bytes
    old = assertion._token(old_token_bytes, work)
    window = clock._validate(live_window)
    registration._integer(transport_deadline_ns, "activation cold inherited deadline", 1)
    bound = min(window[4], transport_deadline_ns)
    subject = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "userId": expected_user_id, "sessionId": expected_session_id,
        "credentialId": expected_credential_id, "credentialRecordId": expected_credential_record_id,
        "challengeId": expected_challenge_id})
    for name, maximum in (("userId", 1024), ("sessionId", 128), ("credentialId", 1366),
            ("credentialRecordId", 1024), ("challengeId", 1024)):
        registration._text(subject[name], "activation cold " + name, maximum, work)
    # All request graphs and exact original bytes are held before the first
    # bootstrap clock/signature callback or journal-readiness callback.
    material = bootstrap._verify_on_work(bootstrap_bytes=original_bootstrap,
        root_public_key=root_public_key, live_window=window,
        work=work, transport_deadline_ns=bound)
    _snapshot(owner, configured, work)
    _store_snapshot(execution_store, store_configuration, work)
    _join_owner(configured, material, root_public_key, work)
    _join_store(store_configuration, configured, material, held_bundle_key, work)
    issued, expires = material.attestation_interval
    opening = material.opening_sample
    if (window[5:] != (material.maximum_plan_age_ns, material.maximum_clock_skew_ns)
            or not issued <= window[0] < window[3] <= expires):
        _fail("activation request window exceeds its root-signed launch or policy")
    bound = min(bound, opening[0] + expires - opening[1])
    _window, live = owner_module.delivery._window(window, bound, work)
    last_epoch, last_monotonic = opening[1], opening[2]

    def current():
        nonlocal last_epoch, last_monotonic
        _snapshot(owner, configured, work)
        _store_snapshot(execution_store, store_configuration, work)
        sample = bootstrap._fresh(material.attestation_interval, work, opening=opening)
        now = live()
        if (sample[1] < last_epoch or sample[0] < last_monotonic
                or sample[2] >= bound or now < sample[1]):
            _fail("activation original launch deadline expired or clock reversed")
        last_epoch, last_monotonic = now, sample[2]
        _snapshot(owner, configured, work)
        _store_snapshot(execution_store, store_configuration, work)
        return now

    current()
    projected = _project_on_work(vector_bytes=material.complete_root_vector_bytes,
        expected_vector_digest=material.complete_root_vector_digest, work=work)
    current()
    scope = {**subject, **owner_module._fixed_scope(configured, work), "deadlineEpochNs": window[3]}
    context_digest = activation_state._context_digest_on_work(scope=scope,
        assertion_bytes=original_assertion, old_token_bytes=old,
        complete_root_vector_bytes=material.complete_root_vector_bytes, work=work)
    work.charge(input_bytes=96)
    nonce = evidence.production._callback(work, lambda: os.urandom(32))
    if type(nonce) is not bytes or len(nonce) != 32:
        _fail("activation state query has no genuine fixed-size challenge")
    query_bytes = head._encode_query_on_work(enrollment_digest=material.state_enrollment_digest,
        context_digest=context_digest, expected_vector_digest=projected.vector_digest,
        challenge=nonce.hex(), work=work)
    current()
    work.charge(input_bytes=len(query_bytes))
    observation_bytes = evidence.production._callback(work, lambda: state_transport._head_on_configuration(
        material.state_endpoint, query_bytes=query_bytes, deadline_ns=bound))
    if type(observation_bytes) is not bytes or not 2 <= len(observation_bytes) <= head.MAX_BYTES:
        _fail("activation state exchange returned no bounded original")
    work.charge(input_bytes=len(observation_bytes))
    observed = activation_state._verify_on_work(scope=scope,
        assertion_bytes=original_assertion, old_token_bytes=old,
        complete_root_vector_bytes=material.complete_root_vector_bytes,
        query_bytes=query_bytes, observation_bytes=observation_bytes,
        enrollment_bytes=material.state_enrollment_bytes, root_public_key=root_public_key,
        now_epoch_ns=current(), work=work)
    if current() >= observed["expiresAtEpochNs"]:
        _fail("activation fresh state observation expired before preparation")
    result = owner_module.OidcSessionActivationPlanOwner.prepare(owner,
        assertion_bytes=original_assertion, old_token_bytes=old,
        head_query_bytes=query_bytes, head_observation_bytes=observation_bytes,
        expected_user_id=subject["userId"], expected_session_id=subject["sessionId"],
        expected_credential_id=subject["credentialId"],
        expected_credential_record_id=subject["credentialRecordId"],
        expected_challenge_id=subject["challengeId"],
        business_before_roots=projected.business_before_roots,
        authorization_before_roots=projected.authorization_before_roots,
        expected_counted_heads=projected.expected_counted_heads,
        live_window=window, transport_deadline_ns=bound, work=work)
    if type(result) is not owner_module.PreparedActivationPlan:
        _fail("activation cold preparation did not return its actual owner result")
    payload = plan.contract._decode_on_work(result.envelope_bytes, envelope=True, work=work)["payload"]
    if (payload["expiresAtEpochNs"] > observed["expiresAtEpochNs"]
            or current() >= min(payload["expiresAtEpochNs"], observed["expiresAtEpochNs"])):
        _fail("activation plan expired after original retention")
    # Decode the exact bytes produced above, not a supplied successful result.
    # The exporter repeats original signature/proof/effect verification and
    # independently joins the original scope and projected roots before use.
    request = evidence.wire._decode_object(result.request_bytes, work=work,
        maximum_bytes=plan.contract.authority.MAX_REQUEST_BYTES,
        maximum_nodes=assertion.MAX_CONTEXT_NODES, maximum_depth=12)
    canonical_request, canonical_scope = registration._wire(request, work), registration._wire(scope, work)
    work.charge(input_bytes=len(canonical_request) + len(result.request_bytes)
        + len(canonical_scope) + len(result.scope_bytes))
    if canonical_request != result.request_bytes or canonical_scope != result.scope_bytes:
        _fail("activation prepared request or independent scope differs from its original bytes")
    registration._same(result.plan_digest,
        evidence.plan._frame(plan.contract.IDENTITY_DOMAIN, (result.envelope_bytes,), work),
        work, "activation original plan locator")
    current()
    encrypted = execution_export._export_on_work(owner, execution_store,
        envelope_bytes=result.envelope_bytes, expected_request=request, expected_scope=scope,
        business_before_roots=projected.business_before_roots,
        authorization_before_roots=projected.authorization_before_roots,
        expected_counted_heads=projected.expected_counted_heads,
        expected_journal_digest=result.journal_digest, bundle_key=held_bundle_key,
        live_window=window, transport_deadline_ns=bound, work=work)
    if current() >= min(payload["expiresAtEpochNs"], observed["expiresAtEpochNs"]):
        _fail("activation original authority expired after durable bundle export")
    return PreparedActivationExport(result, encrypted, payload["expiresAtEpochNs"])

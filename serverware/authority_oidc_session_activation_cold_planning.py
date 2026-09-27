"""Root-original-bound activation planning, not action-time currentness.

The complete vector is an authenticated launch snapshot only. Its fixed
projection supplies independent expectations to the real read-only planner;
observed database roots must match before any plan can be signed. No incoming
request selects roots, policy or keys, and no material/result carrier replaces
the original root-signed bootstrap. No state-service peer or SQL is added.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import authority_current_root_vector as vector
from serverware import authority_index_heads as index_heads
from serverware import authority_oidc_session_activation_plan_owner as owner_module
from serverware import authority_primary_contract as primary


plan, registration, evidence = owner_module.plan, owner_module.registration, owner_module.evidence
clock, assertion = owner_module.clock, owner_module.assertion
OPERATION = plan.contract.OPERATION


class OidcSessionActivationColdPlanningError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class _ProjectedRoots:
    """Ordinary original-derived data; no API admits this as authority."""

    vector_bytes: bytes
    vector_digest: str
    business_before_roots: tuple
    authorization_before_roots: tuple
    expected_counted_heads: tuple


def _fail(message):
    raise OidcSessionActivationColdPlanningError(message)


def _project_on_work(*, vector_bytes, expected_vector_digest, work):
    """Validate the full original vector before deriving this operation's roots."""
    evidence.capture._SharedLedger(work)
    if type(vector_bytes) is not bytes or not 2 <= len(vector_bytes) <= vector.MAX_BYTES:
        _fail("activation launch vector is not a bounded immutable original")
    registration._digest(expected_vector_digest)
    original = vector_bytes
    document = vector._decode_on_work(original, work=work)
    actual_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (original,), work)
    registration._same(actual_digest, expected_vector_digest, work,
        "root-signed activation complete-vector identity")
    contracts = primary.primary_table_contracts(OPERATION)
    business = tuple(item.table for item in contracts if item.root_class == "business")
    authorization = tuple(item.table for item in contracts if item.root_class == "authorization")
    identities = index_heads._activation_ids(include_write_heads=True)
    if len(identities) != plan.writes.HEAD_COUNT:
        _fail("activation launch vector projection is not the fixed thirteen-head union")
    work.prepare_scan(document)
    primary_rows = {item["table"]: item for item in document["primaryRoots"]}
    counted_rows = {item["indexId"]: item for item in document["countedRoots"]}
    selected = {
        "business": [primary_rows[table] for table in business],
        "authorization": [primary_rows[table] for table in authorization],
        "heads": [{name: counted_rows[identity][name] for name in
            ("indexId", "indexRevision", "rootDigest", "leafCount")} for identity in identities],
    }
    owned = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=vector.MAX_BYTES).visit(selected)
    plan.writes._heads(owned["heads"])
    return _ProjectedRoots(original, actual_digest, tuple(owned["business"]),
        tuple(owned["authorization"]), tuple(owned["heads"]))


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


def _join_owner(configured, material, work):
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


def _prepare_on_work(owner, *, bootstrap_bytes, root_public_key, assertion_bytes,
        old_token_bytes, expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id, live_window,
        transport_deadline_ns, work):
    """Reauthenticate the launch original and use only its projected root pins.

    The cold service constructs the actual owner once and retains the original
    bootstrap/root key. This function accepts no bootstrap material or proof
    result, generates no key copy or replacement work/window, and never retries.
    """
    from serverware import oidc_session_activation_planner_bootstrap as bootstrap

    ledger = evidence.capture._SharedLedger(work)
    if (type(owner) is not owner_module.OidcSessionActivationPlanOwner
            or type(owner._configured) is not tuple or len(owner._configured) != 18
            or type(bootstrap_bytes) is not bytes or not 2 <= len(bootstrap_bytes) <= bootstrap.MAX_BYTES
            or type(assertion_bytes) is not bytes
            or not 2 <= len(assertion_bytes) <= assertion.MAX_ASSERTION_BYTES):
        _fail("activation cold preparation requires actual owners and bounded originals")
    configured = owner._configured
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
    _join_owner(configured, material, work)
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
        sample = bootstrap._fresh(material.attestation_interval, work, opening=opening)
        now = live()
        if (sample[1] < last_epoch or sample[0] < last_monotonic
                or sample[2] >= bound or now < sample[1]):
            _fail("activation original launch deadline expired or clock reversed")
        last_epoch, last_monotonic = now, sample[2]
        _snapshot(owner, configured, work)
        return now

    current()
    projected = _project_on_work(vector_bytes=material.complete_root_vector_bytes,
        expected_vector_digest=material.complete_root_vector_digest, work=work)
    current()
    result = owner_module.OidcSessionActivationPlanOwner.prepare(owner,
        assertion_bytes=original_assertion, old_token_bytes=old,
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
    if current() >= payload["expiresAtEpochNs"]:
        _fail("activation plan expired after original retention")
    return result

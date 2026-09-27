"""Configured acquire/sign/retain activation originals, never execute or deliver.

Supplied configuration, keys, subject, policy and current roots still need real
upstream authority admission. This reusable owner checks their fixed joins; it
does not create cold authority. Retained verification is active-window replay
of a known exact envelope, not expired-history or lost-locator recovery.
"""
from __future__ import annotations

import base64
import os
import threading
from dataclasses import dataclass

from serverware import authority_oidc_session_activation_execution_bundle as bundle
from serverware import authority_oidc_session_activation_journal as custody
from serverware import authority_oidc_session_activation_plan as plan
from serverware import authority_oidc_session_activation_planning as planning
from serverware import authority_oidc_session_activation_writes as writes
from serverware.authority_index_contract import CountedNode, IndexLeaf, OpaqueSubtree


registration, evidence, assertion = plan.registration, plan.evidence, plan.assertion
core, clock, contract = plan.core, plan.clock, plan.contract
delivery, reads = plan.transition.delivery, plan.reads
OPERATION = contract.OPERATION
_LOCK_TYPE = type(threading.Lock())
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_SUBJECT_FIELDS = ("userId", "sessionId", "credentialId", "credentialRecordId", "challengeId")


class OidcSessionActivationPlanOwnerError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class PreparedActivationPlan:
    """Immutable token-free originals/locators, not operation permission."""

    request_bytes: bytes
    scope_bytes: bytes
    envelope_bytes: bytes
    plan_digest: str
    journal_digest: str


def _fail(message):
    raise OidcSessionActivationPlanOwnerError(message)


def _bytes_equal(left, right, work, label):
    work.charge(input_bytes=len(left) + len(right))
    if left != right:
        _fail("activation retained " + label + " differs")


def _b64(original, work):
    # Reserve the actual padded encoding, ASCII decode and unpadded copy;
    # these private buffers do not create an additional work allowance.
    padded = 4 * ((len(original) + 2) // 3)
    work.charge(input_bytes=len(original) + 3 * padded)
    return evidence.production._callback(work,
        lambda: base64.urlsafe_b64encode(original).decode("ascii").rstrip("="))


def _policy(raw, work):
    return evidence.wire._decode_object(raw, work=work, maximum_bytes=assertion.MAX_CONTEXT_BYTES,
        maximum_nodes=assertion.MAX_CONTEXT_NODES, maximum_depth=12)


def _fixed_scope(configured, work):
    return {"rpId": configured[11], "origin": configured[12],
        "authenticationPolicy": _policy(configured[13], work), "trustPolicy": _policy(configured[14], work),
        "configurationDigest": configured[9], "plannerIdentity": dict(zip(_IDENTITY_FIELDS, configured[7])),
        "plannerSpkiDigest": configured[8], "maximumPlanAgeNs": configured[15],
        "maximumClockSkewNs": configured[16]}


def _capture(*, values, business_before_roots, authorization_before_roots,
        expected_counted_heads, live_window, transport_deadline_ns, configured, work):
    evidence.capture._SharedLedger(work)
    if type(expected_counted_heads) is not tuple or len(expected_counted_heads) != writes.HEAD_COUNT:
        _fail("activation owner requires independent thirteen-head expectations")
    for roots in (business_before_roots, authorization_before_roots):
        if type(roots) not in (tuple, list) or len(roots) > contract.authority.MAX_QUERY_PROOFS:
            _fail("activation owner primary expectation inventory is not bounded")
    window = clock._validate(live_window)
    if window[5:] != configured[15:17]:
        _fail("activation owner live window differs from its configured policy")
    registration._integer(transport_deadline_ns, "activation owner inherited deadline", 1)
    bound = min(transport_deadline_ns, window[4])
    owned = reads.reads._CopyBudget(work).copy({"values": values,
        "business": business_before_roots, "authorization": authorization_before_roots,
        "heads": expected_counted_heads})
    writes._heads(list(owned["heads"]))
    return owned, window, bound


def _request(subject, assertion_bytes, old_token_bytes, new_token_bytes, ttl, work):
    arguments = dict(zip(("user_id", "session_id", "credential_id", "credential_record_id", "challenge_id"),
        (subject[name] for name in _SUBJECT_FIELDS)))
    arguments.update({"old_token_digest": assertion._digest(old_token_bytes, work),
        "new_token_digest": assertion._digest(new_token_bytes, work),
        "assertion_digest": assertion._digest(assertion_bytes, work), "delivery_ttl_seconds": ttl})
    arguments["businessIntent"] = contract.authority._synthesize_business_intent(OPERATION, arguments, work=work)
    plan.transition._arguments(arguments, work)
    request = {"schema": "serverware.policyAuthorityV9Request/v1", "operation": OPERATION,
        "handler": contract.authority.operation_spec(OPERATION)["handler"],
        "operationManifestDigest": contract.authority.OPERATION_MANIFEST_DIGEST,
        "requestDigest": "sha256:" + "0" * 64, "operationId": "sha256:" + "0" * 64,
        "arguments": arguments}
    request["requestDigest"] = plan.commitment._typed_request_digest(request, work=work)
    request["operationId"] = evidence.plan._frame("serverware.policyAuthorityOperation/v2",
        (evidence.plan._ascii(OPERATION, work), evidence.plan._ascii(request["requestDigest"], work)), work)
    return request


def _journal_scope(configured, request, envelope_bytes, work):
    return {"sourceRevision": contract.authority.SOURCE_REVISION, "configurationDigest": configured[9],
        "requestDigest": request["requestDigest"],
        "planDigest": evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope_bytes,), work)}


def _authenticate_known(envelope_bytes, request, scope, configured, window, check, work):
    """Verify the known original before lookup; this cannot replace full replay."""
    if request.get("operation") != OPERATION:
        _fail("activation retained request has the wrong operation")
    operation_id = evidence.plan._frame("serverware.policyAuthorityOperation/v2",
        (evidence.plan._ascii(OPERATION, work), evidence.plan._ascii(request["requestDigest"], work)), work)
    registration._same(request["operationId"], operation_id, work, "retained activation operation identity")
    registration._integer(scope["deadlineEpochNs"], "retained original deadline", 1)
    if window[3] > scope["deadlineEpochNs"]:
        _fail("activation retained processing exceeds its independent original deadline")
    check()
    envelope = contract._decode_on_work(envelope_bytes, envelope=True, work=work)
    payload = envelope["payload"]
    for name in ("requestDigest", "operationId"):
        registration._same(payload[name], request[name], work, "known activation plan " + name)
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        registration._same(payload[name], scope[name], work, "known activation plan " + name)
    unsigned = contract._encode_on_work(payload, work=work)
    evidence.keys._public_binding(configured[6], configured[8], work)
    evidence.capability._signature(configured[6], envelope["signatureBase64Url"],
        contract.SIGNATURE_DOMAIN, unsigned, evidence.capture._SharedLedger(work))
    now = check()
    evidence._fresh(payload, now, configured[15], configured[16])
    if payload["expiresAtEpochNs"] > scope["deadlineEpochNs"] or now >= scope["deadlineEpochNs"]:
        _fail("activation known plan exceeds its independently admitted original interval")
    return payload


def _ascii(value, work):
    if type(value) is not str or not 2 <= len(value) <= reads.reads.MAX_BOOKKEEPING_BYTES or not value.isascii():
        _fail("activation retained query bytes are not bounded exact ASCII")
    work.charge(input_bytes=len(value))
    return value.encode("ascii")


def _restore_inputs(value, work):
    """Reconstruct bounded raw records only; the real plan verifier follows."""
    registration._closed(value, custody.READ_INPUT_FIELDS, "activation retained read originals")
    if (value["schema"] != contract.PROOF_DOMAIN or type(value["selectedRows"]) is not list
            or len(value["selectedRows"]) != 10 or type(value["beforeProofs"]) is not list
            or len(value["beforeProofs"]) != 10 or type(value["readHeads"]) is not list
            or len(value["readHeads"]) != 7 or type(value["queryFrontiers"]) is not list
            or len(value["queryFrontiers"]) != 7 or type(value["queryReads"]) is not list
            or len(value["queryReads"]) != 17):
        _fail("activation retained read inventory changed")
    heads, frontiers, records = [], [], []
    for item in value["readHeads"]:
        if type(item) is not list or len(item) != 4:
            _fail("activation retained read head is not closed")
        heads.append(reads.batch.CompleteQueryHead(item[0], item[1], CountedNode(item[2], item[3])))
    for item in value["queryFrontiers"]:
        if (type(item) is not list or len(item) != 2 or type(item[1]) is not list
                or len(item[1]) > reads.MAX_OUTSIDE_PREFIXES + 1):
            _fail("activation retained range frontier is not bounded")
        entries = []
        for record in item[1]:
            if type(record) is not list or len(record) != 4 or record[0] not in ("leaf", "opaque"):
                _fail("activation retained frontier terminal is not closed")
            entries.append(IndexLeaf(*record[1:]) if record[0] == "leaf" else OpaqueSubtree(*record[1:]))
        frontiers.append(reads.batch.CompleteQueryFrontier(item[0], tuple(entries)))
    for item in value["queryReads"]:
        registration._closed(item, {"queryId", "declaredQueryJson", "resolvedQueryJson", "returnedRowCount", "addresses"},
            "activation retained query read")
        if type(item["addresses"]) is not list or len(item["addresses"]) > 17:
            _fail("activation retained query addresses exceed their source bound")
        addresses = []
        for address in item["addresses"]:
            registration._closed(address, {"table", "keyJson", "keyDigest", "present"}, "activation retained address")
            addresses.append(reads.reads._make_record(reads.reads.QueryReadAddress, {
                "table": address["table"], "key_json": _ascii(address["keyJson"], work),
                "key_digest": address["keyDigest"], "present": address["present"]}, work))
        records.append(reads.reads._make_record(reads.reads.QueryRead, {"query_id": item["queryId"],
            "declared_query_json": _ascii(item["declaredQueryJson"], work),
            "resolved_query_json": _ascii(item["resolvedQueryJson"], work),
            "addresses": tuple(addresses), "returned_row_count": item["returnedRowCount"]}, work))
    return tuple(value["selectedRows"]), tuple(value["beforeProofs"]), tuple(heads), tuple(frontiers), tuple(records)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationPlanOwner:
    _configured: tuple | None
    _seal: tuple | None
    _pid: int
    _lock: object
    _closed: bool

    def __init__(self, *, read_planner, planner_private_key, planner_public_key,
            expected_planner_identity, expected_planner_spki_digest, configuration_digest,
            delivery_custody_key, journal, rp_id, origin, authn_policy, trust_policy,
            maximum_plan_age_ns, maximum_clock_skew_ns, delivery_ttl_seconds,
            state_enrollment_bytes, state_root_public_key, complete_root_vector_bytes,
            live_window, work, transport_deadline_ns=None):
        ledger = evidence.capture._SharedLedger(work)
        if (type(read_planner) is not planning.OidcSessionActivationReadPlanner
                or type(journal) is not custody.ActivationOriginalJournal
                or not isinstance(planner_private_key, evidence.Ed25519PrivateKey)
                or not isinstance(planner_public_key, evidence.keys.Ed25519PublicKey)
                or type(delivery_custody_key) is not bytes or len(delivery_custody_key) != 32):
            _fail("activation plan owner requires actual configured owners and independent keys")
        enrolled = plan.state._original(state_enrollment_bytes,
            plan.state.head.authorization.MAX_ENROLLMENT_BYTES, "enrollment")
        root_key = state_root_public_key
        plan.state.head.authorization._public(root_key)
        vector_bytes = plan.state._original(complete_root_vector_bytes, plan.state.vector.MAX_BYTES, "complete vector")
        owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
            "identity": expected_planner_identity, "spki": expected_planner_spki_digest,
            "configuration": configuration_digest, "rpId": rp_id, "origin": origin,
            "policy": authn_policy, "trust": trust_policy, "age": maximum_plan_age_ns,
            "skew": maximum_clock_skew_ns, "ttl": delivery_ttl_seconds})
        evidence._identity(owned["identity"])
        for name in ("spki", "configuration"):
            registration._digest(owned[name])
        registration._text(owned["rpId"], "activation RP ID", 4096, work)
        registration._text(owned["origin"], "activation origin", 8192, work)
        registration._integer(owned["age"], "activation plan age", 1, contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
        registration._integer(owned["skew"], "activation plan skew", 0, contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
        registration._integer(owned["ttl"], "activation delivery lifetime", 5, 60)
        registration._closed(owned["policy"], {"userVerification", "allowedAuthenticatorClasses", "requireHardwareAttestation"},
            "configured activation authentication policy")
        registration._closed(owned["trust"], {"roots", "currentBundleDigest", "currentBundleSequence"},
            "configured activation trust policy")
        if type(owned["trust"]["roots"]) is not list or not 1 <= len(owned["trust"]["roots"]) <= assertion.trust.MAX_ROOTS:
            _fail("configured activation root inventory is not bounded")
        for descriptor in owned["trust"]["roots"]:
            registration._closed(descriptor, assertion._ROOT_FIELDS, "configured activation root descriptor")
        window, current = delivery._window(live_window, transport_deadline_ns, work)
        if window[5:] != (owned["age"], owned["skew"]):
            _fail("activation construction window differs from configured policy")
        current()
        read_config = planning.OidcSessionActivationReadPlanner._snapshot_configuration(read_planner)
        journal_config = custody.ActivationOriginalJournal._snapshot_configuration(journal)
        if (read_config[3] != owned["skew"] or type(journal_config) is not tuple or len(journal_config) != 7
                or journal_config[:2] != (contract.authority.SOURCE_REVISION, owned["configuration"])
                or journal_config[3] != delivery_custody_key or journal_config[2] == delivery_custody_key):
            _fail("activation owner/journal/read configuration does not join")
        evidence.keys._public_binding(planner_public_key, owned["spki"], work)
        evidence.keys._pair_on_work(planner_private_key, planner_public_key, work)
        material = plan.state.head.authorization._admit_enrollment_on_work(
            enrollment_bytes=enrolled, root_public_key=root_key, work=work)
        plan.state.vector._decode_on_work(vector_bytes, work=work)
        # Cold bootstrap joins these independent pins to configuration/database.
        # This constructor cannot learn or replace them from an observation.
        for role in ("state", "computation", "completion"):
            if material.payload[role]["spkiDigest"] == owned["spki"]:
                _fail("activation planner key overlaps an enrolled state-purpose key")
        configured = (contract.authority.SOURCE_REVISION, read_planner, read_config, journal, journal_config,
            planner_private_key, planner_public_key, tuple(owned["identity"][name] for name in _IDENTITY_FIELDS),
            owned["spki"], owned["configuration"], delivery_custody_key, owned["rpId"], owned["origin"],
            registration._wire(owned["policy"], work), registration._wire(owned["trust"], work),
            owned["age"], owned["skew"], owned["ttl"], enrolled, root_key, vector_bytes)
        object.__setattr__(self, "_configured", configured)
        object.__setattr__(self, "_seal", configured)
        object.__setattr__(self, "_pid", os.getpid())
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_closed", False)
        current()
        OidcSessionActivationPlanOwner._snapshot_configuration(self)

    def _snapshot_configuration(self):
        if (type(self) is not OidcSessionActivationPlanOwner or self._closed or self._pid != os.getpid()
                or type(self._lock) is not _LOCK_TYPE or type(self._configured) is not tuple
                or self._configured is not self._seal or len(self._configured) != 21):
            _fail("activation plan owner is closed, changed or belongs to another process")
        configured = self._configured
        if (configured[0] != contract.authority.SOURCE_REVISION
                or planning.OidcSessionActivationReadPlanner._snapshot_configuration(configured[1]) != configured[2]
                or custody.ActivationOriginalJournal._snapshot_configuration(configured[3]) != configured[4]):
            _fail("activation configured read or journal owner changed")
        return configured

    def _guard(self, configured, window, bound, work):
        _window, current = delivery._window(window, bound, work)
        def check():
            if OidcSessionActivationPlanOwner._snapshot_configuration(self) is not configured:
                _fail("activation plan owner changed during its invocation")
            now = current()
            if OidcSessionActivationPlanOwner._snapshot_configuration(self) is not configured:
                _fail("activation plan owner changed during its clock check")
            return now
        return check

    def prepare(self, *, assertion_bytes, old_token_bytes, expected_user_id, expected_session_id,
            expected_credential_id, expected_credential_record_id, expected_challenge_id,
            business_before_roots, authorization_before_roots, expected_counted_heads,
            head_query_bytes, head_observation_bytes,
            live_window, work, transport_deadline_ns):
        configured = OidcSessionActivationPlanOwner._snapshot_configuration(self)
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("activation plan owner is already in use")
        try:
            if type(assertion_bytes) is not bytes or not 2 <= len(assertion_bytes) <= assertion.MAX_ASSERTION_BYTES:
                _fail("activation preparation requires a bounded original assertion")
            query_bytes = plan.state._original(head_query_bytes, plan.state.head.MAX_QUERY_BYTES, "head query")
            observation_bytes = plan.state._original(head_observation_bytes, plan.state.head.MAX_BYTES, "head observation")
            old = assertion._token(old_token_bytes, work)
            subject = dict(zip(_SUBJECT_FIELDS, (expected_user_id, expected_session_id, expected_credential_id,
                expected_credential_record_id, expected_challenge_id)))
            owned, window, bound = _capture(values=subject, business_before_roots=business_before_roots,
                authorization_before_roots=authorization_before_roots, expected_counted_heads=expected_counted_heads,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns, configured=configured, work=work)
            check = OidcSessionActivationPlanOwner._guard(self, configured, window, bound, work)
            check()
            subject = owned["values"]
            scope = {**subject, **_fixed_scope(configured, work), "deadlineEpochNs": window[3]}
            state_payload = plan.state._verify_on_work(scope=scope, assertion_bytes=assertion_bytes,
                old_token_bytes=old, complete_root_vector_bytes=configured[20],
                query_bytes=query_bytes, observation_bytes=observation_bytes,
                enrollment_bytes=configured[18], root_public_key=configured[19],
                now_epoch_ns=check(), work=work)
            if check() >= state_payload["expiresAtEpochNs"]:
                _fail("activation observation expired before plan acquisition")
            new = delivery._new_token_on_work(live_window=window, work=work, transport_deadline_ns=bound)
            request = _request(subject, assertion_bytes, old, new, configured[17], work)
            acquired = planning.OidcSessionActivationReadPlanner.acquire_transition(configured[1], request=request,
                business_before_roots=owned["business"], authorization_before_roots=owned["authorization"],
                expected_counted_heads=owned["heads"], assertion_bytes=assertion_bytes, old_token_bytes=old,
                new_token_bytes=new, delivery_custody_key=configured[10], expected_user_id=subject["userId"],
                expected_session_id=subject["sessionId"], expected_credential_id=subject["credentialId"],
                expected_credential_record_id=subject["credentialRecordId"], expected_challenge_id=subject["challengeId"],
                rp_id=scope["rpId"], origin=scope["origin"], authn_policy=scope["authenticationPolicy"],
                trust_policy=scope["trustPolicy"], live_window=window, transport_deadline_ns=bound, work=work)
            check()
            write_bytes = writes._encode_on_work(request_digest=request["requestDigest"],
                counted_before_heads=acquired.counted_before_heads, write_inputs=acquired.write_inputs, work=work)
            context = core.KernelContext(OPERATION, request["arguments"], acquired.selected_rows,
                acquired.database_now, request["requestDigest"], query_reads=acquired.query_reads)
            arguments = {"request": request, "scope": scope, "assertion_bytes": assertion_bytes,
                "old_token_bytes": old, "new_token_bytes": new, "delivery_envelope_bytes": acquired.delivery_envelope_bytes,
                "delivery_custody_key": configured[10], "business_before_roots": owned["business"],
                "authorization_before_roots": owned["authorization"], "before_proofs": acquired.before_proofs,
                "read_heads": acquired.read_heads, "query_frontiers": acquired.query_frontiers,
                "expected_counted_heads": owned["heads"], "write_proof_bytes": write_bytes,
                "state_enrollment_bytes": configured[18], "state_root_public_key": configured[19],
                "complete_root_vector_bytes": configured[20], "head_query_bytes": query_bytes,
                "head_observation_bytes": observation_bytes,
                "live_window": window, "work": work, "transport_deadline_ns": bound}
            envelope = plan._produce_on_work(context, **arguments,
                planner_private_key=configured[5], planner_public_key=configured[6])
            payload = contract._decode_on_work(envelope, envelope=True, work=work)["payload"]
            if check() >= payload["expiresAtEpochNs"]:
                _fail("activation signed plan expired before original retention")
            invocation = plan._capture(context, **arguments)
            journal_scope = _journal_scope(configured, request, envelope, work)
            document = {"schema": custody.SCHEMA, "sourceRevision": configured[0], "request": request,
                "scope": scope, "databaseNow": acquired.database_now.isoformat(),
                "assertionBase64Url": _b64(assertion_bytes, work), "oldTokenBase64Url": _b64(old, work),
                "newTokenBase64Url": _b64(new, work), "deliveryEnvelopeBase64Url": _b64(acquired.delivery_envelope_bytes, work),
                "readInputs": plan._read_inputs(invocation, work), "writeProofBase64Url": _b64(write_bytes, work),
                "headQueryBase64Url": _b64(query_bytes, work),
                "headObservationBase64Url": _b64(observation_bytes, work),
                "stateEnrollmentBase64Url": _b64(configured[18], work),
                "completeRootVectorBase64Url": _b64(configured[20], work),
                "planEnvelopeBase64Url": _b64(envelope, work)}
            original = custody._encode_original_on_work(document, scope=journal_scope, work=work)
            if check() >= payload["expiresAtEpochNs"]:
                _fail("activation signed plan expired before journal publication")
            journal_digest = custody.ActivationOriginalJournal.append(configured[3], scope=journal_scope,
                original_bytes=original, live_window=window, work=work, transport_deadline_ns=bound)
            result = PreparedActivationPlan(registration._wire(request, work), registration._wire(scope, work),
                envelope, journal_scope["planDigest"], registration._digest(journal_digest))
            if check() >= payload["expiresAtEpochNs"]:
                _fail("activation signed plan expired after durable original retention")
            return result
        finally:
            lock.release()

    def verify_retained(self, *, envelope_bytes, expected_request, expected_scope,
            business_before_roots, authorization_before_roots, expected_counted_heads,
            live_window, work, transport_deadline_ns):
        configured = OidcSessionActivationPlanOwner._snapshot_configuration(self)
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("activation plan owner is already in use")
        try:
            _original, _scope, _window, _bound, check, full = OidcSessionActivationPlanOwner._verify_retained_locked(
                self, configured=configured, envelope_bytes=envelope_bytes,
                expected_request=expected_request, expected_scope=expected_scope,
                business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
                expected_counted_heads=expected_counted_heads, expected_journal_digest=None,
                live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
            plan._fresh_replayed(full.payload, full.invocation, full.write_result,
                plan._live(full.invocation, work), work)
            if check() >= full.payload["expiresAtEpochNs"]:
                _fail("activation retained plan expired before return")
            return full.write_result.transition
        finally:
            lock.release()

    def prepare_execution_bundle(self, *, envelope_bytes, expected_request, expected_scope,
            business_before_roots, authorization_before_roots, expected_counted_heads,
            expected_journal_digest, bundle_key, live_window, work, transport_deadline_ns):
        """Prepare private ciphertext only; no durable export or transport claim."""
        key, expected_digest = bundle_key, expected_journal_digest
        if type(key) is not bytes or len(key) != bundle.KEY_BYTES or type(expected_digest) is not str:
            _fail("activation bundle preparation requires an independent key and exact journal locator")
        registration._digest(expected_digest)
        # Immutable key/locator originals are held before readiness or clock
        # callbacks; they are never selected from a retained document.
        configured = OidcSessionActivationPlanOwner._snapshot_configuration(self)
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("activation plan owner is already in use")
        try:
            evidence.capture._SharedLedger(work)
            work.charge(input_bytes=4 * bundle.KEY_BYTES)
            if key == configured[10] or key == configured[4][2]:
                _fail("activation bundle key must differ from delivery and journal keys")
            original, journal_scope, window, bound, check, full = OidcSessionActivationPlanOwner._verify_retained_locked(
                self, configured=configured, envelope_bytes=envelope_bytes,
                expected_request=expected_request, expected_scope=expected_scope,
                business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
                expected_counted_heads=expected_counted_heads, expected_journal_digest=expected_digest,
                live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
            context = {"schema": bundle.CONTEXT_SCHEMA, "operation": OPERATION,
                **journal_scope, "journalDigest": expected_digest}
            live = plan._live(full.invocation, work)
            check()
            plan._fresh_replayed(full.payload, full.invocation, full.write_result, live, work)
            if check() >= full.payload["expiresAtEpochNs"]:
                _fail("activation retained plan expired before bundle preparation")
            candidate = bundle._seal_on_work(original_bytes=original, bundle_key=key, context=context,
                live_window=window, transport_deadline_ns=bound, work=work)
            check()
            plan._fresh_replayed(full.payload, full.invocation, full.write_result, live, work)
            if check() >= full.payload["expiresAtEpochNs"]:
                _fail("activation retained plan expired after bundle preparation")
            return candidate
        finally:
            lock.release()

    def _verify_retained_locked(self, *, configured, envelope_bytes, expected_request, expected_scope,
            business_before_roots, authorization_before_roots, expected_counted_heads,
            expected_journal_digest, live_window, work, transport_deadline_ns):
        """Same-call originals/full replay only; caller retains the actual lock."""
        if type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= contract.MAX_BYTES:
            _fail("activation retained verification requires its known signed original")
        owned, window, bound = _capture(values={"request": expected_request, "scope": expected_scope},
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, configured=configured, work=work)
        request, scope = owned["values"]["request"], owned["values"]["scope"]
        registration._closed(scope, plan._SCOPE_FIELDS, "independent retained activation scope")
        fixed = _fixed_scope(configured, work)
        registration._same({name: scope[name] for name in fixed}, fixed, work, "configured retained activation scope")
        registration._same(request["requestDigest"], plan.commitment._typed_request_digest(request, work=work),
            work, "independent retained request")
        check = OidcSessionActivationPlanOwner._guard(self, configured, window, bound, work)
        check()
        payload = _authenticate_known(envelope_bytes, request, scope, configured, window, check, work)
        journal_scope = _journal_scope(configured, request, envelope_bytes, work)
        if expected_journal_digest is None:
            original = custody.ActivationOriginalJournal.read(configured[3], scope=journal_scope,
                live_window=window, work=work, transport_deadline_ns=bound)
        else:
            original = custody.ActivationOriginalJournal.read_bound(configured[3], scope=journal_scope,
                expected_journal_digest=expected_journal_digest,
                live_window=window, work=work, transport_deadline_ns=bound)
        if original is None:
            _fail("activation exact retained original is absent")
        stored = custody._decode_original_on_work(original, scope=journal_scope, work=work)
        registration._same(stored["request"], request, work, "independent retained request")
        registration._same(stored["scope"], scope, work, "independent retained scope")
        raw = stored["readInputs"]
        for name, value in (("businessBeforeRoots", owned["business"]),
                ("authorizationBeforeRoots", owned["authorization"]), ("countedBeforeHeads", owned["heads"])):
            work.prepare_copy(value)
            registration._same(raw[name], list(value), work, "independent retained " + name)
        signed = registration._encoded_original(stored["planEnvelopeBase64Url"], contract.MAX_BYTES, work)
        _bytes_equal(signed, envelope_bytes, work, "signed envelope")
        selected, proofs, heads, frontiers, records = _restore_inputs(raw, work)
        database_now = registration._utc(stored["databaseNow"], "retained database time", work)
        context = core.KernelContext(OPERATION, request["arguments"], selected, database_now,
            request["requestDigest"], query_reads=records)
        original_assertion = registration._encoded_original(stored["assertionBase64Url"], assertion.MAX_ASSERTION_BYTES, work)
        old = registration._encoded_original(stored["oldTokenBase64Url"], 64, work, minimum=64)
        new = registration._encoded_original(stored["newTokenBase64Url"], 64, work, minimum=64)
        delivery_bytes = registration._encoded_original(stored["deliveryEnvelopeBase64Url"], delivery.ENVELOPE_BYTES,
            work, minimum=delivery.ENVELOPE_BYTES)
        write_bytes = registration._encoded_original(stored["writeProofBase64Url"], writes.MAX_WRITE_PROOF_BYTES, work)
        query_bytes = registration._encoded_original(stored["headQueryBase64Url"], plan.state.head.MAX_QUERY_BYTES, work)
        observation_bytes = registration._encoded_original(stored["headObservationBase64Url"], plan.state.head.MAX_BYTES, work)
        enrolled = registration._encoded_original(stored["stateEnrollmentBase64Url"],
            plan.state.head.authorization.MAX_ENROLLMENT_BYTES, work)
        vector_bytes = registration._encoded_original(stored["completeRootVectorBase64Url"], plan.state.vector.MAX_BYTES, work)
        _bytes_equal(enrolled, configured[18], work, "independently configured state enrollment")
        _bytes_equal(vector_bytes, configured[20], work, "independently configured complete vector")
        check()
        full = plan._verify_full_on_work(context, envelope_bytes=envelope_bytes, request=request, scope=scope,
            assertion_bytes=original_assertion, old_token_bytes=old, new_token_bytes=new,
            delivery_envelope_bytes=delivery_bytes, delivery_custody_key=configured[10],
            business_before_roots=owned["business"], authorization_before_roots=owned["authorization"],
            before_proofs=proofs, read_heads=heads, query_frontiers=frontiers, expected_counted_heads=owned["heads"],
            write_proof_bytes=write_bytes, planner_public_key=configured[6], live_window=window,
            state_enrollment_bytes=configured[18], state_root_public_key=configured[19],
            complete_root_vector_bytes=configured[20], head_query_bytes=query_bytes,
            head_observation_bytes=observation_bytes,
            work=work, transport_deadline_ns=bound)
        registration._same(full.plan_digest, journal_scope["planDigest"], work, "retained full plan identity")
        if check() >= payload["expiresAtEpochNs"]:
            _fail("activation retained plan expired before return")
        return original, journal_scope, window, bound, check, full

    def close(self):
        if type(self) is not OidcSessionActivationPlanOwner or self._pid != os.getpid():
            _fail("activation plan owner cannot close in a different process")
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("activation plan owner is already in use")
        try:
            if self._closed:
                return
            configured = self._configured
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_configured", None)
            object.__setattr__(self, "_seal", None)
            custody.ActivationOriginalJournal.close(configured[3])
        finally:
            lock.release()

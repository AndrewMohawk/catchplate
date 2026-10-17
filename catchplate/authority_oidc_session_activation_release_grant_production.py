"""Original-only root issuance of one fixed LIVE release grant pair.

The signed issuer policy independently selects the client and launch resources
and binds a genuine proof-bootstrap original. Request evidence never chooses
those pins. This library does not own a root key, provision resources, replay
private history, open a token, serve a socket or claim recipient delivery.
"""
from __future__ import annotations

import base64
import hashlib
import time

from catchplate import authority_current_root_authorization as state
from catchplate import authority_current_root_delivery_records as acknowledgments
from catchplate import authority_oidc_session_activation_release_intent as intents
from catchplate import authority_oidc_session_activation_release_proof as proofs
from catchplate import oidc_session_activation_release_grant_issuer_policy as issuer
from catchplate import oidc_session_activation_release_grant_issuer_bootstrap as cold
from catchplate import oidc_session_activation_release_outcome as outcomes
from catchplate import oidc_session_activation_release_transport as transport
from catchplate import oidc_session_activation_release_retained_authority as retained


clients, server = issuer.client, issuer.server
authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, production, clock = issuer.capture, issuer.production, issuer.clock
processing, keys, authority = issuer.processing, issuer.keys, issuer.authority
delivery, storage = clients.delivery, server.storage
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES
_OUTPUT_RESERVATION = storage.MAX_BYTES + server.MAX_BYTES + clients.MAX_BYTES + outcomes.MAX_BYTES


class OidcSessionActivationReleaseGrantProductionError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseGrantProductionError(message)


class _Lifetime:
    """Private same-call clock bookkeeping, never an admitted input carrier."""

    def __init__(self, window, bound, work, continuity):
        self.window, self.bound, self.work = window, bound, work
        self.epoch, self.monotonic = window[0], window[2]
        self.guards, self.continuation = [], continuity
        self.limits = work.limits
        self.ceilings = (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes)
        self.metrics = work.metrics
        if continuity is not None and not callable(continuity):
            _fail("release grant issuer restrictive continuity is not callable")

    def _ledger(self):
        capture._SharedLedger(self.work)
        limits, observed = self.work.limits, self.work.metrics
        if (limits is not self.limits
                or self.ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or observed.hash_work < self.metrics.hash_work
                or observed.input_bytes < self.metrics.input_bytes
                or observed.json_nodes < self.metrics.json_nodes):
            _fail("release grant issuer reset its original work allowance")
        self.metrics = observed

    def _floors(self, epoch, monotonic):
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < self.epoch or monotonic < self.monotonic
                or epoch >= self.window[3] or monotonic >= self.bound):
            _fail("release grant issuer clocks reversed or exceeded the narrowed allowance")
        self.epoch, self.monotonic = epoch, monotonic

    def _owner(self):
        self._ledger()
        if self.continuation is not None:
            observed = self.continuation(self.epoch, self.monotonic)
            self._ledger()
            if type(observed) is not tuple or len(observed) != 2:
                _fail("release grant issuer continuity must return only two clock floors")
            self._floors(*observed)

    def base(self):
        self._owner()
        epoch = clock._check_on_work(self.window, work=self.work)
        monotonic = production._callback(self.work, time.monotonic_ns)
        self._floors(epoch, monotonic)
        self._owner()
        return self.epoch

    def continuity(self, epoch, monotonic):
        # Inner original verifiers add restrictions to this base, never recurse
        # through their own retained live guard or supply replacement authority.
        self._floors(max(self.epoch, epoch), max(self.monotonic, monotonic))
        self.base()
        return self.epoch, self.monotonic

    def current(self):
        self.base()
        for guard in self.guards:
            observed = guard()
            if type(observed) is not int or observed < self.epoch or observed >= self.window[3]:
                _fail("release grant issuer original authority clocks reversed or expired")
            self.epoch = observed
            self.base()
        return self.epoch

    def attach(self, guard):
        if not callable(guard):
            _fail("release grant issuer original admission lacks its live guard")
        self.guards.append(guard)
        self.current()

    def adopt(self, window, bound):
        selected = clock._validate(window)
        shape._integer(bound, minimum=1)
        if (selected[:3] != self.window[:3] or bound > self.bound or bound > selected[4]
                or any(value > old for value, old in zip(selected[3:], self.window[3:]))):
            _fail("release grant issuer admission widened its original allowance")
        self.current()
        self.window, self.bound = selected, bound
        self.current()

    def narrow(self, expiry, age, skew):
        selected = processing._narrow(self.window, deadline_epoch_ns=expiry,
            maximum_lifetime_ns=min(age, self.window[5]),
            maximum_clock_skew_ns=min(skew, self.window[6]))
        self.adopt(selected, min(self.bound, selected[4]))


def _same_bytes(actual, expected, work, label):
    if type(actual) is not bytes or type(expected) is not bytes:
        _fail(label + " requires immutable original bytes")
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail(label + " differs")


def _bytes_digest(original, work, current):
    work.charge(hashes=1, input_bytes=len(original))
    current()
    result = production._callback(work, lambda: "sha256:" + hashlib.sha256(original).hexdigest())
    current()
    return result


def _wrapped(original, work, current):
    """Bound the actual byte transport before its native base64 allocation."""
    encoded_size = (4 * len(original) + 2) // 3
    work.charge(input_bytes=len(original) + encoded_size)
    digest = _bytes_digest(original, work, current)
    current()
    encoded = production._callback(work,
        lambda: base64.urlsafe_b64encode(original).decode("ascii").rstrip("="))
    current()
    if len(encoded) != encoded_size:
        _fail("release grant issuer original wrapper changed its reserved size")
    return {"base64Url": encoded, "byteCount": len(original), "bytesDigest": digest}


def _produce_on_work(*, request_originals, issuer_policy_bytes, proof_bootstrap_bytes,
        root_private_key, root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    """Return only (client authorization, server bootstrap) signed originals.

    Root custody is supplied by the actual independently bound proof bootstrap,
    not caller-selected scope or a successful proof/material object. Old-token
    possession is ephemeral; no original request or token is retained here.
    """
    # Hold all external originals, keys and scalar bounds before any callback.
    request = transport._originals(request_originals, response=False, profile=server.LIVE_PROFILE)
    policy_raw = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES, "release issuer policy")
    proof_bootstrap_raw = authorization._original(proof_bootstrap_bytes,
        issuer.MAX_PROOF_BOOTSTRAP_BYTES, "release issuer proof bootstrap")
    private, root, continuation = root_private_key, root_public_key, _continuity
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    original_bytes = sum(len(raw) for raw in (*request, policy_raw, proof_bootstrap_raw))
    proof_reservation = cold._proof_reservation(len(policy_raw), len(proof_bootstrap_raw))
    if original_bytes + proof_reservation + _OUTPUT_RESERVATION + transport.LIVE_REQUEST_HEADER_BYTES > MAX_ORIGINAL_BYTES:
        _fail("release issuer complete input and output inventory exceeds 64 MiB")
    capture._SharedLedger(work)
    work.charge(input_bytes=original_bytes + transport.LIVE_REQUEST_HEADER_BYTES)
    authorization._private(private)
    authorization._public(root)
    lifetime = _Lifetime(window, bound, work, continuation)
    current = lifetime.current
    current()
    keys._pair_on_work(private, root, work)
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_raw, proof_bootstrap_bytes=proof_bootstrap_raw,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("release issuer requires genuine policy-original admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    material = policy.proof_material
    if type(material) is not issuer.proof_bootstrap._ProofMaterial:
        _fail("release issuer requires the policy-bound genuine proof bootstrap")
    cm = material.completion_material
    evidence_root = cm.evidence_root_public_key
    current_planner = material.current_activation_planner
    # These decoded originals are simultaneously held by the actual material.
    # Reserve them as well as both final grants before request admission/signing.
    embedded = (material.completion_bootstrap_bytes, material.proof_enrollment_bytes,
        material.release_custody_bytes, material.intent_bytes, material.intent_enrollment_bytes,
        material.completion_request_bytes, material.state_receipt_bytes,
        cm.current_root_enrollment_bytes, cm.authorization_enrollment_bytes, cm.grant_enrollment_bytes)
    if current_planner is not None:
        if type(current_planner) is not server.custody.planner_bootstrap._PlannerMaterial:
            _fail("release issuer current template lacks genuine proof-original admission")
        embedded += (material.current_activation_planner_bytes, current_planner.bootstrap_bytes,
            current_planner.state_enrollment_bytes, current_planner.complete_root_vector_bytes)
    if original_bytes + sum(map(len, embedded)) + _OUTPUT_RESERVATION > MAX_ORIGINAL_BYTES:
        _fail("release issuer decoded originals exceed the complete held inventory")
    work.charge(input_bytes=sum(map(len, embedded)))
    _same_bytes(request[2], material.proof_enrollment_bytes, work, "release issuer proof enrollment")
    _same_bytes(request[3], material.intent_bytes, work, "release issuer intent")
    _same_bytes(request[4], material.intent_enrollment_bytes, work, "release issuer intent enrollment")
    scope, release = material.expected_proof_scope, material.expected_release
    intent_scope = {name: scope[name] for name in intents.SCOPE_FIELDS if name != "callerId"}
    intent_scope["callerId"] = material.caller_id
    intent_scope, release = intents._graphs(intent_scope, release)
    current()
    root_custody = server.custody._verify_on_work(custody_bytes=material.release_custody_bytes,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    current()
    historical = root_custody.intent_root_public_key is not None
    intent_root = retained.root_for(root_custody, root)
    retained.require_originals(root_custody, request[4], request[2], work)
    custody_planner = retained.planner_for(root_custody)
    lifetime.attach(server.custody.planner_bootstrap._launch_guard(root_custody.attestation_interval,
        root_custody.opening_sample, lifetime.base, work))
    lifetime.narrow(root_custody.attestation_interval[1], custody_planner.maximum_plan_age_ns,
        custody_planner.maximum_clock_skew_ns)
    if current_planner is None:
        if material.current_activation_planner_bytes is not None:
            _fail("legacy release proof has an unexpected current template")
        plan._same(keys._spki_on_work(evidence_root, work), keys._spki_on_work(root, work),
            work, "legacy release issuer original root")
        _same_bytes(root_custody.planner.state_enrollment_bytes, cm.current_root_enrollment_bytes,
            work, "release issuer exact activation state enrollment")
    else:
        _same_bytes(custody_planner.bootstrap_bytes, material.current_activation_planner_bytes,
            work, "release issuer exact current custody planner")
        _same_bytes(current_planner.bootstrap_bytes, material.current_activation_planner_bytes,
            work, "release issuer genuine current planner original")
    enrolled_state = authorization._admit_enrollment_on_work(enrollment_bytes=cm.current_root_enrollment_bytes,
        root_public_key=evidence_root, work=work)
    current()
    current_state = authorization._admit_enrollment_on_work(
        enrollment_bytes=custody_planner.state_enrollment_bytes, root_public_key=root, work=work)
    current()
    for actual, expected in ((enrolled_state.payload, current_state.payload),
            (enrolled_state.enrollment_digest, cm.enrollment_digest),
            (current_state.enrollment_digest, custody_planner.state_enrollment_digest),
            (current_state.payload["databaseId"], scope["databaseId"]),
            (cm.database_id, scope["databaseId"]),
            (current_state.payload["generationDigest"], scope["generationDigest"]),
            (cm.generation_digest, scope["generationDigest"]),
            (root_custody.delivery_key_digest, cm.custody_material.history.planner.delivery_key_digest)):
        plan._same(actual, expected, work, "release issuer complete original/current state and delivery key")
    current()
    unique = issuer.proof_bootstrap._unique_keys
    base_keys = unique((root_custody.planner.planner_public_key, custody_planner.planner_public_key,
        current_state.computation_public_key,
        current_state.completion_public_key, current_state.state_public_key,
        enrolled_state.computation_public_key, enrolled_state.completion_public_key,
        enrolled_state.state_public_key, evidence_root, root), work)
    intent_enrollment = intents.enrollments._admit_on_work(enrollment_bytes=request[4],
        root_public_key=intent_root, expected_scope=intent_scope, forbidden_public_keys=base_keys, work=work)
    current()
    completion = issuer.proof_bootstrap.completion
    caller_enrollment = completion.caller._admit_enrollment_on_work(
        authorization_enrollment_bytes=cm.authorization_enrollment_bytes,
        current_root_enrollment_bytes=cm.current_root_enrollment_bytes,
        grant_enrollment_bytes=cm.grant_enrollment_bytes, root_public_key=evidence_root,
        configuration_digest=cm.configuration_digest, planner_public_key=cm.planner_public_key,
        operation_public_key=cm.operation_public_key, work=work)
    current()
    grant_enrollment = completion.grants._admit_enrollment_on_work(grant_enrollment_bytes=cm.grant_enrollment_bytes,
        current_root_enrollment_bytes=cm.current_root_enrollment_bytes, root_public_key=evidence_root, work=work)
    current()
    proof_keys = unique((*base_keys, intent_enrollment.caller_public_key, cm.planner_public_key,
        cm.operation_public_key, caller_enrollment.caller_public_key, grant_enrollment.authorizer_public_key,
        cm.custody_material.history.planner.planner_public_key), work)

    # The expected receipt identity comes from independently root-bound exact
    # COMPLETE/ACK originals, never from decoding the incoming proof payload.
    complete_arguments = dict(request_bytes=material.completion_request_bytes,
        enrollment_bytes=cm.current_root_enrollment_bytes, root_public_key=evidence_root, work=work)
    if historical:
        complete_material, complete, complete_digest = state._verify_historical_request_on_work(**complete_arguments)
        if complete["issuedAtEpochNs"] > current():
            _fail("retained COMPLETE evidence is future-issued")
    else:
        complete_material, complete, complete_digest = state._verify_request_on_work(
            **complete_arguments, now_epoch_ns=current())
    current()
    acknowledged = acknowledgments._verify_ack_on_work(request_bytes=material.completion_request_bytes,
        receipt_bytes=material.state_receipt_bytes, enrollment_bytes=cm.current_root_enrollment_bytes,
        root_public_key=evidence_root, expected_pending_sequence=cm.current_pending[0],
        expected_pending_head_digest=cm.current_pending[1], work=work)
    current()
    plan._same(acknowledged.request_payload, complete, work, "release issuer exact signed COMPLETE")
    plan._same(acknowledged.request_digest, complete_digest, work, "release issuer COMPLETE identity")
    for name, expected in (("action", "complete"), ("operation", server.custody.CONSUME_OPERATION),
            ("requestDigest", release["consumeRequestDigest"]), ("pendingDecisionDigest", cm.current_pending[1]),
            ("fence", cm.current_pending[2]), ("databaseId", scope["databaseId"]),
            ("generationDigest", scope["generationDigest"]),
            ("afterVectorDigest", release["consumeBinding"]["afterVectorDigest"])):
        plan._same(complete[name], expected, work, "release issuer root-bound completion " + name)
    for name, expected in (("packetDigest", cm.packet_digest), ("pendingDecisionDigest", cm.current_pending[1]),
            ("completionRequestDigest", complete_digest)):
        plan._same(release["consumeBinding"][name], expected, work, "release issuer root-bound consume " + name)
    complete_age = complete_material.payload["maxControlAgeNs"]

    def complete_live():
        now = lifetime.base()
        state._fresh(complete, complete_material, now)
        return now

    if not historical:
        lifetime.attach(complete_live)
        lifetime.narrow(min(complete["expiresAtEpochNs"], complete["issuedAtEpochNs"] + complete_age),
            complete_age, complete_material.payload["maxClockSkewNs"])
    intent_verifier = intents._verify_historical_on_work if historical else intents._verify_on_work
    admitted_intent = intent_verifier(intent_bytes=request[3], enrollment_bytes=request[4],
        root_public_key=intent_root, forbidden_public_keys=base_keys, expected_scope=intent_scope,
        expected_release=release, old_token_bytes=request[5], live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    if type(admitted_intent) is not (intents._HistoricalIntentEvidence if historical else intents._AdmittedIntent):
        _fail("release issuer requires actual live intent and old-token possession")
    lifetime.attach(admitted_intent.live)
    intent_interval = admitted_intent.payload["issuedAtEpochNs"], admitted_intent.payload["expiresAtEpochNs"]
    retained.contain(root_custody, admitted_intent.payload)
    if not historical:
        lifetime.narrow(min(intent_interval[1], intent_interval[0] + intent_enrollment.payload["maximumAgeNs"]),
            intent_enrollment.payload["maximumAgeNs"], intent_enrollment.payload["maximumClockSkewNs"])
    plan._same(root_custody.release_intent_digest, admitted_intent.intent_digest, work,
        "release issuer original custody intent")
    custody_digest = plan._frame(proofs.contract.CUSTODY_IDENTITY_DOMAIN,
        (retained.custody_for(root_custody),), work)
    current_custody_digest = plan._frame(proofs.contract.CUSTODY_IDENTITY_DOMAIN,
        (material.release_custody_bytes,), work)
    evidence = {"releaseCustodyDigest": custody_digest, "releaseIntentDigest": admitted_intent.intent_digest,
        "stateReceiptDigest": acknowledged.receipt_digest}
    current()
    proof_verifier = proofs._verify_historical_on_work if historical else proofs._verify_on_work
    admitted_proof = proof_verifier(proof_bytes=request[1], enrollment_bytes=request[2],
        root_public_key=intent_root, forbidden_public_keys=proof_keys, expected_scope=scope, expected_release=release,
        expected_evidence=evidence, expected_intent_interval=intent_interval, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    if type(admitted_proof) is not (proofs._HistoricalProofEvidence if historical else proofs._AdmittedProof):
        _fail("release issuer requires genuine original committed-release proof admission")
    lifetime.attach(admitted_proof.live)
    retained.contain(root_custody, admitted_proof.payload)
    proof_enrollment = proofs.enrollments._admit_on_work(enrollment_bytes=request[2], root_public_key=intent_root,
        expected_scope=scope, forbidden_public_keys=proof_keys, work=work)
    current()
    age, skew = proof_enrollment.payload["maximumAgeNs"], proof_enrollment.payload["maximumClockSkewNs"]
    if not historical:
        lifetime.narrow(min(admitted_proof.payload["expiresAtEpochNs"],
            admitted_proof.payload["issuedAtEpochNs"] + age), age, skew)
    delivery._envelope(request[6], work)
    plan._same(_bytes_digest(request[6], work, current), release["deliveryEnvelopeDigest"], work,
        "release issuer original encrypted envelope")
    record = outcomes._encode_on_work(scope={name: admitted_proof.payload[name] for name in outcomes.SCOPE_FIELDS},
        release_binding={name: admitted_proof.payload[name] for name in outcomes.RELEASE_FIELDS},
        evidence_binding={**evidence, "releaseProofDigest": admitted_proof.proof_digest,
            "proofEnrollmentDigest": admitted_proof.payload["enrollmentDigest"],
            "intentEnrollmentDigest": admitted_intent.payload["enrollmentDigest"]},
        caller_id=material.caller_id, work=work)
    current()
    outcome_digest = outcomes._digest_on_work(record, work)
    request_identity = transport._request_identity_on_work(request, profile=server.LIVE_PROFILE,
        deadline_ns=lifetime.bound, work=work, current=current)
    current()

    # All grant targets below are derived from root policy and genuinely
    # admitted originals. The empty checkpoint is authorization, not an I/O
    # observation; the eventual release owner must independently check it.
    launch = policy.release_launch
    storage_scope = {name: scope[name] for name in ("configurationDigest", "databaseId",
        "generationDigest", "runtimeClosureDigest", "receiverIdentity")}
    storage_scope.update({"deliveryId": release["deliveryScope"]["deliveryId"],
        "releaseCustodyDigest": custody_digest,
        "directory": {name: launch["outcomeDirectory" + suffix]
            for name, suffix in (("device", "Device"), ("inode", "Inode"), ("uid", "Uid"), ("gid", "Gid"))},
        "checkpoint": {"recordCount": 0, "outcomeDigest": None}})
    issued, expires = current(), lifetime.window[3]
    if issued >= expires:
        _fail("release issuer has no remaining original grant lifetime")
    interval = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    common = {"sourceRevision": authority.SOURCE_REVISION, "trustMode": "trusted-host-local", **interval}
    storage_payload = {**storage_scope, **common, "schema": storage.PAYLOAD_SCHEMA,
        "purpose": storage.PURPOSE, "serviceUid": storage.SERVICE_UID,
        "serviceGid": storage.SERVICE_GID, "processMode": storage.PROCESS_MODE}
    storage_raw = storage._produce_on_work(payload=storage_payload, root_private_key=private,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    current()
    admitted_storage = storage._verify_on_work(authorization_bytes=storage_raw, root_public_key=root,
        expected_scope=storage_scope, live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    lifetime.attach(admitted_storage.live)
    server_payload = {**common, "schema": server.V2_PAYLOAD_SCHEMA if historical else server.PAYLOAD_SCHEMA,
        "purpose": server.PURPOSE,
        "role": server.ROLE, "profile": server.LIVE_PROFILE,
        **{name: scope[name] for name in ("configurationDigest", "databaseId", "generationDigest",
            "runtimeClosureDigest", "receiverIdentity", "producerId", "producerIdentity")},
        "callerId": material.caller_id, "stateReceiptDigest": acknowledged.receipt_digest,
        "expectedRelease": release, "releaseCustodyDigest": current_custody_digest,
        "deliveryKeyDigest": root_custody.delivery_key_digest, "storageScope": storage_scope,
        "recoveryScope": None, "releaseCustody": _wrapped(material.release_custody_bytes, work, current),
        "storageAuthorization": _wrapped(storage_raw, work, current), "recoveryAuthorization": None,
        "launch": launch, **{name: False for name in server._FALSE_FIELDS}}
    if historical:
        server_payload["evidenceCustodyDigest"] = custody_digest
    current()
    server_raw = server._produce_on_work(payload=server_payload, root_private_key=private,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    current()
    server_material = server._verify_on_work(bootstrap_bytes=server_raw, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    lifetime.attach(server_material.live)
    lifetime.adopt(server_material.live_window, server_material.deadline_ns)
    _same_bytes(server_material.custody_bytes, material.release_custody_bytes, work,
        "release issuer exact proof-associated server custody")
    endpoint = dict(zip(("path", "timeoutSeconds", "peerUid", "peerGid"), policy.endpoint))
    expected_scope = clients._scope({**scope, "serverBootstrapDigest": clients._server_bootstrap_digest_on_work(server_raw, work),
        "profile": server.LIVE_PROFILE, "requestIdentity": request_identity.decode("ascii"),
        "clientId": policy.client_id, "clientIdentity": policy.client_identity, "callerId": material.caller_id,
        "stateReceiptDigest": acknowledged.receipt_digest, "expectedRelease": release,
        "expectedOutcomeDigest": outcome_digest, "endpoint": endpoint}, work)
    client_payload = {**expected_scope, **common, "schema": clients.PAYLOAD_SCHEMA,
        "purpose": clients.PURPOSE, "clientUid": clients.CLIENT_UID, "clientGid": clients.CLIENT_GID}
    current()
    client_raw = clients._produce_on_work(payload=client_payload, server_bootstrap_bytes=server_raw,
        root_private_key=private, root_public_key=root, expected_scope=expected_scope,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    current()
    admitted_client = clients._verify_on_work(authorization_bytes=client_raw, server_bootstrap_bytes=server_raw,
        root_public_key=root, expected_scope=expected_scope, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work)
    lifetime.attach(admitted_client.live)
    lifetime.adopt(admitted_client.live_window, admitted_client.deadline_ns)
    current()
    return client_raw, server_raw

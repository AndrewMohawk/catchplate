"""Original-only fresh recovery grants, never outcome-store observations.

Historical custody, intent and proof retain their original intervals. A fresh
independent root policy selects the exact recovery target, outcome and resource
pins. This pure composition neither creates a record nor opens a token; the
eventual recovery owner must independently read the checkpoint-one store.
"""
from __future__ import annotations

from serverware import oidc_session_activation_release_retained_authority as retained

from serverware import authority_oidc_session_activation_release_grant_production as shared
from serverware import authority_oidc_session_activation_release_intent as intents
from serverware import authority_oidc_session_activation_release_proof as proofs
from serverware import oidc_session_activation_release_recovery_issuer_policy as issuer
from serverware import oidc_session_activation_release_outcome as outcomes
from serverware import oidc_session_activation_release_transport as transport


clients, server = issuer.client, issuer.server
authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, clock, keys, authority = issuer.capture, issuer.clock, issuer.keys, issuer.authority
delivery, storage, recovery = clients.delivery, server.storage, server.recovery
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES
# Keep both the output server original and its readback capacity, plus the
# smaller generated originals and captures, reserved before any admission.
_OUTPUT_RESERVATION = 2 * server.MAX_BYTES + 3 * (
    storage.MAX_BYTES + recovery.MAX_BYTES + clients.MAX_BYTES + outcomes.MAX_BYTES)
_Lifetime = shared._Lifetime


class OidcSessionActivationReleaseRecoveryGrantProductionError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseRecoveryGrantProductionError(message)


def _request_originals(values):
    """Bound the actual recovery prefix7 without inventing an outcome frame."""
    limits = transport.RECOVERY_REQUEST_LIMITS[:7]
    if (type(values) is not tuple or len(values) != 7
            or any(type(raw) is not bytes for raw in values)):
        _fail("recovery grant request requires seven immutable original frames")
    sizes = tuple(map(len, values))
    if (values[0] != transport.RECOVERY_PURPOSE or sizes[0] != limits[0]
            or sizes[5:7] != limits[5:7]
            or any(not 2 <= sizes[index] <= limits[index] for index in (1, 2, 3, 4))):
        _fail("recovery grant prefix differs from the fixed recovery grammar")
    return values


def _input_reservation(request, policy, custody, proof_enrollment, intent_enrollment):
    """Known original/capture footprints, shared by derivation and signing."""
    return (8 * len(custody)
        + 4 * sum(map(len, (*request, policy, proof_enrollment, intent_enrollment)))
        + transport.RECOVERY_REQUEST_HEADER_BYTES)


def _derive_on_work(*, request_originals, issuer_policy_bytes, release_custody_bytes,
        proof_enrollment_bytes, intent_enrollment_bytes, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None,
        _additional_original_bytes=0):
    """Re-admit originals and return private same-call derivation data only.

    Result order is request8, genuine policy, canonical outcome, storage scope,
    recovery scope, request identity71, lifetime. No API accepts this tuple as
    authority. Its outcome is a reconstruction, not a durable-store receipt.
    Additional already-held representations only reduce this same 64 MiB cap;
    no unused grant-generation maximum is reserved by a read-only derivation.
    """
    request = _request_originals(request_originals)
    policy_raw = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES,
        "recovery issuer policy")
    custody_raw = authorization._original(release_custody_bytes, server.custody.MAX_BYTES,
        "recovery historical custody")
    proof_enrolled = authorization._original(proof_enrollment_bytes, proofs.enrollments.MAX_BYTES,
        "recovery independently pinned proof enrollment")
    intent_enrolled = authorization._original(intent_enrollment_bytes, intents.enrollments.MAX_BYTES,
        "recovery independently pinned intent enrollment")
    root, continuation = root_public_key, _continuity
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    other_originals = (*request, policy_raw, proof_enrolled, intent_enrolled)
    original_bytes = len(custody_raw) + sum(map(len, other_originals))
    # Eight custody copies conservatively cover its original, nested planner,
    # decoded/canonical graphs and later embedded-server custody readbacks.
    # Smaller originals retain four-copy capacity. These are tightening bounds,
    # not permission to allocate each individual maximum simultaneously.
    if (type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < MAX_ORIGINAL_BYTES):
        _fail("recovery derivation held-original reservation is invalid")
    reserved = (_additional_original_bytes
        + _input_reservation(request, policy_raw, custody_raw, proof_enrolled, intent_enrolled)
        + 3 * outcomes.MAX_BYTES)
    if MAX_ORIGINAL_BYTES != 64 * 1024 * 1024 or reserved > MAX_ORIGINAL_BYTES:
        _fail("recovery derivation exceeds its complete original and outcome inventory")
    capture._SharedLedger(work)
    work.charge(input_bytes=original_bytes + transport.RECOVERY_REQUEST_HEADER_BYTES)
    authorization._public(root)
    lifetime = _Lifetime(window, bound, work, continuation)
    current = lifetime.current
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_raw, release_custody_bytes=custody_raw,
        proof_enrollment_bytes=proof_enrolled, intent_enrollment_bytes=intent_enrolled,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("recovery grants require genuine independent policy-original admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    material = policy.custody_material
    if type(material) is not server.custody._ReleaseCustodyMaterial:
        _fail("recovery grants require genuine historical custody-original admission")
    evidence_root = retained.root_for(material, root)
    retained.require_originals(material, intent_enrolled, proof_enrolled, work)
    shared._same_bytes(policy.release_custody_bytes, custody_raw, work,
        "recovery policy exact custody original")
    shared._same_bytes(request[2], proof_enrolled, work, "recovery request proof enrollment")
    shared._same_bytes(request[4], intent_enrolled, work, "recovery request intent enrollment")
    scope, release, evidence = proofs._graphs(policy.payload["proofScope"],
        policy.payload["expectedRelease"], policy.payload["expectedEvidence"])
    intent_scope = {name: scope[name] for name in intents.SCOPE_FIELDS if name != "callerId"}
    intent_scope["callerId"] = policy.payload["callerId"]
    current()
    # The expected evidence and outcome are root-policy pins, never claims
    # copied out of the incoming proof. No candidate outcome is an input.
    intent = intents._verify_historical_on_work(intent_bytes=request[3],
        enrollment_bytes=intent_enrolled, root_public_key=evidence_root,
        forbidden_public_keys=policy.forbidden_public_keys, expected_scope=intent_scope,
        expected_release=release, old_token_bytes=request[5], live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    if type(intent) is not intents._HistoricalIntentEvidence:
        _fail("recovery grants require historical intent and actual old-token possession")
    lifetime.attach(intent.live)
    retained.contain(material, intent.payload)
    for actual, expected, label in (
            (intent.intent_digest, material.release_intent_digest, "custody intent"),
            (intent.intent_digest, evidence["releaseIntentDigest"], "independent intent"),
            (intent.payload["enrollmentDigest"], policy.payload["intentEnrollmentDigest"], "intent enrollment")):
        plan._same(actual, expected, work, "recovery historical " + label)
    proof = proofs._verify_historical_on_work(proof_bytes=request[1],
        enrollment_bytes=proof_enrolled, root_public_key=evidence_root,
        forbidden_public_keys=(*policy.forbidden_public_keys, policy.intent_public_key),
        expected_scope=scope, expected_release=release, expected_evidence=evidence,
        expected_intent_interval=(intent.payload["issuedAtEpochNs"], intent.payload["expiresAtEpochNs"]),
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(proof) is not proofs._HistoricalProofEvidence:
        _fail("recovery grants require genuine historical committed-release proof")
    lifetime.attach(proof.live)
    retained.contain(material, proof.payload)
    plan._same(proof.payload["enrollmentDigest"], policy.payload["proofEnrollmentDigest"], work,
        "recovery historical proof enrollment")
    delivery._envelope(request[6], work)
    plan._same(shared._bytes_digest(request[6], work, current), release["deliveryEnvelopeDigest"],
        work, "recovery exact original encrypted envelope")
    record = outcomes._encode_on_work(scope={name: proof.payload[name] for name in outcomes.SCOPE_FIELDS},
        release_binding={name: proof.payload[name] for name in outcomes.RELEASE_FIELDS},
        evidence_binding={**evidence, "releaseProofDigest": proof.proof_digest,
            "proofEnrollmentDigest": proof.payload["enrollmentDigest"],
            "intentEnrollmentDigest": intent.payload["enrollmentDigest"]},
        caller_id=intent.payload["callerId"], work=work)
    current()
    outcome_digest = outcomes._digest_on_work(record, work)
    current()
    plan._same(outcome_digest, policy.payload["expectedOutcomeDigest"], work,
        "recovery reconstructed independent outcome identity")
    request = transport._originals((*request, record), response=False,
        profile=server.RECOVERY_PROFILE)
    request_identity = transport._request_identity_on_work(request, profile=server.RECOVERY_PROFILE,
        deadline_ns=lifetime.bound, work=work, current=current)
    launch = policy.release_launch
    directory = {name: launch["outcomeDirectory" + name[0].upper() + name[1:]]
        for name in storage.DIRECTORY_FIELDS}
    storage_scope = storage._scope({**{name: scope[name] for name in (
        "configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity")},
        "deliveryId": release["deliveryScope"]["deliveryId"],
        "releaseCustodyDigest": evidence["releaseCustodyDigest"], "directory": directory,
        "checkpoint": {"recordCount": 1, "outcomeDigest": outcome_digest}}, work)
    recovery_scope = recovery._scope({**{name: storage_scope[name] for name in (
        "configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity",
        "deliveryId", "releaseCustodyDigest", "directory")}, "callerId": policy.payload["callerId"],
        "deliveryKeyDigest": material.delivery_key_digest, "outcomeDigest": outcome_digest,
        **({"currentReleaseCustodyDigest": policy.payload["currentReleaseCustodyDigest"]}
            if material.intent_root_public_key is not None else {})}, work)
    current()
    return request, policy, record, storage_scope, recovery_scope, request_identity, lifetime


def _produce_on_work(*, request_originals, issuer_policy_bytes, release_custody_bytes,
        proof_enrollment_bytes, intent_enrollment_bytes, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Return only (client authorization, recovery server bootstrap, outcome).

    The actual root pair is externally owned. A checkpoint-one grant is an
    independent expected binding, not evidence that a record exists on disk.
    There is no SQL, storage access, token opening, service or network exchange.
    """
    private, root = root_private_key, root_public_key
    authorization._private(private)
    # Signing alone reserves the large generated server and readback inventory.
    # Keep the former production bound before genuine derivation/decode, without
    # imposing those unused outputs on an active read-only exchange re-derivation.
    producing_request = _request_originals(request_originals)
    producing_originals = (
        authorization._original(issuer_policy_bytes, issuer.MAX_BYTES, "recovery issuer policy"),
        authorization._original(release_custody_bytes, server.custody.MAX_BYTES, "recovery historical custody"),
        authorization._original(proof_enrollment_bytes, proofs.enrollments.MAX_BYTES, "recovery proof enrollment"),
        authorization._original(intent_enrollment_bytes, intents.enrollments.MAX_BYTES, "recovery intent enrollment"))
    if (MAX_ORIGINAL_BYTES != 64 * 1024 * 1024
            or _input_reservation(producing_request, *producing_originals)
                + _OUTPUT_RESERVATION > MAX_ORIGINAL_BYTES):
        _fail("recovery grants exceed their complete original and output inventory")
    request, policy, record, storage_scope, recovery_scope, request_identity, lifetime = _derive_on_work(
        request_originals=request_originals, issuer_policy_bytes=issuer_policy_bytes,
        release_custody_bytes=release_custody_bytes, proof_enrollment_bytes=proof_enrollment_bytes,
        intent_enrollment_bytes=intent_enrollment_bytes, root_public_key=root,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work,
        _continuity=_continuity)
    current = lifetime.current
    current()
    keys._pair_on_work(private, root, work)
    current()
    payload, material = policy.payload, policy.custody_material
    scope, release, evidence = payload["proofScope"], payload["expectedRelease"], payload["expectedEvidence"]
    issued, expires = max(current(), payload["issuedAtEpochNs"]), lifetime.window[3]
    if issued >= expires:
        _fail("recovery grants have no remaining independent original lifetime")
    common = {"sourceRevision": authority.SOURCE_REVISION, "trustMode": "trusted-host-local",
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    storage_payload = {**storage_scope, **common, "schema": storage.PAYLOAD_SCHEMA,
        "purpose": storage.PURPOSE, "serviceUid": storage.SERVICE_UID,
        "serviceGid": storage.SERVICE_GID, "processMode": storage.PROCESS_MODE}
    storage_raw = storage._produce_on_work(payload=storage_payload, root_private_key=private,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    admitted_storage = storage._verify_on_work(authorization_bytes=storage_raw, root_public_key=root,
        expected_scope=storage_scope, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    lifetime.attach(admitted_storage.live)
    bridged = material.intent_root_public_key is not None
    recovery_payload = {**recovery_scope, **common,
        "schema": recovery.V2_PAYLOAD_SCHEMA if bridged else recovery.PAYLOAD_SCHEMA,
        "purpose": recovery.PURPOSE, "serviceUid": recovery.SERVICE_UID,
        "serviceGid": recovery.SERVICE_GID, "processMode": recovery.PROCESS_MODE}
    recovery_raw = recovery._produce_on_work(payload=recovery_payload, root_private_key=private,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    admitted_recovery = recovery._verify_on_work(authorization_bytes=recovery_raw, root_public_key=root,
        expected_scope=recovery_scope, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    lifetime.attach(admitted_recovery.live)
    server_payload = {**common, "schema": server.V3_PAYLOAD_SCHEMA if bridged else server.PAYLOAD_SCHEMA, "purpose": server.PURPOSE,
        "role": server.ROLE, "profile": server.RECOVERY_PROFILE, **scope,
        "callerId": payload["callerId"], "stateReceiptDigest": evidence["stateReceiptDigest"],
        "expectedRelease": release, "releaseCustodyDigest": payload["currentReleaseCustodyDigest"] if bridged
            else evidence["releaseCustodyDigest"],
        "deliveryKeyDigest": material.delivery_key_digest, "storageScope": storage_scope,
        "recoveryScope": recovery_scope,
        "releaseCustody": shared._wrapped(policy.release_custody_bytes, work, current),
        "storageAuthorization": shared._wrapped(storage_raw, work, current),
        "recoveryAuthorization": shared._wrapped(recovery_raw, work, current),
        "launch": policy.release_launch, **{name: False for name in server._FALSE_FIELDS}}
    if bridged:
        server_payload["evidenceCustodyDigest"] = evidence["releaseCustodyDigest"]
    current()
    server_raw = server._produce_on_work(payload=server_payload, root_private_key=private,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    server_material = server._verify_on_work(bootstrap_bytes=server_raw, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    lifetime.attach(server_material.live)
    lifetime.adopt(server_material.live_window, server_material.deadline_ns)
    shared._same_bytes(server_material.custody_bytes, policy.release_custody_bytes, work,
        "recovery server exact historical custody")
    endpoint = dict(zip(("path", "timeoutSeconds", "peerUid", "peerGid"), policy.endpoint))
    expected_scope = clients._scope({**scope,
        "serverBootstrapDigest": clients._server_bootstrap_digest_on_work(server_raw, work),
        "profile": server.RECOVERY_PROFILE, "requestIdentity": request_identity.decode("ascii"),
        "clientId": policy.client_id, "clientIdentity": policy.client_identity,
        "callerId": payload["callerId"], "stateReceiptDigest": evidence["stateReceiptDigest"],
        "expectedRelease": release, "expectedOutcomeDigest": payload["expectedOutcomeDigest"],
        "endpoint": endpoint}, work)
    client_payload = {**expected_scope, **common, "schema": clients.PAYLOAD_SCHEMA,
        "purpose": clients.PURPOSE, "clientUid": clients.CLIENT_UID, "clientGid": clients.CLIENT_GID}
    current()
    client_raw = clients._produce_on_work(payload=client_payload, server_bootstrap_bytes=server_raw,
        root_private_key=private, root_public_key=root, expected_scope=expected_scope,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    admitted_client = clients._verify_on_work(authorization_bytes=client_raw, server_bootstrap_bytes=server_raw,
        root_public_key=root, expected_scope=expected_scope, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    lifetime.attach(admitted_client.live)
    lifetime.adopt(admitted_client.live_window, admitted_client.deadline_ns)
    current()
    return client_raw, server_raw, record

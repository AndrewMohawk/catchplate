"""Signed bounded parents for genuine streamed challenge maintenance.

Only the actual two-pass snapshot owner can produce a parent. Its first pass
computes the complete manifest and relative roots; its second pass retains the
same originals and repeats the computation before any signed result is returned.
Verification authenticates the detached request and manifest, then independently
replays every raw page. A signed decision or a successful producer observation is
never accepted in place of that replay.

Configuration/key custody, current-root admission, capability issuance, SQL
execution and outer commit remain separate protected owners. These functions
neither open a clock window nor enroll their supplied expectations. In particular
historical verification does not renew the original deadline or authorize use of
an expired parent. Partial page retention is not an executable plan.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from catchplate import authority_challenge_chain as chains
from catchplate import authority_challenge_maintenance as maintenance
from catchplate import authority_challenge_manifest as manifests
from catchplate import authority_challenge_plan_request as requests
from catchplate import authority_challenge_replay as replay
from catchplate import authority_challenge_snapshot as snapshots
from catchplate import authority_webauthn_evidence as evidence
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate.authority_query_read_work import _ValidationWork


SCHEMA = "catchplate.policyAuthorityChallengeMaintenancePlan/v1"
ENVELOPE_SCHEMA = "catchplate.policyAuthorityChallengeMaintenancePlanEnvelope/v1"
SIGNATURE_DOMAIN = "catchplate.policyAuthorityChallengeMaintenancePlanSignature/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityChallengeMaintenancePlanIdentity/v1"
MANIFEST_DOMAIN = "catchplate.policyAuthorityChallengeMaintenanceManifestIdentity/v1"
REQUEST_DOMAIN = "catchplate.policyAuthorityChallengeMaintenanceRequestIdentity/v1"
MAX_PARENT_BYTES = 32 * 1024
MAX_PARENT_NODES = 2048
MAX_PARENT_DEPTH = 12
EXPECTATION_FIELDS = frozenset({"context", "plannerIdentity", "plannerSpkiDigest", "policy"})
POLICY_FIELDS = frozenset({"nowEpochNs", "deadlineEpochNs", "maximumPlanAgeNs", "maximumClockSkewNs"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "operationId", "requestDigest",
    "configurationDigest", "plannerIdentity", "plannerSpkiDigest", "requestBytesDigest",
    "requestByteCount", "manifestDigest", "manifestByteCount", "decision", "issuedAtEpochNs",
    "expiresAtEpochNs"})
DECISION_FIELDS = frozenset({"replacementOverflow", "pruningPending", "retainedLimit",
    "primaryAfter", "countedAfter"})


class ChallengePlanError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProducedMaintenancePlan:
    envelope_bytes: bytes
    request_bytes: bytes
    manifest_bytes: bytes
    plan_digest: str
    acquisition_metrics: snapshots.AcquisitionMetrics


@dataclass(frozen=True, slots=True)
class VerifiedMaintenancePlan:
    envelope_bytes: bytes
    request_bytes: bytes
    manifest_bytes: bytes
    plan_digest: str
    replay: replay.MaintenanceReplayObservation


def _require(value):
    if not value:
        raise ChallengePlanError("challenge maintenance parent differs from its original bindings")


def _object(value, fields):
    _require(type(value) is dict and len(value) == len(fields)
        and all(type(name) is str for name in value) and set(value) == fields)


def _same(left, right, work):
    # Canonical byte equality, not Python bool/int or numeric aliases.
    left_raw, right_raw = work.wire(left), work.wire(right)
    work.charge(input_bytes=len(left_raw) + len(right_raw))
    _require(left_raw == right_raw)


def _expectations(value, work):
    _require(type(work) is _ValidationWork)
    _object(value, EXPECTATION_FIELDS)
    owned = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work)).visit(value)
    owned["context"] = manifests._context(owned["context"], work)
    evidence._identity(owned["plannerIdentity"])
    evidence.plan.contract._digest(owned["plannerSpkiDigest"])
    policy = owned["policy"]
    _object(policy, POLICY_FIELDS)
    shape = evidence.plan.contract
    shape._integer(policy["nowEpochNs"], minimum=1)
    shape._integer(policy["deadlineEpochNs"], minimum=1)
    shape._integer(policy["maximumPlanAgeNs"], evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(policy["maximumClockSkewNs"], evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    _require(policy["nowEpochNs"] < policy["deadlineEpochNs"])
    return owned


def _request(raw, context, work):
    request = requests.capture_request(raw, work=work)
    subject = requests.context_subject(request, work=work)
    _same(subject, {name: context[name] for name in subject}, work)
    return request


def _decision(value, work):
    _require(type(value) is chains.MaintenanceDecision)
    return {"replacementOverflow": value.replacement_overflow,
        "pruningPending": value.pruning_pending, "retainedLimit": value.retained_limit,
        "primaryAfter": value.primary_after.json_projection(),
        "countedAfter": [maintenance.head_wire(head) for head in value.counted_after]}


def _payload_shape(value):
    _object(value, PAYLOAD_FIELDS)
    _require(value["schema"] == SCHEMA and value["sourceRevision"] == evidence.authority.SOURCE_REVISION
        and type(value["operation"]) is str
        and value["operation"] in ("webauthn.challenge.create", "webauthn.challenge.maintain"))
    shape = evidence.plan.contract
    for name in ("operationId", "requestDigest", "configurationDigest", "plannerSpkiDigest",
                 "requestBytesDigest", "manifestDigest"):
        shape._digest(value[name])
    evidence._identity(value["plannerIdentity"])
    shape._integer(value["requestByteCount"], evidence.authority.MAX_REQUEST_BYTES, minimum=2)
    shape._integer(value["manifestByteCount"], manifests.MAX_MANIFEST_BYTES, minimum=2)
    shape._integer(value["issuedAtEpochNs"], minimum=1)
    shape._integer(value["expiresAtEpochNs"], minimum=1)
    decision = value["decision"]
    _object(decision, DECISION_FIELDS)
    _require(type(decision["replacementOverflow"]) is bool and type(decision["pruningPending"]) is bool)
    shape._integer(decision["retainedLimit"], 1_000_000)
    _require(type(decision["primaryAfter"]) is dict and type(decision["countedAfter"]) is list
        and len(decision["countedAfter"]) == len(manifests.WRITE_IDS))
    # The independent real replay below, not this bounded shape, establishes
    # every field of these root observations and their exact sorted roster.


def _fresh(payload, expected, now):
    policy = expected["policy"]
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    maximum, skew = policy["maximumPlanAgeNs"], policy["maximumClockSkewNs"]
    cutoff = expected["context"]["cutoffUs"] * 1000
    _require(type(now) is int and 0 < issued < expires
        and expires - issued <= maximum and abs(issued - policy["nowEpochNs"]) <= skew
        and issued <= now + skew and now - issued <= maximum
        and now < expires <= policy["deadlineEpochNs"]
        and abs(cutoff - issued) <= skew and cutoff < expires)


def _bind(payload, expected, request_raw, manifest_raw, work):
    _payload_shape(payload)
    context = expected["context"]
    for name in ("operation", "operationId", "requestDigest", "configurationDigest"):
        _same(payload[name], context[name], work)
    for name in ("plannerIdentity", "plannerSpkiDigest"):
        _same(payload[name], expected[name], work)
    _fresh(payload, expected, expected["policy"]["nowEpochNs"])
    for raw, maximum, domain, digest_name, count_name in (
        (request_raw, evidence.authority.MAX_REQUEST_BYTES, REQUEST_DOMAIN, "requestBytesDigest", "requestByteCount"),
        (manifest_raw, manifests.MAX_MANIFEST_BYTES, MANIFEST_DOMAIN, "manifestDigest", "manifestByteCount")):
        _require(type(raw) is bytes and 2 <= len(raw) <= maximum)
        _same(payload[count_name], len(raw), work)
        _same(payload[digest_name], evidence.plan._frame(domain, (raw,), work), work)


def _manifest(raw, context, work):
    value = evidence.wire._decode_object(raw, work=work, maximum_bytes=manifests.MAX_MANIFEST_BYTES)
    actual = work.wire(value)
    work.charge(input_bytes=len(actual) + len(raw))
    _require(actual == raw)
    value = manifests._validate(value, work)
    _same(value["context"], context, work)
    return value


def _sign(payload, private, public, work):
    """Existing measured callback/signature mechanics; no new key contract."""
    ledger = evidence.capture._SharedLedger(work)
    payload_bytes = evidence.capability._wire(payload, ledger, MAX_PARENT_BYTES, MAX_PARENT_NODES)
    message = evidence.plan._ascii(evidence.plan._frame(SIGNATURE_DOMAIN, (payload_bytes,), work), work)
    placeholder = {"schema": ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(placeholder)
    payload_size, payload_nodes = work.measure(payload)
    _require(size <= MAX_PARENT_BYTES and nodes <= MAX_PARENT_NODES)
    work.charge(input_bytes=3 * payload_size + size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=payload_nodes + nodes)
    _require(work.limits.max_input_bytes - work.input_bytes >= payload_size
        and work.limits.max_json_nodes - work.json_nodes >= payload_nodes)
    signature = evidence.production._sign_and_verify(private, public, message, work)
    _require(work.measure(payload) == (payload_size, payload_nodes)
        and evidence.plan.core.canonical_bytes(payload) == payload_bytes)
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({"schema": ENVELOPE_SCHEMA,
        "payload": payload, "signatureBase64Url": encoded})
    _require(len(result) == size)
    return result


def produce_maintenance_parent(*, acquisition, request_bytes, expectations,
        planner_private_key, planner_public_key, live_window, retain_page, work):
    """Sign first-pass computation, release only after exact second retention.

    retain_page receives (parent_digest, manifest_digest, context, phase, kind,
    index, ordinal, raw_bytes, descriptor, stage). Context is a detached copy of
    this actual snapshot's anchors, including its database cutoff. It must retain these exact originals
    under the caller's original writer custody, returning None. The actual
    snapshot owner checks its complete transcript and SQL snapshot independently.
    """
    _require(type(acquisition) is snapshots.MaintenanceAcquisition and callable(retain_page)
        and isinstance(planner_private_key, Ed25519PrivateKey)
        and isinstance(planner_public_key, Ed25519PublicKey))
    expected = _expectations(expectations, work)
    _request(request_bytes, expected["context"], work)
    _same(acquisition._context, expected["context"], work)
    window = clock._validate(live_window)
    policy = expected["policy"]
    _require(window[0] == policy["nowEpochNs"] and window[3] <= policy["deadlineEpochNs"]
        and window[5:] == (policy["maximumPlanAgeNs"], policy["maximumClockSkewNs"])
        and acquisition._deadline == expected["context"]["originalDeadlineNs"]
        and acquisition._deadline <= window[4])
    evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
    evidence.keys._pair_on_work(planner_private_key, planner_public_key, work)
    clock._check_on_work(window, work=work)
    try:
        # Child passes own their fixed setup/stage ledgers. External custody
        # callbacks may spend those allowances, never replace or reset this
        # parent's signing/request allowance while it is suspended.
        observed = evidence.production._callback(work,
            lambda: snapshots.MaintenanceAcquisition.produce(acquisition))
        manifest_raw = work.wire(observed.manifest)
        _require(len(manifest_raw) <= manifests.MAX_MANIFEST_BYTES)
        _manifest(manifest_raw, expected["context"], work)
        context = expected["context"]
        payload = {"schema": SCHEMA, "sourceRevision": evidence.authority.SOURCE_REVISION,
            **{name: context[name] for name in ("operation", "operationId", "requestDigest", "configurationDigest")},
            "plannerIdentity": expected["plannerIdentity"], "plannerSpkiDigest": expected["plannerSpkiDigest"],
            "requestBytesDigest": evidence.plan._frame(REQUEST_DOMAIN, (request_bytes,), work),
            "requestByteCount": len(request_bytes),
            "manifestDigest": evidence.plan._frame(MANIFEST_DOMAIN, (manifest_raw,), work),
            "manifestByteCount": len(manifest_raw), "decision": _decision(observed.decision, work),
            "issuedAtEpochNs": window[0], "expiresAtEpochNs": window[3]}
        _bind(payload, expected, request_bytes, manifest_raw, work)
        _fresh(payload, expected, clock._check_on_work(window, work=work))
        envelope = _sign(payload, planner_private_key, planner_public_key, work)
        digest = evidence.plan._frame(IDENTITY_DOMAIN, (envelope,), work)

        def retain(phase, kind, index_id, ordinal, raw, descriptor, stage):
            # The database cutoff is selected inside the real read transaction,
            # not known to an outer custody caller. Own its small context on the
            # original physical stage; never expose this parent's mutable graph.
            owned_context = manifests._context(context, stage.work)
            original_context = stage.work.wire(owned_context)
            result = retain_page(digest, payload["manifestDigest"], owned_context,
                phase, kind, index_id, ordinal, raw, descriptor, stage)
            _require(result is None)
            after_context = stage.work.wire(owned_context)
            stage.work.charge(input_bytes=len(original_context) + len(after_context))
            _require(after_context == original_context)

        repeated, metrics = evidence.production._callback(work,
            lambda: snapshots.MaintenanceAcquisition.retain(acquisition, retain))
        manifests.compare_manifest(expected=observed.manifest, actual=repeated.manifest, work=work)
        _same(payload["decision"], _decision(repeated.decision, work), work)
        _fresh(payload, expected, clock._check_on_work(window, work=work))
        return ProducedMaintenancePlan(envelope, request_bytes, manifest_raw, digest, metrics)
    except BaseException:
        snapshots.MaintenanceAcquisition.close(acquisition)
        raise


def verify_maintenance_parent(*, envelope_bytes, request_bytes, manifest_bytes,
        expectations, planner_public_key, read_original, check, work, apply_mutation=None,
        observe_effect=None):
    """Authenticate detached originals and independently replay the whole chain.

    read_original receives (parent_digest, manifest_digest, phase, kind, index,
    ordinal, stage). Its returned raw bytes carry no proof verdict. Tentative
    SQL callbacks require an outer rollback on *any* failure, including a final
    signed-decision mismatch. No commit or current-root admission occurs here.
    """
    _require(isinstance(planner_public_key, Ed25519PublicKey) and callable(read_original)
        and callable(check) and (apply_mutation is None or callable(apply_mutation))
        and (observe_effect is None or callable(observe_effect)))
    expected = _expectations(expectations, work)
    ledger = evidence.capture._SharedLedger(work)
    envelope = evidence.wire._decode_object(envelope_bytes, work=work,
        maximum_bytes=MAX_PARENT_BYTES, maximum_nodes=MAX_PARENT_NODES, maximum_depth=MAX_PARENT_DEPTH)
    _object(envelope, frozenset({"schema", "payload", "signatureBase64Url"}))
    _require(envelope["schema"] == ENVELOPE_SCHEMA)
    payload = envelope["payload"]
    _bind(payload, expected, request_bytes, manifest_bytes, work)
    evidence.capability._canonical(envelope_bytes, envelope, ledger, MAX_PARENT_BYTES, MAX_PARENT_NODES)
    payload_bytes = evidence.capability._wire(payload, ledger, MAX_PARENT_BYTES, MAX_PARENT_NODES)
    evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
    evidence.capability._signature(planner_public_key, envelope["signatureBase64Url"],
        SIGNATURE_DOMAIN, payload_bytes, ledger)
    _request(request_bytes, expected["context"], work)
    manifest = _manifest(manifest_bytes, expected["context"], work)
    digest = evidence.plan._frame(IDENTITY_DOMAIN, (envelope_bytes,), work)

    def read(phase, kind, index_id, ordinal, stage):
        return read_original(digest, payload["manifestDigest"], phase, kind, index_id, ordinal, stage)

    observed = evidence.production._callback(work,
        lambda: replay.replay_maintenance(context=expected["context"], expected_manifest=manifest,
            read_original=read, check=check, apply_mutation=apply_mutation,
            observe_effect=observe_effect))
    _same(payload["decision"], _decision(observed.observation.decision, work), work)
    return VerifiedMaintenancePlan(envelope_bytes, request_bytes, manifest_bytes, digest, observed)

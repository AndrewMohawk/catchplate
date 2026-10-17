"""Detached verifier-authenticated planning inputs, not a planning verdict.

The configured service supplies measured keys, scope and real current clocks.
The verifier must independently admit the request/reservation and acquire the
full root inventory before signing. This pure component does not establish
that provenance, authorize a reservation, open a database or call a planner.
Original response plan/context still require genuine verifier-side replay
against the retained independent inputs, never response-supplied expectations.

The existing internal/v3 signature framing is retained with a distinct purpose
and closed payload. Four canonical bodies remain detached; all work uses the
caller's allowance. Source local maxima do not promise cumulative admission.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import authority_contract as authority
from catchplate import authority_revocation_planning as planning
from catchplate import authority_revocation_writer_commitment as commitment


plan, capture, wire = commitment.plan, commitment.capture, commitment.wire
capability, production, observed = commitment.capability, commitment.production, planning.observed
ENVELOPE_SCHEMA = authority.INTERNAL_ENVELOPE_SCHEMA
REQUEST_SCHEMA = "catchplate.policyAuthorityRevocationPlanningRequest/v1"
REQUEST_PURPOSE = "produce-revocation-observed-plan"
REQUEST_ID_DOMAIN = "catchplate.policyAuthorityRevocationPlanningRequestEnvelope/v1"
MAX_CONTROL_BYTES = authority.MAX_REQUEST_BYTES
MAX_CONTROL_NODES = 4096
MAX_CONTROL_DEPTH = 2
MAX_BODY_BYTES = plan.contract.MAX_PAYLOAD_BYTES
MAX_SMALL_BYTES = 512 * 1024
MAX_REQUEST_BYTES = capture.MAX_TOTAL_INPUT_BYTES
BODY_BOUNDS = ((MAX_BODY_BYTES, plan.contract.MAX_JSON_NODES, plan.contract.MAX_JSON_DEPTH),
    (MAX_BODY_BYTES, plan.contract.MAX_JSON_NODES, plan.contract.MAX_JSON_DEPTH),
    (MAX_SMALL_BYTES, 4096, 8), (MAX_SMALL_BYTES, 4096, 8))
BODY_PREFIXES = ("requestBody", "evidenceBody", "contextBody", "rootInventoryBody")
ENVELOPE_FIELDS = commitment.ENVELOPE_FIELDS
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "generationSequence", "generationDigest",
    "capabilityId", "plannerTransactionId", "operationId", "requestDigest", "deadlineEpochNs",
    *(name + suffix for name in BODY_PREFIXES for suffix in ("Digest", "ByteCount"))})


class RevocationPlanningRequestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _AuthenticatedPlanningRequest:
    """Owned authenticated claims; never accepted as a successful plan token."""

    request: dict
    evidence: dict
    context: dict
    root_inventory: observed.roots._RootInventory


def _validate_lengths(lengths):
    if type(lengths) is not tuple or len(lengths) != 5:
        raise RevocationPlanningRequestError("planning request requires exactly five original bodies")
    for size, maximum in zip(lengths, (MAX_CONTROL_BYTES, *(bound[0] for bound in BODY_BOUNDS))):
        if type(size) is not int or not 2 <= size <= maximum:
            raise RevocationPlanningRequestError("planning request body length exceeds its source bound")
    if sum(lengths) > MAX_REQUEST_BYTES:
        raise RevocationPlanningRequestError("planning request exceeds its aggregate source bound")


def _context(context):
    plan.contract._object(context, planning._CALL_CONTEXT, "planning request context")
    for name in ("expectedCapabilityId", "expectedPlannerTransactionId"):
        plan.contract._digest(context[name])
    if context["expectedApproverPolicyDigest"] is not None:
        plan.contract._digest(context["expectedApproverPolicyDigest"])
    for name in ("expectedFence", "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs",
                 "nowEpochNs", "nowMonotonicNs"):
        plan.contract._integer(context[name], minimum=1)


def _capture_call_graphs(*, request, evidence, context, work):
    """Own service inputs before root acquisition, without dummy observations."""
    try:
        capture._SharedLedger(work)
        if type(request) is not dict or type(evidence) is not dict:
            raise RevocationPlanningRequestError("planning request and evidence require exact objects")
        plan.contract._object(context, planning._CALL_CONTEXT, "planning request context")
        owned = planning.authority_query_reads._CopyBudget(work).copy(
            {"request": request, "evidence": evidence, "context": context})
        plan.contract._request(owned["request"])
        _context(owned["context"])
        return owned
    except commitment._FAILURES as exc:
        if isinstance(exc, RevocationPlanningRequestError):
            raise
        raise RevocationPlanningRequestError("planning invocation capture failed") from exc


def _require_enabled_operation(role, work):
    """Preserve the measured planner allowlist at the fixed raw ingress."""
    try:
        capture._SharedLedger(work)
        if type(role) is not dict:
            raise RevocationPlanningRequestError("planning operation policy is not an exact role")
        enabled = role["enabledOperations"]
        if type(enabled) is not list or len(enabled) > len(authority.OPERATION_REGISTRY):
            raise RevocationPlanningRequestError("planning enabled operations are not a bounded exact list")
        work.prepare_scan(enabled)
        previous, present = None, False
        for operation in enabled:
            if type(operation) is not str or operation not in authority.OPERATION_REGISTRY:
                raise RevocationPlanningRequestError("planning enabled operation is not a known exact string")
            if previous is not None and previous >= operation:
                raise RevocationPlanningRequestError("planning enabled operations are not sorted and unique")
            if operation == plan.contract.OPERATION:
                present = True
            previous = operation
        if not present:
            raise RevocationPlanningRequestError("revocation planning is disabled by measured configuration")
    except commitment._FAILURES as exc:
        if isinstance(exc, RevocationPlanningRequestError):
            raise
        raise RevocationPlanningRequestError("planning enabled-operation policy failed") from exc


def _require_current_context(context, *, now_epoch_ns, now_monotonic_ns,
        maximum_age_ns, maximum_clock_skew_ns):
    """Check current samples against original historical clocks, never retime.

    Callers own and retain the exact context before callbacks. All fields here
    are fixed source-bounded scalars; this helper neither samples a clock nor
    establishes the request's authorization or current-root provenance.
    """
    try:
        _context(context)
        commitment._current(now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
        commitment._fresh({"issuedAtEpochNs": context["nowEpochNs"],
            "issuedMonotonicNs": context["nowMonotonicNs"],
            "deadlineMonotonicNs": context["deadlineMonotonicNs"]},
            {"deadline_epoch_ns": context["deadlineEpochNs"]}, now_epoch_ns, now_monotonic_ns,
            maximum_age_ns, maximum_clock_skew_ns)
    except commitment._FAILURES as exc:
        if isinstance(exc, RevocationPlanningRequestError):
            raise
        raise RevocationPlanningRequestError("planning historical context is not currently fresh") from exc


def _inventory_from_graph(value):
    """Restore only the exact source scalar graph, not reader provenance."""
    plan.contract._object(value, {"businessRoots", "authorizationRoots", "countedHeads"}, "planning inventory")
    vectors = []
    for name, names in (("businessRoots", observed.roots._BUSINESS_TABLES),
                        ("authorizationRoots", observed.roots._AUTHORIZATION_TABLES)):
        rows = value[name]
        if type(rows) is not list or len(rows) != len(names):
            raise RevocationPlanningRequestError("planning inventory primary vector is not complete")
        result = []
        for row in rows:
            plan.contract._object(row, set(observed.roots._PRIMARY_FIELDS), "planning primary root")
            result.append(observed.roots._PrimaryObservation(*(row[field] for field in observed.roots._PRIMARY_FIELDS)))
        vectors.append(tuple(result))
    rows = value["countedHeads"]
    if type(rows) is not list or len(rows) != len(observed.roots._HEAD_IDS):
        raise RevocationPlanningRequestError("planning inventory counted vector is not complete")
    heads = []
    for row in rows:
        plan.contract._object(row, set(observed._HEAD_FIELDS), "planning counted head")
        heads.append(observed.heads.CapturedIndexHead(row["index_id"], row["table_name"], row["counted_profile"],
            row["projection_digest"], row["projection_manifest_digest"], row["index_revision"],
            observed.counted.CountedNode(row["root_digest"], row["leaf_count"])))
    inventory = observed.roots._RootInventory(vectors[0], vectors[1], tuple(heads))
    observed._validate_inventory(inventory)
    return inventory


def _identity(planner_id, request_digest, work):
    return plan._frame(REQUEST_ID_DOMAIN,
        (plan._ascii(planner_id, work), plan._ascii(request_digest, work)), work)


def _shape(envelope, *, signed):
    plan.contract._object(envelope, ENVELOPE_FIELDS if signed else ENVELOPE_FIELDS - {"signature"},
        "planning request control")
    plan.contract._literal(envelope["schema"], ENVELOPE_SCHEMA)
    plan.contract._literal(envelope["purpose"], REQUEST_PURPOSE)
    for name in ("envelopeId", "parentEnvelopeId", "configurationDigest"):
        plan.contract._digest(envelope[name])
    for name in ("issuedAtEpochNs", "issuedMonotonicNs", "deadlineMonotonicNs", "fence"):
        plan.contract._integer(envelope[name], minimum=1)
    if envelope["issuedMonotonicNs"] >= envelope["deadlineMonotonicNs"]:
        raise RevocationPlanningRequestError("planning request issuance does not precede its deadline")
    if signed:
        plan.contract._base64url(envelope["signature"], signature=True)
    payload = envelope["payload"]
    plan.contract._object(payload, PAYLOAD_FIELDS, "planning request payload")
    plan.contract._literal(payload["schema"], REQUEST_SCHEMA)
    plan.contract._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    for name in ("generationSequence", "deadlineEpochNs"):
        plan.contract._integer(payload[name], minimum=1)
    for name in ("generationDigest", "capabilityId", "plannerTransactionId", "operationId", "requestDigest"):
        plan.contract._digest(payload[name])
    for prefix, bound in zip(BODY_PREFIXES, BODY_BOUNDS):
        plan.contract._digest(payload[prefix + "Digest"])
        plan.contract._integer(payload[prefix + "ByteCount"], bound[0], minimum=2)


def _sign_wire(unsigned, bodies, private_key, verifier_key, planner_key, work):
    """Measure the complete output before pairing/signing; recheck afterward."""
    _shape(unsigned, signed=False)
    unsigned_size, unsigned_nodes = work.measure(unsigned)
    # A fixed signature-width size model is not a signature or admission.
    envelope_size, envelope_nodes = work.measure({**unsigned, "signature": "A" * 86})
    _validate_lengths((envelope_size, *(len(raw) for raw in bodies)))
    if max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES:
        raise RevocationPlanningRequestError("planning control exceeds its source node bound")
    production._key_binding(private_key, verifier_key, planner_key, work)
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(ENVELOPE_SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise commitment.QueryReadWorkError("planning control cannot reserve its complete signed output")
    original = plan.core.canonical_bytes(unsigned)
    if len(original) != unsigned_size:
        raise RevocationPlanningRequestError("planning unsigned graph changed after measurement")
    message = plan._ascii(plan._frame(ENVELOPE_SCHEMA, (original,), work), work)
    signature = production._sign_and_verify(private_key, verifier_key, message, work)
    if (work.measure(unsigned) != (unsigned_size, unsigned_nodes)
            or plan.core.canonical_bytes(unsigned) != original):
        raise RevocationPlanningRequestError("planning unsigned graph changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    envelope = {**unsigned, "signature": encoded}
    _shape(envelope, signed=True)
    raw = plan.core.canonical_bytes(envelope)
    if len(raw) != envelope_size:
        raise RevocationPlanningRequestError("planning signed graph changed after measurement")
    return raw


def _produce_request_on_work(*, request, evidence, context, root_inventory,
        verifier_private_key, verifier_public_key, planner_public_key, configuration_digest,
        generation_sequence, generation_digest, issued_at_epoch_ns, issued_monotonic_ns, work):
    """Own and sign four originals; no planner success or provenance is accepted."""
    try:
        ledger = capture._SharedLedger(work)
        commitment._public_keys(planner_public_key, verifier_public_key)
        if not isinstance(verifier_private_key, Ed25519PrivateKey):
            raise RevocationPlanningRequestError("planning request requires an Ed25519 verifier signer")
        commitment._pins(configuration_digest, generation_sequence, generation_digest)
        plan.contract._request(request)
        if type(evidence) is not dict:
            raise RevocationPlanningRequestError("planning evidence is not an exact object")
        _context(context)
        observed._validate_inventory(root_inventory)
        for value in (issued_at_epoch_ns, issued_monotonic_ns):
            plan.contract._integer(value, minimum=1)
        # Real finite measurement rejects aggregate body excess before copies
        # or encoding. The final control size is checked before key callbacks.
        graphs = (request, evidence, context, observed._inventory_graph(root_inventory))
        measured = tuple(work.measure(value) for value in graphs)
        _validate_lengths((2, *(size for size, _ in measured)))
        for (_, nodes), bound in zip(measured, BODY_BOUNDS):
            if nodes > bound[1]:
                raise RevocationPlanningRequestError("planning body exceeds its source node bound")
        owned, inventory = planning._capture_planning_call_inputs(request=request, evidence=evidence,
            context=context, root_inventory=root_inventory, work=work)
        request, context = owned["request"], owned["context"]
        graphs = (request, owned["evidence"], context, observed._inventory_graph(inventory))
        bodies = tuple(capability._wire(value, ledger, bound[0], bound[1])
            for value, bound in zip(graphs, BODY_BOUNDS))
        payload = {"schema": REQUEST_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "generationSequence": generation_sequence, "generationDigest": generation_digest,
            "capabilityId": context["expectedCapabilityId"],
            "plannerTransactionId": context["expectedPlannerTransactionId"],
            "operationId": request["operationId"], "requestDigest": request["requestDigest"],
            "deadlineEpochNs": context["deadlineEpochNs"]}
        for prefix, raw in zip(BODY_PREFIXES, bodies):
            payload[prefix + "Digest"] = commitment.retention._bytes_digest(raw, work)
            payload[prefix + "ByteCount"] = len(raw)
        unsigned = {"schema": ENVELOPE_SCHEMA,
            "envelopeId": _identity(context["expectedPlannerTransactionId"], request["requestDigest"], work),
            "parentEnvelopeId": context["expectedPlannerTransactionId"], "purpose": REQUEST_PURPOSE,
            "configurationDigest": configuration_digest, "issuedAtEpochNs": issued_at_epoch_ns,
            "issuedMonotonicNs": issued_monotonic_ns, "deadlineMonotonicNs": context["deadlineMonotonicNs"],
            "fence": context["expectedFence"], "payload": payload}
        control = _sign_wire(unsigned, bodies, verifier_private_key, verifier_public_key, planner_public_key, work)
        return (control, *bodies)
    except commitment._FAILURES as exc:
        if isinstance(exc, RevocationPlanningRequestError):
            raise
        raise RevocationPlanningRequestError("planning request production failed") from exc


def _verify_request_on_work(*, control_bytes, request_bytes, evidence_bytes, context_bytes,
        root_inventory_bytes, verifier_public_key, planner_public_key,
        expected_configuration_digest, expected_generation_sequence, expected_generation_digest,
        now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns, work):
    """Authenticate control before decoding bodies, then own the bound inputs."""
    try:
        ledger = capture._SharedLedger(work)
        originals = (control_bytes, request_bytes, evidence_bytes, context_bytes, root_inventory_bytes)
        if any(type(raw) is not bytes for raw in originals):
            raise RevocationPlanningRequestError("planning request requires exact original bytes")
        _validate_lengths(tuple(map(len, originals)))
        commitment._public_keys(planner_public_key, verifier_public_key)
        commitment._pins(expected_configuration_digest, expected_generation_sequence, expected_generation_digest)
        commitment._current(now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
        envelope = wire._decode_object(control_bytes, work=work, maximum_bytes=MAX_CONTROL_BYTES,
            maximum_nodes=MAX_CONTROL_NODES, maximum_depth=MAX_CONTROL_DEPTH)
        _shape(envelope, signed=True)
        capability._canonical(control_bytes, envelope, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
        work.prepare_copy(envelope)
        unsigned = envelope.copy()
        signature = unsigned.pop("signature")
        unsigned_wire = capability._wire(unsigned, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
        commitment._distinct_public_keys(planner_public_key, verifier_public_key, work)
        capability._signature(verifier_public_key, signature, ENVELOPE_SCHEMA, unsigned_wire, ledger)
        capability._canonical(unsigned_wire, unsigned, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
        payload = unsigned["payload"]
        plan._same((unsigned["configurationDigest"], payload["generationSequence"], payload["generationDigest"]),
            (expected_configuration_digest, expected_generation_sequence, expected_generation_digest), work,
            "planning request differs from independent configuration or generation")
        graphs = []
        for prefix, raw, bound in zip(BODY_PREFIXES, originals[1:], BODY_BOUNDS):
            plan._same((commitment.retention._bytes_digest(raw, work), len(raw)),
                (payload[prefix + "Digest"], payload[prefix + "ByteCount"]), work,
                "planning request original body differs from signed commitment")
            graph = wire._decode_object(raw, work=work, maximum_bytes=bound[0],
                maximum_nodes=bound[1], maximum_depth=bound[2])
            capability._canonical(raw, graph, ledger, bound[0], bound[1])
            graphs.append(graph)
        request, evidence, context, inventory_graph = graphs
        plan.contract._request(request)
        _context(context)
        inventory = _inventory_from_graph(inventory_graph)
        owned, inventory = planning._capture_planning_call_inputs(request=request, evidence=evidence,
            context=context, root_inventory=inventory, work=work)
        request, context = owned["request"], owned["context"]
        expected_id = _identity(context["expectedPlannerTransactionId"], request["requestDigest"], work)
        plan._same((unsigned["envelopeId"], unsigned["parentEnvelopeId"], unsigned["fence"],
            unsigned["deadlineMonotonicNs"], payload["capabilityId"], payload["plannerTransactionId"],
            payload["operationId"], payload["requestDigest"], payload["deadlineEpochNs"]),
            (expected_id, context["expectedPlannerTransactionId"], context["expectedFence"],
            context["deadlineMonotonicNs"], context["expectedCapabilityId"], context["expectedPlannerTransactionId"],
            request["operationId"], request["requestDigest"], context["deadlineEpochNs"]), work,
            "planning request scope differs from its authenticated original inputs")
        commitment._fresh(unsigned, {"deadline_epoch_ns": context["deadlineEpochNs"]},
            now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
        return _AuthenticatedPlanningRequest(request, owned["evidence"], context, inventory)
    except commitment._FAILURES as exc:
        if isinstance(exc, RevocationPlanningRequestError):
            raise
        raise RevocationPlanningRequestError("planning request authentication failed") from exc

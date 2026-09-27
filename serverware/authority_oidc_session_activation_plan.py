"""Private active-plan signing with genuine original replay and no token export.

The caller retains all original inputs and independently admits request, root,
policy, subject, key and time provenance. Only a bounded signed commitment
envelope leaves the producer. Verification requires those original inputs
again and returns the actual recomputed transition, never an execution grant.
Indexed after-roots and all thirteen after-heads are genuinely replayed and
committed, not accepted from a result carrier. The enrolled state observation
and its exact nonce/context-bound query are reverified and committed as well.
No SQL, action-time authority, historical replay or public activation occurs.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import time

from serverware import authority_oidc_session_activation_plan_contract as contract
from serverware import authority_oidc_session_activation_reads as reads
from serverware import authority_oidc_session_activation_state as state
from serverware import authority_oidc_session_activation_writes as writes
from serverware import authority_request_commitment as commitment
from serverware import authority_transition_oidc_session_activation as transition


assertion, registration, core = transition.assertion, transition.registration, transition.core
evidence, clock = registration.evidence, assertion.clock
_SCOPE_FIELDS = state.SCOPE_FIELDS


class OidcSessionActivationPlanError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Invocation:
    request: dict
    scope: dict
    context: core.KernelContext
    originals: tuple
    raw_reads: dict
    read_heads: tuple
    query_frontiers: tuple
    expected_counted_heads: tuple
    write_proof_bytes: bytes
    state_originals: tuple
    state_expires_at_epoch_ns: int
    window: tuple
    monotonic_deadline: int


def _fail(message):
    raise OidcSessionActivationPlanError(message)


def _capture(context, *, request, scope, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, expected_counted_heads, write_proof_bytes,
        state_enrollment_bytes, state_root_public_key, complete_root_vector_bytes,
        head_query_bytes, head_observation_bytes,
        live_window, transport_deadline_ns, work):
    """Own every caller graph before clock, hash, signature or crypto callbacks."""
    ledger = evidence.capture._SharedLedger(work)
    if (type(context) is not core.KernelContext or context.operation != contract.OPERATION
            or context.verified_webauthn_evidence is not None
            or type(context.database_now) is not datetime or context.database_now.tzinfo is not timezone.utc):
        _fail("activation plan requires its exact original UTC context")
    database_now = context.database_now
    if (type(assertion_bytes) is not bytes or not 2 <= len(assertion_bytes) <= assertion.MAX_ASSERTION_BYTES
            or type(delivery_envelope_bytes) is not bytes
            or len(delivery_envelope_bytes) != transition.delivery.ENVELOPE_BYTES
            or type(delivery_custody_key) is not bytes or len(delivery_custody_key) != 32
            or type(write_proof_bytes) is not bytes
            or not 2 <= len(write_proof_bytes) <= writes.MAX_WRITE_PROOF_BYTES
            or type(expected_counted_heads) is not tuple
            or len(expected_counted_heads) != writes.HEAD_COUNT):
        _fail("activation plan originals are outside their exact bounds")
    originals = (assertion_bytes, assertion._token(old_token_bytes, work),
        assertion._token(new_token_bytes, work), delivery_envelope_bytes, delivery_custody_key)
    state_originals = (
        state._original(state_enrollment_bytes, state.head.authorization.MAX_ENROLLMENT_BYTES, "enrollment"),
        state._original(complete_root_vector_bytes, state.vector.MAX_BYTES, "complete vector"),
        state._original(head_query_bytes, state.head.MAX_QUERY_BYTES, "query"),
        state._original(head_observation_bytes, state.head.MAX_BYTES, "observation"))
    root_key = state_root_public_key
    state.head.authorization._public(root_key)
    window = clock._validate(live_window)
    bound = window[4]
    if transport_deadline_ns is not None:
        registration._integer(transport_deadline_ns, "activation plan inherited deadline", 1)
        bound = min(bound, transport_deadline_ns)
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "request": request, "scope": scope, "countedBeforeHeads": list(expected_counted_heads)})
    raw, records, heads, frontiers = reads._capture(arguments=context.arguments,
        request_digest=context.request_digest, selected_rows=context.selected_rows,
        query_reads=context.query_reads, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, work=work)
    # Validate the independent fixed thirteen-head inventory only after all
    # mutable inputs above are detached. It is never learned from write bytes.
    writes._heads(owned["countedBeforeHeads"])
    expected = owned["scope"]
    registration._closed(expected, _SCOPE_FIELDS, "independent activation plan scope")
    for field in ("configurationDigest", "plannerSpkiDigest"):
        registration._digest(expected[field])
    evidence._identity(expected["plannerIdentity"])
    registration._integer(expected["maximumPlanAgeNs"], "activation plan age", 1,
        contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._integer(expected["maximumClockSkewNs"], "activation plan skew", 0,
        contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    registration._integer(expected["deadlineEpochNs"], "activation plan original deadline", 1)
    if (window[5] != expected["maximumPlanAgeNs"] or window[6] != expected["maximumClockSkewNs"]
            or window[3] > expected["deadlineEpochNs"]):
        _fail("activation plan window differs from independent policy")
    actual = owned["request"]
    if type(actual) is not dict or actual.get("operation") != contract.OPERATION:
        _fail("activation plan request has the wrong operation")
    # All original graphs are owned above. Actual commitment work starts here.
    digest = commitment._typed_request_digest(actual, work=work)
    registration._same((digest, actual["arguments"]),
        (raw["request_digest"], raw["arguments"]), work, "activation request/context join")
    registration._same(actual["requestDigest"], digest, work, "activation request digest")
    operation_id = evidence.plan._frame("serverware.policyAuthorityOperation/v2",
        (evidence.plan._ascii(contract.OPERATION, work), evidence.plan._ascii(digest, work)), work)
    registration._same(actual["operationId"], operation_id, work, "activation operation identity")
    transition._arguments(raw["arguments"], work)
    for name, maximum in (("userId", 1024), ("sessionId", 128), ("credentialId", 1366),
            ("credentialRecordId", 1024), ("challengeId", 1024), ("rpId", 4096), ("origin", 8192)):
        registration._text(expected[name], name, maximum, work)
    held = core.KernelContext(contract.OPERATION, raw["arguments"], raw["selected_rows"],
        database_now, digest, query_reads=records)
    observed = state._verify_on_work(scope=expected, assertion_bytes=originals[0],
        old_token_bytes=originals[1], complete_root_vector_bytes=state_originals[1],
        query_bytes=state_originals[2], observation_bytes=state_originals[3],
        enrollment_bytes=state_originals[0], root_public_key=root_key,
        now_epoch_ns=clock._check_on_work(window, work=work), work=work)
    projected = state._project_on_work(vector_bytes=state_originals[1],
        expected_vector_digest=observed["vectorDigest"], work=work)
    for actual_roots, expected_roots, label in (
            (raw["business_before_roots"], projected.business_before_roots, "business roots"),
            (raw["authorization_before_roots"], projected.authorization_before_roots, "authorization roots"),
            (owned["countedBeforeHeads"], projected.expected_counted_heads, "thirteen counted heads")):
        registration._same(tuple(actual_roots), expected_roots, work, "observed activation " + label)
    return _Invocation(actual, expected, held, originals, raw, heads, frontiers,
        tuple(owned["countedBeforeHeads"]), write_proof_bytes, state_originals,
        observed["expiresAtEpochNs"], window, bound)


def _live(invocation, work):
    """A sticky local guard, retaining the original caller window and cap."""
    epoch, monotonic = invocation.window[0], invocation.window[2]

    def check():
        nonlocal epoch, monotonic
        now = clock._check_on_work(invocation.window, work=work)
        observed = evidence.production._callback(work, lambda: time.monotonic_ns())
        registration._integer(observed, "activation plan monotonic sample", 1)
        if (now < epoch or observed < monotonic or observed >= invocation.monotonic_deadline
                or now >= invocation.state_expires_at_epoch_ns):
            _fail("activation plan deadline expired or clock reversed")
        epoch, monotonic = now, observed
        return now

    return check


def _wire(value, work):
    return evidence.capability._wire(value, evidence.capture._SharedLedger(work),
        contract.MAX_ORIGINAL_BYTES, reads.reads.MAX_JSON_NODES)


class _ReadInputsCapture(evidence.capture._JSONCapture):
    """Normalize private tuple arrays under the existing exact JSON budgets."""

    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > reads.reads.MAX_JSON_DEPTH or self.nodes >= reads.reads.MAX_JSON_NODES:
            _fail("activation retained read graph exceeds its structural bound")
        if type(value) is not tuple:
            return super().visit(value, depth, ancestors)
        if id(value) in ancestors:
            _fail("activation retained read graph is cyclic")
        self.ledger.charge(json_nodes=1)
        self.nodes += 1
        maximum_nodes = getattr(self.ledger, "maximum_json_nodes", reads.reads.MAX_JSON_NODES)
        if len(value) > min(reads.reads.MAX_JSON_NODES - self.nodes,
                maximum_nodes - self.ledger.json_nodes):
            _fail("activation retained read array exceeds its node bound")
        self._bytes(2 + max(0, len(value) - 1))
        branch = ancestors | {id(value)}
        result = [] if self.retain else None
        for child in value:
            fresh = self.visit(child, depth + 1, branch)
            if self.retain:
                result.append(fresh)
        return result


def _read_inputs(invocation, work):
    """Exact private read originals, not a replay result or independent authority.

    The storage schema remains the fixed proof domain. Root/head descriptors
    retain their independent provenance only through the real owning caller.
    """
    if type(invocation) is not _Invocation:
        _fail("activation read originals require the actual captured invocation")
    raw, context = invocation.raw_reads, invocation.context
    records = []
    for record in context.query_reads:
        work.charge(input_bytes=len(record.declared_query_json) + len(record.resolved_query_json)
            + sum(len(address.key_json) for address in record.addresses))
        records.append({"queryId": record.query_id,
            "declaredQueryJson": record.declared_query_json.decode("ascii"),
            "resolvedQueryJson": record.resolved_query_json.decode("ascii"),
            "returnedRowCount": record.returned_row_count,
            "addresses": [{"table": address.table, "keyJson": address.key_json.decode("ascii"),
                "keyDigest": address.key_digest, "present": address.present} for address in record.addresses]})
    return _ReadInputsCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=contract.MAX_ORIGINAL_BYTES).visit({
        "schema": contract.PROOF_DOMAIN, "selectedRows": raw["selected_rows"],
        "beforeProofs": raw["before_proofs"], "readHeads": raw["read_heads"],
        "queryFrontiers": raw["query_frontiers"], "queryReads": records,
        "businessBeforeRoots": raw["business_before_roots"],
        "authorizationBeforeRoots": raw["authorization_before_roots"],
        "countedBeforeHeads": list(invocation.expected_counted_heads)})


def _bodies(invocation, work):
    """Private canonical graph commitments, with no secret-token serialization."""
    read_inputs = _read_inputs(invocation, work)
    context, expected = invocation.context, invocation.scope
    proof = {name: read_inputs[name] for name in ("schema", "selectedRows", "beforeProofs",
        "readHeads", "queryFrontiers", "queryReads")}
    # Bound the encoded original before base64 allocation. The later canonical
    # body and combined four-body checks retain the original aggregate ceiling.
    original = invocation.write_proof_bytes
    encoded_size = (4 * len(original) + 2) // 3
    if encoded_size > contract.MAX_ORIGINAL_BYTES:
        _fail("activation encoded write proof exceeds the original body bound")
    work.charge(input_bytes=len(original) + 3 * (encoded_size + 2))
    proof["writeProofBase64Url"] = base64.urlsafe_b64encode(original).decode("ascii").rstrip("=")
    evaluation = {"schema": contract.CONTEXT_DOMAIN, "request": invocation.request,
        "scope": expected, "databaseNow": context.database_now.isoformat(),
        "businessBeforeRoots": read_inputs["businessBeforeRoots"],
        "authorizationBeforeRoots": read_inputs["authorizationBeforeRoots"],
        "countedBeforeHeads": read_inputs["countedBeforeHeads"]}
    # Domain-separated raw commitments are derived here, never accepted as an
    # input in place of the actual original. The key is deliberately omitted.
    inputs = {"schema": contract.INPUTS_DOMAIN}
    for name, original in zip(("assertion", "oldToken", "newToken", "deliveryEnvelope"),
            invocation.originals[:4]):
        inputs[name] = {"digest": evidence.plan._frame(contract.INPUTS_DOMAIN + "/" + name,
            (original,), work), "byteCount": len(original)}
    for name, original in zip(("stateEnrollment", "completeRootVector", "headQuery", "headObservation"),
            invocation.state_originals):
        inputs[name] = {"digest": evidence.plan._frame(contract.INPUTS_DOMAIN + "/" + name,
            (original,), work), "byteCount": len(original)}
    return _wire(proof, work), _wire(evaluation, work), _wire(inputs, work)


def _replay(invocation, work):
    expected, original, raw = invocation.scope, invocation.originals, invocation.raw_reads
    return writes._replay_on_work(invocation.context, assertion_bytes=original[0],
        old_token_bytes=original[1], new_token_bytes=original[2], delivery_envelope_bytes=original[3],
        delivery_custody_key=original[4], expected_user_id=expected["userId"],
        expected_session_id=expected["sessionId"], expected_credential_id=expected["credentialId"],
        expected_credential_record_id=expected["credentialRecordId"], expected_challenge_id=expected["challengeId"],
        rp_id=expected["rpId"], origin=expected["origin"], authn_policy=expected["authenticationPolicy"],
        trust_policy=expected["trustPolicy"], business_before_roots=raw["business_before_roots"],
        authorization_before_roots=raw["authorization_before_roots"], before_proofs=raw["before_proofs"],
        read_heads=invocation.read_heads, query_frontiers=invocation.query_frontiers,
        expected_counted_heads=invocation.expected_counted_heads, write_proof_bytes=invocation.write_proof_bytes,
        live_window=invocation.window, work=work, transport_deadline_ns=invocation.monotonic_deadline)


def _expiry(invocation, work, issued):
    """Bound the plan by the real selected input lifetimes, not a received claim."""
    arguments, context = invocation.request["arguments"], invocation.context
    session = context._exact("oidc_browser_sessions", {"id": arguments["session_id"]}, work=work)["row"]
    challenge = context._exact("webauthn_challenges", {"id": arguments["challenge_id"]}, work=work)["row"]
    limits = [invocation.scope["deadlineEpochNs"], invocation.state_expires_at_epoch_ns,
        issued + invocation.scope["maximumPlanAgeNs"],
        registration._now(context.database_now) + arguments["delivery_ttl_seconds"] * 1_000_000_000]
    for row, fields in ((session, ("expires_at", "pending_expires_at", "provider_expires_at")),
            (challenge, ("expires_at",))):
        for field in fields:
            limits.append(assertion._time(row[field], field, work))
    return min(limits)


def _fresh(payload, invocation, now, work):
    expected = invocation.scope
    evidence._fresh(payload, now, expected["maximumPlanAgeNs"], expected["maximumClockSkewNs"])
    if (payload["expiresAtEpochNs"] > _expiry(invocation, work, payload["issuedAtEpochNs"])
            or now >= expected["deadlineEpochNs"]):
        _fail("activation plan exceeds its independently admitted original lifetimes")


def _fresh_replayed(payload, invocation, actual, live, work):
    """Retain this call's genuine replay guard through final signature work."""
    original_now = actual.live()
    now = live()
    if (now < original_now or now >= actual.valid_until_epoch_ns
            or payload["expiresAtEpochNs"] > actual.valid_until_epoch_ns):
        _fail("activation plan exceeds its genuine original replay lifetime")
    _fresh(payload, invocation, now, work)


def _produce_on_work(context, *, request, scope, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, expected_counted_heads, write_proof_bytes,
        state_enrollment_bytes, state_root_public_key, complete_root_vector_bytes,
        head_query_bytes, head_observation_bytes,
        planner_private_key, planner_public_key,
        live_window, work, transport_deadline_ns=None):
    """Genuinely replay all originals, then return only a signed token-free envelope."""
    if (not isinstance(planner_private_key, evidence.Ed25519PrivateKey)
            or not isinstance(planner_public_key, evidence.keys.Ed25519PublicKey)):
        _fail("activation plan requires actual independently admitted Ed25519 keys")
    invocation = _capture(context, request=request, scope=scope, assertion_bytes=assertion_bytes,
        old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers,
        expected_counted_heads=expected_counted_heads, write_proof_bytes=write_proof_bytes,
        state_enrollment_bytes=state_enrollment_bytes, state_root_public_key=state_root_public_key,
        complete_root_vector_bytes=complete_root_vector_bytes,
        head_query_bytes=head_query_bytes, head_observation_bytes=head_observation_bytes,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    live = _live(invocation, work)
    live()
    proof_bytes, context_bytes, inputs_bytes = _bodies(invocation, work)
    actual = _replay(invocation, work)
    body_fields = contract._body_commitments_on_work(proof_bytes=proof_bytes,
        context_bytes=context_bytes, inputs_bytes=inputs_bytes, transition_bytes=actual.transition_bytes, work=work)
    expected = invocation.scope
    payload = {**contract._source_fields(), **body_fields,
        "requestDigest": invocation.request["requestDigest"], "operationId": invocation.request["operationId"],
        "configurationDigest": expected["configurationDigest"], "plannerIdentity": expected["plannerIdentity"],
        "plannerSpkiDigest": expected["plannerSpkiDigest"], "issuedAtEpochNs": invocation.window[0],
        "expiresAtEpochNs": min(_expiry(invocation, work, invocation.window[0]), invocation.window[3],
            invocation.window[0] + invocation.monotonic_deadline - invocation.window[1], actual.valid_until_epoch_ns)}
    unsigned = contract._encode_on_work(payload, work=work)
    _fresh_replayed(payload, invocation, actual, live, work)
    evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
    evidence.keys._pair_on_work(planner_private_key, planner_public_key, work)
    message = evidence.plan._ascii(evidence.plan._frame(contract.SIGNATURE_DOMAIN, (unsigned,), work), work)
    # Reserve fixed-size signature transport and both post-sign encodings before
    # invoking the signing key. The genuine signer verifies its actual output.
    placeholder = {"schema": contract.ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    envelope_size, envelope_nodes = work.measure(placeholder)
    payload_size, payload_nodes = work.measure(payload)
    if envelope_size > contract.MAX_BYTES or envelope_nodes > contract.MAX_NODES:
        _fail("activation plan signed output exceeds its wire bound")
    work.charge(input_bytes=envelope_size + 2 * payload_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=envelope_nodes + payload_nodes)
    _fresh_replayed(payload, invocation, actual, live, work)
    signature = evidence.production._sign_and_verify(planner_private_key, planner_public_key, message, work)
    _fresh_replayed(payload, invocation, actual, live, work)
    # The held canonical payload, not a callback-returned projection, is signed.
    if commitment.canonical_bytes(payload) != unsigned:
        _fail("activation plan payload changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    contract.shape._base64url(encoded, signature=True)
    envelope = commitment.canonical_bytes({"schema": contract.ENVELOPE_SCHEMA,
        "payload": payload, "signatureBase64Url": encoded})
    if len(envelope) != envelope_size:
        _fail("activation plan output changed after sizing")
    _fresh_replayed(payload, invocation, actual, live, work)
    return envelope


def _verify_on_work(context, *, envelope_bytes, request, scope, assertion_bytes, old_token_bytes,
        new_token_bytes, delivery_envelope_bytes, delivery_custody_key, business_before_roots,
        authorization_before_roots, before_proofs, read_heads, query_frontiers,
        expected_counted_heads, write_proof_bytes, planner_public_key,
        state_enrollment_bytes, state_root_public_key, complete_root_vector_bytes,
        head_query_bytes, head_observation_bytes,
        live_window, work, transport_deadline_ns=None):
    """Verify the signature, repeat original replay and compare every commitment.

    This active-window API does not renew expired plans or authenticate history.
    Its actual KernelTransition return is ordinary data, not an executor input
    capability or an alternative to independently admitted current roots.
    """
    if not isinstance(planner_public_key, evidence.keys.Ed25519PublicKey):
        _fail("activation plan verification requires an independently admitted public key")
    if type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= contract.MAX_BYTES:
        _fail("activation plan requires a bounded immutable signed original")
    invocation = _capture(context, request=request, scope=scope, assertion_bytes=assertion_bytes,
        old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers,
        expected_counted_heads=expected_counted_heads, write_proof_bytes=write_proof_bytes,
        state_enrollment_bytes=state_enrollment_bytes, state_root_public_key=state_root_public_key,
        complete_root_vector_bytes=complete_root_vector_bytes,
        head_query_bytes=head_query_bytes, head_observation_bytes=head_observation_bytes,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    live = _live(invocation, work)
    live()
    envelope = contract._decode_on_work(envelope_bytes, envelope=True, work=work)
    payload, expected = envelope["payload"], invocation.scope
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        registration._same(payload[name], expected[name], work, "independent activation plan " + name)
    for name in ("requestDigest", "operationId"):
        registration._same(payload[name], invocation.request[name], work, "activation plan " + name)
    unsigned = contract._encode_on_work(payload, work=work)
    evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
    evidence.capability._signature(planner_public_key, envelope["signatureBase64Url"],
        contract.SIGNATURE_DOMAIN, unsigned, evidence.capture._SharedLedger(work))
    _fresh(payload, invocation, live(), work)
    proof_bytes, context_bytes, inputs_bytes = _bodies(invocation, work)
    actual = _replay(invocation, work)
    body_fields = contract._body_commitments_on_work(proof_bytes=proof_bytes,
        context_bytes=context_bytes, inputs_bytes=inputs_bytes, transition_bytes=actual.transition_bytes, work=work)
    for field, expected_value in body_fields.items():
        registration._same(payload[field], expected_value, work, "activation plan original " + field)
    _fresh_replayed(payload, invocation, actual, live, work)
    return actual.transition

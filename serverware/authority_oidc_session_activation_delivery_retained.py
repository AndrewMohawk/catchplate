"""Consume-specific private original serialization and raw reconstruction.

These helpers do not authenticate a plan, query, root, completion or successful
transition. The owning caller must retain its original current guard and work,
authenticate its known envelope before protected lookup, compare independent
expectations, and invoke the actual full plan replay after reconstruction.
No database, signer, journal mutation, key material or replacement lifetime is
accepted or created here. Stored original expectations are data, not authority.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone

from serverware import authority_oidc_session_activation_delivery_journal as journal
from serverware import authority_oidc_session_activation_delivery_plan as plan
from serverware.authority_index_contract import CountedNode, IndexLeaf, OpaqueSubtree


contract, reads, state = plan.contract, plan.reads, plan.state
registration, evidence, core = plan.registration, plan.evidence, plan.core


class DeliveryRetainedOriginalsError(ValueError):
    pass


def _fail(message):
    raise DeliveryRetainedOriginalsError(message)


def _b64(original, work):
    padded = 4 * ((len(original) + 2) // 3)
    work.charge(input_bytes=len(original) + 3 * padded)
    return evidence.production._callback(work,
        lambda: base64.urlsafe_b64encode(original).decode("ascii").rstrip("="))


def _encode_on_work(invocation, *, envelope_bytes, plan_digest, work):
    """Return (scope4, canonical original bytes), never a verified-plan token.

    The exact invocation is the plan's owned original capture, not a successful
    result. The closed codec repeats envelope identity/scope joins; no signature
    admission is implied by accepting this ordinary private capture.
    """
    ledger = evidence.capture._SharedLedger(work)
    original_envelope, identity = envelope_bytes, plan_digest
    if type(invocation) is not plan._Invocation:
        _fail("consume retention needs the exact original capture, not a replay result")
    context = invocation.context
    if (type(context) is not core.KernelContext or context.operation != contract.OPERATION
            or context.verified_webauthn_evidence is not None
            or type(context.database_now) is not datetime or context.database_now.tzinfo is not timezone.utc):
        _fail("consume retention requires the actual UTC original context")
    database_now = context.database_now
    shape = contract.shape
    shape._digest(identity)
    envelope = state._original(original_envelope, contract.MAX_BYTES, "retained signed plan")
    old = plan.assertion._token(invocation.old_token_bytes, work)
    proof = state._original(invocation.write_proof_bytes, plan.writes.MAX_WRITE_PROOF_BYTES, "retained write proof")
    if type(invocation.state_originals) is not tuple or len(invocation.state_originals) != 4:
        _fail("consume retention requires four immutable state originals")
    state_originals = tuple(state._original(raw, maximum, "retained " + label)
        for raw, maximum, label in zip(invocation.state_originals,
            (state.head.authorization.MAX_ENROLLMENT_BYTES, state.vector.MAX_BYTES,
                state.head.MAX_QUERY_BYTES, state.head.MAX_BYTES),
            ("enrollment", "vector", "query", "observation")))
    activation_originals = plan._activation_originals(invocation.activation_originals, work)
    originals = (old, proof, envelope, *state_originals, *activation_originals)
    if (sum(map(len, originals)) > journal.MAX_ORIGINAL_BYTES
            or sum(4 * ((len(raw) + 2) // 3) for raw in originals) > journal.MAX_ORIGINAL_BYTES):
        _fail("consume retained original encodings exceed the fixed aggregate bound")
    # Detach every nested ordinary graph before base64/native/hash callbacks.
    owned = plan.assertion._Capture(ledger, maximum_bytes=plan.assertion.MAX_CONTEXT_BYTES).visit({
        "request": invocation.request, "scope": invocation.scope,
        "activationExpectations": invocation.activation_expectations,
        "activationScope": invocation.activation_scope})
    read_inputs = plan._read_inputs(invocation, work)
    storage_scope = journal._scope({"sourceRevision": contract.authority.SOURCE_REVISION,
        "configurationDigest": owned["scope"]["configurationDigest"],
        "requestDigest": owned["request"]["requestDigest"], "planDigest": identity})
    document = {"schema": journal.SCHEMA, "sourceRevision": contract.authority.SOURCE_REVISION,
        "request": owned["request"], "scope": owned["scope"], "databaseNow": database_now.isoformat(),
        "oldTokenBase64Url": _b64(old, work), "readInputs": read_inputs,
        "writeProofBase64Url": _b64(proof, work), "planEnvelopeBase64Url": _b64(envelope, work),
        "stateEnrollmentBase64Url": _b64(state_originals[0], work),
        "completeRootVectorBase64Url": _b64(state_originals[1], work),
        "headQueryBase64Url": _b64(state_originals[2], work),
        "headObservationBase64Url": _b64(state_originals[3], work),
        "activationOriginals": [_b64(raw, work) for raw in activation_originals],
        "activationExpectations": owned["activationExpectations"], "activationScope": owned["activationScope"]}
    return storage_scope, journal._encode_original_on_work(document, scope=storage_scope, work=work)


def _ascii(value, work):
    if (type(value) is not str or not 2 <= len(value) <= reads.reads.MAX_BOOKKEEPING_BYTES
            or not value.isascii()):
        _fail("consume retained query original is not bounded exact ASCII")
    work.charge(input_bytes=len(value))
    return value.encode("ascii")


def _restore_inputs(value, work):
    """Rebuild real raw record classes, not an admitted read/proof carrier."""
    registration._closed(value, journal.READ_INPUT_FIELDS, "consume retained read graph")
    if value["schema"] != contract.PROOF_DOMAIN:
        _fail("consume retained graph has the wrong operation-specific proof domain")
    for name, count in (("selectedRows", 10), ("beforeProofs", 10), ("readHeads", 7),
            ("queryFrontiers", 7), ("queryReads", 17), ("countedBeforeHeads", 7)):
        if type(value[name]) is not list or len(value[name]) != count:
            _fail("consume retained read inventory differs from its source closure")
    heads, frontiers, records = [], [], []
    for item in value["readHeads"]:
        if type(item) is not list or len(item) != 4:
            _fail("consume retained head must be a closed four-element original")
        work.prepare_copy(item)
        heads.append(reads.batch.CompleteQueryHead(item[0], item[1], CountedNode(item[2], item[3])))
    for item in value["queryFrontiers"]:
        if (type(item) is not list or len(item) != 2 or type(item[1]) is not list
                or len(item[1]) > reads.MAX_OUTSIDE_PREFIXES + 1):
            _fail("consume retained frontier exceeds its fixed original bound")
        entries = []
        for terminal in item[1]:
            if (type(terminal) is not list or len(terminal) != 4
                    or terminal[0] not in ("leaf", "opaque")):
                _fail("consume retained frontier terminal has unknown fields or tag")
            work.prepare_copy(terminal)
            entries.append(IndexLeaf(*terminal[1:]) if terminal[0] == "leaf" else OpaqueSubtree(*terminal[1:]))
        work.charge(input_bytes=1 + len(entries), json_nodes=1)
        frontiers.append(reads.batch.CompleteQueryFrontier(item[0], tuple(entries)))
    for item in value["queryReads"]:
        registration._closed(item, {"queryId", "declaredQueryJson", "resolvedQueryJson", "returnedRowCount", "addresses"},
            "consume retained query read")
        if type(item["addresses"]) is not list or len(item["addresses"]) > reads.MAX_QUERY_ROWS:
            _fail("consume retained query addresses exceed their fixed bound")
        addresses = []
        for address in item["addresses"]:
            registration._closed(address, {"table", "keyJson", "keyDigest", "present"}, "consume retained query address")
            addresses.append(reads.reads._make_record(reads.reads.QueryReadAddress, {
                "table": address["table"], "key_json": _ascii(address["keyJson"], work),
                "key_digest": address["keyDigest"], "present": address["present"]}, work))
        work.charge(input_bytes=1 + len(addresses), json_nodes=1)
        records.append(reads.reads._make_record(reads.reads.QueryRead, {
            "query_id": item["queryId"], "declared_query_json": _ascii(item["declaredQueryJson"], work),
            "resolved_query_json": _ascii(item["resolvedQueryJson"], work),
            "addresses": tuple(addresses), "returned_row_count": item["returnedRowCount"]}, work))
    for name in ("selectedRows", "beforeProofs", "countedBeforeHeads",
            "businessBeforeRoots", "authorizationBeforeRoots"):
        work.prepare_copy(value[name])
    work.charge(input_bytes=3 + len(heads) + len(frontiers) + len(records), json_nodes=3)
    return (tuple(value["selectedRows"]), tuple(value["beforeProofs"]), tuple(heads),
        tuple(frontiers), tuple(records), tuple(value["countedBeforeHeads"]),
        tuple(value["businessBeforeRoots"]), tuple(value["authorizationBeforeRoots"]))


def _restore_on_work(original_bytes, *, scope, work):
    """Return (KernelContext, original kwargs) requiring independent full replay.

    No key, custody object, live window, transport deadline or work object comes
    from the record. The owner must supply those independently and compare its
    known originals/scopes/roots before invoking the genuine consume verifier.
    """
    owned = journal._decode_original_on_work(original_bytes, scope=scope, work=work)
    selected, proofs, heads, frontiers, records, counted, business, authorization = _restore_inputs(
        owned["readInputs"], work)
    database_now = registration._utc(owned["databaseNow"], "restored consume database time", work)
    request = owned["request"]
    context = core.KernelContext(contract.OPERATION, request["arguments"], selected,
        database_now, request["requestDigest"], query_reads=records)
    result = {"envelope_bytes": registration._encoded_original(owned["planEnvelopeBase64Url"], contract.MAX_BYTES, work),
        "request": request, "scope": owned["scope"],
        "old_token_bytes": plan.assertion._token(registration._encoded_original(owned["oldTokenBase64Url"], 64,
            work, minimum=64), work), "business_before_roots": business, "authorization_before_roots": authorization,
        "before_proofs": proofs, "read_heads": heads, "query_frontiers": frontiers,
        "expected_counted_heads": counted,
        "write_proof_bytes": registration._encoded_original(owned["writeProofBase64Url"], plan.writes.MAX_WRITE_PROOF_BYTES, work),
        "state_enrollment_bytes": registration._encoded_original(owned["stateEnrollmentBase64Url"],
            state.head.authorization.MAX_ENROLLMENT_BYTES, work),
        "complete_root_vector_bytes": registration._encoded_original(owned["completeRootVectorBase64Url"], state.vector.MAX_BYTES, work),
        "head_query_bytes": registration._encoded_original(owned["headQueryBase64Url"], state.head.MAX_QUERY_BYTES, work),
        "head_observation_bytes": registration._encoded_original(owned["headObservationBase64Url"], state.head.MAX_BYTES, work),
        "activation_originals": journal._activation_frames(owned["activationOriginals"], work),
        "activation_expectations": owned["activationExpectations"], "activation_scope": owned["activationScope"]}
    return context, result

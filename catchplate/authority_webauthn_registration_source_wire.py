"""Canonical raw registration source observations and genuine live replay.

The fixed producer authenticates the original request and encodes its actual
acquisition; the receiver authenticates the response before source decoding.
Selectors, full root provenance and the original request interval remain
independently admitted inputs; decoding a source document does not enroll any
of them. The actual source verifier proves
the raw memberships and regenerates every PK query/address association on the
same work before ordinary observations are returned.

The database cutoff is an authenticated, bounded planner observation, not an
independent database-clock or current-root authority. No trace, successful
proof carrier, evidence signature, typed request, semantic effect, SQL, clock
sample or new allowance is created. Later signing must still perform its real
source/ceremony checks; this result cannot replace raw proof replay.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from catchplate import authority_webauthn_evidence_input_wire as input_wire
from catchplate import authority_webauthn_evidence_plan_contract as contract
from catchplate import authority_webauthn_evidence_plan_reads as reads_wire
from catchplate import authority_webauthn_registration_source_proofs as source


authority, reads, evidence = source.authority, source.reads, input_wire.evidence
SCHEMA = "catchplate.policyAuthorityWebAuthnRegistrationSourceObservations/v1"
CONTEXT_SCHEMA = "catchplate.policyAuthorityWebAuthnRegistrationSourceRequestContext/v1"
OPERATION = source.OPERATION
MAX_BYTES, MAX_NODES, MAX_DEPTH = contract.MAX_BYTES, contract.MAX_NODES, contract.MAX_DEPTH
_FIELDS = frozenset({"schema", "sourceRevision", "operation", "databaseCutoffUs",
    "businessBeforeRoots", "authorizationBeforeRoots", "selectedRows", "beforeProofs", "queryReads"})
_CONTEXT_FIELDS = frozenset({"schema", "sourceRevision", "operation", "registrationChallengeId",
    "publishedPublicationId", "oidcSessionId", "businessBeforeRoots", "authorizationBeforeRoots",
    "deadlineEpochNs"})


class WebAuthnRegistrationSourceWireError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RegistrationSourceObservations:
    """Ordinary original read observations, never a transferable admission."""

    business_before_roots: tuple[dict, ...]
    authorization_before_roots: tuple[dict, ...]
    selected_rows: tuple[dict, ...]
    before_proofs: tuple[dict, ...]
    query_reads: tuple[reads.QueryRead, ...]
    database_now: datetime


class _Capture(evidence.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise WebAuthnRegistrationSourceWireError("registration source graph exceeds its structure bounds")
        return super().visit(value, depth, ancestors)


def _capture(value, work):
    return _Capture(evidence.capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _list(values, maximum, work):
    if type(values) is not tuple or not 1 <= len(values) <= maximum:
        raise WebAuthnRegistrationSourceWireError("registration source observations require bounded exact tuples")
    work.prepare_copy(values)
    return list(values)


def _tuple(values, work):
    work.prepare_copy(values)
    return tuple(values)


def _roots(value):
    contract._roots(value["businessBeforeRoots"], contract._BUSINESS_TABLES[OPERATION])
    contract._roots(value["authorizationBeforeRoots"], contract._AUTHORIZATION_TABLES[OPERATION])


def _shape(value):
    """Close owned data only; source meanings require the real replay below."""
    source._source()
    shape, retained = contract.shape, contract.retained
    shape._object(value, _FIELDS, "registration source observations")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["operation"], OPERATION)
    shape._integer(value["databaseCutoffUs"], minimum=1)
    _roots(value)
    maximum = contract._SPECS[OPERATION]["maximumQueryRows"]
    for name in ("selectedRows", "beforeProofs", "queryReads"):
        retained._array(value[name], maximum, "registration source " + name, minimum=3)
    count = len(value["selectedRows"])
    if count not in (3, 4) or len(value["beforeProofs"]) != count or len(value["queryReads"]) != count:
        raise WebAuthnRegistrationSourceWireError("registration source observations are not the fixed three/four PK subset")
    tables = contract._BUSINESS_TABLES[OPERATION] + contract._AUTHORIZATION_TABLES[OPERATION]
    for selected in value["selectedRows"]:
        shape._object(selected, retained._SELECTED_FIELDS, "registration source selected row")
        shape._text(selected["table"])
        if selected["table"] not in tables:
            raise WebAuthnRegistrationSourceWireError("registration source selected table is outside its inventory")
        contract._key(selected["key"], selected["table"])
        shape._digest(selected["keyDigest"])
        retained._boolean(selected["present"])
        if (selected["contractSelector"] is not None
                or selected["present"] and type(selected["row"]) is not dict
                or not selected["present"] and selected["row"] is not None):
            raise WebAuthnRegistrationSourceWireError("registration source selection is not an exact PK observation")
    for proof in value["beforeProofs"]:
        retained._proof(proof)
        if proof["table"] not in tables:
            raise WebAuthnRegistrationSourceWireError("registration source proof table is outside its inventory")
        contract._key(proof["key"], proof["table"])
    contract._reads(value["queryReads"], maximum, tables)


def _context(value, work):
    shape = contract.shape
    shape._object(value, _CONTEXT_FIELDS, "registration source request context")
    shape._literal(value["schema"], CONTEXT_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["operation"], OPERATION)
    for name in ("registrationChallengeId", "publishedPublicationId"):
        source.validation._text(value[name], name, 4096, work)
    if value["oidcSessionId"] is not None:
        source.validation._text(value["oidcSessionId"], "OIDC session ID", 4096, work)
    shape._integer(value["deadlineEpochNs"], minimum=1)
    _roots(value)


def _encode_on_work(*, business_before_roots, authorization_before_roots,
        selected_rows, before_proofs, query_reads, database_now, work):
    """Encode actual raw observations without asserting their provenance."""
    ledger = evidence.capture._SharedLedger(work)
    spec, _ = source._source()
    maximum = spec["maximumQueryRows"]
    held_reads = query_reads
    cutoff = input_wire._to_epoch_us(database_now)
    source.validation._now(database_now)
    # Own every mutable row/root/proof graph before native codecs. Actual
    # QueryRead records retain immutable byte fields, then the existing copier
    # and codec reconstruct and charge those fields before encoding them.
    owned = _capture({"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "operation": OPERATION, "databaseCutoffUs": cutoff,
        "businessBeforeRoots": _list(business_before_roots, len(contract._BUSINESS_TABLES[OPERATION]), work),
        "authorizationBeforeRoots": _list(authorization_before_roots,
            len(contract._AUTHORIZATION_TABLES[OPERATION]), work),
        "selectedRows": _list(selected_rows, maximum, work),
        "beforeProofs": _list(before_proofs, maximum, work)}, work)
    owned["queryReads"] = reads_wire._encode_reads_on_work(held_reads, maximum_rows=maximum, work=work)
    _shape(owned)
    return evidence.capability._wire(owned, ledger, MAX_BYTES, MAX_NODES)


def _verify_on_work(*, source_bytes, request_context, request_issued_at_epoch_ns,
        request_expires_at_epoch_ns, maximum_clock_skew_ns, work):
    """Rejoin authenticated originals and perform genuine source proof replay.

    The fixed producer supplies its authenticated request and raw acquisition
    before response signing. The fixed receiver must also authenticate the
    response control and its full byte commitments before entering. No
    signature-success carrier is accepted here, and no original interval is
    renewed by this codec or proof work.
    """
    ledger = evidence.capture._SharedLedger(work)
    if type(source_bytes) is not bytes or not 2 <= len(source_bytes) <= MAX_BYTES:
        raise WebAuthnRegistrationSourceWireError("registration source original is not bounded immutable bytes")
    original = source_bytes
    issued, expires, skew = request_issued_at_epoch_ns, request_expires_at_epoch_ns, maximum_clock_skew_ns
    contract.shape._integer(issued, minimum=1)
    contract.shape._integer(expires, minimum=1)
    contract.shape._integer(skew, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if not 0 < expires - issued <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        raise WebAuthnRegistrationSourceWireError("registration source request interval is outside its source bound")
    # Independent request graphs are detached before the parser or any proof,
    # canonical encoder or hash callback can observe caller-owned objects.
    context = _capture(request_context, work)
    _context(context, work)
    if expires > context["deadlineEpochNs"]:
        raise WebAuthnRegistrationSourceWireError("registration source request exceeds its original deadline")
    document = evidence.wire._decode_object(original, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(document, work)
    _shape(owned)
    evidence.capability._canonical(original, owned, ledger, MAX_BYTES, MAX_NODES)
    for name in ("businessBeforeRoots", "authorizationBeforeRoots"):
        evidence.plan._same(owned[name], context[name], work,
            "registration source differs from independent " + name)
    database_now = input_wire._from_epoch_us(owned["databaseCutoffUs"])
    cutoff_ns = source.validation._now(database_now)
    if abs(cutoff_ns - issued) > skew or cutoff_ns >= expires or cutoff_ns >= context["deadlineEpochNs"]:
        raise WebAuthnRegistrationSourceWireError("registration source cutoff differs from the original request interval")
    records = reads_wire._decode_reads_on_work(owned["queryReads"],
        maximum_rows=contract._SPECS[OPERATION]["maximumQueryRows"], work=work)
    business = _tuple(owned["businessBeforeRoots"], work)
    authorization = _tuple(owned["authorizationBeforeRoots"], work)
    selected = _tuple(owned["selectedRows"], work)
    proofs = _tuple(owned["beforeProofs"], work)
    source._verify_on_work(registration_challenge_id=context["registrationChallengeId"],
        published_publication_id=context["publishedPublicationId"], oidc_session_id=context["oidcSessionId"],
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=selected, before_proofs=proofs, query_reads=records, work=work)
    # Return only the original canonical observations after all proof/native
    # callbacks; a successful source-row carrier never replaces those bytes.
    evidence.capability._canonical(original, owned, ledger, MAX_BYTES, MAX_NODES)
    return _RegistrationSourceObservations(business, authorization, selected, proofs, records, database_now)

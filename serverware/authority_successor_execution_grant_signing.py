"""Private signing suffixes for the two fixed successor-grant domains.

Only the original-enrollment and genuine original-plan producers should call
these helpers, after deriving their complete scope themselves. Closed shapes
and a matching signing key do not establish independent caller authorization,
plan semantics, cold key provenance or a current-root reservation. This module
does not accept arbitrary signature domains, create work allowances, sample
clocks, provision keys, publish grants or execute database operations.
"""
from __future__ import annotations

import base64

from serverware import authority_successor_execution_grant as grants
from serverware.authority_query_read_work import QueryReadWorkError


authorization, capture, plan, shape = (
    grants.authorization, grants.capture, grants.plan, grants.shape)
production, keys = authorization.production, grants.keys


def _sign(*, payload, private_key, public_key, enrollment, work):
    """Own the graph before key callbacks; reserve the complete signed output."""
    ledger = capture._SharedLedger(work)
    if type(enrollment) is not bool:
        raise grants.SuccessorExecutionGrantError("grant signature purpose is not source-selected")
    schema, maximum, validate = (
        (grants.ENROLLMENT_SCHEMA, grants.MAX_ENROLLMENT_BYTES, grants._enrollment_shape)
        if enrollment else
        (grants.GRANT_SCHEMA, grants.MAX_GRANT_BYTES, grants._grant_shape))
    held_private, held_public = private_key, public_key
    authorization._private(held_private)
    authorization._public(held_public)
    owned = grants._Capture(ledger, maximum_bytes=maximum).visit(payload)
    validate(owned)
    keys._pair_on_work(held_private, held_public, work)
    envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > maximum
            or max(unsigned_nodes, envelope_nodes) > grants.MAX_NODES):
        raise grants.SuccessorExecutionGrantError("grant signature output exceeds its source bound")
    # The fixed 64-byte signature has an 86-character unpadded transport.
    # Reserve both canonical payload encodings, comparisons and final output
    # before signing; framing below consumes the existing work separately.
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("grant production cannot reserve its complete signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        raise grants.SuccessorExecutionGrantError("grant payload changed after measurement")
    message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
    signature = production._sign_and_verify(held_private, held_public, message, work)
    if (work.measure(owned) != (unsigned_size, unsigned_nodes)
            or plan.core.canonical_bytes(owned) != unsigned):
        raise grants.SuccessorExecutionGrantError("grant payload changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    result = plan.core.canonical_bytes({"schema": schema, "payload": owned,
        "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise grants.SuccessorExecutionGrantError("signed grant envelope changed after reservation")
    return result


def _sign_grant_on_work(*, payload, private_key, public_key, work):
    """Fixed execution-grant suffix for genuinely replayed same-call claims."""
    return _sign(payload=payload, private_key=private_key, public_key=public_key,
        enrollment=False, work=work)


def _sign_enrollment_on_work(*, payload, private_key, public_key, work):
    """Fixed root-enrollment suffix for original-enrollment-derived scope."""
    return _sign(payload=payload, private_key=private_key, public_key=public_key,
        enrollment=True, work=work)

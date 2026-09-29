"""Bounded signing for the two source-fixed public revocation authorization domains.

Shape validation is not permission. Actual root enrollment or genuine original
replay owns admission before this private suffix; no arbitrary domain or public
signing endpoint is accepted.
"""
from __future__ import annotations

import base64

from serverware import authority_public_revocation_caller_authorization as control
from serverware.authority_query_read_work import QueryReadWorkError


def _sign(*, payload, private_key, public_key, enrollment, work):
    if type(enrollment) is not bool:
        raise control.PublicRevocationCallerAuthorizationError("public revocation signing purpose is not fixed")
    schema = control.ENROLLMENT_SCHEMA if enrollment else control.REQUEST_SCHEMA
    maximum = control.MAX_ENROLLMENT_BYTES if enrollment else control.MAX_AUTHORIZATION_BYTES
    authorization, plan, production = control.authorization, control.plan, control.production
    ledger = control.capture._SharedLedger(work)
    private, public = private_key, public_key
    authorization._private(private)
    authorization._public(public)
    owned = control.grants._Capture(ledger, maximum_bytes=maximum).visit(payload)
    control._shape(owned, enrollment=enrollment)
    control.keys._pair_on_work(private, public, work)
    envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > maximum or max(unsigned_nodes, envelope_nodes) > control.MAX_NODES:
        raise control.PublicRevocationCallerAuthorizationError("public revocation signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("public revocation signing cannot reserve its complete output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        raise control.PublicRevocationCallerAuthorizationError("public revocation payload changed after measurement")
    message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
    signature = production._sign_and_verify(private, public, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        raise control.PublicRevocationCallerAuthorizationError("public revocation payload changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    control.shape._base64url(encoded, signature=True)
    result = plan.core.canonical_bytes({"schema": schema, "payload": owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise control.PublicRevocationCallerAuthorizationError("public revocation output changed after reservation")
    return result


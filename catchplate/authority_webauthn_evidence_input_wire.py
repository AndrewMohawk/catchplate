"""Bounded original-input transport for private WebAuthn evidence replay.

Canonical bytes and their digest are data commitments, not admission. Purpose
codecs close their own shapes and reconstruct actual core inputs; the replay
owner must independently admit the historical input commitment and context.
All capture, encoding, decoding and hashing uses the original caller work.
The transport ceiling does not promise acceptance at the cumulative work cap.
There is no database, registry, signer, clock sample or replacement allowance.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from catchplate import authority_webauthn_evidence as evidence
from catchplate import authority_revocation_invocation as invocation


MAX_BYTES = evidence.authority.MAX_RESULT_BYTES
MAX_NODES = evidence.capture.MAX_TOTAL_JSON_NODES
MAX_DEPTH = 16
IDENTITY_DOMAIN = "catchplate.policyAuthorityWebAuthnEvidenceInputsIdentity/v1"
_RAW_FIELDS = frozenset({"base64Url", "byteCount"})
_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class WebAuthnEvidenceInputWireError(ValueError):
    pass


class _Capture(evidence.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise WebAuthnEvidenceInputWireError("evidence inputs exceed their structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise WebAuthnEvidenceInputWireError("evidence inputs exceed their node bound")
        return result


def _capture(document, work):
    ledger = evidence.capture._SharedLedger(work)
    return _Capture(ledger, maximum_bytes=MAX_BYTES).visit(document)


def _encode_document(document, work):
    owned = _capture(document, work)
    if type(owned) is not dict:
        raise WebAuthnEvidenceInputWireError("evidence inputs require an exact object")
    return evidence.capability._wire(owned, evidence.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode_document(raw, work):
    document = evidence.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(document, work)
    evidence.capability._canonical(raw, owned, evidence.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return owned


def _raw(raw, minimum, maximum):
    if (type(minimum) is not int or type(maximum) is not int
            or not 1 <= minimum <= maximum <= MAX_BYTES
            or type(raw) is not bytes or not minimum <= len(raw) <= maximum):
        raise WebAuthnEvidenceInputWireError("evidence input is not bounded original bytes")


def _pack_raw(raw, *, minimum, maximum, work):
    evidence.capture._SharedLedger(work)
    _raw(raw, minimum, maximum)
    return {"base64Url": invocation._encode(raw, work), "byteCount": len(raw)}


def _unpack_raw(value, *, minimum, maximum, work):
    evidence.capture._SharedLedger(work)
    evidence.plan.contract._object(value, _RAW_FIELDS, "evidence original-byte transport")
    count, encoded = value["byteCount"], value["base64Url"]
    if (type(minimum) is not int or type(maximum) is not int
            or not 1 <= minimum <= maximum <= MAX_BYTES
            or type(count) is not int or not minimum <= count <= maximum
            or type(encoded) is not str or len(encoded) != (4 * count + 2) // 3):
        raise WebAuthnEvidenceInputWireError("evidence original-byte length is invalid")
    # Include one-byte inputs, unlike the existing envelope-only raw decoder.
    # Reserve every scan/codec/roundtrip buffer before allocating or decoding.
    length = len(encoded)
    padded = length + (-length % 4)
    decoded = 3 * (padded // 4)
    reencoded = 4 * ((decoded + 2) // 3)
    work.charge(input_bytes=2 * length + 4 * padded + 2 * decoded + 5 * reencoded)
    if any(character not in _ALPHABET for character in encoded):
        raise WebAuthnEvidenceInputWireError("evidence input base64 alphabet is invalid")
    raw = base64.b64decode(encoded + "=" * (-length % 4), altchars=b"-_", validate=True)
    if len(raw) != count or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded:
        raise WebAuthnEvidenceInputWireError("evidence input base64 is not canonical")
    return raw


def _to_epoch_us(value):
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise WebAuthnEvidenceInputWireError("evidence input time is not an exact UTC datetime")
    delta = value - _EPOCH
    result = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    evidence.plan.contract._integer(result, 2**63 - 1, minimum=1)
    return result


def _from_epoch_us(value):
    evidence.plan.contract._integer(value, 2**63 - 1, minimum=1)
    try:
        result = _EPOCH + timedelta(microseconds=value)
    except OverflowError as exc:
        raise WebAuthnEvidenceInputWireError("evidence input time exceeds datetime range") from exc
    if _to_epoch_us(result) != value:
        raise WebAuthnEvidenceInputWireError("evidence input time lost precision")
    return result


def _digest_on_work(raw, work):
    evidence.capture._SharedLedger(work)
    _raw(raw, 2, MAX_BYTES)
    return evidence.plan._frame(IDENTITY_DOMAIN, (raw,), work)

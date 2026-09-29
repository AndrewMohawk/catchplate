"""Bounded native packet original extraction, deliberately not verification.

This module knows no control-plane state, signature key, quote verifier, live
policy, installation receipt or capability. Its immutable result is untrusted
original input for the genuine native verifier, not accepted authority.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import json
import re

from . import _workload_signed_packet as packets
from ._workload_stream import WorkloadClientError


SCHEMA = "serverware.nativeEnrollmentPacket/v2"
PURPOSE = "workload-bootstrap"
MAX_BYTES = 512 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 1
_COMPONENT_LIMITS = (
    ("delegationBase64url", 32 * 1024),
    ("setupAuthorizationBase64url", 32 * 1024),
    ("targetRequestBase64url", 64 * 1024),
    ("targetIssuerCertificateDerBase64url", 64 * 1024),
    ("policyRequirementsBase64url", 64 * 1024),
)
_FIELDS = frozenset({"apiVersion", "purpose"} | {name for name, _ in _COMPONENT_LIMITS})
_BASE64 = re.compile(r"[A-Za-z0-9_-]+\Z")


@dataclass(frozen=True, slots=True, repr=False)
class _NativePacketOriginals:
    delegation_bytes: bytes
    setup_authorization_bytes: bytes
    target_request_bytes: bytes
    target_issuer_certificate_der_bytes: bytes
    policy_requirements_bytes: bytes


def _fail():
    raise WorkloadClientError("native enrollment packet original container is invalid")


def _flat_preflight(original, budget):
    depth = 0
    quoted = escaped = False
    for index, byte in enumerate(original):
        if index % 1024 == 0:
            budget.check()
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail()
        elif byte in (125, 93):
            depth -= 1
            if depth < 0:
                _fail()
    if quoted or escaped or depth:
        _fail()
    packets._preflight_json(original, budget)


def decode_packet_originals_on_budget(*, packet_bytes, budget):
    """Extract five exact originals only, under the caller's existing budget.

    No component JSON/DER is parsed, no signature is accepted, no deadline is
    created, and no verified/success/installation flag is returned.
    """
    budget.check()
    if type(packet_bytes) is not bytes or not 1 <= len(packet_bytes) <= MAX_BYTES or not packet_bytes.endswith(b"\n"):
        _fail()
    # Representation preflight precedes JSON/base64 allocation; the supplied
    # server ledger additionally meters actual copies through _charge.
    if 16 * len(packet_bytes) + sum(limit for _, limit in _COMPONENT_LIMITS) + 64 * 1024 > MAX_ORIGINAL_BYTES:
        _fail()
    _flat_preflight(packet_bytes, budget)
    try:
        value = json.loads(packet_bytes.decode("ascii"), object_pairs_hook=packets._unique_object,
            parse_int=packets._reject_number, parse_float=packets._reject_number,
            parse_constant=packets._reject_number)
        budget.check()
        if (type(value) is not dict or set(value) != _FIELDS or value["apiVersion"] != SCHEMA
                or value["purpose"] != PURPOSE
                or packets._canonical(value, MAX_BYTES - 1, budget) + b"\n" != packet_bytes):
            _fail()
        originals = []
        for field, limit in _COMPONENT_LIMITS:
            encoded = value[field]
            if (type(encoded) is not str or not 1 <= len(encoded) <= (limit * 8 + 5) // 6
                    or _BASE64.fullmatch(encoded) is None):
                _fail()
            budget.check()
            raw = base64.b64decode(encoded + "=" * ((-len(encoded)) % 4), altchars=b"-_", validate=True)
            if (not 1 <= len(raw) <= limit
                    or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded):
                _fail()
            packets._charge(budget, input_bytes=len(raw))
            originals.append(raw)
        result = _NativePacketOriginals(*originals)
        budget.check()
        return result
    except WorkloadClientError:
        raise
    except (ValueError, TypeError, UnicodeError, binascii.Error, RecursionError):
        raise WorkloadClientError("native enrollment packet original container is invalid") from None

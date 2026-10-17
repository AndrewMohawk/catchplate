"""Offline authentication of original signed workload handoff packets.

The caller must acquire both exact originals through the pinned-file owner and
independently admit the signing key. This module returns ordinary packet data,
not an enrollment receipt, a live attestation verdict, CA admission, policy
freshness or permission to dispatch a request. In particular, signed measurement
pins remain issuer assertions; no witness, release or hardware check occurs here.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import validate_enrollment_tooling
from ._workload_stream import Budget, WorkloadClientError
from .workload_transport import validate_workload_transport


_MAX_PACKET_BYTES = 8 * 1024 * 1024
_MAX_KEY_BYTES = 64 * 1024
_MAX_DEPTH = 64
_MAX_NODES = 100_000
_MAX_PRINCIPAL_BYTES = 1024
_MAX_STATEMENT_BYTES = 16 * 1024
_MAX_LIFETIME_MS = 900_000
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32,256}\Z")
_SIGNATURE = re.compile(r"ed25519:([A-Za-z0-9_-]{86})\Z")
_PACKET_FIELDS = frozenset({
    "apiVersion", "kind", "tooling", "generatedAt", "issuedAtEpochMs",
    "expiresAtEpochMs", "nonce", "principalId", "catchplate", "pinning",
    "identity", "environment", "ca", "allowedRoutes", "agentHandoff",
    "egress", "canaries", "authenticity",
})
_STATEMENT_FIELDS = frozenset({
    "version", "packetSha256", "principalId", "nonce", "issuedAtEpochMs",
    "expiresAtEpochMs", "policyHash", "runtimeManifestDigest", "responseSigningKeyId",
})
_DIGEST_PINS = frozenset({
    "policyHash", "policySigningKeyId", "caIntermediateSpkiSha256",
    "dataPlaneBinaryDigest", "runtimeManifestDigest", "responseSigningKeyId",
    "provenanceDigest", "imageSignaturesDigest", "sourceTreeDigest",
    "policyHighWaterDigest",
})
_PIN_FIELDS = _DIGEST_PINS | {"rollbackEpoch", "policySequence", "releaseChannel"}


def _charge(budget, **amounts) -> None:
    """An inherited server ledger may meter the actual shared primitives."""
    charge = getattr(budget, "charge", None)
    if charge is not None:
        charge(**amounts)


def _preflight_json(raw: bytes, budget: Budget) -> None:
    """Bound nesting and every container/key/scalar before allocating JSON data.

    This lexical pass does not replace the standard decoder's grammar checks.
    Strings count once regardless of escapes; delimiters in strings never affect
    nesting. Primitive tokens count once even when the decoder will reject them.
    """
    cursor = 0
    checked_at = 0
    nodes = 0
    stack: list[int] = []
    size = len(raw)
    while cursor < size:
        if cursor - checked_at >= 16 * 1024:
            budget.check()
            checked_at = cursor
        byte = raw[cursor]
        if byte in b" \t\r\n,:":
            cursor += 1
            continue
        if byte in (123, 91):  # { [
            nodes += 1
            stack.append(125 if byte == 123 else 93)
            if len(stack) > _MAX_DEPTH:
                raise WorkloadClientError("signed workload JSON exceeds its nesting bound")
            cursor += 1
        elif byte in (125, 93):
            if not stack or stack.pop() != byte:
                raise WorkloadClientError("signed workload JSON structure is invalid")
            cursor += 1
        elif byte == 34:
            nodes += 1
            cursor += 1
            while cursor < size and raw[cursor] != 34:
                if cursor - checked_at >= 16 * 1024:
                    budget.check()
                    checked_at = cursor
                if raw[cursor] < 32:
                    raise WorkloadClientError("signed workload JSON string is invalid")
                cursor += 2 if raw[cursor] == 92 else 1
            if cursor >= size:
                raise WorkloadClientError("signed workload JSON string is incomplete")
            cursor += 1
        else:
            nodes += 1
            start = cursor
            while cursor < size and raw[cursor] not in b" \t\r\n,:{}[]\"":
                cursor += 1
                if cursor - start > 21:
                    raise WorkloadClientError("signed workload JSON scalar exceeds its bound")
        if nodes > _MAX_NODES:
            raise WorkloadClientError("signed workload JSON exceeds its node bound")
    if stack:
        raise WorkloadClientError("signed workload JSON structure is incomplete")
    _charge(budget, input_bytes=size, json_nodes=nodes)
    budget.check()


def _integer(text: str) -> int:
    # The closed packet consumer admits integral i64/u64 values, never floats or
    # arbitrary-precision decimal work. Individual timestamp fields are stricter.
    if len(text) > 21:
        raise ValueError("integer bound")
    value = int(text)
    if not -(1 << 63) <= value <= (1 << 64) - 1:
        raise ValueError("integer bound")
    return value


def _reject_number(_: str) -> object:
    raise ValueError("nonintegral number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def _parse_packet(raw: bytes, budget: Budget) -> dict[str, object]:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_PACKET_BYTES:
        raise WorkloadClientError("signed workload packet original exceeds its bound")
    _preflight_json(raw, budget)
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_int=_integer, parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise WorkloadClientError("signed workload packet is not bounded strict JSON") from None
    budget.check()
    if type(value) is not dict:
        raise WorkloadClientError("signed workload packet must be an object")
    # Reject lone surrogate escapes as well as invalid original UTF-8, without
    # recursive traversal or exposing signed instructions/capabilities in errors.
    pending: list[object] = [value]
    visited = 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited % 1024 == 0:
            budget.check()
        if type(item) is dict:
            pending.extend(item.keys())
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
        elif type(item) is str:
            try:
                item.encode("utf-8")
            except UnicodeError:
                raise WorkloadClientError("signed workload JSON text is invalid") from None
    _charge(budget, json_nodes=visited)
    budget.check()
    return value


def _canonical(value: object, maximum: int, budget: Budget) -> bytes:
    budget.check()
    try:
        original = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise WorkloadClientError("signed workload canonical encoding failed") from None
    budget.check()
    if len(original) > maximum:
        raise WorkloadClientError("signed workload canonical encoding exceeds its bound")
    _charge(budget, input_bytes=len(original))
    return original


def _digest(original: bytes, budget=None) -> str:
    if budget is not None:
        _charge(budget, input_bytes=len(original), hashes=1)
    return "sha256:" + hashlib.sha256(original).hexdigest()


def _principal(value: object) -> None:
    if type(value) is not str or not value or len(value) > _MAX_PRINCIPAL_BYTES:
        raise WorkloadClientError("signed workload principal is invalid")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise WorkloadClientError("signed workload principal is invalid") from None
    if size > _MAX_PRINCIPAL_BYTES:
        raise WorkloadClientError("signed workload principal exceeds its bound")


def _live(packet: dict[str, object], now_ms: int) -> None:
    issued = packet.get("issuedAtEpochMs")
    expires = packet.get("expiresAtEpochMs")
    if (
        type(issued) is not int or type(expires) is not int
        or not 0 < issued <= now_ms < expires
        or not 1 <= expires - issued <= _MAX_LIFETIME_MS
    ):
        raise WorkloadClientError("signed workload packet is not within its original lifetime")


def _public_key(raw: bytes, budget: Budget) -> Ed25519PublicKey:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_KEY_BYTES:
        raise WorkloadClientError("signed workload public key original exceeds its bound")
    budget.check()
    _charge(budget, input_bytes=len(raw))
    try:
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey) or key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != raw:
            raise ValueError("public key profile")
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise WorkloadClientError("signed workload key must be canonical public-only Ed25519 PEM") from None
    budget.check()
    return key


def verify_signed_workload_packet(
    packet_raw: bytes,
    signing_key_raw: bytes,
    *,
    expected_principal: str,
    expected_nonce: str,
    budget: Budget,
) -> dict[str, object]:
    """Authenticate signed data only, using independently pinned input originals.

    No receipt flags or embedded keys are accepted as verification authority.
    Caller-owned transport/CA/identity admission and expiry checks on subsequent
    requests remain necessary; the returned mutable dictionary is not a token.
    """
    budget.check()
    _principal(expected_principal)
    if type(expected_nonce) is not str or _NONCE.fullmatch(expected_nonce) is None:
        raise WorkloadClientError("signed workload expected nonce is invalid")
    began_ms = time.time_ns() // 1_000_000
    packet = _parse_packet(packet_raw, budget)
    if "verificationReceipt" in packet:
        raise WorkloadClientError("signed workload input must not contain a verification receipt")
    if (
        set(packet) != _PACKET_FIELDS
        or packet.get("apiVersion") != "catchplate.agentEnrollment/v1"
        or packet.get("kind") != "AgentEnrollment"
    ):
        raise WorkloadClientError("signed workload packet schema is unsupported")
    _principal(packet.get("principalId"))
    if packet["principalId"] != expected_principal or packet.get("nonce") != expected_nonce:
        raise WorkloadClientError("signed workload principal or nonce does not match")
    _live(packet, began_ms)
    for field in (
        "tooling", "catchplate", "identity", "environment", "ca",
        "agentHandoff", "egress", "canaries",
    ):
        if type(packet[field]) is not dict:
            raise WorkloadClientError("signed workload packet object shape is invalid")
    if type(packet["allowedRoutes"]) is not list or type(packet["generatedAt"]) is not str:
        raise WorkloadClientError("signed workload packet field shape is invalid")
    pins = packet["pinning"]
    if type(pins) is not dict or set(pins) != _PIN_FIELDS:
        raise WorkloadClientError("signed workload pin inventory is invalid")
    for field in _DIGEST_PINS:
        if type(pins[field]) is not str or _SHA256.fullmatch(pins[field]) is None:
            raise WorkloadClientError("signed workload digest pin is invalid")
    for field in ("policySequence", "rollbackEpoch"):
        if type(pins[field]) is not int or pins[field] < 1:
            raise WorkloadClientError("signed workload sequence pin is invalid")
    if type(pins["releaseChannel"]) is not str or not pins["releaseChannel"]:
        raise WorkloadClientError("signed workload release channel pin is invalid")
    authenticity = packet["authenticity"]
    if type(authenticity) is not dict or set(authenticity) != {
        "statement", "statementSha256", "signature",
    }:
        raise WorkloadClientError("signed workload authenticity schema is invalid")
    statement = authenticity["statement"]
    if (
        type(statement) is not dict or set(statement) != _STATEMENT_FIELDS
        or statement.get("version") != "catchplate.agentEnrollmentSignature/v1"
    ):
        raise WorkloadClientError("signed workload statement schema is unsupported")
    for field in ("principalId", "nonce", "issuedAtEpochMs", "expiresAtEpochMs"):
        if type(statement[field]) is not type(packet[field]) or statement[field] != packet[field]:
            raise WorkloadClientError("signed workload statement scope does not match")
    for field in ("policyHash", "runtimeManifestDigest", "responseSigningKeyId"):
        if statement[field] != pins[field]:
            raise WorkloadClientError("signed workload statement pins do not match")
    unsigned_packet = {field: value for field, value in packet.items() if field != "authenticity"}
    if statement["packetSha256"] != _digest(_canonical(unsigned_packet, _MAX_PACKET_BYTES, budget), budget):
        raise WorkloadClientError("signed workload packet digest does not match")
    statement_original = _canonical(statement, _MAX_STATEMENT_BYTES, budget)
    if authenticity["statementSha256"] != _digest(statement_original, budget):
        raise WorkloadClientError("signed workload statement digest does not match")
    key = _public_key(signing_key_raw, budget)
    key_id = _digest(key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ), budget)
    if key_id != pins["responseSigningKeyId"]:
        raise WorkloadClientError("signed workload public key does not match the signed pin")
    encoded = authenticity["signature"]
    match = _SIGNATURE.fullmatch(encoded) if type(encoded) is str else None
    if match is None:
        raise WorkloadClientError("signed workload signature encoding is invalid")
    try:
        signature = base64.b64decode(match[1] + "==", altchars=b"-_", validate=True)
        if (
            len(signature) != 64
            or base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=") != match[1]
        ):
            raise ValueError("signature profile")
        budget.check()
        _charge(budget, hashes=1, input_bytes=len(statement_original))
        key.verify(signature, statement_original)
    except (InvalidSignature, ValueError, binascii.Error):
        raise WorkloadClientError("signed workload signature verification failed") from None
    budget.check()
    try:
        validate_enrollment_tooling(packet)
        validate_workload_transport(packet)
    except (ValueError, TypeError, UnicodeError):
        raise WorkloadClientError("signed workload tooling or transport requirements are invalid") from None
    ended_ms = time.time_ns() // 1_000_000
    if ended_ms < began_ms:
        raise WorkloadClientError("signed workload verification clock moved backwards")
    _live(packet, ended_ms)
    budget.check()
    return packet

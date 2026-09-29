"""Opaque public revocation originals in distinct bounded custody profiles.

Every continuation retains its exact request-record locator. The locator and
stage labels confer no authority and prove no remote commit. The one request
profile alone can be locally attempted; recovered attempts never permit send.
All other profiles are retention-only. Original lengths precede body slicing.
"""
from __future__ import annotations

import hashlib

from serverware import authority_contract as authority
from serverware import control_plane_custody_records as records


PREPARED_RECORD_MAGIC = b"SWCPV001"
IDENTITY_DOMAIN = b"serverware.controlPlanePublicWebAuthnRevocationRecord/v1"
REQUEST_FAMILY = "public-webauthn-revocation-request"
RETENTION_FAMILY = "public-webauthn-revocation-originals"
MAX_RECORD_BYTES = authority.MAX_RESULT_BYTES + 1024
_KIB, _MIB = 1024, 1024 * 1024
# Request originals: current-root enrollment, grant enrollment, caller
# enrollment, caller authorization, and the complete actual HTTP-purpose body.
PROFILES = (
    ("options", (4 * _MIB,)),
    ("request", (128 * _KIB, 16 * _KIB, 16 * _KIB, 64 * _KIB, 4 * _MIB)),
    ("prepared", (64 * _MIB, 512 * _KIB, 64 * _KIB, 4 * _KIB, 8 * _KIB, 16 * _KIB)),
    ("grant", (64 * _KIB,)),
    ("reserved", (128 * _KIB, 64 * _MIB, 128 * _KIB)),
    ("execution-locators", (71, 71)),
    ("sql-outcome", (32, 71, 71, 4096)),
    ("completion", (128 * _KIB, 128 * _KIB, 64 * _MIB)),
    ("approval-outcome", (4 * _MIB,)),
    # Retained BEFORE the current-root reserve contact. An absent reserve ACK
    # remains unknown and never permits this request to be sent again.
    ("computed", (128 * _KIB, 64 * _MIB)),
)
KINDS = tuple(kind for kind, _limits in PROFILES)


def _profile(kind):
    if type(kind) is not str or kind not in KINDS:
        raise records.CustodyRecordError("public revocation stage is not source fixed")
    return KINDS.index(kind)


def _lengths(index, lengths):
    limits = PROFILES[index][1]
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 0 <= size <= maximum
                for size, maximum in zip(lengths, limits))
            or sum(lengths) > authority.MAX_RESULT_BYTES):
        raise records.CustodyRecordError("public revocation originals exceed fixed frame bounds")
    optional = index == _profile("sql-outcome")
    if any(size < (0 if optional and number > 0 else 1) for number, size in enumerate(lengths)):
        raise records.CustodyRecordError("public revocation original is missing")


def _parent(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in value[7:])):
        raise records.CustodyRecordError("public revocation parent locator is not exact")
    return bytes.fromhex(value[7:])


def _digest(encoded):
    digest = hashlib.sha256()
    digest.update(len(IDENTITY_DOMAIN).to_bytes(2, "big"))
    digest.update(IDENTITY_DOMAIN)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def encode(kind, parent, originals):
    index = _profile(kind)
    if type(originals) is not tuple or any(type(raw) is not bytes for raw in originals):
        raise records.CustodyRecordError("public revocation requires immutable original byte tuples")
    lengths = tuple(len(raw) for raw in originals)
    _lengths(index, lengths)
    source = records._source_revision(authority.SOURCE_REVISION)
    raw_parent = _parent(parent)
    if (kind == "options") != (raw_parent == bytes(32)):
        raise records.CustodyRecordError("public revocation stage has an invalid predecessor")
    header = (PREPARED_RECORD_MAGIC + bytes((index,)) + len(source).to_bytes(2, "big")
        + raw_parent + source + b"".join(size.to_bytes(8, "big") for size in lengths))
    if len(header) + sum(lengths) > MAX_RECORD_BYTES:
        raise records.CustodyRecordError("public revocation framed originals exceed capacity")
    encoded = b"".join((header, *originals))
    return _digest(encoded), encoded


def decode_prepared(encoded):
    if (type(encoded) is not bytes or not 43 <= len(encoded) <= MAX_RECORD_BYTES
            or encoded[:8] != PREPARED_RECORD_MAGIC or encoded[8] >= len(PROFILES)):
        raise records.CustodyRecordError("public revocation record header is invalid")
    index, source_size = encoded[8], int.from_bytes(encoded[9:11], "big")
    if not 1 <= source_size <= records.MAX_SOURCE_REVISION_BYTES:
        raise records.CustodyRecordError("public revocation source token exceeds its bound")
    offset, count = 43 + source_size, len(PROFILES[index][1])
    body = offset + count * 8
    if body > len(encoded):
        raise records.CustodyRecordError("public revocation length vector is truncated")
    lengths = tuple(int.from_bytes(encoded[pos:pos + 8], "big")
        for pos in range(offset, body, 8))
    _lengths(index, lengths)
    if body + sum(lengths) != len(encoded):
        raise records.CustodyRecordError("public revocation original bodies have trailing or missing bytes")
    try:
        source = encoded[43:offset].decode("ascii")
    except UnicodeError as exc:
        raise records.CustodyRecordError("public revocation source is not ASCII") from exc
    records._source_revision(source)
    kind = PROFILES[index][0]
    raw_parent = encoded[11:43]
    if (kind == "options") != (raw_parent == bytes(32)):
        raise records.CustodyRecordError("public revocation predecessor is invalid")
    originals = [("sha256:" + raw_parent.hex()).encode("ascii")]
    for size in lengths:
        originals.append(encoded[body:body + size])
        body += size
    family = REQUEST_FAMILY if kind == "request" else RETENTION_FAMILY
    return records.PreparedRecord(family, kind, source, tuple(originals), _digest(encoded))

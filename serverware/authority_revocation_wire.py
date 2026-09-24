"""Private bounded ingestion of original signed revocation bytes.

This lexical preflight is not a replacement JSON parser or an authorization
check. The real parser follows only after its allocation/traversal reservation.
The actual signed verifier later captures all graphs and compares its canonical
envelope with the original bytes before signatures. QueryRead strings stay
opaque. External keys, roots, identities, request and clocks remain mandatory.
"""
from __future__ import annotations

import json

from serverware import authority_complete_query_batch as batch
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_plan_contract as contract
from serverware.authority_query_read_work import _ValidationWork, QueryReadWorkError


_EXPECTATIONS = plan._VERIFICATION_INPUTS - {"envelope"}
_MAX_INTEGER_BITS = 16_384
# ceil(16384 * log10(2)); the final bit-length check remains authoritative.
_MAX_INTEGER_DIGITS = 4_933


class RevocationWireError(ValueError):
    pass


def _integer(source, position):
    """Bounded decimal conversion without int(whole_token) or global settings.

    The preflight uses original bytes; json.loads supplies an exact str token
    to the same conversion. At most nine digits enter each small chunk. The
    decoder's ceiling does not widen the downstream encoder's host-dependent
    integer-to-string limit.
    """
    byte_source = type(source) is bytes

    def point(index):
        return source[index] if byte_source else ord(source[index])

    negative = point(position) == 45
    position += int(negative)
    start = position
    value = chunk = width = 0
    while position < len(source) and 48 <= point(position) <= 57:
        if position - start >= _MAX_INTEGER_DIGITS:
            raise RevocationWireError("revocation JSON integer exceeds its source bit bound")
        chunk = 10 * chunk + point(position) - 48
        width += 1
        position += 1
        if width == 9:
            value = value * 1_000_000_000 + chunk
            if value.bit_length() > _MAX_INTEGER_BITS:
                raise RevocationWireError("revocation JSON integer exceeds its source bit bound")
            chunk = width = 0
    if position == start:
        raise RevocationWireError("revocation JSON integer has no digits")
    if width:
        value = value * 10 ** width + chunk
    if value.bit_length() > _MAX_INTEGER_BITS:
        raise RevocationWireError("revocation JSON integer exceeds its source bit bound")
    return position, -value if negative else value


def _hex4(raw, position):
    if position + 4 > len(raw):
        raise RevocationWireError("revocation JSON Unicode escape is incomplete")
    value = 0
    for index in range(position, position + 4):
        point = raw[index]
        if 48 <= point <= 57:
            digit = point - 48
        elif 65 <= point <= 70:
            digit = point - 55
        elif 97 <= point <= 102:
            digit = point - 87
        else:
            raise RevocationWireError("revocation JSON Unicode escape is invalid")
        value = 16 * value + digit
    return value, position + 4


def _string_end(raw, position):
    position += 1
    while position < len(raw):
        point = raw[position]
        if point == 34:
            return position + 1
        if point < 32 or point > 127:
            raise RevocationWireError("revocation JSON strings require lossless ASCII transport")
        position += 1
        if point != 92:
            continue
        if position == len(raw):
            break
        escaped = raw[position]
        position += 1
        if escaped in (34, 92, 47, 98, 102, 110, 114, 116):
            continue
        if escaped != 117:
            raise RevocationWireError("revocation JSON string escape is invalid")
        value, position = _hex4(raw, position)
        if value == 0 or 0xDC00 <= value <= 0xDFFF:
            raise RevocationWireError("revocation JSON contains NUL or a lone surrogate")
        if 0xD800 <= value <= 0xDBFF:
            if position + 2 > len(raw) or raw[position] != 92 or raw[position + 1] != 117:
                raise RevocationWireError("revocation JSON contains a lone surrogate")
            low, position = _hex4(raw, position + 2)
            if not 0xDC00 <= low <= 0xDFFF:
                raise RevocationWireError("revocation JSON contains a lone surrogate")
    raise RevocationWireError("revocation JSON string is unterminated")


def _preflight(raw, work, *, maximum_nodes=contract.MAX_JSON_NODES,
               maximum_depth=contract.MAX_JSON_DEPTH):
    """Count valid JSON nodes exactly; malformed grammar still goes to loads.

    No token list or input-sized graph is allocated. The delimiter stack is
    source-depth bounded. Nodes include keys and primitive values at their
    semantic depth, so an empty container at depth128 is valid but its child
    at129 is not. Colons overcount rather than undercount hook pairs in invalid
    grammar; the real parser remains responsible for separators/key positions.
    """
    work.charge(input_bytes=len(raw))
    remaining_nodes = work.limits.max_json_nodes - work.json_nodes
    position = nodes = objects = pairs = 0
    stack = []

    def check():
        if nodes > maximum_nodes or nodes + objects + 2 * pairs > remaining_nodes:
            raise QueryReadWorkError("revocation JSON parser exceeds remaining node work")

    while position < len(raw):
        point = raw[position]
        if point in (32, 9, 10, 13, 44):
            position += 1
            continue
        if point == 58:
            pairs += 1
            check()
            position += 1
            continue
        if point in (93, 125):
            if not stack or stack.pop() != point:
                raise RevocationWireError("revocation JSON delimiters do not match")
            position += 1
            continue
        if len(stack) > maximum_depth:
            raise RevocationWireError("revocation JSON exceeds its source depth")
        nodes += 1
        objects += int(point == 123)
        check()
        if point in (91, 123):
            stack.append(93 if point == 91 else 125)
            position += 1
        elif point == 34:
            position = _string_end(raw, position)
        elif point == 45 or 48 <= point <= 57:
            position, _ = _integer(raw, position)
        elif raw.startswith(b"true", position):
            position += 4
        elif raw.startswith(b"false", position):
            position += 5
        elif raw.startswith(b"null", position):
            position += 4
        else:
            raise RevocationWireError("revocation JSON token is not lossless integer-only JSON")
    if stack:
        raise RevocationWireError("revocation JSON delimiters are incomplete")
    return nodes, objects + 2 * pairs


def _parse_integer(token):
    end, value = _integer(token, 0)
    if end != len(token):
        raise RevocationWireError("revocation JSON integer token changed")
    return value


def _reject_number(token):
    raise RevocationWireError("revocation JSON floats and nonfinite numbers are forbidden")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RevocationWireError("revocation JSON contains a duplicate decoded key")
        value[key] = item
    return value


def _decode_object(raw: bytes, *, work: _ValidationWork,
                   maximum_bytes=contract.MAX_PAYLOAD_BYTES,
                   maximum_nodes=contract.MAX_JSON_NODES,
                   maximum_depth=contract.MAX_JSON_DEPTH) -> dict:
    """Decode once on existing work, without making any trust/canonical claim.

    For B raw bytes, N JSON nodes (including keys), O objects and P members:
    scanner B/0 is debited before scanning, then decode/parser/bounded callbacks
    reserve3B/(N+O+2P) before ASCII decode or json.loads. The callback B is a
    bounded reservation, not exact visited-token length or process memory.
    Successful total is4B/(N+O+2P),0hashes. Later capture and canonical equality
    are separately charged by the genuine verifier on the same work object.
    """
    batch._SharedLedger(work)
    for value, ceiling in ((maximum_bytes, contract.MAX_PAYLOAD_BYTES),
                           (maximum_nodes, contract.MAX_JSON_NODES),
                           (maximum_depth, contract.MAX_JSON_DEPTH)):
        if type(value) is not int or not 1 <= value <= ceiling:
            raise RevocationWireError("revocation JSON bound exceeds its source ceiling")
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum_bytes:
        raise RevocationWireError("revocation envelope bytes are not exact and source-bounded")
    nodes, hook_nodes = _preflight(raw, work, maximum_nodes=maximum_nodes,
                                    maximum_depth=maximum_depth)
    work.charge(input_bytes=3 * len(raw), json_nodes=nodes + hook_nodes)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object,
            parse_int=_parse_integer, parse_float=_reject_number, parse_constant=_reject_number)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RevocationWireError("revocation envelope bytes are not valid bounded JSON") from exc
    if type(value) is not dict:
        raise RevocationWireError("revocation envelope root is not an object")
    return value


def _decode_envelope(raw: bytes, *, work: _ValidationWork) -> dict:
    """Preserve the signed-envelope decoder's exact source bounds and units."""
    return _decode_object(raw, work=work)


def _verify_signed_envelope_on_work(raw: bytes, *, work: _ValidationWork, **expectations):
    """Genuine raw-byte replay with only independent external expectations."""
    if len(expectations) != len(_EXPECTATIONS) or set(expectations) != _EXPECTATIONS:
        raise RevocationWireError("revocation raw verification expectations are not closed")
    envelope = _decode_envelope(raw, work=work)
    return plan._verify_signed_revocation_plan_on_work(envelope=envelope, work=work,
        original_envelope_bytes=raw, **expectations)

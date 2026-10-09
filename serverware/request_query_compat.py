"""Pure, bounded orderedFormV1 query inspection; not route authorization.

Only an explicitly opted-in, authenticated gmail.read.v1 route may use this
contract. Legacy parsers are unchanged. Callers must commit to BOTH raw_query
(None, empty, and nonempty are distinct) and ordered pairs in canonical v3,
then verify the actual dispatch target against that commitment. This module
never sorts, rewrites, dispatches, grants authority, or validates provider values.
"""
from dataclasses import dataclass


MODE = "orderedFormV1"
ADAPTER = "gmail.read.v1"
MAX_RAW_QUERY_BYTES = 8192
MAX_SEGMENTS = 64
MAX_PAIRS = 64
MAX_REPEATED_VALUES = 32
LIST_OPERATION = "gmail.messages.list"
GET_OPERATION = "gmail.message.get"
LIST_KEYS = frozenset({
    "alt", "includeSpamTrash", "labelIds", "maxResults", "pageToken",
    "prettyPrint", "q",
})
GET_KEYS = frozenset({"alt", "format", "metadataHeaders", "prettyPrint"})
# RFC3986 query characters, excluding '&' (handled only as a pair delimiter)
# and '%' (handled only as a strict escape). Raw spaces/non-ASCII/#/backslash
# are not URI query characters. Encoded punctuation remains ordinary data.
_RAW_COMPONENT_PUNCTUATION = frozenset("-._~!$'()*+,;=:@/?")
_HEX = frozenset("0123456789abcdefABCDEF")


class QueryCompatibilityError(ValueError):
    """A fixed, non-secret error code shared with the Rust helper."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class OrderedFormQuery:
    raw_query: str | None
    pairs: tuple[tuple[str, str], ...]


def _decode_component(raw: str) -> str:
    decoded = bytearray()
    index = 0
    while index < len(raw):
        character = raw[index]
        if character == "%":
            if index + 2 >= len(raw) or any(c not in _HEX for c in raw[index + 1:index + 3]):
                raise QueryCompatibilityError("query_invalid_escape")
            decoded.append(int(raw[index + 1:index + 3], 16))
            index += 3
            continue
        if character == "+":
            decoded.append(0x20)
        elif character.isascii() and (character.isalnum() or character in _RAW_COMPONENT_PUNCTUATION):
            decoded.append(ord(character))
        else:
            raise QueryCompatibilityError("query_invalid_wire")
        index += 1
    try:
        value = decoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise QueryCompatibilityError("query_invalid_utf8") from None
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F or c == "\\" for c in value):
        raise QueryCompatibilityError("query_forbidden_character")
    return value


def parse_query(raw_query: str | None) -> OrderedFormQuery:
    """Parse once using form-query semantics, retaining every wire distinction.

    '&' alone separates pairs; empty segments are skipped but count toward the
    segment bound. The first '=' separates name/value; bare names have empty
    values. '+' means space; percent escapes decode once as strict UTF-8. This
    syntactic parser does NOT authorize query names or repeated parameters.
    """
    if raw_query is None:
        return OrderedFormQuery(None, ())
    if not isinstance(raw_query, str):
        raise QueryCompatibilityError("query_invalid_type")
    if not raw_query.isascii():
        raise QueryCompatibilityError("query_invalid_wire")
    if len(raw_query) > MAX_RAW_QUERY_BYTES:
        raise QueryCompatibilityError("query_too_large")
    if raw_query == "":
        return OrderedFormQuery("", ())
    if raw_query.count("&") + 1 > MAX_SEGMENTS:
        raise QueryCompatibilityError("query_segment_limit")
    pairs: list[tuple[str, str]] = []
    for segment in raw_query.split("&"):
        if not segment:
            continue
        name_wire, _, value_wire = segment.partition("=")
        name = _decode_component(name_wire)
        if not name:
            raise QueryCompatibilityError("query_empty_name")
        value = _decode_component(value_wire)
        pairs.append((name, value))
        if len(pairs) > MAX_PAIRS:
            raise QueryCompatibilityError("query_pair_limit")
    return OrderedFormQuery(raw_query, tuple(pairs))


def validate_gmail_query(query: OrderedFormQuery, *, operation: str) -> None:
    """Check binding, operation names and cardinality, not provider values.

    Reparse before trusting a caller-constructed record. Existing Gmail adapter
    value predicates (including empty-value policy) must still run afterwards.
    """
    if not isinstance(query, OrderedFormQuery) or parse_query(query.raw_query) != query:
        raise QueryCompatibilityError("query_binding_mismatch")
    if operation == LIST_OPERATION:
        allowed, repeated = LIST_KEYS, "labelIds"
    elif operation == GET_OPERATION:
        allowed, repeated = GET_KEYS, "metadataHeaders"
    else:
        raise QueryCompatibilityError("query_operation_unsupported")
    counts: dict[str, int] = {}
    for name, _value in query.pairs:
        if name not in allowed:
            raise QueryCompatibilityError("query_name_denied")
        counts[name] = counts.get(name, 0) + 1
        if name == repeated:
            if counts[name] > MAX_REPEATED_VALUES:
                raise QueryCompatibilityError("query_repeat_limit")
        elif counts[name] > 1:
            raise QueryCompatibilityError("query_duplicate_singleton")


def parse_gmail_query(raw_query: str | None, *, operation: str) -> OrderedFormQuery:
    query = parse_query(raw_query)
    validate_gmail_query(query, operation=operation)
    return query

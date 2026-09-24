"""Hash-free admission of exact complete-query physical read markers.

These shapes describe explicit revocation, registration and aggregate staging.
They do not authenticate a supplied root, projection digest, interval, primary
key, population or clock. Genuine producers and proof engines still bind those
values. This module neither enables a public planner nor grants generic table
access, mutations or additional trace capacity.
"""
from __future__ import annotations

from typing import Any

from serverware import authority_complete_query as complete
from serverware import authority_contract
from serverware import authority_index_heads as heads
from serverware import authority_index_mutation_reader as mutation_reader
from serverware import authority_index_projection as projection
from serverware import authority_index_reader as reader
from serverware.authority_index_contract import I64_MAX, KEY_NIBBLES


PRIMARY_READ_PROFILE = "serverware.policyAuthorityCompletePrimaryRead/v1"
MUTATION_READ_PROFILE = mutation_reader.READ_PROFILE
_CONTEXT_FIELDS = frozenset({"profile", "queryId", "indexId", "projectionDigest",
                             "indexRevision", "rootDigest", "rootCount"})
_LEAF_FIELDS = _CONTEXT_FIELDS | {"lower", "upper", "limit"}
_NODE_FIELDS = _CONTEXT_FIELDS | {"prefixes", "limit"}
_PRIMARY_FIELDS = frozenset({"profile", "queryId", "indexId", "primaryId",
                             "primaryKeyDigest", "limit"})
_PREFIX_FIELDS = frozenset({"depth", "pathPrefix"})
_MUTATION_CONTEXT_FIELDS = frozenset({"profile", "indexId", "projectionDigest",
                                     "indexRevision", "rootDigest", "rootCount"})
_MUTATION_LEAF_FIELDS = _MUTATION_CONTEXT_FIELDS | {"targets", "limit"}
_MUTATION_NODE_FIELDS = _MUTATION_CONTEXT_FIELDS | {"prefixes", "limit"}
_HEX = frozenset("0123456789abcdef")


class IndexTraceError(ValueError):
    pass


def _closed(value: Any, fields: frozenset[str]) -> None:
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(name) is not str or len(name) > 32 for name in value)
            or set(value) != fields):
        raise IndexTraceError("complete read marker is not an exact closed object")


def _hex(value: Any, width: int) -> bool:
    return type(value) is str and len(value) == width and all(character in _HEX for character in value)


def _digest(value: Any) -> bool:
    return type(value) is str and len(value) == 71 and value[:7] == "sha256:" and _hex(value[7:], 64)


def _integer(value: Any, lower: int, upper: int) -> bool:
    return type(value) is int and lower <= value <= upper


def _source_role(operation: str, key: dict[str, Any]):
    if (type(key["queryId"]) is not str or not 1 <= len(key["queryId"]) <= 256
            or type(key["indexId"]) is not str or not 1 <= len(key["indexId"]) <= 128):
        raise IndexTraceError("complete read query identity is not bounded exact text")
    # The actual source roles supply tables/indexes. Do not construct query
    # DTOs or profile commitments here: their constructors perform hashing.
    names = (complete.ROLES if operation == complete.OPERATION else
             complete.REGISTRATION_ROLES if operation == complete.REGISTRATION_OPERATION else ())
    if operation == complete.STAGE_OPERATION:
        # Admit only the source's canonical bounded role spelling. Actual
        # rebinding still requires that ordinal in the owned stage arguments.
        prefix = f"serverware.policyAuthorityQuery/{operation}/"
        suffix = key["queryId"][len(prefix):] if key["queryId"].startswith(prefix) else ""
        parts = suffix.split("/")
        if len(parts) != 3 or parts[2] != "v1":
            raise IndexTraceError("stage physical query identity has an invalid source shape")
        try:
            role = complete._role(operation, parts[0])
        except complete.CompleteQueryError as exc:
            raise IndexTraceError("stage physical query role is not source declared") from exc
        if parts[1] != role.table or key["indexId"] != role.index_id:
            raise IndexTraceError("stage physical query/index pair differs from its source role")
        return role
    for name in names:
        role = complete._role(operation, name)
        query_id = f"serverware.policyAuthorityQuery/{operation}/{role.name}/{role.table}/v1"
        if key["queryId"] == query_id and key["indexId"] == role.index_id:
            return role
    raise IndexTraceError("complete read query/index pair is not source declared")


def _primary_id(value: Any) -> bool:
    # Match the genuine range reader's id codec, which permits an empty SQL
    # text primary key. Bound UTF-8 without creating an encoded copy or hash.
    if type(value) is not str or len(value) > 4096:
        return False
    size = 0
    for character in value:
        point = ord(character)
        if point == 0 or 0xD800 <= point <= 0xDFFF:
            return False
        size += 1 if point < 128 else 2 if point < 2048 else 3 if point < 65536 else 4
        if size > 4096:
            return False
    return True


def validate_complete_read_trace(operation: str, table: str, key: Any) -> None:
    """Admit only one exact existing source producer's physical read shape.

    Metadata reads are limited to the required head union and the source
    roles' leaf/node markers. Business reads here are exact member-PK fetches,
    never predicate scans. Hash-free shape admission is not proof of any value
    association, and must be explicitly enabled by the private planner caller.
    """
    if (type(operation) is not str or operation not in
            (complete.OPERATION, complete.REGISTRATION_OPERATION, complete.STAGE_OPERATION)
            or type(table) is not str or not 1 <= len(table) <= 128):
        raise IndexTraceError("complete read operation or table is not source admitted")
    if table == heads.HEAD_TABLE:
        try:
            heads.validate_head_trace_key(operation, key)
        except heads.IndexHeadReadError as exc:
            raise IndexTraceError("complete head marker differs from its source inventory") from exc
        return
    if table not in (reader.LEAF_TABLE, reader.NODE_TABLE):
        _closed(key, _PRIMARY_FIELDS)
        role = _source_role(operation, key)
        if (table != role.table or type(key["profile"]) is not str
                or key["profile"] != PRIMARY_READ_PROFILE or not _primary_id(key["primaryId"])
                or not _digest(key["primaryKeyDigest"]) or not _integer(key["limit"], 2, 2)):
            raise IndexTraceError("complete primary read marker is not its exact source role/key shape")
        return

    _closed(key, _LEAF_FIELDS if table == reader.LEAF_TABLE else _NODE_FIELDS)
    role = _source_role(operation, key)
    if (type(key["profile"]) is not str or key["profile"] != reader.READ_PROFILE
            or not _digest(key["projectionDigest"]) or not _digest(key["rootDigest"])
            or not _integer(key["indexRevision"], 0, I64_MAX)
            or not _integer(key["rootCount"], 0, I64_MAX)
            or key["indexRevision"] == 0 and key["rootCount"] != 0):
        raise IndexTraceError("complete range marker has invalid bounded source context")
    if table == reader.LEAF_TABLE:
        if (not _hex(key["lower"], KEY_NIBBLES)
                or key["upper"] is not None and (
                    not _hex(key["upper"], KEY_NIBBLES) or key["upper"] < key["lower"])
                or not _integer(key["limit"], 2, role.maximum_rows + 1)):
            raise IndexTraceError("complete leaf read bounds are not exact source-sized values")
        return

    prefixes = key["prefixes"]
    if (type(prefixes) is not list or not 1 <= len(prefixes) <= reader.MAX_NODE_IDENTITIES
            or not _integer(key["limit"], len(prefixes) + 1, len(prefixes) + 1)):
        raise IndexTraceError("complete node batch exceeds its exact identity/sentinel bound")
    previous = ""
    for prefix in prefixes:
        _closed(prefix, _PREFIX_FIELDS)
        if (not _integer(prefix["depth"], 1, KEY_NIBBLES)
                or not _hex(prefix["pathPrefix"], prefix["depth"])
                or prefix["pathPrefix"] <= previous):
            raise IndexTraceError("complete node prefixes are not depth-matched sorted unique identities")
        previous = prefix["pathPrefix"]


def validate_mutation_read_trace(operation: str, table: str, key: Any) -> None:
    """Check a private complete-query producer's fixed physical marker.

    This does not derive targets, prove OLD/NEW, or authenticate before heads.
    The real producer computes the request from genuine primary projections;
    signed replay separately requires its exact complete source-derived block.
    Ordinary complete-read permission is not public v3 writer admission.
    """
    if (type(operation) is not str or operation not in
            (complete.OPERATION, complete.REGISTRATION_OPERATION, complete.STAGE_OPERATION)
            or type(table) is not str or table not in (reader.LEAF_TABLE, reader.NODE_TABLE)):
        raise IndexTraceError("mutation read operation or table is not source admitted")
    _closed(key, _MUTATION_LEAF_FIELDS if table == reader.LEAF_TABLE else _MUTATION_NODE_FIELDS)
    allowed = frozenset(index_id
        for source_table in authority_contract.operation_spec(operation)["businessWrites"]
        for index_id in projection.index_ids_for_table(source_table))
    if (type(key["indexId"]) is not str or not 1 <= len(key["indexId"]) <= 128
            or key["indexId"] not in allowed
            or type(key["profile"]) is not str or key["profile"] != mutation_reader.READ_PROFILE
            or not _digest(key["projectionDigest"]) or not _digest(key["rootDigest"])
            or not _integer(key["indexRevision"], 0, I64_MAX)
            or not _integer(key["rootCount"], 0, I64_MAX)
            or key["indexRevision"] == 0 and key["rootCount"] != 0):
        raise IndexTraceError("mutation read marker has invalid bounded source context")
    values = key["targets"] if table == reader.LEAF_TABLE else key["prefixes"]
    if (type(values) is not list or not 1 <= len(values) <= mutation_reader.MAX_IDENTITIES
            or not _integer(key["limit"], len(values) + 1, len(values) + 1)):
        raise IndexTraceError("mutation read batch exceeds its exact identity/sentinel bound")
    previous = ""
    for value in values:
        if table == reader.LEAF_TABLE:
            if not _hex(value, KEY_NIBBLES) or value <= previous:
                raise IndexTraceError("mutation targets are not sorted unique exact keys")
            previous = value
        else:
            _closed(value, _PREFIX_FIELDS)
            if (not _integer(value["depth"], 1, KEY_NIBBLES)
                    or not _hex(value["pathPrefix"], value["depth"])
                    or value["pathPrefix"] <= previous):
                raise IndexTraceError("mutation prefixes are not depth-matched sorted unique identities")
            previous = value["pathPrefix"]

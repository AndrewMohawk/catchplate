"""Hash-free admission of exact complete-query physical read markers.

These shapes describe explicit revocation, registration, activation/delivery and aggregate staging,
plus completion's indexed-write frontier reads (not a complete-range family).
They do not authenticate a supplied root, projection digest, interval, primary
key, population or clock. Genuine producers and proof engines still bind those
values. This module neither enables a public planner nor grants generic table
access, mutations or additional trace capacity.
"""
from __future__ import annotations

from typing import Any

from catchplate import authority_challenge_id as challenge_ids
from catchplate import authority_complete_query as complete
from catchplate import authority_contract
from catchplate import authority_index_heads as heads
from catchplate import authority_index_mutation_reader as mutation_reader
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate.authority_index_contract import I64_MAX, KEY_NIBBLES


PRIMARY_READ_PROFILE = "catchplate.policyAuthorityCompletePrimaryRead/v1"
MUTATION_READ_PROFILE = mutation_reader.READ_PROFILE
COUNT_READ_PROFILE = "catchplate.policyAuthorityCountedIndexCountRead/v1"
CHALLENGE_CANDIDATE_READ_PROFILE = "catchplate.policyAuthorityChallengeCandidateRead/v1"
CHALLENGE_PRIMARY_READ_PROFILE = "catchplate.policyAuthorityChallengePrimaryRead/v1"
CHALLENGE_FRONTIER_READ_PROFILE = "catchplate.policyAuthorityChallengeWriteFrontierRead/v1"
CHALLENGE_CANDIDATE_PAGE_READ_PROFILE = "catchplate.policyAuthorityChallengeCandidatePageRead/v1"
RECOVERY_HISTORY_CANDIDATE_READ_PROFILE = "catchplate.policyAuthorityRecoveryHistoryCandidateRead/v1"
RECOVERY_HISTORY_PRIMARY_READ_PROFILE = "catchplate.policyAuthorityRecoveryHistoryPrimaryRead/v1"
_HISTORY_CANDIDATE_FIELDS = frozenset({
    "profile", "ordinal", "indexId", "projectionDigest", "indexRevision",
    "rootDigest", "rootCount", "lower", "upper", "limit",
})
_HISTORY_PRIMARY_FIELDS = frozenset({
    "profile", "ordinal", "indexId", "primaryId", "primaryKeyDigest", "limit",
})
_CHALLENGE_CANDIDATE_FIELDS = frozenset({
    "profile", "phase", "indexId", "projectionDigest", "indexRevision",
    "rootDigest", "rootCount", "lower", "upper", "descending", "offset", "limit",
})
_CHALLENGE_PRIMARY_FIELDS = frozenset({
    "profile", "phase", "indexId", "primaryId", "primaryKeyDigest", "limit",
})
_CHALLENGE_FRONTIER_FIELDS = frozenset({
    "profile", "indexId", "projectionDigest", "indexRevision", "rootDigest",
    "rootCount", "ordinal", "parentCount", "parents", "limit",
})
_CHALLENGE_PHASE_INDEX = {
    "expire": "webauthn_challenge_unused_global",
    "old": "webauthn_challenge_terminal_unreferenced_global",
    "overflow": "webauthn_challenge_terminal_unreferenced_global",
}
_CHALLENGE_PRIMARY_PHASE_INDEX = {
    **_CHALLENGE_PHASE_INDEX,
    "scope": "webauthn_challenge_scope_unused",
}
_CHALLENGE_CANDIDATE_PAGE_FIELDS = _CHALLENGE_CANDIDATE_FIELDS | {"baseOffset", "ordinal"}
_COUNT_FIELDS = frozenset({"profile", "indexId", "projectionDigest", "indexRevision",
                          "rootDigest", "rootCount", "lower", "upper", "prefixes", "limit"})
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
             complete.REGISTRATION_ROLES if operation == complete.REGISTRATION_OPERATION else
             complete.ACTIVATION_ROLES if operation == complete.ACTIVATION_OPERATION else
             complete.DELIVERY_ROLES if operation == complete.DELIVERY_OPERATION else ())
    if operation == complete.STAGE_OPERATION:
        # Admit only the source's canonical bounded role spelling. Actual
        # rebinding still requires that ordinal in the owned stage arguments.
        prefix = f"catchplate.policyAuthorityQuery/{operation}/"
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
        query_id = f"catchplate.policyAuthorityQuery/{operation}/{role.name}/{role.table}/v1"
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
            (complete.OPERATION, complete.REGISTRATION_OPERATION, complete.STAGE_OPERATION,
             complete.ACTIVATION_OPERATION, complete.DELIVERY_OPERATION)
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
    """Check a private indexed-write producer's fixed physical marker.

    This does not derive targets, prove OLD/NEW, or authenticate before heads.
    The real producer computes the request from genuine primary projections;
    signed replay separately requires its exact complete source-derived block.
    Ordinary complete-read permission is not public v3 writer admission.
    """
    if (type(operation) is not str or operation not in
            (complete.OPERATION, complete.REGISTRATION_OPERATION, complete.STAGE_OPERATION,
             complete.ACTIVATION_OPERATION, complete.DELIVERY_OPERATION, heads.COMPLETION_OPERATION,
             heads.JIT_RECEIPT_OPERATION, *heads.CHALLENGE_OPERATIONS, *heads.RECOVERY_OPERATIONS)
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


def validate_count_read_trace(operation: str, table: str, key: Any) -> None:
    """Only the private challenge/history families' fixed node-count shapes.

    This hash-free physical permission authenticates no supplied root, count
    or interval. The successor must separately derive each role/cutoff from
    its original request and replay the actual frontier against current heads.
    No leaf scan, SQL COUNT result or caller-selected table/profile is allowed.
    """
    if (type(operation) is not str or operation not in (*heads.CHALLENGE_OPERATIONS, *heads.RECOVERY_HISTORY_OPERATIONS)
            or type(table) is not str or table != reader.NODE_TABLE):
        raise IndexTraceError("count read operation or table is not source admitted")
    # Scope replacement count is a separate source-owned maintenance role.
    # Its exact type/user/scope partition is rederived by counts.scope_interval;
    # the private writer already captures this profile in its full nine heads.
    allowed = ((*heads.CHALLENGE_COUNT_IDS, "webauthn_challenge_scope_unused")
        if operation in heads.CHALLENGE_OPERATIONS else (heads.RECOVERY_HISTORY_ID,))
    _closed(key, _COUNT_FIELDS)
    if (type(key["profile"]) is not str or key["profile"] != COUNT_READ_PROFILE
            or type(key["indexId"]) is not str or key["indexId"] not in allowed
            or not _digest(key["projectionDigest"]) or not _digest(key["rootDigest"])
            or not _integer(key["indexRevision"], 0, I64_MAX)
            or not _integer(key["rootCount"], 0, I64_MAX)
            or key["indexRevision"] == 0 and key["rootCount"] != 0
            or not _hex(key["lower"], KEY_NIBBLES)
            or key["upper"] is not None and (
                not _hex(key["upper"], KEY_NIBBLES) or key["upper"] < key["lower"])):
        raise IndexTraceError("count read marker has invalid bounded source context")
    prefixes = key["prefixes"]
    if (type(prefixes) is not list or not 1 <= len(prefixes) <= reader.MAX_NODE_IDENTITIES
            or not _integer(key["limit"], len(prefixes) + 1, len(prefixes) + 1)):
        raise IndexTraceError("count node batch exceeds its exact identity/sentinel bound")
    previous = ""
    for prefix in prefixes:
        _closed(prefix, _PREFIX_FIELDS)
        if (not _integer(prefix["depth"], 1, KEY_NIBBLES)
                or not _hex(prefix["pathPrefix"], prefix["depth"])
                or prefix["pathPrefix"] <= previous):
            raise IndexTraceError("count node prefixes are not depth-matched sorted unique identities")
        previous = prefix["pathPrefix"]


def validate_challenge_frontier_read_trace(operation: str, table: str, key: Any) -> None:
    """Admit one compact source-owned challenge write-frontier page shape.

    The private producer derives sorted ancestor geometry from actual OLD/NEW
    targets. This marker grants no caller-selected geometry or root verdict;
    compound replay must bind all page originals to that same target set.
    """
    if (type(operation) is not str or operation not in heads.CHALLENGE_OPERATIONS
            or type(table) is not str or table != reader.NODE_TABLE):
        raise IndexTraceError("challenge frontier operation/table is not source admitted")
    _closed(key, _CHALLENGE_FRONTIER_FIELDS)
    allowed = projection.index_ids_for_table("webauthn_challenges")
    if (len(allowed) != 9 or type(key["indexId"]) is not str or key["indexId"] not in allowed
            or type(key["profile"]) is not str or key["profile"] != CHALLENGE_FRONTIER_READ_PROFILE
            or not _digest(key["projectionDigest"]) or not _digest(key["rootDigest"])
            or not _integer(key["indexRevision"], 0, I64_MAX)
            or not _integer(key["rootCount"], 0, I64_MAX)
            or key["indexRevision"] == 0 and key["rootCount"] != 0
            or not _integer(key["parentCount"], 1, 1 + KEY_NIBBLES * 512)
            or not _integer(key["ordinal"], 0, (key["parentCount"] - 1) // 16)
            or not _integer(key["limit"], 256, 256)):
        raise IndexTraceError("challenge frontier marker has invalid bounded source context")
    parents = key["parents"]
    expected_size = min(16, key["parentCount"] - 16 * key["ordinal"])
    if type(parents) is not list or len(parents) != expected_size:
        raise IndexTraceError("challenge frontier parent page differs from its exact source size")
    previous = None
    for prefix in parents:
        if (type(prefix) is not str or not 0 <= len(prefix) < KEY_NIBBLES
                or not _hex(prefix, len(prefix)) or previous is not None and prefix <= previous):
            raise IndexTraceError("challenge frontier parents are not sorted unique proper prefixes")
        previous = prefix
    if (parents[0] == "") is not (key["ordinal"] == 0):
        raise IndexTraceError("challenge frontier root parent is not in its exact first page")


def validate_challenge_candidate_page_trace(operation: str, table: str, key: Any) -> None:
    """Only the private source-window paging marker, not generic OFFSET reads."""
    if (type(operation) is not str or operation not in heads.CHALLENGE_OPERATIONS
            or type(table) is not str or table != reader.LEAF_TABLE):
        raise IndexTraceError("candidate page operation/table is not source admitted")
    _closed(key, _CHALLENGE_CANDIDATE_PAGE_FIELDS)
    if (type(key["phase"]) is not str or key["phase"] not in _CHALLENGE_PRIMARY_PHASE_INDEX
            or type(key["indexId"]) is not str or key["indexId"] != _CHALLENGE_PRIMARY_PHASE_INDEX[key["phase"]]
            or type(key["profile"]) is not str or key["profile"] != CHALLENGE_CANDIDATE_PAGE_READ_PROFILE
            or not _digest(key["projectionDigest"]) or not _digest(key["rootDigest"])
            or not _integer(key["indexRevision"], 0, I64_MAX)
            or not _integer(key["rootCount"], 0, I64_MAX)
            or key["indexRevision"] == 0 and key["rootCount"] != 0
            or not _hex(key["lower"], KEY_NIBBLES)
            or key["upper"] is not None and (
                not _hex(key["upper"], KEY_NIBBLES) or key["upper"] < key["lower"])
            or key["descending"] is not (key["phase"] == "overflow")
            or not _integer(key["baseOffset"], 0, 1000000 if key["phase"] == "overflow" else 0)
            or not _integer(key["ordinal"], 0, 24)
            or not _integer(key["offset"], 0, 1006144)
            or key["offset"] != key["baseOffset"] + 256 * key["ordinal"]
            or not _integer(key["limit"], 256, 256)):
        raise IndexTraceError("candidate page marker differs from its fixed source window")


def validate_challenge_read_trace(operation: str, table: str, key: Any) -> None:
    """Admit only the private challenge reader's fixed candidate/PK shapes.

    Candidate SQL observations are not membership, count or rank authority.
    The successor separately derives the original cutoff/role, authenticates
    complete intervals and primary originals, and replays the exact phase.
    This adds no generic range, table or public v3 admission.
    """
    if type(table) is str and table == reader.NODE_TABLE:
        validate_challenge_frontier_read_trace(operation, table, key)
        return
    if (type(key) is dict and type(key.get("profile")) is str
            and key["profile"] == CHALLENGE_CANDIDATE_PAGE_READ_PROFILE):
        validate_challenge_candidate_page_trace(operation, table, key)
        return
    if (type(operation) is not str or operation not in heads.CHALLENGE_OPERATIONS
            or type(table) is not str or table not in (reader.LEAF_TABLE, "webauthn_challenges")):
        raise IndexTraceError("challenge read operation or table is not source admitted")
    primary = table == "webauthn_challenges"
    _closed(key, _CHALLENGE_PRIMARY_FIELDS if primary else _CHALLENGE_CANDIDATE_FIELDS)
    phase_indexes = _CHALLENGE_PRIMARY_PHASE_INDEX if primary else _CHALLENGE_PHASE_INDEX
    if (type(key["phase"]) is not str or key["phase"] not in phase_indexes
            or type(key["indexId"]) is not str
            or key["indexId"] != phase_indexes[key["phase"]]
            or type(key["profile"]) is not str
            or key["profile"] != (CHALLENGE_PRIMARY_READ_PROFILE if primary
                                  else CHALLENGE_CANDIDATE_READ_PROFILE)):
        raise IndexTraceError("challenge read marker differs from its fixed phase/profile")
    if primary:
        try:
            challenge_ids.require_generated(key["primaryId"])
        except ValueError as exc:
            raise IndexTraceError("challenge primary ID is outside the fresh source domain") from exc
        if not _digest(key["primaryKeyDigest"]) or not _integer(key["limit"], 2, 2):
            raise IndexTraceError("challenge primary read lacks its exact key/sentinel shape")
        return
    if (not _digest(key["projectionDigest"]) or not _digest(key["rootDigest"])
            or not _integer(key["indexRevision"], 0, I64_MAX)
            or not _integer(key["rootCount"], 0, I64_MAX)
            or key["indexRevision"] == 0 and key["rootCount"] != 0
            or not _hex(key["lower"], KEY_NIBBLES)
            or key["upper"] is not None and (
                not _hex(key["upper"], KEY_NIBBLES) or key["upper"] < key["lower"])
            or key["descending"] is not (key["phase"] == "overflow")
            or not _integer(key["offset"], 0, 1000000 if key["phase"] == "overflow" else 0)
            or not _integer(key["limit"], 256, 256)):
        raise IndexTraceError("challenge candidate bounds are not exact source-sized values")


def validate_recovery_history_read_trace(operation: str, table: str, key: Any) -> None:
    """Only the source-owned history phase's head/count/candidate/PK shapes.

    No supplied ordinal, interval, count or row establishes a complete family.
    The compound owner and independent verifier admit original roots/clock,
    contiguous pages and aggregate count. Existing public v3 remains closed.
    """
    if (type(operation) is not str or operation not in heads.RECOVERY_HISTORY_OPERATIONS
            or type(table) is not str):
        raise IndexTraceError("history read operation/table is not source admitted")
    if table == heads.HEAD_TABLE:
        try:
            heads.validate_head_trace_key(operation, key)
        except heads.IndexHeadReadError as exc:
            raise IndexTraceError("history head marker differs from its source inventory") from exc
        return
    if table == reader.NODE_TABLE:
        validate_count_read_trace(operation, table, key)
        return
    if table not in (reader.LEAF_TABLE, "webauthn_credentials"):
        raise IndexTraceError("history marker cannot select another physical table")
    primary = table == "webauthn_credentials"
    _closed(key, _HISTORY_PRIMARY_FIELDS if primary else _HISTORY_CANDIDATE_FIELDS)
    if (type(key["profile"]) is not str
            or key["profile"] != (RECOVERY_HISTORY_PRIMARY_READ_PROFILE if primary
                                  else RECOVERY_HISTORY_CANDIDATE_READ_PROFILE)
            or type(key["indexId"]) is not str or key["indexId"] != heads.RECOVERY_HISTORY_ID
            or not _integer(key["ordinal"], 0, 9999)):
        raise IndexTraceError("history marker is not its fixed profile/page shape")
    if primary:
        if (not _primary_id(key["primaryId"]) or not _digest(key["primaryKeyDigest"])
                or not _integer(key["limit"], 2, 2)):
            raise IndexTraceError("history primary marker is not its exact key/sentinel shape")
        return
    if (not _digest(key["projectionDigest"]) or not _digest(key["rootDigest"])
            or not _integer(key["indexRevision"], 0, I64_MAX)
            or not _integer(key["rootCount"], 0, I64_MAX)
            or key["indexRevision"] == 0 and key["rootCount"] != 0
            or not _hex(key["lower"], KEY_NIBBLES)
            or key["upper"] is not None and (
                not _hex(key["upper"], KEY_NIBBLES) or key["upper"] < key["lower"])
            or not _integer(key["limit"], 1, 1)):
        raise IndexTraceError("history candidate bounds differ from the fixed one-row phase")

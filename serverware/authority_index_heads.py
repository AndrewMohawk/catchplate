"""Capture source-required counted heads in the caller's read transaction.

These immutable observations are not independently current roots, population
proofs, enrolled checkpoints or successful-verifier capabilities. The caller
keeps the same read-only MVCC transaction for head, range and primary reads.
This module creates no connection, transaction, lock, head or replacement
allowance. Potential writable profiles are captured even when a later genuine
kernel produces no mutation for them; proof consumers still select their exact
source-role plus actual-write subset.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from serverware import authority_complete_query as complete
from serverware import authority_contract
from serverware import authority_index_contract as counted
from serverware import authority_index_projection as projection
from serverware import authority_index_range as ranges
from serverware import authority_index_reader as reader
from serverware.authority_query_read_work import _ValidationWork


READ_PROFILE = "serverware.policyAuthorityCountedHeadRead/v1"
HEAD_TABLE = "policy_authority_counted_index_heads"
MAX_HEADS = 11
_FIELDS = ("index_id", "table_name", "counted_profile", "projection_digest",
           "projection_manifest_digest", "index_revision", "root_digest", "leaf_count")
_TRACE_FIELDS = frozenset({"profile", "indexIds", "rowLimit"})
_HEAD_SELECT = ", ".join(
    reader._integer_sql("head", name, 0, counted.I64_MAX)
    if name in ("index_revision", "leaf_count") else
    reader._text_sql("head", name, 71 if name.endswith("digest") else 1,
                     71 if name.endswith("digest") else 128)
    for name in _FIELDS
)


class IndexHeadReadError(reader.IndexReadError):
    pass


@dataclass(frozen=True, slots=True)
class CapturedIndexHead:
    """Owned scalar observation; freely constructible and never an authority."""

    index_id: str
    table: str
    counted_profile: str
    projection_digest: str
    projection_manifest_digest: str
    index_revision: int
    index_root: counted.CountedNode


def required_index_ids(operation: str, *, arguments=None, queries=None) -> tuple[str, ...]:
    """Hash-free fixed inventory, never a caller-selected index subset.

    Revocation preserves its existing role/potential-write union and no-context
    API. Registration is acquisition-only here: its exact two/four read heads
    follow the actual argument mode and the already rebound query family. This
    does not grant registration mutation-frontier or public planner admission.
    """
    if (type(operation) is not str or not 1 <= len(operation) <= 128
            or operation not in (complete.OPERATION, complete.REGISTRATION_OPERATION)):
        raise IndexHeadReadError("counted head operation has no declared complete roles")
    if operation == complete.REGISTRATION_OPERATION or arguments is not None or queries is not None:
        if type(arguments) is not dict or type(queries) is not tuple:
            raise IndexHeadReadError("counted head acquisition requires actual family arguments and queries")
        names = complete.family_roles(operation, arguments=arguments)
        limits = complete.family_limits(operation, arguments=arguments)
        if (len(queries) != limits["query_count"] or len(queries) != len(names)
                or any(type(query) is not complete.CompleteIndexQuery
                       or query.operation != operation for query in queries)
                or (operation == complete.REGISTRATION_OPERATION
                    and tuple(query.role for query in queries) != names)
                or {query.role for query in queries} != set(names)):
            raise IndexHeadReadError("counted head queries differ from the actual argument family")
    else:
        names = complete.ROLES
    # role_manifest constructs/hashes profiles. Use its genuine fixed role
    # definitions instead; trace validation must remain hash-free.
    roles = tuple(complete._role(operation, name) for name in names)
    spec = authority_contract.operation_spec(operation)
    identities = {role.index_id for role in roles}
    if operation == complete.OPERATION:
        for table in spec["businessWrites"]:
            identities.update(projection.index_ids_for_table(table))
    elif len(identities) != limits["head_count"]:
        raise IndexHeadReadError("registration counted heads differ from the source family bound")
    result = tuple(sorted(identities))
    if not roles or not 1 <= len(result) <= MAX_HEADS:
        raise IndexHeadReadError("counted head source inventory is not bounded")
    return result


def validate_head_trace_key(operation: str, key: Any, *, arguments=None, queries=None) -> None:
    """Validate one physical source-owned SELECT marker without hashing."""
    if type(operation) is not str:
        raise IndexHeadReadError("counted head operation is not an exact source identity")
    if operation == complete.REGISTRATION_OPERATION and arguments is None and queries is None:
        # Trace markers carry no mode authority. Admit only the two literal
        # source inventories here; the actual producer below binds precisely
        # one to its owned arguments and complete query family before SQL.
        inventories = tuple(tuple(sorted(complete._role(operation, name).index_id for name in names))
            for names in (complete.REGISTRATION_BASE_ROLES, complete.REGISTRATION_ROLES))
    else:
        inventories = (required_index_ids(operation, arguments=arguments, queries=queries),)
    if (type(key) is not dict or len(key) != len(_TRACE_FIELDS)
            or any(type(name) is not str or len(name) > 32 for name in key)
            or set(key) != _TRACE_FIELDS
            or type(key["profile"]) is not str or key["profile"] != READ_PROFILE
            or type(key["indexIds"]) is not list or not 1 <= len(key["indexIds"]) <= MAX_HEADS
            or any(type(value) is not str or not 1 <= len(value) <= 128
                   for value in key["indexIds"])
            or tuple(key["indexIds"]) not in inventories
            or type(key["rowLimit"]) is not int or key["rowLimit"] != len(key["indexIds"]) + 1):
        raise IndexHeadReadError("counted head trace does not match the exact source inventory")


def _source_context(identities: tuple[str, ...], work: _ValidationWork):
    profiles, empty = {}, {}
    for identity in identities:
        descriptor = projection._definition(identity).document()
        work.prepare_encoding(descriptor, ensure_ascii=False)
        work.charge(hashes=1)
        profile = projection.profile_for(identity)
        profiles[identity] = profile
        ranges._prepare_empty_work(profile, "", work)
        empty[identity] = counted.empty_node(profile, "").digest
    manifest_document = [projection._definition(name).document() for name in projection.INDEX_IDS]
    work.prepare_encoding(manifest_document, ensure_ascii=False)
    work.charge(hashes=1)
    return profiles, empty, projection.projection_manifest_digest()


def _owned_row(raw: Any, acquisition, work: _ValidationWork) -> dict[str, Any]:
    if (type(raw) is not dict or len(raw) != len(_FIELDS)
            or any(type(name) is not str or len(name) > 32 for name in raw)
            or set(raw) != set(_FIELDS)):
        raise IndexHeadReadError("counted head row is not closed")
    for name in _FIELDS:
        value = raw[name]
        if name in ("index_revision", "leaf_count"):
            if type(value) is not int or not 0 <= value <= counted.I64_MAX:
                raise IndexHeadReadError("counted head integer is not exact nonnegative int64")
        elif (type(value) is not str or not 1 <= len(value) <= 128
              or not value.isascii() or "\x00" in value
              or name.endswith("digest") and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None):
            raise IndexHeadReadError("counted head scalar is not bounded exact source text")
    acquisition.charge("head", raw, _FIELDS)
    work.prepare_copy(raw)
    return raw.copy()


def read_operation_index_heads(
    cursor: Any, *, operation: str, trace: Any, work: _ValidationWork,
    acquisition: reader._ReadAcquisitionBudget,
    arguments=None, queries=None,
) -> tuple[CapturedIndexHead, ...]:
    """Read every potential source-required head once, without locking it.

    The existing shared acquisition ledger admits parameters before trace/SQL,
    charges bounded returned scalar frames and poisons caught nested failures.
    Source profiles/manifest reserve actual encoding plus 2*n+1 total hashes;
    empty-root hash frames and raw-row ownership copies are charged separately.
    Fixed bounded metadata checks are not generic CPU/allocation accounting.
    """
    if type(acquisition) is not reader._ReadAcquisitionBudget:
        raise IndexHeadReadError("counted heads require the actual shared acquisition ledger")
    with acquisition.scope(cursor, trace, work):
        identities = required_index_ids(operation, arguments=arguments, queries=queries)
        if type(getattr(trace, "operation", None)) is not str or trace.operation != operation:
            raise IndexHeadReadError("counted head trace operation changed")
        profiles, empty, manifest = _source_context(identities, work)
        key = {"profile": READ_PROFILE, "indexIds": list(identities), "rowLimit": len(identities) + 1}
        validate_head_trace_key(operation, key, arguments=arguments, queries=queries)
        placeholders = ", ".join("%s" for _ in identities)
        rows = acquisition.read(HEAD_TABLE, key,
            f"SELECT {_HEAD_SELECT} FROM serverware_metadata.{HEAD_TABLE} AS head "
            f"WHERE head.index_id IN ({placeholders}) "
            'ORDER BY head.index_id COLLATE "C" LIMIT %s',
            (*identities, len(identities) + 1), len(identities))
        if len(rows) != len(identities):
            raise IndexHeadReadError("counted head inventory is missing required rows")
        owned = tuple(_owned_row(row, acquisition, work) for row in rows)
        result = []
        for identity, row in zip(identities, owned):
            profile = profiles[identity]
            if (row["index_id"] != identity or row["table_name"] != profile.table
                    or row["counted_profile"] != counted.PROFILE
                    or row["projection_digest"] != profile.projection_digest
                    or row["projection_manifest_digest"] != manifest):
                raise IndexHeadReadError("counted head order or source commitments changed")
            revision, count, digest = row["index_revision"], row["leaf_count"], row["root_digest"]
            if ((revision == 0 and count != 0)
                    or (count == 0) != (digest == empty[identity])):
                raise IndexHeadReadError("counted head revision or canonical empty root is invalid")
            result.append(CapturedIndexHead(identity, profile.table, counted.PROFILE,
                profile.projection_digest, manifest, revision, counted.CountedNode(digest, count)))
        acquisition.require_active()
        return tuple(result)

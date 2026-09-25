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
COMPLETION_OPERATION = "webauthn.trust.complete"
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


def required_index_ids(operation: str, *, arguments=None, queries=None,
                       include_write_heads: bool = False) -> tuple[str, ...]:
    """Hash-free fixed inventory, never a caller-selected index subset.

    Revocation preserves its existing role/potential-write union and no-context
    API. Registration/staging read heads follow their rebound argument family;
    a private transition owner can additionally require every
    potential source-write profile. Completion has exact primary-key reads,
    not a complete-range family: its private writer must explicitly request
    every potential write head with no family arguments or queries. No
    arbitrary index subset is accepted.
    """
    if (type(include_write_heads) is not bool
            or type(operation) is not str or not 1 <= len(operation) <= 128
            or operation not in (complete.OPERATION, complete.REGISTRATION_OPERATION,
                                 complete.STAGE_OPERATION, COMPLETION_OPERATION)):
        raise IndexHeadReadError("counted head operation has no declared source inventory")
    if operation == COMPLETION_OPERATION:
        if not include_write_heads or arguments is not None or queries is not None:
            raise IndexHeadReadError("completion heads require explicit write-only source admission")
        identities = {index_id
            for table in authority_contract.operation_spec(operation)["businessWrites"]
            for index_id in projection.index_ids_for_table(table)}
        # The only indexed completion write is its publication. These three
        # profiles are maintained together even when some keys are unchanged.
        if identities != {"webauthn_publication_bundle_digest", "webauthn_publication_status",
                          "webauthn_publication_generation"}:
            raise IndexHeadReadError("completion write heads differ from the fixed source inventory")
        return tuple(sorted(identities))
    if operation != complete.OPERATION or arguments is not None or queries is not None:
        if type(arguments) is not dict or type(queries) is not tuple:
            raise IndexHeadReadError("counted head acquisition requires actual family arguments and queries")
        names = complete.family_roles(operation, arguments=arguments)
        limits = complete.family_limits(operation, arguments=arguments)
        if (len(queries) != limits["query_count"] or len(queries) != len(names)
                or any(type(query) is not complete.CompleteIndexQuery
                       or query.operation != operation for query in queries)
                or (operation != complete.OPERATION
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
    if operation != complete.OPERATION and len(identities) != limits["head_count"]:
        raise IndexHeadReadError("counted heads differ from the source family bound")
    if operation == complete.OPERATION or include_write_heads:
        for table in spec["businessWrites"]:
            identities.update(projection.index_ids_for_table(table))
    result = tuple(sorted(identities))
    if not roles or not 1 <= len(result) <= MAX_HEADS:
        raise IndexHeadReadError("counted head source inventory is not bounded")
    return result


def validate_head_trace_key(operation: str, key: Any, *, arguments=None, queries=None,
                            include_write_heads: bool = False) -> None:
    """Validate one physical source-owned SELECT marker without hashing."""
    if type(operation) is not str or type(include_write_heads) is not bool:
        raise IndexHeadReadError("counted head operation is not an exact source identity")
    if operation in (complete.REGISTRATION_OPERATION, complete.STAGE_OPERATION) and arguments is None and queries is None:
        # Trace markers carry no mode authority. The actual producer binds one
        # fixed mode/read-or-read-write inventory before SQL. Trace admission
        # alone cannot choose a subset or confer any operation authority.
        write_ids = {index_id for table in authority_contract.operation_spec(operation)["businessWrites"]
                     for index_id in projection.index_ids_for_table(table)}
        families = ((complete.REGISTRATION_BASE_ROLES, complete.REGISTRATION_ROLES)
            if operation == complete.REGISTRATION_OPERATION else
            (complete.STAGE_BASE_ROLES, complete.STAGE_BASE_ROLES + (
                "withdrawal_000_sessions_pending_webauthn", "withdrawal_000_sessions_active",
                "withdrawal_000_grants", "withdrawal_000_approvals")))
        inventories = tuple(tuple(sorted({complete._role(operation, name).index_id for name in names}
                                         | (write_ids if with_writes else set())))
            for names in families
            for with_writes in (False, True))
    else:
        inventories = (required_index_ids(operation, arguments=arguments, queries=queries,
                                          include_write_heads=include_write_heads),)
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
    arguments=None, queries=None, include_write_heads: bool = False,
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
        identities = required_index_ids(operation, arguments=arguments, queries=queries,
                                        include_write_heads=include_write_heads)
        key = {"profile": READ_PROFILE, "indexIds": list(identities), "rowLimit": len(identities) + 1}
        validate_head_trace_key(operation, key, arguments=arguments, queries=queries,
                                include_write_heads=include_write_heads)
        return _read_index_heads_on_scope(cursor, operation=operation, identities=identities,
            trace=trace, work=work, acquisition=acquisition)


def _read_index_heads_on_scope(cursor, *, operation, identities, trace, work, acquisition):
    """Read real head rows inside an already admitted source acquisition scope.

    The fixed caller derives its entire source inventory and admits the exact
    physical marker through its own trace. This private mathematical/physical
    seam does not choose an operation family or confer head provenance. It
    allows an independent root observer to read full potential heads without
    inventing complete-query declarations or a historical database cutoff.
    The public planner entry above retains its actual query/family checks.
    """
    if type(acquisition) is not reader._ReadAcquisitionBudget:
        raise IndexHeadReadError("counted heads require the actual shared acquisition ledger")
    acquisition.require_active()
    if (acquisition.cursor is not cursor or acquisition.trace is not trace or acquisition.work is not work
            or type(operation) is not str or operation not in (complete.OPERATION,
                complete.REGISTRATION_OPERATION, complete.STAGE_OPERATION, COMPLETION_OPERATION)
            or type(getattr(trace, "operation", None)) is not str or trace.operation != operation
            or type(identities) is not tuple or not 1 <= len(identities) <= MAX_HEADS):
        raise IndexHeadReadError("counted head source scope changed")
    previous = None
    for identity in identities:
        if (type(identity) is not str or identity not in projection.INDEX_IDS
                or previous is not None and previous >= identity):
            raise IndexHeadReadError("counted head source inventory is not exact, sorted and unique")
        previous = identity
    profiles, empty, manifest = _source_context(identities, work)
    key = {"profile": READ_PROFILE, "indexIds": list(identities), "rowLimit": len(identities) + 1}
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

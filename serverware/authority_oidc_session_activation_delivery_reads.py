"""Original primary/range proof admission for protected delivery consumption.

Declarations and selected rows are not old-token possession, current root
authority, fresh user permission or a committed consumption. The composing
owner must independently admit roots, database time and policy, then run the
actual transition. No successful read-result carrier is accepted as input.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from serverware import authority_audit_capacity as capacity
from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as batch
from serverware import authority_contract
from serverware import authority_query_reads as reads
from serverware import authority_transition_core as core
from serverware import authority_transition_webauthn as webauthn
from serverware.authority_index_contract import CountedNode, IndexLeaf, OpaqueSubtree
from serverware.authority_index_frontier import MAX_OUTSIDE_PREFIXES
from serverware.authority_query_read_work import _ValidationWork


OPERATION = "oidc.session.activation-delivery.consume"
AUDIT_PURPOSE = "activation-delivery-consume-audit"
MAX_BUSINESS_QUERY_ROWS = 16
MAX_QUERY_ROWS = 17
MAX_SELECTED_ROWS = 10
_DELIVERY_TABLE = "oidc_session_activation_deliveries"


@dataclass(frozen=True, slots=True, repr=False)
class _AdmittedReads:
    arguments: dict[str, Any]
    selected_rows: tuple[dict[str, Any], ...]
    query_reads: tuple[reads.QueryRead, ...]


def _identity(request_digest: str, purpose: str, work: _ValidationWork | None) -> str:
    if work is None:
        return core.deterministic_uuid(
            operation=OPERATION, request_digest=request_digest, purpose=purpose)
    return core._deterministic_uuid(
        operation=OPERATION, request_digest=request_digest, purpose=purpose, work=work)


def _point(name, table, column, value, *, absent=False) -> core.BoundedQuery:
    return core.BoundedQuery(
        query_id=core.query_program_id(OPERATION, name, table), table=table,
        predicates=(core.QueryPredicate(column, "eq", value),),
        order_by=(core.QueryOrder(column),), maximum_rows=1,
        absent_key={column: value}, require_absence=absent)


def _queries(*, arguments, cutoff_us, request_digest,
             work: _ValidationWork | None = None) -> tuple[core.Query, ...]:
    """Closed source queries, not proof that any observed population is complete."""
    values = complete._delivery_binding_inputs(arguments, cutoff_us, work=work)
    if work is not None:
        work.prepare_scan(request_digest)
    core.require_digest(request_digest, "delivery consumption request digest")
    audit_id = _identity(request_digest, AUDIT_PURPOSE, work)
    queries = [
        _point("active_session", "oidc_browser_sessions", "id", values["session_id"]),
        _point("target_credential", "webauthn_credentials", "id", values["credential_record_id"]),
        _point("used_challenge", "webauthn_challenges", "id", values["challenge_id"]),
        _point("activation_delivery", _DELIVERY_TABLE, "id", values["delivery_id"]),
    ]
    # The actual high-water selects its publication; no supplied publication ID.
    queries.extend(webauthn._trust_queries(OPERATION, work=work))
    queries.extend((
        _point("rbac_subject", "rbac_role_bindings", "subject_id", values["user_id"]),
        _point("rbac_authority", "rbac_authority_state", "authority_id", 1),
        _point("delivery_consume_audit", capacity.OUTBOX_TABLE, "id", audit_id, absent=True),
    ))
    for role in complete.DELIVERY_ROLES:
        queries.append(complete.bind_query(OPERATION, role, arguments=arguments, cutoff_us=cutoff_us)
            if work is None else complete._bind_query(
                OPERATION, role, arguments=arguments, cutoff_us=cutoff_us, work=work))
    if len(queries) != MAX_BUSINESS_QUERY_ROWS:
        raise core.TransitionKernelError("delivery consumption source query inventory changed")
    if work is not None:
        # Both actual capacity/close constructors re-create the declarations.
        for query in queries:
            if type(query) is complete.CompleteIndexQuery:
                for _ in range(2):
                    complete._prepare_constructor_work(query.index_id, query.selector_items, work)
    return capacity.add_capacity_query(OPERATION, tuple(queries))


def _capture(*, arguments, request_digest, selected_rows, query_reads,
             business_before_roots, authorization_before_roots, before_proofs,
             read_heads, query_frontiers, work):
    """Detach all raw graphs before hashing declarations or proof callbacks."""
    if (type(work) is not _ValidationWork or type(arguments) is not dict
            or len(arguments) != len(complete._DELIVERY_ARGUMENT_FIELDS)
            or type(selected_rows) is not tuple or len(selected_rows) != MAX_SELECTED_ROWS
            or type(before_proofs) is not tuple or len(before_proofs) != MAX_SELECTED_ROWS
            or type(query_reads) is not tuple or len(query_reads) != MAX_QUERY_ROWS
            or type(read_heads) is not tuple or len(read_heads) != 7
            or type(query_frontiers) is not tuple or len(query_frontiers) != 7):
        raise core.TransitionKernelError("delivery consumption original read inventory differs")
    for roots in (business_before_roots, authorization_before_roots):
        if type(roots) not in (tuple, list) or len(roots) > authority_contract.MAX_QUERY_PROOFS:
            raise core.TransitionKernelError("delivery consumption root inventory is not bounded")
    raw_heads = []
    for head in read_heads:
        if type(head) is not batch.CompleteQueryHead or type(head.index_root) is not CountedNode:
            raise core.TransitionKernelError("delivery consumption original head type differs")
        raw_heads.append((head.index_id, head.index_revision, head.index_root.digest, head.index_root.count))
    raw_frontiers = []
    for frontier in query_frontiers:
        if (type(frontier) is not batch.CompleteQueryFrontier or type(frontier.frontier) is not tuple
                or len(frontier.frontier) > MAX_OUTSIDE_PREFIXES + 1):
            raise core.TransitionKernelError("delivery consumption original frontier is not bounded")
        entries = []
        for entry in frontier.frontier:
            if type(entry) is IndexLeaf:
                entries.append(("leaf", entry.key, entry.primary_key_digest, entry.primary_row_digest))
            elif type(entry) is OpaqueSubtree:
                entries.append(("opaque", entry.prefix, entry.digest, entry.count))
            else:
                raise core.TransitionKernelError("delivery consumption original frontier entry differs")
        raw_frontiers.append((frontier.query_id, entries))
    owned = reads._CopyBudget(work).copy({
        "arguments": arguments, "request_digest": request_digest,
        "selected_rows": selected_rows, "before_proofs": before_proofs,
        "business_before_roots": business_before_roots,
        "authorization_before_roots": authorization_before_roots,
        "read_heads": raw_heads, "query_frontiers": raw_frontiers,
    })
    records = tuple(reads._copy_read(record, work) for record in query_reads)
    heads = tuple(batch.CompleteQueryHead(identifier, revision, CountedNode(digest, count))
                  for identifier, revision, digest, count in owned["read_heads"])
    frontiers = tuple(batch.CompleteQueryFrontier(identifier, tuple(
        IndexLeaf(*entry[1:]) if entry[0] == "leaf" else OpaqueSubtree(*entry[1:])
        for entry in entries)) for identifier, entries in owned["query_frontiers"])
    return owned, records, heads, frontiers


def _require_points(context, queries, work):
    expected_addresses = set()
    for query, record in zip(queries, context.query_reads):
        if type(query) is complete.CompleteIndexQuery:
            continue
        if query.absent_key is None:
            if (query.table != webauthn.trust.PUBLICATION_TABLE
                    or record.returned_row_count != 1 or len(record.addresses) != 1):
                raise core.TransitionKernelError("delivery consumption current publication is absent")
            address = record.addresses[0]
            matches = tuple(item for item in context.selected_rows
                if item["table"] == address.table and item["keyDigest"] == address.key_digest)
            if len(matches) != 1 or matches[0]["present"] is not True:
                raise core.TransitionKernelError("delivery consumption current publication is ambiguous")
            selected = matches[0]
        else:
            selected = context._exact(query.table, query.absent_key, work=work)
            wanted = not query.require_absence
            if selected["present"] is not wanted or (wanted and type(selected["row"]) is not dict):
                raise core.TransitionKernelError("delivery consumption primary presence differs")
        expected_addresses.add((selected["table"], selected["keyDigest"]))
    if len(expected_addresses) != MAX_SELECTED_ROWS or len(context.selected_rows) != MAX_SELECTED_ROWS:
        raise core.TransitionKernelError("delivery consumption primary selection is not the exact closure")


def _require_ranges(context, queries, joined_reads, work):
    if len(joined_reads) != len(complete.DELIVERY_ROLES):
        raise core.TransitionKernelError("delivery consumption proved range inventory differs")
    joined = dict(joined_reads)
    if len(joined) != len(complete.DELIVERY_ROLES):
        raise core.TransitionKernelError("delivery consumption proved ranges are duplicated")
    session = context._exact("oidc_browser_sessions", {"id": context.arguments["session_id"]}, work=work)
    delivery = context._exact(_DELIVERY_TABLE, {"id": context.arguments["delivery_id"]}, work=work)
    for query, record in zip(queries, context.query_reads):
        if type(query) is not complete.CompleteIndexQuery:
            continue
        observed = joined.get(query.query_id)
        if observed is None:
            raise core.TransitionKernelError("delivery consumption lacks an actual range proof")
        if query.role == "pending_trust_publications":
            if observed.leaves or record.returned_row_count != 0 or record.addresses:
                raise core.TransitionKernelError("delivery consumption pending trust range is not empty")
            continue
        expected = session if query.role == "session_new_token" else delivery
        if (len(observed.leaves) != 1 or record.returned_row_count != 1 or len(record.addresses) != 1
                or observed.leaves[0].primary_key_digest != expected["keyDigest"]
                or record.addresses[0].table != expected["table"]
                or record.addresses[0].key_digest != expected["keyDigest"]
                or record.addresses[0].present is not True):
            raise core.TransitionKernelError("delivery consumption singleton range differs from its exact row")


def _admit_on_work(*, arguments, request_digest, database_now, selected_rows,
                   query_reads, business_before_roots, authorization_before_roots,
                   before_proofs, read_heads, query_frontiers, work) -> _AdmittedReads:
    """Genuinely verify original proofs with one supplied cumulative allowance.

    Independent root/population admission, real database time, old-token
    possession and current policy remain obligations of the actual caller.
    """
    if type(database_now) is not datetime or database_now.tzinfo is not timezone.utc:
        raise core.TransitionKernelError("delivery consumption time must be an exact UTC datetime")
    owned, records, heads, frontiers = _capture(
        arguments=arguments, request_digest=request_digest, selected_rows=selected_rows,
        query_reads=query_reads, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, work=work)
    cutoff = complete.cutoff_microseconds(database_now)
    queries = _queries(arguments=owned["arguments"], cutoff_us=cutoff,
        request_digest=owned["request_digest"], work=work)
    actual = batch._verify_complete_query_batch(
        operation=OPERATION, arguments=owned["arguments"], cutoff_us=cutoff,
        queries=tuple(query for query in queries if type(query) is complete.CompleteIndexQuery),
        business_before_roots=owned["business_before_roots"],
        authorization_before_roots=owned["authorization_before_roots"],
        selected_rows=owned["selected_rows"], before_proofs=owned["before_proofs"],
        read_heads=heads, query_frontiers=frontiers, work=work)
    checked_queries, checked_reads = reads._validate_query_reads(
        OPERATION, queries=queries, query_reads=records,
        selected_rows=actual.selected_rows, work=work)
    context = core.KernelContext(operation=OPERATION, arguments=actual.arguments,
        selected_rows=actual.selected_rows, database_now=database_now,
        request_digest=owned["request_digest"], query_reads=checked_reads)
    _require_points(context, checked_queries, work)
    _require_ranges(context, checked_queries, actual.joined_reads, work)
    return _AdmittedReads(actual.arguments, actual.selected_rows, checked_reads)

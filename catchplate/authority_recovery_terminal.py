"""Relative recovery terminal row effects, not a complete maintenance kernel.

Every invocation replays genuine primary membership on the original shared
work. Expire/prune population acquisition, complete ranges and overflow ranks
are deliberately NOT implemented here. The four prune requirements must run in
order, with overflow proved against the root after that table's old deletions.
No selected subset, count, requirement record or returned effect grants that
closure. The eventual owner also admits original request/configuration/time,
current roots and, for invalidation, the independently claimed witness.

These measured effects retain the existing lossless typed-request domain;
they do not expand it to historically direct-only floating/NUL payloads.
There is no SQL, registry activation, clock sampling, signing or commit here.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_challenge_retention as retention
from catchplate import authority_complete_query_batch as batch
from catchplate import authority_contract as contract
from catchplate import authority_primary_contract as contracts
from catchplate import authority_radix_mutation as primary
from catchplate import authority_transition_core as core
from catchplate import authority_webauthn_recovery as recovery
from catchplate.authority_query_read_work import _ValidationWork


CEREMONIES = recovery.CEREMONY_TABLE
REVOCATIONS = "webauthn_recovery_revocations"
MAX_ROWS = contract.MAX_QUERY_PROOFS
TERMINAL = ("consumed", "expired", "invalidated")
LIVE = ("pending_candidate", "prepared")
_TIMES = {CEREMONIES: ("consumed_at", "invalidated_at", "expires_at"),
          REVOCATIONS: ("consumed_at", "expires_at")}
_PHASES = ("ceremony-old", "ceremony-overflow", "revocation-old", "revocation-overflow")
_INVALIDATE_FIELDS = frozenset({"recovery_id", "ceremony_type", "authorization",
    "authorization_digest", "signature_digest", "businessIntent"})


class RecoveryTerminalError(core.TransitionKernelError):
    pass


@dataclass(frozen=True, slots=True)
class _QueryRequirement:
    """Source query obligation only; no proof or completed acquisition flag."""

    ordinal: int
    phase: str
    table: str
    statuses: tuple[str, ...]
    time_columns: tuple[str, ...]
    cutoff: str | None
    descending: bool
    maximum_rows: int
    offset: int
    after_phase: str | None
    requires_complete_range: bool = True
    requires_original_rank: bool = False


@dataclass(frozen=True, slots=True)
class _RowEffects:
    """Invocation-local derived effects; never a completeness/authority input."""

    phase: str
    mutations: tuple[dict, ...]
    affected: bool


def _require(value):
    if not value:
        raise RecoveryTerminalError("recovery terminal row differs from its original source requirements")


def _settings(now, seconds, maximum, work):
    _require(type(work) is _ValidationWork and type(seconds) is int
        and 86_400 <= seconds <= 31_536_000 and type(maximum) is int and 100 <= maximum <= 1_000_000)
    now = recovery._now(now)
    try:
        cutoff = (now - timedelta(seconds=seconds)).isoformat()
    except OverflowError as exc:
        raise RecoveryTerminalError("recovery retention cutoff exceeds its timestamp domain") from exc
    work.prepare_utf8(cutoff)
    return now.isoformat(), cutoff


def query_requirements(*, operation, database_now, terminal_retention_seconds, maximum_retained, work):
    """Declare the missing raw complete queries in exact legacy sequence.

    SQL orders COALESCE(time_columns), then id, in the indicated direction.
    These are stored TEXT values, not a new parsed-timestamp ordering. Every
    ordinal is a distinct bounded query, not one aggregate 1024-row allowance.
    Invalidation instead requires exact primary keys selected by its arguments.
    """
    now, cutoff = _settings(database_now, terminal_retention_seconds, maximum_retained, work)
    _require(type(operation) is str and operation in (recovery.EXPIRE, recovery.PRUNE, recovery.INVALIDATE))
    work.charge(input_bytes=2048, json_nodes=128)
    if operation == recovery.INVALIDATE:
        return ()
    if operation == recovery.EXPIRE:
        return (_QueryRequirement(0, "expire", CEREMONIES, LIVE, ("expires_at",),
            now, False, MAX_ROWS, 0, None),)
    return tuple(_QueryRequirement(ordinal, phase, table, TERMINAL, _TIMES[table],
        None if ordinal % 2 else cutoff, bool(ordinal % 2), MAX_ROWS,
        maximum_retained if ordinal % 2 else 0,
        _PHASES[ordinal - 1] if ordinal else None,
        requires_original_rank=bool(ordinal % 2))
        for ordinal, (phase, table) in enumerate(zip(_PHASES,
            (CEREMONIES, CEREMONIES, REVOCATIONS, REVOCATIONS))))


def _membership(context, business, authorization, proofs, work):
    _require(type(context) is core.KernelContext and type(context.selected_rows) is tuple
        and 1 <= len(context.selected_rows) <= 4 and type(proofs) is tuple
        and len(proofs) == len(context.selected_rows)
        and type(business) is tuple and type(authorization) is tuple
        and len(business) + len(authorization) <= 5
        and all(type(root) is primary.PrimaryRoot for root in (*business, *authorization)))
    # The source contracts, including root classes, are never inferred from rows.
    source = contracts.primary_table_contracts(context.operation)
    _require(len(business) + len(authorization) == len(source))
    ledger = batch._SharedLedger(work)
    hashes, size, nodes = ledger.remaining()
    result = primary.evaluate_primary_radix_memberships(table_contracts=source,
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=context.selected_rows, before_proofs=proofs,
        limits=primary.PrimaryRadixLimits(4, 4, 4 * contract.TREE_DEPTH,
            4 * contract.TREE_DEPTH * contract.TREE_RADIX,
            min(66 + 70 * len(proofs), hashes), size, 128, nodes))
    metrics = result.result.metrics
    work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
    _require(result.result.business_after_roots == business
        and result.result.authorization_after_roots == authorization)
    rows = result.selected_rows
    _require(all(row["contractSelector"] is None for row in rows))
    for row in rows:
        if row["row"] is not None:
            _require(work.measure(row["row"])[0] <= 1024 * 1024)
    _require(type(context.arguments) is dict
        and work.measure(context.arguments)[0] <= contract.MAX_REQUEST_BYTES)
    arguments = recovery._own(context.arguments, work)
    return replace(context, arguments=arguments, selected_rows=rows)


def _selected(context, table, identity=None):
    rows = tuple(row for row in context.selected_rows if row["table"] == table
        and (identity is None or row["key"] == {"id": identity}))
    _require(len(rows) == 1)
    return rows[0]


def _inventory(context, expected):
    # No unrelated rows or second primary target can enter a relative stage.
    _require(len(context.selected_rows) == len(expected)
        and {row["table"] for row in context.selected_rows} == set(expected))


def _text(value, work, maximum=1024):
    _require(type(value) is str and 1 <= len(value) <= maximum and "\x00" not in value)
    work.prepare_utf8(value)
    _require(len(value.encode("utf-8")) <= maximum)
    return value


def _terminal_time(row, table, work):
    # COALESCE is first non-NULL, not truthiness, minimum, or parsed chronology.
    for name in _TIMES[table]:
        _require(name in row)
        if row[name] is not None:
            return _text(row[name], work, 64)
    raise RecoveryTerminalError("recovery terminal row has no original expiry")


def _mutation(context, selected, row, work):
    work.prepare_copy(selected["key"])
    work.prepare_copy(selected["row"])
    if row is None:
        return core.delete_mutation(operation=context.operation, selected=selected)
    work.prepare_copy(row)
    return core.mutation(operation=context.operation, selected=selected, row=row)


def _changed(row, work, **changes):
    work.prepare_copy(row)
    return dict(row, **changes)


def _challenge(context, ceremony, now, work):
    selected = _selected(context, retention.CHALLENGE_TABLE, ceremony["challenge_id"])
    _require(selected["present"] is True)
    row = selected["row"]
    retention._validate_inline(row)
    # Even a previously used challenge is updated by the original SQL; retain
    # its exact used_at while the reference commitment changes with ceremony.
    used = row["used_at"] if row["used_at"] is not None else now
    return _mutation(context, selected, _changed(row, work, used_at=used), work)


def _invalidate_arguments(context, work):
    args = context.arguments
    _require(type(args) is dict and set(args) == _INVALIDATE_FIELDS
        and type(args["authorization"]) is dict)
    identity = _text(args["recovery_id"], work, 128)
    _require(args["ceremony_type"] in ("replacement-registration", "lost-active-key-decommission"))
    for name in ("authorization_digest", "signature_digest"):
        core.require_digest(args[name], name)
    raw = recovery._bytes(args["authorization"], work)
    # The whole measured request already has its original generic byte bound.
    # Root-signature/authorization-size admission belongs to the real witness
    # owner; do not invent a smaller burn-only payload policy here.
    work.charge(input_bytes=len(raw))
    return args, identity, raw.decode("ascii")


def _audit(context, args, user_id, now, work):
    identity = "webauthn-recovery-burned:" + args["recovery_id"]
    _text(identity, work, 256)
    selected = _selected(context, capacity.OUTBOX_TABLE, identity)
    event = {"recovery_id": args["recovery_id"], "ceremony_type": args["ceremony_type"],
        "authorization_digest": args["authorization_digest"], "signature_digest": args["signature_digest"],
        "witness_claim_preserved": True}
    raw = recovery._bytes(event, work)
    work.charge(input_bytes=len(raw), hashes=1)
    event_digest = core.framed_digest("catchplate.metadataAuditOutboxEvent/v1", raw)
    common = {"id": identity, "event_type": "webauthn.recovery.authorization_burned",
        "actor_type": "system", "actor_id": user_id,
        "event_json": raw.decode("ascii"), "event_digest": event_digest}
    if selected["present"]:
        # Genuine idempotent PG outbox read: unchanged event, no INSERT/count.
        work.prepare_comparison(common, selected["row"])
        _require(all(type(selected["row"].get(name)) is type(value)
            and selected["row"].get(name) == value for name, value in common.items()))
        return ()
    row = {**common, "storage_format_version": 2, "status": "pending", "claim_id": None,
        "claimed_at": None, "attempts": 0, "audited_at": None, "audit_event_hash": None,
        "last_error": None, "created_at": now}
    return (_mutation(context, selected, row, work),)


def evaluate_row(*, phase, context, business_before_roots, authorization_before_roots,
        before_proofs, terminal_retention_seconds, maximum_retained, work):
    """Reverify originals and derive one row's effects, never batch completeness.

    Supplied full roots must match the source operation inventory. Expire/prune
    each accept only one target plus its genuinely joined challenge (ceremonies
    only). Invalidate accepts the exact PK and, when active, the exact outbox
    key/global aggregate and challenge. Neither its authorization JSON nor its
    output replaces the external claim/burn-on-uncertain-result owner.
    """
    _require(type(context) is core.KernelContext and type(phase) is str)
    requirements = query_requirements(operation=context.operation, database_now=context.database_now,
        terminal_retention_seconds=terminal_retention_seconds, maximum_retained=maximum_retained, work=work)
    now = context.database_now.isoformat()
    context = _membership(context, business_before_roots, authorization_before_roots, before_proofs, work)
    if context.operation == recovery.INVALIDATE:
        _require(phase == "invalidate")
        args, identity, authorization_json = _invalidate_arguments(context, work)
        table = CEREMONIES if args["ceremony_type"] == "replacement-registration" else REVOCATIONS
        selected = _selected(context, table, identity)
        if not selected["present"] or selected["row"]["status"] not in (LIVE if table == CEREMONIES else ("prepared",)):
            _inventory(context, (table,))
            return _RowEffects(phase, (), False)
        expected = (table, capacity.OUTBOX_TABLE, capacity.AGGREGATE_TABLE)
        _inventory(context, expected + ((retention.CHALLENGE_TABLE,) if table == CEREMONIES else ()))
        row = selected["row"]
        user = _text(row["user_id"], work)
        changes = {"authorization_json": authorization_json,
            "authorization_digest": args["authorization_digest"], "signature_digest": args["signature_digest"]}
        if table == CEREMONIES:
            effects = (_challenge(context, row, now, work), _mutation(context, selected,
                _changed(row, work, **changes, status="invalidated", invalidated_at=now), work))
        else:
            effects = (_mutation(context, selected,
                _changed(row, work, **changes, status="expired", consumed_at=now), work),)
        effects += _audit(context, args, user, now, work)
        effects = retention.expand_mutations(context, effects, work=work)
        effects = capacity._finalize_capacity(context, effects, work=work)
    else:
        query = next((item for item in requirements if item.phase == phase), None)
        _require(query is not None)
        selected = _selected(context, query.table)
        _require(selected["present"] is True)
        _inventory(context, (query.table,) + ((retention.CHALLENGE_TABLE,) if query.table == CEREMONIES else ()))
        row = selected["row"]
        _require(row["status"] in query.statuses)
        value = (_text(row["expires_at"], work, 64) if phase == "expire"
            else _terminal_time(row, query.table, work))
        _require(query.cutoff is None or value <= query.cutoff)
        if phase == "expire":
            effects = (_mutation(context, selected, _changed(row, work,
                status="expired", invalidated_at=now), work), _challenge(context, row, now, work))
        else:
            effects = (_mutation(context, selected, None, work),)
        effects = retention.expand_mutations(context, effects, work=work)
    retention.validate_inline_delta(operation=context.operation, selected_rows=context.selected_rows,
        mutations=effects, work=work)
    return _RowEffects(phase, effects, True)

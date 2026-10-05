"""Inductive challenge/reference OLD/NEW join, never admission authority.

The seven derived fields live in the *real challenge primary row*.  An empty
installation and complete writer coverage establish the invariant; ordinary
primary membership then authenticates it.  A challenge-only update preserves
the fields.  Each reference writer proves its original row, matches its full
commitment against the original challenge, and replaces exactly that component.
The database's deferred guard independently rejoins the actual source tables.

This is why a 256-row pruning batch need not reread 768 reference rows or trust
an unsigned SQL count.  There is no type-based exception, backfill, clock, SQL,
or successful-verification DTO here.  The caller must authenticate all supplied
primary originals and independently authorize the actual business mutations.
"""
from __future__ import annotations

import json
import re
from typing import Any

from serverware.authority_query_read_work import (
    QueryReadValidationLimits, _ValidationWork,
)


CHALLENGE_TABLE = "webauthn_challenges"
REFERENCE_COMPONENTS = (
    ("webauthn_recovery_ceremonies", "id", "retention_recovery_id",
     "retention_recovery_row_digest", 1),
    ("jit_webauthn_assertion_receipts", "assertion_receipt_digest",
     "retention_jit_receipt_digest", "retention_jit_row_digest", 2),
    ("policy_activation_webauthn_assertions", "assertion_receipt_digest",
     "retention_activation_receipt_digest", "retention_activation_row_digest", 4),
)
REFERENCE_TABLES = tuple(component[0] for component in REFERENCE_COMPONENTS)
DERIVED_FIELDS = tuple(
    field for component in REFERENCE_COMPONENTS for field in component[2:4]
) + ("retention_reference_mask",)
BASE_FIELDS = frozenset({
    "id", "challenge", "challenge_type", "user_id", "scope_key",
    "approval_request_id", "payload_json", "expires_at", "used_at", "created_at",
})
ROW_FIELDS = BASE_FIELDS | frozenset(DERIVED_FIELDS)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SELECTED_FIELDS = frozenset({
    "table", "key", "keyDigest", "present", "row", "contractSelector",
})
_MUTATION_FIELDS = frozenset({
    "templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row",
})


class ChallengeRetentionError(ValueError):
    pass


def _meter(work: _ValidationWork | None) -> _ValidationWork:
    if work is None:
        return _ValidationWork(QueryReadValidationLimits())
    if type(work) is not _ValidationWork:
        raise ChallengeRetentionError("retention work is not the shared exact meter")
    return work


def _copy(value: Any, work: _ValidationWork) -> Any:
    work.prepare_normalization(value)
    return json.loads(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                 allow_nan=False, separators=(",", ":")))


def _text(value: Any, label: str) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 4096
            or "\x00" in value or len(value.encode("utf-8")) > 4096):
        raise ChallengeRetentionError(f"retention {label} is not bounded exact text")
    return value


def _reference_digest(table: str, row: dict[str, Any], work: _ValidationWork) -> str:
    # This framing is the persisted SQL tree framing, *not* BusinessKey/v1 or
    # the generic domain-NUL canonical-JSON signature framing.
    from serverware import authority_radix_proof as radix

    work.prepare_encoding(row, ensure_ascii=False)
    encoded = radix.tree_json_bytes(row)
    domain = "serverware.policyAuthorityAuthenticatedRow/v1"
    work.charge(hashes=1, input_bytes=24 + len(domain) + len(table) + len(encoded))
    return radix._tree_digest(domain, table.encode("ascii"), encoded)


def _validate_inline(row: dict[str, Any]) -> None:
    if type(row) is not dict or set(row) != ROW_FIELDS:
        raise ChallengeRetentionError("retention challenge original is not the full source row")
    _text(row["id"], "challenge identity")
    mask = 0
    for _table, _pk, identity, digest, bit in REFERENCE_COMPONENTS:
        key, commitment = row[identity], row[digest]
        if key is None and commitment is None:
            continue
        _text(key, "reference identity")
        if type(commitment) is not str or _DIGEST.fullmatch(commitment) is None:
            raise ChallengeRetentionError("retention reference commitment is not exact")
        mask |= bit
    if type(row["retention_reference_mask"]) is not int or row["retention_reference_mask"] != mask:
        raise ChallengeRetentionError("retention reference mask disagrees with its components")


def _empty(row: dict[str, Any]) -> dict[str, Any]:
    if type(row) is not dict or set(row) not in (BASE_FIELDS, ROW_FIELDS):
        raise ChallengeRetentionError("retention challenge is not source closed")
    result = dict(row)
    for field in DERIVED_FIELDS[:-1]:
        result[field] = None
    result["retention_reference_mask"] = 0
    _validate_inline(result)
    return result


def derive_row(
    challenge: dict[str, Any] | None,
    recovery: dict[str, Any] | None,
    jit: dict[str, Any] | None,
    activation: dict[str, Any] | None,
    *, work: _ValidationWork | None = None,
) -> dict[str, Any] | None:
    """Derive the complete join from full originals; this proves no membership.

    Used as the independent full-join oracle for the SQL equality contract.
    The production transition uses the equivalent OLD/NEW induction below,
    not a caller assertion that these rows were independently verified.
    """
    meter = _meter(work)
    owned = _copy([challenge, recovery, jit, activation], meter)
    challenge, *references = owned
    if challenge is None:
        if any(reference is not None for reference in references):
            raise ChallengeRetentionError("retention reference has no challenge")
        return None
    result = _empty(challenge)
    for reference, (table, pk, identity, digest, bit) in zip(references, REFERENCE_COMPONENTS):
        if reference is None:
            continue
        if (type(reference) is not dict or reference.get("challenge_id") != result["id"]):
            raise ChallengeRetentionError("retention reference does not join the challenge")
        result[identity] = _text(reference.get(pk), "reference primary key")
        result[digest] = _reference_digest(table, reference, meter)
        result["retention_reference_mask"] |= bit
    _validate_inline(result)
    return result


def _inventory(operation: str, selected_rows: Any, mutations: Any, work: _ValidationWork):
    from serverware import authority_contract as contract

    if type(operation) is not str or type(selected_rows) not in (tuple, list):
        raise ChallengeRetentionError("retention operation/original inventory is not exact")
    if type(mutations) not in (tuple, list) or len(mutations) > contract.MAX_MUTATIONS:
        raise ChallengeRetentionError("retention mutation inventory is not bounded")
    selected = _copy(list(selected_rows), work)
    entries = _copy(list(mutations), work)
    return _validate_inventory(operation, selected, entries)


def _validate_inventory(operation: str, selected: Any, entries: Any):
    """Private body after actual ownership; not a caller inventory verdict."""
    from serverware import authority_contract as contract

    originals = {}
    for item in selected:
        if type(item) is not dict or set(item) != _SELECTED_FIELDS:
            raise ChallengeRetentionError("retention original envelope is not closed")
        table = item["table"]
        if table not in (CHALLENGE_TABLE, *REFERENCE_TABLES):
            continue
        pk = "id" if table == CHALLENGE_TABLE else next(
            component[1] for component in REFERENCE_COMPONENTS if component[0] == table)
        key = item["key"]
        if (type(key) is not dict or set(key) != {pk}
                or type(item["present"]) is not bool
                or (item["present"] and (type(item["row"]) is not dict
                    or item["row"].get(pk) != key[pk]))
                or (not item["present"] and item["row"] is not None)):
            raise ChallengeRetentionError("retention primary original identity changed")
        address = table, _text(key[pk], "primary identity")
        if address in originals:
            raise ChallengeRetentionError("retention primary original is duplicated")
        originals[address] = item
        if table == CHALLENGE_TABLE and item["present"]:
            _validate_inline(item["row"])
    seen = set()
    for item in entries:
        if type(item) is not dict or set(item) != _MUTATION_FIELDS:
            raise ChallengeRetentionError("retention mutation envelope is not closed")
        table = item["table"]
        if table not in (CHALLENGE_TABLE, *REFERENCE_TABLES):
            continue
        template = contract.mutation_template(operation, item["templateId"])
        if (template["table"] != table or template["mutation"] != item["operation"]
                or template["predicate"] != "exact-primary-key-and-full-row-cas-v1"
                or template["cardinality"] != 1):
            raise ChallengeRetentionError("retention mutation is outside its source template")
        pk = "id" if table == CHALLENGE_TABLE else next(
            component[1] for component in REFERENCE_COMPONENTS if component[0] == table)
        key = item["key"]
        if type(key) is not dict or set(key) != {pk}:
            raise ChallengeRetentionError("retention mutation key is not closed")
        address = table, _text(key[pk], "mutation identity")
        original = originals.get(address)
        if original is None or address in seen:
            raise ChallengeRetentionError("retention mutation lacks a unique primary original")
        seen.add(address)
        if (item["keyDigest"] != original["keyDigest"]
                or item["expectedRow"] != original["row"]
                or (item["operation"] == "INSERT") == original["present"]
                or (item["operation"] == "DELETE" and item["row"] is not None)
                or (item["operation"] != "DELETE" and
                    (type(item["row"]) is not dict or item["row"].get(pk) != key[pk]))):
            raise ChallengeRetentionError("retention mutation OLD/NEW does not match its primary original")
    return originals, entries


def expand_mutations(context: Any, mutations: Any, *, work: _ValidationWork | None = None) -> tuple[dict[str, Any], ...]:
    """Compose exact inline changes before root derivation, never hidden SQL.

    Ref-only writers must select the affected actual challenge primary rows.
    No reference can be inserted over an occupied component, removed without
    its original full-row commitment, or moved without both challenge rows.
    """
    from serverware import authority_transition_core as core

    if type(context) is not core.KernelContext:
        raise ChallengeRetentionError("retention transition context is not exact")
    if type(mutations) is not tuple or any(type(item) is not dict for item in mutations):
        raise ChallengeRetentionError("retention mutations are not an exact tuple")
    if not any(item.get("table") in (CHALLENGE_TABLE, *REFERENCE_TABLES) for item in mutations):
        return mutations
    return _expand(operation=context.operation, selected_rows=context.selected_rows,
                   mutations=mutations, work=_meter(work))


def _expand(*, operation: str, selected_rows: Any, mutations: Any, work: _ValidationWork):
    # Preserve the original public path's import and validation order.
    from serverware import authority_contract as contract
    from serverware import authority_transition_core as core

    meter = _meter(work)
    originals, entries = _inventory(operation, selected_rows, mutations, meter)
    return _expand_inventory(operation, originals, entries, work=meter)


def _expand_inventory(operation: str, originals: Any, entries: Any, *, work: _ValidationWork):
    """Private body after this invocation's genuine inventory validation."""
    from serverware import authority_contract as contract
    from serverware import authority_transition_core as core

    meter = work
    challenge_entries = {entry["key"]["id"]: entry for entry in entries
                         if entry["table"] == CHALLENGE_TABLE}
    changes: dict[str, dict[str, tuple[Any, Any]]] = {}
    for table, pk, identity, digest, _bit in REFERENCE_COMPONENTS:
        for entry in entries:
            if entry["table"] != table:
                continue
            for side, row in (("before", entry["expectedRow"]), ("after", entry["row"])):
                if row is None:
                    continue
                challenge_id = _text(row.get("challenge_id"), "joined challenge")
                original = originals.get((CHALLENGE_TABLE, challenge_id))
                if original is None:
                    raise ChallengeRetentionError("retention reference mutation lacks its challenge original")
                key = table + ":" + side
                parts = changes.setdefault(challenge_id, {})
                if key in parts:
                    raise ChallengeRetentionError("retention has two references in a unique challenge component")
                parts[key] = (_text(row.get(pk), "reference primary key"),
                              _reference_digest(table, row, meter))
    for challenge_id in sorted(set(challenge_entries) | set(changes)):
        original = originals.get((CHALLENGE_TABLE, challenge_id))
        if original is None:
            raise ChallengeRetentionError("retention challenge mutation lacks its original")
        before = original["row"]
        entry = challenge_entries.get(challenge_id)
        planned = before if entry is None else entry["row"]
        inline = _empty(planned) if before is None else dict(before)
        for table, _pk, identity, digest, _bit in REFERENCE_COMPONENTS:
            parts = changes.get(challenge_id, {})
            removed = parts.get(table + ":before")
            inserted = parts.get(table + ":after")
            old_component = inline[identity], inline[digest]
            if removed is not None:
                if removed != old_component:
                    raise ChallengeRetentionError("retention reference OLD commitment disagrees with the challenge")
                inline[identity] = inline[digest] = None
            if inserted is not None:
                if inline[identity] is not None or inline[digest] is not None:
                    raise ChallengeRetentionError("retention reference INSERT overwrites an occupied component")
                inline[identity], inline[digest] = inserted
        inline["retention_reference_mask"] = sum(
            bit for _table, _pk, identity, _digest, bit in REFERENCE_COMPONENTS
            if inline[identity] is not None)
        if planned is None:
            if inline["retention_reference_mask"] != 0:
                raise ChallengeRetentionError("retention cannot delete a referenced challenge")
            continue
        if type(planned) is not dict or set(planned) not in (BASE_FIELDS, ROW_FIELDS):
            raise ChallengeRetentionError("retention NEW challenge row is not source closed")
        after = {**planned, **{field: inline[field] for field in DERIVED_FIELDS}}
        _validate_inline(after)
        if entry is None:
            if after != before:
                entries.append(core.mutation(operation=operation, selected=original, row=after))
        else:
            entry["row"] = after
    if len(entries) > min(contract.MAX_MUTATIONS, contract.operation_spec(operation)["maximumMutations"]):
        raise ChallengeRetentionError("retention inline mutation expansion exceeds its original bound")
    return tuple(entries)


def validate_transition(context: Any, mutations: Any, *, work: _ValidationWork | None = None) -> None:
    """Independently rederive the inline delta, relative to proved originals."""
    from serverware import authority_transition_core as core

    if type(context) is not core.KernelContext:
        raise ChallengeRetentionError("retention transition context is not exact")
    validate_inline_delta(operation=context.operation, selected_rows=context.selected_rows,
                          mutations=mutations, work=work)


def validate_inline_delta(*, operation: str, selected_rows: Any, mutations: Any,
                          work: _ValidationWork | None = None) -> None:
    """Root/executor admission check without synthesizing a time or context."""
    if type(mutations) not in (tuple, list) or any(type(item) is not dict for item in mutations):
        raise ChallengeRetentionError("retention delta is not an exact mutation array")
    if not any(item.get("table") in (CHALLENGE_TABLE, *REFERENCE_TABLES) for item in mutations):
        return
    meter = _meter(work)
    actual = _copy(list(mutations), meter)
    expected = _expand(operation=operation, selected_rows=selected_rows,
                       mutations=actual, work=meter)
    # Canonical order is selected by the enclosing plan. Compare by immutable
    # source mutation identity so this checker introduces no second ordering.
    order = lambda item: (item["table"], item["keyDigest"], item["operation"])
    meter.prepare_comparison(actual, expected)
    if sorted(actual, key=order) != sorted(expected, key=order):
        raise ChallengeRetentionError("retention inline state differs from the real reference OLD/NEW delta")

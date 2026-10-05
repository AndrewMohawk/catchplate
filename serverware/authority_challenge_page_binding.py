"""Bind admitted maintenance-parent context to actual immutable page custody.

The caller independently admits the parent and its context. These functions
only map those owned originals to the real PostgreSQL page-store API. Stored
digest/length fields are framing, never a proof verdict: the complete raw-page
chain still requires independent replay. No connection, transaction, clock
window, work allowance, retry or commit is created here.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time

from serverware import authority_challenge_manifest as manifests
from serverware.authority_query_read_work import _ValidationWork
from serverware.authority_store import challenge_maintenance_pages as store


class ChallengePageBindingError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengePageBindingError("maintenance page differs from its original parent custody")


def _same(left, right, work):
    first, second = work.wire(left), work.wire(right)
    work.charge(input_bytes=len(first) + len(second))
    _require(first == second)


def _prepare(*, parent_plan_digest, maintenance_manifest_digest, context,
        phase_ordinal, page_kind, index_id, page_ordinal, original_deadline_ns, work):
    _require(type(work) is _ValidationWork and type(original_deadline_ns) is int
        and 0 < original_deadline_ns < 2**63)
    owned = manifests._context(context, work)
    _same(owned["originalDeadlineNs"], original_deadline_ns, work)
    # Closed scalar map: no caller-selected table, column, key or role names.
    selected = store._context({"parent_plan_digest": parent_plan_digest,
        "maintenance_manifest_digest": maintenance_manifest_digest,
        "source_revision": owned["sourceRevision"], "operation": owned["operation"],
        "operation_id": owned["operationId"], "request_digest": owned["requestDigest"],
        "configuration_digest": owned["configurationDigest"], "phase_ordinal": phase_ordinal,
        "page_kind": page_kind, "index_id": index_id, "page_ordinal": page_ordinal}, work)
    return owned, selected


def _descriptor(body_bytes, descriptor, work):
    _require(type(body_bytes) is bytes and 1 <= len(body_bytes) <= store.MAX_BODY_BYTES
        and type(descriptor) is dict and len(descriptor) == 2
        and all(type(name) is str for name in descriptor)
        and set(descriptor) == {"digest", "byteCount"}
        and type(descriptor["byteCount"]) is int
        and descriptor["byteCount"] == len(body_bytes))
    manifests._digest(descriptor["digest"])
    work.charge(hashes=1, input_bytes=len(body_bytes))
    actual = {"digest": "sha256:" + hashlib.sha256(body_bytes).hexdigest(),
        "byteCount": len(body_bytes)}
    _same(descriptor, actual, work)
    return actual


def _call(*, context, selected, original_deadline_ns, check, work, action, original_body=None):
    """One real store call, preserving its caller's local custody and meter."""
    _require(callable(check) and type(work) is _ValidationWork)
    limits = work.limits
    limit_values = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    identity = os.getpid(), threading.get_ident()
    context_bytes, selected_bytes = work.wire(context), work.wire(selected)
    last_clock = 0
    last_work = work.hash_work, work.input_bytes, work.json_nodes
    busy = failed = False

    def local():
        nonlocal last_clock, last_work
        _require(not failed and identity == (os.getpid(), threading.get_ident())
            and work.limits is limits
            and (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) == limit_values)
        values = work.hash_work, work.input_bytes, work.json_nodes
        _require(all(type(now) is int and before <= now <= maximum
            for before, now, maximum in zip(last_work, values, limit_values, strict=True)))
        current = store.lifecycle._guard(work, time.monotonic_ns)
        _require(type(current) is int and last_clock <= current < original_deadline_ns)
        last_clock, last_work = current, values

    def guarded_check():
        nonlocal busy, failed
        try:
            local()
            _require(not busy)
            busy = True
            _require(store.lifecycle._guard(work, check) is None)
            local()
        except BaseException:
            failed = True
            raise
        finally:
            busy = False

    try:
        local()
        result = action(guarded_check)
        local()
        _require(type(result) is bytes and 1 <= len(result) <= store.MAX_BODY_BYTES)
        if original_body is not None:
            _require(len(result) == len(original_body))
            work.charge(input_bytes=len(result) + len(original_body))
            _require(result == original_body)
        actual_context, actual_selected = work.wire(context), work.wire(selected)
        work.charge(input_bytes=len(context_bytes) + len(actual_context)
            + len(selected_bytes) + len(actual_selected))
        _require(context_bytes == actual_context and selected_bytes == actual_selected)
        local()
        return result
    except BaseException:
        failed = True
        raise


def retain_original(*, parent_plan_digest, maintenance_manifest_digest, context,
        phase_ordinal, page_kind, index_id, page_ordinal, body_bytes, descriptor,
        connection, original_deadline_ns, check, work) -> None:
    owned, selected = _prepare(parent_plan_digest=parent_plan_digest,
        maintenance_manifest_digest=maintenance_manifest_digest, context=context,
        phase_ordinal=phase_ordinal, page_kind=page_kind, index_id=index_id, page_ordinal=page_ordinal,
        original_deadline_ns=original_deadline_ns, work=work)
    actual = _descriptor(body_bytes, descriptor, work)
    binding = {**selected, "body_digest": actual["digest"], "body_byte_count": actual["byteCount"]}
    # The real store, not a callback verdict, owns native facade/role admission,
    # the nested savepoint and immutable INSERT plus literal SELECT readback.
    _call(context=owned, selected=binding, original_deadline_ns=original_deadline_ns,
        check=check, work=work, original_body=body_bytes, action=lambda guard: store.persist_page(binding=binding,
            body_bytes=body_bytes, connection=connection, original_deadline_ns=original_deadline_ns,
            check=guard, work=work))
    return None


def read_original(*, parent_plan_digest, maintenance_manifest_digest, context,
        phase_ordinal, page_kind, index_id, page_ordinal, connection,
        original_deadline_ns, check, work) -> bytes:
    owned, selected = _prepare(parent_plan_digest=parent_plan_digest,
        maintenance_manifest_digest=maintenance_manifest_digest, context=context,
        phase_ordinal=phase_ordinal, page_kind=page_kind, index_id=index_id, page_ordinal=page_ordinal,
        original_deadline_ns=original_deadline_ns, work=work)
    return _call(context=owned, selected=selected, original_deadline_ns=original_deadline_ns,
        check=check, work=work, action=lambda guard: store.read_original(context=selected,
            connection=connection, original_deadline_ns=original_deadline_ns, check=guard, work=work))

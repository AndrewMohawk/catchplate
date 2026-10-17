"""Necessary complete-vector delta compatibility, not mutation verification.

Only actual source-registered successor operations may select writable tables.
Both full vectors are genuinely source-validated and canonical on the caller's
existing work. Every nonwritable descriptor remains identical. Writable
revision/count deltas obey the actual mutation helpers' event-count semantics,
not an invented one-revision-per-operation or root-change rule.

Primary revisions advance per row mutation, including equal-image UPDATEs.
Each counted profile advances per event whose old or new image is a member;
two nonmembers advance zero, while equal member leaves still advance once.
Thus a positive revision delta may leave the root digest and count unchanged,
and counted advances need not equal the corresponding primary advance.

Two vectors cannot establish the actual events, memberships or exact deltas.
Genuine mutation/projection proofs and independent before-root enrollment and
currentness remain mandatory. This returns ordinary owned data, never a proof
token, reservation, capability or execution permission. No I/O, signature,
clock, SQL, root enrollment or replacement allowance is introduced here.
"""
from __future__ import annotations

from catchplate import authority_contract as authority
from catchplate import authority_current_root_vector as vector
from catchplate import authority_index_projection as projection
from catchplate import authority_successor_programs as programs


OPERATIONS = frozenset(programs.PROGRAMS)


class CurrentRootDeltaError(ValueError):
    pass


def _source(operation):
    if type(operation) is not str or operation not in OPERATIONS:
        raise CurrentRootDeltaError("complete-vector delta operation is not a source successor")
    program = programs.PROGRAMS[operation]
    spec = authority.operation_spec(operation)
    if (type(program) is not programs.SuccessorPlanningProgram
            or program.operation != operation or program.handler != spec["handler"]
            or program.planning_mode != spec["planningMode"]
            or spec["planningMode"] != "typed-successor-planning"):
        raise CurrentRootDeltaError("complete-vector successor differs from its source contract")
    writable = frozenset(spec["businessWrites"])
    if not writable or not writable <= frozenset(vector.PRIMARY_TABLES):
        raise CurrentRootDeltaError("complete-vector writes differ from the primary source inventory")
    indexes = frozenset(identity for table in writable
        for identity in projection.index_ids_for_table(table))
    if not indexes <= frozenset(vector.INDEX_IDS):
        raise CurrentRootDeltaError("complete-vector writes differ from the counted source inventory")
    maximum = spec["maximumMutations"]
    if type(maximum) is not int or maximum < 1:
        raise CurrentRootDeltaError("complete-vector operation mutation bound is invalid")
    return writable, indexes, maximum


def _unchanged(before, after, work, label):
    # Each vector has exact canonical bytes and source-closed scalar records;
    # complete field equality therefore also fixes that descriptor's bytes.
    work.prepare_comparison(before, after)
    if before != after:
        raise CurrentRootDeltaError(label + " changed without source write authority")


def _delta(before, after, revision, maximum, work, label):
    change = after[revision] - before[revision]
    if not 0 <= change <= maximum:
        raise CurrentRootDeltaError(label + " revision rolled back or exceeded its event bound")
    if change == 0:
        _unchanged(before, after, work, label)
    if abs(after["leafCount"] - before["leafCount"]) > change:
        raise CurrentRootDeltaError(label + " count change exceeds its revision events")
    return change


def _validate_on_work(*, operation, before_vector_bytes, after_vector_bytes, work):
    """Return owned before/after vectors after necessary compatibility checks.

    This does not prove that proposed changed roots follow from any mutation.
    Exact mutation counts and projected membership must still be reconstructed
    by the genuine transition proof. No successful proof carrier is accepted.
    """
    vector.capture._SharedLedger(work)
    writable, writable_indexes, maximum = _source(operation)
    # Hold both immutable originals and reject their bounds before the first
    # vector's native hashing/canonical callbacks; neither is decoded authority.
    originals = before_vector_bytes, after_vector_bytes
    if any(type(raw) is not bytes or not 2 <= len(raw) <= vector.MAX_BYTES for raw in originals):
        raise CurrentRootDeltaError("complete-vector delta requires two bounded original byte strings")
    before = vector._decode_on_work(originals[0], work=work)
    after = vector._decode_on_work(originals[1], work=work)
    primary_deltas = {}
    total = 0
    for old, new in zip(before["primaryRoots"], after["primaryRoots"]):
        table = old["table"]
        if table not in writable:
            _unchanged(old, new, work, "nonwritable primary root")
            change = 0
        else:
            change = _delta(old, new, "rootRevision", maximum, work, "writable primary root")
            if change > maximum - total:
                raise CurrentRootDeltaError("complete-vector primary events exceed the operation mutation bound")
            total += change
        primary_deltas[table] = change
    for old, new in zip(before["countedRoots"], after["countedRoots"]):
        if old["indexId"] not in writable_indexes:
            _unchanged(old, new, work, "nonwritable counted root")
        else:
            # Complete vector validation already joins each index's table and
            # source projection. Every written-table profile participates,
            # including one with zero member events in this proposed delta.
            _delta(old, new, "indexRevision", primary_deltas[old["table"]], work,
                "writable counted root")
    return before, after

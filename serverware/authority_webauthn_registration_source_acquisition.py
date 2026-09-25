"""Actual read-only pre-signing registration source acquisition.

The caller owns the admitted read-only transaction, complete source manifest,
independent full before roots, selector authority and original time policy.
Only the existing challenge, high-water, publication and optional OIDC-session
PK queries are issued. The evidence receipt root remains in the full source
inventory, but no receipt row, invented evidence digest or typed request is
needed to acquire the original rows from which evidence may later be signed.

Actual root observations are joined to the independent roots; the existing SQL,
staging and multiproof readers produce raw observations and the fixed source
verifier genuinely checks memberships and exact query/address associations on
the same work. Returned data is not a transferable proof or admission token.
Root currentness, enrollment authorization, committed-publication provenance,
ceremony verification and signing remain separate responsibilities. No effects,
write SQL, key enrollment, clock authority or additional allowance is created.
The configured owner must finish its real transaction/connection exits before
these observations escape that owner.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from serverware import authority_planner as planner
from serverware import authority_webauthn_registration_source_proofs as source


authority, core, reads, batch = source.authority, source.core, source.reads, source.batch
validation = source.validation
OPERATION = source.OPERATION


class WebAuthnRegistrationSourceAcquisitionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RegistrationSourceAcquisition:
    """Raw observations from this read, not source or signing authority."""

    business_before_roots: tuple[dict, ...]
    authorization_before_roots: tuple[dict, ...]
    selected_rows: tuple[dict, ...]
    before_proofs: tuple[dict, ...]
    query_reads: tuple[reads.QueryRead, ...]
    database_now: datetime
    trace: tuple[dict, ...]


def _acquire_on_work(cursor, *, registration_challenge_id,
        published_publication_id, oidc_session_id, manifest,
        business_before_roots, authorization_before_roots, now_epoch_ns,
        deadline_epoch_ns, maximum_clock_skew_ns, query_work, trace=None):
    """Acquire and prove the fixed source subset without a signed request.

    All invocation graphs are owned before query hashing or driver callbacks.
    The configured owner supplies the existing genuine cursor/manifest/trace;
    this worker neither opens a transaction nor accepts a successful proof DTO.
    """
    batch._SharedLedger(query_work)
    spec, contracts = source._source()
    business_tables = tuple(item.table for item in contracts if item.root_class == "business")
    authorization_tables = tuple(item.table for item in contracts if item.root_class == "authorization")
    if (type(manifest) is not tuple or len(manifest) != len(contracts)
            or type(business_before_roots) is not tuple
            or len(business_before_roots) != len(business_tables)
            or type(authorization_before_roots) is not tuple
            or len(authorization_before_roots) != len(authorization_tables)):
        raise WebAuthnRegistrationSourceAcquisitionError("registration source inventories are not full bounded tuples")
    owned = reads._CopyBudget(query_work).copy({
        "challenge": registration_challenge_id, "publication": published_publication_id,
        "session": oidc_session_id, "manifest": manifest,
        "business": business_before_roots, "authorization": authorization_before_roots,
        "now": now_epoch_ns, "deadline": deadline_epoch_ns, "skew": maximum_clock_skew_ns})
    if (any(type(item) is not dict or type(item.get("table")) is not str
                for item in owned["manifest"])
            or sorted(item["table"] for item in owned["manifest"])
                != sorted(business_tables + authorization_tables)):
        raise WebAuthnRegistrationSourceAcquisitionError("registration manifest differs from the full source inventory")
    for name, tables in (("business", business_tables), ("authorization", authorization_tables)):
        roots = owned[name]
        if (any(type(item) is not dict or set(item) != source.proofs._ROOT_FIELDS
                    or type(item["table"]) is not str for item in roots)
                or tuple(item["table"] for item in roots) != tables):
            raise WebAuthnRegistrationSourceAcquisitionError("registration before roots differ from their source classes")
    validation._integer(owned["now"], "registration source evaluation time", 1)
    validation._integer(owned["deadline"], "registration source deadline", 1)
    validation._integer(owned["skew"], "registration source clock skew", 0,
        authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if owned["now"] >= owned["deadline"]:
        raise WebAuthnRegistrationSourceAcquisitionError("registration source deadline has expired")
    if trace is None:
        trace = planner.PlannerTrace(operation=OPERATION)
    if (type(trace) is not planner.PlannerTrace or trace.operation != OPERATION
            or trace._complete_queries is not False or trace._counted_writes is not False):
        raise WebAuthnRegistrationSourceAcquisitionError("registration source acquisition requires its ordinary trace")
    acquisition = planner.authority_index_reader._ReadAcquisitionBudget(cursor, trace, work=query_work)
    try:
        queries = source._queries_on_work(registration_challenge_id=owned["challenge"],
            published_publication_id=owned["publication"], oidc_session_id=owned["session"], work=query_work)
        if (type(queries) is not tuple or len(queries) != 3 + int(owned["session"] is not None)
                or any(type(query) is not core.BoundedQuery or query.maximum_rows != 1 for query in queries)
                or sum(query.maximum_rows for query in queries) > spec["maximumQueryRows"]):
            raise WebAuthnRegistrationSourceAcquisitionError("registration source queries escaped their fixed PK subset")
        with acquisition.read_phase(cursor, trace, query_work):
            business, authorization, _ = planner._read_root_set(cursor, operation=OPERATION,
                manifest=owned["manifest"], trace=trace, work=query_work)
            planner.authority_revocation_semantics._canonical_equal((business, authorization),
                (owned["business"], owned["authorization"]), work=query_work,
                label="registration source roots differ from independent expectations")
            database_now = planner._read_database_now_on_work(cursor, query_work)
            database_ns = validation._now(database_now)
            if (abs(database_ns - owned["now"]) > owned["skew"]
                    or database_ns >= owned["deadline"]):
                raise WebAuthnRegistrationSourceAcquisitionError("registration source cutoff differs from original time policy")
            # Reserve the existing genuine primary empty-ladder constructor
            # work, without a warm-cache discount or a replacement allowance.
            query_work.charge(hashes=authority.TREE_DEPTH + 2)
            staging = planner.authority_query_staging.StagedQueryProofs(operation=OPERATION,
                business_before_roots=business, authorization_before_roots=authorization, query_work=query_work)
            selected, _, records = planner._read_bounded_transition_rows(cursor,
                operation=OPERATION, request=None, queries=queries, manifest=owned["manifest"],
                trace=trace, query_sources=staging, query_work=query_work)
            pending = staging.unproved_rows(selected)
            before_proofs = planner._completion_read_callback_on_work(query_work,
                lambda: planner._derive_multiproofs(cursor, selected_rows=pending,
                    roots=business + authorization, trace=trace))
            before_proofs = staging.merge_proofs(selected_rows=selected, remaining_proofs=before_proofs)
            # Regenerate the exact fixed recipe and genuinely verify all raw
            # memberships and associations. Its ordinary row result is not
            # used as a substitute for the raw originals returned below.
            source._verify_on_work(registration_challenge_id=owned["challenge"],
                published_publication_id=owned["publication"], oidc_session_id=owned["session"],
                business_before_roots=business, authorization_before_roots=authorization,
                selected_rows=selected, before_proofs=before_proofs, query_reads=records, work=query_work)
            acquisition.require_idle(cursor, trace, query_work)
        closed_trace = planner._completion_read_callback_on_work(query_work,
            lambda: trace.close(selected_rows=selected, mutation_plan=()))
        acquisition.require_idle(cursor, trace, query_work)
        return _RegistrationSourceAcquisition(business, authorization, selected,
            before_proofs, records, database_now, closed_trace)
    except BaseException:
        acquisition.failed = True
        raise

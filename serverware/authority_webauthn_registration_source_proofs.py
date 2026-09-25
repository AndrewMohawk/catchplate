"""Verify fixed pre-signing registration source rows on the original work.

The independently admitted selector values and complete existing before-root
inventory anchor genuine primary memberships and exact query/address joins.
Only challenge, high-water, publication and optional OIDC-session rows are
selected. No signed envelope, invented evidence digest or complete-operation
request is needed; the evidence receipt root remains in the full inventory.

The owning composition must independently establish root provenance/currentness,
row-selection authority, original evaluation time, enrollment permission and
prior committed-publication admission. This module performs no SQL, clock,
signing, evidence admission or mutation. Returned row data is not a transferable
proof token and cannot replace replay of the raw memberships by another owner.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_webauthn_evidence_proofs as proofs


authority, core, reads, batch = proofs.authority, proofs.core, proofs.reads, proofs.batch
registration = proofs.registration
validation, trust = registration.registration, registration.trust
OPERATION = registration.OPERATION


class WebAuthnRegistrationSourceProofError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _SourceRows:
    """Owned ordinary rows returned only by this invocation's real proof work."""

    challenge_row: dict
    high_water_row: dict
    published_row: dict
    oidc_session_row: dict | None


def _source():
    _, spec, contracts = proofs._source(OPERATION)
    business = ("oidc_browser_sessions", registration.evidence.EVIDENCE_TABLE)
    authorization = ("webauthn_challenges", trust.HIGH_WATER_TABLE, trust.PUBLICATION_TABLE)
    if (tuple(contract.table for contract in contracts) != business + authorization
            or tuple(contract.table for contract in contracts if contract.root_class == "business") != business
            or tuple(contract.table for contract in contracts if contract.root_class == "authorization") != authorization):
        raise WebAuthnRegistrationSourceProofError("registration source roots differ from the full source inventory")
    return spec, contracts


def _queries_on_work(*, registration_challenge_id, published_publication_id,
        oidc_session_id, work):
    """Regenerate only the existing three/four source PK query declarations."""
    batch._SharedLedger(work)
    spec, _ = _source()
    owned = reads._CopyBudget(work).copy({
        "challenge": registration_challenge_id, "publication": published_publication_id,
        "session": oidc_session_id})
    for name in ("challenge", "publication"):
        validation._text(owned[name], "registration source " + name + " ID", 4096, work)
    if owned["session"] is not None:
        validation._text(owned["session"], "registration source session ID", 4096, work)
    declarations = (
        ("registration_challenge", "webauthn_challenges", "id", owned["challenge"]),
        ("trust_high_water", trust.HIGH_WATER_TABLE, "authority_scope", trust.AUTHORITY_SCOPE),
        ("published_publication", trust.PUBLICATION_TABLE, "id", owned["publication"]),
    )
    if owned["session"] is not None:
        declarations += (("pending_oidc_session", "oidc_browser_sessions", "id", owned["session"]),)
    queries = tuple(core.BoundedQuery(
        query_id=core.query_program_id(OPERATION, name, table), table=table,
        predicates=(core.QueryPredicate(column, "eq", value),),
        order_by=(core.QueryOrder(column),), maximum_rows=1,
        absent_key={column: value}) for name, table, column, value in declarations)
    if (len(queries) > spec["maximumBusinessQueryRows"]
            or sum(query.work_units for query in queries) > spec["maximumBusinessWorkUnits"]):
        raise WebAuthnRegistrationSourceProofError("registration source query subset exceeds its existing bounds")
    # The actual source closer and copy traversal retain the existing query
    # semantics and charge their real work; no replacement allowance is made.
    return reads._snapshot_queries(OPERATION, queries, work=work)


def _verify_on_work(*, registration_challenge_id, published_publication_id,
        oidc_session_id, business_before_roots, authorization_before_roots,
        selected_rows, before_proofs, query_reads, work):
    """Prove raw source memberships and return their exact required row values.

    No successful-source-row carrier is accepted as input. The caller must hold
    independently admitted full roots and selectors before invoking this fixed
    subset; neither these rows nor matching source shapes establish authority.
    """
    ledger = batch._SharedLedger(work)
    spec, contracts = _source()
    count = 3 + int(oidc_session_id is not None)
    proofs._preflight(spec, contracts, business_before_roots,
        authorization_before_roots, selected_rows, before_proofs)
    if (len(selected_rows) != count or type(query_reads) is not tuple
            or len(query_reads) != count
            or any(type(record) is not reads.QueryRead or type(record.addresses) is not tuple
                or len(record.addresses) != 1 for record in query_reads)):
        raise WebAuthnRegistrationSourceProofError("registration source reads are not the exact PK subset")
    # Own the entire caller graph, including selectors, before any proof hash
    # or query encoding. Actual immutable QueryRead originals are reconstructed
    # on the same work before the first native callback as well.
    owned = reads._CopyBudget(work).copy({
        "challenge": registration_challenge_id, "publication": published_publication_id,
        "session": oidc_session_id, "business_before_roots": business_before_roots,
        "authorization_before_roots": authorization_before_roots,
        "selected_rows": selected_rows, "before_proofs": before_proofs})
    records = tuple(reads._copy_read(record, work) for record in query_reads)
    proofs._owned_inventory(owned, contracts)
    queries = _queries_on_work(registration_challenge_id=owned["challenge"],
        published_publication_id=owned["publication"], oidc_session_id=owned["session"], work=work)
    ledger.charge(hashes=authority.TREE_DEPTH + 2)
    business = batch._roots(owned["business_before_roots"])
    authorization = batch._roots(owned["authorization_before_roots"])
    limits = batch._primary_limits(spec, spec["maximumQueryRows"], ledger)
    memberships = proofs._child_on_work(work,
        lambda: proofs.primary.evaluate_primary_radix_memberships(
            table_contracts=contracts, business_before_roots=business,
            authorization_before_roots=authorization, selected_rows=owned["selected_rows"],
            before_proofs=owned["before_proofs"], limits=limits))
    metrics = memberships.result.metrics
    ledger.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
    if (memberships.result.business_after_roots != business
            or memberships.result.authorization_after_roots != authorization
            or metrics.mutations != 0 or metrics.recomputed_ancestors != 0):
        raise WebAuthnRegistrationSourceProofError("registration source proof changed the before roots")
    selected = memberships.selected_rows
    proofs.capacity._validate_capacity_transition(operation=OPERATION,
        selected_rows=selected, mutations=(), work=work)
    # This rebinds every declaration and ordered address to the actual proved
    # selected bytes and requires exact global coverage, not set-only matching.
    reads._validate_query_reads(OPERATION, queries=queries,
        query_reads=records, selected_rows=selected, work=work)
    work.prepare_scan(selected)
    if any(item["present"] is not True or type(item["row"]) is not dict for item in selected):
        raise WebAuthnRegistrationSourceProofError("registration signing requires each selected source row")
    work.prepare_copy(selected)
    rows = {item["table"]: item["row"] for item in selected}
    if len(rows) != count or set(rows) != {query.table for query in queries}:
        raise WebAuthnRegistrationSourceProofError("registration source rows do not match the fixed table subset")
    return _SourceRows(rows["webauthn_challenges"], rows[trust.HIGH_WATER_TABLE],
        rows[trust.PUBLICATION_TABLE], rows.get("oidc_browser_sessions"))

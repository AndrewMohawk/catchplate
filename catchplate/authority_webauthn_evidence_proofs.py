"""Genuine exact-PK proof phases for the two evidence admission operations.

The fixed caller runs read verification, genuine original-input semantic replay,
then write derivation on one shared work object. These functions accept raw
inputs, never a successful proof carrier or a caller-selected kernel. Returned
owned graphs and engine results are observations, not authorization tokens.

Every source business/authorization root is required, including the OIDC
business root for ordinary registration. Query declarations are regenerated
from the actual operation adapter; actual primary memberships precede their
complete selected-address association check. Write derivation independently
replays the primary inputs and the semantic mutations through the genuine
indexed-primary engine with an empty counted inventory. Empty framing and all
primary work remain charged; there is no counted query, SQL, capacity state,
registry activation, trusted clock, root-currentness or durable-write claim.
"""
from __future__ import annotations

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_complete_query_batch as batch
from catchplate import authority_complete_read_write as read_write
from catchplate import authority_contract as authority
from catchplate import authority_index_projection as projection
from catchplate import authority_indexed_mutation as indexed
from catchplate import authority_query_reads as reads
from catchplate import authority_radix_mutation as primary
from catchplate import authority_transition_core as core
from catchplate import authority_transition_webauthn_installation_admission as installation
from catchplate import authority_transition_webauthn_registration_admission as registration
from catchplate.authority_primary_contract import primary_table_contracts


_ROOT_FIELDS = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})
_SELECTED_FIELDS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})
_EVIDENCE_TABLE = registration.evidence.EVIDENCE_TABLE


class WebAuthnEvidenceProofError(ValueError):
    pass


def _source(operation):
    if type(operation) is not str:
        raise WebAuthnEvidenceProofError("evidence proof operation is not exact")
    if operation == registration.OPERATION:
        adapter, maximum = registration, 5
    elif operation == installation.OPERATION:
        adapter, maximum = installation, 3
    else:
        raise WebAuthnEvidenceProofError("evidence proof operation is not source fixed")
    spec = authority.operation_spec(operation)
    templates = spec["mutationTemplates"]
    if (tuple(spec["businessWrites"]) != (_EVIDENCE_TABLE,)
            or spec["globalAuditCapacity"] is not False or spec["selectors"]
            or spec["maximumQueryRows"] != maximum or spec["maximumBusinessQueryRows"] != maximum
            or spec["maximumMutations"] != 1 or spec["maximumBusinessMutations"] != 1
            or spec["maximumWorkUnits"] != 128 or spec["maximumBusinessWorkUnits"] != 128
            or len(templates) != 1 or templates[0]["table"] != _EVIDENCE_TABLE
            or templates[0]["mutation"] != "INSERT"
            or projection.index_ids_for_table(_EVIDENCE_TABLE)):
        raise WebAuthnEvidenceProofError("evidence proof escaped its no-index INSERT contract")
    return adapter, spec, primary_table_contracts(operation)


def _preflight(spec, contracts, business, authorization, selected, proofs):
    if (type(business) is not tuple or type(authorization) is not tuple
            or type(selected) is not tuple or type(proofs) is not tuple
            or len(business) + len(authorization) != len(contracts)
            or not 1 <= len(selected) <= spec["maximumQueryRows"]
            or len(proofs) != len(selected)):
        raise WebAuthnEvidenceProofError("evidence proof inventories are not exact bounded tuples")


def _owned_inventory(owned, contracts):
    for name, root_class in (("business_before_roots", "business"),
            ("authorization_before_roots", "authorization")):
        values = owned[name]
        expected = tuple(contract.table for contract in contracts if contract.root_class == root_class)
        if (any(type(item) is not dict or len(item) != len(_ROOT_FIELDS)
                or set(item) != _ROOT_FIELDS or type(item["table"]) is not str for item in values)
                or tuple(item["table"] for item in values) != expected):
            raise WebAuthnEvidenceProofError("evidence roots differ from the full source table classes")
    if any(type(item) is not dict or len(item) != len(_SELECTED_FIELDS)
            or set(item) != _SELECTED_FIELDS or item["contractSelector"] is not None
            for item in owned["selected_rows"]):
        raise WebAuthnEvidenceProofError("evidence selection is not an exact primary-key record")


def _child_on_work(work, call):
    """Fixed engines spend clamped child limits, not the outer meter directly.

    Their actual returned metrics are charged by the caller. Preserve the
    original outer allowance and counters even if a native callback fails;
    failure aborts this invocation and is never a free retry allowance.
    """
    limits = work.limits
    maxima = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    before = (work.hash_work, work.input_bytes, work.json_nodes)
    try:
        return call()
    finally:
        current_maxima = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
        current = (work.hash_work, work.input_bytes, work.json_nodes)
        if (work.limits is not limits
                or any(type(value) is not int for value in current_maxima + current)
                or current_maxima != maxima or current != before):
            raise WebAuthnEvidenceProofError("evidence proof child changed the outer work allowance")


def _verify_reads_on_work(*, operation, arguments, business_before_roots,
        authorization_before_roots, selected_rows, before_proofs, query_reads, work):
    """Own raw inputs, prove memberships and join the actual exact-PK queries.

    The ordinary dict result is deliberately not accepted by the write phase.
    Root authority, the historical cutoff and original semantic replay remain
    independent responsibilities of the fixed caller.
    """
    ledger = batch._SharedLedger(work)
    adapter, spec, contracts = _source(operation)
    _preflight(spec, contracts, business_before_roots, authorization_before_roots,
        selected_rows, before_proofs)
    if (type(arguments) is not dict or type(query_reads) is not tuple
            or not 1 <= len(query_reads) <= spec["maximumQueryRows"]
            or any(type(record) is not reads.QueryRead or type(record.addresses) is not tuple
                or len(record.addresses) != 1 for record in query_reads)):
        raise WebAuthnEvidenceProofError("evidence query inputs are not exact bounded PK observations")
    # Own the entire variable JSON graph, then the actual immutable-record
    # inventory, before constructors, proof hashing or any semantic callback.
    owned = reads._CopyBudget(work).copy({"arguments": arguments,
        "business_before_roots": business_before_roots,
        "authorization_before_roots": authorization_before_roots,
        "selected_rows": selected_rows, "before_proofs": before_proofs})
    records = tuple(reads._copy_read(record, work) for record in query_reads)
    _owned_inventory(owned, contracts)
    queries = adapter._query_recipe_on_work(arguments=owned["arguments"], work=work)
    if (type(queries) is not tuple or len(queries) != len(records)
            or any(type(query) is not core.BoundedQuery or query.maximum_rows != 1 for query in queries)
            or sum(query.maximum_rows for query in queries) > spec["maximumQueryRows"]):
        raise WebAuthnEvidenceProofError("evidence query recipe is not the actual bounded PK family")
    # PrimaryRoot construction can initialize the real empty ladder. No warm
    # cache discount: the engine's own cold allowance is also charged below.
    ledger.charge(hashes=authority.TREE_DEPTH + 2)
    business = batch._roots(owned["business_before_roots"])
    authorization = batch._roots(owned["authorization_before_roots"])
    limits = batch._primary_limits(spec, spec["maximumQueryRows"], ledger)
    memberships = _child_on_work(work, lambda: primary.evaluate_primary_radix_memberships(
        table_contracts=contracts, business_before_roots=business,
        authorization_before_roots=authorization, selected_rows=owned["selected_rows"],
        before_proofs=owned["before_proofs"], limits=limits))
    metrics = memberships.result.metrics
    ledger.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
    if (memberships.result.business_after_roots != business
            or memberships.result.authorization_after_roots != authorization
            or metrics.mutations != 0 or metrics.recomputed_ancestors != 0):
        raise WebAuthnEvidenceProofError("evidence membership proof changed its before roots")
    selected, proofs = memberships.selected_rows, memberships.before_proofs
    # This genuine generic inventory check applies the existing row/key/byte
    # bounds only. The fixed manifests admit no audit-capacity state or effect.
    capacity._validate_capacity_transition(operation=operation,
        selected_rows=selected, mutations=(), work=work)
    queries, records = reads._validate_query_reads(operation, queries=queries,
        query_reads=records, selected_rows=selected, work=work)
    return {"arguments": owned["arguments"],
        "business_before_roots": owned["business_before_roots"],
        "authorization_before_roots": owned["authorization_before_roots"],
        "selected_rows": selected, "before_proofs": proofs,
        "queries": queries, "query_reads": records}


def _derive_writes_on_work(*, operation, business_before_roots,
        authorization_before_roots, selected_rows, before_proofs, mutations, work):
    """Reverify raw primary inputs and derive roots from real semantic effects.

    The caller must supply the mutations returned by genuine fixed semantic
    replay, not treat a permissible INSERT shape as evidence authority. This
    phase independently verifies the underlying primary inputs in all cases,
    including an identical-retained no-op, without accepting a read token.
    """
    ledger = batch._SharedLedger(work)
    _, spec, contracts = _source(operation)
    _preflight(spec, contracts, business_before_roots, authorization_before_roots,
        selected_rows, before_proofs)
    if type(mutations) is not tuple or len(mutations) > 1:
        raise WebAuthnEvidenceProofError("evidence mutations are not an exact INSERT-or-empty tuple")
    owned = reads._CopyBudget(work).copy({"business_before_roots": business_before_roots,
        "authorization_before_roots": authorization_before_roots,
        "selected_rows": selected_rows, "before_proofs": before_proofs, "mutations": mutations})
    _owned_inventory(owned, contracts)
    if any(type(item) is not dict or item.get("table") != _EVIDENCE_TABLE
            or item.get("operation") != "INSERT" for item in owned["mutations"]):
        raise WebAuthnEvidenceProofError("evidence mutation escaped the sole INSERT table")
    capacity._validate_capacity_transition(operation=operation,
        selected_rows=owned["selected_rows"], mutations=owned["mutations"], work=work)
    ledger.charge(hashes=authority.TREE_DEPTH + 2)
    business = batch._roots(owned["business_before_roots"])
    authorization = batch._roots(owned["authorization_before_roots"])
    limits = read_write._write_limits(spec, ledger)
    result = _child_on_work(work, lambda: indexed.evaluate_indexed_primary_batch(
        table_contracts=contracts, business_before_roots=business,
        authorization_before_roots=authorization, selected_rows=owned["selected_rows"],
        before_proofs=owned["before_proofs"], mutations=owned["mutations"],
        index_inputs=(), limits=limits))
    ledger.charge(hashes=result.metrics.hashes, input_bytes=result.metrics.input_bytes,
        json_nodes=result.metrics.primary.json_nodes)
    if result.before_heads != () or result.after_heads != () or result.metrics.indexes != ():
        raise WebAuthnEvidenceProofError("evidence write derivation acquired counted-index authority")
    return result

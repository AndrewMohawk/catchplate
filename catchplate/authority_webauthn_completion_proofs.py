"""Genuine primary and counted-write proof phases for trust completion.

The fixed caller separately replays original installation semantics and the
exact query program between these phases. Raw documents, not successful proof
carriers, enter each phase. Returned observations establish neither independent
root authority nor installation, currentness, execution or durable custody.
Both phases own their entire input graph and spend the caller's existing work.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_complete_query_batch as batch
from catchplate import authority_complete_read_write as read_write
from catchplate import authority_contract as authority
from catchplate import authority_index_contract as counted
from catchplate import authority_index_heads as heads
from catchplate import authority_index_projection as projection
from catchplate import authority_indexed_mutation as indexed
from catchplate import authority_query_reads as reads
from catchplate import authority_radix_mutation as primary
from catchplate import authority_webauthn_evidence_proofs as evidence_proofs
from catchplate import authority_webauthn_transition_proof_contract as contract
from catchplate import authority_webauthn_transition_proof_wire as wire
from catchplate.authority_primary_contract import primary_table_contracts


OPERATION = "webauthn.trust.complete"
_SELECTED_FIELDS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})


class WebAuthnCompletionProofError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _CompletionReadObservation:
    """Ordinary owned membership observations, never an accepted input token."""

    selected_rows: tuple
    before_proofs: tuple


def _source():
    spec = authority.operation_spec(OPERATION)
    if (spec["maximumBusinessQueryRows"] != 4 or spec["maximumQueryRows"] != 5
            or spec["maximumBusinessMutations"] != 4 or spec["maximumMutations"] != 5
            or spec["maximumBusinessWorkUnits"] != 128 or spec["maximumWorkUnits"] != 130
            or spec["globalAuditCapacity"] is not True):
        raise WebAuthnCompletionProofError("completion proof escaped its source capacity bounds")
    identities = heads.required_index_ids(OPERATION, include_write_heads=True)
    if len(identities) != 3:
        raise WebAuthnCompletionProofError("completion requires all three publication profiles")
    return spec, primary_table_contracts(OPERATION), identities


def _document(owned, spec, contracts, identities):
    contract.validate_payload_shape(owned)
    if owned["operation"] != OPERATION or owned["queryFrontiers"]:
        raise WebAuthnCompletionProofError("completion has only its exact primary-key query family")
    for name, root_class in (("businessBeforeRoots", "business"),
            ("authorizationBeforeRoots", "authorization")):
        expected = tuple(item.table for item in contracts if item.root_class == root_class)
        if tuple(item["table"] for item in owned[name]) != expected:
            raise WebAuthnCompletionProofError("completion roots differ from the full source inventory")
    for name in ("countedBeforeHeads", "countedAfterHeads", "writeFrontiers"):
        if tuple(item["indexId"] for item in owned[name]) != identities:
            raise WebAuthnCompletionProofError("completion counted inventory is not the full source closure")
    selected, proofs = owned["selectedRows"], owned["beforeProofs"]
    if (not 1 <= len(selected) <= spec["maximumQueryRows"] or len(proofs) != len(selected)
            or any(type(item) is not dict or set(item) != _SELECTED_FIELDS
                or item["contractSelector"] is not None for item in selected)):
        raise WebAuthnCompletionProofError("completion selection is not an exact bounded PK inventory")


def _primary_inputs(owned, ledger, work):
    # Root construction may initialize the genuine empty ladder. There is no
    # cache discount; each child engine also reports its own actual work.
    ledger.charge(hashes=authority.TREE_DEPTH + 2)
    business = batch._roots(owned["businessBeforeRoots"])
    authorization = batch._roots(owned["authorizationBeforeRoots"])
    work.prepare_copy(owned["selectedRows"])
    selected = tuple(owned["selectedRows"])
    work.prepare_copy(owned["beforeProofs"])
    proofs = tuple(owned["beforeProofs"])
    return business, authorization, selected, proofs


def _before_heads(owned, roots, identities, ledger):
    primary_by_table = {item.table: item for item in roots}
    result = []
    for raw, identity in zip(owned["countedBeforeHeads"], identities):
        # Reconstruct the real source profile and its canonical empty root;
        # wire shape or a caller-supplied profile digest is not authority.
        ledger.charge(hashes=projection.PROFILE_HASH_WORK + 1)
        profile = projection.profile_for(identity)
        root = counted.CountedNode(raw["rootDigest"], raw["leafCount"])
        revision = raw["indexRevision"]
        empty = counted.empty_node(profile, "")
        if (type(revision) is not int or not 0 <= revision <= counted.I64_MAX
                or revision == 0 and root.count != 0
                or (root.count == 0) != (root.digest == empty.digest)
                or root.count > primary_by_table[profile.table].leaf_count):
            raise WebAuthnCompletionProofError("completion head revision, emptiness or primary population differs")
        result.append(indexed.IndexedMutationHead(identity, revision, root))
    return tuple(result)


def _verify_reads_on_work(*, document, work):
    """Prove raw primary memberships without mutating any supplied root.

    Exact QueryRead association remains the genuine semantic replay's job.
    Counted heads are bound source descriptors here, not population proofs.
    """
    ledger = batch._SharedLedger(work)
    if type(document) is not dict:
        raise WebAuthnCompletionProofError("completion proof document is not exact")
    owned = reads._CopyBudget(work).copy(document)
    spec, contracts, identities = _source()
    _document(owned, spec, contracts, identities)
    records = wire._decode_reads_on_work(owned["queryReads"], operation=OPERATION, work=work)
    if (not 1 <= len(records) <= spec["maximumQueryRows"]
            or any(type(record) is not reads.QueryRead or len(record.addresses) != 1
                or record.returned_row_count not in (0, 1) for record in records)):
        raise WebAuthnCompletionProofError("completion query observations are not exact primary-key reads")
    business, authorization, selected, proofs = _primary_inputs(owned, ledger, work)
    _before_heads(owned, business + authorization, identities, ledger)
    limits = batch._primary_limits(spec, spec["maximumQueryRows"], ledger)
    memberships = evidence_proofs._child_on_work(work,
        lambda: primary.evaluate_primary_radix_memberships(
            table_contracts=contracts, business_before_roots=business,
            authorization_before_roots=authorization, selected_rows=selected,
            before_proofs=proofs, limits=limits))
    metrics = memberships.result.metrics
    ledger.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes,
        json_nodes=metrics.json_nodes)
    if (memberships.result.business_after_roots != business
            or memberships.result.authorization_after_roots != authorization
            or metrics.mutations != 0 or metrics.recomputed_ancestors != 0):
        raise WebAuthnCompletionProofError("completion membership proof changed its before roots")
    capacity._validate_capacity_transition(operation=OPERATION,
        selected_rows=memberships.selected_rows, mutations=(), work=work)
    return _CompletionReadObservation(memberships.selected_rows, memberships.before_proofs)


def _derive_writes_on_work(*, document, mutations, work):
    """Reprove raw primary inputs and derive all three counted write heads.

    Mutations must come from the caller's genuine original-input semantic
    replay. The caller compares these actual roots/heads with the document's
    after vectors; this phase does not accept a prior membership result.
    """
    ledger = batch._SharedLedger(work)
    spec, contracts, identities = _source()
    if (type(document) is not dict or type(mutations) is not tuple
            or not 1 <= len(mutations) <= spec["maximumMutations"]):
        raise WebAuthnCompletionProofError("completion write inputs are not exact bounded values")
    captured = reads._CopyBudget(work).copy({"document": document, "mutations": mutations})
    owned, actual_mutations = captured["document"], captured["mutations"]
    _document(owned, spec, contracts, identities)
    business, authorization, selected, proofs = _primary_inputs(owned, ledger, work)
    capacity._validate_capacity_transition(operation=OPERATION,
        selected_rows=selected, mutations=actual_mutations, work=work)
    before = _before_heads(owned, business + authorization, identities, ledger)
    maximum = read_write._source_sizes(spec)[2]
    inputs = tuple(indexed.IndexedMutationInput(head.index_id, head.index_revision,
        head.index_root, wire._decode_frontier_on_work(raw["frontier"],
            maximum_entries=maximum, work=work))
        for head, raw in zip(before, owned["writeFrontiers"]))
    limits = read_write._write_limits(spec, ledger)
    result = evidence_proofs._child_on_work(work,
        lambda: indexed.evaluate_indexed_primary_batch(
            table_contracts=contracts, business_before_roots=business,
            authorization_before_roots=authorization, selected_rows=selected,
            before_proofs=proofs, mutations=actual_mutations,
            index_inputs=inputs, limits=limits))
    ledger.charge(hashes=result.metrics.hashes, input_bytes=result.metrics.input_bytes,
        json_nodes=result.metrics.primary.json_nodes)
    if (tuple(item.index_id for item in result.before_heads) != identities
            or tuple(item.index_id for item in result.after_heads) != identities):
        raise WebAuthnCompletionProofError("completion write result lost a source publication profile")
    return result

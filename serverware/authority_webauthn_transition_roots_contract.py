"""Source inventories and owned root projections for three WebAuthn transitions.

Requests are genuinely committed before a source-selected two-query metadata
read. Primary tables use one globally sorted union for SQL order, while result
roots retain their actual business/authorization classes. Counted heads cover
every source read family and potential write profile, including unused heads.
No cutoff or successful complete-query object is invented to select them.

Observed records and JSON projections remain ordinary data, not root currency,
historical admission, population proofs, reservations or execution authority.
The physical limits count actual source parameter and returned-scalar frames;
they are not new hash/byte/node allowances or database-network allocation
claims. All request, copy, profile, empty-root and projection work spends the
original meter. No SQL, clock, connection, signer or registry mutation is here.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_request_commitment as commitment
from serverware import authority_revocation_roots as roots
from serverware import authority_transition_webauthn_registration as registration
from serverware import authority_transition_webauthn_trust_stage as stage
from serverware import authority_transition_webauthn_completion as completion
from serverware import authority_webauthn_transition_proof_contract as proof_contract


authority, heads, reader, batch, primary, projection, counted = (
    roots.authority, roots.heads, roots.reader, roots.batch,
    roots.primary, roots.projection, roots.counted)
OPERATIONS = proof_contract.OPERATIONS
PRIMARY_TABLE = roots.PRIMARY_TABLE
PRIMARY_READ_PROFILE = "serverware.policyAuthorityWebAuthnTransitionPrimaryRootRead/v1"
_PrimaryObservation = roots._PrimaryObservation


class WebAuthnTransitionRootContractError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RootInventory:
    """Actual same-snapshot observations; construction grants no authority."""

    operation: str
    request_digest: str
    business_roots: tuple[_PrimaryObservation, ...]
    authorization_roots: tuple[_PrimaryObservation, ...]
    counted_heads: tuple[heads.CapturedIndexHead, ...]


def _source(operation, arguments):
    """Return exact source classes, global primary order and full head union."""
    if type(operation) is not str or operation not in OPERATIONS or type(arguments) is not dict:
        raise WebAuthnTransitionRootContractError("transition root source operation or arguments are invalid")
    spec = authority.operation_spec(operation)
    contracts = primary.primary_table_contracts(operation)
    business = tuple(sorted(set(spec["businessReads"]) | set(spec["businessWrites"])))
    authorization = tuple(sorted(spec["authorizationReads"]))
    tables = tuple(sorted(set(business) | set(authorization)))
    if (set(business) & set(authorization) or not tables
            or tuple(item.table for item in contracts) != tables
            or tuple(item.table for item in contracts if item.root_class == "business") != business
            or tuple(item.table for item in contracts if item.root_class == "authorization") != authorization
            or any(item.key_columns != primary.PRIMARY_KEY_COLUMNS[item.table]
                or type(item.write_access) is not bool
                or item.write_access != (item.table in spec["businessWrites"]) for item in contracts)
            or (authority.TREE_DEPTH, authority.TREE_RADIX) != (64, 16)):
        raise WebAuthnTransitionRootContractError("transition primary inventory differs from its actual source contracts")
    identities = proof_contract._head_ids(operation, arguments)
    if (type(identities) is not tuple or not 1 <= len(identities) <= heads.MAX_HEADS
            or identities != tuple(sorted(set(identities)))
            or any(identity not in projection.INDEX_IDS
                or projection._definition(identity).table not in tables for identity in identities)):
        raise WebAuthnTransitionRootContractError("transition counted inventory differs from its full source profiles")
    return business, authorization, tables, identities


def _validate_owned_request(request, operation, work):
    proof_contract._request(request, operation)
    arguments = request["arguments"]
    if operation == registration.OPERATION:
        registration._arguments(arguments, work)
    elif operation == stage.OPERATION:
        stage._arguments(arguments, work)
    elif operation == completion.OPERATION:
        completion._object(arguments, completion._ARGUMENT_FIELDS, "completion arguments")
        proof_contract.shape._text(arguments["publication_id"], 1024)
        work.prepare_utf8(arguments["publication_id"])
        completion._text(arguments["publication_id"], "publication ID")
        proof_contract.shape._digest(arguments["verification_evidence_digest"])
    else:
        raise WebAuthnTransitionRootContractError("transition root request operation is not source fixed")
    # This actual shared body also recomputes/joins the source business intent;
    # no result from a planner, kernel or prior request validator is accepted.
    digest = commitment._typed_request_digest(request, work=work)
    if commitment._request_different(digest, request["requestDigest"], work=work):
        raise WebAuthnTransitionRootContractError("transition root request commitment changed")
    work.prepare_utf8(operation)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(operation, digest), request["operationId"], work=work):
        raise WebAuthnTransitionRootContractError("transition root operation commitment changed")
    _source(operation, arguments)
    return request


def _capture_request_on_work(*, request, operation, work):
    """Own and genuinely bind a typed request without selecting any roots."""
    ledger = batch._SharedLedger(work)
    if type(operation) is not str or operation not in OPERATIONS:
        raise WebAuthnTransitionRootContractError("transition root request operation is not source fixed")
    proof_contract._request(request, operation)
    owned = batch._JSONCapture(ledger).visit(request)
    return _validate_owned_request(owned, operation, work)


def _limits(operation, arguments):
    """Exact two-SELECT source frame ceilings, not a replacement work budget."""
    _business, _authorization, tables, identities = _source(operation, arguments)
    primary_limit, head_limit = len(tables) + 1, len(identities) + 1
    parameters = (sum(8 + len(name) for name in (*tables, *identities))
        + 8 + len(str(primary_limit)) + 8 + len(str(head_limit)))
    # Both transports contain kind plus eight ordered scalars. Primary depth
    # and radix are the fixed two-digit source values; other counters are I64.
    primary_bytes = sum(9 * 8 + len("primary-root") + len(name) + 2 * 71 + 3 * 19 + 2 * 2
        for name in tables)
    head_bytes = sum(9 * 8 + len("head") + len(identity) + len(projection._definition(identity).table)
        + len(counted.PROFILE) + 3 * 71 + 2 * 19 for identity in identities)
    return reader._ReadAcquisitionLimits(max_sql_reads=2,
        max_parameter_bytes=parameters, max_transport_bytes=primary_bytes + head_bytes)


def _hold_primary(observed, table):
    if type(observed) is not _PrimaryObservation:
        raise WebAuthnTransitionRootContractError("transition primary observation has an unexpected exact type")
    row = {name: getattr(observed, name) for name in roots._PRIMARY_FIELDS}
    if (type(row["table_name"]) is not str or row["table_name"] != table
            or any(type(row[name]) is not int or not 0 <= row[name] <= counted.I64_MAX
                for name in roots._PRIMARY_COUNTERS)
            or type(row["tree_depth"]) is not int or row["tree_depth"] != 64
            or type(row["tree_radix"]) is not int or row["tree_radix"] != 16):
        raise WebAuthnTransitionRootContractError("transition primary observation scalars differ from source")
    for name in ("root_digest", "manifest_digest"):
        proof_contract.shape._digest(row[name])
    return row


def _hold_head(observed, identity):
    if type(observed) is not heads.CapturedIndexHead or type(observed.index_root) is not counted.CountedNode:
        raise WebAuthnTransitionRootContractError("transition counted observation has an unexpected exact type")
    node = observed.index_root
    row = {"index_id": observed.index_id, "table_name": observed.table,
        "counted_profile": observed.counted_profile, "projection_digest": observed.projection_digest,
        "projection_manifest_digest": observed.projection_manifest_digest,
        "index_revision": observed.index_revision, "root_digest": node.digest, "leaf_count": node.count}
    for name in ("index_id", "table_name", "counted_profile"):
        value = row[name]
        if type(value) is not str or not 1 <= len(value) <= 128 or not value.isascii() or "\x00" in value:
            raise WebAuthnTransitionRootContractError("transition counted observation text is not source bounded")
    for name in ("projection_digest", "projection_manifest_digest", "root_digest"):
        proof_contract.shape._digest(row[name])
    if (row["index_id"] != identity
            or any(type(row[name]) is not int or not 0 <= row[name] <= counted.I64_MAX
                for name in ("index_revision", "leaf_count"))):
        raise WebAuthnTransitionRootContractError("transition counted observation identity or counters changed")
    return row


def _project_on_work(inventory, *, operation, request, work):
    """Revalidate and own actual root4/head4 projections without authority."""
    ledger = batch._SharedLedger(work)
    if type(operation) is not str or operation not in OPERATIONS:
        raise WebAuthnTransitionRootContractError("transition root projection operation is not source fixed")
    proof_contract._request(request, operation)
    business, authorization, _tables, identities = _source(operation, request["arguments"])
    if type(inventory) is not _RootInventory:
        raise WebAuthnTransitionRootContractError("transition root projection inventory is not exact")
    observed_operation, request_digest = inventory.operation, inventory.request_digest
    business_values, authorization_values, head_values = (
        inventory.business_roots, inventory.authorization_roots, inventory.counted_heads)
    if (type(observed_operation) is not str or observed_operation != operation
            or type(business_values) is not tuple or len(business_values) != len(business)
            or type(authorization_values) is not tuple or len(authorization_values) != len(authorization)
            or type(head_values) is not tuple or len(head_values) != len(identities)):
        raise WebAuthnTransitionRootContractError("transition root projection inventory is incomplete")
    proof_contract.shape._digest(request_digest)
    # Hold every exact immutable scalar before request hashing or even fixed
    # source-manifest/profile callbacks. This joint real capture also detaches
    # the full caller request; no incoming record is reread afterwards.
    primary_rows = [_hold_primary(row, table) for table, row in
        zip(business + authorization, business_values + authorization_values)]
    head_rows = [_hold_head(row, identity) for identity, row in zip(identities, head_values)]
    owned = batch._JSONCapture(ledger).visit({"request": request, "operation": observed_operation,
        "requestDigest": request_digest, "primary": primary_rows, "heads": head_rows})
    actual = _validate_owned_request(owned["request"], operation, work)
    if commitment._request_different(owned["requestDigest"], actual["requestDigest"], work=work):
        raise WebAuthnTransitionRootContractError("root observations belong to another request")
    business, authorization, _tables, identities = _source(operation, actual["arguments"])
    manifest = roots._callback(work, primary.source_query_manifest_digest)
    primary_empty = roots._primary_empty_root(work)
    profiles, empty_heads, projection_manifest = heads._source_context(identities, work)
    primary_counts, projected_roots, projected_heads = {}, [], []
    for table, row in zip(business + authorization, owned["primary"]):
        if (row["table_name"] != table or row["manifest_digest"] != manifest
                or (row["leaf_count"] == 0) != (row["root_digest"] == primary_empty)
                or row["root_revision"] == 0 and row["leaf_count"] != 0):
            raise WebAuthnTransitionRootContractError("transition primary source manifest or empty root changed")
        primary_counts[table] = row["leaf_count"]
        projected_roots.append({"table": table, "rootRevision": row["root_revision"],
            "rootDigest": row["root_digest"], "leafCount": row["leaf_count"]})
    for identity, row in zip(identities, owned["heads"]):
        profile = profiles[identity]
        if (row["index_id"] != identity or row["table_name"] != profile.table
                or row["counted_profile"] != counted.PROFILE
                or row["projection_digest"] != profile.projection_digest
                or row["projection_manifest_digest"] != projection_manifest
                or row["index_revision"] == 0 and row["leaf_count"] != 0
                or (row["leaf_count"] == 0) != (row["root_digest"] == empty_heads[identity])
                or row["leaf_count"] > primary_counts[profile.table]):
            raise WebAuthnTransitionRootContractError("transition counted source profile, population or empty root changed")
        projected_heads.append({"indexId": identity, "indexRevision": row["index_revision"],
            "rootDigest": row["root_digest"], "leafCount": row["leaf_count"]})
    captured = batch._JSONCapture(ledger).visit({"business": projected_roots[:len(business)],
        "authorization": projected_roots[len(business):], "heads": projected_heads})
    result = []
    for name in ("business", "authorization", "heads"):
        work.prepare_copy(captured[name])
        result.append(tuple(captured[name]))
    return tuple(result)

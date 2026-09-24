"""Inactive signed revocation-plan v4 verification from raw retained evidence.

All expectations and both public keys must come from independent admission.
This verifier establishes neither their provenance nor root/time currentness,
one-use persistence, SQL effects, registry admission or terminal witnessing.
Inputs are decoded lossless JSON; bounded transport parsing remains external.
Source-only digest pins are computed once at import, outside invocation work.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_audit_capacity as capacity
from serverware import authority_audit_trace as audit_trace
from serverware import authority_complete_query_batch as capture
from serverware import authority_contract
from serverware import authority_index_heads as heads
from serverware import authority_index_projection as projection
from serverware import authority_index_reader as reader
from serverware import authority_index_trace as index_trace
from serverware import authority_primary_contract as primary_contract
from serverware import authority_revocation_plan_contract as contract
from serverware import authority_revocation_proof_bundle as retained
from serverware import authority_revocation_read_write as mixed
from serverware import authority_revocation_semantics as semantics
from serverware import authority_revocation_write_trace as write_trace
from serverware import authority_root_transition as roots
from serverware import authority_transition_core as core
from serverware.authority_query_read_work import QueryReadValidationLimits, QueryReadValidationMetrics


_SPEC = authority_contract.operation_spec(contract.OPERATION)
_HANDLER_DIGEST = authority_contract.handler_contract_digest(contract.OPERATION)
_QUERY_MANIFEST_DIGEST = primary_contract.source_query_manifest_digest()
_PROFILE_DIGESTS = tuple((name, projection.profile_for(name).projection_digest)
                         for name in heads.required_index_ids(contract.OPERATION))


class RevocationPlanError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RevocationPlanMetrics:
    capture: QueryReadValidationMetrics
    transport: QueryReadValidationMetrics
    planner_authentication: QueryReadValidationMetrics
    semantic_verification: QueryReadValidationMetrics
    bindings: QueryReadValidationMetrics
    planner_signature_attempts: int
    assertion_signature_attempts: int
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class RevocationPlanObservation:
    """Owned wire/semantic observations, never a reusable authority token."""

    envelope_bytes: bytes
    payload_bytes: bytes
    semantics: semantics.RevocationSemanticObservation
    metrics: RevocationPlanMetrics


def _same(left, right, work, label):
    semantics._canonical_equal(left, right, work=work, label=label)


def _wire(value, ledger):
    return retained._bounded_wire(value, ledger, maximum_bytes=contract.MAX_PAYLOAD_BYTES,
                                  maximum_nodes=contract.MAX_JSON_NODES)


def _frame(domain, frames, work):
    work.prepare_utf8(domain)
    work.charge(hashes=1, input_bytes=1 + 8 * len(frames) + sum(len(frame) for frame in frames))
    return core.framed_digest(domain, *frames)


def _ascii(value, work):
    work.prepare_utf8(value)
    return value.encode("ascii")


def _json_digest(domain, value, ledger):
    return _frame(domain, (_wire(value, ledger),), ledger.work)


class _TraceBudget(audit_trace.AuditTraceBudget):
    """Run the genuine classifier while reserving its actual encodings."""

    def __init__(self, work):
        self._work = work
        # The fixed aggregate key is copied, normalized and UTF-8 encoded by
        # authenticated_key_digest before its domain/2-frame hash. All other
        # constructor encodings dispatch through the genuine _identity seam.
        key = {"aggregate_id": capacity.AGGREGATE_ID}
        key_bytes, _ = work.prepare_encoding(key, ensure_ascii=False, shallow_copies=2)
        table_bytes = work.prepare_utf8(capacity.AGGREGATE_TABLE)
        work.prepare_utf8("serverware.policyAuthorityAuthenticatedKey/v1")
        work.charge(hashes=1, input_bytes=24 + table_bytes + key_bytes)
        super().__init__(contract.OPERATION)

    def _identity(self, access, table, key):
        value = {"access": access, "table": table, "key": key}
        self._work.prepare_encoding(value)
        return super()._identity(access, table, key)


def _authorization_sources(selected, work):
    # Reserve exactly the existing helper's three key encoders (address,
    # commitment and sort), key copy, row encoder and framed row hash. Fixed
    # source contracts/inventories are bounded metadata, not row traversals.
    for item in selected:
        if item["table"] not in _SPEC["authorizationReads"]:
            continue
        for _ in range(3):
            key_bytes, _ = work.prepare_encoding(item["key"])
        work.prepare_copy(item["key"])
        row_bytes, _ = work.prepare_encoding(item["row"])
        table_bytes = work.prepare_utf8(item["table"])
        work.prepare_utf8("serverware.policyAuthorityAuthorizationRow/v1")
        work.charge(hashes=1, input_bytes=1 + 32 + table_bytes + key_bytes
                    + (7 if item["present"] else 6) + row_bytes)
    return roots.derive_authorization_sources(operation=contract.OPERATION, selected_rows=selected)


def _trace_interval(declaration, role, work):
    """Derive the actual source interval from already-verified owned fields.

    The real reader's preparers reserve its genuine profile/selector/partition
    passes. This neither reconstructs another proof nor invents a selector
    recipe or caller-controlled interval. No query DTO is needed here.
    """
    work.prepare_copy(declaration["selectorItems"])
    selector = dict(declaration["selectorItems"])
    reader._profile_work(role.index_id, work)
    profile = projection.profile_for(role.index_id)
    reader._interval_work(role, profile, selector, work)
    return projection.query_interval(role.index_id, selector)


def _trace(payload, ledger, business_after_roots):
    work = ledger.work
    entries, mutations = payload["plannerTrace"]["entries"], payload["mutationPlan"]
    allowed_reads = (set(_SPEC["businessReads"]) | set(_SPEC["businessWrites"])
        | set(_SPEC["authorizationReads"]) | set(_SPEC["frameworkPreconditions"])
        | set(_SPEC["frameworkWrites"]) | {heads.HEAD_TABLE, reader.LEAF_TABLE, reader.NODE_TABLE})
    allowed_writes = set(_SPEC["businessWrites"])
    budget = _TraceBudget(work)
    counted = {item["indexId"]: item for item in payload["rootTransition"]["indexBeforeHeads"]}
    profiles = dict(_PROFILE_DIGESTS)
    selected = {(item["table"], item["keyDigest"]): item for item in payload["selectedBusinessRows"]}
    query_addresses = {item["queryId"]: {(address["table"], address["keyDigest"])
        for address in item["addresses"] if address["present"]}
        for item in payload["revocationProofBundle"]["inputs"]["queryReads"]}
    declarations = {item["role"]: item
        for item in payload["revocationProofBundle"]["inputs"]["queries"]}
    intervals, covers = {}, {}
    write_start = len(entries) - len(mutations)
    if write_start < 0:
        raise RevocationPlanError("revocation trace has no complete write suffix")
    writer_plans, writer_count = write_trace._prepare(mutations=mutations,
        before_proofs=payload["revocationProofBundle"]["inputs"]["beforeProofs"],
        business_after_roots=business_after_roots,
        before_heads=payload["rootTransition"]["indexBeforeHeads"], ledger=ledger)
    writer_start = write_start - writer_count
    if writer_start < 0:
        raise RevocationPlanError("revocation trace omits its complete writer acquisition block")
    writer_markers = iter(write_trace._markers(writer_plans, work))
    read_identities = set()
    for ordinal, entry in enumerate(entries):
        table, key, access = entry["table"], entry["key"], entry["access"]
        if access == "read":
            if ordinal >= write_start or table not in allowed_reads:
                raise RevocationPlanError("revocation trace read is outside its source or suffix")
            mutation_marker = type(key) is dict and key.get("profile") == index_trace.MUTATION_READ_PROFILE
            if writer_start <= ordinal < write_start:
                index_trace.validate_mutation_read_trace(contract.OPERATION, table, key)
                _same((table, key), next(writer_markers), work,
                      "revocation writer acquisition differs from genuine source effects")
            elif mutation_marker:
                raise RevocationPlanError("revocation writer acquisition is outside its exact source block")
            elif (table in {heads.HEAD_TABLE, reader.LEAF_TABLE, reader.NODE_TABLE}
                    or type(key) is dict and key.get("profile") == index_trace.PRIMARY_READ_PROFILE):
                index_trace.validate_complete_read_trace(contract.OPERATION, table, key)
                if table in (reader.LEAF_TABLE, reader.NODE_TABLE):
                    role = index_trace._source_role(contract.OPERATION, key)
                    declaration = declarations.get(role.name)
                    if declaration is None:
                        raise RevocationPlanError("revocation trace range has no proved source declaration")
                    if role.name not in intervals:
                        intervals[role.name] = _trace_interval(declaration, role, work)
                    interval = intervals[role.name]
                    head = counted.get(key["indexId"])
                    if (head is None or key["projectionDigest"] != profiles[key["indexId"]]
                            or (key["indexRevision"], key["rootDigest"], key["rootCount"])
                            != (head["indexRevision"], head["rootDigest"], head["leafCount"])):
                        raise RevocationPlanError("revocation trace range differs from proved head")
                    if table == reader.LEAF_TABLE:
                        _same((key["lower"], key["upper"], key["limit"]),
                              (interval.lower, interval.upper, declaration["maximumRows"] + 1), work,
                              "revocation trace leaf bounds differ from the proved source query")
                    else:
                        # Canonical cover construction has the same fixed
                        # structural bound as the real reader. Every PRESENT
                        # marker must be one actual source batch; this does not
                        # claim that signed markers prove physical execution.
                        if role.name not in covers:
                            covers[role.name] = reader.outside_prefixes(interval)
                        outside = covers[role.name]
                        first = key["prefixes"][0]["pathPrefix"]
                        try:
                            start = outside.index(first)
                        except ValueError as exc:
                            raise RevocationPlanError("revocation trace node is outside its source cover") from exc
                        if start % reader.MAX_NODE_IDENTITIES:
                            raise RevocationPlanError("revocation trace node batch is not source aligned")
                        expected = [{"depth": len(prefix), "pathPrefix": prefix}
                            for prefix in outside[start:start + reader.MAX_NODE_IDENTITIES]]
                        _same(key["prefixes"], expected, work,
                              "revocation trace node batch differs from the proved source cover")
                elif table != heads.HEAD_TABLE:
                    address = table, key["primaryKeyDigest"]
                    row = selected.get(address)
                    if (address not in query_addresses.get(key["queryId"], set()) or row is None
                            or row["key"] != {"id": key["primaryId"]}):
                        raise RevocationPlanError("revocation trace primary lookup differs from proved role")
            if type(key) is dict:
                read_identities.add((table, work.wire(key)))
        else:
            if ordinal < write_start or table not in allowed_writes:
                raise RevocationPlanError("revocation trace write is outside its source or suffix")
            mutation = mutations[ordinal - write_start]
            _same((table, key), (mutation["table"], mutation["key"]), work,
                  "revocation trace write differs from actual mutation order")
        budget.append(entry)
    budget.close(mutations)
    for item in payload["selectedBusinessRows"]:
        if (item["table"], work.wire(item["key"])) not in read_identities:
            raise RevocationPlanError("revocation trace omits an actual selected address")


def _expectations(owned, ledger):
    work, payload = ledger.work, owned["envelope"]["payload"]
    plan = payload["measuredPlan"]
    for name in ("expectedPlannerIdentity", "expectedVerifierIdentity"):
        contract.validate_identity_shape(owned[name])
    for name in ("expectedCapabilityId", "expectedPlannerTransactionId"):
        contract._digest(owned[name])
    if owned["expectedApproverPolicyDigest"] is not None:
        contract._digest(owned["expectedApproverPolicyDigest"])
    for name in ("expectedFence", "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs",
                 "nowEpochNs", "nowMonotonicNs", "maximumAssertionAgeNs", "maximumPlanAgeNs"):
        contract._integer(owned[name], minimum=1)
    contract._integer(owned["maximumClockSkewNs"])
    remaining_epoch = owned["deadlineEpochNs"] - owned["nowEpochNs"]
    remaining_monotonic = owned["deadlineMonotonicNs"] - owned["nowMonotonicNs"]
    if (owned["reservedAtEpochNs"] > owned["nowEpochNs"] + owned["maximumClockSkewNs"]
            or owned["nowEpochNs"] - owned["reservedAtEpochNs"] > owned["maximumPlanAgeNs"]
            or remaining_epoch <= 0 or remaining_monotonic <= 0
            or remaining_epoch > owned["maximumPlanAgeNs"] + owned["maximumClockSkewNs"]
            or remaining_monotonic > owned["maximumPlanAgeNs"]
            or abs(remaining_epoch - remaining_monotonic) > owned["maximumClockSkewNs"]):
        raise RevocationPlanError("revocation plan reservation or deadlines are not fresh and consistent")
    for actual, expected in (
        (payload["typedRequest"], owned["expectedRequest"]),
        (payload["plannerIdentity"], owned["expectedPlannerIdentity"]),
        (plan["capabilityId"], owned["expectedCapabilityId"]),
        (plan["plannerTransactionId"], owned["expectedPlannerTransactionId"]),
        (plan["fence"], owned["expectedFence"]),
        (plan["deadlineEpochNs"], owned["deadlineEpochNs"]),
        (plan["deadlineMonotonicNs"], owned["deadlineMonotonicNs"]),
    ):
        _same(actual, expected, work, "revocation plan differs from independently supplied expectations")


def _bindings(payload, owned, actual, ledger):
    work, plan = ledger.work, payload["measuredPlan"]
    inputs, authorization = payload["revocationProofBundle"]["inputs"], payload["authorizationProjection"]
    expected_fields = {
        "operationContractDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "handlerContractDigest": _HANDLER_DIGEST, "queryManifestDigest": _QUERY_MANIFEST_DIGEST,
        "operationId": payload["typedRequest"]["operationId"],
        "requestDigest": payload["typedRequest"]["requestDigest"], "workUnits": actual.work_units,
        "rootTransitionDigest": actual.proof.transition_digest,
    }
    for name, value in expected_fields.items():
        _same(plan[name], value, work, "revocation measured plan source or semantic field changed")
    transaction = _frame("serverware.policyAuthorityPlannerTransaction/v1",
        tuple(_ascii(plan[name], work) for name in ("operationId", "requestDigest", "capabilityId")), work)
    _same(transaction, plan["plannerTransactionId"], work, "revocation planner transaction derivation changed")
    for claimed, verified in ((payload["selectedBusinessRows"], inputs["selectedRows"]),
                             (payload["queryMultiproofs"], inputs["beforeProofs"]),
                             (payload["mutationPlan"], actual.mutations),
                             (payload["expectedResult"], actual.kernel.result)):
        _same(claimed, verified, work, "revocation outer data differs from genuine semantic evidence")
    sources = _authorization_sources(payload["selectedBusinessRows"], work)
    expected_projection = {
        **{name: plan[name] for name in ("plannerTransactionId", "operation", "operationId",
                                       "requestDigest", "capabilityId")},
        "authorizationReads": list(_SPEC["authorizationReads"]), "sourceRows": sources,
        "sourceHighWaterDigest": _json_digest("serverware.policyAuthorityAuthorizationRootSet/v1",
            owned["expectedBefore"]["authorizationBeforeRoots"], ledger),
        "approverPolicyDigest": owned["expectedApproverPolicyDigest"],
        "assertionEvidenceDigest": _json_digest("serverware.policyAuthorityWebAuthnAssertionEvidence/v1",
            payload["webauthnEvidence"], ledger),
        "verifierSessionIdentityDigest": owned["expectedVerifierIdentity"]["sessionIdentityDigest"],
        "verifierMeasurementDigest": owned["expectedVerifierIdentity"]["measurementDigest"],
        "verifierAttestationReceiptDigest": owned["expectedVerifierIdentity"]["attestationReceiptDigest"],
        "createdAtEpochNs": owned["reservedAtEpochNs"], "expiresAtEpochNs": owned["deadlineEpochNs"],
    }
    _same(authorization, expected_projection, work, "revocation authorization projection changed")
    for value, domain, graph in (
        (plan["selectedBusinessRowsDigest"], "serverware.policyAuthoritySelectedBusinessRows/v1", payload["selectedBusinessRows"]),
        (plan["mutationPlanDigest"], "serverware.policyAuthorityMutationPlan/v3", payload["mutationPlan"]),
        (plan["authorizationProjectionDigest"], "serverware.policyAuthorityAuthorizationProjection/v1", authorization),
        (plan["authorityRootSetBeforeDigest"], "serverware.policyAuthorityRootSet/v1", owned["expectedBefore"]["businessBeforeRoots"]),
        (payload["queryMultiproofsDigest"], "serverware.policyAuthorityRadixMultiproofSet/v3", payload["queryMultiproofs"]),
        (payload["plannerTraceDigest"], contract.PLANNER_TRACE_SCHEMA, payload["plannerTrace"]),
        (payload["expectedResultDigest"], "serverware.policyAuthorityControlledWriterResult/v2", actual.kernel.result),
    ):
        _same(value, _json_digest(domain, graph, ledger), work, "revocation derived commitment changed")
    snapshot = _frame(contract.SNAPSHOT_DOMAIN,
        tuple(_ascii(plan[name], work) for name in contract.SNAPSHOT_FRAME_FIELDS), work)
    _same(plan["authoritySnapshotDigest"], snapshot, work, "revocation v4 snapshot commitment changed")
    _trace(payload, ledger, actual.proof.primary.business_after_roots)


def verify_signed_revocation_plan(
    *, envelope: Any, expected_request: Any, expected_planner_identity: Any,
    planner_public_key: Ed25519PublicKey, expected_verifier_identity: Any,
    verifier_public_key: Ed25519PublicKey, expected_capability_id: str,
    expected_planner_transaction_id: str, expected_fence: int, reserved_at_epoch_ns: int,
    deadline_epoch_ns: int, deadline_monotonic_ns: int, now_epoch_ns: int,
    now_monotonic_ns: int, database_now: datetime, maximum_assertion_age_ns: int,
    maximum_plan_age_ns: int, maximum_clock_skew_ns: int, expected_before: Any,
    expected_approver_policy_digest: str | None, limits: QueryReadValidationLimits | None = None,
) -> RevocationPlanObservation:
    """Verify one complete signed graph against mandatory external expectations.

    One capture precedes SHA or signatures. Both actual transport encodings
    happen before proof replay, so there is no unreserved final outer buffer.
    Only the existing compact-output hold is released by the semantic worker.
    Failure aborts this invocation; return data grants no replay/persistence
    permission and cannot replace the independent inputs of another call.
    """
    try:
        if (not isinstance(planner_public_key, Ed25519PublicKey)
                or not isinstance(verifier_public_key, Ed25519PublicKey)
                or type(database_now) is not datetime or database_now.tzinfo is not timezone.utc):
            raise RevocationPlanError("revocation verification keys or UTC time have invalid types")
        ledger = retained._PackagingLedger(
            QueryReadValidationLimits() if limits is None else limits, comparing=True)
        work, before = ledger.work, ledger.work.metrics
        cutoff = semantics.complete.cutoff_microseconds(database_now)
        owned = capture._JSONCapture(ledger).visit({
            "envelope": envelope, "expectedRequest": expected_request,
            "expectedPlannerIdentity": expected_planner_identity,
            "expectedVerifierIdentity": expected_verifier_identity,
            "expectedCapabilityId": expected_capability_id,
            "expectedPlannerTransactionId": expected_planner_transaction_id,
            "expectedFence": expected_fence, "reservedAtEpochNs": reserved_at_epoch_ns,
            "deadlineEpochNs": deadline_epoch_ns, "deadlineMonotonicNs": deadline_monotonic_ns,
            "nowEpochNs": now_epoch_ns, "nowMonotonicNs": now_monotonic_ns,
            "databaseCutoffUs": cutoff, "maximumAssertionAgeNs": maximum_assertion_age_ns,
            "maximumPlanAgeNs": maximum_plan_age_ns, "maximumClockSkewNs": maximum_clock_skew_ns,
            "expectedBefore": expected_before, "expectedApproverPolicyDigest": expected_approver_policy_digest,
        }, depth=-1)
        captured = mixed._delta(before, work.metrics)
        contract.validate_signed_envelope_shape(owned["envelope"])
        payload = owned["envelope"]["payload"]
        before = work.metrics
        envelope_wire = _wire(owned["envelope"], ledger)
        payload_wire = _wire(payload, ledger)
        transported = mixed._delta(before, work.metrics)
        before = work.metrics
        _expectations(owned, ledger)
        # Closed shape admission fixes the unpadded signature at 86 ASCII
        # characters. Reserve padding allocation, ASCII conversion, URL
        # translation and decoder input plus the exact 64-byte output before
        # any of those buffers is made; no redundant round-trip is performed.
        work.charge(input_bytes=4 * 88 + 64)
        signature_text = owned["envelope"]["signatureBase64Url"] + "=="
        signature = base64.b64decode(signature_text, altchars=b"-_", validate=True)
        if len(signature) != 64:
            raise RevocationPlanError("revocation planner signature has invalid length")
        message = _ascii(_frame(contract.SIGNED_MEASURED_PLAN_SCHEMA, (payload_wire,), work), work)
        planner_public_key.verify(signature, message)
        authenticated = mixed._delta(before, work.metrics)
        before = work.metrics
        semantic_owned = {
            "bundle": payload["revocationProofBundle"], "transition": payload["rootTransition"],
            "request": payload["typedRequest"], "evidence": payload["webauthnEvidence"],
            "verifierIdentity": owned["expectedVerifierIdentity"],
            "capabilityId": owned["expectedCapabilityId"], "databaseCutoffUs": owned["databaseCutoffUs"],
            "nowEpochNs": owned["nowEpochNs"], "deadlineEpochNs": owned["deadlineEpochNs"],
            "maximumAgeNs": owned["maximumAssertionAgeNs"], "expectedBefore": owned["expectedBefore"],
        }
        actual = semantics._verify(semantic_owned, ledger, captured, verifier_public_key)
        verified = mixed._delta(before, work.metrics)
        before = work.metrics
        _bindings(payload, owned, actual, ledger)
        bound = mixed._delta(before, work.metrics)
        return RevocationPlanObservation(envelope_wire, payload_wire, actual,
            RevocationPlanMetrics(captured, transported, authenticated, verified, bound,
                1, actual.metrics.signature_attempts, ledger.hashes, ledger.input_bytes, ledger.json_nodes))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError,
            InvalidSignature, core.TransitionKernelError) as exc:
        if isinstance(exc, RevocationPlanError):
            raise
        raise RevocationPlanError("signed revocation plan verification failed") from exc

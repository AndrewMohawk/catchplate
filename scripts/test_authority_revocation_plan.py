#!/usr/bin/env python3
"""Genuine signed v4 revocation envelopes over independent semantic proofs.

Planner and receipt Ed25519 signatures are real, deterministic fixture keys.
Every expected plan/projection/snapshot/result commitment is independently
framed. Roots, identities, clocks and capability pins are synthetic external
expectations, not independently provisioned currentness or planner admission.
No registry replacement, successful verifier stub, SQL or execution is claimed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_primary_contract
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_plan_production as production
from serverware import authority_revocation_semantics as semantics
from serverware import authority_transition_webauthn as candidate
from serverware import authority_webauthn_assertion as assertion
from authority_revocation_semantics_fixture import SemanticFixture, OPERATION, wire, framed
import test_authority_audit_trace as trace_oracle
import test_authority_index_trace as marker_oracle
import test_authority_index_join as index_oracle
import test_authority_revocation_semantics as semantic_oracle


PAYLOAD_SCHEMA = "serverware.policyAuthorityPlannerResponse/v4"
PLAN_SCHEMA = "serverware.policyAuthorityMeasuredPlan/v4"
SIGNED_SCHEMA = "serverware.signedPolicyAuthorityMeasuredPlan/v4"
SNAPSHOT_DOMAIN = "serverware.policyAuthoritySnapshot/v4"
TRACE_SCHEMA = "serverware.policyAuthorityPlannerTrace/v1"
MIXED_SCHEMA = "serverware.policyAuthorityRevocationReadWriteTransition/v1"
PAYLOAD_FIELDS = {
    "schema", "measuredPlan", "typedRequest", "selectedBusinessRows", "mutationPlan",
    "queryMultiproofs", "queryMultiproofsDigest", "plannerTrace", "plannerTraceDigest",
    "authorizationProjection", "webauthnEvidence", "expectedResult", "expectedResultDigest",
    "plannerIdentity", "rootTransition", "revocationProofBundle",
}
PLAN_FIELDS = {
    "schema", "plannerTransactionId", "operation", "operationId", "requestDigest", "capabilityId",
    "sourceRevision", "authoritySchemaVersion", "operationContractDigest", "operationManifestDigest",
    "handlerContractDigest", "queryManifestDigest", "selectedBusinessRowsDigest", "mutationPlanDigest",
    "workUnits", "authorityRootSetBeforeDigest", "authorizationProjectionDigest", "authoritySnapshotDigest",
    "rootTransitionDigest", "deadlineMonotonicNs", "deadlineEpochNs", "fence",
}
SNAPSHOT_FIELDS = ("operation", "operationId", "requestDigest", "queryManifestDigest",
    "authorityRootSetBeforeDigest", "authorizationProjectionDigest", "selectedBusinessRowsDigest",
    "mutationPlanDigest", "rootTransitionDigest")


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def encoded(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def source_manifest_digest():
    # Source manifest framing includes its domain as a length-prefixed frame,
    # unlike the separate domain-NUL planner/proof protocol commitments.
    frames = (b"serverware.policyAuthorityQueryManifest/v1",
              wire(authority_primary_contract.source_query_manifest()))
    return sha(b"".join(len(frame).to_bytes(8, "big") + frame for frame in frames))


def authorization_sources(fixture):
    tables = authority_contract.operation_spec(OPERATION)["authorizationReads"]
    result = []
    for selected in fixture.selected_rows:
        if selected["table"] not in tables:
            continue
        result.append({"table": selected["table"], "selector": copy.deepcopy(selected["key"]),
            "present": selected["present"], "row": copy.deepcopy(selected["row"]),
            "rowDigest": framed("serverware.policyAuthorityAuthorizationRow/v1",
                selected["table"].encode("ascii"), wire(selected["key"]),
                b"present" if selected["present"] else b"absent", wire(selected["row"]))})
    return sorted(result, key=lambda item: (item["table"], wire(item["selector"])))


def independent_trace(fixture):
    """Closed source markers, not an assertion that physical SQL was run."""
    entries = [trace_oracle.entry(marker_oracle.HEAD_TABLE, marker_oracle.head_marker())]
    for query in fixture.read_write.read.queries:
        joined = fixture.read_write.read.joins[query.role]
        profile, root = joined.index.profile, joined.index.root
        entries.append(trace_oracle.entry(marker_oracle.LEAF_TABLE, {
            "profile": marker_oracle.RANGE_PROFILE, "queryId": query.query_id,
            "indexId": query.index_id, "projectionDigest": profile.projection_digest,
            "indexRevision": joined.anchor.index_revision, "rootDigest": root.digest, "rootCount": root.count,
            "lower": joined.interval.lower, "upper": joined.interval.upper, "limit": query.maximum_rows + 1,
        }))
        selected = {item["keyDigest"]: item for item in joined.selected}
        for leaf in joined.index.matches(joined.interval):
            item = selected[leaf.primary_key_digest]
            entries.append(trace_oracle.entry(query.table, {
                "profile": marker_oracle.PRIMARY_PROFILE, "queryId": query.query_id,
                "indexId": query.index_id, "primaryId": item["key"]["id"],
                "primaryKeyDigest": item["keyDigest"], "limit": 2,
            }))
    entries.extend(trace_oracle.entry(item["table"], item["key"])
                   for item in fixture.selected_rows if item["table"] != trace_oracle.TABLE)
    entries.extend(trace_oracle.capacity_entries(root=True))
    entries.extend(independent_write_trace(fixture))
    entries.extend(trace_oracle.entry(item["table"], item["key"], "write")
                   for item in fixture.final_mutations)
    return {"schema": TRACE_SCHEMA, "operation": OPERATION, "entries": trace_oracle.renumber(entries)}


def independent_write_batches(fixture):
    """Literal OLD/NEW union and radix child complement, not reader helpers."""
    for index_id, info in sorted(fixture.read_write.indexes.items()):
        targets = tuple(sorted(info["targets"]))
        opened = {""} | {key[:depth] for key in targets for depth in range(160)}
        siblings = tuple(sorted(prefix + digit for prefix in opened for digit in "0123456789abcdef"
                                if prefix + digit not in opened and prefix + digit not in targets))
        root = info["before"].root
        context = {"profile": marker_oracle.MUTATION_PROFILE, "indexId": index_id,
            "projectionDigest": info["profile"].projection_digest,
            "indexRevision": info["revision_before"], "rootDigest": root.digest, "rootCount": root.count}
        for kind, values in (("targets", targets), ("prefixes", siblings)):
            for offset in range(0, len(values), 256):
                yield kind, values[offset:offset + 256], context


def independent_write_trace(fixture):
    entries = []
    for kind, batch, context in independent_write_batches(fixture):
        values = (list(batch) if kind == "targets" else
                  [{"depth": len(prefix), "pathPrefix": prefix} for prefix in batch])
        entries.append(trace_oracle.entry(
            marker_oracle.LEAF_TABLE if kind == "targets" else marker_oracle.NODE_TABLE,
            {**context, kind: values, "limit": len(batch) + 1}))
    return entries


class PlanFixture:
    """Reusable source-owned shape with independent raw evidence and signer."""
    def __init__(self, **options):
        self.semantic = SemanticFixture(**options)
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
        self.other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
        self.identity = {"sessionIdentityDigest": sha(b"fixture planner session"),
            "measurementDigest": sha(b"fixture planner measurement"),
            "attestationReceiptDigest": sha(b"fixture planner attestation")}
        self.now_epoch_ns = self.semantic.receipt.now
        self.now_monotonic_ns = 8_000_000_000
        self.reserved_at_epoch_ns = self.now_epoch_ns - 1_000_000_000
        self.deadline_epoch_ns = self.now_epoch_ns + 120_000_000_000
        self.deadline_monotonic_ns = self.now_monotonic_ns + 120_000_000_000
        self.maximum_plan_age_ns = 300_000_000_000
        self.maximum_clock_skew_ns = 1_000_000_000
        self.maximum_assertion_age_ns = 300_000_000_000
        self.fence = 7
        self.approver_policy_digest = None
        self.planner_transaction_id = framed("serverware.policyAuthorityPlannerTransaction/v1",
            self.semantic.operation_id.encode("ascii"), self.semantic.request_digest.encode("ascii"),
            self.semantic.receipt.capability_id.encode("ascii"))
        self.rebuild_payload()

    def rebuild_payload(self):
        fixture = self.semantic
        projection = {
            "plannerTransactionId": self.planner_transaction_id, "operation": OPERATION,
            "operationId": fixture.operation_id, "requestDigest": fixture.request_digest,
            "capabilityId": fixture.receipt.capability_id,
            "authorizationReads": list(authority_contract.operation_spec(OPERATION)["authorizationReads"]),
            "sourceRows": authorization_sources(fixture),
            "sourceHighWaterDigest": framed("serverware.policyAuthorityAuthorizationRootSet/v1",
                wire(fixture.expected_before["authorizationBeforeRoots"])),
            "approverPolicyDigest": self.approver_policy_digest,
            "assertionEvidenceDigest": framed("serverware.policyAuthorityWebAuthnAssertionEvidence/v1",
                wire(fixture.receipt.evidence)),
            "verifierSessionIdentityDigest": fixture.receipt.identity["sessionIdentityDigest"],
            "verifierMeasurementDigest": fixture.receipt.identity["measurementDigest"],
            "verifierAttestationReceiptDigest": fixture.receipt.identity["attestationReceiptDigest"],
            "createdAtEpochNs": self.reserved_at_epoch_ns, "expiresAtEpochNs": self.deadline_epoch_ns,
        }
        self.payload = {
            "schema": PAYLOAD_SCHEMA,
            "measuredPlan": {
                "schema": PLAN_SCHEMA, "plannerTransactionId": self.planner_transaction_id,
                "operation": OPERATION, "operationId": fixture.operation_id,
                "requestDigest": fixture.request_digest, "capabilityId": fixture.receipt.capability_id,
                "sourceRevision": authority_contract.SOURCE_REVISION,
                "authoritySchemaVersion": authority_contract.SCHEMA_VERSION,
                "operationContractDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "handlerContractDigest": authority_contract.handler_contract_digest(OPERATION),
                "queryManifestDigest": source_manifest_digest(), "workUnits": fixture.work_units,
                "authorityRootSetBeforeDigest": framed("serverware.policyAuthorityRootSet/v1",
                    wire(fixture.expected_before["businessBeforeRoots"])),
                "deadlineMonotonicNs": self.deadline_monotonic_ns,
                "deadlineEpochNs": self.deadline_epoch_ns, "fence": self.fence,
            },
            "typedRequest": copy.deepcopy(fixture.request),
            "selectedBusinessRows": copy.deepcopy(list(fixture.selected_rows)),
            "mutationPlan": copy.deepcopy(list(fixture.final_mutations)),
            "queryMultiproofs": copy.deepcopy(list(fixture.before_proofs)),
            "plannerTrace": independent_trace(fixture), "authorizationProjection": projection,
            "webauthnEvidence": copy.deepcopy(fixture.receipt.evidence),
            "expectedResult": copy.deepcopy(fixture.kernel_expected["result"]),
            "plannerIdentity": copy.deepcopy(self.identity),
            "rootTransition": copy.deepcopy(fixture.transition),
            "revocationProofBundle": copy.deepcopy(fixture.bundle),
        }
        self.rehash()

    def rehash(self):
        """Recommit a caller-mutated outer plan without repairing its claims."""
        payload, measured = self.payload, self.payload["measuredPlan"]
        for field, domain, value in (
            ("selectedBusinessRowsDigest", "serverware.policyAuthoritySelectedBusinessRows/v1", payload["selectedBusinessRows"]),
            ("mutationPlanDigest", "serverware.policyAuthorityMutationPlan/v3", payload["mutationPlan"]),
            ("authorizationProjectionDigest", "serverware.policyAuthorityAuthorizationProjection/v1", payload["authorizationProjection"]),
            ("rootTransitionDigest", MIXED_SCHEMA, payload["rootTransition"]),
        ):
            measured[field] = framed(domain, wire(value))
        payload["queryMultiproofsDigest"] = framed("serverware.policyAuthorityRadixMultiproofSet/v3",
            wire(payload["queryMultiproofs"]))
        payload["plannerTraceDigest"] = framed(TRACE_SCHEMA, wire(payload["plannerTrace"]))
        payload["expectedResultDigest"] = framed("serverware.policyAuthorityControlledWriterResult/v2",
            wire(payload["expectedResult"]))
        measured["authoritySnapshotDigest"] = framed(SNAPSHOT_DOMAIN,
            *(measured[field].encode("ascii") for field in SNAPSHOT_FIELDS))
        self.resign()

    def resign(self, *, key=None):
        payload = copy.deepcopy(self.payload)
        message = framed(SIGNED_SCHEMA, wire(payload)).encode("ascii")
        self.envelope = {"schema": SIGNED_SCHEMA, "payload": payload,
            "signatureBase64Url": encoded((self.key if key is None else key).sign(message))}

    def arguments(self):
        fixture = self.semantic
        return {"envelope": copy.deepcopy(self.envelope), "expected_request": copy.deepcopy(fixture.request),
            "expected_planner_identity": copy.deepcopy(self.identity), "planner_public_key": self.key.public_key(),
            "expected_verifier_identity": copy.deepcopy(fixture.receipt.identity),
            "verifier_public_key": fixture.receipt.key.public_key(),
            "expected_capability_id": fixture.receipt.capability_id,
            "expected_planner_transaction_id": self.planner_transaction_id,
            "expected_fence": self.fence, "reserved_at_epoch_ns": self.reserved_at_epoch_ns,
            "deadline_epoch_ns": self.deadline_epoch_ns, "deadline_monotonic_ns": self.deadline_monotonic_ns,
            "now_epoch_ns": self.now_epoch_ns, "now_monotonic_ns": self.now_monotonic_ns,
            "database_now": fixture.database_now, "maximum_assertion_age_ns": self.maximum_assertion_age_ns,
            "maximum_plan_age_ns": self.maximum_plan_age_ns, "maximum_clock_skew_ns": self.maximum_clock_skew_ns,
            "expected_before": copy.deepcopy(fixture.expected_before),
            "expected_approver_policy_digest": self.approver_policy_digest}


PHASES = ("capture", "transport", "planner_authentication", "semantic_verification", "bindings")
add = semantic_oracle.add
graph_cost = semantic_oracle.graph_cost
canonical_comparison = semantic_oracle.canonical_comparison
units = semantic_oracle.units


def capture_document(fixture):
    supplied = fixture.arguments()
    return {"envelope": supplied["envelope"], "expectedRequest": supplied["expected_request"],
        "expectedPlannerIdentity": supplied["expected_planner_identity"],
        "expectedVerifierIdentity": supplied["expected_verifier_identity"],
        "expectedCapabilityId": supplied["expected_capability_id"],
        "expectedPlannerTransactionId": supplied["expected_planner_transaction_id"],
        "expectedFence": supplied["expected_fence"], "reservedAtEpochNs": supplied["reserved_at_epoch_ns"],
        "deadlineEpochNs": supplied["deadline_epoch_ns"], "deadlineMonotonicNs": supplied["deadline_monotonic_ns"],
        "nowEpochNs": supplied["now_epoch_ns"], "nowMonotonicNs": supplied["now_monotonic_ns"],
        "databaseCutoffUs": fixture.semantic.cutoff_us,
        "maximumAssertionAgeNs": supplied["maximum_assertion_age_ns"],
        "maximumPlanAgeNs": supplied["maximum_plan_age_ns"],
        "maximumClockSkewNs": supplied["maximum_clock_skew_ns"],
        "expectedBefore": supplied["expected_before"],
        "expectedApproverPolicyDigest": supplied["expected_approver_policy_digest"]}


def utf8_cost(value):
    return 0, 2 * len(value.encode("utf-8")), 2


def frame_cost(domain, frames):
    return add(utf8_cost(domain), (1, 1 + 8 * len(frames) + sum(map(len, frames)), 0))


def json_digest_cost(domain, value):
    return add(graph_cost(value), frame_cost(domain, (wire(value),)))


def utf8_graph_cost(value):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")
    return 0, 2 * len(encoded), 2 * semantic_oracle.kernel_oracle.nodes(value)


def independent_interval_work(fixture, query):
    declaration = next(item for item in fixture.semantic.bundle["inputs"]["queries"]
        if item["role"] == query.role)
    selector = dict(declaration["selectorItems"])
    joined = fixture.semantic.read_write.read.joins[query.role]
    profile = joined.profile
    descriptor = index_oracle.descriptor(query.index_id)
    partition = {name: selector[name] for name in descriptor["partitionFields"]}
    values = [graph_cost(declaration["selectorItems"]), utf8_graph_cost(descriptor),
        graph_cost(selector), utf8_graph_cost(descriptor), graph_cost(partition), utf8_graph_cost(partition),
        (3, 8 * 6, 0)]
    values.extend(utf8_cost(value) for value in selector.values() if type(value) is str)
    values.extend(utf8_cost(value) for value in ("serverware.policyAuthorityIndexPartition/v1",
        "serverware.policyAuthorityCountedIndex/v1", query.index_id, query.table, profile.projection_digest))
    return add(*values)


def independent_trace_work(fixture):
    """Literal real classifier constructor/append/key/suffix encoding units."""
    key = copy.deepcopy(trace_oracle.KEY)
    values = [graph_cost(key, 4, 4), utf8_cost(trace_oracle.TABLE),
        utf8_cost("serverware.policyAuthorityAuthenticatedKey/v1"),
        (1, 24 + len(trace_oracle.TABLE.encode("ascii")) + len(wire(key)), 0)]
    # The constructor creates scan, row, write, leaf, optional root and 64 node
    # identities; ordinal is never part of the encoded classifier identity.
    constructor = [*trace_oracle.capacity_entries(root=True),
        trace_oracle.entry(trace_oracle.TABLE, key, "write")]
    identity = lambda item: {name: item[name] for name in ("access", "table", "key")}
    values.extend(graph_cost(identity(item)) for item in constructor)
    indexed_tables = {info["profile"].table for info in fixture.semantic.read_write.indexes.values()}
    indexed_mutations = [item for item in fixture.semantic.final_mutations if item["table"] in indexed_tables]
    preparation_hashes = sum(item["row"] is not None for item in indexed_mutations)
    for info in fixture.semantic.read_write.indexes.values():
        preparation_hashes += 1 + 2 * sum(item[field] is not None
            for item in indexed_mutations if item["table"] == info["profile"].table
            for field in ("expectedRow", "row"))
    values.append((preparation_hashes, 0, 0))
    for kind, batch, _ in independent_write_batches(fixture.semantic):
        values.append(graph_cost(batch))
        if kind == "prefixes":
            values.append((0, 64 * len(batch), 8 * len(batch)))
    expected_writer = iter(independent_write_trace(fixture.semantic))
    writes = iter(fixture.payload["mutationPlan"])
    queries = {query.query_id: query for query in fixture.semantic.read_write.read.queries}
    opened = set()
    for item in fixture.payload["plannerTrace"]["entries"]:
        if item["access"] == "read":
            if item["key"].get("profile") == marker_oracle.MUTATION_PROFILE:
                expected = next(expected_writer)
                values.append(canonical_comparison((item["table"], item["key"]),
                    (expected["table"], expected["key"])))
            elif item["table"] == marker_oracle.LEAF_TABLE:
                query = queries[item["key"]["queryId"]]
                if query.role not in opened:
                    values.append(independent_interval_work(fixture, query))
                    opened.add(query.role)
                interval = fixture.semantic.read_write.read.joins[query.role].interval
                values.append(canonical_comparison(
                    (item["key"]["lower"], item["key"]["upper"], item["key"]["limit"]),
                    (interval.lower, interval.upper, query.maximum_rows + 1)))
            values.append(graph_cost(item["key"]))
        else:
            mutation = next(writes)
            values.append(canonical_comparison((item["table"], item["key"]),
                (mutation["table"], mutation["key"])))
        values.append(graph_cost(identity(item)))
    values.extend(graph_cost(item["key"]) for item in fixture.payload["selectedBusinessRows"])
    return add(*values)


def independent_metrics(fixture):
    """Declared outer passes plus independent genuine semantic phase oracles.

    Expected units never inspect returned observations or production counters.
    Admission is the per-dimension maximum of actual total and the sole compact
    hold peak, not an assertion that final spent work alone admits replay.
    """
    payload, measured = fixture.payload, fixture.payload["measuredPlan"]
    semantic = fixture.semantic
    result = {"capture": graph_cost(capture_document(fixture), 1, 1),
        "transport": add(graph_cost(fixture.envelope), graph_cost(payload))}
    authentication = [canonical_comparison(left, right) for left, right in (
        (payload["typedRequest"], semantic.request), (payload["plannerIdentity"], fixture.identity),
        (measured["capabilityId"], semantic.receipt.capability_id),
        (measured["plannerTransactionId"], fixture.planner_transaction_id),
        (measured["fence"], fixture.fence), (measured["deadlineEpochNs"], fixture.deadline_epoch_ns),
        (measured["deadlineMonotonicNs"], fixture.deadline_monotonic_ns))]
    # Fixed canonical 86-character signature: padded88, four bounded codec
    # byte passes and decoded64, all reserved before the actual concatenation.
    authentication.extend(((0, 4 * 88 + 64, 0),
        frame_cost(SIGNED_SCHEMA, (wire(payload),)), utf8_cost(framed(SIGNED_SCHEMA, wire(payload)))))
    result["planner_authentication"] = add(*authentication)
    inner = semantic_oracle.independent_metrics(semantic)
    result["semantic_verification"] = add(*(inner[name] for name in semantic_oracle.PHASES[1:]))
    bindings = [canonical_comparison(measured[field], measured[field]) for field in (
        "operationContractDigest", "operationManifestDigest", "handlerContractDigest", "queryManifestDigest",
        "operationId", "requestDigest", "workUnits", "rootTransitionDigest")]
    transaction_frames = tuple(measured[field].encode("ascii")
        for field in ("operationId", "requestDigest", "capabilityId"))
    bindings.extend(utf8_cost(measured[field]) for field in ("operationId", "requestDigest", "capabilityId"))
    bindings.extend((frame_cost("serverware.policyAuthorityPlannerTransaction/v1", transaction_frames),
        canonical_comparison(fixture.planner_transaction_id, measured["plannerTransactionId"])))
    bindings.extend(canonical_comparison(left, right) for left, right in (
        (payload["selectedBusinessRows"], semantic.bundle["inputs"]["selectedRows"]),
        (payload["queryMultiproofs"], semantic.bundle["inputs"]["beforeProofs"]),
        (payload["mutationPlan"], semantic.final_mutations),
        (payload["expectedResult"], semantic.kernel_expected["result"])))
    for item in semantic.selected_rows:
        if item["table"] in authority_contract.operation_spec(OPERATION)["authorizationReads"]:
            bindings.extend((graph_cost(item["key"], 8, 8), graph_cost(item["row"]),
                utf8_cost(item["table"]), utf8_cost("serverware.policyAuthorityAuthorizationRow/v1"),
                (1, 1 + 32 + len(item["table"].encode("ascii")) + len(wire(item["key"]))
                    + (7 if item["present"] else 6) + len(wire(item["row"])), 0)))
    bindings.extend((json_digest_cost("serverware.policyAuthorityAuthorizationRootSet/v1",
        semantic.expected_before["authorizationBeforeRoots"]),
        json_digest_cost("serverware.policyAuthorityWebAuthnAssertionEvidence/v1", payload["webauthnEvidence"]),
        canonical_comparison(payload["authorizationProjection"], payload["authorizationProjection"])))
    for digest, domain, graph in (
        (measured["selectedBusinessRowsDigest"], "serverware.policyAuthoritySelectedBusinessRows/v1", payload["selectedBusinessRows"]),
        (measured["mutationPlanDigest"], "serverware.policyAuthorityMutationPlan/v3", payload["mutationPlan"]),
        (measured["authorizationProjectionDigest"], "serverware.policyAuthorityAuthorizationProjection/v1", payload["authorizationProjection"]),
        (measured["authorityRootSetBeforeDigest"], "serverware.policyAuthorityRootSet/v1", semantic.expected_before["businessBeforeRoots"]),
        (payload["queryMultiproofsDigest"], "serverware.policyAuthorityRadixMultiproofSet/v3", payload["queryMultiproofs"]),
        (payload["plannerTraceDigest"], TRACE_SCHEMA, payload["plannerTrace"]),
        (payload["expectedResultDigest"], "serverware.policyAuthorityControlledWriterResult/v2", semantic.kernel_expected["result"]),
    ):
        bindings.extend((json_digest_cost(domain, graph), canonical_comparison(digest, digest)))
    bindings.extend(utf8_cost(measured[field]) for field in SNAPSHOT_FIELDS)
    bindings.extend((frame_cost(SNAPSHOT_DOMAIN, tuple(measured[field].encode("ascii") for field in SNAPSHOT_FIELDS)),
        canonical_comparison(measured["authoritySnapshotDigest"], measured["authoritySnapshotDigest"]),
        independent_trace_work(fixture)))
    result["bindings"] = add(*bindings)
    result["total"] = add(*(result[name] for name in PHASES))
    outer = add(*(result[name] for name in PHASES[:3]))
    for name in ("retained_peak", "proof_snapshot"):
        result[name] = add(outer, tuple(inner[name][index] - inner["capture"][index] for index in range(3)))
    result["semantic_total"] = add(outer, result["semantic_verification"])
    result["admission"] = tuple(max(result["retained_peak"][index], result["total"][index]) for index in range(3))
    return result


def production_context(fixture):
    owned = capture_document(fixture)
    return {name: copy.deepcopy(owned[name]) for name in (
        "expectedPlannerIdentity", "expectedVerifierIdentity", "expectedCapabilityId",
        "expectedPlannerTransactionId", "expectedFence", "reservedAtEpochNs",
        "deadlineEpochNs", "deadlineMonotonicNs", "nowEpochNs", "nowMonotonicNs",
        "maximumAssertionAgeNs", "maximumPlanAgeNs", "maximumClockSkewNs",
        "expectedBefore", "expectedApproverPolicyDigest")}


def production_arguments(fixture, work):
    payload = copy.deepcopy(fixture.payload)
    return {"request": payload["typedRequest"], "selected_rows": tuple(payload["selectedBusinessRows"]),
        "mutations": tuple(payload["mutationPlan"]), "before_proofs": tuple(payload["queryMultiproofs"]),
        "trace": tuple(payload["plannerTrace"]["entries"]), "evidence": payload["webauthnEvidence"],
        "result": payload["expectedResult"], "work_units": fixture.semantic.work_units,
        "bundle": payload["revocationProofBundle"], "transition": payload["rootTransition"],
        "transition_digest": payload["measuredPlan"]["rootTransitionDigest"],
        "context": production_context(fixture), "planner_private_key": fixture.key,
        "planner_public_key": fixture.key.public_key(), "work": work}


def independent_production_work(fixture):
    """Actual builder-only units over independently authored raw v4 graphs."""
    payload, semantic = fixture.payload, fixture.semantic
    measured = payload["measuredPlan"]
    inputs = semantic.bundle["inputs"]
    values = [canonical_comparison(left, right) for left, right in (
        (semantic.selected_rows, inputs["selectedRows"]), (semantic.final_mutations, inputs["mutations"]),
        (semantic.before_proofs, inputs["beforeProofs"]),
        (semantic.expected_before["businessBeforeRoots"], inputs["businessBeforeRoots"]),
        (semantic.expected_before["authorizationBeforeRoots"], inputs["authorizationBeforeRoots"]),
        (semantic.expected_before["indexBeforeHeads"], inputs["countedBeforeHeads"]),
        (semantic.request_digest, inputs["requestDigest"]),
        (semantic.request_digest, semantic.transition["requestDigest"]))]
    transaction = tuple(measured[name].encode("ascii") for name in ("operationId", "requestDigest", "capabilityId"))
    values.extend(utf8_cost(measured[name]) for name in ("operationId", "requestDigest", "capabilityId"))
    values.extend((frame_cost("serverware.policyAuthorityPlannerTransaction/v1", transaction),
        canonical_comparison(fixture.planner_transaction_id, fixture.planner_transaction_id)))
    for item in semantic.selected_rows:
        if item["table"] in authority_contract.operation_spec(OPERATION)["authorizationReads"]:
            values.extend((graph_cost(item["key"], 8, 8), graph_cost(item["row"]),
                utf8_cost(item["table"]), utf8_cost("serverware.policyAuthorityAuthorizationRow/v1"),
                (1, 1 + 32 + len(item["table"].encode("ascii")) + len(wire(item["key"]))
                    + (7 if item["present"] else 6) + len(wire(item["row"])), 0)))
    values.extend((json_digest_cost("serverware.policyAuthorityAuthorizationRootSet/v1",
        semantic.expected_before["authorizationBeforeRoots"]),
        json_digest_cost("serverware.policyAuthorityWebAuthnAssertionEvidence/v1", payload["webauthnEvidence"])))
    values.extend(graph_cost(value) for value in (semantic.selected_rows, semantic.final_mutations,
        semantic.before_proofs, payload["plannerTrace"]["entries"]))
    for domain, graph in (
        ("serverware.policyAuthoritySelectedBusinessRows/v1", payload["selectedBusinessRows"]),
        ("serverware.policyAuthorityMutationPlan/v3", payload["mutationPlan"]),
        ("serverware.policyAuthorityAuthorizationProjection/v1", payload["authorizationProjection"]),
        ("serverware.policyAuthorityRootSet/v1", semantic.expected_before["businessBeforeRoots"]),
        ("serverware.policyAuthorityRadixMultiproofSet/v3", payload["queryMultiproofs"]),
        (TRACE_SCHEMA, payload["plannerTrace"]),
        ("serverware.policyAuthorityControlledWriterResult/v2", payload["expectedResult"]),
    ):
        values.append(json_digest_cost(domain, graph))
    values.extend(utf8_cost(measured[name]) for name in SNAPSHOT_FIELDS)
    values.append(frame_cost(SNAPSHOT_DOMAIN, tuple(measured[name].encode("ascii") for name in SNAPSHOT_FIELDS)))
    values.extend((graph_cost(payload, 6, 4), graph_cost(fixture.envelope), (0, 566, 0),
        frame_cost(SIGNED_SCHEMA, (wire(payload),)), utf8_cost(framed(SIGNED_SCHEMA, wire(payload)))))
    return add(*values)


class RevocationPlanTests(unittest.TestCase):
    def verify(self, fixture, **changes):
        supplied = fixture.arguments()
        supplied.update(changes)
        return plan.verify_signed_revocation_plan(**supplied)

    def reject(self, fixture, **changes):
        with self.assertRaises(plan.RevocationPlanError):
            self.verify(fixture, **changes)

    def test_independent_sixteen_twenty_two_three_fields_and_real_signed_semantics(self):
        fixture = PlanFixture()
        self.assertEqual(set(fixture.payload), PAYLOAD_FIELDS)
        self.assertEqual(set(fixture.payload["measuredPlan"]), PLAN_FIELDS)
        self.assertEqual(set(fixture.envelope), {"schema", "payload", "signatureBase64Url"})
        self.assertEqual((len(PAYLOAD_FIELDS), len(PLAN_FIELDS), len(SNAPSHOT_FIELDS)), (16, 22, 9))
        actual = self.verify(fixture)
        self.assertEqual(actual.payload_bytes, wire(fixture.payload))
        self.assertEqual(actual.semantics.kernel.result, fixture.semantic.kernel_expected["result"])
        self.assertEqual(actual.semantics.mutations, fixture.semantic.final_mutations)
        self.assertEqual(actual.semantics.work_units, fixture.semantic.work_units)
        self.assertEqual(actual.semantics.proof.transition_bytes, wire(fixture.semantic.transition))

    def test_json_roundtrip_separate_signer_and_empty_role_variants_are_genuine(self):
        for options in ({"separate_signer": True}, {"approval": False, "include_audit": False}):
            with self.subTest(options=options):
                fixture = PlanFixture(**options)
                supplied = fixture.arguments()
                supplied["envelope"] = json.loads(wire(supplied["envelope"]))
                actual = plan.verify_signed_revocation_plan(**supplied)
                self.assertEqual(actual.payload_bytes, wire(fixture.payload))
                self.assertEqual(actual.semantics.mutations, fixture.semantic.final_mutations)

    def test_real_planner_signature_and_independent_planner_identity_are_required(self):
        for change in ("signature", "signer", "identity", "expected_identity"):
            with self.subTest(change=change):
                fixture = PlanFixture()
                supplied = fixture.arguments()
                if change == "signature":
                    supplied["envelope"]["signatureBase64Url"] = encoded(bytes(64))
                elif change == "signer":
                    supplied["planner_public_key"] = fixture.other_key.public_key()
                elif change == "identity":
                    fixture.payload["plannerIdentity"]["measurementDigest"] = sha(b"untrusted planner")
                    fixture.resign()
                    supplied["envelope"] = copy.deepcopy(fixture.envelope)
                else:
                    supplied["expected_planner_identity"]["sessionIdentityDigest"] = sha(b"different expected planner")
                with self.assertRaises(plan.RevocationPlanError):
                    plan.verify_signed_revocation_plan(**supplied)

    def test_real_receipt_signature_and_independent_verifier_pins_are_required(self):
        fixture = PlanFixture()
        self.reject(fixture, verifier_public_key=fixture.semantic.receipt.other_key.public_key())
        wrong = copy.deepcopy(fixture.semantic.receipt.identity)
        wrong["measurementDigest"] = sha(b"untrusted verifier")
        self.reject(fixture, expected_verifier_identity=wrong)
        fixture.payload["webauthnEvidence"]["verifierSignatureBase64url"] = encoded(bytes(64))
        fixture.payload["authorizationProjection"]["assertionEvidenceDigest"] = framed(
            "serverware.policyAuthorityWebAuthnAssertionEvidence/v1", wire(fixture.payload["webauthnEvidence"]))
        fixture.rehash()
        self.reject(fixture)

    def test_fully_rehashed_signed_false_business_result_is_denied_by_real_kernel(self):
        fixture = PlanFixture()
        fixture.payload["expectedResult"] = {"false": "correct signature and all outer digests"}
        fixture.rehash()
        with patch.object(candidate.WebAuthnCredentialRevokeKernel, "_transition",
                          wraps=candidate.WebAuthnCredentialRevokeKernel()._transition) as kernel:
            self.reject(fixture)
        self.assertEqual(kernel.call_count, 1)

    def test_coherent_false_mutation_proofs_still_fail_genuine_semantic_comparison(self):
        fixture = PlanFixture()
        changes = copy.deepcopy(list(fixture.semantic.final_mutations))
        item = next(item for item in changes if item["table"] == "webauthn_credentials")
        item["row"]["sign_count"] = 99
        fixture.semantic.rebuild_claim(changes)
        fixture.rebuild_payload()
        # Both the outer claimed mutation inventory and retained raw inventory
        # now contain the same independently proved but semantically false NEW.
        fixture.payload["mutationPlan"] = copy.deepcopy(list(fixture.semantic.read_write.mutations))
        fixture.rehash()
        self.reject(fixture)

    def test_duplicate_outer_selected_mutation_and_proof_views_cannot_diverge(self):
        for field in ("selectedBusinessRows", "mutationPlan", "queryMultiproofs"):
            with self.subTest(field=field):
                fixture = PlanFixture()
                fixture.payload[field] = fixture.payload[field][:-1]
                fixture.rehash()
                self.reject(fixture)

    def test_v3_envelopes_and_cross_version_inner_schemas_never_downgrade(self):
        for part in ("envelope", "payload", "measured", "primary_only"):
            with self.subTest(part=part):
                fixture = PlanFixture()
                if part == "payload":
                    fixture.payload["schema"] = "serverware.policyAuthorityPlannerResponse/v3"
                elif part == "measured":
                    fixture.payload["measuredPlan"]["schema"] = "serverware.policyAuthorityMeasuredPlan/v3"
                elif part == "primary_only":
                    fixture.payload["rootTransition"] = copy.deepcopy(fixture.semantic.transition["primaryTransition"])
                fixture.rehash()
                if part == "envelope":
                    fixture.envelope["schema"] = "serverware.signedPolicyAuthorityMeasuredPlan/v3"
                self.reject(fixture)

    def test_independent_capability_transaction_fence_request_and_policy_pins_are_not_claims(self):
        fixture = PlanFixture()
        changes = (
            {"expected_capability_id": sha(b"different capability")},
            {"expected_planner_transaction_id": sha(b"different planner transaction")},
            {"expected_fence": fixture.fence + 1},
            {"deadline_epoch_ns": fixture.deadline_epoch_ns + 1},
            {"deadline_monotonic_ns": fixture.deadline_monotonic_ns + 1},
            {"reserved_at_epoch_ns": fixture.reserved_at_epoch_ns - 1},
            {"expected_approver_policy_digest": sha(b"different policy")},
        )
        for changed in changes:
            with self.subTest(changed=tuple(changed)):
                self.reject(fixture, **changed)
        request = copy.deepcopy(fixture.semantic.request)
        request["arguments"]["reason"] = "different externally requested revocation"
        self.reject(fixture, expected_request=request)

    def test_supplied_clocks_age_skew_and_exact_scalar_types_are_mandatory(self):
        fixture = PlanFixture()
        for changed in (
            {"now_epoch_ns": fixture.deadline_epoch_ns},
            {"now_monotonic_ns": fixture.deadline_monotonic_ns},
            {"reserved_at_epoch_ns": fixture.now_epoch_ns + fixture.maximum_clock_skew_ns + 1},
            {"maximum_plan_age_ns": 1},
            {"now_monotonic_ns": fixture.now_monotonic_ns + fixture.maximum_clock_skew_ns + 1},
            {"maximum_assertion_age_ns": 1},
        ):
            with self.subTest(changed=tuple(changed)):
                self.reject(fixture, **changed)
        for field in ("expected_fence", "reserved_at_epoch_ns", "deadline_epoch_ns", "deadline_monotonic_ns",
                      "now_epoch_ns", "now_monotonic_ns", "maximum_assertion_age_ns", "maximum_plan_age_ns",
                      "maximum_clock_skew_ns"):
            for value in (True, 1.0, "1", None):
                with self.subTest(field=field, value=value):
                    self.reject(fixture, **{field: value})

    def test_all_external_before_vectors_and_database_cutoff_bind_independent_expectations(self):
        fixture = PlanFixture()
        for vector, field in (("businessBeforeRoots", "rootDigest"),
                              ("authorizationBeforeRoots", "rootDigest"),
                              ("indexBeforeHeads", "rootDigest")):
            with self.subTest(vector=vector):
                before = copy.deepcopy(fixture.semantic.expected_before)
                before[vector][0][field] = sha(b"different independent before root")
                self.reject(fixture, expected_before=before)
        from datetime import timedelta
        self.reject(fixture, database_now=fixture.semantic.database_now + timedelta(microseconds=1))
        before = copy.deepcopy(fixture.semantic.expected_before)
        before["indexBeforeHeads"] = before["indexBeforeHeads"][:-1]
        self.reject(fixture, expected_before=before)

    def test_closed_envelope_payload_plan_projection_and_boolean_integer_aliases_deny(self):
        fixture = PlanFixture()
        for location in ("envelope", "payload", "measuredPlan", "authorizationProjection", "plannerIdentity"):
            for action in ("extra", "missing"):
                with self.subTest(location=location, action=action):
                    supplied = fixture.arguments()
                    value = supplied["envelope"]
                    if location != "envelope":
                        value = value["payload"]
                    if location not in ("envelope", "payload"):
                        value = value[location]
                    if action == "extra":
                        value["callerAuthority"] = True
                    else:
                        value.pop(next(iter(value)))
                    with self.assertRaises(plan.RevocationPlanError):
                        plan.verify_signed_revocation_plan(**supplied)
        for field in ("fence", "workUnits", "authoritySchemaVersion", "deadlineEpochNs", "deadlineMonotonicNs"):
            fixture = PlanFixture()
            fixture.payload["measuredPlan"][field] = True
            fixture.rehash()
            self.reject(fixture)

    def test_rehashed_projection_cannot_change_pinned_identity_time_source_or_full_row(self):
        for change in ("identity", "time", "policy", "reads", "source_digest", "source_row"):
            with self.subTest(change=change):
                fixture = PlanFixture()
                projection = fixture.payload["authorizationProjection"]
                if change == "identity":
                    projection["verifierMeasurementDigest"] = sha(b"projection-selected verifier")
                elif change == "time":
                    projection["createdAtEpochNs"] -= 1
                elif change == "policy":
                    projection["approverPolicyDigest"] = sha(b"projection-selected policy")
                elif change == "reads":
                    projection["authorizationReads"] = projection["authorizationReads"][:-1]
                elif change == "source_digest":
                    projection["sourceHighWaterDigest"] = sha(b"different authorization roots")
                else:
                    projection["sourceRows"][0]["rowDigest"] = sha(b"different authorization row")
                fixture.rehash()
                self.reject(fixture)

    def test_rehashed_corrupt_raw_primary_proof_cannot_reach_the_real_kernel(self):
        fixture = PlanFixture()
        raw = fixture.payload["revocationProofBundle"]["inputs"]["beforeProofs"][0]
        raw["rootDigest"] = sha(b"false raw primary proof")
        fixture.payload["rootTransition"]["proofBundleDigest"] = framed(
            "serverware.policyAuthorityRevocationProofBundle/v1", wire(fixture.payload["revocationProofBundle"]))
        fixture.rehash()
        with patch.object(candidate.WebAuthnCredentialRevokeKernel, "_transition",
                          wraps=candidate.WebAuthnCredentialRevokeKernel()._transition) as kernel:
            self.reject(fixture)
        self.assertEqual(kernel.call_count, 0)

    def test_trace_framework_block_point_coverage_and_actual_write_suffix_are_required(self):
        for change in ("framework", "point", "write", "write_order", "ordinal", "counted_shape"):
            with self.subTest(change=change):
                fixture = PlanFixture()
                entries = fixture.payload["plannerTrace"]["entries"]
                if change == "framework":
                    entries.pop(next(index for index, item in enumerate(entries)
                        if item["table"] == trace_oracle.NODE_TABLE))
                elif change == "point":
                    selected = next(item for item in fixture.payload["selectedBusinessRows"]
                        if item["table"] != trace_oracle.TABLE)
                    entries[:] = [item for item in entries if not (item["access"] == "read"
                        and item["table"] == selected["table"] and item["key"] == selected["key"])]
                elif change == "write":
                    entries.pop()
                elif change == "write_order":
                    entries[-1], entries[-2] = entries[-2], entries[-1]
                elif change == "ordinal":
                    entries[0]["ordinal"] = True
                else:
                    entries[0]["key"]["rowLimit"] = 8
                if change != "ordinal":
                    fixture.payload["plannerTrace"]["entries"] = trace_oracle.renumber(entries)
                fixture.rehash()
                self.reject(fixture)

    def test_counted_trace_context_cannot_substitute_a_different_reconstructed_head(self):
        for field, value in (("rootDigest", sha(b"other counted head")), ("rootCount", 99),
                             ("indexRevision", 999), ("projectionDigest", sha(b"other projection"))):
            with self.subTest(field=field):
                fixture = PlanFixture()
                entry = next(item for item in fixture.payload["plannerTrace"]["entries"]
                             if item["table"] == marker_oracle.LEAF_TABLE)
                entry["key"][field] = value
                fixture.rehash()
                self.reject(fixture)
        for field in ("lower", "upper", "limit"):
            fixture = PlanFixture()
            marker = next(item["key"] for item in fixture.payload["plannerTrace"]["entries"]
                if item["table"] == marker_oracle.LEAF_TABLE)
            marker[field] = (marker["lower"][:-1] + "1" if field == "lower" else
                None if field == "upper" else marker["limit"] + 1)
            fixture.rehash()
            with self.subTest(source_range_field=field):
                self.reject(fixture)

    def test_all_caller_graphs_are_owned_before_first_real_hash(self):
        fixture = PlanFixture()
        supplied = fixture.arguments()
        before = wire(fixture.payload)
        real = hashlib.sha256
        changed = []
        def digest(*args, **kwargs):
            if not changed:
                supplied["envelope"]["payload"]["expectedResult"] = {"caller changed": True}
                supplied["expected_request"]["arguments"]["reason"] = "caller changed"
                supplied["expected_before"]["indexBeforeHeads"][0]["rootDigest"] = sha_original
                supplied["expected_planner_identity"]["measurementDigest"] = sha_original
                changed.append(True)
            return real(*args, **kwargs)
        sha_original = "sha256:" + "0" * 64
        with patch.object(hashlib, "sha256", side_effect=digest):
            actual = plan.verify_signed_revocation_plan(**supplied)
        self.assertEqual(changed, [True])
        self.assertEqual(actual.payload_bytes, before)
        self.assertEqual(actual.semantics.kernel.result, fixture.semantic.kernel_expected["result"])

    def test_no_supplied_success_token_key_callback_or_observer_can_replace_verification(self):
        fixture = PlanFixture()
        for field in ("planner_public_key", "verifier_public_key"):
            for value in (None, lambda *args: None, {"verified": True}):
                with self.subTest(field=field, value=type(value)):
                    self.reject(fixture, **{field: value})
        for field in ("verified", "result", "semantics", "signature_verified"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                self.verify(fixture, **{field: True})

    def test_one_joint_capture_one_ledger_and_real_semantic_proof_without_public_reset(self):
        fixture = PlanFixture()
        expected = independent_metrics(fixture)
        seen = {name: [] for name in ("ledgers", "captures", "semantics", "proof", "receipt")}
        real_init = plan.retained._PackagingLedger.__init__
        real_visit = plan.capture._JSONCapture.visit
        real_semantics = semantics._verify
        real_proof = plan.retained._compute_and_package
        real_receipt = assertion._verify_revoke_assertion_evidence

        def initialize(ledger, *args, **kwargs):
            real_init(ledger, *args, **kwargs)
            seen["ledgers"].append(ledger)

        def visit(copier, value, depth=0, ancestors=frozenset()):
            if copier.retain and not ancestors:
                seen["captures"].append((copier.ledger, depth))
            return real_visit(copier, value, depth, ancestors)

        def semantic(owned, ledger, capture, public_key):
            before = units(ledger.work.metrics)
            result = real_semantics(owned, ledger, capture, public_key)
            seen["semantics"].append((ledger, capture, before, result))
            return result

        def proof(**kwargs):
            result = real_proof(**kwargs)
            seen["proof"].append((kwargs["ledger"], result))
            return result

        def receipt(*args, **kwargs):
            result = real_receipt(*args, **kwargs)
            seen["receipt"].append(kwargs["work"])
            return result

        with patch.object(plan.retained._PackagingLedger, "__init__", initialize), \
                patch.object(plan.capture._JSONCapture, "visit", visit), \
                patch.object(semantics, "_verify", semantic), \
                patch.object(semantics, "verify_revocation_semantics", side_effect=AssertionError("fresh semantic ledger")), \
                patch.object(plan.retained, "_compute_and_package", proof), \
                patch.object(plan.mixed, "_verify", wraps=plan.mixed._verify) as mixed_proof, \
                patch.object(assertion, "_verify_revoke_assertion_evidence", receipt), \
                patch.object(assertion, "_verify_receipt_signature", wraps=assertion._verify_receipt_signature) as signature:
            actual = self.verify(fixture)
        self.assertEqual(tuple(len(seen[name]) for name in seen), (1, 1, 1, 1, 1))
        ledger = seen["ledgers"][0]
        self.assertEqual(seen["captures"], [(ledger, -1)])
        self.assertIs(seen["semantics"][0][0], ledger)
        self.assertIs(seen["proof"][0][0], ledger)
        self.assertIs(seen["receipt"][0].shared, ledger.work)
        self.assertIs(actual.semantics, seen["semantics"][0][3])
        self.assertEqual(seen["semantics"][0][2], add(*(expected[name] for name in PHASES[:3])))
        self.assertEqual(units(seen["semantics"][0][1]), expected["capture"])
        self.assertEqual((mixed_proof.call_count, signature.call_count), (1, 1))
        self.assertEqual((actual.metrics.planner_signature_attempts, actual.metrics.assertion_signature_attempts), (1, 1))
        self.assertFalse(ledger._held)
        self.assertEqual(units(ledger.work.metrics), expected["total"])

    def test_independent_phase_totals_and_conservative_peak_exact_and_minus_one_limits(self):
        fixture = PlanFixture()
        expected = independent_metrics(fixture)
        limits = accounting.QueryReadValidationLimits(*expected["admission"])
        actual = self.verify(fixture, limits=limits)
        for name in PHASES:
            self.assertEqual(units(getattr(actual.metrics, name)), expected[name], name)
        self.assertEqual((actual.metrics.total_hashes, actual.metrics.total_input_bytes,
                          actual.metrics.total_json_nodes), expected["total"])
        self.assertEqual((actual.semantics.metrics.total_hashes, actual.semantics.metrics.total_input_bytes,
                          actual.semantics.metrics.total_json_nodes), expected["semantic_total"])
        self.assertEqual(units(actual.semantics.metrics.capture), expected["capture"])
        packaging = actual.semantics.proof.packaging
        self.assertEqual(units(packaging.peak_reserved_work), expected["retained_peak"])
        self.assertEqual((packaging.total_hashes, packaging.total_input_bytes,
                          packaging.total_json_nodes), expected["proof_snapshot"])
        self.assertEqual(actual.envelope_bytes, wire(fixture.envelope))
        for dimension in range(3):
            quotas = list(expected["admission"])
            quotas[dimension] -= 1
            with self.subTest(dimension=dimension):
                self.reject(fixture, limits=accounting.QueryReadValidationLimits(*quotas))

    def test_invalid_limits_and_capture_exhaustion_deny_before_signature_or_semantics(self):
        fixture = PlanFixture()
        invalid = [object(), {}, object.__new__(accounting.QueryReadValidationLimits)]
        for name in ("max_hashes", "max_input_bytes", "max_json_nodes"):
            invalid.append(semantic_oracle.forged(accounting.QueryReadValidationLimits(), **{name: None}))
            invalid.append(semantic_oracle.forged(accounting.QueryReadValidationLimits(), **{name: True}))
        for value in invalid:
            with self.subTest(limits=value), patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    patch.object(semantics, "_verify", wraps=semantics._verify) as worker:
                self.reject(fixture, limits=value)
            self.assertEqual((hashes.call_count, worker.call_count), (0, 0))
        # The compact hold consumes 2,048 nodes; this leaves a single node for
        # the real capture and therefore cannot reach any authentication hash.
        with patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                patch.object(semantics, "_verify", wraps=semantics._verify) as worker:
            self.reject(fixture, limits=accounting.QueryReadValidationLimits(max_json_nodes=2049))
        self.assertEqual((hashes.call_count, worker.call_count), (0, 0))

    def test_genuine_rebuilt_trust_proofs_do_not_authorize_false_policy_or_pending_publication(self):
        for change in ("public_key", "signed_policy", "pending"):
            fixture = PlanFixture()
            semantic = fixture.semantic
            if change == "public_key":
                signer = next(row for row in semantic.rows["webauthn_credentials"]
                    if row["id"] == semantic.signer_id)
                signer["public_key_cose"] = "coherent different proved public key"
                # This rebuilds genuine BEFORE/AFTER primary and counted
                # proofs. The independently signed original policy is stale.
                semantic.rebuild_claim(semantic.final_mutations)
            elif change == "signed_policy":
                semantic.receipt.evidence = semantic.receipt.sign({**semantic.receipt.evidence,
                    "credentialPolicyDigest": sha(b"correctly signed false credential policy")})
            else:
                pending = copy.deepcopy(semantic.rows["webauthn_trust_publications"][0])
                pending.update(id="pending-publication-uuid", status="pending", sequence=2,
                    bundle_digest=sha(b"independent pending bundle"), published_at=None)
                semantic.rows["webauthn_trust_publications"].append(pending)
                semantic.rebuild_claim(semantic.final_mutations)
            fixture.rebuild_payload()
            with self.subTest(change=change), \
                    patch.object(plan.mixed, "_verify", wraps=plan.mixed._verify) as proof, \
                    patch.object(candidate.WebAuthnCredentialRevokeKernel, "_transition",
                        wraps=candidate.WebAuthnCredentialRevokeKernel()._transition) as kernel:
                self.reject(fixture)
            self.assertEqual(proof.call_count, 1)
            self.assertEqual(kernel.call_count, 1)

    def test_outer_final_binding_denial_cannot_reset_the_spent_semantic_ledger(self):
        fixture = PlanFixture()
        expected = independent_metrics(fixture)
        self.assertGreater(expected["total"][2], expected["retained_peak"][2])
        limits = list(expected["admission"])
        limits[2] = expected["total"][2] - 1
        real = plan._bindings
        seen = []

        def bindings(payload, owned, actual, ledger):
            seen.append((ledger, units(ledger.work.metrics), ledger._held, actual))
            return real(payload, owned, actual, ledger)

        with patch.object(plan, "_bindings", bindings), \
                patch.object(plan.mixed, "_verify", wraps=plan.mixed._verify) as proof:
            self.reject(fixture, limits=accounting.QueryReadValidationLimits(*limits))
        self.assertEqual((len(seen), proof.call_count), (1, 1))
        ledger, before, held, actual = seen[0]
        self.assertFalse(held)
        self.assertEqual(before, expected["semantic_total"])
        self.assertEqual(actual.kernel.result, fixture.semantic.kernel_expected["result"])
        self.assertEqual(ledger.hashes, expected["total"][0])
        self.assertEqual(ledger.work.limits.max_json_nodes, limits[2])

    def test_writer_block_uses_genuine_preparation_geometry_and_same_spent_ledger(self):
        fixture = PlanFixture()
        seen = []
        real = plan.write_trace._prepare
        def prepare(**kwargs):
            ledger = kwargs["ledger"]
            before = units(ledger.work.metrics)
            result = real(**kwargs)
            seen.append((ledger, before, units(ledger.work.metrics), result))
            return result
        with patch.object(plan.write_trace, "_prepare", side_effect=prepare), \
                patch.object(plan.write_trace.indexed, "_verify_primary",
                    wraps=plan.write_trace.indexed._verify_primary) as primary, \
                patch.object(plan.write_trace.indexed.counted, "evaluate_index_mutations",
                    wraps=plan.write_trace.indexed.counted.evaluate_index_mutations) as sparse, \
                patch.object(plan.mixed, "_verify", wraps=plan.mixed._verify) as proof:
            actual = self.verify(fixture)
        self.assertEqual((len(seen), primary.call_count, sparse.call_count, proof.call_count),
            (1, 1, len(fixture.semantic.read_write.indexes), 1))
        ledger, before, after, (prepared, count) = seen[0]
        self.assertGreater(before[0], 0)
        self.assertGreater(after[0], before[0])
        self.assertEqual(after[1:], before[1:])  # historical preparation is hash scope
        self.assertEqual(tuple(item.index_id for item, _, _ in prepared),
            tuple(sorted(fixture.semantic.read_write.indexes)))
        self.assertEqual(count, len(independent_write_trace(fixture.semantic)))
        self.assertEqual(units(ledger.work.metrics), independent_metrics(fixture)["total"])
        self.assertEqual(actual.semantics.mutations, fixture.semantic.final_mutations)

    def test_resigned_missing_extra_reordered_or_displaced_writer_batches_deny_after_semantics(self):
        for change in ("missing", "duplicate", "order", "outside", "ordinary_inside", "all_missing"):
            fixture = PlanFixture()
            entries = fixture.payload["plannerTrace"]["entries"]
            positions = [index for index, item in enumerate(entries)
                if item["key"].get("profile") == marker_oracle.MUTATION_PROFILE]
            if change == "missing":
                entries.pop(positions[0])
            elif change == "duplicate":
                entries.insert(positions[0], copy.deepcopy(entries[positions[0]]))
            elif change == "order":
                entries[positions[0]], entries[positions[1]] = entries[positions[1]], entries[positions[0]]
            elif change == "outside":
                entries.insert(1, entries.pop(positions[0]))
            elif change == "ordinary_inside":
                entries.insert(positions[1], trace_oracle.entry("webauthn_credentials", {"id": "credential"}))
            else:
                entries[:] = [item for item in entries if item["key"].get("profile") != marker_oracle.MUTATION_PROFILE]
            fixture.payload["plannerTrace"]["entries"] = trace_oracle.renumber(entries)
            fixture.rehash()
            with self.subTest(change=change), patch.object(plan, "_trace", wraps=plan._trace) as reached:
                self.reject(fixture)
            self.assertEqual(reached.call_count, 1)

    def test_resigned_shape_valid_writer_targets_prefixes_and_before_context_are_exact(self):
        for change in ("target", "prefix", "head", "revision", "profile", "readonly"):
            fixture = PlanFixture()
            entries = fixture.payload["plannerTrace"]["entries"]
            wanted = "prefixes" if change == "prefix" else "targets"
            marker = next(item["key"] for item in entries
                if item["key"].get("profile") == marker_oracle.MUTATION_PROFILE and wanted in item["key"])
            if change == "target":
                marker["targets"] = ["f" * 160]
                marker["limit"] = 2
            elif change == "prefix":
                marker["prefixes"] = [{"depth": 1, "pathPrefix": "f"}]
                marker["limit"] = 2
            elif change == "head":
                marker["rootDigest"] = sha(b"after or unrelated root is not before")
            elif change == "revision":
                marker["indexRevision"] += 1
            elif change == "profile":
                marker["projectionDigest"] = sha(b"different source projection")
            else:
                # This final control is source-shape denial; the preceding
                # substitutions remain well-shaped but semantically false.
                marker["indexId"] = "webauthn_publication_status"
            fixture.rehash()
            with self.subTest(change=change), patch.object(plan, "_trace", wraps=plan._trace) as reached:
                self.reject(fixture)
            self.assertEqual(reached.call_count, 1)

    def test_complete_writer_identity_coverage_with_wrong_batch_boundaries_still_denies(self):
        fixture = PlanFixture()
        entries = fixture.payload["plannerTrace"]["entries"]
        position = next(index for index, item in enumerate(entries)
            if item["key"].get("profile") == marker_oracle.MUTATION_PROFILE
            and len(item["key"].get("prefixes", ())) == 256)
        original = entries[position]
        left, right = copy.deepcopy(original), copy.deepcopy(original)
        left["key"]["prefixes"], right["key"]["prefixes"] = (
            left["key"]["prefixes"][:128], right["key"]["prefixes"][128:])
        left["key"]["limit"] = right["key"]["limit"] = 129
        entries[position:position + 1] = [left, right]
        self.assertEqual(left["key"]["prefixes"] + right["key"]["prefixes"], original["key"]["prefixes"])
        for entry in (left, right):
            plan.index_trace.validate_mutation_read_trace(OPERATION, entry["table"], entry["key"])
        fixture.payload["plannerTrace"]["entries"] = trace_oracle.renumber(entries)
        fixture.rehash()
        with patch.object(plan, "_trace", wraps=plan._trace) as reached:
            self.reject(fixture)
        self.assertEqual(reached.call_count, 1)

    def test_writer_marker_copy_budget_is_consumed_before_dynamic_batch_publication(self):
        fixture = PlanFixture()
        real = plan.write_trace._markers
        seen = []
        def markers(plans, work):
            for expected in real(plans, work):
                seen.append((work, units(work.metrics), copy.deepcopy(expected)))
                yield expected
        with patch.object(plan.write_trace, "_markers", side_effect=markers):
            actual = self.verify(fixture)
        expected = independent_write_trace(fixture.semantic)
        self.assertEqual([value for _, _, value in seen], [(item["table"], item["key"]) for item in expected])
        self.assertTrue(all(work is seen[0][0] for work, _, _ in seen))
        self.assertTrue(all(left[1][1] < right[1][1] and left[1][2] < right[1][2]
            for left, right in zip(seen, seen[1:])))
        self.assertEqual((actual.metrics.total_hashes, actual.metrics.total_input_bytes,
            actual.metrics.total_json_nodes), independent_metrics(fixture)["total"])

    def test_private_builder_matches_independent_payload_signature_and_genuine_replay(self):
        for options in ({}, {"separate_signer": True, "include_audit": False}):
            fixture = PlanFixture(**options)
            expected = independent_production_work(fixture)
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(options=options), patch.object(production, "_sign_and_verify",
                    wraps=production._sign_and_verify) as signing:
                actual = production._build_and_sign(**production_arguments(fixture, work))
            self.assertEqual(actual.payload, fixture.payload)
            self.assertEqual(actual.envelope, fixture.envelope)
            self.assertEqual((actual.payload_bytes, actual.envelope_bytes), (wire(fixture.payload), wire(fixture.envelope)))
            self.assertEqual((signing.call_count, actual.signing_attempts, actual.signature_verifications), (1, 1, 1))
            self.assertEqual(units(actual.metrics), expected)
            self.assertEqual(units(work.metrics), expected)
            replay = self.verify(fixture, envelope=actual.envelope)
            self.assertEqual(replay.semantics.mutations, fixture.semantic.final_mutations)
            self.assertEqual(replay.semantics.kernel.result, fixture.semantic.kernel_expected["result"])

    def test_private_builder_exact_units_and_preconsumed_original_work_never_allocate_a_meter(self):
        fixture = PlanFixture()
        expected, spent = independent_production_work(fixture), (11, 17, 5)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*add(expected, spent)))
        work.charge(hashes=spent[0], input_bytes=spent[1], json_nodes=spent[2])
        with patch.object(accounting._ValidationWork, "__init__", side_effect=AssertionError("fresh work")):
            actual = production._build_and_sign(**production_arguments(fixture, work))
        self.assertEqual(units(actual.metrics), expected)
        self.assertEqual(units(work.metrics), add(expected, spent))
        self.assertEqual(actual.envelope_bytes, wire(fixture.envelope))

    def test_private_builder_minus_one_denies_before_final_buffers_or_signing(self):
        fixture = PlanFixture()
        expected = independent_production_work(fixture)
        original = production.core.canonical_bytes
        for dimension in range(3):
            limits = list(expected)
            limits[dimension] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
            encoded = []
            def encode(value):
                if type(value) is dict and value.get("schema") in (PAYLOAD_SCHEMA, SIGNED_SCHEMA):
                    encoded.append(value["schema"])
                return original(value)
            with self.subTest(dimension=dimension), \
                    patch.object(production.core, "canonical_bytes", side_effect=encode), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as signing:
                with self.assertRaises(ValueError):
                    production._build_and_sign(**production_arguments(fixture, work))
            self.assertEqual((encoded, signing.call_count), ([], 0))
            self.assertGreater(work.input_bytes, 0)

    def test_private_builder_context_is_closed_exact_fresh_and_checked_before_hashes(self):
        fixture = PlanFixture()
        for change in ("missing", "extra", "boolean", "stale", "skew", "identity", "roots"):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            arguments = production_arguments(fixture, work)
            context = arguments["context"]
            if change == "missing":
                context.pop("expectedFence")
            elif change == "extra":
                context["trustedByCaller"] = True
            elif change == "boolean":
                context["expectedFence"] = True
            elif change == "stale":
                context["nowEpochNs"] = context["deadlineEpochNs"]
            elif change == "skew":
                context["nowMonotonicNs"] += context["maximumClockSkewNs"] + 1
            elif change == "identity":
                context["expectedPlannerIdentity"]["measurementDigest"] = "sha256:" + "F" * 64
            else:
                context["expectedBefore"]["indexBeforeHeads"][0]["leafCount"] = True
            with self.subTest(change=change), patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as signing:
                with self.assertRaises(ValueError):
                    production._build_and_sign(**arguments)
            self.assertEqual((hashes.call_count, signing.call_count), (0, 0))
            self.assertEqual(units(work.metrics), (0, 0, 0))

    def test_private_builder_divergent_raw_views_and_wrong_reserved_transaction_cannot_sign(self):
        for change in ("selected", "mutations", "proofs", "before", "request", "transaction"):
            fixture = PlanFixture()
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            arguments = production_arguments(fixture, work)
            if change == "selected":
                arguments["selected_rows"] = arguments["selected_rows"][:-1]
            elif change == "mutations":
                arguments["mutations"] = arguments["mutations"][:-1]
            elif change == "proofs":
                arguments["before_proofs"] = arguments["before_proofs"][:-1]
            elif change == "before":
                arguments["context"]["expectedBefore"]["indexBeforeHeads"][0]["rootDigest"] = sha(b"another root")
            elif change == "request":
                arguments["request"]["requestDigest"] = sha(b"another request")
            else:
                arguments["context"]["expectedPlannerTransactionId"] = sha(b"another reservation")
            with self.subTest(change=change), patch.object(production, "_sign_and_verify",
                    wraps=production._sign_and_verify) as signing:
                with self.assertRaises(ValueError):
                    production._build_and_sign(**arguments)
            self.assertEqual(signing.call_count, 0)

    def test_private_builder_uses_actual_pinned_public_verification_and_never_returns_placeholder(self):
        fixture = PlanFixture()
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        arguments = production_arguments(fixture, work)
        arguments["planner_public_key"] = fixture.other_key.public_key()
        with patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as signing:
            with self.assertRaisesRegex(plan.RevocationPlanError, "pinned public key"):
                production._build_and_sign(**arguments)
        self.assertEqual(signing.call_count, 1)
        self.assertGreater(work.hash_work, 0)
        self.assertGreater(work.input_bytes, 0)
        good = production._build_and_sign(**production_arguments(fixture,
            accounting._ValidationWork(accounting.QueryReadValidationLimits())))
        self.assertNotEqual(good.envelope["signatureBase64Url"], "A" * 86)
        self.assertEqual(good.envelope["signatureBase64Url"], fixture.envelope["signatureBase64Url"])

    def test_private_builder_same_length_post_sign_payload_drift_denies_before_envelope_output(self):
        fixture = PlanFixture()
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        arguments = production_arguments(fixture, work)
        real_sign, real_encode = production._sign_and_verify, production.core.canonical_bytes
        encoded = []
        def sign(*args):
            signature = real_sign(*args)
            reason = arguments["request"]["arguments"]["reason"]
            arguments["request"]["arguments"]["reason"] = "!" * len(reason)
            return signature
        def encode(value):
            if type(value) is dict and value.get("schema") in (PAYLOAD_SCHEMA, SIGNED_SCHEMA):
                encoded.append(value["schema"])
            return real_encode(value)
        with patch.object(production, "_sign_and_verify", side_effect=sign), \
                patch.object(production.core, "canonical_bytes", side_effect=encode):
            with self.assertRaisesRegex(plan.RevocationPlanError, "payload changed during signing"):
                production._build_and_sign(**arguments)
        self.assertEqual(encoded, [PAYLOAD_SCHEMA, PAYLOAD_SCHEMA])

    def test_private_builder_key_callbacks_cannot_replace_widen_spend_refund_or_alias_meter_units(self):
        fixture = PlanFixture()
        expected = independent_production_work(fixture)
        real = production._sign_and_verify
        for change in ("replace", "widen", "spend", "refund", "float_counter", "float_limit"):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*add(expected, (3, 7, 5))))
            arguments = production_arguments(fixture, work)
            def sign(*args):
                signature = real(*args)
                if change == "replace":
                    work.limits = accounting.QueryReadValidationLimits(work.limits.max_hashes,
                        work.limits.max_input_bytes, work.limits.max_json_nodes)
                elif change == "widen":
                    object.__setattr__(work.limits, "max_input_bytes", work.limits.max_input_bytes + 1)
                elif change == "spend":
                    work.charge(input_bytes=1)
                elif change == "refund":
                    work.input_bytes -= 1
                elif change == "float_counter":
                    work.input_bytes = float(work.input_bytes)
                else:
                    object.__setattr__(work.limits, "max_json_nodes", float(work.limits.max_json_nodes))
                return signature
            with self.subTest(change=change), patch.object(production, "_sign_and_verify", side_effect=sign):
                with self.assertRaises(ValueError):
                    production._build_and_sign(**arguments)


if __name__ == "__main__":
    unittest.main()

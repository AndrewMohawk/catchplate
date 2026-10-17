#!/usr/bin/env python3
"""Inert exact-plan roster regression; no database or cryptographic authority.

The real persistence validator and existing evidence parsers run through their
closed-record admission. A sentinel stops at the following audit-capacity
boundary, before any database access. Quote/signature bytes are synthetic shape
fixtures, not verified evidence. SQL is rendered and inspected, not executed.
"""
from __future__ import annotations

import base64
import copy
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_contract as contract
from catchplate import authority_credential_currentness as currentness
from catchplate import authority_static_credential_assignment as assignment
from catchplate import authority_static_credential_custody as creation
from catchplate import authority_static_credential_rotation_custody as rotation
from catchplate.authority_store import executor_v9 as store
from catchplate.authority_store import root_transition_sql as sql


DIGEST = "sha256:" + "1" * 64
BASE_OPERATION = "webauthn.counter.cas"


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def native_evidence(codec):
    boot = encoded(bytes([1]) * 32)
    holder = currentness.holder_id(boot, DIGEST)
    assigned = {name: DIGEST for name in assignment.ASSIGNMENT_FIELDS}
    assigned.update(holderId=holder, bootId=boot,
        expectedPcrs={"PCR" + str(index): "sha384:" + "1" * 96 for index in range(3)},
        expectedEif="sha384:" + "1" * 96, expectedModuleId="synthetic-module",
        maxAgeSeconds=30, futureSkewSeconds=0, instanceId="spiffe://fixture/native",
        secretKekId="attested-memory-kek:" + "1" * 24,
        intakeOrigin="https://native.example", portalOrigin="https://portal.example")
    selected = {"schema": assignment.SIGNED_SCHEMA, "payload": {
        "schema": assignment.SCHEMA, "controlPlaneConfigurationDigest": DIGEST,
        "deploymentId": "fixture", "assignment": assigned,
        "issuedAtEpochNs": 1000, "expiresAtEpochNs": 2000},
        "signature": encoded(bytes([2]) * 64)}
    statement = {name: DIGEST for name in codec.STATEMENT_FIELDS}
    statement.update(apiVersion=codec.STATEMENT_SCHEMA, operation=codec.profile.OPERATION,
        holderId=holder, bootId=boot, actorId="oidc:fixture",
        credentialId="11111111-1111-4111-8111-111111111111",
        credentialVersion=1 if codec is creation else 2, deploymentId="fixture",
        instanceId=assigned["instanceId"], secretKekId=assigned["secretKekId"],
        intakeOrigin=assigned["intakeOrigin"], portalOrigin=assigned["portalOrigin"],
        challenge=encoded(bytes([3]) * 32), generationCreatedAtEpochNs=1000,
        issuedAtEpochNs=1000, expiresAtEpochNs=2000)
    if codec is rotation:
        statement["previousCredentialVersion"] = 1
    return {"statement": statement, "signature": "ed25519:" + encoded(bytes([4]) * 64),
        "nativeKeyEvidence": {"apiVersion": "catchplate.nativeResponseProofKeyEvidence/v1",
            "responseProofPublicKey": encoded(bytes([5]) * 32),
            "attestationDocumentB64": encoded(b"synthetic-not-a-quote")},
        "assignmentOriginal": assignment.canonical(selected).decode("ascii")}


def payload(operation):
    plan = {name: DIGEST for name in sql._PLAN_FIELDS}
    plan.update(schema="catchplate.policyAuthorityMeasuredPlan/v3", operation=operation,
        sourceRevision=contract.SOURCE_REVISION, authoritySchemaVersion=contract.SCHEMA_VERSION,
        operationContractDigest=contract.OPERATION_MANIFEST_DIGEST,
        operationManifestDigest=contract.OPERATION_MANIFEST_DIGEST,
        handlerContractDigest=contract.handler_contract_digest(operation), workUnits=1,
        deadlineMonotonicNs=2000, deadlineEpochNs=2000, fence=1)
    result = {name: None for name in sql._PAYLOAD_FIELDS}
    result.update(schema="catchplate.policyAuthorityPlannerResponse/v3", measuredPlan=plan,
        queryMultiproofsDigest=DIGEST, plannerTraceDigest=DIGEST, expectedResultDigest=DIGEST,
        plannerIdentity={name: DIGEST for name in (
            "sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")})
    if operation == creation.profile.OPERATION:
        result["staticCredentialCustodyEvidence"] = native_evidence(creation)
    elif operation == rotation.profile.OPERATION:
        result["staticCredentialRotationEvidence"] = native_evidence(rotation)
    return result


class ReachedFollowingBoundary(Exception):
    pass


def admitted(value):
    before = copy.deepcopy(value)
    try:
        with mock.patch.object(store.authority_audit_capacity, "validate_capacity_transition",
                side_effect=ReachedFollowingBoundary):
            store.complete_authority_planner_transaction(planner_transaction_id=DIGEST,
                authorization_projection_digest=DIGEST,
                exact_plan_bytes=store._canonical(value).encode("ascii"),
                planned_at_epoch_ns=1000, connection=None)
    except ReachedFollowingBoundary:
        result = True
    except ValueError:
        result = False
    else:
        raise AssertionError("fixture crossed the inert stop boundary")
    assert value == before
    return result


def main():
    legacy, create, rotate = [payload(operation) for operation in (
        BASE_OPERATION, creation.profile.OPERATION, rotation.profile.OPERATION)]
    controls = 0
    for value in (legacy, create, rotate):
        assert admitted(value)
        controls += 1
    for value, field, wrong_field in (
            (create, "staticCredentialCustodyEvidence", "staticCredentialRotationEvidence"),
            (rotate, "staticCredentialRotationEvidence", "staticCredentialCustodyEvidence")):
        absent = copy.deepcopy(value)
        absent.pop(field)
        assert not admitted(absent)
        swapped = copy.deepcopy(value)
        swapped[wrong_field] = swapped.pop(field)
        assert not admitted(swapped)
        controls += 2
    extra = copy.deepcopy(legacy)
    extra["staticCredentialCustodyEvidence"] = create["staticCredentialCustodyEvidence"]
    assert not admitted(extra)
    malformed = copy.deepcopy(rotate)
    malformed["staticCredentialRotationEvidence"]["statement"]["credentialVersion"] = 1
    assert not admitted(malformed)
    oversized = copy.deepcopy(create)
    oversized["staticCredentialCustodyEvidence"]["nativeKeyEvidence"]["attestationDocumentB64"] = encoded(bytes(12 * 1024 + 1))
    assert not admitted(oversized)
    controls += 3
    rendered = sql.load_root_transition_sql('"catchplate_metadata"')
    closed = sql._exact_payload_keys("rt_payload_json")
    assert " ".join(closed.split()) in " ".join(rendered.split())
    for operation, field in ((creation.profile.OPERATION, "staticCredentialCustodyEvidence"),
            (rotation.profile.OPERATION, "staticCredentialRotationEvidence")):
        assert "WHEN '" + operation + "' THEN" in closed
        assert sql._exact_keys("rt_payload_json", sql._PAYLOAD_FIELDS + (field,)) in closed
    assert "ELSE " + sql._exact_keys("rt_payload_json", sql._PAYLOAD_FIELDS) + " END" in closed
    assert "json_object_keys" in closed and "array_agg" in closed
    print(f"PASS {controls} real Python roster/parser controls; SQL closed branches rendered only")


if __name__ == "__main__":
    main()

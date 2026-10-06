#!/usr/bin/env python3
"""Inert public-provenance acquisition controls, not SQL/native authorization.

Reuses synthetic in-memory material/signatures from the rotation component
fixture. Real lookup, codecs, commitments and historical signature/outbox
verification run; authenticated HTTP ownership and SELECT results are explicit
boundary doubles. Its unused runtime-custody import is isolated as well. No
real connection, Nitro quote or hardware assertion runs.
"""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]

import test_authority_static_rotation as fixture
from serverware import authority_request_commitment as commitment
from serverware import control_plane_static_credential_provenance as lookup
from serverware import control_plane_static_credential_rotation as http
from serverware import db

# Currentness._rows is the genuine SELECT/serializer implementation. Its
# unrelated live custody transport cannot be initialized in this inert test.
with mock.patch.dict(sys.modules, {"serverware.control_plane_custody_client": SimpleNamespace()}):
    from serverware import control_plane_credential_currentness

C, H, B = fixture.C, fixture.H, fixture.B


def retained(f, version):
    codec = fixture.creation if version == 1 else fixture.rotation
    custody = fixture.old_custody if version == 1 else fixture.custody
    if version == 1:
        values = {"actor_id": f["actor"], "control_plane_configuration_digest": f["cfg"],
            "credential_policy": f["policy"], "approval_id": None, "request": {
                **f["initial"], "nativeGenerationOriginal": f["native1"],
                "executionIssuedAtEpochNs": f["now"] - 50_000_000_000,
                "executionExpiresAtEpochNs": f["now"] - 40_000_000_000}}
        evidence = f["proof"](custody, {**f["old"]["statement"], "inputSha256": H(C(values))})
        evidence["assignmentOriginal"] = f["native_proof"]["assignmentOriginal"]
    else:
        values, evidence = copy.deepcopy(f["values"]), copy.deepcopy(f["native_proof"])
    digest = codec.request_digest(codec.OPERATION, values)
    operation_id = commitment.operation_id(codec.OPERATION, digest)
    capability = H(b"synthetic capability")
    transaction = commitment.framed_digest("serverware.policyAuthorityPlannerTransaction/v1",
        operation_id.encode(), digest.encode(), capability.encode())
    typed = {"schema": "serverware.policyAuthorityV9Request/v1", "operation": codec.OPERATION,
        "operationId": operation_id, "requestDigest": digest,
        "handler": fixture.contract.operation_spec(codec.OPERATION)["handler"],
        "operationManifestDigest": fixture.contract.OPERATION_MANIFEST_DIGEST,
        "arguments": {**values, "businessIntent": fixture.contract.synthesize_business_intent(codec.OPERATION, values)}}
    measured = {name: H(name.encode()) for name in lookup._PLAN_FIELDS}
    measured.update(schema="serverware.policyAuthorityMeasuredPlan/v3", operation=codec.OPERATION,
        operationId=operation_id, requestDigest=digest, capabilityId=capability, plannerTransactionId=transaction,
        sourceRevision=fixture.contract.SOURCE_REVISION, authoritySchemaVersion=fixture.contract.SCHEMA_VERSION,
        operationContractDigest=fixture.contract.OPERATION_MANIFEST_DIGEST,
        operationManifestDigest=fixture.contract.OPERATION_MANIFEST_DIGEST,
        handlerContractDigest=fixture.contract.handler_contract_digest(codec.OPERATION))
    field = "staticCredentialCustodyEvidence" if version == 1 else "staticCredentialRotationEvidence"
    payload = {name: None for name in lookup._PAYLOAD_FIELDS}
    payload.update(schema="serverware.policyAuthorityPlannerResponse/v3", measuredPlan=measured,
        typedRequest=typed, **{field: evidence})
    raw = C(payload)
    row = dict(planner_transaction_id=transaction, operation=codec.OPERATION, operation_id=operation_id,
        request_digest=digest, capability_id=capability, plan_protocol="v3", retained_record_digest=None,
        status="consumed", source_revision=fixture.contract.SOURCE_REVISION,
        exact_plan_base64url=B(raw), exact_plan_bytes_digest=H(raw), exact_plan_byte_count=len(raw))
    original = lookup._acquire(row, credential_id=f["item"], version=version,
        origin_digest=digest, configuration_digest=f["cfg"])
    stamp = f["credential"]["created_at"] if version == 1 else fixture.STAMP(f["now"])
    native = codec.generation(values["request"]["nativeGenerationOriginal"])
    credential = {**f["credential"], **native["envelope"], "updated_at": stamp}
    head = {"credential_id": f["item"], "last_version": version, "updated_at": stamp}
    predecessor = None if version == 1 else values["request"]["predecessorBarrierSha256"]
    root = fixture.current.new_root(f["item"], version, digest, stamp, predecessor=predecessor)
    event = {"schema": "serverware.staticCredentialCreationAudit/v1" if version == 1 else fixture.provenance.ROTATION_AUDIT_SCHEMA,
        "operation": codec.OPERATION, "requestDigest": digest, "credentialId": f["item"], "credentialVersion": version,
        "candidateSha256": codec.approval_payload_digest(values), "intentSha256": native["intentSha256"],
        "nativeGenerationSha256": H(values["request"]["nativeGenerationOriginal"].encode()),
        "custodyStatementSha256": H(C(evidence["statement"])), "approvalId": None}
    if version > 1:
        event.update({name: evidence["statement"][name] for name in fixture.custody.STATEMENT_FIELDS
            - fixture.old_custody.STATEMENT_FIELDS})
        event["credentialPostSha256"] = H(fixture.rows.credential_original(credential))
    outbox = {**f["outbox"], "id": fixture.provenance.generation_outbox_id(original),
        "event_type": codec.OPERATION, "event_json": C(event).decode(),
        "event_digest": fixture.core.framed_digest("serverware.metadataAuditOutboxEvent/v1", C(event)),
        "created_at": stamp, "audited_at": fixture.STAMP(f["now"] + 1_000_000_000)}
    return dict(row=row, payload=payload, original=original, credential=credential, head=head,
        root=root, outbox=outbox, version=version, duplicate=False, change=False)


class Selection:
    def __init__(self, rows): self.rows = rows
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return self.rows


class Connection:
    def __init__(self, state): self.state, self.root_reads = state, 0
    def __enter__(self): return self
    def __exit__(self, *unused): return False
    def execute(self, sql, parameters):
        assert sql.startswith("SELECT ")
        state = self.state
        if sql.startswith("SELECT credential_version"):
            return Selection([{"credential_version": state["version"]}])
        if "FROM policy_authority_planner_transactions " in sql:
            assert sql.endswith("status = 'consumed' LIMIT 2")
            return Selection([state["row"]] * (2 if state["duplicate"] else 1))
        for table, name in (("credentials", "credential"), ("credential_generations", "head"),
                ("credential_currentness_roots", "root"), ("metadata_audit_outbox", "outbox")):
            if sql.startswith("SELECT * FROM " + table + " WHERE "):
                row = copy.deepcopy(state[name])
                if name == "root":
                    self.root_reads += 1
                    if state["change"] and self.root_reads > 1:
                        row["updated_at"] = "2027-01-15T08:00:01+00:00"
                return Selection([row])
        raise AssertionError("unexpected SELECT shape")


def observe(f, state):
    owner = object.__new__(http._Owner)
    owner.dispatched = owner.drain_started = False
    owner.last_epoch = f["now"] + 100_000_000_000  # Both native grants are historical.
    owner.cold = SimpleNamespace(binding=SimpleNamespace(configuration_digest=f["cfg"]),
        payload={http.proof.FIELD: {"deploymentId": "fixture"}})
    owner.policy = {"nativeSecretKekId": f["kek_id"]}
    with mock.patch.object(http._Owner, "check", return_value=None), mock.patch.object(db, "connect", return_value=Connection(state)):
        return lookup.lookup(owner, f["item"])


def main():
    f = fixture.fixture()
    creation, rotation = retained(f, 1), retained(f, 2)
    for state in (creation, rotation):
        result = observe(f, state)
        assert set(result) == {"apiVersion", "okForAction", "credentialId", "credentialVersion",
            "originRequestDigest", "provenanceOriginal", "provenanceSha256"}
        assert result["provenanceOriginal"] == state["original"] and result["okForAction"] is False
        public = fixture.provenance.generation_evidence(result["provenanceOriginal"])
        assert set(public) == {"statement", "signature", "nativeKeyEvidence"}
        assert "assignmentOriginal" not in result["provenanceOriginal"] and "secret_ciphertext" not in result["provenanceOriginal"]
    negatives = []
    for field, value in (("exact_plan_byte_count", rotation["row"]["exact_plan_byte_count"] + 1),
            ("exact_plan_bytes_digest", H(b"wrong")), ("status", "planned")):
        state = copy.deepcopy(rotation); state["row"][field] = value; negatives.append(state)
    for field in ("duplicate", "change"):
        state = copy.deepcopy(rotation); state[field] = True; negatives.append(state)
    state = copy.deepcopy(rotation); state["outbox"]["status"] = "pending"; negatives.append(state)
    state = copy.deepcopy(rotation)
    state["payload"]["staticCredentialRotationEvidence"]["signature"] = "ed25519:" + B(bytes([7]) * 64)
    raw = C(state["payload"])
    state["row"].update(exact_plan_base64url=B(raw), exact_plan_bytes_digest=H(raw), exact_plan_byte_count=len(raw))
    negatives.append(state)
    from cryptography.exceptions import InvalidSignature
    for ordinal, state in enumerate(negatives):
        try: observe(f, state)
        except (ValueError, InvalidSignature): pass
        else: raise AssertionError(f"changed acquisition {ordinal} was accepted")
    print("PASS 9 provenance lookup controls; HTTP/SELECT doubles, actual historical signature/outbox codecs; no live authority")


if __name__ == "__main__":
    main()

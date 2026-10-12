#!/usr/bin/env python3
"""One bounded synthetic rotation check; not SQL, Nitro or hardware admission.

Real material/signature parsers and the pure kernel run unchanged. Selected
rows and the prior-verified WebAuthn projection are explicit fixture data, not
authenticated database roots or actual physical approval.
"""
import ast
import base64
import copy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from serverware import authority_contract as contract
from serverware import authority_challenge_retention as retention
from serverware import authority_credential_currentness as current
from serverware import authority_static_credential_create as creation
from serverware import authority_static_credential_custody as old_custody
from serverware import authority_static_credential_rotate as rotation
from serverware import authority_static_credential_rotation_custody as custody
from serverware import authority_static_credential_rotation_approval as approval
from serverware import authority_static_credential_provenance as provenance
from serverware import authority_static_credential_assignment as assignment
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_static_credential_rotate as kernel
from serverware import authority_webauthn_bindings as bindings
from serverware import credential_currentness_rows as rows
import authority_revocation_trust_fixture as trust

C, H = creation.canonical, creation.sha256
B = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
STAMP = lambda ns: datetime.fromtimestamp(ns // 1_000_000_000, timezone.utc).isoformat()


def selected(table, key, row):
    return {"table": table, "key": key, "keyDigest": core.framed_digest(
        "serverware.policyAuthorityBusinessKey/v1", table.encode(), C(key)),
        "present": row is not None, "row": row, "contractSelector": None}


def fixture():
    now = 1_800_000_000_000_000_000
    actor, item = "oidc:rotation-fixture", "12345678-1234-4234-8234-123456789abc"
    cfg, kek_id, kek = H(b"configuration"), "attested-memory-kek:" + "a" * 24, AESGCM(bytes(range(32)))
    policy = {"rpId": "unit.example", "origins": ["https://unit.example"], "allowedAuthenticatorClasses": ["hardware"],
        "hardwareRequired": True, "requireUserPresence": True, "requireUserVerification": True, "maxAssertionAgeSeconds": 30}
    key = Ed25519PrivateKey.generate()
    public = key.public_key()
    key_id = H(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    boot = B(b"b" * 32)
    base = {name: H(name.encode()) for name in old_custody.STATEMENT_FIELDS}
    base.update(holderId=current.holder_id(boot, key_id), bootId=boot, keyId=key_id, actorId=actor,
        credentialId=item, credentialVersion=1, controlPlaneConfigurationDigest=cfg, deploymentId="fixture",
        instanceId="spiffe://fixture/native", secretKekId=kek_id, challenge=B(b"c" * 32),
        intakeOrigin="https://intake.example", portalOrigin="https://unit.example")

    def proof(module, statement):
        statement = {**statement, "apiVersion": module.STATEMENT_SCHEMA, "operation": module.profile.OPERATION}
        return {"statement": statement, "signature": "ed25519:" + B(key.sign(module.SIGNATURE_DOMAIN + C(statement))),
            "nativeKeyEvidence": {"apiVersion": "serverware.nativeResponseProofKeyEvidence/v1",
                "responseProofPublicKey": B(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
                "attestationDocumentB64": B(b"explicit synthetic acquisition, not a Nitro quote")}}

    initial = {"credentialId": item, "credentialVersion": 1, "name": "fixture", "kind": "bearer", "metadata": {},
        "issuedAtEpochNs": now - 100_000_000_000, "expiresAtEpochNs": now - 20_000_000_000}
    native1 = creation.material.seal_generation_original(actor_id=actor, configuration_digest=cfg,
        credential_policy=policy, intent=initial, raw=b"synthetic predecessor", secret_kek_id=kek_id, kek=kek,
        epoch_ns=now - 50_000_000_000)
    generation1 = creation.generation(native1)
    old = proof(old_custody, {**base, "intentSha256": generation1["intentSha256"], "generationSha256": H(native1.encode()),
        "generationCreatedAtEpochNs": now - 50_000_000_000, "issuedAtEpochNs": now - 50_000_000_000,
        "expiresAtEpochNs": now - 40_000_000_000})
    origin = H(b"creation request")
    historical = C({"apiVersion": provenance.SCHEMA, "creationRequestDigest": origin,
        "nativeEvidenceOriginal": C(old).decode()}).decode()
    credential = {"id": item, "name": "fixture", "kind": "bearer", **generation1["envelope"], "metadata": "{}",
        "lifecycle_status": "active", "revocation_error": None, "revocation_requested_at": None,
        "created_at": STAMP(now - 50_000_000_000), "updated_at": STAMP(now - 50_000_000_000)}
    head = {"credential_id": item, "last_version": 1, "updated_at": credential["updated_at"]}
    root = current.new_root(item, 1, origin, credential["created_at"])
    audit = {"schema": "serverware.staticCredentialCreationAudit/v1", "operation": creation.OPERATION, "requestDigest": origin,
        "credentialId": item, "credentialVersion": 1, "candidateSha256": H(b"creation candidate"),
        "intentSha256": generation1["intentSha256"], "nativeGenerationSha256": H(native1.encode()),
        "custodyStatementSha256": H(C(old["statement"])), "approvalId": None}
    outbox = {"id": provenance.outbox_id(historical), "event_type": creation.OPERATION, "actor_type": "admin",
        "actor_id": actor, "event_json": C(audit).decode(), "event_digest": core.framed_digest("serverware.metadataAuditOutboxEvent/v1", C(audit)),
        "storage_format_version": 1, "status": "audited", "claim_id": None, "claimed_at": None, "attempts": 1,
        "audited_at": STAMP(now - 40_000_000_000), "audit_event_hash": H(b"completed audit"), "last_error": None,
        "created_at": credential["created_at"]}
    barrier_id = "12345678-1234-4234-8234-123456789abd"
    barrier_original = {"apiVersion": current.BARRIER_SCHEMA, "barrierId": barrier_id, "credentialId": item,
        "credentialVersion": 1, "epoch": 1, "holders": [], "issuedAtEpochNs": now - 2_000_000_000,
        "expiresAtEpochNs": now + 20_000_000_000}
    barrier = {"id": barrier_id, "root_id": root["id"], "credential_id": item, "credential_version": 1, "epoch": 1,
        "original_json": C(barrier_original).decode(), "original_sha256": current.barrier_digest(barrier_original),
        "status": "admitted", "quiesce_request_digest": H(b"quiesce"), "admit_request_digest": H(b"admit"),
        "consume_request_digest": None, "created_at": STAMP(now - 2_000_000_000), "updated_at": STAMP(now - 1_000_000_000)}
    root.update(status="admitted", barrier_id=barrier_id, updated_at=STAMP(now - 1_000_000_000))
    intent = {"credentialId": item, "previousCredentialVersion": 1, "credentialVersion": 2,
        "previousCredentialSha256": H(rows.credential_original(credential)), "previousCurrentnessOriginRequestDigest": origin,
        "previousProvenanceOriginal": historical, "name": "fixture", "kind": "bearer", "metadata": {},
        "issuedAtEpochNs": now - 10_000_000_000, "expiresAtEpochNs": now + 300_000_000_000}
    native2 = rotation.material.seal_generation_original(actor_id=actor, configuration_digest=cfg,
        credential_policy=policy, intent=intent, raw=b"synthetic successor", secret_kek_id=kek_id, kek=kek,
        epoch_ns=now - 5_000_000_000)
    values = {"actor_id": actor, "control_plane_configuration_digest": cfg, "credential_policy": policy, "approval_id": None,
        "request": {**intent, "nativeGenerationOriginal": native2, "executionIssuedAtEpochNs": now - 1_000_000_000,
            "executionExpiresAtEpochNs": now + 10_000_000_000, "predecessorBarrierSha256": barrier["original_sha256"],
            "predecessorCurrentnessRootSha256": current.root_digest(root)}}
    native = rotation.generation(native2)
    statement = {**base, "credentialVersion": 2, "intentSha256": native["intentSha256"], "generationSha256": H(native2.encode()),
        "inputSha256": H(C(values)), "generationCreatedAtEpochNs": now - 5_000_000_000,
        "issuedAtEpochNs": now - 1_000_000_000, "expiresAtEpochNs": now + 10_000_000_000,
        **{name: values["request"][name] for name in custody.STATEMENT_FIELDS - old_custody.STATEMENT_FIELDS - {"previousProvenanceSha256"}},
        "previousProvenanceSha256": H(historical.encode())}
    native_proof = proof(custody, statement)
    assignment_row = {name: H(name.encode()) for name in assignment.ASSIGNMENT_FIELDS}
    assignment_row.update({name: base[name] for name in ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
        "policyHash", "instanceId", "secretKekId", "intakeOrigin", "portalOrigin")})
    assignment_row.update(expectedBinaryDigest=base["dataPlaneBinarySha256"], expectedPcrs={"PCR" + str(i): "sha384:" + "a" * 96 for i in range(3)},
        expectedEif="sha384:" + "a" * 96, expectedModuleId="fixture-module", maxAgeSeconds=60, futureSkewSeconds=0)
    assigned = {"schema": assignment.SCHEMA, "controlPlaneConfigurationDigest": cfg, "deploymentId": "fixture", "assignment": assignment_row,
        "issuedAtEpochNs": now - 100_000_000_000, "expiresAtEpochNs": now + 300_000_000_000}
    from serverware import authority_request_commitment as commitment
    signer = Ed25519PrivateKey.generate()
    native_proof["assignmentOriginal"] = C({"schema": assignment.SIGNED_SCHEMA, "payload": assigned,
        "signature": B(signer.sign(commitment.framed_digest(assignment.SIGNED_SCHEMA, C(assigned)).encode()))}).decode()
    return locals()


class RotationControls(unittest.TestCase):
    def setUp(self):
        self.f = fixture()

    def context(self):
        f = self.f; now = f["now"]; values = f["values"]; actor = f["actor"]
        request_digest = rotation.request_digest(rotation.OPERATION, values)
        operation_id = core.framed_digest("serverware.policyAuthorityOperation/v2", rotation.OPERATION.encode(), request_digest.encode())
        credential = {"id": "hardware", "credential_id": "public-hardware", "user_id": actor, "sign_count": 2,
            "revoked_at": None, "last_used_at": None, "updated_at": STAMP(now - 20_000_000_000), "attestation_trusted": 1,
            **trust.credential_fields(), "authenticator_class": "hardware", "attestation_leaf_sha256": H(b"leaf"), "attestation_root_sha256": H(b"root")}
        challenge = {"id": "assertion", "challenge": B(b"challenge" * 4), "challenge_type": "policy_authority", "user_id": actor,
            "scope_key": operation_id, "approval_request_id": None, "payload_json": C({"operationId": operation_id,
                "credentialId": credential["credential_id"], "rpId": "unit.example", "origin": "https://unit.example"}).decode(),
            "expires_at": STAMP(now + 10_000_000_000), "used_at": None, "created_at": STAMP(now - 1_000_000_000)}
        challenge.update({field: 0 if field == "retention_reference_mask" else None for field in retention.DERIVED_FIELDS})
        # The genuine reader commits its original ten columns; the selected
        # row below retains all seventeen columns for full-row custody/CAS.
        public = {**json.loads(challenge["payload_json"]), "challengeId": challenge["id"], "challenge": challenge["challenge"],
            "challengeRowDigest": bindings.challenge_row_digest(challenge)}
        high = trust.trust_rows()["webauthn_trust_publication_high_water"][0]
        evidence = {"operation": rotation.OPERATION, "operationId": operation_id, "requestDigest": request_digest,
            "credentialRecordId": credential["id"], "credentialId": credential["credential_id"], "challengeId": challenge["id"],
            "challengeDigest": H(C(public)), "clientChallengeDigest": H(b"challenge" * 4), "rpId": "unit.example", "origin": "https://unit.example",
            "priorCounter": 2, "counter": 3, "verifiedAtEpochNs": now - 1_000_000_000, "expiresAtEpochNs": now + 10_000_000_000,
            "trustHighWaterDigest": trust.framed("serverware.webauthnTrustHighWater/v1", C(trust.trust_high_water_document(high))),
            "metadataPublicationSequence": 1, "credentialPolicyDigest": trust.framed("serverware.policyAuthorityCredentialPolicy/v1", C(trust.credential_policy_document(credential, high))),
            "verifiedAssertionReceiptDigest": H(b"fixture projection, not signed hardware receipt")}
        selection = list(trust.selected_rows())
        for table, field, row in (("credentials", "id", f["credential"]), ("credential_generations", "credential_id", f["head"]),
                (current.ROOT_TABLE, "id", f["root"]), (current.BARRIER_TABLE, "id", f["barrier"]),
                ("metadata_audit_outbox", "id", f["outbox"]), ("webauthn_credentials", "id", credential),
                ("webauthn_challenges", "id", challenge), ("rbac_role_bindings", "subject_id", {"subject_id": actor, "status": "active", "roles_json": '["admin"]'})):
            selection.append(selected(table, {field: row[field]}, row))
        selection += [selected(current.ROOT_TABLE, {"id": current.root_id(f["item"], 2)}, None),
            selected("metadata_audit_outbox", {"id": shared._audit_identity(rotation.OPERATION, request_digest)}, None)]
        selected_policy = {"schema": rotation.SCHEMA, "credentialPolicy": f["policy"], "operationMaxSeconds": 30,
            "maximumArgumentBytes": rotation.MAX_ARGUMENT_BYTES, "maximumSecretBytes": rotation.MAX_SECRET_BYTES,
            "twoPersonRequired": False, "nativeSecretKekId": f["kek_id"], "intentMaxSeconds": 3600, "nativeCustodyPurpose": custody.STATEMENT_SCHEMA}
        return core.KernelContext(rotation.OPERATION, {**values, "businessIntent": contract.synthesize_business_intent(rotation.OPERATION, values)},
            tuple(selection), datetime.fromtimestamp(now // 1_000_000_000, timezone.utc), request_digest,
            verified_webauthn_evidence=evidence, static_credential_rotation_policy=selected_policy,
            static_credential_configuration_digest=f["cfg"], verified_static_credential_rotation_evidence=f["native_proof"])

    def test_atomic_successor_and_latest_provenance(self):
        ctx = self.context(); result = kernel.StaticCredentialRotateKernel().transition(ctx)
        effects = {(m["table"], tuple(m["key"].values())[0]): m for m in result.mutations}
        f = self.f; credential = effects[("credentials", f["item"])]["row"]
        self.assertEqual(credential["credential_version"], 2)
        self.assertEqual(credential["created_at"], f["credential"]["created_at"])
        self.assertEqual(effects[("credentials", f["item"])]["expectedRow"], f["credential"])
        self.assertEqual(effects[(current.ROOT_TABLE, f["root"]["id"])]["row"]["status"], "consumed")
        self.assertEqual(effects[(current.BARRIER_TABLE, f["barrier"]["id"])]["row"]["consume_request_digest"], ctx.request_digest)
        outbox = effects[("metadata_audit_outbox", shared._audit_identity(rotation.OPERATION, ctx.request_digest))]["row"]
        outbox.update(status="audited", audited_at=STAMP(f["now"]), audit_event_hash=H(b"rotation audited"))
        original = C({"apiVersion": provenance.ROTATION_SCHEMA, "rotationRequestDigest": ctx.request_digest,
            "nativeEvidenceOriginal": C({k: v for k, v in f["native_proof"].items() if k != "assignmentOriginal"}).decode()}).decode()
        self.assertEqual(provenance.verify_generation_rows(original, credential=credential,
            generation=effects[("credential_generations", f["item"])]["row"], root=effects[(current.ROOT_TABLE, current.root_id(f["item"], 2))]["row"],
            outbox=outbox, configuration_digest=f["cfg"], now_epoch_ns=f["now"] + 60_000_000_000), "fixture")
        with self.assertRaises(ValueError): provenance.original(original)

    def test_predecessor_and_barrier_refusals(self):
        original = self.context()
        for table, field, value in (("credentials", "credential_version", 2), ("credential_generations", "last_version", 2),
                ("credentials", "name", "substituted"), ("metadata_audit_outbox", "status", "pending"),
                (current.ROOT_TABLE, "status", "open"), (current.BARRIER_TABLE, "status", "consumed"),
                (current.BARRIER_TABLE, "consume_request_digest", H(b"already consumed"))):
            with self.subTest(table=table, field=field):
                changed = copy.deepcopy(original.selected_rows)
                next(row["row"] for row in changed if row["table"] == table and row["present"])[field] = value
                with self.assertRaises(ValueError): kernel.StaticCredentialRotateKernel().transition(replace(original, selected_rows=changed))
        with self.assertRaises(ValueError): kernel.StaticCredentialRotateKernel().transition(replace(original, verified_static_credential_rotation_evidence=None))

    def test_candidate_null_and_purpose_separation(self):
        f = self.f; candidate = copy.deepcopy(f["values"])
        candidate["request"].update(predecessorBarrierSha256=None, predecessorCurrentnessRootSha256=None)
        approval.candidate(C(candidate).decode())
        self.assertEqual(rotation.approval_payload_digest(candidate, candidate=True), rotation.approval_payload_digest(f["values"]))
        self.assertEqual(approval.approval_request(candidate, candidate=True), approval.approval_request(f["values"]))
        with self.assertRaises(ValueError): rotation.arguments(rotation.OPERATION, candidate)
        with self.assertRaises(ValueError): creation.generation(f["native2"])
        with self.assertRaises(ValueError): old_custody.evidence({k: v for k, v in f["native_proof"].items() if k != "assignmentOriginal"})
        with self.assertRaises(ValueError): custody.evidence(f["old"])

    def test_execution_cannot_outlive_actual_barrier(self):
        f = self.f
        original = {**f["barrier_original"], "expiresAtEpochNs": f["now"] + 5_000_000_000}
        digest = current.barrier_digest(original)
        f["barrier"].update(original_json=C(original).decode(), original_sha256=digest)
        f["values"]["request"]["predecessorBarrierSha256"] = digest
        statement = {**f["native_proof"]["statement"], "predecessorBarrierSha256": digest, "inputSha256": H(C(f["values"]))}
        f["native_proof"] = {**f["proof"](custody, statement), "assignmentOriginal": f["native_proof"]["assignmentOriginal"]}
        with self.assertRaisesRegex(ValueError, "barrier's original interval"):
            kernel.StaticCredentialRotateKernel().transition(self.context())


if __name__ == "__main__":
    unittest.main()

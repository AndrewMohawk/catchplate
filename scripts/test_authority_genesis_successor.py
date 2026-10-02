#!/usr/bin/env python3
"""Signed synthetic originals and pure transaction-row controls, not live owners.

No SQL connection, WebAuthn assertion, authenticated-root acquisition or committed
authority is fabricated. Explicit row fixtures exercise the actual source kernel;
they are not claimed as a successful planner acquisition or database ceremony.
Only root's later focused invocation may execute these authored controls.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    import base64
    from datetime import datetime, timezone
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import db, authority_contract as contract, authority_transition_core as core
    from serverware import authority_transition_policy_genesis as g
    from serverware import authority_primary_contract as primary, authority_radix_proof as radix
    from serverware import authority_policy_candidate_evidence as signatures

    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    ns = int(now.timestamp()) * 10**9
    sha = db._candidate_authority_sha256
    encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
    keypairs = {}
    for kind, seed in (("authority_genesis", b"g"), ("audit_inclusion_receipt", b"a")):
        key = Ed25519PrivateKey.from_private_bytes(seed * 32)
        public = key.public_key()
        digest = sha(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        row = dict(evidence_kind=kind, signing_key_id=digest, key_revision=1,
            signature_domain=db._POLICY_AUTHORITY_EVIDENCE_DOMAINS[kind],
            public_key_base64url=encode(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            public_key_digest=digest, trust_receipt_digest=sha(b"synthetic-trust-row"), trust_receipt_json='{"synthetic":true}',
            trust_receipt_payload_digest=sha(b"synthetic-trust-payload"), trust_receipt_signature_digest=sha(b"synthetic-trust-signature"),
            not_before_epoch_ns=ns-10**10, not_after_epoch_ns=ns+10**10,
            max_clock_skew_ns=0, max_evidence_age_ns=10**10, installed_by="synthetic-row-fixture", installed_at_epoch_ns=ns-10**10)
        head = dict(evidence_kind=kind, head_key_revision=1, head_signing_key_id=digest,
            head_public_key_digest=digest, updated_at_epoch_ns=ns-10**10)
        keypairs[kind] = key, row, head

    def sign(operation, value):
        kind = "authority_genesis" if operation == g.PREPARE else "audit_inclusion_receipt"
        prefix = "genesis" if operation == g.PREPARE else "inclusion_receipt"
        key, trusted, _ = keypairs[kind]
        domain = trusted["signature_domain"]
        row = dict(value)
        payload = dict(issuedAtEpochNs=ns-10**9, expiresAtEpochNs=ns+10**9,
            record=db._candidate_authority_signed_record(row, current_prefix=prefix))
        payload_json = db.dumps(payload)
        signature = key.sign(b"\0".join((db._POLICY_AUTHORITY_SIGNATURE_FRAME, domain.encode("ascii"),
            db._POLICY_AUTHORITY_CANONICAL_PROFILE.encode("ascii"), payload_json.encode("ascii"))))
        envelope = dict(apiVersion=domain, kind="PolicyAuthorityGenesis" if operation == g.PREPARE else "PolicyAuthorityAuditInclusion",
            canonicalProfile=db._POLICY_AUTHORITY_CANONICAL_PROFILE, signatureDomain=domain, payload=payload,
            payloadSha256=sha(payload_json.encode("ascii")), signatureAlgorithm="Ed25519",
            signingKeyId=trusted["signing_key_id"], signingKeySpkiSha256=trusted["signing_key_id"], signature=encode(signature))
        raw = db.dumps(envelope)
        row.update({prefix+"_envelope_json":raw, prefix+"_envelope_digest":sha(raw.encode("ascii")),
            prefix+"_payload_json":payload_json, prefix+"_payload_digest":sha(payload_json.encode("ascii")),
            "signature_algorithm":"Ed25519", "signing_key_id":trusted["signing_key_id"],
            "signature":encode(signature), "signature_digest":sha(signature)})
        return row

    high = dict(scope="active", policyId="synthetic-policy", sequence=1, rollbackEpoch=1, policyHash=sha(b"synthetic-policy"))
    record = sign(g.PREPARE, dict(genesis_preparation_digest=sha(b"independently-signed-genesis-reference"),
        policy_id=high["policyId"], policy_sequence=1, rollback_epoch=1, policy_hash=high["policyHash"],
        high_water_digest=sha(db.dumps(high).encode("ascii")), prepared_by="synthetic-actor",
        prepared_at_epoch_ns=ns-10**9, expires_at_epoch_ns=ns+10**9))
    policy = dict(auditStoreIdentityDigest=sha(b"synthetic-independent-audit-store"),
        auditSignerPublicKeyDigest=keypairs["audit_inclusion_receipt"][1]["signing_key_id"])

    def args(operation, row):
        kind = "authority_genesis" if operation == g.PREPARE else "audit_inclusion_receipt"
        _, key, head = keypairs[kind]
        value = dict(schema=g.PREPARE_SCHEMA, record=row) if operation == g.PREPARE else dict(schema=g.FINALIZE_SCHEMA,
            genesisPreparationDigest=record["genesis_preparation_digest"], inclusionReceipt=row,
            auditStoreIdentityDigest=policy["auditStoreIdentityDigest"])
        value["verificationInputs"] = dict(key=key, head=head, revocationSequence=0)
        return {**value, "businessIntent":contract.synthesize_business_intent(operation, value)}

    def selection(table, key, row=None):
        return dict(table=table, key=key, keyDigest=radix.authenticated_key_digest(table, key), present=row is not None, row=row)

    populations = {table: [] for table in g.TABLES}
    populations["policy_authority_trusted_keys"] = [entry[1] for entry in keypairs.values()]

    def context(operation, arguments, populated, extra=()):
        rows = list(extra)
        for table, values in populated.items():
            for row in values:
                key = {name:row[name] for name in primary.PRIMARY_KEY_COLUMNS[table]}
                rows.append(selection(table, key, row))
        kind = "authority_genesis" if operation == g.PREPARE else "audit_inclusion_receipt"
        rows.append(selection("policy_authority_trusted_key_heads", {"evidence_kind":kind}, keypairs[kind][2]))
        for query in g.queries(operation, arguments=arguments, database_now=now, request_digest=sha(b"actual-request-fixture")):
            if query.absent_key is not None:
                key = dict(query.absent_key)
                if any(isinstance(value, core.SelectedRowFieldReference) for value in key.values()):
                    key = {"policy_hash":record["policy_hash"]}
                if not any(entry["table"] == query.table and entry["key"] == key for entry in rows):
                    rows.append(selection(query.table, key))
        return core.KernelContext(operation=operation, arguments=arguments, selected_rows=tuple(rows), database_now=now,
            request_digest=sha(b"actual-request-fixture"), genesis_root_digest=sha(b"separate-admitted-root"), genesis_policy=policy)

    prep_args = args(g.PREPARE, record)
    prep_context = context(g.PREPARE, prep_args, populations)
    prepared = g.transition(prep_context)
    audit = g.stage(record, now)
    eventhash = sha(b"actual-audit-event-fixture")
    receipt = dict(transition_digest=audit["transition"]["transition_digest"], outbox_id=audit["outbox"]["id"],
        outbox_event_digest=audit["outbox"]["event_digest"], audit_store_identity_digest=policy["auditStoreIdentityDigest"],
        audit_ledger_namespace=db._POLICY_AUTHORITY_AUDIT_LEDGER_NAMESPACE,
        audit_signer_public_key_digest=policy["auditSignerPublicKeyDigest"], audit_event_hash=eventhash,
        audit_sequence=1, previous_audit_event_hash=None)
    receipt["inclusion_root_digest"] = db._policy_authority_audit_inclusion_root(
        audit_store_identity_digest=policy["auditStoreIdentityDigest"], audit_ledger_namespace=receipt["audit_ledger_namespace"],
        audit_signer_public_key_digest=policy["auditSignerPublicKeyDigest"], audit_sequence=1, previous_root_digest=None,
        audit_event_hash=eventhash, outbox_event_digest=receipt["outbox_event_digest"], transition_digest=receipt["transition_digest"])
    receipt = sign(g.FINALIZE, receipt)
    final_args = args(g.FINALIZE, receipt)
    new_populations = {table:list(values) for table, values in populations.items()}
    verification = next(change["row"] for change in prepared.mutations if change["table"] == "policy_authority_evidence_verifications")
    new_populations["policy_authority_evidence_verifications"].append(verification)
    stored = next(change["row"] for change in prepared.mutations if change["table"] == "policy_authority_genesis_preparations")
    extra = (selection("policy_authority_genesis_preparations", {"genesis_preparation_digest":record["genesis_preparation_digest"]}, stored),
        selection("metadata_audit_outbox", {"id":audit["outbox"]["id"]}, {**audit["outbox"], "status":"audited", "audit_event_hash":eventhash}),
        selection("policy_authority_transition_audits", {"transition_digest":receipt["transition_digest"]}, audit["transition"]))
    final_context = context(g.FINALIZE, final_args, new_populations, extra)
    return dict(g=g, core=core, db=db, contract=contract, record=record, receipt=receipt, arguments=prep_args,
        final_arguments=final_args, prepared=prepared, prepare_context=prep_context, final_context=final_context,
        policy=policy, now=now, ns=ns, sign=sign, args=args)


def scenario(name):
    import copy
    from dataclasses import replace
    from serverware import authority_transition_policy as legacy
    f = fixture(); g, core = f["g"], f["core"]
    def refuses(call, message=None):
        try:
            call()
        except Exception as error:
            if message is not None:
                assert message in str(error), (message, str(error))
            return
        raise AssertionError("expected source refusal")

    if name == "prepare":
        result = legacy._PolicyGenesisPrepareKernel().transition(f["prepare_context"])
        assert result == f["prepared"] and len(result.mutations) == 4
        assert {change["table"] for change in result.mutations} == {"policy_authority_evidence_verifications",
            "metadata_audit_outbox", "policy_authority_transition_audits", "policy_authority_genesis_preparations"}
        assert all(change["operation"] == "INSERT" for change in result.mutations)
        stored = next(change["row"] for change in result.mutations if change["table"] == "policy_authority_genesis_preparations")
        verification = next(change["row"] for change in result.mutations if change["table"] == "policy_authority_evidence_verifications")
        assert stored["verification_receipt_digest"] == verification["verification_receipt_digest"]
        assert stored["genesis_envelope_json"] == f["record"]["genesis_envelope_json"]
        queries = legacy._PolicyGenesisPrepareKernel().queries(arguments=f["arguments"], database_now=f["now"],
            request_digest=f["prepare_context"].request_digest)
        assert not any(query.table == "policy_authority_external_evidence_receipts" for query in queries)
        assert sum(query.maximum_rows for query in queries) < f["contract"].MAX_SELECTORS_PER_OPERATION
        assert all(query.page_size == 16 for query in queries if query.proof_primitive == "bounded-limit-plus-one")
    elif name == "finalize":
        result = legacy._PolicyGenesisFinalizeKernel().transition(f["final_context"])
        assert len(result.mutations) == 6 and result.result["ok"] and not result.result["idempotent"]
        rows = {change["table"]:change["row"] for change in result.mutations}
        receipt = rows["policy_authority_audit_inclusion_receipts"]
        assert receipt["verification_receipt_digest"] == rows["policy_authority_evidence_verifications"]["verification_receipt_digest"]
        assert receipt["inclusion_receipt_envelope_json"] == f["receipt"]["inclusion_receipt_envelope_json"]
        assert rows["policy_high_water"]["policy_hash"] == f["record"]["policy_hash"]
        assert rows["policy_publications"]["status"] == "committed"
        assert rows["policy_authority_genesis_finalizations"]["genesis_transition_digest"] == f["prepared"].result["genesis_transition_digest"]
        material = dict(genesisPreparationDigest=f["record"]["genesis_preparation_digest"], highWaterDigest=f["record"]["high_water_digest"],
            inclusionReceiptEnvelopeDigest=f["receipt"]["inclusion_receipt_envelope_digest"], finalizedAtEpochNs=f["ns"])
        assert result.result["finalization_digest"] == f["db"]._policy_authority_domain_digest(
            b"serverware.policyAuthorityGenesisFinalization/v1", f["db"].dumps(material).encode("ascii"))
    elif name == "actual-prestate":
        context = f["prepare_context"]
        for table, field, value, error in (("policy_authority_trusted_keys", "installed_at_epoch_ns", f["ns"], "prestate changed"),
                ("policy_authority_trusted_key_heads", "head_key_revision", 2, "head prestate changed")):
            rows = copy.deepcopy(context.selected_rows)
            target = next(row for row in rows if row["table"] == table and row["row"]["evidence_kind"] == "authority_genesis")
            target["row"][field] = value
            refuses(lambda: g.transition(replace(context, selected_rows=rows)), error)
        refuses(lambda: g.transition(replace(context, genesis_policy=None)), "signed audit pins")
        refuses(lambda: g.transition(replace(context, genesis_root_digest=f["record"]["signing_key_id"])), "admitted root")
        revoked = dict(table="policy_authority_trusted_key_revocations", key={"synthetic":"row-only"},
            keyDigest="sha256:"+"a"*64, present=True, row={"evidence_kind":"authority_genesis",
                "signing_key_id":f["record"]["signing_key_id"], "revocation_sequence":1})
        changed_args = copy.deepcopy(context.arguments); changed_args["verificationInputs"]["revocationSequence"] = 1
        refuses(lambda: g.transition(replace(context, selected_rows=(*context.selected_rows, revoked), arguments=changed_args)), "revoked")
        changed = copy.deepcopy(f["arguments"]); changed["record"]["signature"] = "A" * 86
        refuses(lambda: g.queries(g.PREPARE, arguments=changed, database_now=f["now"], request_digest=context.request_digest))
    elif name == "audit-refusals":
        context = f["final_context"]
        for field, value in (("status", "pending"), ("audit_event_hash", "sha256:"+"9"*64), ("event_digest", "sha256:"+"8"*64)):
            rows = copy.deepcopy(context.selected_rows)
            next(row for row in rows if row["table"] == "metadata_audit_outbox")["row"][field] = value
            refuses(lambda: g.transition(replace(context, selected_rows=rows)), "terminal audited outbox")
        policy = {**f["policy"], "auditStoreIdentityDigest":"sha256:"+"9"*64}
        refuses(lambda: g.transition(replace(context, genesis_policy=policy)), "inclusion purpose")
        from datetime import timedelta
        refuses(lambda: g.transition(replace(context, database_now=f["now"]+timedelta(seconds=2))))
    elif name == "versions":
        args = copy.deepcopy(f["arguments"])
        refuses(lambda: legacy._genesis_prepare_arguments(args), "not exact")
        old = dict(record=f["record"], policySignatureEvidenceDigest="sha256:"+"a"*64)
        old["businessIntent"] = f["contract"].synthesize_business_intent(g.PREPARE, old)
        assert legacy._genesis_prepare_arguments(old)[0] == f["record"]
        assert not g.selected(g.PREPARE, old)
        for changed in ({**args, "schema":"serverware.policyAuthorityGenesisPrepare/v3"}, {**args, "policySignatureEvidenceDigest":"sha256:"+"a"*64}):
            refuses(lambda: g.parse_arguments(g.PREPARE, changed))
        assert g.configuration(None) is None
        refuses(lambda: g.configuration({**f["policy"], "autoApprove":True}))
        spec = f["contract"].operation_spec(g.PREPARE)
        assert "bound-verified-assertion-receipt" in str(spec)
    elif name == "commissioning":
        from serverware import development_policy_commissioning as m
        prepared = f["prepared"].result
        authorization = {"challengeId":"synthetic-shape-only", "credentialRecordId":"synthetic-shape-only", "assertion":{"not":"authority"}}
        value = {"input":{key:item for key,item in f["final_arguments"].items() if key != "businessIntent"},
            "webauthnAuthorization":authorization}
        assert m.finalize_input(m._canonical(value), prepared, prepare_schema=g.PREPARE_SCHEMA) == value
        changed = copy.deepcopy(value); changed["input"].pop("schema")
        refuses(lambda: m.finalize_input(m._canonical(changed), prepared, prepare_schema=g.PREPARE_SCHEMA))
        changed = copy.deepcopy(value); changed["input"]["genesisPreparationDigest"] = "sha256:"+"0"*64
        refuses(lambda: m.finalize_input(m._canonical(changed), prepared, prepare_schema=g.PREPARE_SCHEMA))
    else:
        raise AssertionError(name)


class GenesisSuccessorTests(unittest.TestCase):
    def check(self, name):
        environment = {key:value for key,value in os.environ.items() if not key.startswith("SERVERWARE_")}
        with tempfile.TemporaryDirectory(prefix="serverware-genesis-v2-") as directory:
            environment.update(SERVERWARE_DATA_DIR=directory, SERVERWARE_RELEASE_CHANNEL="dev", SERVERWARE_PROCESS_MODE="serverware-control-plane")
            command = "import sys; sys.path.insert(0,sys.argv[1]); from scripts.test_authority_genesis_successor import scenario; scenario(sys.argv[2])"
            result = subprocess.run([sys.executable, "-I", "-B", "-c", command, str(ROOT), name], cwd=ROOT,
                env=environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_prepare_commits_current_signature_verification_and_original_audit(self): self.check("prepare")
    def test_finalization_joins_real_format_audit_originals_and_existing_tables(self): self.check("finalize")
    def test_supplied_key_head_or_missing_admitted_configuration_is_not_authority(self): self.check("actual-prestate")
    def test_nonterminal_changed_or_unpinned_audit_refuses(self): self.check("audit-refusals")
    def test_explicit_v2_and_legacy_shapes_remain_distinct(self): self.check("versions")
    def test_actual_commissioning_preflight_preserves_v2_pair_and_retained_prepare(self): self.check("commissioning")


if __name__ == "__main__":
    unittest.main()

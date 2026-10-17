#!/usr/bin/env python3
"""Real JIT denial crypto/kernel/SQL components, NOT admitted authority.

Reuse the approval fixture's genuine ES256 keys, original SQL row shapes and
Ed25519 verifier. Trust roots, pending business rows, capabilities and framework
completion remain explicitly synthetic. No HTTP, provider, measured process or
hardware ceremony is exercised. Optional PostgreSQL uses an externally owned
disposable Unix-socket engine and actual production SQL helpers, not the entire
installed executor. This script neither starts an engine nor provisions trust.
"""
from __future__ import annotations

import argparse
import copy
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Import-only offline validator mode; never start an app or adopt live state.
os.environ["CATCHPLATE_PROCESS_MODE"] = "metadata-bootstrap"
os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
from scripts import test_authority_jit_approval as common
from catchplate import authority_transition_jit_denial as denial
from catchplate import authority_transition_jit_approval as approval
from catchplate.authority_store.jit_denial_sql import assert_jit_denial_sql

core, service, reads, verifier = common.core, common.service, common.reads, common.verifier
canonical, sha, framed, b64, row = common.canonical, common.sha, common.framed, common.b64, common.row
OPERATION = "jit.deny"


class DenialFixture(common.Fixture):
    """Only selected originals/admission are synthetic; crypto is not replaced."""

    def sign(self, number=0, *, note="synthetic component denial", overrides=None):
        credential = next(value for value in self.data["webauthn_credentials"]
            if value["id"] == "hardware-" + str(number))
        review = next(value for value in self.data["approval_review_receipts"]
            if value["id"] == "review-" + str(number))
        args = dict(item_id=self.item, note=note, actor_id=self.actors[number], authn=None,
            challenge_id=str(uuid.uuid4()), review_receipt_id=review["id"],
            review_digest=review["review_digest"], require_review_receipt=True,
            required_approver_roles={"$authorityType": "set", "items": ["admin"]},
            allowed_approver_ids={"$authorityType": "set", "items": list(self.actors)},
            authority_policy_hash=self.policy_hash, authority_route_id="route",
            require_approver_webauthn=True, approval_threshold=self.policy["threshold"],
            approver_credential_policy=self.policy["credentialPolicy"])
        args.update(overrides or {})
        request = service._controlled_writer_request_digest(OPERATION, args)
        operation_id = framed("catchplate.policyAuthorityOperation/v2", OPERATION.encode(), request.encode())
        payload = {"schema": "catchplate.policyAuthorityWebAuthnChallenge/v1", "operationId": operation_id,
            "rpId": common.config.WEBAUTHN_RP_ID, "origin": common.config.WEBAUTHN_ORIGIN,
            "issuedAtEpochNs": self.now - 1_000_000_000, "expiresAtEpochNs": self.now + 25_000_000_000,
            "credentialId": credential["credential_id"]}
        challenge = row("webauthn_challenges", id=args["challenge_id"], challenge=b64(uuid.uuid4().bytes * 2),
            challenge_type="policy_authority", user_id=args["actor_id"], scope_key=operation_id,
            approval_request_id=self.item, payload_json=canonical(payload).decode(),
            expires_at=(self.at + timedelta(seconds=25)).isoformat(), created_at=self.stamp,
            retention_reference_mask=0)
        self.data["webauthn_challenges"].append(challenge)
        public_challenge = {**payload, "challengeId": challenge["id"], "challenge": challenge["challenge"],
            "challengeRowDigest": framed("catchplate.policyAuthorityWebAuthnChallengeRow/v1",
                canonical({key: challenge[key] for key in approval.CHALLENGE_FIELDS}))}
        binding = {key: credential[key] for key in approval.CREDENTIAL_FIELDS}
        policy_digest = framed("catchplate.policyAuthorityCredentialPolicy/v1",
            canonical(common.trust.credential_policy_document(binding, self.high)))
        public_credential = common.actual_credential_projection(binding, policy_digest, self.trust_digest)
        client = canonical({"type": "webauthn.get", "challenge": challenge["challenge"],
            "origin": common.config.WEBAUTHN_ORIGIN, "crossOrigin": False})
        auth = hashlib.sha256(common.config.WEBAUTHN_RP_ID.encode()).digest() + b"\x05" + (
            credential["sign_count"] + 1).to_bytes(4, "big")
        normalized = {"credentialId": credential["credential_id"], "clientDataJSON": b64(client),
            "authenticatorData": b64(auth), "signature": b64(self.keys[number].sign(
                auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())))}
        args["authn"] = {"credential_id": credential["credential_id"], "assertion": {
            "id": credential["credential_id"], "rawId": credential["credential_id"], "type": "public-key",
            "response": {key: normalized[key] for key in ("clientDataJSON", "authenticatorData", "signature")}}}
        if service._controlled_writer_request_digest(OPERATION, args) != request:
            raise ValueError("denial original facade request digest changed")
        process = object.__new__(service.AuthorityProcess)
        process.signing_key = Ed25519PrivateKey.generate()
        process.configuration = service.MeasuredConfiguration(payload={"webauthn": {
            "rpId": common.config.WEBAUTHN_RP_ID, "origin": common.config.WEBAUTHN_ORIGIN,
            "maximumChallengeAgeNs": 30_000_000_000, "allowedAuthenticatorClasses": ["hardware"],
            "requireAttestationTrusted": True}}, digest=sha(b"synthetic trust config"),
            root_key=process.signing_key.public_key())
        process.role_config = {"measurementDigest": sha(b"synthetic measurement"),
            "attestationReceiptDigest": sha(b"synthetic verifier admission")}
        cap_id = sha(uuid.uuid4().bytes)
        # The selected rows and admitted signer identity are explicit doubles.
        # Real raw-assertion verification and real receipt signing run inside.
        with patch.object(process, "_read_webauthn_authority", return_value=(
                public_challenge, public_credential, normalized)), \
                patch.object(service.time, "time_ns", return_value=self.now):
            evidence, receipt, receipt_digest = process._build_v9_webauthn_evidence(
                operation=OPERATION, operation_id=operation_id, request_digest=request, capability_id=cap_id,
                authorization_reference=process._webauthn_reference_from_arguments(args),
                deadline_epoch_ns=self.now + 20_000_000_000, arguments=args)
        verification = dict(operation=OPERATION, operation_id=operation_id, request_digest=request,
            capability_id=cap_id, verifier_identity={"sessionIdentityDigest": evidence["verifierSessionIdentityDigest"],
                **process.role_config}, verifier_public_key=process.signing_key.public_key(),
            now_epoch_ns=self.now, deadline_epoch_ns=self.now + 20_000_000_000,
            maximum_age_ns=30_000_000_000, work=None)
        verified = verifier._verify_operation_assertion_evidence(evidence, **verification)
        return dict(arguments=service._synthesize_business_arguments(OPERATION, args), raw_arguments=args,
            request=request, operation_id=operation_id, capability_id=cap_id, evidence=dict(verified),
            signed_evidence=evidence, verification=verification, receipt=receipt, receipt_digest=receipt_digest,
            evidence_row=common.authorization_records._assertion_storage_row(evidence),
            challenge=challenge, credential=credential)

    def context(self, signed, fetch=None):
        queries = denial.JitDenyKernel().queries_with_evidence(arguments=signed["arguments"],
            database_now=self.at, request_digest=signed["request"], evidence=signed["evidence"])
        union, records = {}, []
        for query in queries:
            resolved = reads.resolve_query(OPERATION, query, prior_reads=tuple(records),
                selected_rows=tuple(union.values()))
            if fetch is None:
                if any(p.operator != "eq" for p in resolved.predicates):
                    raise ValueError("denial fixture only interprets exact source equalities")
                actual = [copy.deepcopy(value) for value in self.data[resolved.table]
                    if all(value[p.column] == p.value for p in resolved.predicates)]
                for order in reversed(resolved.order_by):
                    actual.sort(key=lambda item: item[order.column], reverse=order.descending)
                actual = actual[:resolved.maximum_rows]
            else:
                actual = fetch(resolved)
            observations = [common.selected(resolved.table, value) for value in actual]
            if not actual and resolved.absent_key is not None:
                observations = [common.selected(resolved.table, key=dict(resolved.absent_key))]
            for observation in observations:
                address = observation["table"], observation["keyDigest"]
                if address in union and union[address] != observation:
                    raise ValueError("denial query observations conflict")
                union[address] = observation
            records.append(reads.capture_query_read(OPERATION, query, resolved_query=resolved,
                ordered_selected_rows=tuple(observations), returned_row_count=len(actual)))
        reads.validate_query_reads(OPERATION, queries=queries, query_reads=tuple(records),
            selected_rows=tuple(union.values()))
        return core.KernelContext(OPERATION, signed["arguments"], tuple(union.values()), self.at,
            signed["request"], signed["evidence"], tuple(records))

    def apply_model(self, transition):
        """Pure replay model only; actual persistence is tested separately below."""
        for mutation in transition.mutations:
            rows = self.data[mutation["table"]]
            matches = [value for value in rows
                if all(value[name] == selected for name, selected in mutation["key"].items())]
            if matches:
                if len(matches) != 1 or matches[0] != mutation["expectedRow"]:
                    raise ValueError("denial pure model CAS mismatch")
                rows.remove(matches[0])
            elif mutation["operation"] != "INSERT":
                raise ValueError("denial pure model update lost its row")
            rows.append(copy.deepcopy(mutation["row"]))


def transition(fixture, signed, fetch=None):
    return denial.JitDenyKernel().transition(fixture.context(signed, fetch))


class JitDenialPureTests(unittest.TestCase):
    def test_installed_facade_passes_original_review_and_assertion_only_to_dispatch(self):
        from catchplate import db
        from catchplate.authority_store import authority_dispatch
        fixture = DenialFixture()
        signed = fixture.sign()
        values = copy.deepcopy(signed["raw_arguments"])
        for field in ("required_approver_roles", "allowed_approver_ids"):
            values[field] = set(values[field]["items"])
        calls = []

        class DispatchBoundary(Exception):
            pass

        def stop(operation, document):
            calls.append((operation, copy.deepcopy(document)))
            raise DispatchBoundary()

        with patch.object(db, "dispatch_policy_authority_operation", side_effect=stop), \
                patch.object(db, "connect", side_effect=AssertionError("facade reached a database")), \
                self.assertRaises(DispatchBoundary):
            db.deny_request(**values)
        self.assertEqual(calls, [(OPERATION, {
            "schema": "catchplate.policyAuthorityControlledWriterInput/v1", "handler": "deny_request",
            "operationManifestDigest": common.contract.OPERATION_MANIFEST_DIGEST,
            "arguments": authority_dispatch._authority_marshal_value(values)})])
        self.assertNotIn("businessIntent", calls[0][1]["arguments"])

    def test_one_actor_denies_threshold_two_with_real_signed_originals_and_no_vote_or_grant(self):
        fixture = DenialFixture(threshold=2)
        signed = fixture.sign()
        result = transition(fixture, signed)
        self.assertEqual(result.result["status"], "denied")
        self.assertFalse(result.result["idempotent_replay"])
        self.assertEqual({item["table"] for item in result.mutations}, {"approval_requests",
            "approval_review_receipts", "webauthn_challenges", "webauthn_credentials", "metadata_audit_outbox"})
        self.assertEqual(approval.raw_receipt_from_originals(signed["evidence"],
            signed["challenge"], signed["credential"]), (signed["receipt"], signed["receipt_digest"]))
        self.assertNotEqual(signed["receipt_digest"], signed["evidence"]["verifiedAssertionReceiptDigest"])
        changed = {item["table"]: item["row"] for item in result.mutations}
        self.assertEqual(changed["webauthn_credentials"]["sign_count"], 2)
        for table in ("approval_review_receipts", "webauthn_challenges"):
            self.assertEqual(changed[table]["used_at"], fixture.stamp)
        authn = json.loads(changed["approval_requests"]["approval_authn"])
        self.assertEqual(authn, {"schema": "catchplate.jitDenialAuthnReceipt/v3",
            "approverPolicyDigest": fixture.policy_digest, "verifiedAssertionReceiptDigest": signed["receipt_digest"],
            "authorityCapabilityId": signed["capability_id"], "authorityRequestDigest": signed["request"],
            "reviewReceiptId": "review-0", "reviewDigest": signed["arguments"]["review_digest"]})
        audit = changed["metadata_audit_outbox"]
        self.assertEqual(audit["event_type"], "approval.denied")
        event = json.loads(audit["event_json"])
        self.assertEqual(event["schema"], "catchplate.jitApprovalDenied/v3")
        for key, value in authn.items():
            if key != "schema":
                self.assertEqual(event[key], value)
        self.assertEqual(event["approvalRequestId"], fixture.item)
        self.assertEqual(event["requestDigest"], fixture.data["approval_requests"][0]["request_digest"])
        self.assertEqual(event["verifiedEvidenceDigest"], signed["evidence"]["verifiedAssertionReceiptDigest"])
        self.assertFalse(fixture.data[common.HISTORY])
        self.assertFalse(fixture.data["approval_grants"])
        self.assertFalse(fixture.data["approval_request_decisions"])

    def test_review_required_closed_arguments_and_utf8_note_bound(self):
        fixture = DenialFixture()
        signed = fixture.sign(note="é" * 250)
        self.assertEqual(transition(fixture, signed).result["decision_note"], "é" * 250)
        for field, value in (("require_review_receipt", False), ("require_review_receipt", 1),
                ("review_receipt_id", None), ("review_digest", None), ("challenge_id", None),
                ("note", "é" * 251), ("note", True), ("authn", {"method": "webauthn", "user_verified": True})):
            with self.subTest(field=field, kind=type(value).__name__), self.assertRaises(core.TransitionKernelError):
                denial.arguments({**signed["arguments"], field: value})
        for field in denial.FIELDS:
            values = dict(signed["arguments"])
            del values[field]
            with self.subTest(missing=field), self.assertRaises(core.TransitionKernelError):
                denial.arguments(values)
        with self.assertRaises(core.TransitionKernelError):
            denial.arguments({**signed["arguments"], "ttl_seconds": 60})

    def test_native_family_in_any_stored_reference_refuses_even_with_live_review(self):
        fixture = DenialFixture()
        signed = fixture.sign()
        self.assertEqual(transition(fixture, signed).result["status"], "denied")
        markers = ("native-jit:" + "a" * 64, "native-jit:malformed", "native-jit", "native-jit-other",
            "NATIVE-JIT:malformed", " \t\r\nNaTiVe-JiT:malformed", "\u2003native-jit:malformed")
        for field in ("url", "canonical_request", "redacted_display"):
            for marker in markers:
                with self.subTest(field=field, marker=marker), \
                        patch.dict(fixture.data["approval_requests"][0], {field: marker}):
                    before = copy.deepcopy(fixture.data)
                    with patch.object(approval, "_policy", side_effect=AssertionError("native policy reached")) as policy, \
                            patch.object(approval, "_assertion", side_effect=AssertionError("native assertion reached")) as assertion, \
                            self.assertRaisesRegex(core.TransitionKernelError, "Native JIT decisions require their continuation authority"):
                        transition(fixture, signed)
                    policy.assert_not_called(); assertion.assert_not_called()
                    self.assertEqual(fixture.data, before)

    def test_native_or_malformed_references_cannot_enter_denial_replay(self):
        fixture = DenialFixture()
        signed = fixture.sign()
        fixture.apply_model(transition(fixture, signed))
        self.assertTrue(transition(fixture, signed).result["idempotent_replay"])
        for field in ("url", "canonical_request", "redacted_display"):
            for value in ("native-jit:retained", " \tNATIVE-JIT:malformed", None, 0, False, [], {}):
                with self.subTest(field=field, type=type(value).__name__), \
                        patch.dict(fixture.data["approval_requests"][0], {field: value}):
                    before = copy.deepcopy(fixture.data)
                    with self.assertRaisesRegex(core.TransitionKernelError, "Native JIT decisions require their continuation authority"):
                        transition(fixture, signed)
                    self.assertEqual(fixture.data, before)
        self.assertTrue(transition(fixture, signed).result["idempotent_replay"])

    def test_real_evidence_signature_and_raw_assertion_mismatches_refuse(self):
        fixture = DenialFixture()
        signed = fixture.sign()
        altered = copy.deepcopy(signed["signed_evidence"])
        altered["counter"] += 1
        with self.assertRaises(verifier.AssertionEvidenceError):
            verifier._verify_operation_assertion_evidence(altered, **signed["verification"])
        with self.assertRaises(verifier.AssertionEvidenceError):
            verifier._verify_operation_assertion_evidence(signed["signed_evidence"],
                **{**signed["verification"], "operation": "jit.decide"})
        for name in ("clientDataJSON", "authenticatorData", "signature"):
            changed = copy.deepcopy(signed["arguments"])
            changed["authn"]["assertion"]["response"][name] = b64(b"unverified replacement")
            with self.subTest(name=name), self.assertRaises(core.TransitionKernelError):
                transition(fixture, {**signed, "arguments": changed})
        with self.assertRaises(core.TransitionKernelError):
            denial.JitDenyKernel().queries(arguments=signed["arguments"], database_now=fixture.at,
                request_digest=signed["request"])

    def test_actor_review_and_all_original_currentness_bindings_refuse(self):
        fixture = DenialFixture()
        signed = fixture.sign()
        changes = (("approval_review_receipts", "reviewer_id", fixture.actors[1]),
            ("approval_review_receipts", "approval_request_id", "another-request"),
            ("approval_review_receipts", "review_digest", sha(b"other review")),
            ("approval_review_receipts", "used_at", fixture.stamp),
            ("approval_review_receipts", "expires_at", fixture.stamp),
            ("approval_requests", "expires_at", fixture.stamp),
            ("approval_requests", "status", "approved"), ("approval_requests", "status", "expired"),
            ("webauthn_challenges", "expires_at", fixture.stamp),
            ("webauthn_challenges", "used_at", fixture.stamp),
            ("webauthn_challenges", "scope_key", sha(b"other operation")),
            ("webauthn_credentials", "user_id", fixture.actors[1]),
            ("webauthn_credentials", "sign_count", 2),
            ("webauthn_credentials", "revoked_at", fixture.stamp),
            ("rbac_role_bindings", "status", "deprovisioned"),
            ("rbac_role_bindings", "roles_json", '["viewer"]'),
            ("policy_high_water", "policy_hash", sha(b"changed current policy")),
            ("webauthn_trust_publications", "withdrawn_credential_ids_json", '["hardware-0"]'))
        for table, field, value in changes:
            with self.subTest(table=table, field=field, value=value), \
                    patch.dict(fixture.data[table][0], {field: value}), self.assertRaises(core.TransitionKernelError):
                transition(fixture, signed)
        for table in ("approval_review_receipts", "webauthn_challenges", "webauthn_credentials"):
            with self.subTest(missing=table), patch.dict(fixture.data, {table: []}), \
                    self.assertRaises(core.TransitionKernelError):
                transition(fixture, signed)

    def test_complete_stored_policy_is_required_and_grant_cannot_coexist(self):
        for field, value in (("approval_threshold", 2), ("authority_route_id", "other-route"),
                ("authority_policy_hash", sha(b"other-policy")), ("require_approver_webauthn", False),
                ("allowed_approver_ids", {"$authorityType": "set", "items": ["oidc:synthetic-a"]}),
                ("required_approver_roles", {"$authorityType": "set", "items": ["viewer"]})):
            fixture = DenialFixture()
            signed = fixture.sign(overrides={field: value})
            with self.subTest(field=field), self.assertRaises(core.TransitionKernelError):
                transition(fixture, signed)
        fixture = DenialFixture()
        signed = fixture.sign()
        for field in fixture.policy:
            broken = {key: value for key, value in fixture.policy.items() if key != field}
            raw = canonical(broken).decode()
            with self.subTest(policy_field=field), patch.dict(fixture.data["approval_requests"][0],
                    {"approver_policy_json": raw, "approver_policy_digest": framed(
                        "catchplate.jitApproverPolicy/v1", raw.encode())}), self.assertRaises(core.TransitionKernelError):
                transition(fixture, signed)
        fixture.data["approval_grants"] = [row("approval_grants", id="approval:" + fixture.item)]
        with self.assertRaises(core.TransitionKernelError):
            transition(fixture, signed)

    def test_exact_replay_is_read_only_and_cannot_reuse_review_under_new_assertion(self):
        fixture = DenialFixture(threshold=2)
        signed = fixture.sign()
        fixture.apply_model(transition(fixture, signed))
        before = copy.deepcopy(fixture.data)
        for _ in range(2):
            replay = transition(fixture, signed)
            self.assertTrue(replay.result["idempotent_replay"])
            self.assertEqual(replay.mutations, ())
        self.assertEqual(fixture.data, before)
        for field, value in (("note", "changed"), ("review_digest", sha(b"changed"))):
            with self.subTest(field=field), self.assertRaises(core.TransitionKernelError):
                transition(fixture, {**signed, "arguments": {**signed["arguments"], field: value}})
        credential, = [value for value in fixture.data["webauthn_credentials"]
            if value["id"] == signed["evidence"]["credentialRecordId"]]
        with patch.dict(credential, {"revoked_at": fixture.stamp}), \
                self.assertRaises(core.TransitionKernelError):
            transition(fixture, signed)
        fresh = fixture.sign()
        with self.assertRaises(core.TransitionKernelError):
            transition(fixture, fresh)
        fixture.at += timedelta(seconds=31)
        with self.assertRaises(core.TransitionKernelError):
            transition(fixture, signed)


class JitDenialPostgresTests(unittest.TestCase):
    # Reuse the actual source-derived DDL/CAS/historical SQL setup; do not
    # inherit approval test methods or mistake these helpers for full v9.
    insert = common.JitApprovalPostgresTests.insert
    seed = common.JitApprovalPostgresTests.seed
    fetch = common.JitApprovalPostgresTests.fetch
    inventory = common.JitApprovalPostgresTests.inventory
    complete = common.JitApprovalPostgresTests.complete

    def setUp(self):
        common.JitApprovalPostgresTests.setUp(self)
        guard, _ = common.optional._guard_parts(namespace=self.ns)
        self.db.execute(f"""CREATE FUNCTION {self.ns}.admit_denial(cap_id text, rows_json text,
            mutations_json text, evidence_digest text, trust_digest text, started bigint)
            RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $body$
            DECLARE capability record; planner record; trust_publication record; trust_high_water record;
                assertion_evidence record; assertion_requirements jsonb := '{{"jit.deny":true}}'::jsonb;
                authorization_projection record; computed_trust_high_water_digest text := trust_digest;
                now_epoch_ns bigint := started;
            BEGIN
                SELECT * INTO STRICT capability FROM {self.ns}.{common.CAPABILITIES} WHERE capability_id=cap_id FOR UPDATE;
                SELECT rows_json AS selected_business_rows_json, mutations_json AS mutation_plan_json INTO planner;
                {common.locked_webauthn_trust_projection(self.ns)}
                SELECT * INTO STRICT assertion_evidence FROM {self.ns}.{common.EVIDENCE} WHERE capability_id=cap_id;
                SELECT evidence_digest AS assertion_evidence_digest INTO authorization_projection;
                {guard}
                {common.fresh_assertion_cas_sql(self.ns)}
                {assert_jit_denial_sql(self.ns)}
                {common.retain_webauthn_receipt_sql(self.ns)}
            END; $body$""")

    def commit(self, fixture, signed, *, before_apply=None, after_complete=None, mutations_override=None):
        from psycopg.types.json import Jsonb
        with self.db.transaction():
            context = fixture.context(signed, self.fetch)
            result = denial.JitDenyKernel().transition(context)
            cap = common.JitApprovalPostgresTests.capability(self, fixture, signed, result.result)
            cap.update(operation=OPERATION, handler_name="deny_request")
            self.insert(common.CAPABILITIES, cap)
            self.insert(common.EVIDENCE, signed["evidence_row"])
            mutations = result.mutations if mutations_override is None else mutations_override(result.mutations)
            self.db.execute(f"SELECT {self.ns}.admit_denial(%s,%s,%s,%s,%s,%s)", (
                cap["capability_id"], canonical(context.selected_rows).decode(), canonical(mutations).decode(),
                signed["evidence_row"]["assertion_evidence_digest"], fixture.trust_digest, fixture.now))
            if before_apply is not None:
                before_apply()
            for mutation in sorted(mutations, key=lambda value: (value["table"], value["keyDigest"], value["operation"])):
                self.db.execute(f"SELECT {self.ns}.apply_one(%s,%s)",
                    (Jsonb(mutation), Jsonb(list(common.PRIMARY_KEY_COLUMNS[mutation["table"]]))))
            # Synthetic admitted framework completion, exactly as approval's
            # component fixture. Not a signed witness or full writer claim.
            self.complete(cap, result.result, fixture.now + 1)
            if after_complete is not None:
                after_complete()
        return result

    def test_actual_sql_denial_retains_history_consumes_review_and_never_votes_or_grants(self):
        fixture = DenialFixture(threshold=2)
        signed = fixture.sign()
        self.seed(fixture)
        result = self.commit(fixture, signed)
        self.assertEqual(result.result["status"], "denied")
        for table in ("approval_grants", "approval_request_decisions", common.AGGREGATE):
            self.assertEqual(self.db.execute(f'SELECT count(*) AS n FROM "{table}"').fetchone()["n"], 0)
        history = self.db.execute(f"SELECT * FROM {common.HISTORY}").fetchone()
        self.assertEqual(history["operation"], OPERATION)
        self.assertEqual(history["receipt_json"], canonical(signed["receipt"]).decode())
        self.assertEqual(history["assertion_receipt_digest"], signed["receipt_digest"])
        self.assertEqual(self.db.execute("SELECT sign_count FROM webauthn_credentials WHERE id='hardware-0'")
            .fetchone()["sign_count"], 2)
        self.assertEqual(self.db.execute("SELECT used_at FROM approval_review_receipts WHERE id='review-0'")
            .fetchone()["used_at"], fixture.stamp)
        audit = self.db.execute("SELECT * FROM metadata_audit_outbox").fetchall()
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["event_type"], "approval.denied")
        before = self.inventory()
        replay = transition(fixture, signed, self.fetch)
        self.assertTrue(replay.result["idempotent_replay"])
        self.assertEqual(replay.mutations, ())
        self.db.execute(f"SELECT {self.ns}.history_only(%s)", (signed["capability_id"],))
        self.assertEqual(self.inventory(), before)

    def test_late_cas_or_completion_failure_rolls_back_all_history_and_business_rows(self):
        import psycopg
        fixture = DenialFixture()
        signed = fixture.sign()
        self.seed(fixture)
        before = self.inventory()

        def changed_review():
            self.db.execute("UPDATE approval_review_receipts SET expires_at=%s WHERE id='review-0'", (fixture.stamp,))

        with self.assertRaisesRegex(psycopg.errors.RaiseException, "CAS precondition changed"):
            self.commit(fixture, signed, before_apply=changed_review)
        self.assertEqual(self.inventory(), before)

        def cancel():
            raise RuntimeError("synthetic post-completion transaction cancellation")

        with self.assertRaises(RuntimeError):
            self.commit(fixture, signed, after_complete=cancel)
        self.assertEqual(self.inventory(), before)
        self.assertEqual(self.commit(fixture, signed).result["status"], "denied")

    def test_independent_writer_denial_binding_and_missing_history_refuse_without_repair(self):
        import psycopg
        fixture = DenialFixture()
        signed = fixture.sign()
        self.seed(fixture)
        before = self.inventory()
        for mode in ("receipt", "capability", "request", "review", "missing-review"):
            def changed(original):
                values = copy.deepcopy(list(original))
                if mode == "missing-review":
                    return [item for item in values if item["table"] != "approval_review_receipts"]
                item = next(item for item in values if item["table"] == "approval_requests")
                authn = json.loads(item["row"]["approval_authn"])
                key = {"receipt": "verifiedAssertionReceiptDigest", "capability": "authorityCapabilityId",
                    "request": "authorityRequestDigest", "review": "reviewDigest"}[mode]
                authn[key] = sha(b"different actual writer binding")
                item["row"]["approval_authn"] = canonical(authn).decode()
                return values
            with self.subTest(mode=mode), self.assertRaises(psycopg.errors.RaiseException):
                self.commit(fixture, signed, mutations_override=changed)
            self.assertEqual(self.inventory(), before)
        self.commit(fixture, signed)
        with self.db.transaction(force_rollback=True):
            self.db.execute(f"DELETE FROM {common.HISTORY}")
            with self.assertRaises(psycopg.errors.RaiseException):
                with self.db.transaction():
                    self.db.execute(f"SELECT {self.ns}.history_only(%s)", (signed["capability_id"],))
            self.assertEqual(self.db.execute(f"SELECT count(*) AS n FROM {common.HISTORY}").fetchone()["n"], 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-dsn")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(JitDenialPureTests)
    if args.postgres_dsn:
        from scripts.test_webauthn_trust_projection_postgres import local_connection_parameters
        common.PARAMETERS = local_connection_parameters(args.postgres_dsn)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(JitDenialPostgresTests))
    else:
        def no_network(event, _arguments):
            if event.startswith("socket."):
                raise AssertionError("pure JIT denial controls forbid sockets and DNS")
        sys.addaudithook(no_network)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Connected JIT components, NOT a fully admitted authority or hardware test.

Ephemeral ES256 assertions and Ed25519 verifier signatures are genuine. Pending
business rows, trust admission, capabilities and framework completion are
explicit synthetic inputs. The target history/decision/grant/aggregate start
absent. Actual query definitions, kernel, SQL history/prior-voter/mutation
helpers, immediate FKs and grant consumer run unchanged. No engine is started;
--postgres-dsn selects an externally owned disposable Unix-socket PG16/17.
"""
from __future__ import annotations

import argparse
import ast
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import unittest
import uuid
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Import-only offline validator mode; never start an app or adopt live state.
os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
from serverware import authority_approver_policy as policies
from serverware import authority_contract as contract
from serverware import authority_query_reads as reads
from serverware import authority_rbac_currentness as rbac
from serverware import authority_service as service
from serverware import authority_transition_core as core
from serverware import authority_transition_jit_approval as jit
from serverware import authority_webauthn_assertion as verifier
from serverware import authority_webauthn_bindings
from serverware import config
from serverware.authority_primary_contract import PRIMARY_KEY_COLUMNS
from serverware.authority_store import authorization_records
from serverware.authority_store.metadata_schema_source import metadata_base_schema_source
from serverware.authority_store.v9_schema_source import authority_v9_schema_source
from serverware.authority_store.mutation_sql import apply_mutation_sql, closed_record_sql
from serverware.authority_store.primary_tree_sql import framed_digest_function_sql
from serverware.authority_store.webauthn_challenge_sql import challenge_original_sql
from serverware.authority_store.webauthn_trust_sql import (
    locked_webauthn_trust_projection, webauthn_credential_policy_sql,
)
from serverware.authority_store.jit_prior_decision_sql import assert_prior_jit_decisions_sql
from serverware.authority_store.webauthn_receipt_history import (
    retain_webauthn_receipt_sql, assert_webauthn_receipt_history_sql,
)
from scripts import authority_revocation_trust_fixture as trust
from scripts import test_authority_executor_optional_evidence as optional
from scripts.test_authority_webauthn_receipt_domains import canonical, sha, framed, b64

PARAMETERS = None
DDL = metadata_base_schema_source() + "\n" + authority_v9_schema_source()
HISTORY = "policy_authority_webauthn_assertion_receipts"
CAPABILITIES = "policy_authority_writer_capabilities"
WRITERS = "policy_authority_writer_receipts"
EVIDENCE = "policy_authority_webauthn_assertion_evidence"
AGGREGATE = "policy_authority_bounded_aggregate_states"
TABLES = ("credentials", "routes", "approval_requests", "approval_grants",
    "approval_review_receipts", CAPABILITIES, WRITERS, HISTORY,
    "approval_request_decisions", "webauthn_credentials", "webauthn_challenges",
    "webauthn_trust_publications", "webauthn_trust_publication_high_water",
    "policy_high_water", "rbac_role_bindings", "rbac_authority_state",
    "policy_authority_authenticated_table_roots", "metadata_audit_outbox", AGGREGATE, EVIDENCE)


def table_ddl(table):
    matches = re.findall(r"^[ \t]*CREATE TABLE IF NOT EXISTS\s+" + re.escape(table)
        + r"\s*\(\n.*?^[ \t]*\);[ \t]*$", DDL, re.M | re.S)
    if len(matches) != 1:
        raise ValueError("actual table declaration is not unique: " + table)
    return matches[0]


def row(table, **values):
    """Full real column roster; explicitly supplied fixture values, not defaults."""
    names = re.findall(r"^[ \t]+([a-z][a-z0-9_]*)\s+(?:TEXT|BIGINT|INTEGER)\b", table_ddl(table), re.M)
    if not names or set(values) - set(names):
        raise ValueError("fixture column drift: " + table)
    return {**dict.fromkeys(names), **values}


def selected(table, value=None, key=None):
    key = key if key is not None else {name: value[name] for name in PRIMARY_KEY_COLUMNS[table]}
    return dict(table=table, key=key, keyDigest=framed(
        "serverware.policyAuthorityBusinessKey/v1", table.encode(), canonical(key)),
        present=value is not None, row=copy.deepcopy(value), contractSelector=None)


def actual_credential_projection(binding, policy_digest, high_water_digest):
    """Execute only the actual reader's final projection over selected originals.

    Selection/root custody is synthetic; this does not substitute a verifier.
    Keeping the original expression protects the production framing contract.
    """
    tree = ast.parse((ROOT / "serverware/authority_service.py").read_text())
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AuthorityProcess")
    method = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == "_read_webauthn_authority")
    expressions = [n.value for n in ast.walk(method) if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "credential" for t in n.targets)]
    if len(expressions) != 1:
        raise ValueError("actual credential projection drift")
    return eval(compile(ast.Expression(expressions[0]), "<actual reader projection>", "eval"),
        {"_canonical": service._canonical, "_framed_digest": service._framed_digest,
            "authority_webauthn_bindings": authority_webauthn_bindings},
        dict(credential_binding=binding, credential_policy_digest=policy_digest,
            trust_high_water_digest=high_water_digest,
            webauthn={"rpId": config.WEBAUTHN_RP_ID, "origin": config.WEBAUTHN_ORIGIN}))


def fresh_assertion_cas_sql(namespace):
    """The entire actual executor CAS guard, not a transplanted predicate."""
    tree = optional._read("serverware/authority_store/executor_v9.py")
    function = optional._one([node for node in tree.body if isinstance(node, ast.FunctionDef)
        and node.name == "install_authority_v9_executor"])
    template = optional._one([optional._template(node) for node in ast.walk(function)
        if isinstance(node, ast.JoinedStr) and any(isinstance(part, ast.Constant)
            and isinstance(part.value, str) and "IF fence_head.fence <> capability.fence" in part.value
            for part in node.values)])
    block = optional._one(re.findall(r"IF \(\s*assertion_requirements->>capability.operation\s*\)::boolean"
        r"\s*THEN\s*IF NOT EXISTS \(.*?END IF;\s*END IF;", template, re.S))
    for name, value in {"namespace": namespace, "challenge_original_sql()": challenge_original_sql(),
            "webauthn_credential_policy_sql()": webauthn_credential_policy_sql()}.items():
        if "{" + name + "}" not in block:
            raise ValueError("actual CAS interpolation changed")
        block = block.replace("{" + name + "}", value)
    if "{" in block or "}" in block:
        raise ValueError("actual CAS acquired an unbound dependency")
    return block


class Fixture:
    def __init__(self, threshold=1):
        # Current bounded time is required by the actual SQL guard, which takes
        # its own clock_timestamp sample. No fake SQL clock or extended budget.
        self.now = time.time_ns() // 1_000_000 * 1_000_000
        self.at = datetime.fromtimestamp(self.now // 1_000_000_000, timezone.utc).replace(
            microsecond=(self.now % 1_000_000_000) // 1000)
        self.stamp = self.at.isoformat()
        self.item = str(uuid.uuid4())
        self.data = {table: [] for table in TABLES}
        self.data.update(trust.trust_rows())
        self.high = self.data["webauthn_trust_publication_high_water"][0]
        self.publication = self.data["webauthn_trust_publications"][0]
        self.trust_digest = framed("serverware.webauthnTrustHighWater/v1",
            canonical(trust.trust_high_water_document(self.high)))
        self.actors = ("oidc:synthetic-a", "oidc:synthetic-b")
        self.keys = [ec.generate_private_key(ec.SECP256R1()) for _ in self.actors]
        self.policy = {"schema": "serverware.jitApproverPolicy/v1", "requiredRoles": ["admin"],
            "roleMatch": "any", "allowedApproverIds": list(self.actors), "allowAnyApproverId": False,
            "requireWebAuthn": True, "threshold": threshold, "credentialPolicy": {
                "allowedCredentialRecordIds": [], "allowedAuthenticatorClasses": ["hardware"],
                "allowedAaguids": [], "requireAttestationTrusted": True,
                "requiredTrustBundleDigest": self.publication["bundle_digest"], "minimumTrustBundleSequence": 1,
                "rpId": config.WEBAUTHN_RP_ID, "origins": [config.WEBAUTHN_ORIGIN],
                "requireUserPresence": True, "requireUserVerification": True,
                "counterPolicy": "strict", "maxAssertionAgeSeconds": 30}}
        self.policy_digest = framed(self.policy["schema"], canonical(self.policy))
        self.policy_hash = sha(b"synthetic current policy")
        self.data["credentials"] = [row("credentials", id="service-credential", name="synthetic",
            kind="static", encrypted_secret="NOT-A-SECRET-CUSTODY-CLAIM", credential_version=1,
            metadata="{}", lifecycle_status="active", created_at=self.stamp, updated_at=self.stamp)]
        self.data["routes"] = [row("routes", id="route", name="synthetic", enabled=1,
            match_host="synthetic.invalid", match_path_prefix="/", credential_id="service-credential",
            injection="{}", policies="[]", created_at=self.stamp, updated_at=self.stamp)]
        self.data["approval_requests"] = [row("approval_requests", id=self.item, route_id="route",
            method="GET", url="https://synthetic.invalid/resource", status="pending", requested_at=self.stamp,
            expires_at=(self.at + timedelta(seconds=120)).isoformat(), principal_id="application",
            credential_id="service-credential", credential_version=1, policy_hash=self.policy_hash,
            request_digest=sha(b"approved application request"), operation_digest=sha(b"approved operation"),
            canonical_request="{}", redacted_display="{}", grant_ttl_seconds=60, grant_max_uses=1,
            approver_policy_json=canonical(self.policy).decode(), approver_policy_digest=self.policy_digest)]
        self.data["policy_high_water"] = [row("policy_high_water", scope="global", policy_id="synthetic",
            sequence=1, rollback_epoch=0, policy_hash=self.policy_hash, updated_at=self.stamp)]
        for number, actor in enumerate(self.actors):
            public = self.keys[number].public_key().public_numbers()
            cose = b64(cbor2.dumps({1: 2, 3: -7, -1: 1,
                -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")}))
            self.data["webauthn_credentials"].append(row("webauthn_credentials", id="hardware-" + str(number),
                credential_id=b64(("synthetic-key-" + str(number)).encode()), user_id=actor,
                label="synthetic ES256, not physical hardware", public_key_cose=cose, sign_count=1,
                authenticator_class="hardware", attestation_trusted=1, attestation_trust_path="[]",
                attestation_trust_bundle_digest=self.publication["bundle_digest"], attestation_trust_bundle_sequence=1,
                transports="[]", created_at=self.stamp, updated_at=self.stamp))
            self.data["rbac_role_bindings"].append(row("rbac_role_bindings", subject_id=actor,
                roles_json='["admin"]', status="active", generation=1,
                binding_digest=sha(canonical({"subject_id": actor, "roles": ["admin"], "status": "active",
                    "generation": 1, "updated_at": self.stamp, "updated_by": "synthetic-admission", "reason": None})),
                updated_at=self.stamp, updated_by="synthetic-admission"))
            self.data["approval_review_receipts"].append(row("approval_review_receipts",
                id="review-" + str(number), approval_request_id=self.item, reviewer_id=actor,
                review_digest=sha(("review-" + str(number)).encode()),
                expires_at=(self.at + timedelta(seconds=120)).isoformat(), created_at=self.stamp))
        # Explicit root-admission boundary, NOT a generated/authenticated tree
        # or independently witnessed RBAC state. The actual consumer validates
        # the canonical state and each binding; no successful check is mocked.
        root = {"table": "rbac_role_bindings", "rootRevision": 1,
            "rootDigest": sha(b"synthetic admitted RBAC root"), "leafCount": 2}
        manifest = sha(b"synthetic admitted RBAC manifest")
        self.data["policy_authority_authenticated_table_roots"] = [row(
            "policy_authority_authenticated_table_roots", table_name="rbac_role_bindings", root_revision=1,
            root_digest=root["rootDigest"], leaf_count=2, tree_depth=64, tree_radix=16,
            manifest_digest=manifest, updated_at_epoch_ns=self.now)]
        self.data["rbac_authority_state"] = [row("rbac_authority_state", authority_id=1, generation=1,
            state_digest=rbac.state_digest(rbac.state_material(1, root, manifest)), binding_table_revision=0,
            verified_binding_table_revision=0, updated_at=self.stamp)]

    def sign(self, number=0):
        credential = next(value for value in self.data["webauthn_credentials"]
            if value["id"] == "hardware-" + str(number))
        review = next(value for value in self.data["approval_review_receipts"]
            if value["id"] == "review-" + str(number))
        args = dict(item_id=self.item, ttl_seconds=60, note="synthetic component approval",
            actor_id=self.actors[number], authn=None, challenge_id=str(uuid.uuid4()),
            review_receipt_id=review["id"], review_digest=review["review_digest"], require_review_receipt=True,
            required_approver_roles={"$authorityType": "set", "items": ["admin"]},
            allowed_approver_ids={"$authorityType": "set", "items": list(self.actors)},
            authority_policy_hash=self.policy_hash, authority_route_id="route", require_approver_webauthn=True,
            approval_threshold=self.policy["threshold"], approver_credential_policy=self.policy["credentialPolicy"])
        request = service._controlled_writer_request_digest("jit.decide", args)
        operation_id = framed("serverware.policyAuthorityOperation/v2", b"jit.decide", request.encode())
        payload = {"schema": "serverware.policyAuthorityWebAuthnChallenge/v1", "operationId": operation_id,
            "rpId": config.WEBAUTHN_RP_ID, "origin": config.WEBAUTHN_ORIGIN,
            "issuedAtEpochNs": self.now - 1_000_000_000, "expiresAtEpochNs": self.now + 25_000_000_000,
            "credentialId": credential["credential_id"]}
        challenge = row("webauthn_challenges", id=args["challenge_id"], challenge=b64(uuid.uuid4().bytes * 2),
            challenge_type="policy_authority", user_id=args["actor_id"], scope_key=operation_id,
            approval_request_id=self.item, payload_json=canonical(payload).decode(),
            expires_at=(self.at + timedelta(seconds=25)).isoformat(), created_at=self.stamp,
            retention_reference_mask=0)
        self.data["webauthn_challenges"].append(challenge)
        original_challenge = {key: challenge[key] for key in jit.CHALLENGE_FIELDS}
        public_challenge = {**payload, "challengeId": challenge["id"], "challenge": challenge["challenge"],
            "challengeRowDigest": framed("serverware.policyAuthorityWebAuthnChallengeRow/v1", canonical(original_challenge))}
        binding = {key: credential[key] for key in jit.CREDENTIAL_FIELDS}
        policy_digest = framed("serverware.policyAuthorityCredentialPolicy/v1",
            canonical(trust.credential_policy_document(binding, self.high)))
        public_credential = actual_credential_projection(binding, policy_digest, self.trust_digest)
        client = canonical({"type": "webauthn.get", "challenge": challenge["challenge"],
            "origin": config.WEBAUTHN_ORIGIN, "crossOrigin": False})
        auth = hashlib.sha256(config.WEBAUTHN_RP_ID.encode()).digest() + b"\x05" + (
            credential["sign_count"] + 1).to_bytes(4, "big")
        normalized = {"credentialId": credential["credential_id"], "clientDataJSON": b64(client),
            "authenticatorData": b64(auth), "signature": b64(self.keys[number].sign(
                auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())))}
        args["authn"] = {"credential_id": credential["credential_id"], "assertion": {
            "id": credential["credential_id"], "rawId": credential["credential_id"], "type": "public-key",
            "response": {key: normalized[key] for key in ("clientDataJSON", "authenticatorData", "signature")}}}
        if service._controlled_writer_request_digest("jit.decide", args) != request:
            raise ValueError("original facade request digest changed")
        process = object.__new__(service.AuthorityProcess)
        process.signing_key = Ed25519PrivateKey.generate()
        process.configuration = service.MeasuredConfiguration(payload={"webauthn": {
            "rpId": config.WEBAUTHN_RP_ID, "origin": config.WEBAUTHN_ORIGIN,
            "maximumChallengeAgeNs": 30_000_000_000, "allowedAuthenticatorClasses": ["hardware"],
            "requireAttestationTrusted": True}}, digest=sha(b"synthetic trust config"),
            root_key=process.signing_key.public_key())
        process.role_config = {"measurementDigest": sha(b"synthetic measurement"),
            "attestationReceiptDigest": sha(b"synthetic verifier admission")}
        cap_id = sha(uuid.uuid4().bytes)
        with patch.object(process, "_read_webauthn_authority", return_value=(
                public_challenge, public_credential, normalized)), patch.object(service.time, "time_ns", return_value=self.now):
            evidence, receipt, receipt_digest = process._build_v9_webauthn_evidence(
                operation="jit.decide", operation_id=operation_id, request_digest=request, capability_id=cap_id,
                authorization_reference=process._webauthn_reference_from_arguments(args),
                deadline_epoch_ns=self.now + 20_000_000_000, arguments=args)
        verified = verifier._verify_operation_assertion_evidence(evidence, operation="jit.decide",
            operation_id=operation_id, request_digest=request, capability_id=cap_id,
            verifier_identity={"sessionIdentityDigest": evidence["verifierSessionIdentityDigest"],
                **process.role_config}, verifier_public_key=process.signing_key.public_key(),
            now_epoch_ns=self.now, deadline_epoch_ns=self.now + 20_000_000_000,
            maximum_age_ns=30_000_000_000, work=None)
        return dict(arguments=service._synthesize_business_arguments("jit.decide", args), request=request,
            operation_id=operation_id, capability_id=cap_id, evidence=dict(verified), receipt=receipt,
            receipt_digest=receipt_digest, evidence_row=authorization_records._assertion_storage_row(evidence),
            challenge=challenge, credential=credential)

    def context(self, signed, fetch=None):
        kernel = jit.JitDecideKernel()
        queries = kernel.queries_with_evidence(arguments=signed["arguments"], database_now=self.at,
            request_digest=signed["request"], evidence=signed["evidence"])
        union, records = {}, []
        for query in queries:
            resolved = reads.resolve_query("jit.decide", query, prior_reads=tuple(records),
                selected_rows=tuple(union.values()))
            if fetch is None:
                if any(p.operator != "eq" for p in resolved.predicates):
                    raise ValueError("fixture only interprets exact source equalities")
                actual = [copy.deepcopy(value) for value in self.data[resolved.table]
                    if all(value[p.column] == p.value for p in resolved.predicates)]
                for order in reversed(resolved.order_by):
                    actual.sort(key=lambda item: item[order.column], reverse=order.descending)
                actual = actual[:resolved.maximum_rows]
            else:
                actual = fetch(resolved)
            observations = [selected(resolved.table, value) for value in actual]
            if not actual and resolved.absent_key is not None:
                observations = [selected(resolved.table, key=dict(resolved.absent_key))]
            for observation in observations:
                address = (observation["table"], observation["keyDigest"])
                if address in union and union[address] != observation:
                    raise ValueError("query observations conflict")
                union[address] = observation
            records.append(reads.capture_query_read("jit.decide", query, resolved_query=resolved,
                ordered_selected_rows=tuple(observations), returned_row_count=len(actual)))
        reads.validate_query_reads("jit.decide", queries=queries, query_reads=tuple(records),
            selected_rows=tuple(union.values()))
        return core.KernelContext("jit.decide", signed["arguments"], tuple(union.values()),
            self.at, signed["request"], signed["evidence"], tuple(records))


class JitApprovalPureTests(unittest.TestCase):
    def test_exact_database_nanoseconds_preserve_offsets_and_pre_epoch_instants(self):
        from datetime import tzinfo

        class NoOffset(tzinfo):
            def utcoffset(self, value):
                return None

        vectors = (
            (datetime(1970, 1, 1, tzinfo=timezone.utc), 0),
            (datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc), -1000),
            (datetime(2026, 10, 13, 12, 0, 0, 1, tzinfo=timezone.utc), 1791892800000001000),
            (datetime(2026, 10, 13, 12, 0, 0, 1000, tzinfo=timezone.utc), 1791892800001000000),
            (datetime(2026, 10, 13, 17, 30, 0, 1000,
                tzinfo=timezone(timedelta(hours=5, minutes=30))), 1791892800001000000),
        )
        for observed, expected in vectors:
            with self.subTest(observed=observed.isoformat()):
                self.assertEqual(core._epoch_nanoseconds(observed), expected)
                self.assertEqual(core._epoch_nanoseconds(observed), jit.shared._database_epoch_ns(observed))
        for observed in (datetime(2026, 10, 13), datetime(2026, 10, 13, tzinfo=NoOffset())):
            with self.subTest(naive=observed.tzinfo is None), self.assertRaises(core.TransitionKernelError):
                core._epoch_nanoseconds(observed)

    def test_actual_jit_aggregate_same_clock_accepts_but_future_nanosecond_and_microsecond_refuse(self):
        # Fixed admitted row inputs, not a clock mock or an authorization proof.
        # The former float bound rounded the first instant up24ns and second
        # down64ns. Exercise actual first-vote and second-vote producers alike.
        item_id = "fixed-aggregate-timestamp-component"
        aggregate_id, partition = jit.shared._aggregate_key("jit-approval-decisions", item_id)
        missing = selected(AGGREGATE, key={"aggregate_id": aggregate_id})
        for microseconds, expected in ((1, 1791892800000001000), (1000, 1791892800001000000)):
            now = datetime(2026, 10, 13, 12, 0, 0, microseconds, tzinfo=timezone.utc)

            def context(value):
                return core.KernelContext("jit.decide", {}, (value,), now, sha(b"fixed aggregate request"))

            def consume(value):
                return context(selected(AGGREGATE, value)).bounded_aggregate(aggregate_id=aggregate_id,
                    aggregate_kind="jit-approval-decisions", partition_digest=partition)

            with self.subTest(microseconds=microseconds):
                first = jit._add_vote(context(missing), item_id, missing)
                first_row = first["row"]
                self.assertEqual(first_row["updated_at_epoch_ns"], expected)
                self.assertEqual(consume(first_row), first_row)
                retained = selected(AGGREGATE, first_row)
                second = jit._add_vote(context(retained), item_id, retained)
                second_row = second["row"]
                self.assertEqual(second_row["updated_at_epoch_ns"], expected)
                self.assertEqual((second_row["live_count"], second_row["active_count"]), (2, 2))
                self.assertEqual(consume(second_row), second_row)
                for ahead in (1, 1000):
                    # updated_at is a separately checked row field, not part
                    # of the aggregate state material; keep its valid digest.
                    future = {**second_row, "updated_at_epoch_ns": expected + ahead}
                    self.assertEqual(core._aggregate_state_material(future, reserved_units={}, committed_units={}),
                        json.loads(future["state_json"]))
                    with self.subTest(ahead_ns=ahead), self.assertRaisesRegex(core.TransitionKernelError,
                            "bounded aggregate state is not authoritative"):
                        consume(future)

    def test_genuine_producer_originals_and_cold_facade_kernel(self):
        fixture = Fixture()
        signed = fixture.sign()
        self.assertEqual(jit.raw_receipt_from_originals(signed["evidence"],
            signed["challenge"], signed["credential"]), (signed["receipt"], signed["receipt_digest"]))
        self.assertNotEqual(signed["receipt_digest"], signed["evidence"]["verifiedAssertionReceiptDigest"])
        context = fixture.context(signed)
        result = jit.JitDecideKernel().transition(context)
        self.assertEqual(result.result["status"], "approved")
        self.assertEqual(result.result["approver_policy"], fixture.policy)
        self.assertEqual(result.result["decision_count"], 1)
        self.assertFalse(result.result["idempotent_replay"])
        self.assertTrue(context.query_reads)
        inserted = {item["table"] for item in result.mutations if item["operation"] == "INSERT"}
        self.assertTrue({"approval_grants", "approval_request_decisions", AGGREGATE} <= inserted)
        self.assertFalse(fixture.data[HISTORY])
        self.assertFalse(fixture.data[AGGREGATE])
        domain = b"serverware.policyAuthorityWebAuthnCredentialBinding/v1"
        original = canonical({key: signed["credential"][key] for key in jit.CREDENTIAL_FIELDS})
        self.assertEqual(signed["receipt"]["credentialBindingDigest"], sha(
            len(domain).to_bytes(8, "big") + domain + len(original).to_bytes(8, "big") + original))

    def test_current_policy_counter_trust_review_and_raw_input_refuse(self):
        fixture = Fixture()
        signed = fixture.sign()
        changes = (("webauthn_credentials", "sign_count", 2),
            ("webauthn_credentials", "revoked_at", fixture.stamp),
            ("webauthn_challenges", "used_at", fixture.stamp),
            ("approval_review_receipts", "used_at", fixture.stamp),
            ("approval_requests", "expires_at", fixture.stamp),
            ("policy_high_water", "policy_hash", sha(b"changed policy")),
            ("webauthn_trust_publications", "withdrawn_credential_ids_json", '["hardware-0"]'),
            ("rbac_role_bindings", "status", "deprovisioned"))
        for table, field, value in changes:
            with self.subTest(table=table, field=field), patch.dict(fixture.data[table][0], {field: value}), \
                    self.assertRaises(core.TransitionKernelError):
                jit.JitDecideKernel().transition(fixture.context(signed))
        for field, value in (("approval_threshold", 2), ("authority_route_id", "other-route"),
                ("review_digest", sha(b"wrong review"))):
            altered = {**signed, "arguments": {**signed["arguments"], field: value}}
            with self.subTest(field=field), self.assertRaises(core.TransitionKernelError):
                jit.JitDecideKernel().transition(fixture.context(altered))

    def test_aggregate_insert_contract_is_narrow_and_fresh_cas_is_actual_source(self):
        def kinds(operation):
            return {item["mutation"] for item in contract.operation_spec(operation)["mutationTemplates"]
                if item["table"] == AGGREGATE}
        self.assertEqual(kinds("jit.decide"), {"INSERT", "UPDATE"})
        self.assertEqual(kinds("jit.deny"), {"UPDATE"})
        self.assertEqual(kinds("webauthn.credential.revoke"), {"UPDATE"})
        guard = fresh_assertion_cas_sql('"component"')
        self.assertIn(challenge_original_sql(), guard)
        self.assertIn("serverware_policy_authority_framed_digest", guard)
        self.assertIn("authority v9 WebAuthn CAS mutations are incomplete", guard)


class JitApprovalPostgresTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        from psycopg.rows import dict_row
        self.db = psycopg.connect(**PARAMETERS, autocommit=True, row_factory=dict_row)
        self.db.isolation_level = psycopg.IsolationLevel.SERIALIZABLE
        self.addCleanup(self.db.close)
        facts = self.db.execute("SELECT current_setting('server_version_num')::int AS version, inet_server_addr() AS address").fetchone()
        self.assertIn(facts["version"] // 10000, (16, 17))
        self.assertIsNone(facts["address"])
        self.schema = "jit_component_" + uuid.uuid4().hex
        self.ns = '"' + self.schema + '"'
        self.db.execute(f"CREATE SCHEMA {self.ns}")
        self.addCleanup(self.db.execute, f"DROP SCHEMA {self.ns} CASCADE")
        self.db.execute(f"SET search_path = {self.ns}, pg_catalog")
        for table in TABLES:
            self.db.execute(table_ddl(table))
        for definition in optional._actual_helpers(namespace=self.ns):
            self.db.execute(definition)
        self.db.execute(framed_digest_function_sql(self.ns))
        declarations = """key_predicate text; update_columns text; current_row jsonb; post_row jsonb;
            key_names text[]; supplied_key_names text[]; matched_count bigint;"""
        self.db.execute(f"""CREATE FUNCTION {self.ns}.apply_one(mutation jsonb,key_columns jsonb)
            RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $body$
            DECLARE {declarations} BEGIN
            IF NOT {closed_record_sql('mutation')} THEN RAISE EXCEPTION 'closed mutation'; END IF;
            {apply_mutation_sql(self.ns)} END; $body$""")
        guard, _ = optional._guard_parts(namespace=self.ns)
        self.db.execute(f"""CREATE FUNCTION {self.ns}.admit_components(cap_id text, rows_json text,
            mutations_json text, evidence_digest text, trust_digest text, started bigint, replay boolean DEFAULT false)
            RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $body$
            DECLARE capability record; planner record; trust_publication record; trust_high_water record;
                assertion_evidence record; assertion_requirements jsonb := '{{"jit.decide":true}}'::jsonb;
                authorization_projection record; computed_trust_high_water_digest text := trust_digest;
                now_epoch_ns bigint := started;
            BEGIN
                SELECT * INTO STRICT capability FROM {self.ns}.{CAPABILITIES} WHERE capability_id=cap_id FOR UPDATE;
                SELECT rows_json AS selected_business_rows_json, mutations_json AS mutation_plan_json INTO planner;
                {locked_webauthn_trust_projection(self.ns)}
                SELECT * INTO STRICT assertion_evidence FROM {self.ns}.{EVIDENCE} WHERE capability_id=cap_id;
                SELECT evidence_digest AS assertion_evidence_digest INTO authorization_projection;
                {guard}
                IF replay THEN {assert_webauthn_receipt_history_sql(self.ns)}
                ELSE {fresh_assertion_cas_sql(self.ns)} {assert_prior_jit_decisions_sql(self.ns)}
                    {retain_webauthn_receipt_sql(self.ns)} END IF;
            END; $body$""")
        self.db.execute(f"""CREATE FUNCTION {self.ns}.history_only(cap_id text, retain boolean DEFAULT false)
            RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $body$
            DECLARE capability record;
            BEGIN SELECT * INTO STRICT capability FROM {self.ns}.{CAPABILITIES} WHERE capability_id=cap_id;
                IF retain THEN {retain_webauthn_receipt_sql(self.ns)}
                ELSE {assert_webauthn_receipt_history_sql(self.ns)} END IF;
            END; $body$""")

    def insert(self, table, value):
        from psycopg import sql
        self.db.execute(sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(sql.Identifier(table),
            sql.SQL(",").join(map(sql.Identifier, value)),
            sql.SQL(",").join(sql.Placeholder() for _ in value)), tuple(value.values()))

    def seed(self, fixture):
        for table in TABLES:
            for value in fixture.data[table]:
                self.insert(table, value)

    def fetch(self, query):
        from psycopg import sql
        self.assertTrue(all(p.operator == "eq" for p in query.predicates))
        terms = [sql.SQL("{} = %s").format(sql.Identifier(p.column)) for p in query.predicates]
        orders = [sql.SQL("{} {}").format(sql.Identifier(p.column),
            sql.SQL("DESC" if p.descending else "ASC")) for p in query.order_by]
        statement = sql.SQL("SELECT * FROM {} WHERE {} ORDER BY {} LIMIT %s").format(
            sql.Identifier(query.table), sql.SQL(" AND ").join(terms), sql.SQL(",").join(orders))
        return self.db.execute(statement, tuple(p.value for p in query.predicates) + (query.maximum_rows,)).fetchall()

    def capability(self, fixture, signed, result):
        value = row(CAPABILITIES)
        for name in value:
            if name.endswith("_digest") or name in ("capability_id", "envelope_id", "planner_transaction_id"):
                value[name] = sha((name + signed["capability_id"]).encode())
        value.update(capability_id=signed["capability_id"], capability_protocol="v3", capability_record_digest=None,
            operation="jit.decide", operation_id=signed["operation_id"], handler_name="approve_request",
            request_digest=signed["request"], approver_policy_digest=policies.from_jit_policy(fixture.policy),
            webauthn_receipt_json=canonical(signed["receipt"]).decode(), webauthn_receipt_digest=signed["receipt_digest"],
            webauthn_trust_high_water_digest=fixture.trust_digest, witness_sequence=1, fence=1,
            issued_monotonic_ns=1, deadline_monotonic_ns=20_000_000_001, issued_at_epoch_ns=fixture.now,
            expires_at_epoch_ns=fixture.now + 20_000_000_000, deadline_epoch_ns=fixture.now + 20_000_000_000,
            status="reserved", reserved_at_epoch_ns=fixture.now, reserved_transaction_id=1,
            result_digest=None, commit_receipt_digest=None, committed_at_epoch_ns=None,
            failure_digest=None, failed_at_epoch_ns=None,
            expected_result_digest=framed("serverware.policyAuthorityControlledWriterResult/v2", canonical(result)))
        return value

    def commit(self, fixture, signed, *, selected_override=None, before_apply=None, after_complete=None):
        from psycopg.types.json import Jsonb
        with self.db.transaction():
            context = fixture.context(signed, self.fetch)
            transition = jit.JitDecideKernel().transition(context)
            cap = self.capability(fixture, signed, transition.result)
            self.insert(CAPABILITIES, cap)
            self.insert(EVIDENCE, signed["evidence_row"])
            self.db.execute(f"SELECT {self.ns}.admit_components(%s,%s,%s,%s,%s,%s)", (
                cap["capability_id"], canonical(context.selected_rows if selected_override is None
                    else selected_override(context.selected_rows)).decode(), canonical(transition.mutations).decode(),
                signed["evidence_row"]["assertion_evidence_digest"], fixture.trust_digest, fixture.now))
            if before_apply is not None:
                before_apply()
            # Same business ordering as v9. No constraints are deferred.
            for mutation in sorted(transition.mutations,
                    key=lambda value: (value["table"], value["keyDigest"], value["operation"])):
                self.db.execute(f"SELECT {self.ns}.apply_one(%s,%s)",
                    (Jsonb(mutation), Jsonb(list(PRIMARY_KEY_COLUMNS[mutation["table"]]))))
            # Explicit admitted framework-completion boundary; not a signed
            # witness, root update, or full v9 writer execution claim.
            self.complete(cap, transition.result, fixture.now + 1)
            if after_complete is not None:
                after_complete()
        return transition

    def inventory(self):
        return {table: sorted(self.db.execute(f'SELECT * FROM "{table}"').fetchall(), key=canonical)
            for table in TABLES}

    def next_signature(self, fixture, number):
        fixture.data = self.inventory()
        signed = fixture.sign(number)
        self.insert("webauthn_challenges", signed["challenge"])
        return signed

    def grant_reason(self, fixture):
        from serverware import db
        grant = self.db.execute("SELECT * FROM approval_grants").fetchone()
        return db._release_grant_authority_reason(db.PostgresMetadataConnection(self.db), grant,
            now_epoch_ms=fixture.now // 1_000_000 + 1, required_approver_roles={"admin"},
            allowed_approver_ids=set(fixture.actors), require_approver_webauthn=True, reserved_attempt_id=None,
            approval_threshold=fixture.policy["threshold"], approver_credential_policy=fixture.policy["credentialPolicy"])

    def complete(self, cap, result, when):
        result_digest = framed("serverware.policyAuthorityControlledWriterResult/v2", canonical(result))
        receipt = {"schema": "serverware.policyAuthorityWriterCommitReceipt/v2",
            "capabilityId": cap["capability_id"], "envelopeId": cap["envelope_id"],
            "plannerTransactionId": cap["planner_transaction_id"],
            "authorizationProjectionDigest": cap["authorization_projection_digest"],
            "operation": cap["operation"], "handlerName": cap["handler_name"],
            "requestDigest": cap["request_digest"], "resultDigest": result_digest,
            "authorityRootSetBeforeDigest": cap["authority_root_set_digest"],
            "authorityRootSetAfterDigest": cap["authority_root_set_digest"],
            "authoritySnapshotDigest": cap["authority_snapshot_digest"],
            "operationManifestDigest": cap["operation_manifest_digest"], "queryManifestDigest": cap["query_manifest_digest"],
            "witnessReservationDigest": cap["witness_reservation_digest"], "witnessSequence": cap["witness_sequence"],
            "deadlineMonotonicNs": cap["deadline_monotonic_ns"], "fence": cap["fence"],
            "committedAtEpochNs": when, "sourceRevision": contract.SOURCE_REVISION}
        digest = framed(receipt["schema"], canonical(receipt))
        writer = {name: cap[name] for name in ("capability_id", "envelope_id", "operation", "handler_name",
            "request_digest", "operation_manifest_digest", "query_manifest_digest", "witness_reservation_digest",
            "witness_sequence", "deadline_monotonic_ns", "fence")}
        writer.update(commit_receipt_digest=digest, result_json=canonical(result).decode(), result_digest=result_digest,
            authority_root_set_before_digest=cap["authority_root_set_digest"],
            authority_root_set_after_digest=cap["authority_root_set_digest"], committed_at_epoch_ns=when,
            source_revision=contract.SOURCE_REVISION)
        self.insert(WRITERS, writer)
        self.db.execute(f"UPDATE {CAPABILITIES} SET status='committed',result_digest=%s,"
            "commit_receipt_digest=%s,committed_at_epoch_ns=%s WHERE capability_id=%s",
            (result_digest, digest, when, cap["capability_id"]))

    def test_cold_approval_production_sql_immediate_fk_and_actual_grant_consumer(self):
        from serverware import db
        fixture = Fixture()
        signed = fixture.sign()
        self.seed(fixture)
        constraints = self.db.execute("SELECT condeferrable, condeferred FROM pg_constraint "
            "WHERE conrelid='approval_request_decisions'::regclass AND confrelid=%s::regclass AND contype='f'",
            (HISTORY,)).fetchall()
        self.assertEqual(constraints, [{"condeferrable": False, "condeferred": False}])
        self.assertEqual(self.db.execute(f"SELECT count(*) AS n FROM {HISTORY}").fetchone()["n"], 0)
        self.assertEqual(self.db.execute(f"SELECT count(*) AS n FROM {AGGREGATE}").fetchone()["n"], 0)
        outcome = self.commit(fixture, signed)
        self.assertEqual(outcome.result["status"], "approved")
        self.assertEqual(outcome.result["approver_policy"], fixture.policy)
        for name in db._APPROVAL_PUBLIC_FIELDS:
            self.assertIn(name, outcome.result)
        history = self.db.execute(f"SELECT * FROM {HISTORY}").fetchone()
        self.assertEqual(history["receipt_json"], canonical(signed["receipt"]).decode())
        self.assertEqual(history["assertion_receipt_digest"], signed["receipt_digest"])
        self.assertIsNone(self.grant_reason(fixture))

    def test_threshold_two_distinct_actual_votes_then_replay_never_renews(self):
        fixture = Fixture(threshold=2)
        first = fixture.sign()
        self.seed(fixture)
        outcome = self.commit(fixture, first)
        self.assertEqual((outcome.result["status"], outcome.result["decision_count"]), ("pending", 1))
        self.assertEqual(self.db.execute("SELECT count(*) AS n FROM approval_grants").fetchone()["n"], 0)
        second = self.next_signature(fixture, 1)
        outcome = self.commit(fixture, second)
        self.assertEqual((outcome.result["status"], outcome.result["decision_count"]), ("approved", 2))
        self.assertIsNone(self.grant_reason(fixture))
        before = self.inventory()
        for signed in (first, second):
            replay = jit.JitDecideKernel().transition(fixture.context(signed, self.fetch))
            self.assertTrue(replay.result["idempotent_replay"])
            self.assertEqual(replay.mutations, ())
            self.assertEqual(replay.result["decision_count"], 2)
            self.db.execute(f"SELECT {self.ns}.history_only(%s)", (signed["capability_id"],))
        self.assertEqual(self.inventory(), before)
        # A fresh capability/assertion is not a same-operation retry and cannot
        # reuse this actor's vote or extend its existing grant.
        changed = self.next_signature(fixture, 0)
        with self.assertRaises(core.TransitionKernelError):
            jit.JitDecideKernel().transition(fixture.context(changed, self.fetch))
        self.assertEqual(self.db.execute("SELECT expires_at FROM approval_grants").fetchone()["expires_at"],
            before["approval_grants"][0]["expires_at"])

    def test_full_retention_cas_and_late_failure_roll_back_history_and_completion(self):
        import psycopg
        fixture = Fixture()
        signed = fixture.sign()
        self.seed(fixture)
        before = self.inventory()

        def drift_retention():
            # A valid full-row change outside the original10 commitment. It
            # must still fail the actual full17 expectedRow mutation CAS.
            self.db.execute("UPDATE webauthn_challenges SET retention_jit_receipt_digest=%s,"
                "retention_jit_row_digest=%s,retention_reference_mask=2 WHERE id=%s",
                (sha(b"other retained receipt"), sha(b"other retained row"), signed["challenge"]["id"]))

        with self.assertRaisesRegex(psycopg.errors.RaiseException, "CAS precondition changed"):
            self.commit(fixture, signed, before_apply=drift_retention)
        self.assertEqual(self.inventory(), before)
        marker = RuntimeError("synthetic post-completion transaction cancellation")

        def cancel():
            raise marker

        with self.assertRaises(RuntimeError) as caught:
            self.commit(fixture, signed, after_complete=cancel)
        self.assertIs(caught.exception, marker)
        self.assertEqual(self.inventory(), before)
        self.assertEqual(self.commit(fixture, signed).result["status"], "approved")

    def test_prior_voter_omission_foreign_currentness_and_writer_tampering_refuse(self):
        import psycopg
        fixture = Fixture(threshold=2)
        first = fixture.sign()
        self.seed(fixture)
        self.commit(fixture, first)
        second = self.next_signature(fixture, 1)
        before = self.inventory()
        for mode in ("omit", "foreign"):
            def altered(rows):
                result = copy.deepcopy(list(rows))
                if mode == "omit":
                    return [item for item in result if not (item["table"] == "approval_request_decisions"
                        and item["present"])]
                for item in result:
                    if item["table"] == "approval_request_decisions" and item["present"]:
                        item["row"]["approval_request_id"] = "foreign-approval"
                return result
            with self.subTest(mode=mode), self.assertRaisesRegex(psycopg.errors.RaiseException, "prior voter partition changed"):
                self.commit(fixture, second, selected_override=altered)
            self.assertEqual(self.inventory(), before)
        controls = (
            ("UPDATE webauthn_credentials SET revoked_at=%s WHERE id='hardware-0'", (fixture.stamp,)),
            ("UPDATE webauthn_credentials SET sign_count=0 WHERE id='hardware-0'", ()),
            ("UPDATE rbac_role_bindings SET status='deprovisioned' WHERE subject_id=%s", (fixture.actors[0],)),
            ("UPDATE webauthn_trust_publications SET withdrawn_credential_ids_json='[\"hardware-0\"]'", ()),
            (f"UPDATE {CAPABILITIES} SET approver_policy_digest=%s WHERE capability_id=%s",
                (fixture.policy_digest, first["capability_id"])),
            (f"UPDATE {WRITERS} SET result_json='{{}}' WHERE capability_id=%s", (first["capability_id"],)),
        )
        for sql, parameters in controls:
            with self.subTest(sql=sql):
                # Outer rollback restores the deliberately corrupted retained
                # state; the inner actual commit owns its own failed savepoint.
                with self.db.transaction(force_rollback=True):
                    self.db.execute(sql, parameters)
                    with self.assertRaises(psycopg.Error):
                        self.commit(fixture, second)
                self.assertEqual(self.inventory(), before)
        self.assertEqual(self.commit(fixture, second).result["decision_count"], 2)

    def test_history_idempotence_conflict_and_committed_replay_never_backfills(self):
        import psycopg
        fixture = Fixture()
        signed = fixture.sign()
        self.seed(fixture)
        self.commit(fixture, signed)
        before = self.inventory()
        for _ in range(2):
            self.db.execute(f"SELECT {self.ns}.history_only(%s,true)", (signed["capability_id"],))
            self.db.execute(f"SELECT {self.ns}.history_only(%s)", (signed["capability_id"],))
        self.assertEqual(self.inventory(), before)
        with self.db.transaction(force_rollback=True):
            self.db.execute(f"UPDATE {HISTORY} SET signature_digest=%s", (sha(b"altered retained receipt"),))
            for retain in (False, True):
                with self.db.transaction(force_rollback=True):
                    with self.assertRaises(psycopg.errors.RaiseException):
                        # Separate nested transaction leaves the outer negative
                        # fixture usable after PostgreSQL aborts this statement.
                        with self.db.transaction():
                            self.db.execute(f"SELECT {self.ns}.history_only(%s,%s)", (signed["capability_id"], retain))
        self.assertEqual(self.inventory(), before)
        with self.db.transaction(force_rollback=True):
            # Respect the real FK: remove the dependent decision before making
            # the historical row absent. Replay must refuse, not repair it.
            self.db.execute("DELETE FROM approval_request_decisions")
            self.db.execute(f"DELETE FROM {HISTORY}")
            with self.assertRaises(psycopg.errors.RaiseException):
                with self.db.transaction():
                    self.db.execute(f"SELECT {self.ns}.history_only(%s)", (signed["capability_id"],))
            self.assertEqual(self.db.execute(f"SELECT count(*) AS n FROM {HISTORY}").fetchone()["n"], 0)
        self.assertEqual(self.inventory(), before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-dsn")
    args = parser.parse_args()
    global PARAMETERS
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(JitApprovalPureTests)
    if args.postgres_dsn:
        from scripts.test_webauthn_trust_projection_postgres import local_connection_parameters
        PARAMETERS = local_connection_parameters(args.postgres_dsn)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(JitApprovalPostgresTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

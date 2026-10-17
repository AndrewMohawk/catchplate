#!/usr/bin/env python3
"""Independent source-recipe parity for cutoff-native revocation queries.

The actual candidate, complete-role binder, source closure and framework-query
composer run here. Literal query documents and independently derived audit IDs
provide the expected program; instrumentation delegates actual code and SHA.
These unrun fixtures establish no assertion signature, current root, trusted
time, complete SQL population, kernel authorization or registry activation.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_complete_query as complete
from catchplate import authority_contract
from catchplate import authority_transition_core as core
from catchplate import authority_transition_webauthn as candidate
import test_authority_complete_query as complete_oracle


OPERATION = "webauthn.credential.revoke"
REQUEST_DIGEST = "sha256:" + "6" * 64
NOW = datetime(1970, 1, 1, 0, 0, 1, 7, tzinfo=timezone.utc)
CUTOFF_US = 1_000_007
HINTS = ("oidc_session_ids", "approval_grant_ids", "control_plane_approval_ids", "registration_challenge_ids")


def wire(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def source_values(**changes):
    values = complete_oracle.arguments()
    values["audit_event"] = {"credential_record_id": values["record_id"], "note": "audit-雪"}
    values.update(copy.deepcopy(changes))
    return values


def arguments(values):
    owned = copy.deepcopy(values)
    return {**owned, "businessIntent": {
        "schema": "catchplate.policyAuthorityBusinessIntent/v2", "operation": OPERATION,
        "planningAdapterId": "catchplate.policyAuthorityPlanningAdapter/revoke_webauthn_credential/v1",
        "arguments": copy.deepcopy(owned),
    }}


def audit_identity(request_digest, subject):
    label = "credential" if subject is None else "approval:" + subject
    subject_hash = hashlib.sha256(label.encode("utf-8")).hexdigest()
    material = {"schema": "catchplate.policyAuthorityDeterministicIdentity/v1",
        "operation": OPERATION, "requestDigest": request_digest,
        "purpose": "webauthn-revocation-audit:" + subject_hash}
    digits = list(hashlib.sha256(wire(material)).hexdigest()[:32])
    digits[12] = "5"
    digits[16] = "89ab"[int(digits[16], 16) & 3]
    value = "".join(digits)
    return "-".join((value[:8], value[8:12], value[12:16], value[16:20], value[20:]))


def counter_identity():
    domain = b"catchplate.metadataAuditOutboxCapacityPartition/v1\0"
    partition = "sha256:" + hashlib.sha256(domain + (6).to_bytes(8, "big") + b"global").hexdigest()
    return "metadata-audit-outbox-global-capacity-v1:" + partition


def point_document(name, table, identifier, *, column="id"):
    return {"schema": "catchplate.policyAuthorityQueryProgram/v1",
        "queryId": f"catchplate.policyAuthorityQuery/{OPERATION}/{name}/{table}/v1",
        "table": table, "predicates": [{"column": column, "operator": "eq", "value": identifier}],
        "orderBy": [{"column": column, "descending": False}], "maximumRows": 1,
        "overflowDisposition": "fail-closed", "absentKey": {column: identifier},
        "requireAbsence": False, "proofPrimitive": "primary-key-row", "workUnits": 1,
        "exactPage": False, "pageSize": None, "continuationTokenDigest": None,
        "secondaryIndexName": None}


def trust_query_documents():
    high_water = point_document("webauthn_trust_high_water", "webauthn_trust_publication_high_water",
        "webauthn-metadata", column="authority_scope")
    publication = point_document("webauthn_trust_publication", "webauthn_trust_publications", "unused")
    publication["absentKey"] = None
    publication["predicates"] = [{"column": "scope", "operator": "eq", "value": "global"},
        {"column": "status", "operator": "eq", "value": "published"}]
    publication["predicates"].extend({"column": column, "operator": "eq", "value": {
        "schema": "catchplate.policyAuthoritySelectedRowField/v1",
        "table": "webauthn_trust_publication_high_water", "key": {"authority_scope": "webauthn-metadata"},
        "column": source}} for column, source in (
            ("bundle_digest", "publication_digest"), ("payload_digest", "metadata_blob_digest"),
            ("rollback_epoch", "rollback_epoch"), ("sequence", "publication_sequence")))
    return high_water, publication


def resolved_trust_document(document, high_water):
    """Independent four-field source reference resolution, never JSON parsing."""
    result = copy.deepcopy(document)
    for predicate in result.get("predicates", ()):
        value = predicate["value"]
        if type(value) is dict and value.get("schema") == "catchplate.policyAuthoritySelectedRowField/v1":
            if (value["table"] != "webauthn_trust_publication_high_water"
                    or value["key"] != {"authority_scope": "webauthn-metadata"}):
                raise AssertionError("fixture reference left its fixed proved high-water row")
            predicate["value"] = high_water[value["column"]]
    return result


def expected_program(values, *, cutoff_us=CUTOFF_US, request_digest=REQUEST_DIGEST,
                     signer=None, challenge="assertion-challenge", evidence=False, framework=False):
    result = [point_document("revoked_credential", "webauthn_credentials", values["record_id"])]
    result.extend(complete_oracle.complete_document(role, values=values, cutoff_us=cutoff_us)
                  for role in complete_oracle.ROLES if role != "pending_trust_publications")
    subjects = [*values["control_plane_approval_ids"]]
    if values["audit_event"] is not None:
        subjects.append(None)
    result.extend(point_document(f"audit_{ordinal}", "metadata_audit_outbox",
        audit_identity(request_digest, subject)) for ordinal, subject in enumerate(subjects))
    if evidence:
        signer = values["record_id"] if signer is None else signer
        if signer != values["record_id"]:
            result.append(point_document("assertion_credential", "webauthn_credentials", signer))
        result.append(point_document("assertion_challenge", "webauthn_challenges", challenge))
        result.extend(trust_query_documents())
        result.append(complete_oracle.complete_document("pending_trust_publications", values=values,
            cutoff_us=cutoff_us))
    if framework:
        result.append(point_document("global_audit_capacity_before_v1",
            "policy_authority_bounded_aggregate_states", counter_identity(), column="aggregate_id"))
    return result


def documents(program):
    return [query.contract_value() for query in program]


class RevocationQueryProgramTests(unittest.TestCase):
    def setUp(self):
        self.kernel = candidate.WebAuthnCredentialRevokeKernel()
        self.values = source_values()

    def full(self, values=None, *, cutoff_us=CUTOFF_US, request_digest=REQUEST_DIGEST,
             signer="separate-signer", challenge="assertion-challenge", **changes):
        values = self.values if values is None else values
        inputs = {"arguments": arguments(values), "cutoff_us": cutoff_us,
            "request_digest": request_digest,
            "evidence": {"credentialRecordId": signer, "challengeId": challenge}}
        inputs.update(changes)
        return self.kernel.queries_with_evidence_at_cutoff(**inputs)

    def assert_program(self, actual, expected):
        self.assertIs(type(actual), tuple)
        self.assertEqual(documents(actual), expected)
        self.assertEqual(wire(documents(actual)), wire(expected))
        self.assertEqual([query.query_id for query in actual], [entry["queryId"] for entry in expected])
        self.assertTrue(all(type(query) is (complete.CompleteIndexQuery
            if entry["schema"] == "catchplate.policyAuthorityCompleteIndexQuery/v1" else core.BoundedQuery)
            for query, entry in zip(actual, expected)))

    def test_cascade_exact_fields_bytes_and_order_match_independent_source_documents(self):
        actual = candidate.cascade_queries_at_cutoff(operation=OPERATION, values=self.values,
            cutoff_us=CUTOFF_US, request_digest=REQUEST_DIGEST)
        self.assert_program(actual, expected_program(self.values))
        self.assertEqual(len(actual), 8)
        self.assertEqual(tuple(query.role for query in actual[1:6]), complete_oracle.ROLES[:-1])

    def test_full_recipe_appends_separate_signer_and_challenge_after_all_audits(self):
        actual = self.full()
        self.assert_program(actual, expected_program(self.values, evidence=True, signer="separate-signer"))
        self.assertEqual(len(actual), 13)
        self.assertEqual([query.table for query in actual[-5:-3]], ["webauthn_credentials", "webauthn_challenges"])
        self.assertEqual([query.table for query in actual[-3:]],
            ["webauthn_trust_publication_high_water", "webauthn_trust_publications", "webauthn_trust_publications"])

    def test_same_signer_reuses_target_query_without_a_duplicate_credential_declaration(self):
        actual = self.full(signer=self.values["record_id"])
        self.assert_program(actual, expected_program(self.values, evidence=True))
        self.assertEqual(len(actual), 12)
        self.assertEqual(sum(query.table == "webauthn_credentials" for query in actual), 1)

    def test_real_capacity_composition_appends_one_exact_framework_query_last(self):
        business = self.full()
        actual = capacity.add_capacity_query(OPERATION, business)
        self.assert_program(actual, expected_program(self.values, evidence=True,
            signer="separate-signer", framework=True))
        self.assertEqual(actual[:-1], business)
        self.assertEqual(actual[-1].absent_key, {"aggregate_id": counter_identity()})
        self.assertEqual(sum(query.maximum_rows for query in actual),
                         sum(query.maximum_rows for query in business) + 1)
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.add_capacity_query(OPERATION, actual)

    def test_datetime_methods_and_cutoff_native_methods_share_identical_programs(self):
        evidence = {"credentialRecordId": "separate-signer", "challengeId": "assertion-challenge"}
        instants = (NOW, NOW.astimezone(timezone(timedelta(hours=5, minutes=30))),
                    NOW.astimezone(timezone(timedelta(hours=-7))))
        for instant in instants:
            with self.subTest(instant=instant):
                cascade = candidate.cascade_queries(operation=OPERATION, values=self.values,
                    database_now=instant, request_digest=REQUEST_DIGEST)
                self.assert_program(cascade, expected_program(self.values))
                ordinary = self.kernel.queries(arguments=arguments(self.values),
                    database_now=instant, request_digest=REQUEST_DIGEST)
                self.assertEqual(ordinary, cascade)
                full = self.kernel.queries_with_evidence(arguments=arguments(self.values),
                    database_now=instant, request_digest=REQUEST_DIGEST, evidence=evidence)
                self.assertEqual(full, self.full())

    def test_datetime_delegation_and_full_recipe_call_genuine_source_preparation_once(self):
        actual_arguments = candidate._arguments
        actual_cascade = candidate.cascade_queries_at_cutoff
        actual_evidence = self.kernel.queries_with_evidence_at_cutoff
        with patch.object(candidate, "_arguments", wraps=actual_arguments) as preparations, \
                patch.object(candidate, "cascade_queries_at_cutoff", wraps=actual_cascade) as cascades, \
                patch.object(self.kernel, "queries_with_evidence_at_cutoff", wraps=actual_evidence) as evidence_calls:
            actual = self.kernel.queries_with_evidence(arguments=arguments(self.values),
                database_now=NOW, request_digest=REQUEST_DIGEST,
                evidence={"credentialRecordId": "separate-signer", "challengeId": "assertion-challenge"})
        self.assertEqual((preparations.call_count, cascades.call_count, evidence_calls.call_count), (1, 1, 1))
        self.assertEqual(evidence_calls.call_args.kwargs["cutoff_us"], CUTOFF_US)
        self.assertEqual(cascades.call_args.kwargs["cutoff_us"], CUTOFF_US)
        self.assert_program(actual, expected_program(self.values, evidence=True, signer="separate-signer"))

    def test_empty_hints_keep_all_five_roles_and_minimum_one_row_allowances(self):
        values = source_values(**{name: [] for name in HINTS}, audit_event=None)
        actual = self.full(values, signer=values["record_id"])
        self.assert_program(actual, expected_program(values, evidence=True))
        self.assertEqual(len(actual), 10)
        self.assertEqual(tuple(query.maximum_rows for query in actual
            if type(query) is complete.CompleteIndexQuery), (1, 1, 1, 1, 1, 1))
        self.assertFalse(any(query.table == "metadata_audit_outbox" for query in actual))

    def test_each_hint_accepts_exactly_32_entries_without_truncation_or_profile_changes(self):
        for name in HINTS:
            values = source_values(**{field: [] for field in HINTS}, audit_event=None)
            values[name] = [f"item-{ordinal:02d}" for ordinal in range(32)]
            with self.subTest(name=name):
                actual = self.full(values)
                self.assert_program(actual, expected_program(values, evidence=True, signer="separate-signer"))
                for query, (_, _, _, hint) in zip(
                        (query for query in actual if type(query) is complete.CompleteIndexQuery),
                        complete_oracle.ROLE_SPECS):
                    self.assertEqual(query.maximum_rows, 32 if hint == name else 1)
                values[name].append("item-32")
                with self.assertRaises(core.TransitionKernelError):
                    self.full(values)
        # Thirty-two approval audits plus the optional credential audit,
        # separate signer/challenge, and actual framework query reach the
        # source recipe's maximum declaration count without expanding bounds.
        values = source_values(**{field: [] for field in HINTS})
        values["control_plane_approval_ids"] = [f"approval-{ordinal:02d}" for ordinal in range(32)]
        maximum = capacity.add_capacity_query(OPERATION, self.full(values))
        self.assertEqual(len(maximum), 45)
        self.assert_program(maximum, expected_program(values, evidence=True,
            signer="separate-signer", framework=True))

    def test_actual_aggregate_mutation_allowance_accepts_136_and_rejects_137(self):
        spec = authority_contract.operation_spec(OPERATION)
        self.assertEqual((spec["maximumBusinessQueryRows"], spec["maximumBusinessMutations"],
                          spec["maximumBusinessWorkUnits"], spec["maximumQueryRows"], spec["maximumMutations"]),
                         (192, 136, 2048, 193, 137))
        values = source_values(oidc_session_ids=[f"session-{n:02d}" for n in range(31)],
            approval_grant_ids=[f"grant-{n:02d}" for n in range(32)],
            control_plane_approval_ids=[f"approval-{n:02d}" for n in range(19)],
            registration_challenge_ids=[f"challenge-{n:02d}" for n in range(31)])
        bound = 3 + 31 + 32 + 2 * 19 + 31 + 1
        self.assertEqual(bound, 136)
        actual = capacity.add_capacity_query(OPERATION, self.full(values))
        self.assert_program(actual, expected_program(values, evidence=True,
            signer="separate-signer", framework=True))
        self.assertLessEqual(sum(query.maximum_rows for query in actual), 193)
        self.assertLessEqual(sum(query.work_units for query in actual), 2050)
        values["registration_challenge_ids"].append("challenge-31")
        with self.assertRaisesRegex(core.TransitionKernelError, "aggregate mutation bound"):
            self.full(values)

    def test_cutoff_native_signed64_boundaries_are_exact_and_do_not_use_datetime_range(self):
        for cutoff in (-(2**63), -1, 0, CUTOFF_US, 2**63 - 1):
            with self.subTest(cutoff=cutoff):
                actual = self.full(cutoff_us=cutoff)
                self.assert_program(actual, expected_program(self.values, cutoff_us=cutoff,
                    evidence=True, signer="separate-signer"))
                self.assertEqual(actual[5].selector(), {"expires_after_us": cutoff})

        class IntegerSubclass(int):
            pass

        for cutoff in (True, False, None, "1000007", 1.0, -(2**63) - 1, 2**63, IntegerSubclass(1)):
            with self.subTest(cutoff=cutoff), self.assertRaises(core.TransitionKernelError):
                self.full(cutoff_us=cutoff)

    def test_datetime_microseconds_epoch_extremes_and_invalid_awareness_are_preserved(self):
        cases = (
            (datetime(1970, 1, 1, tzinfo=timezone.utc), 0),
            (datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc), -1),
            (datetime(1, 1, 1, tzinfo=timezone.utc), -62_135_596_800_000_000),
            (datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc), 253_402_300_799_999_999),
        )
        for instant, cutoff in cases:
            with self.subTest(instant=instant):
                actual = self.kernel.queries_with_evidence(arguments=arguments(self.values),
                    database_now=instant, request_digest=REQUEST_DIGEST,
                    evidence={"credentialRecordId": "separate-signer", "challengeId": "assertion-challenge"})
                self.assert_program(actual, expected_program(self.values, cutoff_us=cutoff,
                    evidence=True, signer="separate-signer"))

        class DateTimeSubclass(datetime):
            pass

        invalid = (NOW.replace(tzinfo=None), None, 0, True, "1970-01-01T00:00:00+00:00",
                   DateTimeSubclass(1970, 1, 1, tzinfo=timezone.utc))
        for instant in invalid:
            with self.subTest(instant=instant), self.assertRaises(core.TransitionKernelError):
                self.kernel.queries_with_evidence(arguments=arguments(self.values),
                    database_now=instant, request_digest=REQUEST_DIGEST,
                    evidence={"credentialRecordId": "separate-signer", "challengeId": "assertion-challenge"})
            with self.assertRaises(core.TransitionKernelError):
                candidate.cascade_queries(operation=OPERATION, values=self.values,
                    database_now=instant, request_digest=REQUEST_DIGEST)

    def test_full_recipe_rejects_nonclosed_arguments_changed_intent_and_invalid_source_values(self):
        valid = arguments(self.values)
        missing = dict(valid)
        del missing["businessIntent"]
        for supplied in ([], missing, {**valid, "extra": None}, {**valid, "businessIntent": {}},
                         {**valid, "record_id": "different-with-unchanged-intent"}):
            with self.subTest(supplied=type(supplied)), self.assertRaises(core.TransitionKernelError):
                self.full(arguments=supplied)
        for changes in ({"source": "trust-withdrawal"}, {"record_id": ""}, {"actor_id": " "},
                        {"reason": "x" * 16_385}, {"audit_event": []}):
            with self.subTest(fields=tuple(changes)), self.assertRaises(core.TransitionKernelError):
                self.full(source_values(**changes))

    def test_hint_container_order_duplicates_and_utf8_id_bounds_are_not_coerced(self):
        for hint in HINTS:
            for invalid in ((), None, ["duplicate", "duplicate"], ["z", "a"], [1], ["bad\nvalue"]):
                with self.subTest(hint=hint, value=invalid), self.assertRaises(core.TransitionKernelError):
                    self.full(source_values(**{hint: invalid}))
        accepted = "雪" * 341 + "x"
        self.assertEqual(len(accepted.encode("utf-8")), 1024)
        values = source_values(record_id=accepted, oidc_session_ids=[accepted])
        self.assert_program(self.full(values, signer=accepted), expected_program(values, evidence=True))
        for changes in ({"record_id": accepted + "x"}, {"oidc_session_ids": [accepted + "x"]}):
            with self.subTest(fields=tuple(changes)), self.assertRaises(core.TransitionKernelError):
                self.full(source_values(**changes))

    def test_assertion_identity_inputs_require_bounded_text_but_not_claimed_proof_objects(self):
        for name in ("credentialRecordId", "challengeId"):
            for value in (None, False, 1, "", " leading", "trailing ", "bad\nvalue", "x" * 1025):
                evidence = {"credentialRecordId": "separate-signer", "challengeId": "assertion-challenge",
                            name: value}
                with self.subTest(name=name, value=value), self.assertRaises(core.TransitionKernelError):
                    self.full(evidence=evidence)
        accepted = "雪" * 341 + "x"
        actual = self.full(signer=accepted, challenge=accepted)
        self.assert_program(actual, expected_program(self.values, evidence=True,
            signer=accepted, challenge=accepted))
        with self.assertRaises(core.TransitionKernelError):
            self.full(evidence={"credentialRecordId": "separate-signer"})

    def test_genuine_profile_and_audit_hash_counts_include_capacity_resnapshots(self):
        actual_sha = hashlib.sha256
        cases = (source_values(control_plane_approval_ids=[], audit_event=None),
                 source_values(audit_event=None), self.values)
        for values in cases:
            audits = len(values["control_plane_approval_ids"]) + int(values["audit_event"] is not None)
            with self.subTest(audits=audits):
                with patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
                    cascade = candidate.cascade_queries_at_cutoff(operation=OPERATION, values=values,
                        cutoff_us=CUTOFF_US, request_digest=REQUEST_DIGEST)
                self.assertEqual(hashes.call_count, 5 + 2 * audits)
                with patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
                    business = self.full(values)
                self.assertEqual(hashes.call_count, 12 + 2 * audits)
                with patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
                    composed = capacity.add_capacity_query(OPERATION, self.full(values))
                self.assertEqual(hashes.call_count, 24 + 2 * audits)
                # Contract projections themselves compute profile hashes, so
                # comparisons are intentionally outside the observed windows.
                self.assert_program(cascade, expected_program(values))
                self.assert_program(business, expected_program(values, evidence=True, signer="separate-signer"))
                self.assert_program(composed, expected_program(values, evidence=True,
                    signer="separate-signer", framework=True))

    def test_audit_subject_order_optional_event_and_request_digest_bind_exact_point_keys(self):
        values = source_values(control_plane_approval_ids=["approval-a", "approval-雪"])
        first = self.full(values)
        second_digest = "sha256:" + "7" * 64
        second = self.full(values, request_digest=second_digest)
        self.assert_program(first, expected_program(values, evidence=True, signer="separate-signer"))
        self.assert_program(second, expected_program(values, evidence=True,
            signer="separate-signer", request_digest=second_digest))
        first_audits = [query.absent_key for query in first if query.table == "metadata_audit_outbox"]
        second_audits = [query.absent_key for query in second if query.table == "metadata_audit_outbox"]
        self.assertEqual(len(first_audits), 3)
        self.assertTrue(all(a != b for a, b in zip(first_audits, second_audits)))
        without_event = source_values(control_plane_approval_ids=values["control_plane_approval_ids"], audit_event=None)
        self.assertEqual([query.absent_key for query in self.full(without_event)
                          if query.table == "metadata_audit_outbox"], first_audits[:2])
        for digest in (None, "not-a-digest", "sha256:" + "G" * 64):
            with self.subTest(digest=digest), self.assertRaises(core.TransitionKernelError):
                self.full(request_digest=digest)

    def test_program_does_not_retain_mutable_argument_or_assertion_identity_aliases(self):
        supplied = arguments(self.values)
        evidence = {"credentialRecordId": "separate-signer", "challengeId": "assertion-challenge"}
        before = copy.deepcopy((supplied, evidence))
        actual = self.full(arguments=supplied, evidence=evidence)
        self.assertEqual((supplied, evidence), before)
        expected = wire(expected_program(self.values, evidence=True, signer="separate-signer"))
        supplied["record_id"] = "changed"
        supplied["oidc_session_ids"].append("changed")
        supplied["audit_event"]["note"] = "changed"
        supplied["businessIntent"]["arguments"]["record_id"] = "changed"
        evidence.update(credentialRecordId="changed", challengeId="changed")
        self.assertEqual(wire(documents(actual)), expected)

    def test_supplied_context_recipe_is_not_assertion_request_or_kernel_authority(self):
        minimal = {"credentialRecordId": "separate-signer", "challengeId": "assertion-challenge"}
        actual_transition = self.kernel.transition
        with patch.object(self.kernel, "transition", wraps=actual_transition) as transition:
            actual = self.full(evidence=minimal)
        self.assertEqual(transition.call_count, 0)
        self.assertEqual(actual, self.full(evidence={**minimal, "signature": "unverified caller value"}))
        # With no audit subjects the legacy recipe never consumes requestDigest.
        # Full operation admission must bind the request independently; this
        # mechanical factoring does not silently add such a claim or gate.
        no_audits = source_values(control_plane_approval_ids=[], audit_event=None)
        self.assertEqual(self.full(no_audits, request_digest="unused caller value"), self.full(no_audits))
        changed = source_values(reason="changed supplied reason",
            audit_event={"different": "payload with the same supplied request digest"})
        self.assertEqual(self.full(changed), actual)


if __name__ == "__main__":
    unittest.main()

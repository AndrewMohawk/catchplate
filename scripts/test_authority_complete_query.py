#!/usr/bin/env python3
"""Source-bound complete-query declarations, not installed index authority.

The real declaration, projection, closure, capacity and retained-read helpers
are exercised without importing a blocked planner or replacing its registry.
Independent JSON/profile/interval oracles describe the expected data. A valid
declaration or retained observation is not a proof of an index population,
current checkpoint, complete SQL result, admitted clock or launched operation.
The planner linkage check is supplemental source inspection only.
"""
from __future__ import annotations

import ast
import copy
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_capacity as capacity
from serverware import authority_complete_query as complete
from serverware import authority_contract
from serverware import authority_index_projection as projection
from serverware import authority_query_reads as reads
from serverware import authority_transition_core as core
import test_authority_index_join as index_oracle


OPERATION = "webauthn.credential.revoke"
NOW = datetime(1970, 1, 1, 0, 0, 1, 7, tzinfo=timezone.utc)
CUTOFF_US = 1_000_007
ROLE_SPECS = (
    ("sessions_pending_webauthn", "oidc_browser_sessions", "webauthn_session_credential_status", "oidc_session_ids"),
    ("sessions_active", "oidc_browser_sessions", "webauthn_session_credential_status", "oidc_session_ids"),
    ("grants", "approval_grants", "webauthn_grant_approver_active", "approval_grant_ids"),
    ("approvals", "control_plane_approvals", "webauthn_control_approval_approved", "control_plane_approval_ids"),
    ("global_registration_challenges", "webauthn_challenges", "webauthn_registration_unused_global", "registration_challenge_ids"),
)
ROLES = tuple(row[0] for row in ROLE_SPECS)
GROUPS = {"sessions_pending_webauthn": "oidc_sessions", "sessions_active": "oidc_sessions",
          "grants": "approval_grants", "approvals": "control_plane_approvals",
          "global_registration_challenges": "registration_challenges"}


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def framed(domain, *frames):
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def arguments():
    return {
        "record_id": "credential-雪", "actor_id": "user", "source": "explicit",
        "reason": "component fixture", "audit_event": None,
        "oidc_session_ids": ["session-a", "session-b"],
        "approval_grant_ids": ["grant-a", "grant-b"],
        "control_plane_approval_ids": ["approval-a"],
        "registration_challenge_ids": ["challenge-a"],
    }


def selector_for(role, *, record_id="credential-雪", cutoff_us=CUTOFF_US):
    if role == "global_registration_challenges":
        return {"expires_after_us": cutoff_us}
    result = {"credential_record_id": record_id}
    if role.startswith("sessions_"):
        result["status"] = role.removeprefix("sessions_")
    return result


def expected_shared_budget(role):
    return {"group": GROUPS[role], "maximumRows": 32, "measure": "distinct-primary-address-union"}


def complete_document(role, *, values=None, cutoff_us=CUTOFF_US):
    values = arguments() if values is None else values
    _, table, index_id, hint = next(row for row in ROLE_SPECS if row[0] == role)
    return {
        "schema": "serverware.policyAuthorityCompleteIndexQuery/v1", "operation": OPERATION, "role": role,
        "queryId": f"serverware.policyAuthorityQuery/{OPERATION}/{role}/{table}/v1",
        "table": table, "indexId": index_id,
        "projectionDigest": index_oracle.expected_profile(index_id).projection_digest,
        "selector": selector_for(role, record_id=values["record_id"], cutoff_us=cutoff_us),
        "maximumRows": max(1, len(values[hint])), "proofPrimitive": "authenticated-complete-index-range",
        "workUnits": 1, "overflowDisposition": "fail-closed", "order": "fixed-index-key",
        "sharedBudget": expected_shared_budget(role),
    }


def expected_role_manifest():
    documents = []
    for role, table, index_id, hint in ROLE_SPECS:
        sources = ({"expires_after_us": "supplied-cutoff-microseconds"}
                   if role == "global_registration_challenges" else
                   {"credential_record_id": "arguments.record_id"})
        if role.startswith("sessions_"):
            sources["status"] = {"constant": role.removeprefix("sessions_")}
        documents.append({
            "schema": "serverware.policyAuthorityCompleteIndexQueryRole/v1",
            "querySchema": "serverware.policyAuthorityCompleteIndexQuery/v1", "operation": OPERATION,
            "role": role, "queryId": f"serverware.policyAuthorityQuery/{OPERATION}/{role}/{table}/v1",
            "table": table, "indexId": index_id,
            "projectionDigest": index_oracle.expected_profile(index_id).projection_digest,
            "selectorSources": sources, "requiredSource": {"arguments.source": "explicit"},
            "rowBound": {"rule": "max(1,length-of-hint-list)", "hintField": hint, "maximum": 32},
            "sharedBudget": expected_shared_budget(role),
            "proofPrimitive": "authenticated-complete-index-range", "workUnits": 1,
            "order": "fixed-index-key", "overflowDisposition": "fail-closed",
        })
    return documents


def legacy_query(name="exact", **changes):
    options = dict(query_id=f"serverware.policyAuthorityQuery/{OPERATION}/{name}/webauthn_credentials/v1",
        table="webauthn_credentials", predicates=(core.QueryPredicate("id", "eq", "credential-雪"),),
        order_by=(), maximum_rows=1, absent_key={"id": "credential-雪"})
    options.update(changes)
    return core.BoundedQuery(**options)


def legacy_document(query):
    # This literal stays the old closed v1 shape, with no complete-index fields.
    return {
        "schema": "serverware.policyAuthorityQueryProgram/v1", "queryId": query.query_id,
        "table": query.table,
        "predicates": [{"column": item.column, "operator": item.operator, "value": item.value}
                       for item in query.predicates],
        "orderBy": [{"column": item.column, "descending": item.descending} for item in query.order_by],
        "maximumRows": query.maximum_rows, "overflowDisposition": "fail-closed",
        "absentKey": query.absent_key, "requireAbsence": query.require_absence,
        "proofPrimitive": query.proof_primitive, "workUnits": query.work_units,
        "exactPage": query.exact_page, "pageSize": query.page_size,
        "continuationTokenDigest": query.continuation_token_digest,
        "secondaryIndexName": query.secondary_index_name,
    }


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


def selected(table, identifier, row):
    key = {"id": identifier}
    return {"table": table, "key": key,
            "keyDigest": framed("serverware.policyAuthorityBusinessKey/v1", table.encode("ascii"), canonical(key)),
            "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None}


class CompleteQueryTests(unittest.TestCase):
    def setUp(self):
        self.arguments = arguments()

    def bind(self, role="grants", **changes):
        options = {"arguments": self.arguments, "cutoff_us": CUTOFF_US, **changes}
        return complete.bind_query(OPERATION, role, **options)

    def program(self, **changes):
        return tuple(self.bind(role, **changes) for role in ROLES)

    def test_five_source_roles_bind_exact_profile_selector_and_hint_bound(self):
        for role, table, index_id, hint in ROLE_SPECS:
            with self.subTest(role=role):
                query = self.bind(role)
                self.assertIs(type(query), complete.CompleteIndexQuery)
                self.assertEqual((query.operation, query.role, query.table, query.index_id),
                                 (OPERATION, role, table, index_id))
                self.assertEqual(query.query_id,
                    f"serverware.policyAuthorityQuery/{OPERATION}/{role}/{table}/v1")
                self.assertEqual(query.selector(), selector_for(role))
                self.assertEqual(query.selector_items, tuple(sorted(selector_for(role).items())))
                self.assertEqual(query.maximum_rows, max(1, len(self.arguments[hint])))
                self.assertEqual(query.projection_digest, index_oracle.expected_profile(index_id).projection_digest)
                self.assertEqual(query.proof_primitive, complete.PROOF_PRIMITIVE)
                self.assertEqual(query.work_units, 1)
                self.assertEqual((query.shared_group, query.shared_maximum_rows), (GROUPS[role], 32))
                self.assertNotIsInstance(query, core.BoundedQuery)
                for attribute in ("predicates", "order_by", "absent_key", "exact_page",
                                  "page_size", "continuation_token_digest", "secondary_index_name"):
                    self.assertFalse(hasattr(query, attribute))

    def test_real_projection_intervals_match_independent_fixed_role_encodings(self):
        for role, _, index_id, _ in ROLE_SPECS:
            with self.subTest(role=role):
                query = self.bind(role)
                profile = index_oracle.expected_profile(index_id)
                expected = index_oracle.expected_interval(profile, selector_for(role))
                self.assertEqual(projection.query_interval(query.index_id, query.selector()), expected)
        pending, active = self.program()[:2]
        self.assertNotEqual(projection.query_interval(pending.index_id, pending.selector()),
                            projection.query_interval(active.index_id, active.selector()))
        low = self.bind("global_registration_challenges", cutoff_us=-(2**63))
        high = self.bind("global_registration_challenges", cutoff_us=2**63 - 1)
        for query in (low, high):
            self.assertEqual(projection.query_interval(query.index_id, query.selector()),
                index_oracle.expected_interval(index_oracle.expected_profile(query.index_id), query.selector()))
        empty = projection.query_interval(high.index_id, high.selector())
        self.assertEqual(empty.lower, empty.upper)

    def test_complete_contract_and_role_manifest_have_independent_exact_wire_shapes(self):
        self.assertEqual(complete.QUERY_SCHEMA, "serverware.policyAuthorityCompleteIndexQuery/v1")
        self.assertEqual(complete.ROLE_SCHEMA, "serverware.policyAuthorityCompleteIndexQueryRole/v1")
        self.assertEqual(complete.PROOF_PRIMITIVE, "authenticated-complete-index-range")
        self.assertEqual(complete.ROLES, ROLES)
        for query in self.program():
            with self.subTest(role=query.role):
                self.assertEqual(query.contract_value(), complete_document(query.role))
                self.assertEqual(canonical(query.contract_value()), canonical(complete_document(query.role)))
        expected = expected_role_manifest()
        actual = complete.role_manifest(OPERATION)
        self.assertEqual(actual, expected)
        actual[0]["selectorSources"]["status"]["constant"] = "changed"
        actual[1]["sharedBudget"]["maximumRows"] = 64
        actual.clear()
        self.assertEqual(complete.role_manifest(OPERATION), expected)
        for operation in ("webauthn.registration.finalize", "webauthn.trust.stage", "webauthn.trust.complete",
                          "webauthn.counter.cas", "not.a.source.operation"):
            self.assertEqual(complete.role_manifest(operation), [])

    def test_only_revoke_manifest_commits_roles_and_handler_digest_binds_them(self):
        manifest = authority_contract.operation_manifest()
        self.assertEqual({name for name, value in manifest.items() if value["completeIndexQueryRoles"]}, {OPERATION})
        self.assertEqual({name for name, spec in authority_contract.OPERATIONS.items()
                          if complete.PROOF_PRIMITIVE in spec["proofPrimitives"]}, {OPERATION})
        entry = manifest[OPERATION]
        self.assertEqual(entry["completeIndexQueryRoles"], expected_role_manifest())
        # Other handler fields come from the actual manifest; the new role
        # documents and hash framing are independent literal oracles.
        document = {name: value for name, value in entry.items()
                    if name not in {"handlerDigest", "predicateClosure", "selectorClosure", "proofKind"}}
        document.update(sourceRevision=authority_contract.SOURCE_REVISION, operation=OPERATION,
                        completeIndexQueryRoles=expected_role_manifest())
        def handler_digest(value):
            hasher = hashlib.sha256()
            for frame in (b"serverware.policyAuthorityHandlerContract/v1", canonical(value)):
                hasher.update(len(frame).to_bytes(8, "big"))
                hasher.update(frame)
            return "sha256:" + hasher.hexdigest()
        self.assertEqual(entry["handlerDigest"], handler_digest(document))
        self.assertNotEqual(entry["handlerDigest"], handler_digest({**document, "completeIndexQueryRoles": []}))
        changed = copy.deepcopy(document)
        changed["completeIndexQueryRoles"][0]["selectorSources"]["status"]["constant"] = "active"
        self.assertNotEqual(entry["handlerDigest"], handler_digest(changed))

    def test_hint_addresses_bound_work_but_never_enter_selector_or_partition(self):
        before = self.program()
        changed = copy.deepcopy(self.arguments)
        for _, _, _, hint in ROLE_SPECS:
            changed[hint] = ["different-" + item for item in changed[hint]]
        after = self.program(arguments=changed)
        self.assertEqual(before, after)
        for _, _, _, hint in ROLE_SPECS:
            changed[hint] = []
        empty_hints = self.program(arguments=changed)
        self.assertTrue(all(query.maximum_rows == 1 for query in empty_hints))
        self.assertEqual([query.selector_items for query in empty_hints],
                         [query.selector_items for query in before])

    def test_declarations_and_projections_are_owned_immutable_data_not_tokens(self):
        query = self.bind()
        snapshot = complete.snapshot_query(query)
        self.assertEqual(snapshot, query)
        self.assertIsNot(snapshot, query)
        with self.assertRaises(FrozenInstanceError):
            query.maximum_rows = 1
        selector = query.selector()
        selector["credential_record_id"] = "changed"
        self.arguments["record_id"] = "caller changed"
        self.assertEqual(query.selector(), {"credential_record_id": "credential-雪"})
        self.assertEqual(snapshot, query)
        document = query.contract_value()
        document.clear()
        self.assertTrue(query.contract_value())
        self.assertEqual(set(field.name for field in fields(query)),
                         {"operation", "role", "selector_items", "maximum_rows"})

    def test_constructor_role_operation_selectors_and_scalar_types_are_closed(self):
        query = self.bind("sessions_active")
        bad_items = (
            list(query.selector_items), (("credential_record_id", "credential-雪"),),
            (*query.selector_items, ("extra", "not-admitted")),
            tuple(reversed(query.selector_items)),
            (("credential_record_id", "credential-雪"), ("status", "revoked")),
            (("credential_record_id", "credential-雪"), ("status", "pending_webauthn")),
            (("credential_record_id", None), ("status", "active")),
            (("credential_record_id", True), ("status", "active")),
            (("credential_record_id", "nul\0value"), ("status", "active")),
            (("credential_record_id", "\ud800"), ("status", "active")),
            (("credential_record_id", "x" * 4097), ("status", "active")),
            (("credential_record_id", "credential-雪"), ("credential_record_id", "credential-雪")),
        )
        for items in bad_items:
            with self.subTest(items=repr(items)[:160]), self.assertRaises(complete.CompleteQueryError):
                replace(query, selector_items=items)
        for operation in (None, True, "webauthn.registration.finalize", "webauthn.trust.complete", "unknown"):
            with self.subTest(operation=operation), self.assertRaises(complete.CompleteQueryError):
                replace(query, operation=operation)
        for role in (None, True, "sessions_revoked", "credential_id", "grants/extra"):
            with self.subTest(role=role), self.assertRaises(complete.CompleteQueryError):
                replace(query, role=role)
        cutoff = self.bind("global_registration_challenges")
        for value in (True, False, 0.0, None, "1", -(2**63) - 1, 2**63):
            with self.subTest(cutoff=value), self.assertRaises(complete.CompleteQueryError):
                replace(cutoff, selector_items=(("expires_after_us", value),))

    def test_exact_row_bound_and_all_hint_list_controls_are_source_owned(self):
        query = self.bind()
        for count in (1, 32):
            self.assertEqual(replace(query, maximum_rows=count).maximum_rows, count)
        for count in (False, True, 0, -1, 33, 256, 1.0, "1", None):
            with self.subTest(count=count), self.assertRaises(complete.CompleteQueryError):
                replace(query, maximum_rows=count)
        for _, _, _, hint in ROLE_SPECS:
            for invalid in ((), ["b", "a"], ["same", "same"], [None], [1], ["bad\0"],
                            [f"item-{index:02d}" for index in range(33)]):
                changed = {**self.arguments, hint: invalid}
                with self.subTest(hint=hint, value=invalid), self.assertRaises(complete.CompleteQueryError):
                    self.bind(arguments=changed)
        full = {**self.arguments, **{hint: [f"item-{index:02d}" for index in range(32)]
                                   for _, _, _, hint in ROLE_SPECS}}
        self.assertTrue(all(query.maximum_rows == 32 for query in self.program(arguments=full)))
        # These are individual declaration ceilings. The business kernel still
        # rejects a full request whose combined mutation obligations overflow.

    def test_source_id_utf8_and_argument_container_boundaries_are_exact(self):
        class TextSubclass(str):
            pass
        class DictionarySubclass(dict):
            pass
        class ListSubclass(list):
            pass
        for record_id in ("a" * 1024, "é" * 512, "😀" * 256):
            query = self.bind(arguments={**self.arguments, "record_id": record_id})
            self.assertEqual(query.selector(), {"credential_record_id": record_id})
        for record_id in ("a" * 1025, "é" * 512 + "a", "😀" * 256 + "a",
                          " leading", "trailing ", "line\nbreak", "delete\x7f", TextSubclass("credential")):
            with self.subTest(record_id=repr(record_id)[:60]), self.assertRaises(complete.CompleteQueryError):
                self.bind(arguments={**self.arguments, "record_id": record_id})
        bounded = {**self.arguments, **{f"unused_{index}": None for index in range(64 - len(self.arguments))}}
        self.assertEqual(len(bounded), 64)
        self.assertEqual(self.bind(arguments=bounded), self.bind())
        for values in (None, DictionarySubclass(self.arguments), {**bounded, "one_more": None},
                       {**self.arguments, "oidc_session_ids": ListSubclass(self.arguments["oidc_session_ids"])},
                       {**self.arguments, "source": TextSubclass("explicit")}):
            with self.subTest(kind=type(values)), self.assertRaises(complete.CompleteQueryError):
                self.bind(arguments=values)

    def test_binder_requires_explicit_source_and_relevant_intent_fields(self):
        for name in ("record_id", "source", "oidc_session_ids", "approval_grant_ids",
                     "control_plane_approval_ids", "registration_challenge_ids"):
            changed = dict(self.arguments)
            del changed[name]
            with self.subTest(missing=name), self.assertRaises(complete.CompleteQueryError):
                self.bind(arguments=changed)
        for source in (None, True, "trust-withdrawal", "administrative", "offline-last-key-decommission"):
            with self.subTest(source=source), self.assertRaises(complete.CompleteQueryError):
                self.bind(arguments={**self.arguments, "source": source})
        for record_id in (None, True, "", "bad\0", "\ud800", "x" * 4097):
            with self.subTest(record_id=repr(record_id)[:80]), self.assertRaises(complete.CompleteQueryError):
                self.bind(arguments={**self.arguments, "record_id": record_id})
        # The binder intentionally does not validate unrelated whole-request
        # authorization, evidence, reason or audit payload fields.
        unrelated = {**self.arguments, "reason": object(), "audit_event": object()}
        self.assertEqual(self.bind(arguments=unrelated), self.bind())

    def test_binding_revalidation_requires_every_role_and_rederives_all_sources(self):
        program = self.program()
        checked = complete.validate_bindings(OPERATION, program,
            arguments=self.arguments, cutoff_us=CUTOFF_US)
        self.assertEqual(checked, program)
        self.assertTrue(all(actual is not original for actual, original in zip(checked, program)))
        reversed_program = tuple(reversed(program))
        self.assertEqual(complete.validate_bindings(OPERATION, reversed_program,
            arguments=self.arguments, cutoff_us=CUTOFF_US), reversed_program)
        cases = (program[:-1], (*program, program[0]), (*program[:-1], program[0]), list(program), ())
        for values in cases:
            with self.subTest(roles=repr(values)[:100]), self.assertRaises(complete.CompleteQueryError):
                complete.validate_bindings(OPERATION, values, arguments=self.arguments, cutoff_us=CUTOFF_US)
        for index, changed in (
            (0, replace(program[0], selector_items=(("credential_record_id", "different"),
                                                    ("status", "pending_webauthn")))),
            (2, replace(program[2], maximum_rows=1)),
            (4, replace(program[4], selector_items=(("expires_after_us", CUTOFF_US + 1),))),
        ):
            values = list(program)
            values[index] = changed
            with self.subTest(index=index), self.assertRaises(complete.CompleteQueryError):
                complete.validate_bindings(OPERATION, tuple(values), arguments=self.arguments, cutoff_us=CUTOFF_US)
        for changed, cutoff in (({**self.arguments, "record_id": "different"}, CUTOFF_US),
                                (self.arguments, CUTOFF_US + 1)):
            with self.subTest(cutoff=cutoff), self.assertRaises(complete.CompleteQueryError):
                complete.validate_bindings(OPERATION, program, arguments=changed, cutoff_us=cutoff)

    def test_snapshot_revalidates_subclasses_incomplete_and_constructor_bypassed_values(self):
        query = self.bind()
        class QuerySubclass(complete.CompleteIndexQuery):
            pass
        incomplete = object.__new__(complete.CompleteIndexQuery)
        cases = (None, object(), legacy_query(), incomplete,
                 QuerySubclass(query.operation, query.role, query.selector_items, query.maximum_rows),
                 forged(query, operation="webauthn.counter.cas"),
                 forged(query, role="unknown"), forged(query, selector_items=[]),
                 forged(query, maximum_rows=True), forged(query, maximum_rows=33))
        for value in cases:
            with self.subTest(value=type(value)), self.assertRaises(complete.CompleteQueryError):
                complete.snapshot_query(value)
        snapshot = complete.snapshot_query(query)
        object.__setattr__(query, "maximum_rows", 1)
        self.assertEqual(snapshot.maximum_rows, 2)
        with self.assertRaises(complete.CompleteQueryError):
            complete.validate_bindings(OPERATION, tuple(query if item.role == "grants" else item
                for item in self.program()), arguments=self.arguments, cutoff_us=CUTOFF_US)

    def test_clock_conversion_is_exact_microseconds_without_sampling_or_float_coercion(self):
        cases = ((NOW, CUTOFF_US),
                 (datetime(1970, 1, 1, tzinfo=timezone.utc), 0),
                 (datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc), -1),
                 (NOW.astimezone(timezone(timedelta(hours=5, minutes=30))), CUTOFF_US))
        for instant, expected in cases:
            with self.subTest(instant=instant):
                self.assertEqual(complete.cutoff_microseconds(instant), expected)
        class DateTimeSubclass(datetime):
            pass
        for instant in (None, True, 0, "1970-01-01T00:00:00+00:00", NOW.replace(tzinfo=None),
                        DateTimeSubclass(1970, 1, 1, tzinfo=timezone.utc)):
            with self.subTest(instant=instant), self.assertRaises(complete.CompleteQueryError):
                complete.cutoff_microseconds(instant)

    def test_legacy_query_program_v1_bytes_and_old_proof_variants_are_unchanged(self):
        old = (
            legacy_query(),
            legacy_query("page", predicates=(core.QueryPredicate("revoked_at", "is-null"),),
                order_by=(core.QueryOrder("id"),), maximum_rows=2, absent_key=None,
                proof_primitive="ordered-exact-page", exact_page=True),
            legacy_query("limited", absent_key=None, maximum_rows=3, page_size=2,
                proof_primitive="bounded-limit-plus-one"),
            legacy_query("secondary", absent_key=None, proof_primitive="authenticated-secondary-index",
                secondary_index_name="old_index"),
        )
        for query in old:
            with self.subTest(primitive=query.proof_primitive):
                self.assertEqual(canonical(query.contract_value()), canonical(legacy_document(query)))
                self.assertEqual(query.contract_value()["schema"], "serverware.policyAuthorityQueryProgram/v1")
                self.assertNotIn("selector", query.contract_value())
                self.assertNotIn("indexId", query.contract_value())
        self.assertEqual(reads.snapshot_queries(OPERATION, old[:2]), old[:2])
        with self.assertRaises(core.TransitionKernelError):
            legacy_query(proof_primitive=complete.PROOF_PRIMITIVE)
        bypassed = forged(old[0], proof_primitive=complete.PROOF_PRIMITIVE)
        with self.assertRaises(core.TransitionKernelError):
            core.close_queries(OPERATION, (bypassed,))
        with self.assertRaises(core.TransitionKernelError):
            capacity.add_capacity_query(OPERATION, (bypassed,))
        with self.assertRaises(reads.QueryReadError):
            reads.snapshot_queries(OPERATION, (bypassed,))
        self.assertNotEqual(self.bind().contract_value()["schema"], old[0].contract_value()["schema"])

    def test_mixed_close_and_capacity_preserve_exact_legacy_framework_query(self):
        mixed = (legacy_query(), *self.program())
        self.assertEqual(core.close_queries(OPERATION, mixed), mixed)
        snapshot = reads.snapshot_queries(OPERATION, mixed)
        self.assertEqual(snapshot, mixed)
        self.assertTrue(all(actual is not original for actual, original in zip(snapshot, mixed)))
        composed = capacity.add_capacity_query(OPERATION, mixed)
        self.assertEqual(composed[:-1], mixed)
        counter = composed[-1]
        self.assertIs(type(counter), core.BoundedQuery)
        self.assertEqual(counter, capacity.add_capacity_query(OPERATION, ())[0])
        self.assertEqual(counter.absent_key, {"aggregate_id": capacity.AGGREGATE_ID})
        self.assertEqual(canonical(counter.contract_value()), canonical(legacy_document(counter)))
        self.assertEqual(sum(query.maximum_rows for query in composed),
                         sum(query.maximum_rows for query in mixed) + 1)
        # Closure accounts declarations, but only the operation-specific binder
        # can prove that this source role inventory is present and correctly bound.
        partial = (self.bind(),)
        self.assertEqual(core.close_queries(OPERATION, partial), partial)
        with self.assertRaises(complete.CompleteQueryError):
            complete.validate_bindings(OPERATION, partial, arguments=self.arguments, cutoff_us=CUTOFF_US)

    def test_mixed_program_business_rows_work_collisions_and_operation_limits_reject(self):
        program = self.program()
        spec = authority_contract.operation_spec(OPERATION)
        row_allowance = spec["maximumBusinessQueryRows"] - sum(query.maximum_rows for query in program)
        at_rows = legacy_query("row_boundary", absent_key=None, maximum_rows=row_allowance)
        self.assertEqual(sum(query.maximum_rows for query in capacity.add_capacity_query(OPERATION,
            (at_rows, *program))), spec["maximumQueryRows"])
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.add_capacity_query(OPERATION, (replace(at_rows, maximum_rows=row_allowance + 1), *program))
        work_allowance = spec["maximumBusinessWorkUnits"] - sum(query.work_units for query in program)
        at_work = legacy_query("work_boundary", work_units=work_allowance)
        capacity.add_capacity_query(OPERATION, (at_work, *program))
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.add_capacity_query(OPERATION, (replace(at_work, work_units=work_allowance + 1), *program))
        with self.assertRaises(core.TransitionKernelError):
            core.close_queries(OPERATION, (*program, program[0]))
        with self.assertRaises(core.TransitionKernelError):
            core.close_queries("webauthn.counter.cas", program)
        counter = capacity.add_capacity_query(OPERATION, ())[0]
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.add_capacity_query(OPERATION, (*program, counter))
        invalid = forged(self.bind(), maximum_rows=True)
        with self.assertRaises(core.TransitionKernelError):
            core.close_queries(OPERATION, (invalid,))
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.add_capacity_query(OPERATION, (invalid,))
        with self.assertRaises(reads.QueryReadError):
            reads.snapshot_queries(OPERATION, (invalid,))

    def test_retained_complete_declaration_has_no_invented_order_or_absence_proof(self):
        query = self.bind()
        resolved = reads.resolve_query(OPERATION, query, prior_reads=(), selected_rows=())
        self.assertEqual(resolved, query)
        self.assertIsNot(resolved, query)
        self.assertEqual(reads.reference_source_rows(OPERATION, query, prior_reads=(), selected_rows=()), ())
        empty = reads.capture_query_read(OPERATION, query, resolved_query=resolved,
            ordered_selected_rows=(), returned_row_count=0)
        self.assertEqual((empty.declared_query_json, empty.resolved_query_json),
                         (canonical(query.contract_value()), canonical(query.contract_value())))
        self.assertEqual((empty.addresses, empty.returned_row_count), ((), 0))
        self.assertEqual(reads.validate_query_reads(OPERATION, queries=(query,), query_reads=(empty,),
            selected_rows=()), (empty,))
        self.assertNotIn("orderBy", json.loads(empty.resolved_query_json))
        absent = selected(query.table, "missing", None)
        with self.assertRaises(reads.QueryReadError):
            reads.capture_query_read(OPERATION, query, resolved_query=resolved,
                ordered_selected_rows=(absent,), returned_row_count=0)

    def test_query_retention_remains_observation_not_index_membership_or_completeness(self):
        query = self.bind()
        # Deliberately not members of the complete role's active-grant selector.
        rows = (selected(query.table, "b", {"id": "b", "state": "inactive"}),
                selected(query.table, "a", {"id": "a", "state": "inactive"}))
        record = reads.capture_query_read(OPERATION, query, resolved_query=query,
            ordered_selected_rows=rows, returned_row_count=2)
        validated = reads.validate_query_reads(OPERATION, queries=(query,), query_reads=(record,), selected_rows=rows)
        self.assertEqual(validated, (record,))
        self.assertEqual(reads.query_rows(OPERATION, query_reads=validated, selected_rows=rows,
            query_id=query.query_id), rows)
        self.assertEqual([json.loads(address.key_json)["id"] for address in record.addresses], ["b", "a"])
        rows[0]["row"]["state"] = "changed unreferenced row field"
        self.assertEqual(reads.validate_query_reads(OPERATION, queries=(query,), query_reads=(record,),
            selected_rows=rows), validated)
        self.assertEqual(set(field.name for field in fields(record)), {
            "query_id", "declared_query_json", "resolved_query_json", "addresses", "returned_row_count"})

    def test_complete_retained_records_cannot_change_declaration_or_cross_query_kind(self):
        query = self.bind()
        alternate = replace(query, selector_items=(("credential_record_id", "different"),))
        legacy = core.BoundedQuery(query_id=query.query_id, table=query.table, predicates=(),
            order_by=(), maximum_rows=query.maximum_rows)
        for before, after in ((query, alternate), (query, legacy), (legacy, query),
                              (query, replace(query, maximum_rows=1))):
            with self.subTest(after=type(after)), self.assertRaises(reads.QueryReadError):
                reads.capture_query_read(OPERATION, before, resolved_query=after,
                    ordered_selected_rows=(), returned_row_count=0)
        record = reads.capture_query_read(OPERATION, query, resolved_query=query,
            ordered_selected_rows=(), returned_row_count=0)
        changed = replace(record, declared_query_json=canonical(alternate.contract_value()),
                          resolved_query_json=canonical(alternate.contract_value()))
        with self.assertRaises(reads.QueryReadError):
            reads.validate_query_reads(OPERATION, queries=(query,), query_reads=(changed,), selected_rows=())

    def test_planner_source_rebinds_owned_roles_and_rejects_whole_inventory_before_business_io(self):
        # Supplemental source linkage, not execution/import of the blocked
        # planner. Its earlier database-clock read remains outside this claim.
        text = (ROOT / "serverware/authority_planner.py").read_text(encoding="utf-8")
        module = ast.parse(text, filename="serverware/authority_planner.py")
        reader, = [node for node in module.body if isinstance(node, ast.FunctionDef)
                   and node.name == "_read_bounded_transition_rows"]
        def calls(node, name):
            return [item for item in ast.walk(node) if isinstance(item, ast.Call)
                    and ast.unparse(item.func) == name]
        snapshot, = calls(reader, "authority_query_reads.snapshot_queries")
        guards = [node for node in reader.body if isinstance(node, ast.If)
                  and ast.unparse(node.test) ==
                  "any(type(query) is authority_complete_query.CompleteIndexQuery for query in queries)"]
        self.assertEqual(len(guards), 1)
        guard = guards[0]
        self.assertEqual(len(guard.body), 1)
        self.assertIsInstance(guard.body[0], ast.Raise)
        self.assertEqual(ast.unparse(guard.body[0].exc),
            "AuthorityPlannerError('complete index query acquisition is not available')")
        self.assertFalse(guard.orelse)
        self.assertLess(snapshot.lineno, guard.lineno)
        loop, = [node for node in reader.body if isinstance(node, ast.For)]
        self.assertLess(guard.end_lineno, loop.lineno)
        for name in ("query_sources.authenticate_references", "authority_query_reads.resolve_query", "cursor.execute"):
            actual, = calls(reader, name)
            self.assertLess(guard.end_lineno, actual.lineno)
        self.assertFalse(any(isinstance(node, ast.For) for node in reader.body[:reader.body.index(guard)]))
        planner, = [node for node in module.body if isinstance(node, ast.ClassDef)
                    and node.name == "TypedTransitionPlanningProgram"]
        method, = [node for node in planner.body if isinstance(node, ast.FunctionDef)
                   and node.name == "read_inputs"]
        bind, = calls(method, "authority_complete_query.validate_bindings")
        capacity_call, = calls(method, "authority_audit_capacity.add_capacity_query")
        read, = calls(method, "_read_bounded_transition_rows")
        self.assertLess(bind.lineno, capacity_call.lineno)
        self.assertLess(capacity_call.lineno, read.lineno)
        self.assertEqual({item.arg: ast.unparse(item.value) for item in bind.keywords},
            {"arguments": "arguments", "cutoff_us": "authority_complete_query.cutoff_microseconds(database_now)"})
        adoption = [node for node in ast.walk(method) if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "proposed_queries" for target in node.targets)
                    and calls(node, "next")]
        self.assertEqual(len(adoption), 1)
        self.assertIn("next(bound_queries)", ast.unparse(adoption[0].value))
        self.assertLess(bind.lineno, adoption[0].lineno)
        self.assertLess(adoption[0].lineno, capacity_call.lineno)


if __name__ == "__main__":
    unittest.main()

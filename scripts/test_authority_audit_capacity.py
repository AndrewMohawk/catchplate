#!/usr/bin/env python3
"""Fresh audit business mutations and replay; global counting is separate.

Real KernelContext/helpers/templates are used without DB or registry substitutes.
Independent fixtures cover fresh INSERT construction and composition with the
global finalizer, not the full planner or complete caller kernels. Explicit AST
checks are SOURCE evidence, not successful signed activation replay or consumed-
evidence admission. No authenticated baseline/all-writer maintenance is claimed.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_capacity as capacity
from serverware import authority_contract
from serverware import authority_transition_core as core
from serverware import authority_transition_policy as policy
from serverware import authority_transition_quota as quota
from serverware.audit_outbox_contract import MAX_PENDING

TABLE = "policy_authority_bounded_aggregate_states"
OUTBOX = "metadata_audit_outbox"
NOW = datetime(1970, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
COUNTS = {"policy.activation.prepare": 7, "policy.genesis.prepare": 1,
          "rbac.binding.mutate": 1, "policy.activation.abort": 1}
QUOTA_OPERATIONS = ("control-approval.request", "control-approval.decide", "control-approval.consume",
    "control-approval.deny", "jit.request", "jit.review-receipt.issue", "jit.decide", "jit.deny")
_DEFAULT = object()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def framed(domain, *frames):
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    for value in frames:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return "sha256:" + digest.hexdigest()


REQUEST = "sha256:" + hashlib.sha256(b"audit-freshness-local-component").hexdigest()
EXPIRY = framed("serverware.policyAuthorityAggregateExpiryIndex/v1", b"[]")
GLOBAL_KIND = "metadata-audit-outbox-global-capacity-v1"
GLOBAL_PARTITION = framed("serverware.metadataAuditOutboxCapacityPartition/v1", b"global")
GLOBAL_ID = GLOBAL_KIND + ":" + GLOBAL_PARTITION


def operation_id(operation):
    return framed("serverware.policyAuthorityOperation/v2", operation.encode("ascii"), REQUEST.encode("ascii"))


def selection(table, key, *, present=False, row=None):
    return {"table": table, "key": copy.deepcopy(key),
        "keyDigest": framed("serverware.policyAuthorityBusinessKey/v1", table.encode("ascii"), canonical(key)),
        "present": present, "row": copy.deepcopy(row), "contractSelector": None}


def context(operation="policy.genesis.prepare", selections=()):
    return core.KernelContext(operation=operation, arguments={}, selected_rows=tuple(copy.deepcopy(selections)),
        database_now=NOW, request_digest=REQUEST)


def audit_rows(operation="policy.genesis.prepare"):
    rows = []
    for ordinal in range(COUNTS[operation]):
        event = canonical({"componentOperation": operation, "ordinal": ordinal})
        rows.append({"id": "policy-authority:" + hashlib.sha256(event).hexdigest(),
            "event_type": "policy.authority.component", "actor_type": "admin", "actor_id": "component-actor",
            "event_json": event.decode("ascii"), "event_digest": framed("serverware.metadataAuditOutboxEvent/v1", event),
            "storage_format_version": 2, "status": "pending", "claim_id": None, "claimed_at": None,
            "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None, "created_at": NOW.isoformat()})
    return tuple(rows)


def audit_selection(identity, **kwargs):
    return selection(OUTBOX, {"id": identity}, **kwargs)


def audit_context(operation="policy.genesis.prepare", *, selections=None):
    rows = audit_rows(operation)
    selected = tuple(audit_selection(row["id"]) for row in rows) if selections is None else selections
    return context(operation, selected), rows


def audit_mutations(ctx, rows, *, identity=_DEFAULT):
    return policy._fresh_audit_mutations(ctx,
        operation_id=operation_id(ctx.operation) if identity is _DEFAULT else identity, outbox_rows=rows)


def aggregate_row(*, limit=100_000, live=0, kind=GLOBAL_KIND, partition=GLOBAL_PARTITION):
    row = {"aggregate_id": kind + ":" + partition, "aggregate_kind": kind, "partition_digest": partition,
        "revision": 7, "live_count": live, "active_count": live, "capacity_limit": limit,
        "reserved_units_json": "{}", "committed_units_json": "{}", "next_sequence": 11,
        "minimum_expiry_epoch_ns": None, "expiry_index_root_digest": EXPIRY, "work_page_id": None,
        "updated_at_epoch_ns": 1_000_000_000, "source_revision": authority_contract.SOURCE_REVISION}
    state = {"schema": "serverware.policyAuthorityAggregateState/v1", "aggregateId": row["aggregate_id"],
        "aggregateKind": kind, "partitionDigest": partition, "revision": 7, "liveCount": live,
        "activeCount": live, "capacityLimit": limit, "reservedUnits": {}, "committedUnits": {},
        "nextSequence": 11, "minimumExpiryEpochNs": None, "expiryIndexRootDigest": EXPIRY, "workPageId": None}
    row["state_json"] = canonical(state).decode("ascii")
    row["state_digest"] = framed("serverware.policyAuthorityAggregateState/v1", canonical(state))
    return row


def with_counter(ctx, **kwargs):
    row = aggregate_row(**kwargs)
    return replace(ctx, selected_rows=(*ctx.selected_rows,
        selection(TABLE, {"aggregate_id": row["aggregate_id"]}, present=True, row=row)))


def quota_event(ctx):
    return quota._audit_mutations(ctx, event_type="component.quota", actor_type="admin",
        actor_id="component-actor", event={"purpose": "local-component", "nested": {"v": 1}})


class AuditBusinessMutationTests(unittest.TestCase):
    def test_policy_fixed_counts_return_only_exact_fresh_inserts(self):
        for operation, count in COUNTS.items():
            ctx, rows = audit_context(operation)
            before = copy.deepcopy((ctx.selected_rows, rows))
            mutations = audit_mutations(ctx, rows)
            self.assertIs(type(mutations), tuple)
            self.assertEqual(len(mutations), count)
            template, = [entry["templateId"] for entry in authority_contract.operation_spec(operation)["mutationTemplates"]
                if entry["table"] == OUTBOX and entry["mutation"] == "INSERT"]
            for row, mutation in zip(rows, mutations):
                self.assertEqual(mutation, {"templateId": template, "operation": "INSERT", "table": OUTBOX,
                    "key": {"id": row["id"]}, "keyDigest": audit_selection(row["id"])["keyDigest"],
                    "expectedRow": None, "row": row})
            self.assertEqual((ctx.selected_rows, rows), before)

    def test_fresh_helper_does_not_bootstrap_or_update_any_counter(self):
        ctx, rows = audit_context()
        mutations = audit_mutations(ctx, rows)
        self.assertTrue(all(item["table"] == OUTBOX for item in (*ctx.selected_rows, *mutations)))
        with self.assertRaisesRegex(capacity.AuditCapacityError, "before row is missing or ambiguous"):
            capacity.finalize_capacity(ctx, mutations)

    def test_global_finalizer_composition_keeps_one_and_seven_capacity_boundaries(self):
        self.assertEqual(MAX_PENDING, 100_000)
        for operation, count in COUNTS.items():
            ctx, rows = audit_context(operation)
            ctx = with_counter(ctx, live=MAX_PENDING-count)
            business = audit_mutations(ctx, rows)
            result = capacity.finalize_capacity(ctx, business)
            self.assertEqual(result[:-1], business)
            self.assertEqual(len(result), count + 1)
            self.assertEqual(result[-1]["key"], {"aggregate_id": GLOBAL_ID})
            self.assertEqual(result[-1]["row"]["live_count"], MAX_PENDING)
            self.assertEqual(result[-1]["row"]["committed_units_json"], "{}")
            capacity.validate_capacity_transition(operation=operation, selected_rows=ctx.selected_rows, mutations=result)
            full = with_counter(audit_context(operation)[0], live=MAX_PENDING-count+1)
            before = copy.deepcopy(full.selected_rows)
            with self.assertRaisesRegex(capacity.AuditCapacityError, "transition exceeds its bound"):
                capacity.finalize_capacity(full, audit_mutations(full, rows))
            self.assertEqual(full.selected_rows, before)

    def test_policy_existing_pending_claimed_and_audited_ids_never_become_updates(self):
        for status in ("pending", "claimed", "audited"):
            proposed = audit_rows()[0]
            ctx, rows = audit_context(selections=(audit_selection(proposed["id"], present=True,
                row={**proposed, "status": status}),))
            with self.assertRaisesRegex(core.TransitionKernelError, "fresh audit identity is not proven absent"):
                audit_mutations(ctx, rows)

    def test_policy_absence_requires_exact_false_and_explicit_null(self):
        row = audit_rows()[0]
        cases = [audit_selection(row["id"], present=value) for value in (None, 0, 1, "false")]
        cases.extend(audit_selection(row["id"], row=value) for value in ({}, row))
        for field in ("present", "row"):
            missing = audit_selection(row["id"])
            del missing[field]
            cases.append(missing)
        for chosen in cases:
            ctx, rows = audit_context(selections=(chosen,))
            with self.assertRaisesRegex(core.TransitionKernelError, "fresh audit identity is not proven absent"):
                audit_mutations(ctx, rows)

    def test_policy_requires_unique_complete_selected_identity(self):
        chosen = audit_selection(audit_rows()[0]["id"])
        for selections in ((), (chosen, copy.deepcopy(chosen))):
            ctx, rows = audit_context(selections=selections)
            with self.assertRaisesRegex(core.TransitionKernelError, "exact row is absent or ambiguous"):
                audit_mutations(ctx, rows)

    def test_policy_record_container_count_and_pending_identity_types_remain_closed(self):
        ctx, rows = audit_context()
        class StringSubclass(str):
            pass
        invalid = [None, list(rows), {"rows": rows}, (), rows + rows, (None,), ("row",), (1,), ({},)]
        invalid.extend(({**rows[0], "id": value},) for value in (
            None, True, 1, "", "non-ascii-é", "x" * 257, StringSubclass(rows[0]["id"])))
        invalid.extend(({**rows[0], "status": value},) for value in (
            None, True, "claimed", "audited", StringSubclass("pending")))
        for value in invalid:
            with self.assertRaisesRegex(core.TransitionKernelError, "audit records differ from the source operation"):
                audit_mutations(ctx, value)
        ctx, rows = audit_context("policy.activation.prepare")
        for value in (rows[:-1], rows + ({**rows[0], "id": "additional"},)):
            with self.assertRaisesRegex(core.TransitionKernelError, "audit records differ from the source operation"):
                audit_mutations(ctx, value)

    def test_policy_ascii_boundary_and_duplicate_ids(self):
        identity = "x" * 256
        row = {**audit_rows()[0], "id": identity}
        ctx = context(selections=(audit_selection(identity),))
        self.assertEqual(audit_mutations(ctx, (row,))[0]["row"], row)
        ctx, rows = audit_context("policy.activation.prepare")
        with self.assertRaisesRegex(core.TransitionKernelError, "audit records differ from the source operation"):
            audit_mutations(ctx, (rows[0], {**rows[1], "id": rows[0]["id"]}, *rows[2:]))

    def test_policy_operation_identity_is_exact_and_request_bound(self):
        ctx, rows = audit_context()
        class StringSubclass(str):
            pass
        for identity in (None, True, "", "caller-selected", StringSubclass(operation_id(ctx.operation)),
                operation_id("policy.activation.prepare"),
                framed("serverware.policyAuthorityOperation/v2", ctx.operation.encode(), b"sha256:" + b"f" * 64)):
            with self.assertRaisesRegex(core.TransitionKernelError, "audit event identity differs from the source operation"):
                audit_mutations(ctx, rows, identity=identity)
        with self.assertRaisesRegex(core.TransitionKernelError, "audit records differ from the source operation"):
            audit_mutations(replace(ctx, operation="policy.genesis.finalize"), rows)
        with self.assertRaisesRegex(core.TransitionKernelError, "exact row is absent or ambiguous"):
            audit_mutations(ctx, ({**rows[0], "id": "unselected"},))

    def test_quota_eight_operations_emit_one_fresh_event_without_counter(self):
        event = {"purpose": "local-component", "nested": {"v": 1}}
        expected = framed("serverware.metadataAuditOutboxEvent/v1", canonical(event))
        for operation in QUOTA_OPERATIONS:
            identity = quota._audit_query(operation, REQUEST).absent_key["id"]
            mutations, digest, replay = quota_event(context(operation, (audit_selection(identity),)))
            self.assertEqual((digest, replay, len(mutations)), (expected, False, 1))
            change = mutations[0]
            self.assertEqual((change["table"], change["operation"], change["expectedRow"]), (OUTBOX, "INSERT", None))
            self.assertEqual(change["keyDigest"], audit_selection(identity)["keyDigest"])
            self.assertEqual(change["row"]["event_json"].encode(), canonical(event))
            self.assertEqual((change["row"]["status"], change["row"]["storage_format_version"]), ("pending", 1))
            self.assertEqual(change["row"]["created_at"], NOW.isoformat())

    def test_quota_exact_replay_retains_pending_claimed_and_audited_rows(self):
        operation = "control-approval.request"
        identity = quota._audit_query(operation, REQUEST).absent_key["id"]
        fresh, digest, _ = quota_event(context(operation, (audit_selection(identity),)))
        for status in ("pending", "claimed", "audited"):
            row = {**fresh[0]["row"], "status": status, "attempts": 3}
            ctx = context(operation, (audit_selection(identity, present=True, row=row),))
            before = copy.deepcopy(ctx.selected_rows)
            self.assertEqual(quota_event(ctx), ((), digest, True))
            self.assertEqual(ctx.selected_rows, before)
            self.assertEqual(capacity.finalize_capacity(with_counter(ctx, live=5), ()), ())

    def test_quota_replay_compares_all_existing_event_identity_fields(self):
        operation = "control-approval.request"
        identity = quota._audit_query(operation, REQUEST).absent_key["id"]
        fresh, _, _ = quota_event(context(operation, (audit_selection(identity),)))
        for field in ("event_type", "actor_type", "actor_id", "event_json", "event_digest"):
            row = {**fresh[0]["row"], field: "changed"}
            with self.assertRaisesRegex(core.TransitionKernelError, "audit outbox replay conflicts with its prior event"):
                quota_event(context(operation, (audit_selection(identity, present=True, row=row),)))

    def test_quota_absence_requires_null_row_and_exact_unique_selection(self):
        operation = "control-approval.request"
        identity = quota._audit_query(operation, REQUEST).absent_key["id"]
        for row in ({}, {"id": identity}):
            with self.assertRaisesRegex(core.TransitionKernelError, "fresh audit identity is not proven absent"):
                quota_event(context(operation, (audit_selection(identity, row=row),)))
        chosen = audit_selection(identity)
        del chosen["row"]
        with self.assertRaisesRegex(core.TransitionKernelError, "fresh audit identity is not proven absent"):
            quota_event(context(operation, (chosen,)))
        chosen = audit_selection(identity)
        for selections in ((), (chosen, copy.deepcopy(chosen))):
            with self.assertRaisesRegex(core.TransitionKernelError, "exact row is absent or ambiguous"):
                quota_event(context(operation, selections))
        for value in (None, 0, 1, "false"):
            with self.assertRaises(core.TransitionKernelError):
                quota_event(context(operation, (audit_selection(identity, present=value),)))

    def test_quota_event_bound_and_fresh_metadata_validation_remain(self):
        operation = "control-approval.request"
        identity = quota._audit_query(operation, REQUEST).absent_key["id"]
        ctx = context(operation, (audit_selection(identity),))
        for event in (None, [], "event"):
            with self.assertRaisesRegex(core.TransitionKernelError, "authority audit event is not an exact object"):
                quota._audit_mutations(ctx, event_type="component", actor_type="admin", actor_id=None, event=event)
        with self.assertRaisesRegex(core.TransitionKernelError, "authority audit event exceeds its bound"):
            quota._audit_mutations(ctx, event_type="component", actor_type="admin", actor_id=None,
                                  event={"value": "x" * (2 * 1024 * 1024)})
        for event_type, actor_type in (("", "admin"), ("component", "")):
            with self.assertRaises(core.TransitionKernelError):
                quota._audit_mutations(ctx, event_type=event_type, actor_type=actor_type, actor_id=None, event={})

    def test_real_query_builders_preserve_non_audit_aggregate_queries(self):
        # Query shape only; these empty intent objects are not an authorization
        # fixture and are never passed to either kernel's transition method.
        cases = ((quota._ControlApprovalRequestKernel(), {"action": "component", "resource_id": "resource",
            "payload_digest": REQUEST, "requester_id": "actor", "request": {}, "ttl_seconds": 60,
            "require_webauthn": False, "businessIntent": {}}, "control-plane-approvals"),
            (quota._JitReviewReceiptKernel(), {"approval_request_id": "approval", "reviewer_id": "actor",
             "review_digest": REQUEST, "ttl_seconds": 60, "businessIntent": {}}, "jit-review-receipts"))
        for kernel, arguments, kind in cases:
            queries = kernel.queries(arguments=arguments, database_now=NOW, request_digest=REQUEST)
            aggregates = [query for query in queries if query.table == TABLE]
            self.assertEqual(len(aggregates), 1)
            partition = framed("serverware.policyAuthorityAggregatePartition/v1", kind.encode(), b"global")
            self.assertEqual(aggregates[0].absent_key, {"aggregate_id": kind + ":" + partition})
            self.assertEqual(sum(query.table == OUTBOX for query in queries), 1)

    def test_generic_aggregate_updates_keep_their_own_business_capacity(self):
        kind = "control-plane-approvals"
        partition = framed("serverware.policyAuthorityAggregatePartition/v1", kind.encode(), b"global")
        for limit in (3, 100_001):
            row = aggregate_row(limit=limit, live=limit-1, kind=kind, partition=partition)
            ctx = context("control-approval.request", (selection(TABLE, {"aggregate_id": row["aggregate_id"]},
                present=True, row=row),))
            change = quota._aggregate_update(ctx, kind=kind, partition="global", live_delta=1,
                active_delta=1, next_sequence_delta=1)
            self.assertEqual((change["row"]["capacity_limit"], change["row"]["live_count"]), (limit, limit))
            full = context(ctx.operation, (selection(TABLE, change["key"], present=True, row=change["row"]),))
            with self.assertRaisesRegex(core.TransitionKernelError, "bounded aggregate capacity transition is invalid"):
                quota._aggregate_update(full, kind=kind, partition="global", live_delta=1, active_delta=1)

    def test_source_links_remove_only_old_audit_selectors_and_counter_helper(self):
        # Source coverage, NOT execution of all twelve operation kernels.
        trees = [ast.parse((ROOT / "serverware" / filename).read_text())
                 for filename in ("authority_transition_policy.py", "authority_transition_quota.py")]
        names = {node.name for node in trees[0].body if isinstance(node, ast.FunctionDef)}
        self.assertNotIn("_aggregate_mutation", names)
        self.assertNotIn("_audit_capacity_mutations", names)
        callers = {node.name for node in trees[0].body if isinstance(node, ast.ClassDef)
            and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                and child.func.id == "_fresh_audit_mutations" for child in ast.walk(node))}
        self.assertEqual(callers, {"_PolicyActivationPrepareKernel", "_PolicyGenesisPrepareKernel",
                                  "_RbacBindingMutateKernel", "_PolicyActivationAbortKernel"})
        for tree in trees:
            for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
                self.assertFalse(any(isinstance(value, ast.Constant) and value.value == "audit_capacity"
                    for value in [*call.args, *(keyword.value for keyword in call.keywords)]))
        helper = next(node for node in trees[1].body if isinstance(node, ast.FunctionDef) and node.name == "_audit_mutations")
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "_aggregate_update" for node in ast.walk(helper)))
        self.assertTrue(any(isinstance(node, ast.FunctionDef) and node.name == "_aggregate_update" for node in trees[1].body))

    def test_activation_prepare_empty_replay_keeps_consumed_evidence_source_guards(self):
        # Explicitly SOURCE-ONLY: no successful signed replay is manufactured.
        kernel = policy._PolicyActivationPrepareKernel()
        self.assertIs(kernel.permits_empty_mutation, True)
        tree = ast.parse((ROOT / "serverware/authority_transition_policy.py").read_text())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == type(kernel).__name__)
        transition = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "transition")
        branches = [node for node in transition.body if isinstance(node, ast.If)
                    and ast.unparse(node.test) == "preparation_selected.get('present') is True"]
        self.assertEqual(len(branches), 1)
        branch = branches[0]
        calls = [node for node in ast.walk(branch) if isinstance(node, ast.Call)]
        named = {node.func.id for node in calls if isinstance(node.func, ast.Name)}
        self.assertTrue({"_consumed_decision_gate_statement", "_validated_input_evidence"} <= named)
        self.assertTrue(any(isinstance(node.func, ast.Attribute) and node.func.attr == "consumed_evidence" for node in calls))
        self.assertNotIn("_fresh_audit_mutations", named)
        returns = [node for node in branch.body if isinstance(node, ast.Return)]
        self.assertEqual(len(returns), 1)
        self.assertIs(returns[0], branch.body[-1])
        result = returns[0].value
        self.assertIsInstance(result, ast.Call)
        self.assertEqual(ast.unparse(result.func), "core.KernelTransition")
        keywords = {keyword.arg: keyword.value for keyword in result.keywords}
        self.assertEqual(ast.literal_eval(keywords["mutations"]), ())
        self.assertEqual(ast.literal_eval(keywords["work_units"]), 16)
        self.assertTrue(any(isinstance(node, ast.Raise) for node in ast.walk(branch)))


if __name__ == "__main__":
    unittest.main()

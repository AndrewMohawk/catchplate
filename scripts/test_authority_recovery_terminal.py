#!/usr/bin/env python3
"""Independent-tree relative effects; no SQL, complete query or witness claim.

The real membership, inline induction, templates and capacity finalizer run in
these component controls. They cannot establish original-current root custody,
complete expire/prune ranges/ranks, witnessed authorization or a public route.
"""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_recovery_terminal as terminal
from catchplate import authority_query_read_work as measured
from test_authority_audit_capacity import aggregate_row
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_digest, sql_json


NOW = datetime(2026, 1, 5, tzinfo=timezone.utc)
EARLIER = (NOW - timedelta(days=2)).isoformat()
REQUEST = "sha256:" + "1" * 64
DIGEST = "sha256:" + "2" * 64
REFUSALS = (ValueError, terminal.core.TransitionKernelError)


def meter(**limits):
    return measured._ValidationWork(measured.QueryReadValidationLimits(**limits))


def ceremony(**changes):
    value = {name: DIGEST for name in ("pending_token_digest", "oidc_token_digest", "identity_digest",
        "challenge_digest", "credential_history_digest", "trust_bundle_digest", "auth_policy_digest")}
    value.update({name: "original-" + name for name in ("nonce", "oidc_session_id", "label", "reason",
        "trust_signing_key_id", "recovery_root_key_id", "recovery_root_provider", "recovery_audience", "rp_id", "origin")})
    value.update({name: None for name in ("root_sequence", "candidate_json", "candidate_digest", "statement_json",
        "statement_digest", "authorization_json", "authorization_digest", "signature_digest", "replacement_record_id",
        "prepared_at", "consumed_at", "invalidated_at")})
    value.update(id="recovery-1", user_id="user-1", challenge_id="challenge-1", roles_json='["developer"]',
        credential_history_count=1, active_credential_count=0, trust_bundle_sequence=1, trust_bundle_rollback_epoch=0,
        status="pending_candidate", created_at=EARLIER, session_expires_at=NOW.isoformat(),
        pending_expires_at=NOW.isoformat(), expires_at=NOW.isoformat())
    value.update(changes)
    return value


def revocation(**changes):
    value = ceremony()
    for name in ("label", "challenge_id", "challenge_digest", "rp_id", "origin", "candidate_json",
            "candidate_digest", "replacement_record_id", "prepared_at", "invalidated_at"):
        value.pop(name)
    value.update(status="prepared", active_credential_count=1, root_sequence=1,
        active_credential_record_id="credential-1", active_credential_id_digest=DIGEST,
        statement_json="{}", statement_digest=DIGEST)
    value.update(changes)
    return value


def challenge(parent, **changes):
    value = dict(id="challenge-1", challenge="original-challenge", challenge_type="recovery-registration",
        user_id="user-1", scope_key="scope", approval_request_id=None, payload_json="{}",
        expires_at=NOW.isoformat(), used_at=None, created_at=EARLIER)
    value.update(changes)
    value.update({name: None for name in terminal.retention.DERIVED_FIELDS})
    value.update(retention_reference_mask=1, retention_recovery_id=parent["id"],
        retention_recovery_row_digest=sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1",
            terminal.CEREMONIES.encode("ascii"), sql_json(parent)))
    return value


def arguments():
    return dict(recovery_id="recovery-1", ceremony_type="replacement-registration",
        authorization={"statement": "original"}, authorization_digest=DIGEST,
        signature_digest="sha256:" + "3" * 64, businessIntent={"component": "only"})


def fixture(operation, target, *, phase, args=None, used=None, audit=None, live=0,
        include_challenge=True, corrupt_inline=False, work=None):
    table = terminal.REVOCATIONS if phase.startswith("revocation") or (
        args is not None and args.get("ceremony_type") == "lost-active-key-decommission") else terminal.CEREMONIES
    values = {table: [] if target is None else [target]}
    selections = {table: {"id": "recovery-1"}}
    active_invalidation = operation == terminal.recovery.INVALIDATE and target is not None and (
        target["status"] in (terminal.LIVE if table == terminal.CEREMONIES else ("prepared",)))
    if table == terminal.CEREMONIES and include_challenge and (
            operation != terminal.recovery.INVALIDATE or active_invalidation):
        joined = challenge(target, used_at=used)
        if corrupt_inline:
            joined["retention_recovery_row_digest"] = "sha256:" + "f" * 64
        values[terminal.retention.CHALLENGE_TABLE] = [joined]
        selections[terminal.retention.CHALLENGE_TABLE] = {"id": joined["id"]}
    if active_invalidation:
        values[terminal.capacity.OUTBOX_TABLE] = [] if audit is None else [audit]
        selections[terminal.capacity.OUTBOX_TABLE] = {"id": "webauthn-recovery-burned:recovery-1"}
        counter = aggregate_row(live=live)
        values[terminal.capacity.AGGREGATE_TABLE] = [counter]
        selections[terminal.capacity.AGGREGATE_TABLE] = {"aggregate_id": counter["aggregate_id"]}
    roots, readonly, selected, proofs = [], [], [], []
    for item in terminal.contracts.primary_table_contracts(operation):
        tree = IndependentTree(values.get(item.table, []), table=item.table, columns=item.key_columns, revision=7)
        (roots if item.root_class == "business" else readonly).append(tree.root)
        if item.table in selections:
            observed = tree.selected(selections[item.table])
            selected.append(observed)
            proofs.append(tree.proof(observed))
    context = terminal.core.KernelContext(operation=operation, arguments=args or {},
        selected_rows=tuple(selected), database_now=NOW, request_digest=REQUEST)
    return dict(phase=phase, context=context, business_before_roots=tuple(roots),
        authorization_before_roots=tuple(readonly), before_proofs=tuple(proofs),
        terminal_retention_seconds=86_400, maximum_retained=100, work=work or meter())


def by_table(result):
    return {item["table"]: item for item in result.mutations}


class RecoveryTerminalControls(unittest.TestCase):
    def test_expire_preserves_candidates_and_coalesce_and_rehashes_reference(self):
        for status, candidate, used in (("pending_candidate", None, None), ("prepared", '{"original":true}', EARLIER)):
            original = ceremony(status=status, candidate_json=candidate, statement_json='{"unchanged":true}')
            call = fixture(terminal.recovery.EXPIRE, original, phase="expire", used=used)
            before = copy.deepcopy(call["context"].selected_rows)
            result = terminal.evaluate_row(**call)
            changes = by_table(result)
            after = dict(original, status="expired", invalidated_at=NOW.isoformat())
            self.assertEqual(changes[terminal.CEREMONIES]["row"], after)
            joined = changes[terminal.retention.CHALLENGE_TABLE]["row"]
            self.assertEqual(joined["used_at"], NOW.isoformat() if used is None else used)
            self.assertEqual(joined["retention_recovery_row_digest"], sql_digest(
                "catchplate.policyAuthorityAuthenticatedRow/v1", terminal.CEREMONIES.encode(), sql_json(after)))
            self.assertEqual(joined["retention_reference_mask"], 1)
            self.assertEqual(call["context"].selected_rows, before)
        for original in (ceremony(status="consumed"), ceremony(expires_at=(NOW + timedelta(seconds=1)).isoformat())):
            with self.assertRaises(REFUSALS):
                terminal.evaluate_row(**fixture(terminal.recovery.EXPIRE, original, phase="expire"))

    def test_four_prune_requirements_and_real_delete_reference_induction(self):
        requirements = terminal.query_requirements(operation=terminal.recovery.PRUNE, database_now=NOW,
            terminal_retention_seconds=86_400, maximum_retained=100, work=meter())
        self.assertEqual(tuple(item.phase for item in requirements), terminal._PHASES)
        self.assertEqual(tuple(item.offset for item in requirements), (0, 100, 0, 100))
        self.assertEqual(tuple(item.after_phase for item in requirements),
            (None, "ceremony-old", "ceremony-overflow", "revocation-old"))
        self.assertEqual(tuple(item.requires_original_rank for item in requirements), (False, True, False, True))
        self.assertTrue(all(item.maximum_rows == 256 and item.requires_complete_range for item in requirements))
        for phase in terminal._PHASES:
            original = (revocation if phase.startswith("revocation") else ceremony)(status="expired",
                consumed_at=EARLIER, expires_at=NOW.isoformat())
            result = terminal.evaluate_row(**fixture(terminal.recovery.PRUNE, original, phase=phase))
            self.assertEqual(result.mutations[0]["operation"], "DELETE")
            self.assertIsNone(result.mutations[0]["row"])
            if phase.startswith("ceremony"):
                joined = by_table(result)[terminal.retention.CHALLENGE_TABLE]["row"]
                self.assertEqual(joined["retention_reference_mask"], 0)
                self.assertIsNone(joined["retention_recovery_id"])
                self.assertIsNone(joined["retention_recovery_row_digest"])
        original = ceremony(status="expired", consumed_at=NOW.isoformat(), invalidated_at=EARLIER, expires_at=EARLIER)
        with self.assertRaises(REFUSALS):
            terminal.evaluate_row(**fixture(terminal.recovery.PRUNE, original, phase="ceremony-old"))
        # Overflow derives only a relative effect: it does not assert the rank.
        terminal.evaluate_row(**fixture(terminal.recovery.PRUNE, original, phase="ceremony-overflow"))

    def test_invalidation_both_branches_and_genuine_audit_capacity(self):
        for kind, make in (("replacement-registration", ceremony), ("lost-active-key-decommission", revocation)):
            args = dict(arguments(), ceremony_type=kind)
            original = make(status="prepared")
            call = fixture(terminal.recovery.INVALIDATE, original, phase="invalidate", args=args)
            result = terminal.evaluate_row(**call)
            changes = by_table(result)
            table = terminal.CEREMONIES if kind == "replacement-registration" else terminal.REVOCATIONS
            self.assertEqual(changes[table]["row"]["status"], "invalidated" if table == terminal.CEREMONIES else "expired")
            self.assertEqual(changes[table]["row"]["authorization_json"], '{"statement":"original"}')
            self.assertEqual(changes[terminal.capacity.AGGREGATE_TABLE]["row"]["live_count"], 1)
            audit = changes[terminal.capacity.OUTBOX_TABLE]["row"]
            self.assertEqual(audit["id"], "webauthn-recovery-burned:recovery-1")
            self.assertEqual(audit["actor_id"], "user-1")
            repeated = terminal.evaluate_row(**fixture(terminal.recovery.INVALIDATE, original,
                phase="invalidate", args=args, audit=audit, live=1))
            self.assertNotIn(terminal.capacity.OUTBOX_TABLE, by_table(repeated))
            self.assertNotIn(terminal.capacity.AGGREGATE_TABLE, by_table(repeated))
            changed = dict(audit, actor_id="other-user")
            with self.assertRaises(REFUSALS):
                terminal.evaluate_row(**fixture(terminal.recovery.INVALIDATE, original,
                    phase="invalidate", args=args, audit=changed))
            with self.assertRaises(REFUSALS):
                terminal.evaluate_row(**fixture(terminal.recovery.INVALIDATE, original,
                    phase="invalidate", args=args, live=terminal.capacity.MAX_PENDING))

    def test_invalidation_absence_and_terminal_are_exact_primary_noops(self):
        for kind, make in (("replacement-registration", ceremony), ("lost-active-key-decommission", revocation)):
            args = dict(arguments(), ceremony_type=kind)
            for original in (None, make(status="expired")):
                result = terminal.evaluate_row(**fixture(terminal.recovery.INVALIDATE, original,
                    phase="invalidate", args=args))
                self.assertEqual(result.mutations, ())
                self.assertFalse(result.affected)

    def test_proof_root_inline_and_original_budget_fail_closed(self):
        for change in ("row", "proof", "root", "selector", "inline", "missing-challenge"):
            call = fixture(terminal.recovery.EXPIRE, ceremony(), phase="expire",
                corrupt_inline=change == "inline", include_challenge=change != "missing-challenge")
            if change == "row":
                call["context"].selected_rows[0]["row"]["user_id"] = "changed"
            elif change == "proof":
                call["before_proofs"][0]["rowDigest"] = "sha256:" + "f" * 64
            elif change == "root":
                call["business_before_roots"] = (replace(call["business_before_roots"][0], root_revision=8),
                    *call["business_before_roots"][1:])
            elif change == "selector":
                call["context"].selected_rows[0]["contractSelector"] = "invented"
            with self.subTest(change=change), self.assertRaises(REFUSALS):
                terminal.evaluate_row(**call)
        work = meter(max_input_bytes=1024)
        held = work.limits
        with self.assertRaises(REFUSALS):
            terminal.evaluate_row(**fixture(terminal.recovery.EXPIRE, ceremony(), phase="expire", work=work))
        self.assertIs(work.limits, held)
        for field in ("terminal_retention_seconds", "maximum_retained"):
            call = fixture(terminal.recovery.EXPIRE, ceremony(), phase="expire")
            call[field] = True
            with self.assertRaises(REFUSALS):
                terminal.evaluate_row(**call)


if __name__ == "__main__":
    unittest.main()

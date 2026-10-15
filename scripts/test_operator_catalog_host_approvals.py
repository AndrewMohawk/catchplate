#!/usr/bin/env python3
"""Focused host-approval permission tests; no provider or live workspace use."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class InputTests(unittest.TestCase):
    def test_omission_preserves_serialized_permission_and_null_is_refused(self):
        from serverware.operator_catalog_inputs import RuleInput
        values = dict(name="Exact request", expected_revision=1, expected_policy_hash="sha256:" + "0" * 64,
            application_id="00000000-0000-4000-8000-000000000001",
            credential_id="00000000-0000-4000-8000-000000000002",
            upstream_url="https://api.example.com/v1/items", methods=["GET"], response_fields=["status"])
        automatic = RuleInput(**values).model_dump()
        self.assertNotIn("approval_mode", automatic)
        reviewed = RuleInput(**values, approval_mode="host_review_v1").model_dump()
        self.assertEqual(reviewed.pop("approval_mode"), "host_review_v1")
        self.assertEqual(reviewed, automatic)
        for value in (None, False, "automatic", "native", ""):
            with self.assertRaises(ValueError):
                RuleInput(**values, approval_mode=value)

    def test_all_preset_inputs_inherit_the_same_opt_in(self):
        from serverware import operator_catalog_inputs as inputs
        for name in ("RuleInput", "GithubRuleInput", "GmailReadRuleInput", "NpmMetadataRuleInput",
                "NpmInstallRuleInput", "NpmPublishRuleInput", "XUsernameRuleInput", "XPostRuleInput",
                "AlchemyChainStatusRuleInput"):
            self.assertTrue(issubclass(getattr(inputs, name), inputs.ApprovalRuleInput), name)

    def test_marker_is_additive_and_conflicting_quota_is_refused(self):
        from serverware import operator_catalog_approvals as approval
        from serverware.operator_catalog_schema import CatalogIntegrityError
        route = {"constraints": [{"type": "responseEnvelope", "statusCodes": [200]}]}
        before = deepcopy(route)
        approval.apply({}, route)
        self.assertEqual(route, before)
        approval.apply({"approval_mode": approval.MODE}, route)
        self.assertEqual(route["constraints"], before["constraints"] + [approval.CONSTRAINT])
        for record in ({"approval_mode": None}, {"approval_mode": "automatic"},
                {"approval_mode": approval.MODE, "daily_post_attempt_limit": 10}):
            with self.assertRaises(CatalogIntegrityError):
                approval.validate(record)


def catalog_worker():
    import test_operator_catalog_github as fixture
    from serverware import operator_catalog_approvals as approval
    f = fixture.Fixture()
    credential, application = f.credential()["credential"], f.application()
    result = f.rule(application, credential)
    identifier = result["access_rule"]["id"]
    before = f.snapshot()
    settings = dict(**f.review(), id=identifier, approval_mode=approval.MODE)
    with patch.object(approval, "require_available", side_effect=ValueError("unavailable")):
        with unittest.TestCase().assertRaises(ValueError):
            f.mutations.set_rule_approval(f.inputs.RuleApprovalInput(**settings), fixture.ACTOR)
    assert f.snapshot() == before
    with patch.object(approval, "require_available", return_value=None):
        changed = f.mutations.set_rule_approval(f.inputs.RuleApprovalInput(**settings), fixture.ACTOR)
    assert changed["access_rule"]["approval_mode"] == approval.MODE
    route = f.signed()["routes"][0]
    assert route["constraints"][-1] == approval.CONSTRAINT and "jit" not in route
    with patch.object(approval, "require_available", return_value=None):
        with unittest.TestCase().assertRaises(f.schema.CatalogConflict):
            f.mutations.set_rule_approval(f.inputs.RuleApprovalInput(**settings), fixture.ACTOR)
    removed = f.mutations.set_rule_approval(f.inputs.RuleApprovalInput(**f.review(), id=identifier,
        approval_mode="automatic"), fixture.ACTOR)
    assert "approval_mode" not in removed["access_rule"]
    assert all(c["type"] != "hostTrustedApproval" for c in f.signed()["routes"][0]["constraints"])
    events = fixture.workspace.rows(f.db, "audit_events")
    assert sum(e["event_type"] == "operator_catalog.access_rule.approval_changed" for e in events) == 2
    return {"signed_enable_disable_stale_revision_and_audit": True}


class CatalogTests(unittest.TestCase):
    def setUp(self):
        import test_operator_catalog_github as fixture
        fixture.OperatorCatalogGithubTests.setUp(self)

    def test_actual_catalog_transaction_signs_and_audits_explicit_change(self):
        import test_operator_catalog_github as fixture
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, fixture.worker_failure_summary(result))
        self.assertTrue(json.loads(result.stdout)["signed_enable_disable_stale_revision_and_audit"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        import test_operator_catalog_github as fixture
        os.umask(0o077)
        try:
            print(json.dumps(catalog_worker()))
        except Exception as error:
            print(json.dumps(fixture.safe_worker_failure(error)))
            raise SystemExit(1) from None
    else:
        unittest.main(verbosity=2)

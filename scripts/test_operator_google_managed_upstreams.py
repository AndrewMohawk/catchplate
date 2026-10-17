#!/usr/bin/env python3
"""Later managed-Google restarts and reviewed upstream changes, no providers.

Runs only in the root-owned bounded network-none backend harness. Reuses the
connected managed fixture, never changes its source or substitutes successful
profile, publication, database, encryption or signed-policy guards.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import test_operator_google_managed_config as managed_tests
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = managed_tests.ACTOR
NEW_ORIGIN = "https://registry.npmjs.org"


def cancellation(_request):
    f = managed_tests.Fixture()
    prepared = f.prepare()
    cancelled = f.setup.cancel({**f.review(), "operation_id": prepared["operation_id"]}, ACTOR)
    assert cancelled["status"] == "cancelled" and f.selected() is None
    return {"operation": cancelled, "retained": f.retained(), "audit": f.rows("audit_events"),
        "settings": f.rows("operator_demo_settings")}


def cancelled_restart(request):
    f = managed_tests.Fixture()
    expected = request["operation"]
    assert f.setup.status(expected["operation_id"], ACTOR) == expected
    assert f.selected() is None and not f.profiles.selected()
    assert f.config.GOOGLE_OAUTH_CLIENT_ID == f.config.GOOGLE_OAUTH_CLIENT_SECRET == ""
    assert f.config.GOOGLE_OAUTH_CLIENT_SECRET_FILE is None
    assert not (f.config.DATA_DIR / "master.key").exists()
    try:
        f.profiles.require_profile()
    except f.profiles.OperatorGoogleProfileError:
        pass
    else:
        raise AssertionError("cancelled-only restart activated a managed profile")
    assert f.setup.review_configuration(ACTOR)["eligible"] is True
    return {"operation": expected, "retained": f.retained(), "audit": f.rows("audit_events"),
        "settings": f.rows("operator_demo_settings")}


def assert_google(f, expected):
    actual = f.setup.status(expected["operation_id"], ACTOR)
    assert actual == expected and actual["status"] == "activated" and f.selected() == actual
    assert f.profiles.require_profile().binding_digest == expected["profile_binding_digest"]
    assert f.config.GOOGLE_OAUTH_CLIENT_ID == expected["client_id"]
    assert f.config.GOOGLE_OAUTH_CLIENT_SECRET == managed_tests.SECRET
    assert f.config.GOOGLE_OAUTH_CLIENT_SECRET_FILE is None
    assert not f.provider_calls


def profile_rows(f):
    with closing(f.db.connect()) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM operator_catalog_oauth_profile")]


def prepare_upstream(request):
    f = managed_tests.Fixture()
    google = request["operation"]
    assert_google(f, google)
    from catchplate import operator_upstream_setup as upstream
    # Real nonempty resources make authority preservation a meaningful oracle.
    credential = workspace.create_credential(f.db, f.store, f.schema, f.inputs, f.mutations)["credential"]
    application = workspace.create_application(f.db, f.store, f.schema, f.inputs, f.mutations)["application"]
    workspace.create_rule(f.db, f.store, f.schema, f.inputs, f.mutations, application["id"], credential["id"])
    before, profile = f.retained(), profile_rows(f)
    review = upstream.review(ACTOR)
    assert review["eligible"] and review["old_settings"] == google["target_settings"]
    protected = {item["origin"]: item["reasons"] for item in review["protected_origins"]}
    assert "google_profile" in protected["https://gmail.googleapis.com"]
    target = [*review["old_settings"]["allowed_upstreams"], NEW_ORIGIN]
    payload = {key: review[key] for key in (
        "expected_revision", "expected_policy_hash", "expected_settings_digest")} | {
            "operation_id": str(uuid.uuid4()), "allowed_upstreams": target}
    receipt = upstream.prepare(payload, ACTOR)
    assert receipt["status"] == "pending" and receipt["activation_receipt"] is None
    assert upstream.status(receipt["operation_id"], ACTOR) == receipt
    assert receipt["target_settings"] == {**review["old_settings"], "allowed_upstreams": target}
    assert f.retained() == before and profile_rows(f) == profile
    assert f.demo.settings()["allowed_upstreams"] == review["old_settings"]["allowed_upstreams"]
    assert_google(f, google)
    if request.get("stale") == "revision":
        workspace.create_credential(f.db, f.store, f.schema, f.inputs, f.mutations,
            "Intervening static credential after reviewed upstream Prepare")
        assert f.review()["expected_policy_hash"] == receipt["policy_hash"]
    elif request.get("stale") == "policy":
        f.mutations.revoke_application(f.inputs.TargetInput(**f.review(), id=application["id"]), ACTOR)
        assert f.review()["expected_policy_hash"] != receipt["policy_hash"]
    if request.get("stale"):
        assert f.review()["expected_revision"] == receipt["revision"] + 1
    return {"operation": google, "upstream": receipt, "retained": f.retained(),
        "profile": profile_rows(f), "audit": f.rows("audit_events")}


def activate_upstream(request):
    from catchplate import operator_upstream_setup_preflight as preflight
    from catchplate import operator_catalog_oauth_profile as profiles
    original, observed = preflight.validate_before_database_initialization, []

    def metadata_only_preflight():
        with patch.object(profiles, "require_profile",
                side_effect=AssertionError("read-only preflight attempted serving-profile admission")):
            original()
        observed.append(True)

    # Observe only the real read-only preflight, not the subsequent EX startup
    # transaction where the exact provisional profile is intentionally usable.
    with patch.object(preflight, "validate_before_database_initialization", side_effect=metadata_only_preflight):
        f = managed_tests.Fixture()
    assert observed == [True]
    from catchplate import operator_upstream_setup as upstream
    google, pending = request["operation"], request["upstream"]
    assert_google(f, google)
    operation = upstream.status(pending["operation_id"], ACTOR)
    assert operation["status"] == "activated" and operation["revision"] == pending["staged_revision"] + 1
    assert operation["activation_receipt"] == {"schema": "catchplate.operatorUpstreamSetupActivation/v1",
        "operation_id": pending["operation_id"], "activated_revision": operation["revision"],
        "policy_hash": pending["policy_hash"], "settings_digest": pending["target_settings_digest"],
        "activated_at": operation["completed_at"]}
    assert f.demo.settings()["allowed_upstreams"] == pending["target_settings"]["allowed_upstreams"]
    assert f.demo.settings()["fixture_cidrs"] == pending["target_settings"]["fixture_cidrs"]
    settings, = f.rows("operator_demo_settings")
    assert json.loads(settings["settings_json"]) == pending["target_settings"]
    assert pending["target_settings"] != google["target_settings"]
    assert json.loads(os.environ["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"]) == pending["target_settings"]["allowed_upstreams"]
    assert f.retained() == request["retained"] and profile_rows(f) == request["profile"]
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    for credential in workspace.catalog(f.db, f.schema)["credentials"]:
        assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == workspace.common._PROVIDER_SECRET
    review = upstream.review(ACTOR)
    assert review["eligible"] and review["old_settings"] == pending["target_settings"]
    return {"operation": google, "upstream": operation, "retained": f.retained(),
        "profile": profile_rows(f), "audit": f.rows("audit_events")}


def refused_restart(_request):
    before = managed_tests.raw_snapshot()
    initializers, contacts = [], []

    def forbidden_initializer():
        initializers.append(True)
        raise AssertionError("refused upstream change reached generic DB initialization")

    try:
        from catchplate import operator_google_managed_config as managed
        managed.bootstrap()
        from catchplate import operator_demo
        operator_demo.activate()
        from catchplate import db, oauth
        from catchplate.control_plane_startup import validate_control_plane_startup

        def forbidden_provider(*_args, **_kwargs):
            contacts.append(True)
            raise AssertionError("refused upstream startup contacted a provider")

        with patch.object(db, "init_db", side_effect=forbidden_initializer), \
                patch.object(oauth, "request_bytes", side_effect=forbidden_provider):
            validate_control_plane_startup()
    except RuntimeError as error:
        assert str(error) in {"operator Google profile refused", "operator upstream setup preflight refused"}
    else:
        raise AssertionError("unreviewed or stale managed upstream restart was admitted")
    assert not initializers and not contacts and managed_tests.raw_snapshot() == before
    return {"refused_before_generic_DB_init": True, "retained_state_unchanged": True}


class ManagedGoogleLaterUpstreamTests(unittest.TestCase):
    def setUp(self):
        managed_tests.ManagedGoogleConfigurationTests.setUp(self)

    def worker(self, name, request=None, *, origins=None, changes=None):
        environment = {**self.environment, **(changes or {})}
        if origins is not None:
            environment["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(origins)
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            input=json.dumps(request or {}), cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        self.assertNotIn(managed_tests.SECRET, result.stdout)
        return json.loads(result.stdout)

    def google(self, changes=None):
        prepared = self.worker("prepare", changes=changes)
        return self.worker("activate", prepared, changes=changes)

    def test_cancelled_only_cold_restart_retains_history_key_and_no_active_profile(self):
        cancelled = self.worker("cancellation")
        self.assertEqual(self.worker("cancelled_restart", cancelled), cancelled)

    def test_active_managed_google_reviewed_upstream_and_current_settings_survive_two_restarts(self):
        google = self.google()
        prepared = self.worker("prepare_upstream", google)
        target = prepared["upstream"]["target_settings"]["allowed_upstreams"]
        self.worker("refused_restart", origins=[*target, "https://unprepared.example.com"])
        activated = self.worker("activate_upstream", prepared, origins=target)
        self.assertEqual(activated["audit"][:len(prepared["audit"])], prepared["audit"])
        events = [row for row in activated["audit"] if row["event_type"] == "operator_catalog.upstream_setup.activated"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["id"], "operator-upstream-setup:" + prepared["upstream"]["operation_id"] + ":activated")
        self.assertEqual(self.worker("activate_upstream", activated, origins=target), activated)

    def test_stale_reviewed_revision_and_policy_refuse_before_generic_initialization(self):
        for kind in ("revision", "policy"):
            data, provider = Path(self.scratch.name) / (kind + "-data"), Path(self.scratch.name) / (kind + "-provider")
            data.mkdir(mode=0o700)
            provider.mkdir(mode=0o700)
            changes = {"CATCHPLATE_DATA_DIR": str(data), managed_tests.KEY_DIRECTORY: str(provider)}
            google = self.google(changes)
            prepared = self.worker("prepare_upstream", {**google, "stale": kind}, changes=changes)
            self.worker("refused_restart", origins=prepared["upstream"]["target_settings"]["allowed_upstreams"],
                changes=changes)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(managed_tests.no_network)
        actions = {function.__name__: function for function in (cancellation, cancelled_restart,
            prepare_upstream, activate_upstream, refused_restart, managed_tests.prepare, managed_tests.activate)}
        result = actions[sys.argv[2]](json.loads(sys.stdin.read(131072)))
        assert managed_tests.NETWORK_ATTEMPTS == []
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)

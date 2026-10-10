#!/usr/bin/env python3
"""Real managed state/locks with synthetic gate-health transport only.

No actual gate, provider, consent or external socket is used. Each worker uses
the full managed startup/SQLite/signing/key fixture. Only HTTPConnection is
substituted; the actual bounded health reader and both local snapshots run.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import test_operator_google_managed_config as managed_tests
import test_operator_publication as coordination
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
BINARY = "sha256:" + "7" * 64
FIELDS = {"ready", "policy_hash", "loaded_policy_hash", "managed_google"}


def health(f):
    from serverware import operator_google_gate_configuration as producer
    with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        identity = producer.expected_identity(conn)
        policy = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()[0]
    assert identity["operation"] is not None
    assert f.managed.committed_identity() == {**identity["operation"],
        "profile_binding_digest": identity["profile_binding_digest"]}
    return {"ok": True, "policy_hash": policy, "data_plane_binary_digest": BINARY,
        "policy_shadow": {"managed_google": identity}}


class HealthTransport:
    """Synthetic transport, with real OS-lock observations at every request."""
    def __init__(self, f, document):
        self.f, self.document, self.connections, self.callback = f, document, [], None

    def connect(self, host, port, *, timeout):
        entry = {"requested": False, "closed": False}
        self.connections.append(entry)
        assert (host, port, timeout) == ("127.0.0.1", 9091, 1)
        assert coordination.shared_probe(self.f.config.DATA_DIR / self.f.store.operator_publication.LOCK_NAME), \
            "health transport ran under publication EX"
        transport = self

        class Response:
            status = 200

            def read(self, bound):
                assert bound == 131073
                return json.dumps(transport.document, sort_keys=True, separators=(",", ":")).encode("ascii")

        class Connection:
            def request(self, method, path, *, headers):
                assert (method, path, headers) == ("GET", "/healthz", {"Connection": "close"})
                assert not entry["requested"]
                entry["requested"] = True
                callback, transport.callback = transport.callback, None
                if callback is not None:
                    callback()

            def getresponse(self):
                assert entry["requested"]
                return Response()

            def close(self):
                assert not entry["closed"]
                entry["closed"] = True

        return Connection()

    def complete(self, *, expected=None):
        if expected is not None:
            assert len(self.connections) == expected
        assert all(entry == {"requested": True, "closed": True} for entry in self.connections)


def fixture():
    f = managed_tests.Fixture()
    from serverware import operator_google_managed_readiness as readiness
    assert f.config.EXPECTED_DATA_PLANE_BINARY_DIGEST == BINARY
    assert f.profiles.require_profile().client_id == managed_tests.CLIENT
    assert f.config.GOOGLE_OAUTH_CLIENT_SECRET == managed_tests.SECRET
    return f, readiness


def exact_and_mismatched(_request):
    f, readiness = fixture()
    expected = health(f)
    before = managed_tests.raw_snapshot()
    transport = HealthTransport(f, expected)
    with patch.object(f.store.http.client, "HTTPConnection", side_effect=transport.connect):
        result = readiness.observe()
        assert result == {"ready": True, "policy_hash": expected["policy_hash"],
            "loaded_policy_hash": expected["policy_hash"],
            "managed_google": expected["policy_shadow"]["managed_google"]}
        mutations = (
            lambda value: value.update(data_plane_binary_digest="sha256:" + "8" * 64),
            lambda value: value["policy_shadow"]["managed_google"]["operation"].update(operation_id=str(uuid.uuid4())),
            lambda value: value["policy_shadow"]["managed_google"]["operation"].update(owner_id=str(uuid.uuid4())),
            lambda value: value["policy_shadow"]["managed_google"]["operation"].update(config_version=2),
            lambda value: value["policy_shadow"]["managed_google"].update(effective_settings_digest="sha256:" + "0" * 64),
            lambda value: value["policy_shadow"]["managed_google"].update(profile_binding_digest="sha256:" + "0" * 64),
            lambda value: value["policy_shadow"].pop("managed_google"),
            lambda value: value["policy_shadow"]["managed_google"].pop("operation"),
        )
        for change in mutations:
            transport.document = deepcopy(expected)
            change(transport.document)
            assert transport.document["policy_hash"] == expected["policy_hash"]
            observed = readiness.observe()
            assert set(observed) == FIELDS and observed["ready"] is False
    transport.complete(expected=1 + len(mutations))
    assert managed_tests.raw_snapshot() == before and not f.provider_calls
    return {"exact_local_and_gate_identity_ready": True, "same_policy_mismatch_controls": len(mutations),
        "actual_health_reader": True, "retained_state_unchanged": True}


def outer_excludes_http(_request):
    f, readiness = fixture()
    transport = HealthTransport(f, health(f))
    before = managed_tests.raw_snapshot()
    with patch.object(f.store.http.client, "HTTPConnection", side_effect=transport.connect):
        with f.store.operator_publication.exclusive():
            observed = readiness.observe()
            assert set(observed) == FIELDS and observed["ready"] is False and observed["loaded_policy_hash"] is None
            assert f.store.loaded_gate_status() is None
            assert f.store.loaded_policy_hash() is None
            assert transport.connections == [], "an HTTP attempt was hidden by failure normalization"
        assert readiness.observe()["ready"] is True
    transport.complete(expected=1)
    assert managed_tests.raw_snapshot() == before
    return {"actual_outer_EX_forbids_all_health_HTTP": True, "ready_after_lock_release": True}


def changed_during_observation(_request):
    f, readiness = fixture()
    transport = HealthTransport(f, health(f))
    with patch.object(f.store.http.client, "HTTPConnection", side_effect=transport.connect):
        credential = workspace.create_credential(f.db, f.store, f.schema, f.inputs, f.mutations)["credential"]
        application = workspace.create_application(f.db, f.store, f.schema, f.inputs, f.mutations)["application"]
        transport.complete()
        transport.connections.clear()
        old_hash = f.store.get_policy_high_water()["policy_hash"]
        changed = []

        def real_policy_change():
            assert coordination.shared_probe(f.config.DATA_DIR / f.store.operator_publication.LOCK_NAME)
            receipt = workspace.create_rule(f.db, f.store, f.schema, f.inputs, f.mutations,
                application["id"], credential["id"])
            assert receipt["policy"]["policy_hash"] != old_hash
            changed.append(receipt["access_rule"]["id"])

        transport.callback = real_policy_change
        observed = readiness.observe()
        assert len(changed) == 1 and set(observed) == FIELDS and observed["ready"] is False
        assert f.store.get_policy_high_water()["policy_hash"] != old_hash
        assert 1 <= len(transport.connections) <= 3  # Mutation may itself observe gate health once.
        transport.complete()
        transport.document = health(f)
        assert readiness.observe()["ready"] is True
    transport.complete()
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == workspace.common._PROVIDER_SECRET
    assert f.config.GOOGLE_OAUTH_CLIENT_SECRET == managed_tests.SECRET and not f.provider_calls
    return {"real_catalog_policy_changed_between_snapshots": True, "stale_observation_refused": True,
        "fresh_exact_observation_ready": True}


class ConnectedManagedReadinessTests(unittest.TestCase):
    def setUp(self):
        managed_tests.ManagedGoogleConfigurationTests.setUp(self)
        self.environment.update({"SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": BINARY,
            "SERVERWARE_DECISION_GATE_BASE": "http://127.0.0.1:9091"})
        prepared = self.worker("prepare")
        self.worker("activate", prepared)

    def worker(self, name, request=None):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            input=json.dumps(request or {}), cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        self.assertNotIn(managed_tests.SECRET, result.stdout)
        return json.loads(result.stdout)

    def test_exact_pair_and_same_policy_wrong_binary_operation_settings_or_absent_fields(self):
        self.worker("exact_and_mismatched")

    def test_actual_outer_publication_EX_prevents_HTTP_without_poisoning_later_readiness(self):
        self.worker("outer_excludes_http")

    def test_real_local_policy_change_around_health_observation_cannot_be_reported_ready(self):
        self.worker("changed_during_observation")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(managed_tests.no_network)
        actions = {function.__name__: function for function in (managed_tests.prepare, managed_tests.activate,
            exact_and_mismatched, outer_excludes_http, changed_during_observation)}
        result = actions[sys.argv[2]](json.loads(sys.stdin.read(131072)))
        assert managed_tests.NETWORK_ATTEMPTS == []
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)

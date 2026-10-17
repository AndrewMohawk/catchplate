#!/usr/bin/env python3
"""Catalog refresh components, with actual local state and synthetic gate HTTP.

These offline workers reuse the real SQLite/signing/managed-startup fixtures.
Only HTTPConnection is substituted. Timings include an explicit synthetic
transport delay; they are not live app, provider or native acceptance evidence.
"""
from contextlib import closing, contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_operator_catalog_github as shared
import test_operator_google_managed_readiness_connected as connected
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
OTHER = "sha256:" + "9" * 64
X = {"schema": "catchplate.operatorXAppReadGate/v1", "adapter": "x.app_read.v1", "operation": "x.username.read"}
ALCHEMY = {"schema": "catchplate.operatorAlchemyRpcReadGate/v1", "adapter": "alchemy.rpc_read.v1", "operation": "alchemy.rpc.read"}


def check(value, message):
    if not value:
        raise AssertionError(message)


class Transport(connected.HealthTransport):
    """Keep the real bounded reader and actual publication-lock probe."""
    delay = 0

    def connect(self, *args, **kwargs):
        time.sleep(self.delay)
        return super().connect(*args, **kwargs)


def fixture(managed=False):
    f = connected.fixture()[0] if managed else shared.Fixture()
    base = connected.health(f) if managed else {
        "ok": True, "policy_hash": f.store.get_policy_high_water()["policy_hash"]}
    value = {**base, "operator_x_app_read": dict(X), "operator_alchemy_rpc_read": dict(ALCHEMY)}
    return f, Transport(f, value)


@contextmanager
def observed(f, transport):
    with patch.object(f.config, "DECISION_GATE_BASE", "http://127.0.0.1:9091"), \
            patch.object(f.store.http.client, "HTTPConnection", side_effect=transport.connect):
        try:
            yield
        finally:
            transport.complete()


def status(f, *, active, x, alchemy):
    result = f.mutations.catalog_status()
    check(result["policy"]["activation"] == ("active" if active else "pending"), "policy activation changed")
    check((result["capabilities"]["x"] is not None) == x, "X display availability changed")
    check((result["capabilities"]["alchemy"] is not None) == alchemy, "Alchemy display availability changed")
    return result


def without_time(value):
    value = deepcopy(value)
    value["observed_activity"].pop("observed_at_epoch_ms")
    return value


def one_read(_request, *, managed=False):
    from catchplate import operator_catalog_x as x, operator_catalog_alchemy as alchemy
    from catchplate import operator_google_managed_readiness as readiness
    f, transport = fixture(managed)
    before = workspace.snapshot(f.db, catalog=True)
    original = readiness._snapshot
    transport.delay = 0.04
    timings = {"previous_ms": [], "shared_ms": []}

    def previous(state):
        # The exact former three production observations, not a fake result.
        policy = f.mutations._policy_observation(state)
        return (policy, x.capability(state["policy_hash"]) is not None,
            alchemy.capability(state["policy_hash"]) is not None, False, False, False, False)

    with observed(f, transport):
        for _ in range(3):
            count = len(transport.connections)
            with patch.object(readiness, "_snapshot", wraps=original) as snapshots, \
                    patch.object(f.mutations, "_catalog_observation", side_effect=previous):
                start = time.monotonic()
                old = status(f, active=True, x=True, alchemy=True)
                timings["previous_ms"].append((time.monotonic() - start) * 1000)
                check(snapshots.call_count == (6 if managed else 0), "former snapshot count changed")
            check(len(transport.connections) - count == 3, "former path no longer reads three times")
            count = len(transport.connections)
            with patch.object(readiness, "_snapshot", wraps=original) as snapshots:
                start = time.monotonic()
                current = status(f, active=True, x=True, alchemy=True)
                timings["shared_ms"].append((time.monotonic() - start) * 1000)
                check(snapshots.call_count == (2 if managed else 0), "shared managed bracketing changed")
            check(len(transport.connections) - count == 1, "catalog repeated its gate read")
            check(without_time(old) == without_time(current), "public catalog changed beyond observation time")
    check(workspace.snapshot(f.db, catalog=True) == before, "read-only catalog mutated retained rows")
    return {"managed": managed, "synthetic_delay_ms": 40, "samples_per_path": 3,
        "previous_reads": 3, "shared_reads": 1,
        **{key: round(statistics.median(value), 3) for key, value in timings.items()}}


def markers(_request, *, managed=False):
    f, transport = fixture(managed)
    good = deepcopy(transport.document)
    with observed(f, transport):
        for key in ("operator_x_app_read", "operator_alchemy_rpc_read"):
            for marker in (None, {}, True, {**good[key], "extra": True}, {**good[key], "adapter": "old"}):
                transport.document = {**good, key: marker}
                count = len(transport.connections)
                status(f, active=True, x=key != "operator_x_app_read", alchemy=key != "operator_alchemy_rpc_read")
                check(len(transport.connections) - count == 1, "optional marker caused another read")
        transport.document = good
        status(f, active=True, x=True, alchemy=True)
    return {"independent_optional_markers": True}


def unavailable(_request, *, managed=False):
    f, transport = fixture(managed)
    good = deepcopy(transport.document)
    with observed(f, transport):
        for change in ({"ok": False}, {"policy_hash": OTHER}):
            transport.document = {**good, **change}
            count = len(transport.connections)
            status(f, active=False, x=False, alchemy=False)
            check(len(transport.connections) - count == 1, "failure retried health")
        transport.document = good
        def failed():
            raise OSError("synthetic transport unavailable")
        transport.callback = failed
        count = len(transport.connections)
        status(f, active=False, x=False, alchemy=False)
        check(len(transport.connections) - count == 1, "transport failure retried")
        with f.store.operator_publication.exclusive():
            count = len(transport.connections)
            status(f, active=False, x=False, alchemy=False)
            check(len(transport.connections) == count, "HTTP attempted under inherited publication EX")
        status(f, active=True, x=True, alchemy=True)
    return {"no_retry_or_locked_http": True}


def local_fence(_request, *, managed=False):
    f, transport = fixture(managed)
    initial = transport.document["policy_hash"]
    def replace_hash(value):
        with closing(f.db.connect()) as conn, conn:
            conn.execute("UPDATE operator_demo_policy SET policy_hash=? WHERE singleton=1", (value,))
    with observed(f, transport):
        # A new consistent gate/current hash is not the serialized catalog hash.
        transport.document["policy_hash"] = OTHER
        transport.callback = lambda: replace_hash(OTHER)
        try:
            result = status(f, active=False, x=False, alchemy=False)
            check(result["policy"]["policy_hash"] == initial, "catalog snapshot was silently replaced")
        finally:
            replace_hash(initial)
            transport.document["policy_hash"] = initial
        original = f.db.metadata_connection
        closed = []
        @contextmanager
        def failed_close():
            with original() as conn:
                yield conn
            closed.append(conn)
            raise OSError("synthetic local fence close failure")
        with patch.object(f.db, "metadata_connection", side_effect=failed_close):
            result = status(f, active=False, x=False, alchemy=False)
        check(closed and result["policy"]["loaded_policy_hash"] == initial, "failed fence diagnostic lost")
        import sqlite3
        try:
            closed[-1].execute("SELECT 1")
        except sqlite3.ProgrammingError:
            pass
        else:
            raise AssertionError("owned local fence handle was not closed")
        status(f, active=True, x=True, alchemy=True)
    return {"snapshot_and_owned_close_fences": True}


def fresh_mutations(_request):
    from catchplate import operator_catalog_x as x, operator_catalog_alchemy as alchemy
    f, transport = fixture()
    before = workspace.snapshot(f.db, catalog=True)
    with observed(f, transport):
        result = status(f, active=True, x=True, alchemy=True)
        policy_hash = result["policy"]["policy_hash"]
        review = {"expected_revision": result["revision"], "expected_policy_hash": policy_hash}
        for provider, key, create, payload in (
                (x, "operator_x_app_read", f.mutations.create_x_credential,
                    f.inputs.XAppBearerInput(**review, name="Synthetic X", secret="synthetic_token")),
                (alchemy, "operator_alchemy_rpc_read", f.mutations.create_alchemy_credential,
                    f.inputs.AlchemyKeyInput(**review, name="Synthetic Alchemy", secret="synthetic_token"))):
            count = len(transport.connections)
            check(provider.capability(policy_hash) == provider._capability(), "standalone display changed")
            transport.document.pop(key)
            with patch.object(f.mutations, "_mutate", side_effect=AssertionError("mutation started before admission")) as mutate:
                try:
                    create(payload, "synthetic-observation-test")
                except f.schema.CatalogConflict:
                    pass
                else:
                    raise AssertionError("stale catalog capability authorized mutation")
                mutate.assert_not_called()
            check(len(transport.connections) - count == 2, "standalone capability/mutation reused catalog read")
    check(workspace.snapshot(f.db, catalog=True) == before, "refused admission mutated rows")
    return {"no_cross_request_or_mutation_cache": True}


def managed_drift(_request):
    f, transport = fixture(True)
    good = deepcopy(transport.document)
    with observed(f, transport):
        for key in ("operation", "effective_settings_digest", "profile_binding_digest"):
            changed = deepcopy(good)
            identity = changed["policy_shadow"]["managed_google"]
            if key == "operation":
                identity[key]["config_version"] += 1
            else:
                identity[key] = OTHER
            transport.document = changed
            status(f, active=False, x=False, alchemy=False)
        transport.document = {**good, "data_plane_binary_digest": OTHER}
        status(f, active=False, x=False, alchemy=False)
        transport.document = good
        old = f.config.EXPECTED_DATA_PLANE_BINARY_DIGEST
        transport.callback = lambda: setattr(f.config, "EXPECTED_DATA_PLANE_BINARY_DIGEST", OTHER)
        try:
            status(f, active=False, x=False, alchemy=False)
        finally:
            f.config.EXPECTED_DATA_PLANE_BINARY_DIGEST = old
        status(f, active=True, x=True, alchemy=True)
    return {"actual_managed_snapshot_and_binary_guards": True}


OPERATIONS = {function.__name__: function for function in
    (one_read, markers, unavailable, local_fence, fresh_mutations, managed_drift)}
OPERATIONS.update({"managed_" + name: lambda request, function=function: function(request, managed=True)
    for name, function in tuple(OPERATIONS.items()) if name in {"one_read", "markers", "unavailable", "local_fence"}})
OPERATIONS.update({"prepare": connected.managed_tests.prepare, "activate": connected.managed_tests.activate})


class CatalogObservationTests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def worker(self, name, request=None):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            input=json.dumps(request or {}), cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-35:]))
        return json.loads(result.stdout)

    def test_one_read_preserves_projection_and_measures_delayed_transport(self):
        print("CATALOG_OBSERVATION_TIMING=" + json.dumps(self.worker("one_read"), sort_keys=True), flush=True)

    def test_optional_markers_fail_independently(self): self.worker("markers")
    def test_transport_failure_and_inherited_lock_do_not_retry(self): self.worker("unavailable")
    def test_final_local_policy_and_close_failure_fence(self): self.worker("local_fence")
    def test_mutation_and_standalone_capability_remain_fresh(self): self.worker("fresh_mutations")


class ManagedCatalogObservationTests(CatalogObservationTests):
    def setUp(self):
        connected.ConnectedManagedReadinessTests.setUp(self)

    def test_one_read_preserves_projection_and_measures_delayed_transport(self):
        print("CATALOG_OBSERVATION_TIMING=" + json.dumps(self.worker("managed_one_read"), sort_keys=True), flush=True)

    def test_optional_markers_fail_independently(self): self.worker("managed_markers")
    def test_transport_failure_and_inherited_lock_do_not_retry(self): self.worker("managed_unavailable")
    def test_final_local_policy_and_close_failure_fence(self): self.worker("managed_local_fence")
    def test_mutation_and_standalone_capability_remain_fresh(self): self.worker("managed_drift")


if __name__ == "__main__":
    if sys.flags.optimize or os.getenv("PYTHONOPTIMIZE", "") not in {"", "0"}:
        raise SystemExit("catalog observation tests require assertions enabled")
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(connected.managed_tests.no_network)
        outcome = OPERATIONS[sys.argv[2]](json.loads(sys.stdin.read(131072)))
        check(connected.managed_tests.NETWORK_ATTEMPTS == [], "worker attempted network contact")
        print(json.dumps(outcome, sort_keys=True))
    else:
        unittest.main(verbosity=2)

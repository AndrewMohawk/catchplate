#!/usr/bin/env python3
"""Real SQLite/custody/publication X manifest controls in disposable workers.

No provider, Rust, or deployed acceptance. Successful owners are real; only
failure-only secret access/file publication seams are injected. Network denied.
"""
from contextlib import closing, ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_x_configuration as fixture

ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def project(config, db):
    from serverware import operator_x_gate_configuration as public, operator_publication as publication
    from serverware import operator_provider_key as keys, operator_x_provider_custody as custody
    before = fixture.snapshot(config), fixture.key_snapshot()
    with publication.exclusive(), closing(db.connect()) as conn, ExitStack() as stack:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        for module, names in ((keys, ("read_existing_pinned", "initialize_first_x")),
                (custody, ("read_secret", "open_x"))):
            for name in names:
                stack.enter_context(patch.object(module, name, side_effect=AssertionError("projection accessed secret")))
        value = public.record(conn)
        assert public.expected_identity(conn) == {key: value[key] for key in (
            "operation", "profile_binding_digest", "effective_settings_digest")}
        assert conn.total_changes == 0 and conn.in_transaction
    assert (fixture.snapshot(config), fixture.key_snapshot()) == before
    assert set(value) == {"schema", "operation", "profile_binding", "profile_binding_digest",
        "effective_settings", "effective_settings_digest"}
    assert value["schema"] == public.SCHEMA and len(canonical(value)) <= public.MAX_BYTES
    assert value["effective_settings_digest"] == "sha256:" + hashlib.sha256(canonical(value["effective_settings"])).hexdigest()
    assert fixture.SECRET.encode() not in canonical(value)
    if value["profile_binding"] is not None:
        assert len(value["profile_binding"]) == 13
        assert value["profile_binding_digest"] == "sha256:" + hashlib.sha256(canonical(value["profile_binding"])).hexdigest()
    return value


def exported(config, value):
    target = config.DATA_DIR / "gate-runtime" / "operator-x-configuration.json"
    info = target.lstat()
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.geteuid() and info.st_nlink == 1
    assert target.read_bytes() == canonical(value)
    assert (target.parent / "policy-bundle.json").read_bytes() == config.POLICY_BUNDLE_PATH.read_bytes()
    return target


def lifecycle():
    config, db, store, _, service = fixture.fixture()
    initial = project(config, db)
    assert initial["operation"] is initial["profile_binding"] is initial["profile_binding_digest"] is None
    exported(config, initial)
    assert fixture.key_snapshot() == {}
    before_policy = config.POLICY_BUNDLE_PATH.read_bytes()
    command = fixture.payload(service)
    operation = service.configure(command, fixture.ACTOR)
    configured = project(config, db)
    assert configured["operation"]["operation_id"] == operation["operation_id"]
    assert configured["operation"]["config_version"] == 1
    assert configured["effective_settings"] == initial["effective_settings"]
    assert config.POLICY_BUNDLE_PATH.read_bytes() == before_policy
    target = exported(config, configured)
    identity = target.stat().st_ino
    store.materialize()
    assert exported(config, configured).stat().st_ino == identity
    assert "https://api.x.com" not in configured["effective_settings"]["allowed_upstreams"]
    from serverware import operator_x_readiness as readiness
    local = readiness._snapshot()
    assert not local["destination_allowed"]
    health = {"ok": True, "policy_hash": local["policy_hash"],
        "data_plane_binary_digest": local["expected_binary_digest"],
        "policy_shadow": {"managed_x": local["managed_x"]},
        "operator_x_post": {"schema": "serverware.operatorXPostGate/v1", "adapter": "x.post.v1", "operation": "tweets.write"}}
    assert readiness.observe_health(health)["ready"] is False
    return {"configured_publication": True, "origin_added": False, "secret_reads": 0}


def publication_failure():
    config, db, store, _, service = fixture.fixture()
    from serverware import operator_gate_publication as writer
    initial = project(config, db)
    target = exported(config, initial)
    actual = writer._replace_publication
    def fail_x(path, raw, **options):
        if path.name == "operator-x-configuration.json":
            raise OSError("private-publication-failure")
        return actual(path, raw, **options)
    command = fixture.payload(service)
    with patch.object(writer, "_replace_publication", side_effect=fail_x):
        operation = service.configure(command, fixture.ACTOR)
    assert target.read_bytes() == canonical(initial)
    snapshot = fixture.snapshot(config), fixture.key_snapshot(), target.read_bytes()
    assert service.status(operation["operation_id"], fixture.ACTOR)["operation_id"] == operation["operation_id"]
    assert service.configuration(fixture.ACTOR)["consent_ready"] is False
    assert (fixture.snapshot(config), fixture.key_snapshot(), target.read_bytes()) == snapshot
    fixture.refused(lambda: service.configure(command, fixture.ACTOR), service.catalog.CatalogConflict)
    configured = project(config, db)
    store.materialize()
    exported(config, configured)
    assert (fixture.snapshot(config), fixture.key_snapshot()) == snapshot[:2]
    return {"commit_retained": True, "get_repair": False, "existing_publisher_recovery": True}


def admission():
    config, db, _, _, _ = fixture.fixture()
    from serverware import operator_x_gate_configuration as public, operator_publication as publication
    with closing(db.connect()) as conn:
        conn.execute("BEGIN")
        fixture.refused(lambda: public.record(conn), public.GateConfigurationUnavailable)
    with publication.exclusive(), closing(db.connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        fixture.refused(lambda: public.record(conn), public.GateConfigurationUnavailable)
    # Retained origin/fixture settings must use the original exact decoder.
    with publication.exclusive(), closing(db.connect()) as conn, conn:
        conn.execute("UPDATE operator_demo_settings SET settings_json=? WHERE singleton=1", ('{"allowed_upstreams":[]}',))
    with publication.exclusive(), closing(db.connect()) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        fixture.refused(lambda: public.record(conn), public.GateConfigurationUnavailable)
    return {"unowned_writable_and_malformed_settings_refused": True}


class GateConfigurationTests(unittest.TestCase):
    def setUp(self):
        fixture.XConfigurationTests.setUp(self)
        # Explicit synthetic local binary identity; no compiled-gate claim.
        self.environment["SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"] = "sha256:" + "f" * 64

    def worker(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        self.assertNotIn(fixture.SECRET, result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-35:]))
        return json.loads(result.stdout)

    def test_real_first_save_public_manifest_no_origin_or_policy_change(self):
        self.assertTrue(self.worker("lifecycle")["configured_publication"])

    def test_publication_failure_retains_commit_and_get_never_repairs(self):
        self.assertFalse(self.worker("publication-failure")["get_repair"])

    def test_exact_projection_owner_and_retained_settings(self):
        self.assertTrue(self.worker("admission")["unowned_writable_and_malformed_settings_refused"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(fixture.no_network)
        result = {"lifecycle": lifecycle, "publication-failure": publication_failure, "admission": admission}[sys.argv[2]]()
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)

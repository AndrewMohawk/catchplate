#!/usr/bin/env python3
"""Small deterministic operator-profile admission and health-boundary controls."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class OperatorDemoProfileTests(unittest.TestCase):
    def environment(self, directory):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("SERVERWARE_")}
        environment.update(SERVERWARE_OPERATOR_DEMO="1", SERVERWARE_RELEASE_CHANNEL="dev",
            SERVERWARE_PROCESS_MODE="serverware-control-plane", SERVERWARE_METADATA_STORE_BACKEND="sqlite",
            SERVERWARE_AUDIT_STORE_BACKEND="sqlite", SERVERWARE_GRANT_STORE_BACKEND="sqlite",
            SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED="0", SERVERWARE_KEY_RELEASE_REQUIRED="0",
            SERVERWARE_DATA_DIR=directory, SERVERWARE_OPERATOR_DEMO_UPSTREAMS='["https://api.example.com"]',
            SERVERWARE_OPERATOR_DEMO_PROXY_URL="https://proxy.example.com")
        return environment

    def run_profile(self, directory, changes=None, operation="active"):
        environment = self.environment(directory)
        environment.update(changes or {})
        return subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=15)

    def test_origin_and_literal_path_contract(self):
        from serverware.operator_demo import origin
        for spelling in ("https://api.example.com", "https://api.example.com/", "https://api.example.com:443/"):
            self.assertEqual(origin(spelling)[0], "https://api.example.com")
        self.assertEqual(origin("https://api.example.com/v1/data", target=True)[1], "/v1/data")
        for value in ("http://api.example.com", "https://user@api.example.com", "https://127.0.0.1",
                      "https://api.example.com:8443", "https://-api.example.com", "https://api..example.com",
                      "https://api.local", "https://api.test", "https://api.invalid", "https://api.example.com#x",
                      "https://api.example.com?q=x", "https://API.example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                origin(value)
        for path in ("/*", "/a/{id}", "/a/%2f", "/a/../b", "/a\\b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                origin("https://api.example.com" + path, target=True)

    def test_production_native_provider_and_mixed_profiles_refused(self):
        for change in ({"SERVERWARE_RELEASE_CHANNEL": "production"}, {"SERVERWARE_PRODUCTION_IMAGE": "1"},
                       {"SERVERWARE_DEVELOPMENT_SANDBOX": "1"}, {"SERVERWARE_CONTROL_PLANE_CUSTODY_CONFIG_FD": "4"},
                       {"SERVERWARE_GOOGLE_CLIENT_SECRET": "synthetic-forbidden"},
                       {"SERVERWARE_POLICY_AUTHORITY_SOCKET_PATH": "/not-used"}):
            with self.subTest(selection=next(iter(change))), tempfile.TemporaryDirectory() as directory:
                target = str(Path(directory) / "data")
                result = self.run_profile(target, change)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(Path(target).exists())

    def test_private_marker_restart_and_configuration_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            target = str(Path(directory) / "data")
            for operation in ("active", "active", "changed", "stale-pid"):
                result = self.run_profile(target, operation=operation)
                self.assertEqual(result.returncode, 0, result.stderr)
            marker = Path(target) / ".serverware-operator-demo.json"
            self.assertEqual(marker.read_bytes(), b'{"schema": "serverware.operatorDemo/v1", "syntheticOnly": false}\n')
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def test_unmarked_data_and_broad_fixture_ranges_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            preserved = Path(directory) / "existing.txt"
            preserved.write_text("preserve")
            self.assertEqual(self.run_profile(directory).returncode, 2)
            self.assertEqual(preserved.read_text(), "preserve")
        for cidr in ("172.16.0.0/16", "169.254.1.1/32", "100.64.0.1/32", "240.0.0.1/32", "8.8.8.8/32"):
            with self.subTest(cidr=cidr), tempfile.TemporaryDirectory() as directory:
                result = self.run_profile(str(Path(directory) / "data"), {
                    "SERVERWARE_OPERATOR_DEMO_UPSTREAMS": '["https://demo-upstream:8443"]',
                    "SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS": json.dumps([cidr])})
                self.assertEqual(result.returncode, 2)

    def test_unusable_health_dependency_is_pending_not_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_profile(str(Path(directory) / "data"), operation="health")
            self.assertEqual(result.returncode, 0, result.stderr)


def worker(operation):
    from serverware import operator_demo
    assert not operator_demo.active(), "environment alone activated operator profile"
    try:
        operator_demo.activate()
    except (ValueError, RuntimeError, OSError):
        raise SystemExit(2) from None
    assert operator_demo.active()
    if operation == "health":
        from serverware import config, operator_demo_store as store
        with patch.object(config, "DECISION_GATE_BASE", "http://127.0.0.1:invalid"):
            assert store.loaded_policy_hash() is None
        class Reply:
            status = 200
            body = b"null"
            def read(self, maximum):
                return self.body[:maximum]
        class Client:
            def __init__(self, *args, **kwargs): pass
            def request(self, *args, **kwargs): pass
            def getresponse(self): return Reply()
            def close(self): pass
        with patch.object(config, "DECISION_GATE_BASE", "http://127.0.0.1:9091"), patch.object(store.http.client, "HTTPConnection", Client):
            for value in (None, [], "text", True, {"ok": True}, {"ok": True, "policy_hash": []}):
                Reply.body = json.dumps(value).encode()
                assert store.loaded_policy_hash() is None
            Reply.body = json.dumps({"ok": True, "policy_hash": "sha256:" + "a" * 64}).encode()
            assert store.loaded_policy_hash() == "sha256:" + "a" * 64
            Reply.status = 503
            assert store.loaded_policy_hash() is None
        return
    if operation == "changed":
        os.environ["SERVERWARE_OPERATOR_DEMO_PROXY_URL"] = "https://other.example.com"
    elif operation == "stale-pid":
        os.environ["SERVERWARE_CONTROL_PLANE_STARTUP_VALIDATED_PID"] = "0"
    if operation != "active":
        try:
            operator_demo.active()
        except RuntimeError:
            return
        raise AssertionError("changed operator profile remained active")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(sys.argv[2])
    else:
        unittest.main()

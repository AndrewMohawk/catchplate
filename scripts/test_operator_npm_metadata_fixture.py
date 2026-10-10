#!/usr/bin/env python3
"""Pure npm fixture/oracle tests: no Docker, process execution, DNS or sockets."""
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import check_operator_npm_metadata as check
from scripts import operator_npm_metadata_fixture as registry
from scripts import operator_npm_metadata_fixture_network as network
from scripts import prepare_operator_npm_metadata_fixture as recipe

SOURCE, BINARY, INITIALIZER, NODE, NPM = map(Path, ("/synthetic/source", "/synthetic/gate", "/synthetic/init.py", "/synthetic/node", "/synthetic/npm"))
ROOT = recipe.base.SCRATCH / "serverware-npm-metadata-private.Source01"
SCOPE = ("principal-fixture", "route-fixture", "sha256:" + "a" * 64)
CREDENTIAL = "credential-fixture"


def build():
    return recipe.build(SOURCE, BINARY, INITIALIZER, ROOT, NODE, NPM, expected_binary_sha256="a" * 64)


def fields(spec):
    result = [("host", "registry.npmjs.org"), ("authorization", "Bearer " + registry.TOKEN),
        ("accept", spec["accept"]), ("pacote-version", "21.0.4"), ("pacote-req-type", "packument"),
        ("pacote-pkg-id", "registry:" + spec["package"]), ("connection", "close")]
    if spec["client"] == "npm":
        result += [("npm-command", "view"), ("npm-auth-type", "web"),
            ("user-agent", "npm/11.8.0 node/v25.5.0 linux x64 workspaces/false")]
    else:
        result += [("user-agent", "pacote/21.0.4 node/v25.5.0")]
    return result


def wire_items():
    result = []
    for spec in registry.SPECS:
        row = {"case": spec["case"], "requestHeaders": registry.validate_headers(fields(spec), spec)}
        request, operation = check.canonical_digests(row, SCOPE, CREDENTIAL, "127.0.0.1")
        result.append({"case": spec["case"], "requestDigest": request, "operationDigest": operation,
            "upstreamStatus": spec["status"], "responseBodySha256": check.digest(spec["body"]),
            "responseBodyBytes": len(spec["body"])})
    return result


def audit_rows(items):
    result = []
    for index, item in enumerate(items):
        attempt = check.digest(str(index).encode())
        common = {"attempt_id": attempt, "flow_id": attempt, "principal_id": SCOPE[0],
            "route_id": SCOPE[1], "policy_hash": SCOPE[2], "credential_ref": CREDENTIAL,
            "credential_version": 1, "method": "GET", "body_sha256": check.digest(b""),
            "request_digest": item["requestDigest"], "operation_digest": item["operationDigest"]}
        result.append({"id": index * 2, "event_type": check.START, "event": {**common, "outcome": "release_started"}})
        blocked = item["case"] in check.BLOCK_ERRORS
        validation = ({"error": check.BLOCK_ERRORS[item["case"]]} if blocked else
            {"ok": True, "mode": "npmMetadataJsonV1", "adapter": "npm.metadata.v1", "body_bytes_preserved": True,
                "allowed_fields_redacted": False})
        result.append({"id": index * 2 + 1, "event_type": check.BLOCK if blocked else check.RELEASE,
            "event": {**common, "outcome": "blocked" if blocked else "released", "upstream_status": item["upstreamStatus"],
                "response_validation": validation, "response_body_sha256": item["responseBodySha256"],
                "response_body_bytes": item["responseBodyBytes"]}})
    return result


class NpmMetadataFixtureTests(unittest.TestCase):
    def setUp(self):
        guard = ExitStack(); self.addCleanup(guard.close)
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen", "subprocess.run"):
            guard.enter_context(patch(target, side_effect=AssertionError("pure fixture test attempted runtime I/O")))

    def test_network_none_topology_and_mounts(self):
        config = build(); services = config["services"]
        attached = {"serverware", "decision-gate-rs", "npm-registry", "edge", "check"}
        self.assertEqual(set(config), {"name", "services"})
        self.assertEqual(set(services), attached | {"initialize", "npm-pki", "basic-pki", "network"})
        recipe.validate(config, SOURCE, BINARY, INITIALIZER, ROOT, NODE, NPM, expected_binary_sha256="a" * 64)
        for name, service in services.items():
            self.assertEqual(service["network_mode"], "service:network" if name in attached else "none")
            for field in ("networks", "ports", "expose", "extra_hosts", "dns", "privileged", "devices", "pid", "ipc", "env_file"):
                self.assertNotIn(field, service)
            self.assertEqual(service["pull_policy"], "never")
            self.assertEqual(service["restart"], "no")
            self.assertTrue(service["read_only"])
            self.assertIn("ALL", service["cap_drop"])
            mounts = service["volumes"]
            self.assertEqual(len(mounts), len({mount["target"] for mount in mounts}))
        mounts = {row["target"]: row for row in services["check"]["volumes"]}
        self.assertNotIn("/data", mounts)
        self.assertEqual({target for target, row in mounts.items() if not row["read_only"]}, {"/client-work"})
        self.assertEqual(mounts["/node"]["source"], str(NODE))
        self.assertEqual(mounts["/npm"]["source"], str(NPM))
        changed = deepcopy(config); changed["services"]["check"]["network_mode"] = "host"
        with self.assertRaises(ValueError):
            recipe.validate(changed, SOURCE, BINARY, INITIALIZER, ROOT, NODE, NPM, expected_binary_sha256="a" * 64)

    def test_kernel_isolation_predicate_rejects_external_interface_route(self):
        files = {"/proc/net/route": "Iface Destination Gateway Flags RefCnt Use Metric Mask\n",
            "/proc/net/ipv6_route": "", "/proc/sys/net/ipv4/ip_nonlocal_bind": "0\n"}
        with patch.object(network.socket, "if_nameindex", return_value=[(1, "lo")]) as interfaces, \
                patch.object(Path, "read_text", autospec=True, side_effect=lambda path, **_: files[str(path)]):
            network.assert_isolated_network(attached=False)
            interfaces.return_value = [(1, "lo"), (2, "eth0")]
            with self.assertRaises(ValueError): network.assert_isolated_network(attached=False)
            interfaces.return_value = [(1, "lo")]
            files["/proc/net/route"] += "lo 00000000 00000000 0001 0 0 0 00000000\n"
            with self.assertRaises(ValueError): network.assert_isolated_network(attached=False)
        self.assertIn(b"93.184.216.34 registry.npmjs.org\n", network.HOSTS)
        self.assertEqual(network.RESOLV, b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")

    def test_seven_fixed_responses_full_corgi_and_hostile_controls(self):
        self.assertEqual([spec["case"] for spec in registry.SPECS], ["npm_unscoped", "npm_scoped", "pacote_unscoped",
            "pacote_scoped", "not_found", "wrong_package", "reflection"])
        for spec in registry.SPECS[:4]:
            document = json.loads(spec["body"])
            self.assertEqual(document, registry.metadata(spec["package"]))
            self.assertEqual(set(document["versions"]), {"1.0.0", "2.0.0"})
            self.assertEqual(spec["target"], registry.path(spec["package"]))
            self.assertEqual(spec["contentType"], "application/vnd.npm.install-v1+json" if spec["client"] == "pacote" else "application/json")
            self.assertNotIn(registry.TOKEN.encode(), spec["body"])
            self.assertLess(len(spec["body"]), 1048576)
        self.assertEqual(registry.SPECS[4]["status"], 404)
        self.assertNotEqual(json.loads(registry.SPECS[5]["body"])["name"], registry.SPECS[5]["package"])
        self.assertIn(registry.TOKEN.encode(), registry.SPECS[6]["body"])
        self.assertEqual(registry.path(registry.PACKAGES[1]), "/@serverware-fixture%2fmetadata")

    def test_all_parsed_headers_and_no_secret_observations(self):
        for spec in registry.SPECS:
            admitted = registry.validate_headers(fields(spec), spec)
            self.assertNotIn("authorization", admitted)
            self.assertNotIn(registry.TOKEN, json.dumps(admitted))
            for extra in [("authorization", "Bearer other"), ("accept-encoding", "gzip"), ("npm-session", "random"),
                    ("x-extra", "not admitted"), ("host", "other.example")]:
                with self.subTest(case=spec["case"], extra=extra[0]), self.assertRaises(ValueError):
                    registry.validate_headers(fields(spec) + [extra], spec)
            changed = [(name, "Bearer wrong" if name == "authorization" else value) for name, value in fields(spec)]
            with self.assertRaises(ValueError): registry.validate_headers(changed, spec)

    def test_independent_v2_commitments_repeated_requests_not_attempts(self):
        items = wire_items()
        self.assertEqual(items[0]["requestDigest"], items[4]["requestDigest"])
        self.assertEqual(items[0]["requestDigest"], items[5]["requestDigest"])
        self.assertEqual(items[1]["requestDigest"], items[6]["requestDigest"])
        self.assertEqual(len({item["requestDigest"] for item in items}), 4)
        row = {"case": registry.SPECS[0]["case"], "requestHeaders": registry.validate_headers(fields(registry.SPECS[0]), registry.SPECS[0])}
        a = check.canonical_digests(row, SCOPE, CREDENTIAL, "127.0.0.1")
        b = check.canonical_digests(row, SCOPE, CREDENTIAL, "127.0.0.2")
        self.assertNotEqual(a[0], b[0]); self.assertEqual(a[1], b[1])
        row["requestHeaders"]["authorization"] = "Bearer " + registry.TOKEN
        with self.assertRaises(check.CheckFailure): check.canonical_digests(row, SCOPE, CREDENTIAL, "127.0.0.1")

    def test_seven_unique_audit_pairs_accept_out_of_order_arrivals(self):
        items = wire_items(); rows = audit_rows(items)
        pairs, complete = check.joined_attempts(list(reversed(rows)), items, SCOPE, CREDENTIAL)
        self.assertTrue(complete); self.assertEqual(len(pairs), 7)
        self.assertFalse(check.joined_attempts(rows[:-1], items, SCOPE, CREDENTIAL)[1])
        for change in ("duplicate", "attempt", "digest", "response", "block", "scope", "generation"):
            candidate = deepcopy(rows)
            if change == "duplicate": candidate.append(deepcopy(rows[1]))
            elif change == "attempt": candidate[-1]["event"]["attempt_id"] = rows[1]["event"]["attempt_id"]
            elif change == "digest": candidate[-1]["event"]["request_digest"] = "sha256:" + "f" * 64
            elif change == "response": candidate[1]["event"]["response_body_sha256"] = "sha256:" + "f" * 64
            elif change == "block": candidate[-1]["event"]["response_validation"]["error"] = "unrelated_error"
            elif change == "scope": candidate[0]["event"]["route_id"] = "other"
            else: candidate[0]["event"]["credential_version"] = True
            with self.subTest(change=change), self.assertRaises(check.CheckFailure):
                check.joined_attempts(candidate, items, SCOPE, CREDENTIAL)

    def test_negative_guard_requires_exact_error_route_and_hashed_destination(self):
        for error, path in check.DENIAL_PATHS.items():
            event = {"error": error, "route_id": SCOPE[1], "adapter": "npm.metadata.v1", "method": "GET",
                "outcome": "denied", "status_code": 403, "url": {"origin_sha256": check.digest(registry.ORIGIN.encode()),
                    "origin_bytes": len(registry.ORIGIN), "path_sha256": check.digest(path.encode()),
                    "path_bytes": len(path), "query_keys": []}}
            self.assertEqual(check.validate_denial(event, SCOPE[1]), error)
            for key, value in (("error", "unrelated403"), ("route_id", "other"), ("status_code", 502), ("url", {})):
                with self.subTest(key=key), self.assertRaises(check.CheckFailure):
                    check.validate_denial({**event, key: value}, SCOPE[1])

    def test_stock_job_uses_extra_trust_not_transport_override(self):
        job = (Path(__file__).parent / "operator_npm_metadata_job.mjs").read_text()
        self.assertIn("NODE_EXTRA_CA_CERTS: extraCa", job)
        self.assertIn("strictSSL: true", job)
        self.assertIn("retry: { retries: 0 }", job)
        self.assertIn("'fetch-retries=0'", job)
        self.assertIn("'--globalconfig', '/dev/null', 'view'", job)
        self.assertIn("await pacote.manifest", job)
        self.assertIn("HOME: clientHome", job)
        self.assertLess(job.index("process.env.HOME = clientHome"), job.index("load('/npm/node_modules/pacote/lib/index.js')"))
        for bypass in ("NODE_TLS_REJECT_UNAUTHORIZED", "rejectUnauthorized", "fetch:", "agent:", "cafile=", "ca: "):
            self.assertNotIn(bypass, job)

    def test_failure_diagnostics_are_closed_fixed_fields_not_raw_errors(self):
        failure = {"schema": "serverware.privateNpmMetadataClient/v1", "phase": "wrong_app", "client": "npm",
            "npmVersion": "11.8.0", "pacoteVersion": "21.0.4", "registryFetchVersion": "19.1.1",
            "strictSSL": True, "extraCaPreservesDefaultRoots": True, "configuredRetries": 0,
            "isolatedCache": True, "requestRewrite": False, "ok": False,
            "error": "stock npm metadata operation failed", "stage": "npm_json", "errorCode": "ERR_SYSTEM_ERROR",
            "processExitCode": 1, "stdoutBytes": 0, "stderrBytes": 80}
        result = check.client_failure_observation(failure, "wrong_app")
        self.assertEqual(set(result), {"phase", "stage", "errorCode", "processExitCode", "stdoutBytes", "stderrBytes"})
        self.assertEqual(result["errorCode"], "ERR_SYSTEM_ERROR")
        for key, value in (("raw", "canary-secret"), ("errorCode", "canary-secret"), ("stage", "canary-secret"),
                ("stderrBytes", -1), ("stdoutBytes", 1048577), ("processExitCode", True),
                ("phase", "npm_scoped"), ("phase", []), ("phase", {}), ("client", []), ("client", {}),
                ("configuredRetries", False), ("configuredRetries", 0.0), ("configuredRetries", []),
                ("error", "canary-secret")):
            with self.subTest(key=key):
                self.assertIsNone(check.client_failure_observation({**failure, key: value}, "wrong_app"))
        self.assertIsNone(check.client_failure_observation(None, "wrong_app"))
        for expected_phase in ([], {}, None, False):
            with self.subTest(expected_phase=expected_phase):
                self.assertIsNone(check.client_failure_observation(failure, expected_phase))
        self.assertEqual(check.ClientFailure("wrong_app", failure).observation, result)
        self.assertNotIn("ERR_SYSTEM_ERROR", str(check.ClientFailure("wrong_app", failure)))


if __name__ == "__main__":
    unittest.main()

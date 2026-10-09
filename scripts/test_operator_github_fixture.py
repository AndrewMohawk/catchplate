#!/usr/bin/env python3
"""Pure recipe and tiny-file provenance tests; no containers, SDK or sockets.

These controls do not establish runtime namespace isolation or SDK success.
Executable inputs below are inert bytes, never loaded or run. Their synthetic
pins are patched explicitly; the production executable/dependency pins stay
independently checked and the real manifest/hash code processes the files.
"""
from contextlib import ExitStack
from copy import deepcopy
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import prepare_operator_github_fixture as fixture
from scripts import operator_github_fixture_network as network


SOURCE = Path("/synthetic/source")
BINARY = Path("/synthetic/serverware-decision-gate")
INITIALIZER = Path("/synthetic/initialize.py")
NODE = Path("/synthetic/node")
SDK = Path("/synthetic/sdk")
ROOT = fixture.base.SCRATCH / "serverware-github-private.Source01"
SHA = "a" * 64
RUNTIME = {"serverware", "decision-gate-rs", "github", "edge", "check"}
ONE_OFF = {"initialize", "github-pki", "basic-pki"}
IP = "93.184.216.34"


def build():
    return fixture.build(SOURCE, BINARY, INITIALIZER, ROOT, NODE, SDK,
                         expected_binary_sha256=SHA)


def mounts(service):
    values = service["volumes"]
    result = {value["target"]: value for value in values}
    if len(result) != len(values):
        raise AssertionError("duplicate mount target")
    return result


class GithubFixtureTests(unittest.TestCase):
    def setUp(self):
        self.no_runtime = ExitStack()
        self.addCleanup(self.no_runtime.close)
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo",
                       "subprocess.run", "subprocess.Popen"):
            self.no_runtime.enter_context(patch(target, side_effect=AssertionError(
                "source-only fixture test attempted runtime I/O")))

    def validate(self, config):
        fixture.validate(config, SOURCE, BINARY, INITIALIZER, ROOT, NODE, SDK,
                         expected_binary_sha256=SHA)

    def test_exact_network_none_topology_has_no_bridge_ports_or_default_escape(self):
        config = build()
        self.assertEqual(set(config), {"name", "services"})
        self.assertEqual(set(config["services"]), RUNTIME | ONE_OFF | {"network"})
        self.assertEqual(config, build())
        self.validate(config)
        for name, service in config["services"].items():
            with self.subTest(service=name):
                self.assertEqual(service["network_mode"],
                    "service:network" if name in RUNTIME else "none")
                for field in ("networks", "ports", "expose", "extra_hosts", "dns", "dns_search",
                              "privileged", "devices", "pid", "ipc", "env_file", "extends", "volumes_from"):
                    self.assertNotIn(field, service)
                self.assertEqual(service["pull_policy"], "never")
                self.assertEqual(service["restart"], "no")
                self.assertEqual(service["labels"]["traefik.enable"], "false")
                self.assertEqual(service["labels"]["com.centurylinklabs.watchtower.enable"], "false")
        self.assertEqual(network.FIXTURE_IP, IP)
        self.assertEqual(network.HOSTS, ("127.0.0.1 localhost serverware decision-gate-rs "
            "proxy.operator-basic.example.test\n93.184.216.34 api.github.com\n").encode())
        self.assertEqual(network.RESOLV, b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")
        for name in RUNTIME | {"network"}:
            values = mounts(config["services"][name])
            for target, relative in (("/etc/hosts", "hosts"), ("/etc/resolv.conf", "resolv.conf")):
                self.assertEqual(values[target], fixture.bind(
                    ROOT / "runtime/upstream-data/github-network" / relative, target))
        # Real isolation predicate, mocked kernel reads only: no netlink/socket
        # creation. Even before attachment it must reject an interface or route.
        routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
        files = {"/proc/net/route": routes, "/proc/net/ipv6_route": "",
                 "/proc/sys/net/ipv4/ip_nonlocal_bind": "0\n"}
        with patch.object(network.socket, "if_nameindex", return_value=[(1, "lo")]) as interfaces, \
                patch.object(Path, "read_text", autospec=True, side_effect=lambda path, **_: files[str(path)]):
            network.assert_isolated_network(attached=False)
            interfaces.return_value = [(1, "lo"), (2, "eth0")]
            with self.assertRaises(ValueError):
                network.assert_isolated_network(attached=False)
            interfaces.return_value = [(1, "lo")]
            files["/proc/net/route"] = routes + "lo 00000000 00000000 0001 0 0 0 00000000\n"
            with self.assertRaises(ValueError):
                network.assert_isolated_network(attached=False)
            files["/proc/net/route"] = routes
            files["/proc/sys/net/ipv4/ip_nonlocal_bind"] = "1\n"
            with self.assertRaises(ValueError):
                network.assert_isolated_network(attached=False)

    def test_capabilities_are_temporary_and_all_participants_remain_bounded(self):
        config = build()
        for name, service in config["services"].items():
            with self.subTest(service=name):
                self.assertIs(service["read_only"], True)
                self.assertEqual(service["cap_drop"], ["ALL"])
                self.assertEqual(service["security_opt"], ["no-new-privileges:true"])
                self.assertEqual(service["mem_limit"], service["memswap_limit"])
                self.assertIn(service["mem_limit"], {"64m", "128m", "256m", "512m", "1g"})
                self.assertGreater(service["cpus"], 0)
                self.assertLessEqual(service["cpus"], 2)
                self.assertGreater(service["pids_limit"], 0)
                self.assertLessEqual(service["pids_limit"], 128)
                if name == "network":
                    self.assertEqual(service["user"], "0:0")
                    self.assertEqual(set(service["cap_add"]), {"NET_ADMIN", "SETUID", "SETGID"})
                    self.assertLessEqual(service["cpus"], 0.25)
                    self.assertLessEqual(service["pids_limit"], 16)
                elif name in {"initialize", "basic-pki"}:
                    self.assertEqual(service["user"], "0:0")
                    self.assertEqual(service["cap_add"], ["CHOWN", "DAC_OVERRIDE"])
                else:
                    self.assertEqual(service["user"], "10001:10001")
                    self.assertFalse(service.get("cap_add"))
        for name, dependency in (("github", "network"), ("serverware", "github"),
                                  ("decision-gate-rs", "serverware")):
            self.assertEqual(config["services"][name]["depends_on"][dependency], {"condition": "service_healthy"})
        for name in ("edge", "check"):
            self.assertEqual(config["services"][name]["profiles"], [name])
        self.assertEqual(config["services"]["network"]["sysctls"],
            {"net.ipv4.ip_unprivileged_port_start": "0", "net.ipv4.ip_nonlocal_bind": "0"})
        self.assertEqual((network.KEEPER_SECONDS, network.EDGE_SECONDS), (300, 240))

    def test_only_github_origin_is_admitted_without_cidr_or_demo_exceptions(self):
        config = build()
        for name in ("serverware", "decision-gate-rs"):
            environment = config["services"][name]["environment"]
            self.assertEqual(json.loads(environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"]),
                             ["https://api.github.com"])
            self.assertNotIn("SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS", environment)
            self.assertFalse(any(key.startswith("PRIVATE_OPERATOR_") for key in environment))
        serialized = json.dumps(config, sort_keys=True)
        self.assertNotIn("demo-upstream", serialized)
        self.assertNotIn("172.16.", serialized)
        self.assertNotIn("host.docker.internal", serialized)
        gate = config["services"]["decision-gate-rs"]
        self.assertEqual(gate["environment"]["SERVERWARE_DECISION_GATE_MANAGEMENT_HOST"], "127.0.0.1")
        command = config["services"]["check"]["command"]
        for flag, value in (("--control-base", "http://serverware:3000"),
                            ("--management-base", "http://127.0.0.1:9091"),
                            ("--proxy-url", "https://" + fixture.basic.PROXY_HOST + ":8443"),
                            ("--timeout-seconds", "180")):
            self.assertEqual(command[command.index(flag) + 1], value)
        provider = config["services"]["github"]["command"]
        self.assertEqual(provider, ["python", "-B", "-m", "scripts.operator_github_fixture",
                                    "--lifetime-seconds", "300"])
        # Constructor refusal must precede inherited token/CA/endpoint work.
        # Import is stdlib-only; its real parent constructor is never invoked.
        from scripts import check_operator_github as checker
        args = SimpleNamespace(control_base="http://serverware:3000", management_base="http://127.0.0.1:9091",
                               proxy_url=checker.PROXY, upstream_address=None)
        with patch.object(checker.isolated, "assert_isolated_network") as isolation, \
                patch.object(checker.OrdinaryClientCheck, "__init__", side_effect=AssertionError(
                    "rejected endpoint reached inherited runtime construction")) as parent:
            for key, value in (("control_base", "http://other.example:3000"),
                               ("management_base", "http://93.184.216.34:9091"),
                               ("proxy_url", "https://proxy.operator-basic.example.test:443"),
                               ("upstream_address", "127.0.0.1"), ("upstream_address", IP)):
                with self.subTest(endpoint=key), self.assertRaises(checker.CheckFailure):
                    checker.GithubCheck(SimpleNamespace(**{**vars(args), key: value}))
            parent.assert_not_called()
            self.assertEqual(isolation.call_count, 5)
        # The generic Endpoint has not been widened to permit arbitrary public
        # addresses; only the isolated GitHub constructor can bind its fixed IP.
        with self.assertRaises(checker.CheckFailure):
            checker.Endpoint("https://api.github.com", address=IP)

    def test_binary_sdk_source_and_public_trust_mounts_are_exact_and_read_only(self):
        config = build()
        services = config["services"]
        self.assertEqual(services["serverware"]["environment"]["SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"],
                         "sha256:" + SHA)
        command = services["check"]["command"]
        self.assertEqual(command[command.index("--expected-binary-sha256") + 1], "sha256:" + SHA)
        expected = {("decision-gate-rs", "/usr/local/bin/serverware-decision-gate"): BINARY,
                    ("initialize", "/initialize.py"): INITIALIZER,
                    ("check", "/node"): NODE, ("check", "/sdk/node_modules"): SDK / "node_modules"}
        for (name, target), source in expected.items():
            value = mounts(services[name])[target]
            self.assertEqual(value, fixture.bind(source, target))
        for service in services.values():
            for value in service["volumes"]:
                self.assertEqual(value["type"], "bind")
                self.assertEqual(value["bind"], {"create_host_path": False})
                if value["target"] in {"/app", "/node", "/sdk/node_modules", "/etc/hosts", "/etc/resolv.conf"}:
                    self.assertIs(value["read_only"], True)
        client = mounts(services["check"])
        self.assertNotIn("/data", client)
        self.assertNotIn("/run/secrets/serverware", client)
        self.assertEqual(set(name for name in client if name.startswith("/client-secrets/")),
                         {"/client-secrets/admin.token"})
        self.assertFalse(any("key.pem" in name for name in client))
        self.assertEqual(fixture.NODE_SHA256,
                         "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d")
        self.assertEqual(fixture.LOCK_SHA256,
                         "1d4b07947867c9476eccda94c4673d73212092f3c2ccea6980d2c5dbf8126092")

    def test_recipe_validator_refuses_escape_privilege_and_binding_mutations(self):
        original = build()
        mutations = [
            lambda value: value.update(networks={"escape": {"external": True}}),
            lambda value: value["services"]["check"].update(network_mode="host"),
            lambda value: value["services"]["github"].update(network_mode="bridge"),
            lambda value: value["services"]["network"].update(network_mode="host"),
            lambda value: value["services"]["decision-gate-rs"].update(ports=["9090:9090"]),
            lambda value: value["services"]["check"].update(cap_add=["NET_ADMIN"]),
            lambda value: value["services"]["serverware"].update(dns=["8.8.8.8"]),
            lambda value: value["services"]["network"].update(cap_add=["ALL"]),
            lambda value: value["services"]["serverware"]["environment"].update(
                SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS='["93.184.216.34/32"]'),
            lambda value: value["services"]["serverware"]["environment"].update(
                SERVERWARE_OPERATOR_DEMO_UPSTREAMS='["https://api.github.com","https://other.example"]'),
            lambda value: value["services"]["serverware"]["environment"].update(
                SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST="sha256:" + "b" * 64),
            lambda value: value["services"]["check"]["volumes"].append(fixture.bind(SOURCE, "/other", False)),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                changed = deepcopy(original)
                mutate(changed)
                with self.assertRaises(ValueError):
                    self.validate(changed)
        for invalid in ("sha256:" + SHA, SHA.upper(), "a" * 63, SHA + "\n"):
            with self.subTest(invalid_length=len(invalid)), self.assertRaises(ValueError):
                fixture.build(SOURCE, BINARY, INITIALIZER, ROOT, NODE, SDK, expected_binary_sha256=invalid)

    def tiny_inputs(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(
            prefix="github-fixture-source-test.", dir=os.environ.get("TMPDIR", str(fixture.base.SCRATCH)))))
        directory.chmod(0o755)
        source, sdk = directory / "source", directory / "sdk"

        def write(path, raw):
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            parent = path.parent
            while parent != directory:
                parent.chmod(0o755)
                parent = parent.parent
            path.write_bytes(raw)
            path.chmod(0o644)
            return hashlib.sha256(raw).hexdigest()

        required = {fixture.basic.CHECKER, fixture.basic.SETUP, fixture.basic.RELAY,
                    fixture.CHECKER, fixture.JOB, fixture.FIXTURE,
                    "scripts/demo_upstream.py", "scripts/operator_ordinary_client_fixture.py",
                    "scripts/prepare_operator_github_fixture.py", "scripts/operator_github_fixture_network.py"}
        files = {name: write(source / name, ("# inert source: " + name + "\n").encode()) for name in required}
        commit = "c" * 40
        source_manifest = directory / "source.json"
        source_sha = write(source_manifest, json.dumps({"schema": "serverware.privateProxyBasicSource/v1",
            "sourceCommit": commit, "files": files}, sort_keys=True).encode())
        binary, node, initializer = (directory / name for name in ("gate", "node", "initialize.py"))
        binary_sha = write(binary, b"inert gate bytes, not executable\n")
        node_sha = write(node, b"inert Node bytes, not executable\n")
        initializer_sha = write(initializer, b"# inert initializer, never imported\n")
        lock_sha = write(sdk / "package-lock.json", b'{"syntheticUnitTestLock":true}\n')
        for name, version in (("@octokit/rest", "22.0.1"), ("undici", "8.11.2")):
            write(sdk / "node_modules" / name / "package.json", json.dumps({"name": name, "version": version}).encode())
        sdk_manifest = directory / "sdk.json"
        sdk_data = {"schema": "serverware.privateGithubDependencies/v1", "packageLockSha256": lock_sha,
                    "files": fixture.basic.inventory(sdk / "node_modules", limit=8192, byte_limit=64 * 1024**2)}
        sdk_sha = write(sdk_manifest, json.dumps(sdk_data, sort_keys=True).encode())
        stack.enter_context(patch.object(fixture.base, "SCRATCH", directory))
        stack.enter_context(patch.object(fixture.base, "INITIALIZER_SHA256", initializer_sha))
        stack.enter_context(patch.object(fixture, "NODE_SHA256", node_sha))
        stack.enter_context(patch.object(fixture, "LOCK_SHA256", lock_sha))
        return SimpleNamespace(source=source, binary=binary, initializer=initializer,
            job_root=directory / "serverware-github-private.Unit001", node_binary=node, sdk_root=sdk,
            expected_binary_sha256=binary_sha, source_manifest=source_manifest,
            expected_source_manifest_sha256=source_sha, expected_source_commit=commit,
            sdk_manifest=sdk_manifest, expected_sdk_manifest_sha256=sdk_sha, write=False)

    def test_read_only_preparation_binds_real_tiny_bytes_without_running_any_input(self):
        args = self.tiny_inputs()
        result = fixture.prepare(args)
        receipt, config = result["preparation"], result["compose"]
        self.assertFalse(args.job_root.exists())
        self.assertEqual(receipt["sourceCommit"], args.expected_source_commit)
        self.assertEqual(receipt["sourceManifestSha256"], args.expected_source_manifest_sha256)
        self.assertEqual(receipt["binarySha256"], hashlib.sha256(args.binary.read_bytes()).hexdigest())
        self.assertEqual(receipt["nodeSha256"], hashlib.sha256(args.node_binary.read_bytes()).hexdigest())
        self.assertEqual(receipt["sdkManifestSha256"], args.expected_sdk_manifest_sha256)
        self.assertEqual(receipt["sdkPackages"], {"@octokit/rest": "22.0.1", "undici": "8.11.2"})
        self.assertEqual(receipt["composeSha256"], hashlib.sha256(
            (json.dumps(config, indent=2, sort_keys=True) + "\n").encode()).hexdigest())
        self.assertTrue(receipt["syntheticOnly"])
        for key in ("automaticExecution", "launched", "productionReady", "realGithubVerified"):
            self.assertIs(receipt[key], False)
        self.assertNotIn("subnet", receipt)
        self.assertIn("scripts/operator_github_fixture_network.py", receipt["sourceSha256"])

    def test_altered_binary_node_source_initializer_lock_or_sdk_bytes_refuse(self):
        args = self.tiny_inputs()
        for path in (args.binary, args.node_binary, args.initializer,
                     args.source / fixture.JOB, args.sdk_root / "package-lock.json",
                     args.sdk_root / "node_modules/undici/package.json"):
            with self.subTest(input=path.name):
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"tampered")
                    with self.assertRaises(ValueError):
                        fixture.prepare(args)
                finally:
                    path.write_bytes(original)
                self.assertFalse(args.job_root.exists())

    def test_manifest_identity_pin_and_required_namespace_source_are_not_optional(self):
        args = self.tiny_inputs()
        for field, value in (("expected_source_commit", "d" * 40),
                             ("expected_source_manifest_sha256", "d" * 64),
                             ("expected_sdk_manifest_sha256", "d" * 64),
                             ("expected_binary_sha256", "d" * 64)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture.prepare(SimpleNamespace(**{**vars(args), field: value}))
        manifest = json.loads(args.source_manifest.read_bytes())
        absent = "scripts/operator_github_fixture_network.py"
        (args.source / absent).unlink()
        del manifest["files"][absent]
        args.source_manifest.write_text(json.dumps(manifest, sort_keys=True))
        args.expected_source_manifest_sha256 = hashlib.sha256(args.source_manifest.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            fixture.prepare(args)
        self.assertFalse(args.job_root.exists())

    def test_block_failure_diagnostics_are_closed_bounded_and_never_echo_material(self):
        from scripts import check_operator_github as checker
        categories = {"github_response_link_denied", "provider_operation_outcome_unknown",
            "upstream_request_failed", "upstream_body_failed", "response_credential_reflection",
            "response_metadata_limit_exceeded", "response_metadata_invalid", "response_metadata_reserved_header",
            "response_metadata_duplicate", "response_release_mode_invalid", "response_body_too_large", "response_invalid_json",
            "credential_lease_changed_before_release", "credential_lease_lifetime_insufficient_for_upstream_send",
            "credential_generation_changed_before_upstream_send", "credential_lease_expired_before_upstream_send",
            "credential_lease_changed_before_upstream_send"}
        self.assertEqual(checker.BLOCK_ERROR_CATEGORIES, categories)
        secret = "synthetic-private-response-material-NEVER-ECHO"
        request, operation = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        keys = {"case", "status", "bodyBytes", "errorCategory", "hasLink", "requestDigest", "operationDigest"}
        for category in categories:
            body = json.dumps({"error": category, "message": secret, "headers": {secret: secret}}).encode()
            observed = checker.block_failure_observation("cross_repo_link", 502, body,
                {"LiNk": secret, secret: secret}, request, operation)
            self.assertEqual(observed, {"case": "cross_repo_link", "status": 502,
                "bodyBytes": len(body), "errorCategory": category, "hasLink": True,
                "requestDigest": request, "operationDigest": operation})
            self.assertNotIn(secret, json.dumps(observed))
        for body in (secret.encode(), b"[]", b"null", b'{"error":[]}', b'{"error":null}',
                     json.dumps({"error": secret}).encode(), b"\xff", b"{" * 32,
                     None, secret, b" " * 1048577):
            with self.subTest(body_type=type(body).__name__):
                observed = checker.block_failure_observation(secret, 502, body,
                    {secret: secret}, secret, secret)
                self.assertEqual(set(observed), keys)
                self.assertEqual(observed["case"], "unrecognized")
                self.assertEqual(observed["errorCategory"], "unrecognized")
                self.assertEqual(observed["bodyBytes"],
                    len(body) if isinstance(body, bytes) and len(body) <= 1048576 else None)
                self.assertIs(observed["hasLink"], False)
                self.assertIsNone(observed["requestDigest"])
                self.assertIsNone(observed["operationDigest"])
                self.assertNotIn(secret, json.dumps(observed))
        for status in (None, True, False, "502", 502.0, 99, 600, secret):
            self.assertIsNone(checker.block_failure_observation("cross_origin_link", status,
                b"{}", None, request, operation)["status"])
        for status in (100, 502, 599):
            self.assertEqual(checker.block_failure_observation("cross_origin_link", status,
                b"{}", None, request, operation)["status"], status)

    def test_hostile_link_oracle_keeps_exact_block_status_code_and_request_count(self):
        from scripts import check_operator_github as checker
        scope = ("synthetic-app", "synthetic-route", "sha256:" + "c" * 64)
        credential = "synthetic-credential"
        secret = "synthetic-private-error-body-NEVER-ECHO"

        def fresh():
            value = checker.GithubCheck.__new__(checker.GithubCheck)
            value.proxy = SimpleNamespace(address="127.0.0.1")
            value.wire, value.failed_observation = [], None
            # This group tests the acceptance/diagnostic oracle, not the separate
            # live credential-disclosure guard. No credential or transport exists.
            value.clean = lambda _body: None
            return value

        def row(case, status=502, error="github_response_link_denied"):
            spec = checker.fixture.SPECS[case]
            return {"method": spec["method"], "target": spec["target"], "status": status,
                "requestBodyBase64": base64.b64encode(spec["request"]).decode(),
                "requestBodySha256": checker.digest(spec["request"]),
                "responseBodyBase64": base64.b64encode(json.dumps({"error": error, "message": secret}).encode()).decode(),
                "headers": {}, "clientHeaders": {"accept": "application/vnd.github.v3+json"}}

        for case in ("cross_repo_link", "cross_origin_link"):
            value, incoming = fresh(), row(case)
            value.accept_wire([incoming], (case,), scope, credential, sdk_status=502)
            self.assertEqual(len(value.wire), 1)
            self.assertEqual(value.wire[0]["case"], case)
            self.assertIsNone(value.failed_observation)
            self.assertNotIn(secret, json.dumps(value.wire))
            for sdk_status, wire_status, error in ((200, 200, "github_response_link_denied"),
                    (200, 502, "github_response_link_denied"), (502, 200, "github_response_link_denied"),
                    (None, 502, "github_response_link_denied"), ("502", 502, "github_response_link_denied"),
                    (True, 502, "github_response_link_denied"), (502, 502.0, "github_response_link_denied"),
                    (502, True, "github_response_link_denied"), (502, 502, "provider_operation_outcome_unknown"),
                    (502, 502, "response_blocked"), (502, 502, secret), (502, 502, None)):
                with self.subTest(case=case, sdk_type=type(sdk_status).__name__, wire_type=type(wire_status).__name__):
                    value, incoming = fresh(), row(case, wire_status, error)
                    with self.assertRaises(checker.CheckFailure) as caught:
                        value.accept_wire([incoming], (case,), scope, credential, sdk_status=sdk_status)
                    self.assertEqual(value.wire, [])
                    self.assertEqual(value.failed_observation["case"], case)
                    self.assertNotIn(secret, str(caught.exception))
                    self.assertNotIn(secret, json.dumps(value.failed_observation))
                    request, operation = checker.canonical_digests(incoming, scope, credential, "127.0.0.1")
                    self.assertEqual(value.failed_observation["requestDigest"], request)
                    self.assertEqual(value.failed_observation["operationDigest"], operation)
            for rows in ([], [row(case), row(case)]):
                value = fresh()
                with self.assertRaises(checker.CheckFailure):
                    value.accept_wire(rows, (case,), scope, credential, sdk_status=502)
                self.assertEqual(value.wire, [])
                self.assertIsNone(value.failed_observation)
            value, incoming = fresh(), row(case)
            incoming["target"] += "&unexpected=1"
            with self.assertRaises(checker.CheckFailure):
                value.accept_wire([incoming], (case,), scope, credential, sdk_status=502)
            self.assertEqual(value.wire, [])
            self.assertIsNone(value.failed_observation)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Inert Alchemy receiver/topology controls; no sockets, PKI, SDKs or Docker.

HTTP handlers are called with in-memory request streams. Network effects are
replaced only in the dedicated guard unit; no admitted runtime is fabricated.
"""
from copy import deepcopy
from email.message import Message
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import operator_alchemy_examples_fixture as receiver
from scripts import check_operator_alchemy_examples as checker
from scripts import operator_alchemy_fixture_network as network
from scripts import prepare_operator_alchemy_fixture as recipe


def raw_request(client="node", method="eth_chainId", case="success"):
    identifier = "probe:" + case if client == "probe" else (
        receiver.METHODS.index(method) + {"node": 0, "python": 0, "go": 1}[client])
    return json.dumps({"method": method, "params": [], "id": identifier, "jsonrpc": "2.0"}).encode()


def fields(client, raw, case="success", chain="eth-mainnet"):
    result = [("Host", receiver.HOSTS[chain]), ("Authorization", "Bearer " + receiver.TOKEN),
        ("Content-Type", "application/json"), ("Content-Length", str(len(raw))), ("Connection", "close"),
        ("Accept", receiver.MEDIA[client])]
    result += [("User-Agent", "serverware-alchemy-probe/" + case if client == "probe" else receiver.AGENTS[client])]
    if client == "node":
        result += [("Accept-Language", "*"), ("Sec-Fetch-Mode", "cors")]
    return result


def handler(client="node", method="eth_chainId", case="success", *, raw=None, header_fields=None, chain="eth-mainnet"):
    raw = raw_request(client, method, case) if raw is None else raw
    instance = object.__new__(receiver.Handler)
    instance.server = SimpleNamespace(total=0, attempts=[])
    instance.command, instance.path = "POST", receiver.TARGET
    instance.rfile, instance.headers = io.BytesIO(raw), Message()
    for name, value in fields(client, raw, case, chain) if header_fields is None else header_fields:
        instance.headers[name] = value
    sent = []
    instance.send = lambda status, body, extra=(): sent.append((status, body, extra))
    return instance, sent


class ReceiverTests(unittest.TestCase):
    def test_six_stock_reads_and_six_probes_have_closed_nonsensitive_observations(self):
        server = SimpleNamespace(total=0, attempts=[])
        inputs = [(client, method, "success") for client in receiver.CLIENTS for method in receiver.METHODS]
        inputs += [("probe", "eth_chainId", case) for case in receiver.CASES[1:]]
        for client, method, case in inputs:
            instance, sent = handler(client, method, case)
            instance.server = server
            instance.resource()
            row = server.attempts[-1]
            self.assertEqual(set(row), receiver.ROW_KEYS)
            self.assertTrue(row["accepted"])
            self.assertEqual((row["client"], row["rpcMethod"], row["case"]), (client, method, case))
            raw = raw_request(client, method, case)
            self.assertEqual(receiver.base64.b64decode(row["requestBodyBase64"], validate=True), raw)
            self.assertEqual(row["requestBodySha256"], "sha256:" + hashlib.sha256(raw).hexdigest())
            self.assertEqual(row["requestBodyBytes"], len(raw))
            self.assertEqual(row["semanticHeaders"]["content-length"], str(len(raw)))
            self.assertEqual(type(row["requestId"]), str if client == "probe" else int)
            self.assertNotIn(receiver.TOKEN, json.dumps(row))
            self.assertNotIn("authorization", row["semanticHeaders"])
            self.assertNotIn("connection", row["semanticHeaders"])
            code, response, extra = sent[0]
            self.assertEqual((code, extra), (receiver.status(case), ()))
            self.assertEqual(row["responseBodySha256"], "sha256:" + hashlib.sha256(response).hexdigest())
        self.assertEqual(server.total, 12)
        self.assertEqual([row["ordinal"] for row in server.attempts], list(range(1, 13)))

    def test_both_exact_chains_and_original_json_bytes_are_preserved(self):
        for chain, expected in receiver.CHAIN_IDS.items():
            raw = b' { "jsonrpc":"2.0", "id":42, "params":[], "method":"eth_chainId" }\n'
            instance, sent = handler(raw=raw, chain=chain)
            instance.resource()
            row = instance.server.attempts[0]
            self.assertTrue(row["accepted"])
            self.assertEqual(row["chain"], chain)
            self.assertEqual(receiver.base64.b64decode(row["requestBodyBase64"]), raw)
            self.assertEqual(json.loads(sent[0][1])["result"], expected)
        self.assertEqual(receiver.body("success", 1, "eth_blockNumber"), b'{"jsonrpc":"2.0","id":1,"result":"0x10"}')

    def test_closed_headers_refuse_duplicate_secret_proxy_and_framing_inputs(self):
        for client in receiver.CLIENTS:
            raw = raw_request(client)
            for name, value in (("Proxy-Authorization", "private-canary"), ("Cookie", "private-canary"),
                    ("Transfer-Encoding", "chunked"), ("Accept-Encoding", "gzip"),
                    ("Host", receiver.HOSTS[receiver.CHAIN]), ("Content-Length", str(len(raw))),
                    ("X-Unknown", "private-canary")):
                with self.subTest(client=client, field=name), self.assertRaises(ValueError):
                    receiver.validated_headers(client, fields(client, raw) + [(name, value)])
            for selected, bad in (("Authorization", "Bearer serverware-alchemy-placeholder-v1"),
                    ("Authorization", "Bearer private-canary"), ("Host", "outside.invalid"),
                    ("Host", receiver.HOSTS[receiver.CHAIN] + ":443"), ("Content-Type", "text/plain"),
                    ("Content-Length", "0"), ("Content-Length", "01"), ("Content-Length", "65537")):
                changed = [(name, bad if name == selected else value) for name, value in fields(client, raw)]
                with self.assertRaises(ValueError):
                    receiver.validated_headers(client, changed)
        with self.assertRaises(ValueError):
            receiver.validated_headers("node", fields("node", raw_request()) + [("User-Agent", "node")])

    def test_node_explicit_accept_is_bound_and_transport_defaults_are_not_inferred(self):
        original = fields("node", raw_request())
        self.assertEqual(receiver.validated_headers("node", original)["accept"], "application/json")
        missing = [(name, value) for name, value in original if name != "Accept"]
        for invalid in (missing, missing + [("Accept", "*/*")], missing + [("Accept", "text/plain")]):
            with self.assertRaises(ValueError):
                receiver.validated_headers("node", invalid)

    def test_node_viem_transport_fingerprint_refuses_old_sdk_and_unexpected_defaults(self):
        original = fields("node", raw_request())
        self.assertEqual(receiver.classify("POST", "/v2", original), ("node", "success"))
        for selected, bad in (("User-Agent", "node"), ("Accept-Language", "en-US"),
                ("Sec-Fetch-Mode", "no-cors")):
            changed = [(name, bad if name == selected else value) for name, value in original]
            with self.assertRaises(ValueError):
                receiver.validated_headers("node", changed)
        for name in ("Accept-Language", "Sec-Fetch-Mode", "User-Agent"):
            with self.assertRaises(ValueError):
                receiver.validated_headers("node", [(key, value) for key, value in original if key != name])
        old = [(name, value) for name, value in original
            if name not in {"User-Agent", "Accept-Language", "Sec-Fetch-Mode"}]
        old += [("Alchemy-Ethers-Sdk-Method", "send"), ("Alchemy-Ethers-Sdk-Version", "3.6.5")]
        with self.assertRaises(ValueError):
            receiver.classify("POST", "/v2", old)
        with self.assertRaises(ValueError):
            receiver.validated_headers("node", old)
        self.assertEqual(checker.expected_id("node", "success", "eth_chainId"), 0)
        self.assertEqual(checker.expected_id("node", "success", "eth_blockNumber"), 1)

    def test_python_patched_sdk_fingerprint_is_exact_and_old_versions_are_counted_refusals(self):
        expected = "web3.py/7.15.0/web3.providers.rpc.rpc.HTTPProvider"
        self.assertEqual(receiver.AGENTS["python"], expected)
        raw = raw_request("python")
        original = [(name, expected if name == "User-Agent" else value)
            for name, value in fields("python", raw)]
        self.assertEqual(receiver.classify("POST", "/v2", original), ("python", "success"))
        self.assertEqual(receiver.validated_headers("python", original)["user-agent"], expected)
        for invalid in (expected.replace("7.15.0", "7.13.0"), expected.replace("7.15.0", "7.14.0"),
                expected.replace("7.15.0", "7.15.1"), expected + " extra", "arbitrary-client"):
            changed = [(name, invalid if name == "User-Agent" else value) for name, value in original]
            with self.subTest(agent=invalid):
                with self.assertRaises(ValueError):
                    receiver.classify("POST", "/v2", changed)
                with self.assertRaises(ValueError):
                    receiver.validated_headers("python", changed)
                instance, sent = handler("python", header_fields=changed)
                instance.resource()
                self.assertEqual(instance.server.total, 1)
                self.assertEqual(instance.server.attempts, [{"ordinal": 1, "accepted": False}])
                self.assertEqual(sent[0][0], 400)

    def test_checker_accepts_new_python_fingerprint_and_refuses_old_observation(self):
        for method in ("eth_chainId", "eth_blockNumber"):
            instance, _ = handler("python", method)
            instance.resource()
            row = instance.server.attempts[0]
            self.assertEqual(row["semanticHeaders"]["user-agent"],
                "web3.py/7.15.0/web3.providers.rpc.rpc.HTTPProvider")
            self.assertEqual(checker.validate_row(row, 1, "python", "success", method), raw_request("python", method))
            for invalid in ("web3.py/7.13.0/web3.providers.rpc.rpc.HTTPProvider", "arbitrary-client"):
                changed = deepcopy(row)
                changed["semanticHeaders"]["user-agent"] = invalid
                with self.assertRaises(ValueError):
                    checker.validate_row(changed, 1, "python", "success", method)

    def test_rpc_write_batch_notification_ids_and_duplicate_fields_remain_counted_refusals(self):
        good = json.loads(raw_request())
        invalid = [b"[]", b"{}", b"{", b"x" * (receiver.MAX_BODY + 1),
            receiver.base.encoded({**good, "method": "eth_sendRawTransaction"}),
            receiver.base.encoded({**good, "params": ["private-canary"]}),
            receiver.base.encoded({key: value for key, value in good.items() if key != "id"}),
            receiver.base.encoded({**good, "secret": "private-canary"}),
            b'{"jsonrpc":"2.0","id":42,"id":43,"method":"eth_chainId","params":[]}',
            b'{"jsonrpc":"2.0","id":-0,"method":"eth_chainId","params":[]}']
        invalid += [receiver.base.encoded({**good, "id": value}) for value in (None, True, 1.0, -1, 1 << 53, "private-canary")]
        for raw in invalid:
            instance, sent = handler(raw=raw)
            instance.resource()
            self.assertEqual(instance.server.attempts, [{"ordinal": 1, "accepted": False}])
            self.assertEqual(sent[0][0], 400)
            self.assertNotIn(b"private-canary", sent[0][1])
        for client, identifier in (("python", 1), ("go", 0)):
            with self.assertRaises(ValueError):
                receiver.request(receiver.base.encoded({**good, "id": identifier}), client=client)

    def test_target_fingerprint_and_body_length_failures_do_not_disappear(self):
        for method, target in (("GET", "/v2"), ("POST", "/v2?"), ("POST", "/v2?x=1"),
                ("POST", "/v2/"), ("POST", "/v2/private-canary"), ("DELETE", "/v2")):
            instance, sent = handler()
            instance.command, instance.path = method, target
            instance.resource()
            self.assertEqual(instance.server.attempts, [{"ordinal": 1, "accepted": False}])
            self.assertEqual(sent[0][0], 400)
        instance, sent = handler()
        instance.rfile = io.BytesIO(b"{}")
        instance.resource()
        self.assertFalse(instance.server.attempts[0]["accepted"])
        self.assertEqual(sent[0][0], 400)
        with self.assertRaises(ValueError):
            receiver.classify("POST", "/v2", fields("probe", raw_request("probe", case="error429"), "success"))

    def test_fixed_response_probes_bind_typed_id_and_exact_bounds(self):
        for identifier in (42, "probe:rpc-error"):
            value = json.loads(receiver.body("rpc-error", identifier))
            self.assertIs(type(value["id"]), type(identifier))
            self.assertEqual(value["id"], identifier)
            self.assertEqual(set(value), {"jsonrpc", "id", "error"})
            self.assertEqual(receiver.status("rpc-error"), 200)
            self.assertEqual(receiver.status("error429"), 429)
            self.assertNotEqual(json.loads(receiver.body("wrong-id", identifier))["id"], identifier)
            self.assertEqual(len(receiver.body("oversize", identifier)), 65537)
            self.assertIn(receiver.TOKEN.encode(), receiver.body("reflection", identifier))
        with self.assertRaises(ValueError):
            json.loads(receiver.body("invalid-json", "probe:invalid-json"))

    def test_count_precedes_parser_and_only_private_observation_get_is_off_count(self):
        for parsed, method, target, expected in ((False, None, "", 1), (True, "TRACE", "/v2", 1),
                (True, "POST", "/_fixture/observations", 1),
                (True, "GET", "/_fixture/observations?x=1", 1),
                (True, "GET", "/_fixture/observations", 0)):
            instance, _ = handler()
            def parse(current):
                self.assertEqual(current.server.total, 1)
                current.command, current.path = method, target
                return parsed
            with patch.object(receiver.base.Handler, "parse_request", parse):
                self.assertEqual(instance.parse_request(), parsed)
            self.assertEqual(instance.server.total, expected)
            self.assertEqual(len(instance.server.attempts), expected)
        instance, sent = handler()
        instance.send_error(414, "private-canary", explain="private-canary")
        self.assertEqual(instance.server.attempts, [{"ordinal": 1, "accepted": False}])
        self.assertNotIn(b"private-canary", sent[0][1])

    def test_overflow_is_visible_but_observation_memory_stays_bounded(self):
        instance, sent = handler()
        instance.server.total = receiver.MAX_ATTEMPTS
        instance.server.attempts = [{"ordinal": value, "accepted": False} for value in range(1, receiver.MAX_ATTEMPTS + 1)]
        original = deepcopy(instance.server.attempts)
        instance.resource()
        self.assertEqual(instance.server.total, receiver.MAX_ATTEMPTS + 1)
        self.assertEqual(instance.server.attempts, original)
        self.assertEqual(sent[0][0], 400)


class RecipeTests(unittest.TestCase):
    def build(self):
        self.args = (Path("/detached/source"), Path("/pinned/gate"), Path("/pinned/initialize.py"),
            Path("/srv/catchplate-fast/tmp/serverware-alchemy-private.abcdef12"), Path("/pinned/node"), Path("/pinned/alchemy-node"))
        return recipe.build(*self.args, expected_binary_sha256="a" * 64)

    def test_exact_six_runtime_services_share_only_network_none_and_fixed_hosts(self):
        config = self.build()
        self.assertNotIn("networks", config)
        services = config["services"]
        runtime = {name for name, service in services.items() if not service.get("profiles") or name in {"edge", "check"}}
        self.assertEqual(runtime, {"network", "alchemy", "serverware", "decision-gate-rs", "edge", "check"})
        for name, service in services.items():
            self.assertTrue(service["read_only"])
            self.assertEqual(service["restart"], "no")
            self.assertNotIn("ports", service)
            self.assertEqual(service["network_mode"], "none" if name in {"initialize", "alchemy-pki", "basic-pki", "network"} else "service:network")
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertEqual(len(service["volumes"]), len({mount["target"] for mount in service["volumes"]}))
            for mount in service["volumes"]:
                self.assertNotIn("github", mount["source"])
                self.assertNotIn("x-username", mount["target"])
                self.assertNotEqual(mount["target"], "/client-trust/requests-ca.pem")
        for name in ("serverware", "decision-gate-rs"):
            self.assertEqual(json.loads(services[name]["environment"]["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"]),
                ["https://" + host for host in network.PROVIDER_HOSTS])
        self.assertEqual(services["check"]["command"][0], "/app/scripts/check_operator_alchemy_examples.py")
        self.assertEqual(sum(mount["target"] == "/app/examples/alchemy-chain-status-node/node_modules"
            for mount in services["check"]["volumes"]), 1)
        self.assertEqual((network.KEEPER_SECONDS, network.EDGE_SECONDS), (300, 240))
        self.assertEqual(network.HOSTS.count(network.FIXTURE_IP.encode()), 1)
        for host in network.PROVIDER_HOSTS:
            self.assertIn(host.encode(), network.HOSTS)

    def test_recomputation_refuses_ports_and_old_root_prefix(self):
        config = self.build()
        recipe.validate(config, *self.args, expected_binary_sha256="a" * 64)
        changed = deepcopy(config)
        changed["services"]["alchemy"]["ports"] = ["443:443"]
        with self.assertRaises(ValueError):
            recipe.validate(changed, *self.args, expected_binary_sha256="a" * 64)
        changed_args = (*self.args[:3], Path("/srv/catchplate-fast/tmp/serverware-x-private.abcdef12"), *self.args[4:])
        with self.assertRaises(ValueError):
            recipe.build(*changed_args, expected_binary_sha256="a" * 64)

    def test_network_guard_checks_both_synthetic_names_without_real_network_calls(self):
        resolved = []
        class Socket:
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                pass
            def bind(self, address):
                self.address = address
        def resolve(host, *_args):
            resolved.append(host)
            ip = network.FIXTURE_IP if host in network.PROVIDER_HOSTS else network.LOOPBACK
            return [(None, None, None, None, (ip, 443))]
        def read(path):
            return network.HOSTS if str(path) == "/etc/hosts" else network.RESOLV
        with patch.object(network.inherited, "assert_isolated_network") as baseline, \
                patch.object(network.Path, "read_bytes", read), patch.object(network.socket, "socket", return_value=Socket()), \
                patch.object(network.socket, "getaddrinfo", side_effect=resolve):
            network.assert_isolated_network()
        baseline.assert_called_once_with(attached=False)
        self.assertEqual(resolved, [*network.PROVIDER_HOSTS, network.PROXY_HOST, "serverware", "decision-gate-rs"])


if __name__ == "__main__":
    unittest.main()

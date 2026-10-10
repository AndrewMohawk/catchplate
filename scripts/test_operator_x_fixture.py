"""Inert receiver/recipe tests; never create sockets, PKI, clients or containers."""
from copy import deepcopy
from email.message import Message
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import operator_x_examples_fixture as receiver
from scripts import operator_x_fixture_network as network
from scripts import prepare_operator_x_fixture as recipe


def fields(client, case="success"):
    result = [("Host", "api.x.com"), ("Authorization", "Bearer " + receiver.TOKEN),
        ("Accept", receiver.MEDIA[client]), ("Connection", "close"),
        ("User-Agent", receiver.AGENTS[client] if client != "probe" else "serverware-x-probe/" + case)]
    if client == "node":
        result.extend([("Content-Type", "application/json"), ("Accept-Language", "*"), ("Sec-Fetch-Mode", "cors")])
    return result


def handler(client="node", case="success", header_fields=None):
    instance = object.__new__(receiver.Handler)
    instance.server = SimpleNamespace(total=0, attempts=[])
    instance.command, instance.path = "GET", receiver.TARGET
    instance.headers = Message()
    for name, value in fields(client, case) if header_fields is None else header_fields:
        instance.headers[name] = value
    sent = []
    instance.send = lambda status, body, extra=(): sent.append((status, body, extra))
    return instance, sent


class ReceiverTests(unittest.TestCase):
    def test_three_stock_fingerprints_and_five_distinct_raw_probe_cases(self):
        for client, case in [(client, "success") for client in receiver.CLIENTS] + [
                ("probe", case) for case in receiver.CASES[1:]]:
            self.assertEqual(receiver.classify("GET", receiver.TARGET, fields(client, case)), (client, case))
            admitted = receiver.validated_headers(client, fields(client, case), case)
            self.assertNotIn("authorization", admitted)
            self.assertNotIn("connection", admitted)
            self.assertEqual("content-type" in admitted, client == "node")
        for method, target in [("POST", receiver.TARGET), ("GET", receiver.TARGET + "?"),
                ("GET", receiver.TARGET + "?user.fields=id"), ("GET", receiver.TARGET + "/"),
                ("GET", "/2/users/by/username/other_user")]:
            with self.assertRaises(ValueError):
                receiver.classify(method, target, fields("node"))
        for bad_case in ("request-denied", "success", "arbitrary"):
            with self.assertRaises(ValueError):
                receiver.classify("GET", receiver.TARGET, fields("probe", bad_case))

    def test_closed_headers_refuse_duplicates_framing_unexpected_fields_and_dummy(self):
        for client in receiver.CLIENTS:
            for name, value in [("Proxy-Authorization", "private-canary"), ("Cookie", "private-canary"),
                    ("Content-Length", "0"), ("Transfer-Encoding", "chunked"), ("Accept-Encoding", "gzip"),
                    ("User-Agent", "duplicate"), ("X-Github-Api-Version", "2022-11-28")]:
                with self.subTest(client=client, field=name), self.assertRaises(ValueError):
                    receiver.validated_headers(client, fields(client) + [(name, value)])
            for auth in ("Bearer serverware-x-placeholder-v1", "Bearer wrong", "Bearer nonascii-\u2603"):
                changed = [(name, auth if name == "Authorization" else value) for name, value in fields(client)]
                with self.assertRaises(ValueError):
                    receiver.validated_headers(client, changed)
        with self.assertRaises(ValueError):
            receiver.validated_headers("probe", fields("probe", "error429") + [("Content-Type", "application/json")], "error429")

    def test_response_cases_have_exact_bounded_bytes_and_closed_observations(self):
        for client, case in [(client, "success") for client in receiver.CLIENTS] + [
                ("probe", case) for case in receiver.CASES[1:]]:
            instance, sent = handler(client, case)
            instance.resource()
            self.assertEqual(instance.server.total, 1)
            row, = instance.server.attempts
            self.assertEqual(set(row), receiver.ROW_KEYS)
            self.assertEqual((row["client"], row["case"], row["accepted"]), (client, case, True))
            self.assertNotIn(receiver.TOKEN, json.dumps(row))
            code, body, extra = sent[0]
            self.assertEqual(code, receiver.status(case))
            self.assertEqual(extra, ())
            self.assertEqual(row["responseBodySha256"], "sha256:" + hashlib.sha256(body).hexdigest())
            self.assertEqual(row["responseBodyBytes"], len(body))
            self.assertEqual(row["requestBodySha256"], "sha256:" + hashlib.sha256(b"").hexdigest())
        self.assertEqual(len(receiver.body("oversize")), 1048577)
        self.assertEqual(len(receiver.body("error-oversize")), 65537)
        self.assertIsInstance(json.loads(receiver.body("oversize")), dict)
        self.assertIn(receiver.TOKEN.encode(), receiver.body("reflection"))
        with self.assertRaises(ValueError):
            json.loads(receiver.body("invalid-json"))

    def test_refused_arrival_is_counted_without_echo_and_overflow_is_visible(self):
        instance, sent = handler(header_fields=fields("node") + [("Cookie", "private-canary")])
        instance.resource()
        self.assertEqual(instance.server.attempts, [{"ordinal": 1, "accepted": False}])
        self.assertEqual(sent[0][0], 400)
        self.assertNotIn(b"private-canary", sent[0][1])
        instance.arrival = None
        instance.server.total = receiver.MAX_ATTEMPTS
        before = deepcopy(instance.server.attempts)
        instance.resource()
        self.assertEqual(instance.server.total, receiver.MAX_ATTEMPTS + 1)
        self.assertEqual(instance.server.attempts, before)
        self.assertEqual(sent[-1][0], 400)

    def test_count_precedes_parser_and_unknown_methods_or_malformed_requests_remain_counted(self):
        for parsed, method in ((False, None), (True, "TRACE"), (True, "GET")):
            instance, _ = handler()
            def parse(current):
                self.assertEqual(current.server.total, 1, "arrival must be counted before parser validation")
                current.command = method
                return parsed
            with patch.object(receiver.base.Handler, "parse_request", parse):
                self.assertEqual(instance.parse_request(), parsed)
            self.assertEqual(instance.server.total, 1)
            self.assertEqual(instance.server.attempts, [{"ordinal": 1, "accepted": False}])
            if parsed and method == "GET":
                instance.resource()
                self.assertEqual(instance.server.total, 1, "normal method handler must not double-count")

    def test_private_observation_get_exempts_only_its_own_provisional_arrival(self):
        instance, _ = handler()
        instance.server.total = 1
        previous = {"ordinal": 1, "accepted": False}
        instance.server.attempts = [previous]
        def parse(current):
            self.assertEqual(current.server.total, 2)
            current.command, current.path = "GET", "/_fixture/observations"
            return True
        with patch.object(receiver.base.Handler, "parse_request", parse):
            self.assertTrue(instance.parse_request())
        self.assertEqual(instance.server.total, 1)
        self.assertEqual(instance.server.attempts, [previous])
        instance.send_error(501, "private-canary", explain="private-canary")


class RecipeTests(unittest.TestCase):
    def build(self):
        self.args = (Path("/detached/source"), Path("/pinned/gate"), Path("/pinned/initialize.py"),
            Path("/srv/catchplate-fast/tmp/serverware-x-private.abcdef12"), Path("/pinned/node"), Path("/pinned/x-node"))
        return recipe.build(*self.args, expected_binary_sha256="a" * 64)

    def test_existing_hardened_topology_has_only_fixed_x_provider_and_no_union_ca(self):
        config = self.build()
        services = config["services"]
        runtime = {name for name, service in services.items() if not service.get("profiles") or name in {"edge", "check"}}
        self.assertEqual(runtime, {"network", "x", "serverware", "decision-gate-rs", "edge", "check"})
        self.assertNotIn("networks", config)
        for name, service in services.items():
            self.assertTrue(service["read_only"])
            self.assertEqual(service["restart"], "no")
            self.assertNotIn("ports", service)
            self.assertEqual(service["network_mode"], "none" if name in {"initialize", "basic-pki", "x-pki", "network"} else "service:network")
            self.assertIn("no-new-privileges:true", service["security_opt"])
            for mount in service["volumes"]:
                if mount["target"] == "/app":
                    self.assertTrue(mount["read_only"])
                self.assertNotIn("github", mount["source"])
                self.assertNotIn("github", mount["target"])
                self.assertNotEqual(mount["target"], "/client-trust/requests-ca.pem")
        for name in ("serverware", "decision-gate-rs"):
            self.assertEqual(services[name]["environment"]["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"], '["https://api.x.com"]')
        self.assertEqual(services["check"]["command"][0], "/app/scripts/check_operator_x_examples.py")
        self.assertEqual(sum(m["target"] == "/app/examples/x-username-node/node_modules" for m in services["check"]["volumes"]), 1)
        self.assertIn(b" api.x.com\n", network.HOSTS)
        self.assertNotIn(b"api.github.com", network.HOSTS)

    def test_exact_recomputation_and_fresh_root_prefix_refuse_configuration_drift(self):
        config = self.build()
        recipe.validate(config, *self.args, expected_binary_sha256="a" * 64)
        changed = deepcopy(config)
        changed["services"]["x"]["ports"] = ["443:443"]
        with self.assertRaises(ValueError):
            recipe.validate(changed, *self.args, expected_binary_sha256="a" * 64)
        changed_args = (*self.args[:3], Path("/srv/catchplate-fast/tmp/serverware-github-private.abcdef12"), *self.args[4:])
        with self.assertRaises(ValueError):
            recipe.build(*changed_args, expected_binary_sha256="a" * 64)


if __name__ == "__main__":
    unittest.main()

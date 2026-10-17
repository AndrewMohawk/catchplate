#!/usr/bin/env python3
"""Inert examples-fixture controls; no SDKs, subprocesses, sockets or containers.

These test receiver/checker contracts, not actual example or proxy execution.
"""
from copy import deepcopy
from email.message import Message
import hashlib
import io
import json
import os
import signal
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import operator_github_examples_fixture as receiver
from scripts import check_operator_github_examples as checker


def fields(client):
    result = [("Host", "api.github.com"), ("Authorization", "Bearer " + receiver.TOKEN),
        ("Accept", receiver.MEDIA[client]), ("Connection", "close")]
    if client == "node":
        result.extend([("User-Agent", "octokit-rest.js/22.0.1 octokit-core.js/7.0.8 Node.js/25"),
            ("Accept-Language", "*"), ("Sec-Fetch-Mode", "cors")])
    else:
        result.extend([("User-Agent", receiver.AGENTS[client]), ("X-GitHub-Api-Version", "2022-11-28")])
    return result


def handler(client="node", page=1, *, header_fields=None):
    instance = object.__new__(receiver.Handler)
    instance.server = SimpleNamespace(total=0, attempts=[])
    instance.command = "GET"
    instance.path = receiver.target(client, page)
    instance.headers = Message()
    for name, value in fields(client) if header_fields is None else header_fields:
        instance.headers[name] = value
    responses = []
    instance.send = lambda status, body, extra=(): responses.append((status, body, extra))
    return instance, responses


class ReceiverTests(unittest.TestCase):
    def test_exact_six_stock_targets_only(self):
        expected = {
            "node": ("per_page=100", "per_page=100&page=2"),
            "python": ("direction=desc&sort=updated&state=open", "page=2&per_page=30&state=open"),
            "go": ("page=1&per_page=100&state=open", "page=2&per_page=100&state=open"),
        }
        seen = set()
        for client, queries in expected.items():
            for page, query in enumerate(queries, 1):
                target = "/repos/catchplate-fixture/operator-demo/issues?" + query
                self.assertEqual(receiver.classify("GET", target), (client, page))
                seen.add(target)
                for method, bad in (("POST", target), ("GET", target + "&extra=1"),
                        ("GET", target.replace("operator-demo", "other-repo")),
                        ("GET", target.replace("/repos/catchplate-fixture/operator-demo", "/repositories/1729"))):
                    with self.assertRaises(ValueError):
                        receiver.classify(method, bad)
        self.assertEqual(len(seen), 6)

    def test_exact_public_headers_and_provider_canary(self):
        for client in receiver.CLIENTS:
            with self.subTest(client=client):
                admitted = receiver.validated_headers(client, fields(client))
                self.assertNotIn("authorization", admitted)
                self.assertNotIn("connection", admitted)
                self.assertEqual(admitted["accept"], receiver.MEDIA[client])
                for name, value in (("Proxy-Authorization", "Basic synthetic-private"),
                        ("Cookie", "hidden"), ("Content-Length", "0"), ("Transfer-Encoding", "chunked"),
                        ("Accept-Encoding", "gzip"), ("User-Agent", "duplicate")):
                    with self.assertRaises(ValueError):
                        receiver.validated_headers(client, fields(client) + [(name, value)])
                for authorization in ("token catchplate-github-placeholder-v1", "Bearer wrong", ""):
                    changed = [(n, authorization if n == "Authorization" else v) for n, v in fields(client)]
                    with self.assertRaises(ValueError):
                        receiver.validated_headers(client, changed)

    def test_successful_receiver_has_closed_observations_and_two_pages(self):
        for client in receiver.CLIENTS:
            for page in (1, 2):
                with self.subTest(client=client, page=page):
                    instance, responses = handler(client, page)
                    instance.resource()
                    self.assertEqual(instance.server.total, 1)
                    row, = instance.server.attempts
                    checker.validate_row(row, 1, client, page)
                    self.assertEqual(set(row), checker.ROW_KEYS)
                    self.assertNotIn(receiver.TOKEN, json.dumps(row))
                    status, body, extra = responses[0]
                    self.assertEqual(status, 200)
                    self.assertEqual(row["responseBodySha256"], "sha256:" + hashlib.sha256(body).hexdigest())
                    self.assertEqual(json.loads(body)[0]["state"], "open")
                    links = [value for name, value in extra if name == "Link"]
                    self.assertEqual(links, ['<' + receiver.ORIGIN + receiver.target(client, 2) + '>; rel="next"']
                        if page == 1 else [])

    def test_refusal_counts_arrival_without_echo_and_enforces_cap(self):
        instance, responses = handler(header_fields=fields("node") + [("Proxy-Authorization", "never-echo-this")])
        instance.resource()
        self.assertEqual(instance.server.attempts, [{"ordinal": 1, "accepted": False}])
        self.assertEqual(responses[0][0], 400)
        self.assertNotIn(b"never-echo-this", responses[0][1])
        instance.server.total = receiver.MAX_ATTEMPTS
        before = deepcopy(instance.server.attempts)
        instance.resource()
        self.assertEqual(instance.server.total, receiver.MAX_ATTEMPTS + 1)
        self.assertEqual(instance.server.attempts, before)
        self.assertEqual(responses[-1][0], 400)


class CheckerTests(unittest.TestCase):
    def test_exited_leader_with_descendant_pipes_is_signalled_before_reaping(self):
        calls = []
        process = SimpleNamespace(pid=424242, returncode=None, stdout=io.BytesIO(), stderr=io.BytesIO(),
            poll=Mock(side_effect=AssertionError("poll would release child identity")))
        def reaped(*, timeout):
            self.assertEqual(timeout, 2)
            calls.append("reap")
            process.returncode = 0
            return 0
        process.wait = Mock(side_effect=reaped)
        observed = SimpleNamespace(si_pid=424242, si_code=os.CLD_EXITED, si_status=0)
        def observe(*args):
            self.assertEqual(args, (os.P_PID, 424242, os.WEXITED | os.WNOHANG | os.WNOWAIT))
            self.assertIsNone(process.returncode)
            calls.append("observe-unreaped")
            return observed
        # A descendant still owns the pipe even though the launcher has exited.
        # The selector never gets EOF, and the ORIGINAL deadline expires.
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.get_map.return_value = {"descendant-pipe": True}
        selector.select.return_value = []
        with patch.object(checker.subprocess, "Popen", return_value=process) as launch, \
                patch.object(checker.selectors, "DefaultSelector", return_value=selector), \
                patch.object(checker.time, "monotonic", side_effect=[10.0, 10.1, 10.2, 11.1]), \
                patch.object(checker.os, "waitid", side_effect=observe), \
                patch.object(checker.os, "getpgid", return_value=424242), \
                patch.object(checker.os, "getsid", return_value=424242), \
                patch.object(checker.os, "getpgrp", return_value=111), \
                patch.object(checker.os, "killpg", side_effect=lambda pid, sig: calls.append(("signal", pid, sig))) as kill:
            with self.assertRaisesRegex(checker.CheckFailure, "example process deadline exceeded"):
                checker.run_example("python", {}, 1)
        self.assertEqual(calls, ["observe-unreaped", ("signal", 424242, signal.SIGKILL), "reap"])
        self.assertTrue(launch.call_args.kwargs["start_new_session"])
        kill.assert_called_once_with(424242, signal.SIGKILL)
        process.poll.assert_not_called()
        process.wait.assert_called_once_with(timeout=2)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_cleanup_refuses_lost_child_or_unowned_group(self):
        process = SimpleNamespace(pid=424242, returncode=None, wait=Mock())
        with patch.object(checker.os, "waitid", side_effect=ChildProcessError), \
                patch.object(checker.os, "killpg") as kill:
            with self.assertRaisesRegex(checker.CheckFailure, "ownership unavailable"):
                checker._cleanup_example_group(process)
            kill.assert_not_called()
        with patch.object(checker.os, "waitid", return_value=None), \
                patch.object(checker.os, "getpgid", return_value=123), \
                patch.object(checker.os, "killpg") as kill:
            with self.assertRaisesRegex(checker.CheckFailure, "ownership differs"):
                checker._cleanup_example_group(process)
            kill.assert_not_called()
        with patch.object(checker.os, "waitid", return_value=None), \
                patch.object(checker.os, "getpgid", side_effect=ProcessLookupError), \
                patch.object(checker.os, "killpg") as kill:
            with self.assertRaisesRegex(checker.CheckFailure, "ownership unavailable"):
                checker._cleanup_example_group(process)
            kill.assert_not_called()
        process.wait.assert_not_called()

    def test_child_exit_observation_never_reaps_and_handles_live_or_signal(self):
        process = SimpleNamespace(pid=424242, returncode=None, wait=Mock(), poll=Mock())
        outcomes = [None, SimpleNamespace(si_pid=424242, si_code=os.CLD_EXITED, si_status=1),
            SimpleNamespace(si_pid=424242, si_code=os.CLD_KILLED, si_status=9)]
        with patch.object(checker.os, "waitid", side_effect=outcomes):
            self.assertIsNone(checker._child_exit_status(process))
            self.assertEqual(checker._child_exit_status(process), 1)
            self.assertEqual(checker._child_exit_status(process), -9)
        process.wait.assert_not_called()
        process.poll.assert_not_called()

    def test_closed_observation_refuses_drift_before_digest(self):
        instance, _ = handler("python", 1)
        instance.resource()
        original = instance.server.attempts[0]
        for key, value in (("ordinal", True), ("page", True), ("status", True),
                ("providerCredentialMatched", False), ("proxyAuthorizationPresent", True),
                ("requestBodySha256", "sha256:" + "0" * 64), ("responseBodyBytes", True),
                ("target", "/unrelated"), ("extra", "do-not-emit")):
            with self.subTest(key=key), self.assertRaises((ValueError, checker.CheckFailure)):
                checker.validate_row({**original, key: value}, 1, "python", 1)
        changed = deepcopy(original)
        changed["semanticHeaders"]["authorization"] = "secret"
        with self.assertRaises((ValueError, checker.CheckFailure)):
            checker.validate_row(changed, 1, "python", 1)

    def test_independent_canonical_v3_read_projection(self):
        instance, _ = handler("go", 1)
        instance.resource()
        row = instance.server.attempts[0]
        scope = ("principal", "route", "sha256:" + "a" * 64)
        actual = checker.canonical_digests(row, scope, "credential", "127.0.0.1")
        expected = {"v": 3, "principal": "principal", "client_ip": "127.0.0.1", "route_id": "route",
            "credential_ref": "credential", "credential_version": "1", "policy_hash": "sha256:" + "a" * 64,
            "request": {"method": "GET", "scheme": "https", "authority": "api.github.com",
                "path": "/repos/catchplate-fixture/operator-demo/issues",
                "query": [["page", "1"], ["per_page", "100"], ["state", "open"]],
                "query_wire": "page=1&per_page=100&state=open", "query_mode": "githubRestV1",
                "headers": {"host": "api.github.com", "accept": "application/vnd.github.squirrel-girl-preview",
                    "user-agent": "go-github/v74.0.0", "x-github-api-version": "2022-11-28"},
                "body_sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "discard_headers": ["accept-encoding"]}, "operation": {"operation": "github.issues.read"}}
        encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        hashed = lambda value: "sha256:" + hashlib.sha256(encode(value)).hexdigest()
        self.assertEqual(actual, (hashed(expected), hashed({k: v for k, v in expected.items() if k not in {"v", "client_ip"}})))
        self.assertNotEqual(actual, checker.canonical_digests(row, ("other", *scope[1:]), "credential", "127.0.0.1"))

    def test_actual_entrypoints_and_minimal_child_environments(self):
        self.assertEqual(checker.COMMANDS["node"], ("/node", "/app/examples/github-issues-node/client.mjs"))
        self.assertEqual(checker.COMMANDS["python"], ("/example-python/bin/python", "-I", "-B", "/app/examples/github-issues-python/issues.py"))
        self.assertEqual(checker.COMMANDS["go"], ("/example-go/github-issues",))
        with patch.dict("os.environ", {"GITHUB_TOKEN": "ambient-provider-secret", "HTTPS_PROXY": "ambient"}, clear=True):
            for client in receiver.CLIENTS:
                env = checker.client_environment(client, "app", "application-secret")
                self.assertNotIn("GITHUB_TOKEN", env)
                self.assertNotIn("HTTPS_PROXY", env)
                self.assertNotIn(receiver.TOKEN, env.values())
                self.assertEqual(env["CATCHPLATE_PROXY_TOKEN"], "application-secret")
                self.assertEqual(env["CATCHPLATE_PROXY_URL"], "https://proxy.operator-basic.example.test:8443")
                if client == "python":
                    self.assertNotIn("CATCHPLATE_PROXY_CA_FILE", env)
                    self.assertEqual(env["CATCHPLATE_CA_FILE"], "/client-trust/requests-ca.pem")
                else:
                    self.assertEqual(env["CATCHPLATE_PROXY_CA_FILE"], "/client-trust/outer-ca.pem")
                    self.assertEqual(env["CATCHPLATE_CA_FILE"], "/client-trust/inner-ca.pem")
                wrong = checker.client_environment(client, "app", "application-secret", wrong_repo=True)
                self.assertEqual({k for k in env if env[k] != wrong[k]}, {"CATCHPLATE_GITHUB_REPO"})

    def test_exact_success_outputs(self):
        self.assertEqual(checker.expected_output("node"), {"ok": True, "operation": "list", "issueCount": 2,
            "issues": [{"number": 11, "title": "Fixture issue 11"}, {"number": 12, "title": "Fixture issue 12"}]})
        self.assertEqual(checker.expected_output("python"), [
            {"number": 11, "title": "Fixture issue 11", "state": "open"},
            {"number": 12, "title": "Fixture issue 12", "state": "open"}])
        self.assertEqual(checker.expected_output("go"), {"pages": 2, "issues": 2, "pull_requests": 0})


if __name__ == "__main__":
    unittest.main()

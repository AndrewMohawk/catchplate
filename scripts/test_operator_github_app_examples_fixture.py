"""In-memory protocol/receiver controls; no sockets, SDKs or running application."""
from copy import deepcopy
from email.message import Message
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from serverware import github_app as protocol
from serverware.http_client import HttpResponse
from scripts import operator_github_app_examples_fixture as fixture
from scripts import check_operator_github_app_examples as checker
from scripts.test_operator_github_examples_fixture import fields as stock_fields

NOW = 1800000000


def fields(authorization, *, body=None):
    value = [("Host", "api.github.com"), ("Authorization", authorization), ("Accept", "application/vnd.github+json"),
        ("Accept-Encoding", "identity"), ("Connection", "close"), ("User-Agent", "serverware-github-app/1"),
        ("X-GitHub-Api-Version", "2022-11-28")]
    return value + ([] if body is None else [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])


def issue_fields(client, cycle=0):
    return [(name, "Bearer " + fixture.TOKENS[cycle] if name.lower() == "authorization" else value)
        for name, value in stock_fields(client)]


class ReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pem = cls.private.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        cls.signing = protocol.load_private_key(cls.pem.encode())
        cls.replacement = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.replacement_signing = protocol.load_private_key(cls.replacement.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cls.config = protocol.AppConfig(123, 456, fixture.examples.OWNER, fixture.examples.REPO, "read")

    def setUp(self):
        for name in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen"):
            self.enterContext(patch(name, side_effect=AssertionError("inert test attempted runtime I/O")))
        self.oracle = fixture.Oracle(self.private.public_key(), self.replacement.public_key())

    def provision(self, *, now=NOW, config=None, signing=None):
        def transport(request, **kwargs):
            self.assertEqual(kwargs["require_https"], True)
            self.assertEqual(request.full_url.split("/", 3)[:3], ["https:", "", "api.github.com"])
            # urllib's normal final framing fields; no real transport is claimed.
            sent = list(request.header_items()) + [("Host", "api.github.com"), ("Connection", "close")]
            if request.data is not None:
                sent += [("Content-Length", str(len(request.data)))]
            status, raw, _ = self.oracle.handle(request.method, "/" + request.full_url.split("/", 3)[3],
                sent, request.data or b"", now)
            headers = (("content-type", "application/json; charset=utf-8"), ("content-length", str(len(raw))))
            return HttpResponse(status, dict(headers), headers, raw)
        return protocol.mint_installation_token(config or self.config, signing or self.signing,
            transport=transport, clock=lambda: now)

    def reject_candidate(self, config, now=NOW):
        with self.assertRaises(protocol.GitHubAppError):
            self.provision(now=now, config=config, signing=self.replacement_signing)
        self.assertEqual(len(self.oracle.mints), 1)
        self.assertEqual(self.oracle.auth[-1]["signingKey"], "B")
        self.assertIs(self.oracle.auth[-1]["bindingMatches"], False)

    def read_cycle(self, cycle, now):
        for client in fixture.examples.CLIENTS:
            for page in (1, 2):
                status, body, extra = self.oracle.handle("GET", fixture.examples.target(client, page),
                    issue_fields(client, cycle), b"", now)
                self.assertEqual((status, body), (200, fixture.examples.body(page)))
                self.assertEqual(bool([v for k, v in extra if k == "Link"]), page == 1)

    def test_real_jwt_protocol_initial_name_binding_then_original_expiry_and_pinned_id_refresh(self):
        first = self.provision()
        self.assertEqual((first.config.account_id, first.config.repository_id), (700, 900))
        self.assertEqual(first.token, fixture.TOKENS[0])
        self.reject_candidate(first.config)
        self.read_cycle(0, NOW + 1)
        second = self.provision(now=NOW + 122, config=first.config)
        self.assertEqual(second.config, first.config)
        self.assertEqual(second.token, fixture.TOKENS[1])
        self.read_cycle(1, NOW + 123)
        third = self.provision(now=NOW + 124, config=first.config, signing=self.replacement_signing)
        self.assertEqual(third.config, first.config)
        self.assertEqual(third.token, fixture.TOKENS[2])
        self.read_cycle(2, NOW + 130)
        observed = checker.validate_observation(self.oracle.observation())
        self.assertEqual((observed["total"], len(observed["auth"]), len(observed["attempts"])), (28, 10, 18))
        self.assertEqual([v["selection"] for v in observed["mints"]], ["name", "id", "id"])
        self.assertEqual([v["signingKey"] for v in observed["mints"]], ["A", "A", "B"])
        self.assertNotIn("BEGIN PRIVATE", json.dumps(observed))
        for token in fixture.TOKENS:
            self.assertNotIn(token, json.dumps(observed))

    def test_jwt_independently_verifies_signature_identity_and_clock(self):
        jwt = protocol.app_jwt(self.config, self.signing, NOW)
        fixture.verify_jwt("Bearer " + jwt, self.private.public_key(), NOW)
        for header, now in (("token " + jwt, NOW), ("Bearer " + jwt, NOW + 601),
                ("Bearer " + jwt, NOW - 100), ("Bearer " + jwt[:-8] + "AAAAAAAA", NOW)):
            with self.assertRaises(Exception): fixture.verify_jwt(header, self.private.public_key(), now)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(Exception): fixture.verify_jwt("Bearer " + jwt, other.public_key(), NOW)

    def test_scope_widening_duplicate_json_and_wrong_round_selection_refused(self):
        jwt = "Bearer " + protocol.app_jwt(self.config, self.signing, NOW)
        for body in (b'{"permissions":{"issues":"write","metadata":"read"},"repositories":["operator-demo"]}',
                b'{"permissions":{"issues":"read","metadata":"read"},"repository_ids":[900]}',
                b'{"permissions":{"issues":"read","metadata":"read"},"repositories":["operator-demo","other"]}',
                b'{"repositories":[],"repositories":[]}'):
            oracle = fixture.Oracle(self.private.public_key(), self.replacement.public_key())
            oracle.handle("GET", fixture.INSTALL_PATH, fields(jwt), b"", NOW)
            with self.assertRaises(ValueError): oracle.handle("POST", fixture.MINT_PATH, fields(jwt, body=body), body, NOW)
            self.assertEqual(oracle.mints, [])
            self.assertEqual(oracle.auth[-1], {"ordinal": 2, "accepted": False})

    def test_early_refresh_expired_or_wrong_token_and_unexpected_resource_refused(self):
        first = self.provision(); self.reject_candidate(first.config); self.read_cycle(0, NOW + 1)
        with self.assertRaises(protocol.GitHubAppError): self.provision(now=NOW + 100, config=first.config)
        self.assertEqual(len(self.oracle.mints), 1)
        for when, headers, target in ((NOW + 121, issue_fields("node"), fixture.examples.target("node", 1)),
                (NOW + 1, issue_fields("node", 1), fixture.examples.target("node", 1)),
                (NOW + 1, issue_fields("node"), "/repos/serverware-fixture/other/issues")):
            self.oracle = fixture.Oracle(self.private.public_key(), self.replacement.public_key())
            first = self.provision(); self.reject_candidate(first.config)
            with self.assertRaises(ValueError): self.oracle.handle("GET", target, headers, b"", when)
            self.assertEqual(self.oracle.attempts, [{"ordinal": 5, "accepted": False}])

    def test_wrong_signing_key_cannot_substitute_candidate_or_committed_replacement(self):
        first = self.provision()
        with self.assertRaises(protocol.GitHubAppError): self.provision(config=first.config)
        self.assertEqual(self.oracle.auth[-1], {"ordinal": 4, "accepted": False})
        self.oracle = fixture.Oracle(self.private.public_key(), self.replacement.public_key())
        first = self.provision(); self.reject_candidate(first.config); self.read_cycle(0, NOW + 1)
        self.provision(now=NOW + 122, config=first.config); self.read_cycle(1, NOW + 123)
        with self.assertRaises(protocol.GitHubAppError): self.provision(now=NOW + 124, config=first.config)
        self.assertEqual(len(self.oracle.mints), 2)
        with self.assertRaises(ValueError): fixture.Oracle(self.private.public_key(), self.private.public_key())

    def test_exact_provisioning_headers_and_no_proxy_credential_or_redirect_target(self):
        good = fields("Bearer synthetic")
        fixture.provisioning_headers(good, post=False, length=0)
        for additions in ([('Cookie', 'synthetic')], [('Proxy-Authorization', 'synthetic')], [('Host', 'duplicate')],
                [('Content-Length', '0')], [('Transfer-Encoding', 'chunked')]):
            with self.assertRaises(ValueError): fixture.provisioning_headers(good + additions, post=False, length=0)
        with self.assertRaises(ValueError):
            self.oracle.handle("GET", "https://other.invalid/repos/x", good, b"", NOW)

    def test_framing_refusal_counts_before_decode_and_caps_retained_rows(self):
        handler = object.__new__(fixture.Handler)
        handler.server, handler.command, handler.path = SimpleNamespace(oracle=self.oracle), "POST", fixture.MINT_PATH
        handler.headers, handler.rfile = Message(), io.BytesIO(b"private-canary")
        handler.headers["Transfer-Encoding"] = "chunked"
        responses = []
        handler.send = lambda status, body, extra=(): responses.append((status, body))
        handler.resource()
        self.assertEqual(self.oracle.auth, [{"ordinal": 1, "accepted": False}])
        self.assertEqual(responses, [(400, b'{"message":"synthetic App fixture refused"}')])
        for _ in range(fixture.MAX_ARRIVALS + 6): handler.resource()
        self.assertEqual(self.oracle.total, fixture.MAX_ARRIVALS + 7)
        self.assertEqual(len(self.oracle.auth), fixture.MAX_ARRIVALS)
        self.assertNotIn("private-canary", json.dumps(self.oracle.observation()))
        with self.assertRaises(checker.CheckFailure): checker.validate_observation(self.oracle.observation())


if __name__ == "__main__":
    unittest.main()

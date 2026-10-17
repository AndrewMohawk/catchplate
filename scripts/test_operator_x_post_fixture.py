"""Inert managed-X provider/network controls; no sockets, PKI or containers.

Injected unit clocks exercise decisions, not real expiry acceptance. The actual
stock SDK/HTTPS/refresh story remains the separately run one-shot fixture.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import operator_x_post_fixture as provider
from scripts import operator_x_post_fixture_network as network
from scripts import operator_x_post_profiles as profiles


class Clock:
    def __init__(self):
        self.wall, self.mono = 1800000000.0, 1000.0

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds


class Flow:
    def __init__(self):
        self.clock = Clock()
        self.state = provider.State(wall=lambda: self.clock.wall, monotonic=lambda: self.clock.mono)
        self.verifier, self.browser_state = "v" * 43, "s" * 43
        self.first = self.second = None

    def authorize(self, **changes):
        args = {"response_type": "code", "client_id": provider.CLIENT_ID,
            "redirect_uri": provider.CALLBACK_URL, "scope": " ".join(provider.SCOPES),
            "state": self.browser_state, "code_challenge_method": "S256",
            "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()}
        args.update(changes)
        result = self.state.request("GET", "/i/oauth2/authorize?" + urlencode(args),
            [("Host", "x.com"), ("Accept-Encoding", "identity"), ("Connection", "close")])
        if result[0] == 302:
            location = dict(result[1])["Location"]
            query = parse_qs(urlsplit(location).query)
            assert query["state"] == [self.browser_state]
            self.code = query["code"][0]
        return result

    def basic(self, raw):
        return [("Host", "api.x.com"), ("Authorization", "Basic " + base64.b64encode(
            (provider.CLIENT_ID + ":" + provider.CLIENT_SECRET).encode()).decode()),
            ("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json"),
            ("Content-Length", str(len(raw))), ("Connection", "close")]

    def form_request(self, args, target="/2/oauth2/token", **changes):
        raw = urlencode(args).encode()
        fields = self.basic(raw)
        fields = [(name, changes.get(name.lower(), value)) for name, value in fields]
        return self.state.request("POST", target, fields, raw)

    def code_args(self):
        return {"grant_type": "authorization_code", "code": self.code,
            "redirect_uri": provider.CALLBACK_URL, "code_verifier": self.verifier}

    def connect(self):
        assert self.authorize()[0] == 302
        status, _, raw = self.form_request(self.code_args())
        assert status == 200
        self.first = json.loads(raw)
        assert self.identity(self.first)[0] == 200
        return self.first

    def identity(self, token):
        return self.state.request("GET", "/2/users/me", [("Host", "api.x.com"),
            ("Authorization", "Bearer " + token["access_token"]), ("Accept", "application/json"),
            ("Connection", "close")])

    def refresh(self):
        status, extra, raw = self.form_request({"grant_type": "refresh_token", "refresh_token": self.first["refresh_token"]})
        if status == 200:
            self.second = json.loads(raw)
        return status, extra, raw

    def post(self, client, token, case="success", *, extra=(), body=None):
        fields = list(profiles.provider_headers(client, case).items())
        fields += [("Authorization", "Bearer " + token["access_token"]), ("Connection", "keep-alive"), *extra]
        return self.state.request("POST", profiles.TARGET, fields,
            profiles.post_body(client, case) if body is None else body)

    def revoke(self, token, hint):
        return self.form_request({"token": token[hint], "token_type_hint": hint}, "/2/oauth2/revoke")


class FixtureTests(unittest.TestCase):
    def test_full_inert_original_expiry_refresh_seven_posts_exact_cleanup(self):
        flow = Flow()
        initial = flow.state.observations()
        self.assertEqual(initial["issuedGenerations"], [])
        self.assertIsNone(initial["initialAccessExpiresAtEpochMs"])
        flow.connect()
        issued = flow.state.observations()
        self.assertEqual(issued["initialAccessExpiresAtEpochMs"] - issued["initialAccessIssuedAtEpochMs"], 120000)
        for client in profiles.CLIENTS:
            self.assertEqual(flow.post(client, flow.first)[0], 201)
        flow.clock.advance(121)
        self.assertTrue(flow.state.observations()["initialAccessExpired"])
        self.assertEqual(flow.refresh()[0], 200)
        self.assertEqual(flow.identity(flow.second)[0], 200)
        self.assertEqual(flow.second["expires_in"], 600)
        for client in profiles.CLIENTS:
            self.assertEqual(flow.post(client, flow.second)[0], 201)
        status, _, reflected = flow.post("node", flow.second, "reflection")
        self.assertEqual(status, 201)
        self.assertIn(flow.second["access_token"].encode(), reflected)
        for token in (flow.first, flow.second):
            for hint in ("access_token", "refresh_token"):
                self.assertEqual(flow.revoke(token, hint)[0], 200)
        view = flow.state.observations()
        self.assertEqual(view["counts"], {"total": 16, "authorize": 1, "code": 1,
            "refresh": 1, "identity": 2, "revoke": 4, "posts": 7, "rejected": 0})
        self.assertEqual(view["issuedGenerations"], [1, 2])
        self.assertTrue(view["refreshAfterInitialExpiry"] and view["cleanupComplete"])
        self.assertEqual(view["initialAccessExpiresAtEpochMs"], issued["initialAccessExpiresAtEpochMs"])
        for ordinal, row in enumerate(view["posts"], 1):
            self.assertEqual(set(row), provider.POST_KEYS)
            self.assertEqual(row["ordinal"], ordinal)
            self.assertEqual(row["requestHeaders"], profiles.provider_headers(row["client"], row["case"]))
            self.assertEqual(row["requestBodyBytes"], len(profiles.post_body(row["client"], row["case"])))
            self.assertEqual(row["requestBodySha256"], provider.sha(profiles.post_body(row["client"], row["case"])))
            if ordinal < 7:
                self.assertEqual(row["responseBodySha256"], provider.sha(provider.response_body(ordinal)))
        public = provider.encoded(view)
        for secret in (provider.CLIENT_SECRET, flow.code, flow.browser_state, flow.verifier,
                *[token[hint] for token in (flow.first, flow.second) for hint in ("access_token", "refresh_token")], profiles.TEXT):
            self.assertNotIn(secret.encode(), public)

    def test_pkce_code_single_use_including_failed_verifier(self):
        flow = Flow(); self.assertEqual(flow.authorize()[0], 302)
        bad = dict(flow.code_args(), code_verifier="z" * 43)
        self.assertEqual(flow.form_request(bad)[0], 400)
        self.assertEqual(flow.form_request(flow.code_args())[0], 400)
        self.assertEqual(flow.state.observations()["issuedGenerations"], [])
        flow = Flow(); flow.connect()
        self.assertEqual(flow.form_request(flow.code_args())[0], 400)
        self.assertEqual(flow.authorize()[0], 400)
        self.assertEqual(flow.state.observations()["counts"]["code"], 1)

    def test_exact_authorization_scope_client_callback_and_query(self):
        for values in ({"scope": "tweet.write"}, {"client_id": "wrong"},
                {"redirect_uri": "https://elsewhere.example/callback"}, {"state": "short"},
                {"code_challenge_method": "plain"}, {"unknown": "refused"}):
            flow = Flow()
            self.assertEqual(flow.authorize(**values)[0], 400)
            self.assertEqual(flow.state.observations()["issuedGenerations"], [])
        with self.assertRaises(ValueError):
            provider.form(b"a=1&a=2")

    def test_confidential_original_client_required_for_code_refresh_and_cleanup(self):
        flow = Flow(); flow.authorize()
        self.assertEqual(flow.form_request(flow.code_args(), authorization="Basic wrong")[0], 400)
        self.assertEqual(flow.form_request(flow.code_args())[0], 200)
        flow = Flow(); flow.connect(); flow.clock.advance(121)
        args = {"grant_type": "refresh_token", "refresh_token": flow.first["refresh_token"]}
        self.assertEqual(flow.form_request(args, authorization="Basic wrong")[0], 400)
        self.assertEqual(flow.refresh()[0], 200)
        self.assertEqual(flow.refresh()[0], 400)
        args = {"token": flow.first["access_token"], "token_type_hint": "access_token"}
        self.assertEqual(flow.form_request(args, "/2/oauth2/revoke", authorization="Basic wrong")[0], 400)
        self.assertFalse(flow.state.observations()["cleanupComplete"])
        self.assertEqual(flow.revoke(flow.first, "access_token")[0], 200)
        self.assertEqual(flow.revoke(flow.first, "access_token")[0], 400)
        self.assertEqual(flow.form_request(dict(args, token_type_hint="refresh_token"), "/2/oauth2/revoke")[0], 400)

    def test_code_and_access_require_both_original_clocks(self):
        for clock in ("wall", "mono"):
            flow = Flow(); flow.authorize()
            setattr(flow.clock, clock, getattr(flow.clock, clock) + 61)
            self.assertEqual(flow.form_request(flow.code_args())[0], 400)
            flow = Flow(); flow.connect()
            setattr(flow.clock, clock, getattr(flow.clock, clock) + 121)
            self.assertEqual(flow.post("node", flow.first)[0], 400)
            self.assertFalse(flow.state.observations()["initialAccessExpired"])
        flow = Flow(); flow.connect(); flow.clock.wall -= 1
        self.assertEqual(flow.post("node", flow.first)[0], 400)

    def test_exact_stock_bytes_headers_and_token_required(self):
        for extra in (("Cookie", "private-canary"), ("Proxy-Authorization", "private-canary"),
                ("Accept-Encoding", "gzip"), ("Content-Length", "0"), ("User-Agent", "duplicate")):
            flow = Flow(); flow.connect()
            status, _, raw = flow.post("node", flow.first, extra=(extra,))
            self.assertEqual(status, 400)
            self.assertNotIn(b"private-canary", raw)
            self.assertEqual(flow.state.observations()["posts"], [])
        flow = Flow(); flow.connect()
        self.assertEqual(flow.post("node", flow.first, body=profiles.post_body("python"))[0], 400)
        self.assertEqual(flow.post("python", flow.first)[0], 400)
        fake = dict(flow.first, access_token=profiles.PLACEHOLDER)
        self.assertEqual(flow.post("node", fake)[0], 400)
        self.assertEqual(flow.post("node", flow.first)[0], 201)

    def test_identity_is_exact_once_per_issued_generation(self):
        flow = Flow(); flow.connect()
        self.assertEqual(flow.identity(flow.first)[0], 400)
        flow.clock.advance(121); flow.refresh()
        status, _, raw = flow.identity(flow.second)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {"data": {"id": provider.SUBJECT,
            "name": "Synthetic local X account", "username": provider.USERNAME}})
        self.assertEqual(flow.identity(flow.second)[0], 400)

    def test_early_refresh_cannot_claim_original_expiry_or_renew_it(self):
        flow = Flow(); flow.connect()
        before = flow.state.observations()
        flow.clock.advance(61); self.assertEqual(flow.refresh()[0], 200)
        after = flow.state.observations()
        self.assertFalse(after["refreshAfterInitialExpiry"] or after["initialAccessExpired"])
        self.assertEqual(after["initialAccessExpiresAtEpochMs"], before["initialAccessExpiresAtEpochMs"])
        self.assertEqual(flow.refresh()[0], 400)

    def test_fixed_contact_observation_and_original_lifetime_caps(self):
        flow = Flow()
        for _ in range(provider.MAX_CONTACTS + 1):
            self.assertEqual(flow.state.request("GET", "/unknown", [("Host", "api.x.com")])[0], 400)
        view = flow.state.observations()
        self.assertTrue(view["overflowed"])
        self.assertEqual(view["counts"]["total"], provider.MAX_CONTACTS + 1)
        self.assertEqual(view["counts"]["rejected"], provider.MAX_CONTACTS + 1)
        flow = Flow()
        for _ in range(provider.MAX_OBSERVATIONS):
            flow.state.observations()
        with self.assertRaises(ValueError):
            flow.state.observations()
        flow = Flow(); flow.clock.advance(network.KEEPER_SECONDS)
        self.assertEqual(flow.authorize()[0], 400)
        flow.state.stop("expired")
        self.assertEqual(flow.state._view()["terminal"], "expired")

    def test_durable_public_projection_atomic_replacement_and_no_raw_material(self):
        # Direct persistence-helper test, NOT runtime-directory UID admission.
        flow = Flow(); flow.connect()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            flow.state._directory = root
            flow.state._persist()
            path = root / "observations.json"
            first_inode = path.stat().st_ino
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(flow.first["access_token"].encode(), path.read_bytes())
            self.assertEqual(flow.post("node", flow.first)[0], 201)
            self.assertNotEqual(path.stat().st_ino, first_inode)
            self.assertEqual(json.loads(path.read_bytes())["counts"]["posts"], 1)
            self.assertFalse((root / "observations.next").exists())
            os.link(path, root / "extra")
            with self.assertRaises(ValueError):
                flow.state._persist()

    def test_real_http_handler_counts_body_framing_refusal_and_valid_passthrough(self):
        flow = Flow(); flow.connect()
        def handler(fields, raw):
            instance = object.__new__(provider.Handler)
            instance.server = SimpleNamespace(state=flow.state)
            instance.command, instance.path = "POST", profiles.TARGET
            instance.headers = Message()
            for name, value in fields:
                instance.headers[name] = value
            instance.rfile = io.BytesIO(raw)
            sent = []
            instance.send = lambda *args: sent.append(args)
            instance.handle_request()
            return sent
        fields = list(profiles.provider_headers("node").items()) + [("Authorization", "Bearer " + flow.first["access_token"])]
        self.assertEqual(handler(fields, b"")[0][0], 400)
        self.assertEqual(flow.state.observations()["counts"]["rejected"], 1)
        self.assertEqual(handler(fields, profiles.post_body("node"))[0][0], 201)
        self.assertEqual(flow.state.observations()["counts"]["posts"], 1)

    def test_network_source_closed_addresses_and_different_private_custody(self):
        lines = [line.split() for line in network.HOSTS.decode().splitlines()]
        mapping = {host: row[0] for row in lines for host in row[1:]}
        self.assertEqual(mapping["x.com"], "93.184.216.34")
        self.assertEqual(mapping["api.x.com"], "93.184.216.34")
        self.assertEqual(mapping[network.CONTROL_HOST], "127.0.0.1")
        self.assertEqual(mapping[network.PROXY_HOST], "127.0.0.1")
        self.assertEqual(provider.CALLBACK_URL, "https://catchplate-x.example.com/api/oauth/callback/x")
        self.assertEqual((network.KEEPER_SECONDS, network.EDGE_SECONDS), (300, 240))
        source = Path(network.__file__).read_text()
        self.assertIn('custody = ROOT / "x-custody"', source)
        self.assertIn('custody.mkdir(mode=0o700)', source)
        self.assertIn('os.chown(custody, 10001, 10001)', source)
        self.assertNotIn('setdefault', source)


def deny_network(event, _args):
    if event in ("socket.__new__", "socket.connect", "socket.bind", "socket.getaddrinfo"):
        raise AssertionError("inert fixture controls attempted network access")


if __name__ == "__main__":
    sys.addaudithook(deny_network)
    unittest.main()

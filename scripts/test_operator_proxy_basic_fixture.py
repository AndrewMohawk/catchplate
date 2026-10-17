#!/usr/bin/env python3
"""Pure Basic-client upstream oracle tests; no HTTP, files or subprocesses.

These tests do not prove proxy forwarding. The separately bounded real-client
check must reach this case through the actual proxy with its stock clients.
"""
from __future__ import annotations

import base64
import hashlib
import unittest

try:
    from scripts import operator_ordinary_client_fixture as fixture
except ModuleNotFoundError:
    import operator_ordinary_client_fixture as fixture


CASE = "json_proxy_basic_v1"
AUTHORIZATION = b"Bearer synthetic-operator-" + b"A" * 43
DIGEST = hashlib.sha256(AUTHORIZATION).hexdigest()
WORKLOAD_TOKEN = b"W" * 43
USERNAME = b"12345678-1234-4234-8234-123456789abc"
BASIC_VALUE = base64.b64encode(USERNAME + b":" + WORKLOAD_TOKEN)
USER_AGENT = b"catchplate-test-run/operator-check-" + b"a" * 32
ACCEPTS = (b"application/json", b"application/json;q=0.9",
           b"application/json;q=0.8", b"application/json;q=0.7")


def headers():
    return [(b"host", b"demo-upstream:8443"), (b"authorization", AUTHORIZATION),
            (b"content-type", b"application/json"),
            (b"content-length", str(fixture.REQUEST_BODY_LENGTH).encode("ascii")),
            (b"accept", ACCEPTS[0]), (b"user-agent", USER_AGENT)]


def replace_header(name, values):
    return [(key, value) for key, value in headers() if key != name] + [(name, value) for value in values]


def query(case=CASE, digest=DIGEST):
    return fixture.build_target(case, digest).split("?", 1)[1].encode("ascii")


def admit(fields=None, *, case=CASE, raw_query=None):
    return fixture.admit_request("POST", b"/ordinary-client", query(case) if raw_query is None else raw_query,
                                 headers() if fields is None else fields)


class ProxyBasicFixtureTests(unittest.TestCase):
    def rejected(self, function):
        with self.assertRaises(fixture.FixtureRejected) as caught:
            function()
        self.assertEqual(str(caught.exception), "ordinary client fixture rejected")
        for value in (WORKLOAD_TOKEN, BASIC_VALUE, AUTHORIZATION, DIGEST.encode(), USER_AGENT):
            self.assertNotIn(value.decode(), repr(caught.exception))

    def test_closed_case_accepts_exact_client_shapes_and_fixed_v2_result(self):
        expected = fixture.Outcome(200, fixture.REQUEST_BODY,
            (("content-type", "application/json"),) + fixture.V2_RESPONSE_METADATA)
        for accept in ACCEPTS:
            for connection in ([], [(b"connection", b"close")], [(b"connection", b"keep-alive")]):
                for encoding in ([], [(b"accept-encoding", b"identity")]):
                    fields = replace_header(b"accept", [accept]) + connection + encoding
                    with self.subTest(accept=accept, connection=connection, encoding=encoding):
                        admitted = admit(fields)
                        self.assertEqual(admitted, fixture.Admission(CASE, fixture.REQUEST_BODY_LENGTH))
                        self.assertEqual(fixture.verify_body(admitted, fixture.REQUEST_BODY), expected)
        self.assertEqual(admit([(name.title(), value) for name, value in headers()]), admit())
        self.assertEqual(admit(replace_header(b"content-type", [b"application/json; charset=utf-8"])), admit())

    def test_every_required_header_is_required_and_every_physical_header_is_singleton(self):
        for name, value in headers():
            with self.subTest(name=name):
                self.rejected(lambda: admit(replace_header(name, [])))
                self.rejected(lambda: admit(headers() + [(name, value)]))
                self.rejected(lambda: admit(headers() + [(name.title(), value)]))
        for name, value in ((b"connection", b"close"), (b"accept-encoding", b"identity")):
            self.rejected(lambda: admit(headers() + [(name, value), (name.title(), value)]))

    def test_all_unlisted_physical_headers_are_refused(self):
        for name in (b"x-extra", b"cookie", b"forwarded", b"x-forwarded-for", b"via", b"te",
                     b"proxy-authorization", b"proxy-connection", b"content-encoding", b"trailer",
                     b"transfer-encoding", b"authorization-extra"):
            for value in (b"", b"identity", WORKLOAD_TOKEN, BASIC_VALUE, b"Basic " + BASIC_VALUE):
                with self.subTest(name=name, value_length=len(value)):
                    self.rejected(lambda: admit(headers() + [(name, value)]))

    def test_host_accept_user_agent_and_optional_values_are_closed(self):
        wrong = {
            b"host": (b"demo-upstream", b"DEMO-UPSTREAM:8443", b"demo-upstream:8443.", b"other:8443"),
            b"accept": (b"*/*", b"application/json;q=1.0", b"application/json;q=0.6", b"application/json, text/plain"),
            b"user-agent": (b"catchplate-test-run", USER_AGENT[:-1], USER_AGENT + b"a",
                            USER_AGENT[:-32] + b"A" * 32, USER_AGENT + b" extra"),
            b"connection": (b"Close", b"keep-alive, upgrade", b"upgrade", b""),
            b"accept-encoding": (b"Identity", b"gzip", b"identity, gzip", b""),
        }
        for name, values in wrong.items():
            for value in values:
                with self.subTest(name=name, value_length=len(value)):
                    self.rejected(lambda: admit(replace_header(name, [value])))

    def test_workload_token_and_basic_form_cannot_hide_in_any_admitted_header(self):
        self.assertEqual(len(WORKLOAD_TOKEN), 43)
        self.assertEqual(len(BASIC_VALUE), 108)
        for name, original in headers() + [(b"connection", b"close"), (b"accept-encoding", b"identity")]:
            for secret in (WORKLOAD_TOKEN, BASIC_VALUE, b"Basic " + BASIC_VALUE):
                for value in (secret, original + b" " + secret, secret + b" " + original):
                    with self.subTest(name=name, value_length=len(value)):
                        self.rejected(lambda: admit(replace_header(name, [value])))

    def test_provider_authorization_and_body_keep_independent_fixed_oracles(self):
        for value in (fixture.DUMMY_AUTHORIZATION.encode(), b"Bearer " + WORKLOAD_TOKEN,
                      b"Basic " + BASIC_VALUE, b"Bearer synthetic-operator-" + b"B" * 43):
            self.rejected(lambda: admit(replace_header(b"authorization", [value])))
        for body in (b"", fixture.REQUEST_BODY + b" ", fixture.REQUEST_BODY.replace(b"true", b"null")):
            self.rejected(lambda: fixture.verify_body(admit(), body))
        for raw in (query() + b"&extra=" + WORKLOAD_TOKEN, query().replace(DIGEST.encode(), b"0" * 64),
                    query().replace(fixture.REQUEST_BODY_SHA256.encode(), b"0" * 64),
                    query().replace(b"json_proxy_basic_v1", b"json_proxy_basic_v2")):
            self.rejected(lambda: admit(raw_query=raw))
        for name, values in ((b"content-type", [b"text/plain"]),
                             (b"content-length", [str(fixture.REQUEST_BODY_LENGTH + 1).encode()])):
            self.rejected(lambda: admit(replace_header(name, values)))

    def test_no_header_digest_or_workload_secret_is_reflected(self):
        admitted = admit()
        outcome = fixture.verify_body(admitted, fixture.REQUEST_BODY)
        for value in (WORKLOAD_TOKEN, BASIC_VALUE, AUTHORIZATION, DIGEST.encode(), USER_AGENT,
                      fixture.DUMMY_AUTHORIZATION.encode()):
            self.assertNotIn(value.decode(), repr(admitted))
            self.assertNotIn(value.decode(), repr(outcome))
            self.assertNotIn(value, outcome.body)
            self.assertNotIn(value, fixture.REJECTION_BODY)
        self.assertEqual(outcome.headers, (("content-type", "application/json"),) + fixture.V2_RESPONSE_METADATA)

    def test_historical_cases_retain_their_open_extra_headers_and_fixed_results(self):
        minimal = [(name, value) for name, value in headers()
                   if name in {b"authorization", b"content-type", b"content-length"}]
        for case in ("json", "empty", "json_v2", "empty_v2"):
            fields = minimal + [(b"x-legacy", b"first"), (b"X-Legacy", b"second"), (b"content-encoding", b"identity")]
            admitted = admit(fields, case=case)
            empty = case in {"empty", "empty_v2"}
            media = fixture.EMPTY_RESPONSE_CONTENT_TYPE if empty else "application/json"
            metadata = fixture.V2_RESPONSE_METADATA if case.endswith("_v2") else ()
            self.assertEqual(fixture.verify_body(admitted, fixture.REQUEST_BODY),
                fixture.Outcome(204 if empty else 200, b"" if empty else fixture.REQUEST_BODY,
                                (("content-type", media),) + metadata))
            self.rejected(lambda: admit(fields + [(b"proxy-authorization", b"Basic " + BASIC_VALUE)], case=case))


if __name__ == "__main__":
    unittest.main()

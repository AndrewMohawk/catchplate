#!/usr/bin/env python3
"""Pure synthetic upstream oracle tests: stdlib only, no server or HTTP calls.

These checks do not prove proxy forwarding or serializer/wire behavior. The
separate private acceptance checker must observe those through the real proxy.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
import unittest

try:
    from scripts import operator_ordinary_client_fixture as fixture
except ModuleNotFoundError:
    import operator_ordinary_client_fixture as fixture


AUTHORIZATION = b"Bearer synthetic-operator-" + b"A" * 43
AUTHORIZATION_SHA256 = hashlib.sha256(AUTHORIZATION).hexdigest()


def query(case="json", digest=AUTHORIZATION_SHA256):
    return fixture.build_target(case, digest).split("?", 1)[1].encode("ascii")


def headers():
    return [(b"authorization", AUTHORIZATION),
            (b"content-type", b"application/json"),
            (b"content-length", str(fixture.REQUEST_BODY_LENGTH).encode("ascii"))]


def admit(*, case="json", method="POST", path=b"/ordinary-client", fields=None, raw_query=None):
    return fixture.admit_request(method, path, query(case) if raw_query is None else raw_query,
                                 headers() if fields is None else fields)


def replacing(name, values):
    return [(key, value) for key, value in headers() if key != name] + [(name, value) for value in values]


class OrdinaryClientFixtureTests(unittest.TestCase):
    def rejected(self, function, status=None):
        with self.assertRaises(fixture.FixtureRejected) as caught:
            function()
        self.assertEqual(str(caught.exception), "ordinary client fixture rejected")
        if status is not None:
            self.assertEqual(caught.exception.status_code, status)
        return caught.exception

    def test_fixed_body_is_noncanonical_json_with_large_integer_and_nesting(self):
        raw = fixture.REQUEST_BODY
        parsed = json.loads(raw)
        self.assertEqual(parsed["z"], [100, 18446744073709551617])
        self.assertEqual(parsed["escaped"], "a/b")
        self.assertEqual(parsed["nested"]["items"], [True, None, {"number": 1.23}])
        self.assertTrue(raw.startswith(b"\n{\n") and raw.endswith(b"}\r\n"))
        self.assertIn(b"1e+02", raw)
        self.assertIn(b"1.2300", raw)
        self.assertIn(b"\\u0061\\/b", raw)
        self.assertNotEqual(json.dumps(parsed).encode(), raw)
        self.assertGreater(fixture.MAX_BODY_BYTES, len(raw))
        self.assertEqual(fixture.REQUEST_BODY_LENGTH, len(raw))
        self.assertEqual(fixture.REQUEST_BODY_SHA256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(fixture.JSON_RESPONSE_BODY, raw)

    def test_target_has_exact_three_query_keys_and_fixed_body_expectation(self):
        for case in ("json", "empty"):
            target = fixture.build_target(case, AUTHORIZATION_SHA256)
            self.assertEqual(target, "/ordinary-client?case=" + case
                + "&expectedAuthorizationSha256=" + AUTHORIZATION_SHA256
                + "&expectedBodySha256=" + fixture.REQUEST_BODY_SHA256)
            self.assertEqual(tuple(part.split("=", 1)[0] for part in target.split("?", 1)[1].split("&")),
                             fixture.QUERY_KEYS)
        for case, digest in (("unknown", AUTHORIZATION_SHA256), ("json&extra=1", AUTHORIZATION_SHA256),
                ("json", "sha256:" + AUTHORIZATION_SHA256), ("json", AUTHORIZATION_SHA256.upper()),
                ("json", "a" * 63), ("json", "a" * 65), ("json", None), ("json", "a" * 64 + "\n")):
            with self.subTest(case=case, digest_type=type(digest).__name__):
                self.rejected(lambda: fixture.build_target(case, digest))

    def test_only_exact_post_path_and_canonical_query_are_admitted(self):
        valid = query()
        for method in ("GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "post", ""):
            self.rejected(lambda: admit(method=method), 405)
        for path in (b"/echo", b"/ordinary-client/", b"/%6frdinary-client", b"", "/ordinary-client"):
            self.rejected(lambda: admit(path=path))
        invalid = (b"", valid + b"&unknown=1", valid + b"&case=json", valid + b"&",
            valid.replace(b"case=json", b"case=JSON"), valid.replace(b"case=json", b"case=%6ason"),
            valid.replace(b"case=json", b"case=empty+"), valid.replace(b"case=json", b"%63ase=json"),
            b"&".join(reversed(valid.split(b"&"))), valid + b"\n", b"x" * 513,
            valid.replace(fixture.REQUEST_BODY_SHA256.encode(), b"0" * 64),
            valid.replace(b"expectedBodySha256", b"expectedBodyBytes"))
        for index, value in enumerate(invalid):
            with self.subTest(query_case=index):
                self.rejected(lambda: admit(raw_query=value))

    def test_v2_cases_are_explicit_with_the_same_closed_canonical_query_keys(self):
        for case in ("json_v2", "empty_v2"):
            target = fixture.build_target(case, AUTHORIZATION_SHA256)
            self.assertEqual(target, "/ordinary-client?case=" + case
                + "&expectedAuthorizationSha256=" + AUTHORIZATION_SHA256
                + "&expectedBodySha256=" + fixture.REQUEST_BODY_SHA256)
            self.assertEqual(tuple(part.split("=", 1)[0] for part in target.split("?", 1)[1].split("&")),
                             fixture.QUERY_KEYS)
            self.assertEqual(admit(case=case), fixture.Admission(case, fixture.REQUEST_BODY_LENGTH))
            raw_query = query(case)
            for invalid in (raw_query + b"&metadata=1", b"&".join(reversed(raw_query.split(b"&"))),
                            raw_query.replace(case.encode(), case.upper().encode()),
                            raw_query.replace(b"_v2", b"%5fv2"), raw_query.replace(b"_v2", b"_v3")):
                self.rejected(lambda: admit(raw_query=invalid))
        for case in ("json_v3", "empty_v2&server=reflected", "json+v2"):
            self.rejected(lambda: fixture.build_target(case, AUTHORIZATION_SHA256))

    def test_fixed_metadata_is_emitted_only_by_v2_json_and_empty204(self):
        self.assertEqual(fixture.V2_RESPONSE_METADATA, (
            ("server", "serverware-synthetic-upstream"),
            ("date", "Thu, 01 Jan 1970 00:00:00 GMT"), ("cache-control", "no-store")))
        for base, status, body, media in (("json", 200, fixture.REQUEST_BODY, "application/json"),
                                        ("empty", 204, b"", fixture.EMPTY_RESPONSE_CONTENT_TYPE)):
            legacy = fixture.verify_body(admit(case=base), fixture.REQUEST_BODY)
            outcome = fixture.verify_body(admit(case=base + "_v2"), fixture.REQUEST_BODY)
            self.assertEqual((outcome.status_code, outcome.body), (status, body))
            self.assertEqual(legacy.headers, (("content-type", media),))
            self.assertEqual(outcome.headers, legacy.headers + fixture.V2_RESPONSE_METADATA)
            self.assertFalse({"content-length", "transfer-encoding", "trailer"} & dict(outcome.headers).keys())
            for secret in (AUTHORIZATION.decode(), AUTHORIZATION_SHA256, fixture.DUMMY_AUTHORIZATION):
                self.assertNotIn(secret, repr(outcome))

    def test_v2_keeps_exact_body_and_credential_oracles(self):
        for case in ("json_v2", "empty_v2"):
            for body in (b"", fixture.REQUEST_BODY + b" ", json.dumps(json.loads(fixture.REQUEST_BODY)).encode()):
                self.rejected(lambda: fixture.verify_body(admit(case=case), body))
            self.rejected(lambda: admit(case=case, fields=replacing(b"authorization", [fixture.DUMMY_AUTHORIZATION.encode()])))
            self.rejected(lambda: admit(case=case, fields=headers() + [(b"authorization", AUTHORIZATION)]))
            self.rejected(lambda: admit(raw_query=query(case).replace(fixture.REQUEST_BODY_SHA256.encode(), b"0" * 64)))

    def test_exact_injected_authorization_is_required_without_exposing_it(self):
        accepted = admit()
        self.assertEqual(accepted, fixture.Admission("json", fixture.REQUEST_BODY_LENGTH))
        self.assertNotIn(AUTHORIZATION.decode(), repr(accepted))
        self.assertNotIn(AUTHORIZATION_SHA256, repr(accepted))
        candidates = (fixture.DUMMY_AUTHORIZATION.encode(), b"Bearer SERVERWARE_WRONG",
            b"Bearer actual-provider-secret", b"Bearer synthetic-operator-" + b"A" * 31,
            b"Bearer synthetic-operator-" + b"A" * 129, b"Bearer synthetic-operator-" + b"!" * 43,
            b"bearer synthetic-operator-" + b"A" * 43, AUTHORIZATION + b" ", b" " + AUTHORIZATION, b"")
        for index, authorization in enumerate(candidates):
            # Even a caller supplying the hash of its own dummy/real secret
            # cannot turn this into a successful upstream oracle.
            own_digest = hashlib.sha256(authorization).hexdigest()
            with self.subTest(auth_case=index):
                self.rejected(lambda: admit(fields=replacing(b"authorization", [authorization]),
                                             raw_query=query(digest=own_digest)))
        other_synthetic = b"Bearer synthetic-operator-" + b"B" * 43
        self.rejected(lambda: admit(fields=replacing(b"authorization", [other_synthetic])))
        self.assertEqual(admit(fields=replacing(b"authorization", [other_synthetic]),
            raw_query=query(digest=hashlib.sha256(other_synthetic).hexdigest())), accepted)

    def test_physical_authorization_singleton_and_zero_proxy_authorization(self):
        for fields in (replacing(b"authorization", []), replacing(b"authorization", [AUTHORIZATION] * 2),
                headers() + [(b"Authorization", AUTHORIZATION)],
                headers() + [(b"proxy-authorization", b"")],
                headers() + [(b"Proxy-Authorization", b"Basic synthetic")]):
            self.rejected(lambda: admit(fields=fields))
        mixed_case = [(key.title(), value) for key, value in headers()]
        self.assertEqual(admit(fields=mixed_case), admit())

    def test_framing_is_bounded_singleton_and_unambiguous(self):
        length = str(fixture.REQUEST_BODY_LENGTH).encode()
        invalid_lengths = ([], [length, length], [b"0" + length], [b"+" + length],
            [length + b" "], [b" " + length], [b"-1"], [b"0"], [b""], [b"1, 1"], [b"100000"],
            [str(fixture.REQUEST_BODY_LENGTH + 1).encode()])
        for values in invalid_lengths:
            self.rejected(lambda: admit(fields=replacing(b"content-length", values)))
        self.rejected(lambda: admit(fields=replacing(b"content-length", [b"65537"])), 413)
        for name, value in ((b"transfer-encoding", b"chunked"), (b"Transfer-Encoding", b"identity"),
                (b"transfer-encoding", b""), (b"trailer", b"x-result"), (b"Trailer", b"")):
            self.rejected(lambda: admit(fields=headers() + [(name, value)]))

    def test_media_and_content_encoding_are_explicit_and_singleton(self):
        for value in (b"application/json", b"application/json; charset=utf-8"):
            self.assertEqual(admit(fields=replacing(b"content-type", [value])), admit())
        for values in ([], [b"text/plain"], [b"application/json;"] , [b"application/json"] * 2,
                [b"application/json; charset=iso-8859-1"], [b"application/json, text/plain"],
                [b"application/json; charset=utf-8; charset=utf-8"]):
            self.rejected(lambda: admit(fields=replacing(b"content-type", values)), 415)
        self.assertEqual(admit(fields=headers() + [(b"content-encoding", b"identity")]), admit())
        for values in ([b"gzip"], [b"br"], [b""], [b"identity"] * 2, [b"identity, gzip"]):
            self.rejected(lambda: admit(fields=replacing(b"content-encoding", values)), 415)

    def test_malformed_or_excessive_physical_headers_are_refused(self):
        invalid = (None, {b"authorization": AUTHORIZATION}, headers() + [(b"bad name", b"x")],
            headers() + [(b"x", b"line\r\nbreak")], headers() + [(b"x", b"nul\0")],
            headers() + [(b"x", b"tab\t")], headers() + [(b"x", b"del\x7f")],
            headers() + [("not-bytes", b"x")], headers() + [(b"x", "not-bytes")],
            headers() + [(b"x",)], headers() + [(b"x", b"a", b"b")],
            headers() + [(b"x", b"a" * fixture.MAX_HEADER_BYTES)],
            headers() + [(b"x", b"a")] * fixture.MAX_HEADER_COUNT)
        for index, fields in enumerate(invalid):
            with self.subTest(header_case=index):
                self.rejected(lambda: fixture.admit_request("POST", b"/ordinary-client", query(), fields))

    def test_json_result_is_exact_verified_raw_body_not_reserialized(self):
        raw = bytes(bytearray(fixture.REQUEST_BODY))
        outcome = fixture.verify_body(admit(), raw)
        self.assertEqual(outcome.status_code, 200)
        self.assertIs(outcome.body, raw)
        self.assertEqual(outcome.body, fixture.JSON_RESPONSE_BODY)
        self.assertEqual(outcome.headers, (("content-type", "application/json"),))
        self.assertNotIn(AUTHORIZATION, outcome.body)
        self.assertNotIn(AUTHORIZATION_SHA256.encode(), outcome.body)
        self.assertNotIn(fixture.DUMMY_AUTHORIZATION.encode(), outcome.body)

    def test_body_oracle_is_independent_of_caller_digest_length_and_json_semantics(self):
        raw = fixture.REQUEST_BODY
        changed = raw.replace(b"true", b"null")
        self.assertEqual(len(changed), len(raw))
        bodies = (b"", raw[:-1], raw + b" ", changed, json.dumps(json.loads(raw)).encode(),
                  b"{}", b"null", b"x" * (fixture.MAX_BODY_BYTES + 1), bytearray(raw))
        for index, body in enumerate(bodies):
            with self.subTest(body_case=index):
                self.rejected(lambda: fixture.verify_body(admit(), body))
        changed_query = query().replace(fixture.REQUEST_BODY_SHA256.encode(), hashlib.sha256(changed).hexdigest().encode())
        self.rejected(lambda: admit(raw_query=changed_query))
        for admitted in (replace(admit(), content_length=len(raw) + 1), replace(admit(), case="unknown"), None):
            self.rejected(lambda: fixture.verify_body(admitted, raw))

    def test_empty_case_is_real_204_without_body_or_synthesized_length(self):
        outcome = fixture.verify_body(admit(case="empty"), fixture.REQUEST_BODY)
        self.assertEqual(outcome.status_code, 204)
        self.assertEqual(outcome.body, b"")
        self.assertEqual(outcome.headers, (("content-type", "application/json; charset=utf-8"),))
        self.assertFalse({"content-length", "transfer-encoding", "trailer"} & dict(outcome.headers).keys())
        self.rejected(lambda: fixture.verify_body(admit(case="empty"), b""))

    def test_chunk_reader_retains_only_bounded_bytes_and_stops_on_first_overflow(self):
        seen = []
        async def chunks(values):
            for index, value in enumerate(values):
                seen.append(index)
                yield value
        raw = fixture.REQUEST_BODY
        self.assertEqual(asyncio.run(fixture.read_bounded_body(chunks([b"", raw[:7], raw[7:], b""]))), raw)
        at_limit = b"x" * fixture.MAX_BODY_BYTES
        self.assertEqual(asyncio.run(fixture.read_bounded_body(chunks([at_limit]))), at_limit)
        for values in ([at_limit, b"x", b"must not consume"], [at_limit + b"x", b"must not consume"]):
            seen.clear()
            self.rejected(lambda: asyncio.run(fixture.read_bounded_body(chunks(values))), 413)
            self.assertEqual(len(seen), len(values) - 1)
        self.rejected(lambda: asyncio.run(fixture.read_bounded_body(chunks(["not bytes"]))))


if __name__ == "__main__":
    unittest.main()

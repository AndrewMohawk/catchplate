#!/usr/bin/env python3
"""Offline ECR signing foundation checks, not AWS/proxy/authorization acceptance.

Default: stdlib-only tests. --botocore additionally requires the installed,
unmodified Botocore 1.34.46 oracle. --emit-botocore-vectors prints synthetic
reference vectors from that oracle only; it never calls the production signer.
No session, ambient credentials, response, transport or provider is used.
"""
import base64
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import aws_ecr_signing as signing


# Public documentation examples, NOT real credentials. Session key/token are
# synthetic companions for this offline test only. Never consult AWS_* inputs.
ACCESS = "AKIAIOSFODNN7EXAMPLE"
SESSION_ACCESS = "ASIAIOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
TOKEN = "synthetic-session-token+/="
REGION = "us-east-1"
AUTHORITY = "api.ecr.us-east-1.amazonaws.com"
STAMP = "20261010T120000Z"
NOW = int(datetime(2026, 10, 10, 12, tzinfo=timezone.utc).timestamp())
MONO = 1_000_000_000_000
EXPIRY = "2026-10-10T12:10:00Z"
ACTION_NAMES = (
    "BatchCheckLayerAvailability", "InitiateLayerUpload", "UploadLayerPart",
    "CompleteLayerUpload", "PutImage",
)
PART = b"synthetic-layer-part\x00\xff"
DIGEST = "sha256:" + hashlib.sha256(PART).hexdigest()
UPLOAD_ID = "00000000-0000-4000-8000-000000000001"
MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
MANIFEST = json.dumps({"schemaVersion": 2, "mediaType": MEDIA_TYPE,
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": 2,
               "digest": "sha256:" + hashlib.sha256(b"{}").hexdigest()}, "layers": []},
    sort_keys=True, separators=(",", ":"))


def prohibit_network(event, args):
    if event.startswith("socket."):
        raise PermissionError("offline signer tests forbid sockets and DNS")


# Separate-script, process-wide safety boundary, before any optional SDK import.
sys.addaudithook(prohibit_network)


def bodies():
    common = {"registryId": "123456789012", "repositoryName": "catchplate-fixture"}
    fields = (
        {"layerDigests": [DIGEST]}, {},
        {"uploadId": UPLOAD_ID, "partFirstByte": 0, "partLastByte": len(PART) - 1,
         "layerPartBlob": base64.b64encode(PART).decode("ascii")},
        {"uploadId": UPLOAD_ID, "layerDigests": [DIGEST]},
        {"imageManifest": MANIFEST, "imageManifestMediaType": MEDIA_TYPE,
         "imageTag": "fixture", "imageDigest": "sha256:" + hashlib.sha256(MANIFEST.encode()).hexdigest()},
    )
    return tuple((action, json.dumps({**common, **extra}).encode("utf-8"))
                 for action, extra in zip(ACTION_NAMES, fields))


def credentials(session=False, **changes):
    fields = {"kind": "session" if session else "long_term",
              "access_key_id": SESSION_ACCESS if session else ACCESS,
              "secret_access_key": SECRET,
              "session_token": TOKEN if session else None,
              "expires_at": EXPIRY if session else None}
    return signing.Credentials(**{**fields, **changes})


def clock(wall=0, mono=0):
    return signing.ClockObservation(NOW + wall, MONO + mono)


def dispatch_fields(signed, body=b"{}", **changes):
    return {**{name: getattr(signed, name) for name in
               ("method", "scheme", "authority", "path", "query", "headers")},
            "body": body, "clock": clock(), **changes}


def stock_vector(action, body, session=False):
    """Independent reference: actual installed SDK, explicit fake tuple only."""
    import botocore
    import botocore.auth as auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials, CredentialResolver

    if (botocore.__version__ != "1.34.46" or Path(botocore.__file__).resolve()
            != Path("/usr/lib/python3/dist-packages/botocore/__init__.py")):
        raise AssertionError("the pinned installed Botocore oracle is required")

    class FrozenDateTime(datetime):
        @classmethod
        def utcnow(cls):
            return cls(2026, 10, 10, 12, 0, 0)

    request = AWSRequest(method="POST", url="https://" + AUTHORITY + "/", data=body,
        headers={"Content-Type": "application/x-amz-json-1.1", "Host": AUTHORITY,
                 "X-Amz-Target": "AmazonEC2ContainerRegistry_V20150921." + action})
    signer = auth.SigV4Auth(Credentials(SESSION_ACCESS if session else ACCESS,
                                     SECRET, TOKEN if session else None), "ecr", REGION)
    with patch.object(auth, "datetime", SimpleNamespace(datetime=FrozenDateTime)), \
            patch.object(auth.logger, "disabled", True), \
            patch.object(CredentialResolver, "load_credentials",
                         side_effect=AssertionError("ambient credential lookup forbidden")):
        signer.add_auth(request)
        headers = dict(sorted((name.lower(), value) for name, value in request.headers.items()))
        # Authorization is an output, not a canonical input. Preserve the actual
        # SDK result, then remove it before asking its canonicalizer to inspect.
        del request.headers["Authorization"]
        canonical = signer.canonical_request(request)
        string_to_sign = signer.string_to_sign(request, canonical)
    # Botocore 1.34.46 AWSRequestPreparer._prepare_body explicitly represents
    # data=b"" as prepared body=None; SigV4Auth.payload hashes the empty payload.
    # Require that exact zero-length representation, never normalize nonempty
    # bytes or accept a missing nonempty body.
    prepared_body = request.body
    if (type(request.data) is not bytes or request.data != body
            or (prepared_body is not None if body == b"" else
                type(prepared_body) is not bytes or prepared_body != body)):
        raise AssertionError("SDK changed the supplied body")
    return {"action": action, "kind": "session" if session else "long_term",
            "bodyBase64": base64.b64encode(body).decode("ascii"),
            "bodySha256": hashlib.sha256(body).hexdigest(), "headers": headers,
            "canonicalRequest": canonical, "stringToSign": string_to_sign}


class AwsEcrSigningTests(unittest.TestCase):
    def reject(self, function, *args, **kwargs):
        with self.assertRaises(signing.SigningError) as caught:
            function(*args, **kwargs)
        self.assertEqual(str(caught.exception), "AWS ECR signing unavailable")
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception

    def signed(self, *, body=b"{}", session=False, **changes):
        arguments = {"region": REGION, "action": "PutImage", "body": body, "clock": clock()}
        return signing.sign(credentials(session), **{**arguments, **changes})

    def test_whole_credential_tuple_and_redacted_errors(self):
        self.assertEqual(repr(credentials()), "Credentials(<redacted>)")
        self.assertEqual(repr(credentials(True)), "Credentials(<redacted>)")
        invalid = ({"kind": "unknown"}, {"kind": True}, {"access_key_id": SESSION_ACCESS},
            {"access_key_id": ACCESS.lower()}, {"access_key_id": ACCESS + "A"},
            {"secret_access_key": SECRET[:-1]}, {"secret_access_key": "!" * 40},
            {"secret_access_key": "é" * 40}, {"secret_access_key": b"x" * 40},
            {"session_token": TOKEN}, {"expires_at": EXPIRY})
        for changes in invalid:
            with self.subTest(changes=tuple(changes)):
                self.reject(credentials, **changes)
        for changes in ({"access_key_id": ACCESS}, {"session_token": None},
                {"session_token": ""}, {"session_token": "a b"}, {"session_token": "\n"},
                {"session_token": "é"}, {"session_token": "x" * 8193}, {"expires_at": None}):
            self.reject(credentials, True, **changes)
        self.assertEqual(len(credentials(True, session_token="x" * 8192).session_token), 8192)
        signed = self.signed(session=True)
        self.assertEqual(repr(signed), "SignedRequest(<redacted>)")
        for value in (SECRET, TOKEN, ACCESS, SESSION_ACCESS, "authorization", "canonical_request"):
            self.assertNotIn(value, repr(signed) + repr(credentials(True)))
        with self.assertRaises(FrozenInstanceError):
            signed.body_length = 99
        with self.assertRaises(FrozenInstanceError):
            credentials().secret_access_key = "x" * 40
        self.reject(signing.SignedRequest)

    def test_explicit_transport_accept_is_signed_and_dispatch_bound(self):
        signed = self.signed(include_accept=True)
        headers = dict(signed.headers)
        self.assertEqual(headers["accept"], "*/*")
        self.assertIn("SignedHeaders=accept;content-type;host;x-amz-date;x-amz-target,", headers["authorization"])
        signing.assert_dispatch(signed, **dispatch_fields(signed))
        for changed in (tuple((k, v) for k, v in signed.headers if k != "accept"),
                tuple((k, "application/json" if k == "accept" else v) for k, v in signed.headers)):
            self.reject(signing.assert_dispatch, signed, **dispatch_fields(signed, headers=changed))
        for value in (1, "true", None):
            self.reject(self.signed, include_accept=value)
        self.assertNotIn("accept", dict(self.signed().headers))

    def test_five_actions_exact_owned_headers_and_canonical_input(self):
        self.assertEqual(signing.ACTIONS, frozenset(ACTION_NAMES))
        for session in (False, True):
            for action, body in bodies():
                signed = self.signed(body=body, action=action, session=session)
                expected = {"content-type": "application/x-amz-json-1.1", "host": AUTHORITY,
                    "x-amz-date": STAMP,
                    "x-amz-target": "AmazonEC2ContainerRegistry_V20150921." + action}
                if session:
                    expected["x-amz-security-token"] = TOKEN
                actual = dict(signed.headers)
                authorization = actual.pop("authorization")
                self.assertEqual(actual, expected)
                self.assertEqual(signed.headers, tuple(sorted(signed.headers)))
                names = ";".join(sorted(expected))
                canonical = ("POST\n/\n\n" + "".join(key + ":" + expected[key] + "\n"
                    for key in sorted(expected)) + "\n" + names + "\n" + hashlib.sha256(body).hexdigest())
                self.assertEqual(signed.canonical_request, canonical.encode("ascii"))
                self.assertEqual(signed.string_to_sign, "AWS4-HMAC-SHA256\n" + STAMP
                    + "\n20261010/us-east-1/ecr/aws4_request\n"
                    + hashlib.sha256(canonical.encode("ascii")).hexdigest())
                key = SESSION_ACCESS if session else ACCESS
                prefix = "AWS4-HMAC-SHA256 Credential=" + key + "/20261010/us-east-1/ecr/aws4_request, SignedHeaders=" + names + ", Signature="
                self.assertTrue(authorization.startswith(prefix))
                self.assertRegex(authorization[len(prefix):], r"^[0-9a-f]{64}$")
                self.assertEqual((signed.method, signed.scheme, signed.authority, signed.path, signed.query),
                                 ("POST", "https", AUTHORITY, "/", ""))
                signing.assert_dispatch(signed, **dispatch_fields(signed, body))

    def test_opaque_bytes_limits_and_no_reserialization(self):
        signatures = set()
        for body in (b"", b"{}", b"{ }", b"not-json\x00\xff", b'{"x":1,"x":2}'):
            signed = self.signed(body=body)
            self.assertEqual((signed.body_length, signed.body_sha256), (len(body), hashlib.sha256(body).hexdigest()))
            signing.assert_dispatch(signed, **dispatch_fields(signed, body))
            signatures.add(dict(signed.headers)["authorization"])
        self.assertEqual(len(signatures), 5)  # Opaque binding, not JSON authorization.
        self.assertEqual(signing.MAX_BODY_BYTES, 32 * 1024 * 1024)
        body = b"x" * signing.MAX_BODY_BYTES
        signed = self.signed(body=body)
        signing.assert_dispatch(signed, **dispatch_fields(signed, body))
        self.reject(self.signed, body=body + b"x")
        for body in ("{}", bytearray(b"{}"), memoryview(b"{}"), None):
            self.reject(self.signed, body=body)

    def test_closed_region_action_and_signer_owned_target(self):
        for region in ("", "US-east-1", "us-east-01", "us-east-0", "us-east-100", "cn-north-1",
                "us-gov-west-1", "us-east-1.amazonaws.com", "us-east-1:443", "us-east-1\n",
                "us-" + "a" * 59 + "-1", True, None):
            self.reject(self.signed, region=region)
        long_region = "us-" + "a" * 58 + "-1"
        self.assertEqual(len(long_region), 63)
        self.assertEqual(self.signed(region=long_region).authority, "api.ecr." + long_region + ".amazonaws.com")
        for action in ("GetAuthorizationToken", "DeleteRepository", "ecr:PutImage", "putImage",
                       "PutImage\n", "", True, None):
            self.reject(self.signed, action=action)
        # There is deliberately no caller-supplied service, URL, signing date or
        # header argument. TypeError here is normal Python signature validation.
        for key, value in (("service", "s3"), ("url", "https://invalid.invalid"),
                           ("headers", {}), ("date", STAMP)):
            with self.assertRaises(TypeError):
                signing.sign(credentials(), region=REGION, action="PutImage", body=b"{}", clock=clock(), **{key: value})

    def test_clock_and_session_calendar_lifetime_boundaries(self):
        for wall, mono in ((True, MONO), (NOW, True), (-1, MONO), (253402300800, MONO),
                           (NOW, -1), (NOW, 2**63), (1.0, MONO), (NOW, 1.0), (None, MONO)):
            self.reject(signing.ClockObservation, wall, mono)
        for seconds, stamp in ((0, "19700101T000000Z"), (253402300799, "99991231T235959Z")):
            self.assertEqual(dict(self.signed(clock=signing.ClockObservation(seconds, 0)).headers)["x-amz-date"], stamp)
        for expiry in ("2026-02-29T12:00:00Z", "2026-10-10T24:00:00Z", "2026-10-10T12:00:60Z",
                "2026-10-10T12:00:00+00:00", "2026-10-10T12:00:00.0Z", "2026-10-10T12:00:00z",
                "2026-10-10T12:00:00", "1969-12-31T23:59:59Z", "10000-01-01T00:00:00Z",
                "2026-13-01T00:00:00Z", "2026-01-00T00:00:00Z", datetime(2026, 10, 10), True):
            self.reject(credentials, True, expires_at=expiry)
        credentials(True, expires_at="2028-02-29T12:00:00Z")
        for seconds in (0, 5, -1):
            expiry = datetime.fromtimestamp(NOW + seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.reject(signing.sign, credentials(True, expires_at=expiry), region=REGION,
                        action="PutImage", body=b"{}", clock=clock())
        expiry = "2026-10-10T12:00:06Z"
        signing.sign(credentials(True, expires_at=expiry), region=REGION, action="PutImage", body=b"{}", clock=clock())
        self.reject(self.signed, clock=datetime(2026, 10, 10, tzinfo=timezone.utc))

    def test_dispatch_exact_request_headers_body_and_optional_length(self):
        for session in (False, True):
            signed = self.signed(session=session)
            valid = signed.headers + (("content-length", "2"),)
            signing.assert_dispatch(signed, **dispatch_fields(signed, headers=tuple(reversed(valid))))
            for name, value in (("method", "GET"), ("scheme", "http"), ("authority", AUTHORITY + ":443"),
                    ("authority", AUTHORITY.upper()), ("authority", "api.ecr.us-west-2.amazonaws.com"),
                    ("path", "/other"), ("query", "x=1"), ("body", b"[]"), ("body", b"{} "),
                    ("body", bytearray(b"{}"))):
                self.reject(signing.assert_dispatch, signed, **dispatch_fields(signed, **{name: value}))
            for index, (name, value) in enumerate(signed.headers):
                for replacement in ((name, value + "x"), (name.upper(), value)):
                    changed = signed.headers[:index] + (replacement,) + signed.headers[index + 1:]
                    self.reject(signing.assert_dispatch, signed, **dispatch_fields(signed, headers=changed))
                self.reject(signing.assert_dispatch, signed,
                            **dispatch_fields(signed, headers=signed.headers[:index] + signed.headers[index + 1:]))
            for extra in (("content-length", "02"), ("content-length", " 2"), ("content-length", "3"),
                    ("content-length", 2), ("content-length", True), ("Content-Length", "2"),
                    ("host", AUTHORITY), ("Host", AUTHORITY), ("x-amz-date", STAMP),
                    ("x-canary", TOKEN), ("transfer-encoding", "chunked")):
                self.reject(signing.assert_dispatch, signed, **dispatch_fields(signed, headers=signed.headers + (extra,)))
            self.reject(signing.assert_dispatch, signed, **dispatch_fields(signed, headers=list(signed.headers)))
            self.reject(signing.assert_dispatch, signed,
                        **dispatch_fields(signed, headers=tuple(list(pair) for pair in signed.headers)))
        empty = self.signed(body=b"")
        signing.assert_dispatch(empty, **dispatch_fields(empty, b"", headers=empty.headers + (("content-length", "0"),)))

    def test_freshness_dual_clocks_second_check_and_unsealed_results(self):
        signed = self.signed()
        for observed in (clock(), clock(59, 59_999_999_999)):
            signing.require_fresh(signed, clock=observed)
            signing.assert_dispatch(signed, **dispatch_fields(signed, clock=observed))
        for observed in (clock(-1, 0), clock(0, -1), clock(60, 0), clock(0, 60_000_000_000)):
            self.reject(signing.require_fresh, signed, clock=observed)
            self.reject(signing.assert_dispatch, signed, **dispatch_fields(signed, clock=observed))
        session = signing.sign(credentials(True, expires_at="2026-10-10T12:00:10Z"),
            region=REGION, action="PutImage", body=b"{}", clock=clock())
        signing.require_fresh(session, clock=clock(4, 4_000_000_000))
        for checker in (lambda: signing.require_fresh(session, clock=clock(5, 5_000_000_000)),
                        lambda: signing.assert_dispatch(session, **dispatch_fields(session, clock=clock(5, 5_000_000_000)))):
            self.reject(checker)
        before = (signed.headers, signed.canonical_request, signed.string_to_sign)
        with patch.object(signing.hashlib, "sha256", side_effect=AssertionError("freshness must not hash")):
            signing.require_fresh(signed, clock=clock(1, 1_000_000_000))
            self.reject(signing.require_fresh, signed, clock=clock(60, 60_000_000_000))
        self.assertEqual((signed.headers, signed.canonical_request, signed.string_to_sign), before)
        unsealed = object.__new__(signing.SignedRequest)
        for value in (None, {}, SimpleNamespace(**dispatch_fields(signed)), unsealed):
            self.reject(signing.require_fresh, value, clock=clock())
            self.reject(signing.assert_dispatch, value, **dispatch_fields(signed))

    def test_fixed_failures_do_not_export_supplied_canaries(self):
        canary = "private-value-not-for-errors"
        failures = [self.reject(self.signed, region=canary), self.reject(self.signed, action=canary),
                    self.reject(credentials, secret_access_key=canary)]
        signed = self.signed(session=True)
        failures.append(self.reject(signing.assert_dispatch, signed,
            **dispatch_fields(signed, headers=signed.headers + (("x-private", canary),))))
        for failure in failures:
            for private in (canary, SECRET, TOKEN, ACCESS, SESSION_ACCESS):
                self.assertNotIn(private, str(failure) + repr(failure))
        self.assertNotIn("catchplate.config", sys.modules)
        self.assertNotIn("catchplate.db", sys.modules)


class AwsEcrBotocoreTests(unittest.TestCase):
    def compare(self, action, body, session=False):
        expected = stock_vector(action, body, session)
        actual = signing.sign(credentials(session), region=REGION, action=action, body=body, clock=clock())
        self.assertEqual(dict(actual.headers), expected["headers"])
        self.assertEqual(actual.canonical_request, expected["canonicalRequest"].encode("ascii"))
        self.assertEqual(actual.string_to_sign, expected["stringToSign"])
        self.assertEqual(actual.body_sha256, expected["bodySha256"])
        self.assertEqual(actual.body_length, len(body))
        return expected["headers"]["authorization"]

    def test_stock_sigv4_all_five_actions_long_term_and_session(self):
        for session in (False, True):
            for action, body in bodies():
                with self.subTest(action=action, session=session):
                    self.compare(action, body, session)

    def test_stock_sigv4_exact_empty_binary_and_whitespace_bodies(self):
        for session in (False, True):
            signatures = {self.compare("UploadLayerPart", body, session)
                          for body in (b"", b"{}", b"{ }", PART)}
            self.assertEqual(len(signatures), 4)


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(AwsEcrSigningTests)
    if RUN_BOTOCORE:
        suite.addTests(loader.loadTestsFromTestCase(AwsEcrBotocoreTests))
    return suite


RUN_BOTOCORE = False
if __name__ == "__main__":
    if "--emit-botocore-vectors" in sys.argv:
        if sys.argv[1:] != ["--emit-botocore-vectors"]:
            raise SystemExit("vector mode accepts no other arguments")
        print(json.dumps({"schema": "catchplate.syntheticEcrBotocoreVectors/v1", "botocoreVersion": "1.34.46",
            "region": REGION, "unixSeconds": NOW, "monotonicNs": MONO,
            "sessionExpiry": EXPIRY, "cases": [stock_vector(action, body, session)
                for session in (False, True) for action, body in (*bodies(), ("UploadLayerPart", PART))]},
            sort_keys=True, indent=2))
    else:
        RUN_BOTOCORE = "--botocore" in sys.argv
        if RUN_BOTOCORE:
            sys.argv.remove("--botocore")
        unittest.main(verbosity=2)

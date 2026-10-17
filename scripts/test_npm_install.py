#!/usr/bin/env python3
"""Closed install reference-path checks; no npm process, network, store or lease.

Uses the existing physical-header fixture and annotation-only mitmproxy import
stub. All compiler, gzip, canonical-request and credential-guard code is real;
parsed HTTP objects are synthetic. This is not Rust/stock-client acceptance.
"""
from copy import deepcopy
from dataclasses import replace
import gzip
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import test_npm_metadata as fixture  # Installs the socket/SQLite refusal hook.
from catchplate import npm_install as npm, npm_metadata, policy_bundle as pb
from catchplate import adapters, policy_engine as engine, policy_route_authority as authority

PACKAGES = ["@fixture/package", "fixture-package"]
AUDIT = b'{"fixture-package":["2.0.0","1.0.0"],"@fixture/package":["1.0.0"]}'
SECRET = "synthetic-private-npm-install-value"


def document(mode):
    value = fixture.document()
    route = value["routes"][0]
    route["match"].update(methods=["POST" if mode == "audit" else "GET"], paths=npm.route_paths(mode))
    route["adapter"] = {"type": npm.ADAPTER, "config": {
        "credentialBinding": deepcopy(route["adapter"]["config"]["credentialBinding"]),
        "packages": list(PACKAGES), "mode": mode,
        "request": npm.request_profile(mode), "response": npm.response_profile(mode)}}
    route["constraints"] = [npm.response_envelope("fixture.install-response", mode)]
    return value


def snapshot(mode, value=None, *, schema=True):
    return pb.compile_policy_bundle(document(mode) if value is None else value, validate_schema=schema)


def request(mode, *, body=None, target=None, headers=()):
    if mode == "audit":
        body = gzip.compress(AUDIT, mtime=0) if body is None else body
        fields = [(b"Content-Type", b"application/json"), (b"Content-Encoding", b"gzip"),
            (b"Content-Length", str(len(body)).encode())]
        target = npm.AUDIT_PATH if target is None else target
        params = {}
    else:
        body = b"" if body is None else body
        fields = []
        target = ("/fixture-package" if mode == "metadata" else
            "/fixture-package/-/fixture-package-1.0.0.tgz") if target is None else target
        pieces = target[1:].split("/")
        params = ({"package": target[1:]} if mode == "metadata" else
            {"package": pieces[0], "filename": pieces[2]} if len(pieces) == 3 else
            {"scope": pieces[0], "package": pieces[1], "filename": pieces[3]})
    flow = fixture.request(npm.ORIGIN + target, method="POST" if mode == "audit" else "GET",
        body=body, headers=fields + list(headers))
    return flow, params


def response(mode, body, *, status=200, media=None, fields=(), guarded=True):
    route = snapshot(mode).routes[0]
    flow, params = request(mode)
    media = ("application/octet-stream" if mode == "tarball" and status == 200 else "application/json") if media is None else media
    flow.response = SimpleNamespace(status_code=status, raw_content=body, content=body, trailers=None,
        headers=fixture.ParsedHeaders([(b"Content-Type", media.encode())] + list(fields)))
    flow.metadata.update(catchplate_route=route,
        catchplate_operation=adapters.get_adapter(npm.ADAPTER).operation_fields(flow, route, params))
    if guarded:
        guard = engine._ResponseCredentialGuard()
        guard.add_text_encodings(SECRET)
        engine._install_response_credential_guard(flow, guard)
    return flow, route, params


def admit_response(flow, route, params):
    adapter = adapters.get_adapter(npm.ADAPTER)
    for check in (lambda: engine._validate_response_content_encoding(flow),
            lambda: engine._evaluate_response_envelope(flow, route),
            lambda: adapter.prepare_response(flow, route, params),
            lambda: adapter.validate_response(flow, route, params)):
        result = check()
        if not result.allowed:
            return result
    return result


class NpmInstallTests(unittest.TestCase):
    def test_closed_schemas_profiles_and_v1_v2_typed_read_classification(self):
        schema = json.loads((ROOT / "schemas/adapters/npm.install.v1.schema.json").read_text())
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), {"credentialBinding", "packages", "mode", "request", "response"})
        self.assertIn("packageName", schema["$defs"])
        for mode, operation, maximum in (("metadata", "npm.install.metadata.read", 0),
                ("tarball", "npm.install.tarball.read", 0), ("audit", "npm.install.audit.read", 65536)):
            value = document(mode)
            before = deepcopy(value)
            for schema_enabled in (True, False):
                route = snapshot(mode, value, schema=schema_enabled).routes[0]
                npm.validate_route(route)
                self.assertEqual(route.adapter_config["request"]["maxBodyBytes"], maximum)
                self.assertEqual(pb.provider_request_profile(npm.ADAPTER, mode), npm.request_profile(mode))
                self.assertEqual(authority._declared(value["routes"][0]), (npm.ADAPTER, [operation]))
                self.assertEqual(authority._builtin(npm.ADAPTER, operation), "read")
                v2 = deepcopy(value)
                v2["apiVersion"] = "catchplate.policy/v2"
                snapshot(mode, authority.prepare_unsigned(v2, []), schema=schema_enabled)
            self.assertEqual(value, before)
        self.assertIsNone(authority._builtin("generic.rest", "npm.install.audit.read"))
        self.assertIsNone(authority._builtin(npm.ADAPTER, "npm.install.write"))

    def test_signed_closure_transport_and_profiles_cannot_be_widened(self):
        mutations = [lambda r: r["match"].update(host="elsewhere.invalid"),
            lambda r: r["match"].update(scheme="http"), lambda r: r["match"].update(port=443.0),
            lambda r: r["match"].update(methods=["PUT"]), lambda r: r["match"].update(paths=["/**"]),
            lambda r: r.update(jit={}), lambda r: r.update(responseObservation={}),
            lambda r: r["credentialHeader"].update(expectedValue="Bearer another"),
            lambda r: r["adapter"]["config"].update(packages=PACKAGES[::-1]),
            lambda r: r["adapter"]["config"].update(packages=["fixture-package", "fixture-package"]),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(subjects=["wrong"]),
            lambda r: r["adapter"]["config"]["request"].update(maxBodyBytes=True),
            lambda r: r["adapter"]["config"]["request"].update(allowedQueryKeys=["any"]),
            lambda r: r["adapter"]["config"]["request"].update(allowedHeaders=["content-encoding"]),
            lambda r: r["adapter"]["config"]["response"].update(maxBodyBytes=16777216),
            lambda r: r["constraints"][0].update(contentTypePolicy="npmJsonUtf8V1")]
        for mode in npm.MODES:
            for schema_enabled in (True, False):
                for index, mutate in enumerate(mutations):
                    value = document(mode)
                    mutate(value["routes"][0])
                    with self.subTest(mode=mode, schema=schema_enabled, mutation=index), self.assertRaises(pb.PolicyBundleError):
                        snapshot(mode, value, schema=schema_enabled)
        route = document("audit")["routes"][0]
        route["match"]["methods"] = ["PUT"]
        with self.assertRaises(pb.PolicyBundleError):
            authority._declared(route)

    def test_exact_metadata_and_tarball_targets_and_captures(self):
        adapter = adapters.get_adapter(npm.ADAPTER)
        for mode, target, package in (("metadata", "/@fixture%2fpackage", "@fixture/package"),
                ("metadata", "/fixture-package", "fixture-package"),
                ("tarball", "/@fixture/package/-/package-1.0.0.tgz", "@fixture/package"),
                ("tarball", "/fixture-package/-/fixture-package-1.0.0.tgz", "fixture-package")):
            flow, params = request(mode, target=target)
            route = snapshot(mode).routes[0]
            self.assertTrue(adapter.validate_request(flow, route, params).allowed)
            self.assertEqual(adapter.operation_fields(flow, route, params)["package"], package)
            self.assertFalse(adapter.validate_request(flow, route, {}).allowed)
        for target in ("/@fixture%2fpackage/-/package-1.0.0.tgz", "/fixture-package/-/wrong-1.0.0.tgz",
                "/fixture-package/-/fixture-package-v1.0.0.tgz", "/fixture-package/-/fixture-package-01.0.0.tgz",
                "/other/-/other-1.0.0.tgz", "/fixture-package/-/fixture-package-1.0.0.tgz?",
                "/fixture-package/-/fixture-package-1.0.0.tgz#", "/-/whoami"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                npm.validate_request("GET", npm.ORIGIN + target, b"", packages=PACKAGES, mode="tarball", headers={})
        for origin in ("https://REGISTRY.NPMJS.ORG", npm.ORIGIN + ":443", "http://registry.npmjs.org", "https://user@registry.npmjs.org"):
            with self.assertRaises(ValueError):
                npm.target_parts(origin + "/fixture-package", "metadata")

    def test_audit_normalizes_semantics_not_wire_bytes(self):
        flow, params = request("audit")
        before = flow.request.raw_content
        route = snapshot("audit").routes[0]
        adapter = adapters.get_adapter(npm.ADAPTER)
        self.assertTrue(adapter.validate_request(flow, route, params).allowed)
        self.assertEqual(adapter.operation_fields(flow, route, params), {
            "operation": "npm.install.audit.read", "packages": PACKAGES,
            "packageVersions": {"@fixture/package": ["1.0.0"], "fixture-package": ["1.0.0", "2.0.0"]}})
        self.assertTrue(adapter.rewrite_request(flow, route, params).allowed)
        self.assertEqual(flow.request.raw_content, before)

    def test_bounded_single_gzip_member_including_crc_size_and_suffix(self):
        good = gzip.compress(b"opaque decoded bytes", mtime=0)
        self.assertEqual(npm.bounded_gzip(good, len(good), 20), b"opaque decoded bytes")
        corrupt = bytearray(good)
        corrupt[-8] ^= 1
        for raw, compressed, decoded in ((good + b"x", 1000, 100), (good + good, 1000, 100),
                (good[:-1], 1000, 100), (bytes(corrupt), 1000, 100), (b"not-gzip", 1000, 100),
                (good, len(good) - 1, 100), (good, 1000, 19), (gzip.compress(b""), 1000, 100)):
            with self.subTest(size=len(raw), compressed=compressed, decoded=decoded), self.assertRaises(ValueError):
                npm.bounded_gzip(raw, compressed, decoded)

    def test_audit_strict_json_closed_packages_versions_and_decoded_bound(self):
        invalid = [b"{}", b"[]", b'"text"', b'{"fixture-package":[]}', b'{"other":["1.0.0"]}',
            b'{"fixture-package":["1.0.0","1.0.0"]}', b'{"fixture-package":["v1.0.0"]}',
            b'{"fixture-package":[NaN]}', b'{"fixture-package":[1e999]}', b'{"fixture-package":[true]}',
            b'{"fixture-package":["1.0.0"],"fixture-package":["1.0.0"]}',
            b'{"fixture-package":' + b'[' * 65 + b'0' + b']' * 65 + b'}',
            b'{"fixture-package":["1.0.0"]}' + b" " * 262144,
            json.dumps({"fixture-package": [f"1.0.{i}" for i in range(129)]}).encode()]
        route = snapshot("audit").routes[0]
        for index, body in enumerate(invalid):
            flow, params = request("audit", body=gzip.compress(body, mtime=0))
            with self.subTest(index=index):
                self.assertFalse(adapters.get_adapter(npm.ADAPTER).validate_request(flow, route, params).allowed)

    def test_audit_fixed_physical_framing_and_no_generic_encoding_exception(self):
        route = snapshot("audit").routes[0]
        adapter = adapters.get_adapter(npm.ADAPTER)
        for mutate in (lambda h: h.__delitem__("content-length"),
                lambda h: h.__setitem__("content-length", "01"),
                lambda h: h.__setitem__("content-length", "0"),
                lambda h: h.__setitem__("content-encoding", "identity"),
                lambda h: h.__setitem__("content-encoding", "GZIP"),
                lambda h: h.__setitem__("transfer-encoding", "chunked"),
                lambda h: h.__setitem__("content-type", "application/json; charset=latin-1")):
            flow, params = request("audit")
            mutate(flow.request.headers)
            self.assertFalse(adapter.validate_request(flow, route, params).allowed)
            self.assertFalse(adapters.preflight_request_admission(flow, route,
                engine._normalized_request_headers(flow)).allowed)
        for name, value in ((b"content-encoding", b"gzip"), (b"content-type", b"application/json"),
                (b"content-length", b"10")):
            flow, params = request("audit", headers=[(name, value)])
            self.assertFalse(adapter.validate_request(flow, route, params).allowed)
            with self.assertRaises(ValueError):
                engine._normalized_request_headers(flow)
        flow, _ = request("audit")
        legacy = replace(route, adapter_type="generic.rest")
        self.assertFalse(adapters.preflight_request_admission(flow, legacy,
            engine._normalized_request_headers(flow)).allowed)
        for mode in ("metadata", "tarball"):
            with self.assertRaises(ValueError):
                npm.validate_request("GET", npm.ORIGIN + ("/fixture-package" if mode == "metadata"
                    else "/fixture-package/-/fixture-package-1.0.0.tgz"), b"", packages=PACKAGES,
                    mode=mode, headers={"transfer-encoding": "chunked"})

    def test_actual_canonical_and_final_request_joins_keep_compressed_bytes(self):
        snap = snapshot("audit")
        route = snap.routes[0]
        flow, params = request("audit", headers=[(b"Accept-Encoding", b"gzip"),
            (b"Npm-Session", b"discard-me"), (b"X-Catchplate-Agent", b"fixture")])
        def no_implicit_decode(*args, **kwargs):
            raise AssertionError("generic decoder must not handle typed gzip")
        flow.request.get_content = no_implicit_decode
        before = flow.request.raw_content
        principal = snap.principals["agent:fixture"]
        credential = snap.credentials[route.credential_ref]
        self.assertTrue(adapters.preflight_request_admission(flow, route,
            engine._normalized_request_headers(flow)).allowed)
        discarded = engine._discard_declared_request_headers(flow, route, principal, credential)
        engine._strip_identity_headers(flow, principal)
        engine._strip_identity_content_encoding(flow, "gzip", route)
        headers = engine._canonical_forwarded_request_headers(flow, credential, route=route)
        self.assertEqual(headers["content-encoding"], "gzip")
        self.assertEqual(headers["content-length"], str(len(before)))
        self.assertNotIn("npm-session", headers)
        self.assertNotIn("accept-encoding", headers)
        canonical = engine._canonical_request(flow, principal=principal, route=route,
            credential_version="1", policy_hash=snap.hash,
            operation_fields=adapters.get_adapter(npm.ADAPTER).operation_fields(flow, route, params),
            forwarded_headers=headers, discard_headers=discarded)
        self.assertEqual(canonical["request"]["body_sha256"], "sha256:" + hashlib.sha256(before).hexdigest())
        self.assertTrue(engine._provider_request_matches_canonical(flow, canonical, credential, route=route))
        flow.request.raw_content = gzip.compress(AUDIT, mtime=1)
        self.assertFalse(engine._provider_request_matches_canonical(flow, canonical, credential, route=route))
        flow.request.raw_content = before
        flow.request.headers["Content-Encoding"] = "identity"
        self.assertFalse(engine._provider_request_matches_canonical(flow, canonical, credential, route=route))

    def test_response_modes_preserve_whole_bytes_and_discard_only_after_inspection(self):
        cases = [("metadata", b'{"name":"fixture-package","dist":{"tarball":"https://elsewhere.invalid/inert"}}'),
            ("tarball", gzip.compress(b"not an extracted archive; opaque bytes", mtime=0)),
            ("audit", b'{"fixture-package":[{"severity":"high","extra":{"x":1}}]}')]
        for mode, raw in cases:
            flow, route, params = response(mode, raw, fields=[(b"X-Cache", b"discarded")])
            result = admit_response(flow, route, params)
            self.assertTrue(result.allowed, result.payload)
            self.assertEqual(flow.response.raw_content, raw)
            self.assertEqual(set(flow.response.headers), {"content-type", "content-length"})
            self.assertEqual(flow.response.headers["Content-Length"], str(len(raw)))
        self.assertTrue(admit_response(*response("audit", b"{}")).allowed)
        for raw in (b'{"other":[]}', b'{"fixture-package":{}}', b'{"fixture-package":[1]}', b"[]"):
            self.assertFalse(admit_response(*response("audit", raw)).allowed)
        self.assertFalse(admit_response(*response("metadata", b'{"name":"other"}')).allowed)

    def test_response_raw_decoded_json_and_discarded_header_secret_guards(self):
        compressed = gzip.compress(SECRET.encode(), mtime=0)
        self.assertNotIn(SECRET.encode(), compressed)
        plain = gzip.compress(b"safe payload", mtime=0)
        named = plain[:3] + b"\x08" + plain[4:10] + SECRET.encode() + b"\x00" + plain[10:]
        for raw in (compressed, named):
            self.assertFalse(admit_response(*response("tarball", raw)).allowed)
        encoded = "".join("\\u%04x" % ord(char) for char in SECRET)
        raw = ('{"fixture-package":[{"text":"' + encoded + '"}]}').encode()
        self.assertFalse(admit_response(*response("audit", raw)).allowed)
        for mode, raw in (("metadata", b'{"name":"fixture-package"}'), ("tarball", plain), ("audit", b"{}")):
            self.assertFalse(admit_response(*response(mode, raw, fields=[(b"X-Cache", SECRET.encode())])).allowed)
            self.assertFalse(admit_response(*response(mode, raw, guarded=False)).allowed)

    def test_response_errors_media_encoding_and_original_profile_bounds(self):
        for mode in npm.MODES:
            for status in npm.STATUSES[1:]:
                raw = b'{"error":{"message":"synthetic"}}'
                self.assertTrue(admit_response(*response(mode, raw, status=status)).allowed)
            for status in (201, 204, 206, 301, 418, 501):
                self.assertFalse(admit_response(*response(mode, b"{}", status=status)).allowed)
            body = b'{"error":"' + b"x" * (65536 - 12) + b'"}'
            self.assertEqual(len(body), 65536)
            self.assertTrue(admit_response(*response(mode, body, status=404)).allowed)
            self.assertFalse(admit_response(*response(mode, body + b" ", status=404)).allowed)
        for mode, raw in (("audit", b"{}"), ("tarball", gzip.compress(b"safe", mtime=0))):
            for media in ("text/html", "application/json; charset=latin-1", "application/octet-stream; charset=utf-8"):
                self.assertFalse(admit_response(*response(mode, raw, media=media)).allowed)
            for fields in ([(b"Content-Encoding", b"gzip")], [(b"Content-Type", b"application/json")]):
                self.assertFalse(admit_response(*response(mode, raw, fields=fields)).allowed)
        self.assertEqual(npm.response_profile("tarball")["maxBodyBytes"], 8388608)
        self.assertEqual(npm.MAX_TARBALL_DECODED_BYTES, 33554432)
        for raw in (gzip.compress(b"safe") + b"tail", gzip.compress(b"safe")[:-1]):
            self.assertFalse(admit_response(*response("tarball", raw)).allowed)

    def test_legacy_metadata_publish_and_generic_modes_cannot_borrow_install_contract(self):
        old = fixture.compile_route()
        npm_metadata.validate_route(old)
        self.assertEqual(old.adapter_type, "npm.metadata.v1")
        self.assertIsInstance(adapters.get_adapter("npm.registry"), adapters.NpmRegistryAdapter)
        for mode in npm.MODES:
            for adapter in ("generic.rest", "npm.registry", "npm.metadata.v1", "npm.publish.v1"):
                with self.subTest(mode=mode, adapter=adapter), self.assertRaises(pb.PolicyBundleError):
                    pb.validate_buffered_passthrough_response("fixture", adapter, npm.response_profile(mode))
        flow, _ = request("metadata", target="/@fixture%2fpackage")
        route = snapshot("metadata").routes[0]
        self.assertTrue(engine._npm_install_scoped_target(flow, route))
        self.assertFalse(engine._npm_install_scoped_target(flow, replace(route, adapter_type="generic.rest")))


if __name__ == "__main__":
    unittest.main(verbosity=2)

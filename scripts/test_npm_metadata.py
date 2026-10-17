#!/usr/bin/env python3
"""Bounded synthetic npm metadata compiler/adapter checks; no provider or store.

--pure needs only compiler dependencies. The default suite adds deliberately
synthetic parsed-field objects and the actual adapter/engine guard functions.
It does not run mitmproxy, an HTTP parser, a forwarding transport, npm install,
a real npm token, or production SDK acceptance. When mitmproxy is absent, its
annotation-only import is stubbed; no HTTP methods or production checks are
replaced. Hidden-wire framing remains a Rust transport obligation.
"""
from copy import deepcopy
from collections.abc import MutableMapping
from dataclasses import replace
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PURE = "--pure" in sys.argv
if PURE:
    sys.argv.remove("--pure")


def no_external_state(event, args):
    if event in {"sqlite3.connect", "socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise RuntimeError("npm metadata fixture attempted external state")


sys.addaudithook(no_external_state)
from catchplate import npm_metadata as npm, policy_bundle as pb, policy_route_authority as authority

PACKAGES = ["@fixture/package", "fixture-package"]
URL = npm.ORIGIN + "/fixture-package"
SECRET = "synthetic-private-npm-value"


def document():
    return {"apiVersion": "catchplate.policy/v1", "kind": "PolicyBundle",
        "metadata": {"id": "npm-metadata-test", "sequence": 1, "rollbackEpoch": 1},
        "defaults": {"action": "deny", "failMode": "closed", "unknownHosts": "block",
            "unknownPaths": "block", "validationFailure": "block"},
        "principals": [{"id": "agent:fixture", "sourceCidrs": ["127.0.0.1/32"],
            "requiredHeaders": {"X-Catchplate-Agent": "fixture"}}],
        "credentials": [{"id": "credential:fixture", "credentialType": "static",
            "provider": "operator-demo", "providerSubject": "fixture-subject",
            "injection": {"type": "bearer", "header": "Authorization"}}],
        "routes": [{"id": "route.npm-fixture", "principals": ["agent:fixture"],
            "credentialRef": "credential:fixture", "credentialHeader": dict(npm.REPLACEMENT),
            "match": {"scheme": "https", "host": npm.HOST, "port": 443,
                "methods": ["GET"], "paths": list(npm.PATHS)},
            "adapter": {"type": npm.ADAPTER, "config": {
                "credentialBinding": {"credentialType": "static", "provider": "operator-demo",
                    "subjects": ["fixture-subject"], "secretClass": "bearerToken"},
                "packages": list(PACKAGES), "request": npm.request_profile(),
                "response": npm.response_profile()}},
            "constraints": [npm.response_envelope("fixture.npm-response")]}]}


def compile_route(value=None, *, schema=True):
    return pb.compile_policy_bundle(document() if value is None else value,
        validate_schema=schema).routes[0]


class NpmMetadataPureTests(unittest.TestCase):
    def test_embedded_schema_has_real_local_definitions_and_closed_root(self):
        # The gate embeds every adapter schema before admitting any policy.
        # Guard the required registry shape here; actual gate initialization
        # remains covered by its Rust validate_policy_schema regression.
        for adapter in sorted(pb.SUPPORTED_ADAPTERS):
            schema = json.loads((ROOT / "schemas/adapters" / f"{adapter}.schema.json").read_text())
            with self.subTest(adapter=adapter):
                self.assertIsInstance(schema.get("$defs"), dict)
        schema = json.loads((ROOT / "schemas/adapters/npm.metadata.v1.schema.json").read_text())
        self.assertEqual(schema["type"], "object")
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), {"credentialBinding", "packages", "request", "response"})
        self.assertEqual(set(schema["properties"]), set(schema["required"]))
        self.assertEqual(schema["properties"]["packages"]["items"], {"$ref": "#/$defs/packageName"})
        self.assertEqual(schema["$defs"], {"packageName": {"type": "string", "minLength": 1,
            "maxLength": 214, "pattern": "^" + npm.PACKAGE_PATTERN + "$"}})
        self.assertEqual(schema["properties"]["request"]["const"], npm.request_profile())
        self.assertEqual(schema["properties"]["response"]["const"], npm.response_profile())
        pending = [schema]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                if "$ref" in value:
                    reference = value["$ref"]
                    self.assertTrue(reference.startswith("#/$defs/"))
                    self.assertIn(reference.removeprefix("#/$defs/"), schema["$defs"])
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)

    def test_exact_schema_compiler_v1_v2_and_hash_binding(self):
        value = document()
        before = deepcopy(value)
        for schema in (True, False):
            route = compile_route(value, schema=schema)
            npm.validate_route(route)
            self.assertEqual(route.adapter_type, npm.ADAPTER)
            self.assertEqual(pb.provider_request_profile(npm.ADAPTER), npm.request_profile())
            self.assertEqual(pb.adapter_operation_field_names(npm.ADAPTER, npm.OPERATION),
                frozenset({"operation", "package"}))
            self.assertIsNone(pb.adapter_operation_field_names(npm.ADAPTER, "npm.read"))
            self.assertIsNone(pb.request_query_mode(npm.ADAPTER, route.adapter_config))
            upgraded = deepcopy(value)
            upgraded["apiVersion"] = "catchplate.policy/v2"
            upgraded = authority.prepare_unsigned(upgraded, [])
            compile_route(upgraded, schema=schema)
            self.assertEqual(authority._builtin(npm.ADAPTER, npm.OPERATION), "read")
        different = deepcopy(value)
        different["routes"][0]["adapter"]["config"]["packages"] = ["other-package"]
        self.assertNotEqual(pb.compile_policy_bundle(value).hash, pb.compile_policy_bundle(different).hash)
        self.assertEqual(value, before)

    def test_package_names_are_canonical_sorted_unique_and_bounded(self):
        self.assertEqual(npm.validate_packages(PACKAGES), PACKAGES)
        npm.validate_packages(["a" * 214])
        for names in ([], PACKAGES[::-1], ["a", "a"], ["*"], ["Upper"], [".hidden"],
                ["_hidden"], ["a~b"], ["@scope/Upper"], ["@scope/a/b"], ["@scope%2fa"],
                ["a@b"], ["a/b"], ["-"], ["a" * 215], ["a\n"], ["é"], [1],
                [f"package-{i:02}" for i in range(65)]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                npm.validate_packages(names)

    def test_signed_authority_refuses_transport_binding_and_profile_changes(self):
        mutations = [
            lambda r: r["match"].update(host="elsewhere.invalid"),
            lambda r: r["match"].update(host="REGISTRY.NPMJS.ORG"),
            lambda r: r["match"].update(scheme="http"),
            lambda r: r["match"].update(port=444),
            lambda r: r["match"].update(port=443.0),
            lambda r: r["match"].update(methods=["HEAD"]),
            lambda r: r["match"].update(methods=["get"]),
            lambda r: r["match"].update(methods=["GET", "GET"]),
            lambda r: r["match"].update(paths=["/**"]),
            lambda r: r.update(jit={}),
            lambda r: r.update(responseObservation={}),
            lambda r: r.pop("credentialHeader"),
            lambda r: r["credentialHeader"].update(expectedValue="Bearer other-placeholder"),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(provider="npm"),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(subjects=["other-subject"]),
            lambda r: r["adapter"]["config"]["request"].update(maxBodyBytes=False),
            lambda r: r["adapter"]["config"]["request"].update(maxBodyBytes=0.0),
            lambda r: r["adapter"]["config"]["request"].update(allowedQueryKeys=["version"]),
            lambda r: r["adapter"]["config"]["request"].update(allowedMediaTypes=["application/json"]),
            lambda r: r["adapter"]["config"]["request"].update(bodyMode="none"),
            lambda r: r["adapter"]["config"]["response"].update(maxBodyBytes=1048576.0),
            lambda r: r["adapter"]["config"]["response"].update(allowedFields=["name"]),
            lambda r: r["constraints"][0].update(statusCodes=[200.0] + npm.STATUSES[1:]),
            lambda r: r["constraints"][0].update(contentTypePolicy="githubJsonUtf8V1"),
        ]
        for schema in (True, False):
            for index, mutation in enumerate(mutations):
                value = document()
                mutation(value["routes"][0])
                with self.subTest(schema=schema, index=index), self.assertRaises(pb.PolicyBundleError):
                    compile_route(value, schema=schema)

    def test_closed_binding_subject_and_response_exactness_without_schema(self):
        config = document()["routes"][0]["adapter"]["config"]
        for subject in (" ", " padded", "padded ", "bad\x00subject", "bad\x85subject", "é" * 257):
            value = deepcopy(config)
            value["credentialBinding"]["subjects"] = [subject]
            with self.subTest(subject=repr(subject)), self.assertRaises(ValueError):
                npm.validate_config(value)
        for field in ("allowedHeaders", "discardHeaders"):
            value = deepcopy(config)
            value["request"][field].reverse()
            with self.assertRaises(ValueError):
                npm.validate_config(value)
        for mutation in (
                lambda r: r.update(mode="json"),
                lambda r: r.update(contentTypes=["application/json"]),
                lambda r: r["error"].update(maxBodyBytes=65537),
                lambda r: r["error"].update(allowedHeaders=["retry-after"]),
                lambda r: r.update(bodyFormat="json")):
            value = deepcopy(config)
            mutation(value["response"])
            with self.assertRaises(ValueError):
                npm.validate_config(value)

    def test_canonical_request_paths_no_query_body_or_other_operations(self):
        for url, expected in ((URL, "fixture-package"),
                (npm.ORIGIN + "/@fixture%2fpackage", "@fixture/package")):
            self.assertEqual(npm.validate_request("GET", url, b"", packages=PACKAGES), expected)
            pb.validated_request_urlsplit_for_route(url, compile_route())
            pb.validate_request_target_path(url)
        targets = ["/other-package", "/fixture-package?", "/fixture-package?version=1", "/fixture-package#",
            "/@fixture/package", "/@fixture%2Fpackage", "/@fixture%252fpackage", "/%66ixture-package",
            "/fixture-package/-/fixture-package.tgz", "/-/npm/v1/security/audits/quick", "/-/whoami",
            "/fixture-package/1.0.0", "/@fixture%2fpackage/", "/fixture-package/..", "//fixture-package"]
        for target in targets:
            with self.subTest(target=target), self.assertRaises(ValueError):
                npm.validate_request("GET", npm.ORIGIN + target, b"", packages=PACKAGES)
        with self.assertRaises(ValueError):
            npm.validate_request("GET", npm.ORIGIN + ":443/fixture-package", b"", packages=PACKAGES)
        for method, body in (("HEAD", b""), ("POST", b""), ("GET", b"{}"), ("GET", None)):
            with self.assertRaises(ValueError):
                npm.validate_request(method, URL, body, packages=PACKAGES)

    def test_media_type_profile_is_exact_and_does_not_widen_generic_json(self):
        for media in npm.CONTENT_TYPES:
            for suffix in ("", ";charset=utf-8", "; charset=UTF-8", ";\tcharset=utf-8"):
                self.assertTrue(npm.is_json_content_type(media.upper() + suffix))
        for value in ("application/problem+json", "application/json; charset=latin-1",
                "application/json; charset=\"utf-8\"", "application/json ", " application/json",
                "application/json;charset=utf-8;charset=utf-8", "application/json;foo=bar",
                "application/vnd.npm.install-v2+json", "application/json\n", None):
            self.assertFalse(npm.is_json_content_type(value))

    def test_legacy_policy_is_unchanged_and_mode_cannot_be_borrowed(self):
        legacy = json.loads((ROOT / "policies/credential-limits.examples.json").read_text())
        before = pb.compile_policy_bundle(legacy).hash
        compile_route()
        self.assertEqual(pb.compile_policy_bundle(legacy).hash, before)
        self.assertEqual(pb.provider_request_profile("npm.registry")["discardHeaders"], ["npm-session"])
        for adapter in ("generic.rest", "npm.registry", "gmail.read.v1"):
            with self.assertRaises(pb.PolicyBundleError):
                pb.validate_buffered_passthrough_response("fixture", adapter, npm.response_profile())


if not PURE:
    try:
        import mitmproxy  # noqa: F401
    except ModuleNotFoundError as error:
        if error.name != "mitmproxy":
            raise
        annotation_module = ModuleType("mitmproxy")
        annotation_http = ModuleType("mitmproxy.http")
        annotation_http.HTTPFlow = object
        annotation_module.http = annotation_http
        sys.modules["mitmproxy"] = annotation_module
        sys.modules["mitmproxy.http"] = annotation_http
    from catchplate import adapters, policy_engine as engine

    class ParsedHeaders(MutableMapping):
        """Fixture storage preserving every supplied physical pair, not a parser."""
        def __init__(self, fields=()):
            self.fields = tuple(fields)

        def get_all(self, name):
            return [value.decode("latin-1") for key, value in self.fields if key.lower() == name.lower().encode("ascii")]

        def __getitem__(self, name):
            values = self.get_all(name)
            if not values:
                raise KeyError(name)
            return ", ".join(values)

        def __setitem__(self, name, value):
            self.fields = tuple((key, item) for key, item in self.fields if key.lower() != name.lower().encode("ascii"))
            self.fields += ((name.encode("ascii"), value.encode("latin-1")),)

        def __delitem__(self, name):
            if not self.get_all(name):
                raise KeyError(name)
            self.fields = tuple((key, item) for key, item in self.fields if key.lower() != name.lower().encode("ascii"))

        def __iter__(self):
            return iter(dict.fromkeys(key.decode("ascii").lower() for key, _ in self.fields))

        def __len__(self):
            return len(set(key.lower() for key, _ in self.fields))

        def clear(self):
            self.fields = ()

    def request(url=URL, *, method="GET", body=b"", headers=()):
        value = SimpleNamespace(method=method, pretty_url=url, headers=ParsedHeaders(headers),
            raw_content=body, get_content=lambda strict=True: body, trailers=None)
        return SimpleNamespace(request=value, response=None, metadata={},
            client_conn=SimpleNamespace(peername=("127.0.0.1", 12345)))

    class NpmMetadataAdapterTests(unittest.TestCase):
        def setUp(self):
            self.snapshot = pb.compile_policy_bundle(document())
            self.route = self.snapshot.routes[0]
            self.adapter = adapters.get_adapter(npm.ADAPTER)
            self.params = {"package": "fixture-package"}

        def response(self, body=b'{"name":"fixture-package","versions":{"1.0.0":{"dist":{"tarball":"https://elsewhere.invalid/file.tgz"}}}}',
                *, status=200, media=b"application/json", fields=(), guarded=True):
            flow = request()
            flow.response = SimpleNamespace(status_code=status, raw_content=body, content=body, trailers=None,
                headers=ParsedHeaders(([(b"Content-Type", media)] if media is not None else []) + list(fields)))
            flow.metadata.update(catchplate_route=self.route,
                catchplate_operation=self.adapter.operation_fields(flow, self.route, self.params))
            if guarded:
                guard = engine._ResponseCredentialGuard()
                guard.add_text_encodings(SECRET)
                engine._install_response_credential_guard(flow, guard)
            return flow

        def admit(self, flow):
            for check in (lambda: engine._validate_response_content_encoding(flow),
                    lambda: engine._evaluate_response_envelope(flow, self.route),
                    lambda: self.adapter.prepare_response(flow, self.route, self.params),
                    lambda: self.adapter.validate_response(flow, self.route, self.params)):
                result = check()
                if not result.allowed:
                    return result
            return result

        def test_request_adapter_canonical_and_scoped_guard(self):
            for package, wire in (("fixture-package", "fixture-package"), ("@fixture/package", "@fixture%2fpackage")):
                flow = request(npm.ORIGIN + "/" + wire)
                params = {"package": wire}
                self.assertTrue(self.adapter.validate_request(flow, self.route, params).allowed)
                self.assertEqual(self.adapter.operation_fields(flow, self.route, params),
                    {"operation": npm.OPERATION, "package": package})
                self.assertEqual(engine._npm_metadata_scoped_target(flow, self.route), package.startswith("@"))
                self.assertFalse(engine._npm_metadata_scoped_target(flow, replace(self.route, adapter_type="generic.rest")))
            self.assertFalse(self.adapter.validate_request(request(), self.route, {}).allowed)
            self.assertFalse(self.adapter.validate_request(request(headers=[(b"Npm-Command", b"view"),
                (b"npm-command", b"view")]), self.route, self.params).allowed)
            self.assertFalse(self.adapter.validate_request(request(headers=[(b"Content-Type", b"application/json")]),
                self.route, self.params).allowed)

        def test_actual_header_discard_and_canonical_operation(self):
            flow = request(headers=[(b"Accept", b"application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"),
                (b"Accept-Encoding", b"gzip,deflate"), (b"Npm-Session", b"synthetic-session"),
                (b"Pacote-Version", b"21.0.4"), (b"Pacote-Req-Type", b"packument"),
                (b"Pacote-Pkg-Id", b"registry:fixture-package"), (b"X-Catchplate-Agent", b"fixture")])
            principal = self.snapshot.principals["agent:fixture"]
            credential = self.snapshot.credentials[self.route.credential_ref]
            self.assertTrue(adapters.preflight_request_admission(flow, self.route,
                engine._normalized_request_headers(flow)).allowed)
            discarded = engine._discard_declared_request_headers(flow, self.route, principal, credential)
            engine._strip_identity_headers(flow, principal)
            self.assertNotIn("accept-encoding", flow.request.headers)
            self.assertNotIn("npm-session", flow.request.headers)
            self.assertTrue(self.adapter.validate_request(flow, self.route, self.params).allowed)
            canonical = engine._canonical_request(flow, principal=principal, route=self.route,
                credential_version="1", policy_hash=self.snapshot.hash,
                operation_fields=self.adapter.operation_fields(flow, self.route, self.params),
                forwarded_headers=engine._canonical_forwarded_request_headers(flow, credential, route=self.route),
                discard_headers=discarded)
            self.assertIn(npm.OPERATION, json.dumps(canonical))
            self.assertNotIn("synthetic-session", json.dumps(canonical))

        def test_full_and_corgi_bytes_identity_and_unlisted_header_discard(self):
            for media in npm.CONTENT_TYPES:
                flow = self.response(media=(media.upper() + "; charset=UTF-8").encode(),
                    fields=[(b"X-Cache", b"one"), (b"x-cache", b"two"), (b"ETag", b"metadata-etag")])
                original = flow.response.raw_content
                self.assertTrue(self.admit(flow).allowed)
                self.assertEqual(flow.response.raw_content, original)
                self.assertEqual(flow.response.headers["Content-Type"], media)
                self.assertEqual(set(flow.response.headers), {"content-type", "content-length"})
            for body in (b'{"name":"other"}', b'{"_id":"fixture-package"}', b'[]', b'null'):
                self.assertFalse(self.admit(self.response(body)).allowed)

        def test_response_status_errors_and_exact_size_bounds(self):
            for status in npm.STATUSES[1:]:
                flow = self.response(b'{"arbitrary":{"error":"fixture"}}', status=status)
                original = flow.response.raw_content
                self.assertTrue(self.admit(flow).allowed)
                self.assertEqual(flow.response.raw_content, original)
            for status in (201, 204, 206, 301, 418, 501):
                self.assertFalse(self.admit(self.response(status=status)).allowed)
            for status, maximum in ((200, 1048576), (404, 65536)):
                prefix = b'{"name":"fixture-package","padding":"'
                body = prefix + b"x" * (maximum - len(prefix) - 2) + b'"}'
                self.assertTrue(self.admit(self.response(body, status=status)).allowed)
                self.assertFalse(self.admit(self.response(body + b" ", status=status)).allowed)

        def test_strict_json_rejects_duplicates_numbers_unicode_and_depth(self):
            for body in (b'{"name":"fixture-package","name":"fixture-package"}',
                    b'{"name":"fixture-package","n":NaN}', b'{"name":"fixture-package","n":1e999}',
                    b'{"name":"fixture-package","x":"\\ud800"}', b'\xef\xbb\xbf{}',
                    b'{"name":"fixture-package"} trailing', b'{"x":' + b'[' * 128 + b'0' + b']' * 128 + b'}'):
                with self.subTest(body=body[:50]):
                    self.assertFalse(self.admit(self.response(body)).allowed)

        def test_raw_decoded_and_discarded_header_reflection_denied_before_release(self):
            for body in (json.dumps({"name": "fixture-package", "x": SECRET}).encode(),
                    ('{"name":"fixture-package","x":"' + ''.join('\\u%04x' % ord(c) for c in SECRET) + '"}').encode()):
                self.assertFalse(self.admit(self.response(body)).allowed)
            for fields in ([(b"X-Metadata", SECRET.encode())], [(b"X-Metadata", b"safe"), (b"x-metadata", SECRET.encode())],
                    [(b"X_Catchplate_Foo", b"reserved")], [(b"Set-Cookie", b"session=fixture")],
                    [(b"Content_Type", b"application/json")], [(b"X-Large", b"x" * 8193)]):
                self.assertFalse(self.admit(self.response(fields=fields)).allowed)
            self.assertFalse(self.admit(self.response(guarded=False)).allowed)

        def test_media_duplicate_transport_fields_and_no_legacy_adapter_widening(self):
            for media in (None, b"text/html", b"application/problem+json", b"application/json; charset=latin-1"):
                self.assertFalse(self.admit(self.response(media=media)).allowed)
            for fields in ([(b"Content-Type", b"application/json")], [(b"Content-Encoding", b"gzip")],
                    [(b"Content-Length", b"1"), (b"content-length", b"1")],
                    [(b"Transfer-Encoding", b"chunked"), (b"transfer-encoding", b"chunked")]):
                self.assertFalse(self.admit(self.response(fields=fields)).allowed)
            self.assertIsInstance(adapters.get_adapter("npm.registry"), adapters.NpmRegistryAdapter)


if __name__ == "__main__":
    unittest.main(verbosity=2)

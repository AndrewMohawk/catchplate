#!/usr/bin/env python3
"""Independent bounded npm publish protocol controls; no registry or custody.

Stock-shaped documents follow cached npm 11.8.0/libnpmpublish buildMetadata:
one version, one base64 attachment, SHA512/SHA1, and the inert HTTP tarball URL.
Tiny positive tarballs are real in-memory gzip/tar archives. This suite does not
execute npm, parse HTTP framing, extract archives, or prove public publication.
--pure selects compiler/schema/helper checks. Default also exercises actual
adapters and engine guards with the existing annotation-only parsed-flow fixture.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PURE = "--pure" in sys.argv
if PURE:
    sys.argv.remove("--pure")


def no_external_state(event, _args):
    if event in {"sqlite3.connect", "socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("npm publish protocol fixture attempted external state")


sys.addaudithook(no_external_state)
from catchplate import npm_metadata, npm_publish as npm, policy_bundle as pb
from catchplate import policy_route_authority as authority

PACKAGE = "fixture-package"
VERSION = "1.2.3"
SECRET = "synthetic-private-npm-publish-value"
ORIGIN = "https://registry.npmjs.org"
WIRE_LIMIT = 16777216
TARBALL_LIMIT = 8388608
HEADERS = ["accept", "content-type", "npm-auth-type", "npm-command", "npm-in-ci", "npm-scope", "user-agent"]
STATUSES = [200, 201, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504]
FIELDS = frozenset({"operation", "packageName", "packageVersion", "tag", "tarballIntegrity",
    "tarballShasum", "attachmentName", "attachmentBytes"})


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def inert_tarball(package, version):
    data = encoded({"name": package, "version": version, "description": "inert synthetic package"})
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo("package/package.json")
        entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
        archive.addfile(entry, io.BytesIO(data))
    return gzip.compress(stream.getvalue(), mtime=0)


def stock_document(package=PACKAGE, version=VERSION, tag="latest", *, tarball=None, access="public"):
    blob = inert_tarball(package, version) if tarball is None else tarball
    name = package + "-" + version + ".tgz"
    manifest = {"name": package, "version": version, "_id": package + "@" + version,
        "description": "synthetic stock-shaped publication", "_nodeVersion": "25.5.0", "_npmVersion": "11.8.0",
        "dependencies": {"synthetic-dependency": "^2.0.0"},
        "dist": {"integrity": "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode("ascii"),
            "shasum": hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
            "tarball": "http://registry.npmjs.org/" + package + "/-/" + name}}
    return {"_id": package, "name": package, "description": manifest["description"],
        "dist-tags": {tag: version}, "versions": {version: manifest}, "access": access,
        "_attachments": {name: {"content_type": "application/octet-stream",
            "data": base64.b64encode(blob).decode("ascii"), "length": len(blob)}}}


def target(package=PACKAGE):
    return ORIGIN + "/" + package.replace("/", "%2f")


def document(package=PACKAGE, tag="latest", *, window=None):
    constraints = [npm.response_envelope("publish.response")]
    if window is not None:
        constraints.append({"id": "publish.window", "type": "requestTimeWindow", "phase": "request",
            "timezone": "UTC", "dailyWindows": [dict(window)]})
    return {"apiVersion": "catchplate.policy/v1", "kind": "PolicyBundle",
        "metadata": {"id": "npm-publish-test", "sequence": 1, "rollbackEpoch": 1},
        "defaults": {"action": "deny", "failMode": "closed", "unknownHosts": "block",
            "unknownPaths": "block", "validationFailure": "block"},
        "principals": [{"id": "agent:fixture", "sourceCidrs": ["127.0.0.1/32"],
            "requiredHeaders": {"X-Catchplate-Agent": "fixture"}}],
        "credentials": [{"id": "credential:fixture", "credentialType": "static", "provider": "operator-demo",
            "providerSubject": "fixture-subject", "injection": {"type": "bearer", "header": "Authorization"}}],
        "routes": [{"id": "route.npm-publish", "principals": ["agent:fixture"], "credentialRef": "credential:fixture",
            "credentialHeader": {"mode": "replaceExact", "expectedValue": "Bearer catchplate-npm-placeholder-v1"},
            "match": {"scheme": "https", "host": "registry.npmjs.org", "port": 443,
                "methods": ["PUT"], "paths": ["/{package}"]},
            "adapter": {"type": "npm.publish.v1", "config": {"credentialBinding": {
                "credentialType": "static", "provider": "operator-demo", "subjects": ["fixture-subject"],
                "secretClass": "bearerToken"}, "package": package, "tag": tag,
                "request": npm.request_profile(), "response": npm.response_profile()}}, "constraints": constraints}]}


def compile_route(value=None, *, schema=True):
    return pb.compile_policy_bundle(document() if value is None else value, validate_schema=schema).routes[0]


def operation(body=None, *, package=PACKAGE, tag="latest", url=None, method="PUT"):
    return npm.validate_request(method, target(package) if url is None else url,
        encoded(stock_document(package, tag=tag)) if body is None else body, package=package, tag=tag)


class NpmPublishPureTests(unittest.TestCase):
    def test_real_embedded_schema_profiles_and_v1_v2_authority(self):
        schema = json.loads((ROOT / "schemas/adapters/npm.publish.v1.schema.json").read_text())
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["properties"]), {"credentialBinding", "package", "tag", "request", "response"})
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertIsInstance(schema.get("$defs"), dict)
        self.assertTrue(schema["$defs"])
        self.assertEqual(npm.request_profile(), {"allowedHeaders": HEADERS,
            "discardHeaders": ["accept-encoding", "npm-session"], "allowedQueryKeys": [],
            "allowedMediaTypes": ["application/json"], "maxBodyBytes": WIRE_LIMIT, "valueRules": []})
        expected = {"mode": "npmPublishJsonV1", "maxBodyBytes": 65536,
            "contentTypes": ["application/json"], "allowedHeaders": []}
        self.assertEqual(npm.response_profile(), {**expected, "error": {**expected, "onInvalid": "block"}})
        self.assertEqual(npm.response_envelope("test")["statusCodes"], STATUSES)
        original = document()
        for validate_schema in (True, False):
            for version in ("catchplate.policy/v1", "catchplate.policy/v2"):
                raw = deepcopy(original)
                raw["apiVersion"] = version
                if version.endswith("/v2"):
                    raw = authority.prepare_unsigned(raw, [])
                npm.validate_route(compile_route(raw, schema=validate_schema))
        self.assertEqual(authority._builtin("npm.publish.v1", "npm.publish"), "publish")
        self.assertIsNone(authority._builtin("npm.publish.v1", "npm.metadata.read"))
        self.assertEqual(pb.adapter_operation_field_names("npm.publish.v1", "npm.publish"), FIELDS)
        self.assertEqual(pb.provider_request_profile("npm.publish.v1"), npm.request_profile())
        self.assertEqual(original, document())

    def test_stock_shaped_scoped_and_unscoped_bytes_exact_operation(self):
        for package in (PACKAGE, "@fixture/package"):
            for tag in ("latest", "next", "release-1.2"):
                for access in (None, "public", "restricted"):
                    value = stock_document(package, tag=tag, access=access)
                    name, attachment = next(iter(value["_attachments"].items()))
                    dist = value["versions"][VERSION]["dist"]
                    expected = {"operation": "npm.publish", "packageName": package, "packageVersion": VERSION,
                        "tag": tag, "tarballIntegrity": dist["integrity"], "tarballShasum": dist["shasum"],
                        "attachmentName": name, "attachmentBytes": str(attachment["length"])}
                    self.assertEqual(operation(encoded(value), package=package, tag=tag), expected)
                    value.pop("description")
                    self.assertEqual(operation(encoded(value), package=package, tag=tag), expected)

    def test_signed_package_tag_transport_and_profiles_cannot_be_expanded(self):
        mutations = [lambda r: r["match"].update(methods=["GET", "PUT"]),
            lambda r: r["match"].update(methods=["POST"]), lambda r: r["match"].update(paths=["/**"]),
            lambda r: r["match"].update(host="REGISTRY.NPMJS.ORG"), lambda r: r["match"].update(port=443.0),
            lambda r: r["match"].update(scheme="http"), lambda r: r.update(jit={}),
            lambda r: r.update(responseObservation={}), lambda r: r.pop("credentialHeader"),
            lambda r: r["credentialHeader"].update(expectedValue="Bearer other"),
            lambda r: r["adapter"]["config"].update(package="*"),
            lambda r: r["adapter"]["config"].update(tag="*"),
            lambda r: r["adapter"]["config"].update(packages=[PACKAGE]),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(provider="npm"),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(subjects=["other"]),
            lambda r: r["adapter"]["config"]["request"].update(maxBodyBytes=float(WIRE_LIMIT)),
            lambda r: r["adapter"]["config"]["request"].update(allowedQueryKeys=["tag"]),
            lambda r: r["adapter"]["config"]["response"].update(mode="npmMetadataJsonV1"),
            lambda r: r["adapter"]["config"]["response"].update(maxBodyBytes=65536.0),
            lambda r: r["constraints"][0].update(statusCodes=[200.0] + STATUSES[1:])]
        for schema in (True, False):
            for index, mutate in enumerate(mutations):
                raw = document(); mutate(raw["routes"][0])
                with self.subTest(schema=schema, index=index), self.assertRaises(pb.PolicyBundleError):
                    compile_route(raw, schema=schema)
        original = pb.compile_policy_bundle(document()).hash
        for changed in (document("other-package"), document(tag="next"),
                document(window={"start": "09:00", "end": "17:00"})):
            self.assertNotEqual(pb.compile_policy_bundle(changed).hash, original)

    def test_canonical_target_and_tag_version_grammar(self):
        for suffix in ("?", "?tag=latest", "#", "/", "/-/fixture.tgz", "/-rev/1"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                operation(url=target() + suffix)
        for url in (ORIGIN + ":443/" + PACKAGE, "http://registry.npmjs.org/" + PACKAGE,
                "https://REGISTRY.NPMJS.ORG/" + PACKAGE, "https://registry.npmjs.org./" + PACKAGE,
                "https://user@registry.npmjs.org/" + PACKAGE, "https://other.invalid/" + PACKAGE,
                ORIGIN + "/other", ORIGIN + "/%66ixture-package", ORIGIN + "//" + PACKAGE,
                ORIGIN + "/@fixture/package", ORIGIN + "/@fixture%2Fpackage", ORIGIN + "/@fixture%252fpackage"):
            with self.subTest(url=url), self.assertRaises(ValueError): operation(url=url)
        for method in ("GET", "HEAD", "POST", "DELETE", "put"):
            with self.assertRaises(ValueError): operation(method=method)
        for tag in ("", "Latest", "1.2.3", "*", "next/other", "next\n", "a" * 65, None, 1):
            with self.subTest(tag=tag), self.assertRaises(ValueError): npm.validate_tag(tag)
        for version in ("0.0.0", "1.2.3-alpha.1", "1.2.3+build.01"):
            operation(encoded(stock_document(version=version)))
        for version in ("1.2", "v1.2.3", "01.2.3", "1.2.3-01", "1.2.3-", "1.2.3+", "1.2.3\n"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                operation(encoded(stock_document(version=version)))

    def test_document_identity_tags_and_closed_attachment_integrity(self):
        changes = [lambda v: v.update(name="other"), lambda v: v.update(_id="other"),
            lambda v: v.update(access="private"), lambda v: v.update(description=None),
            lambda v: v.update(_rev="1-synthetic"), lambda v: v.pop("access"),
            lambda v: v["dist-tags"].update(other=VERSION),
            lambda v: v.update({"dist-tags": {"next": VERSION}}),
            lambda v: v.update({"dist-tags": {"latest": "9.9.9"}}),
            lambda v: v["versions"].update({"9.9.9": deepcopy(v["versions"][VERSION])}),
            lambda v: v["versions"][VERSION].update(name="other"),
            lambda v: v["versions"][VERSION].update(version="9.9.9"),
            lambda v: v["versions"][VERSION].update(_id=PACKAGE + "@9.9.9"),
            lambda v: v["versions"][VERSION]["dist"].update(integrity="sha512-AAAA"),
            lambda v: v["versions"][VERSION]["dist"].update(shasum="0" * 40),
            lambda v: v["versions"][VERSION]["dist"].update(shasum=v["versions"][VERSION]["dist"]["shasum"].upper()),
            lambda v: v["versions"][VERSION]["dist"].update(tarball="https://registry.npmjs.org/file.tgz"),
            lambda v: v["versions"][VERSION]["dist"].update(extra="unreviewed"),
            lambda v: v["_attachments"].update({"extra.sigstore": {"data": "synthetic"}})]
        name = PACKAGE + "-" + VERSION + ".tgz"
        for field, bad in (("content_type", "application/gzip"), ("length", True), ("length", 0),
                ("length", 1), ("length", 1.0), ("data", "!!!!"), ("data", "YQ==\n"), ("extra", True)):
            changes.append(lambda v, field=field, bad=bad: v["_attachments"][name].update({field: bad}))
        for index, change in enumerate(changes):
            value = stock_document(); change(value)
            with self.subTest(index=index), self.assertRaises(ValueError): operation(encoded(value))
        value = stock_document(tarball=b"a")
        value["_attachments"][name]["data"] = "YR=="  # Same decoded byte, noncanonical padding bits.
        with self.assertRaises(ValueError): operation(encoded(value))

    def test_strict_json_and_wire_decoded_manifest_limits(self):
        valid = encoded(stock_document())
        for body in (b"", b"null", b"[]", b"\xef\xbb\xbf" + valid, valid + b" trailing",
                valid[:-1] + b',"name":"fixture-package"}',
                valid.replace(b'"length":', b'"length":NaN,"length":', 1),
                valid.replace(b'"description":"synthetic stock-shaped publication"', b'"description":"\\ud800"', 1),
                valid.replace(b'"description":"synthetic stock-shaped publication"', b'"description":1e999', 1)):
            with self.subTest(body=body[:24]), self.assertRaises((ValueError, UnicodeError)): operation(body)
        value = stock_document(tarball=b"x" * TARBALL_LIMIT)
        self.assertEqual(operation(encoded(value))["attachmentBytes"], str(TARBALL_LIMIT))
        value = stock_document(tarball=b"x" * (TARBALL_LIMIT + 1))
        with self.assertRaises(ValueError): operation(encoded(value))
        value = stock_document(); value["description"] = ""
        value["description"] = "x" * (WIRE_LIMIT - len(encoded(value)))
        body = encoded(value)
        self.assertEqual(len(body), WIRE_LIMIT)
        operation(body)
        with self.assertRaises(ValueError): operation(body + b" ")
        value = stock_document(); manifest = value["versions"][VERSION]; manifest["padding"] = ""
        manifest["padding"] = "x" * (65536 - len(encoded(manifest)))
        operation(encoded(value))
        manifest["padding"] += "x"
        with self.assertRaises(ValueError): operation(encoded(value))

    def test_conservative_manifest_budget_is_independent_of_number_spelling(self):
        for number in (0, 1.0, 1e20, -0.0, 10 ** 200):
            self.assertEqual(npm.manifest_budget({"n": number}), 326)
        for value, expected in (({"a": []}, 8), ({"x": "é"}, 10), ({"x": False}, 11),
                ({"x": None}, 10), ({"x": '"\n'}, 12)):
            self.assertEqual(npm.manifest_budget(value), expected)
        value = stock_document()
        manifest = value["versions"][VERSION]
        manifest.update(number=0, padding="")
        # Independently account for punctuation/string bytes and the fixed
        # 320-byte numeric cost; never use the helper to choose its own limit.
        manifest["padding"] = "x" * (65536 - len(encoded(manifest)) - 319)
        for number in (0, 1.0, 1e20, -0.0, 10 ** 200):
            manifest["number"] = number
            operation(encoded(value))
            manifest["padding"] += "x"
            with self.assertRaises(ValueError): operation(encoded(value))
            manifest["padding"] = manifest["padding"][:-1]

    def test_optional_utc_daily_window_is_closed_and_boundary_exact(self):
        raw = document(window={"start": "09:00", "end": "17:00"})
        self.assertEqual(len(compile_route(raw).constraints), 2)
        mutations = [lambda c: c.update(timezone="America/New_York"), lambda c: c.update(weekdays=["mon"]),
            lambda c: c.update(phase="response"), lambda c: c.update(description="implicit expansion"),
            lambda c: c["dailyWindows"].append({"start": "18:00", "end": "19:00"}),
            lambda c: c["dailyWindows"][0].update(start="17:00", end="09:00"),
            lambda c: c["dailyWindows"][0].update(start="09:00", end="09:00"),
            lambda c: c["dailyWindows"][0].update(start="9:00"),
            lambda c: c["dailyWindows"][0].update(end="24:00")]
        for mutation in mutations:
            changed = deepcopy(raw); mutation(changed["routes"][0]["constraints"][1])
            with self.assertRaises(pb.PolicyBundleError): compile_route(changed, schema=False)
        self.assertEqual(len(compile_route().constraints), 1)

    def test_metadata_and_legacy_registry_jit_remain_separate(self):
        legacy = json.loads((ROOT / "policies/npm-weekday-hours.example.json").read_text())
        before = pb.compile_policy_bundle(legacy).hash
        compile_route()
        self.assertEqual(pb.compile_policy_bundle(legacy).hash, before)
        self.assertTrue(legacy["routes"][0]["jit"]["approvers"]["authn"]["requireHardwareAttestation"])
        for jit in ({}, {"required": False}):
            changed = deepcopy(legacy); changed["routes"][0]["jit"] = jit
            with self.assertRaises(pb.PolicyBundleError): pb.compile_policy_bundle(changed, validate_schema=False)
        self.assertEqual(npm_metadata.request_profile()["maxBodyBytes"], 0)
        self.assertEqual(npm_metadata.response_profile()["mode"], "npmMetadataJsonV1")
        with self.assertRaises(ValueError): npm_metadata.validate_request("PUT", target(), encoded(stock_document()), packages=[PACKAGE])
        for adapter in ("npm.registry", "npm.metadata.v1", "generic.rest"):
            with self.assertRaises(pb.PolicyBundleError):
                pb.validate_buffered_passthrough_response("fixture", adapter, npm.response_profile())


if not PURE:
    # Reuses only inert parsed-field objects and annotation import compatibility;
    # no admission, transport, credential, response or production guard is mocked.
    import test_npm_metadata as parsed
    from types import SimpleNamespace
    from catchplate import adapters, policy_engine as engine
    from catchplate.constraints import _enforce_request_time_window

    class NpmPublishAdapterTests(unittest.TestCase):
        def setUp(self):
            self.snapshot = pb.compile_policy_bundle(document())
            self.route = self.snapshot.routes[0]
            self.adapter = adapters.get_adapter("npm.publish.v1")
            self.params = {"package": PACKAGE}

        def flow(self, *, body=None, url=None, method="PUT", fields=()):
            return parsed.request(target() if url is None else url, method=method,
                body=encoded(stock_document()) if body is None else body,
                headers=[(b"Content-Type", b"application/json"), *fields])

        def response(self, body=b'{"id":"fixture-package","rev":"1-synthetic","arbitrary":{"n":1e0}}',
                *, status=201, media=b"application/json", fields=(), guarded=True):
            flow = self.flow()
            flow.response = SimpleNamespace(status_code=status, raw_content=body, content=body, trailers=None,
                headers=parsed.ParsedHeaders(([(b"Content-Type", media)] if media is not None else []) + list(fields)))
            flow.metadata.update(catchplate_route=self.route,
                catchplate_operation=self.adapter.operation_fields(flow, self.route, self.params))
            if guarded:
                guard = engine._ResponseCredentialGuard(); guard.add_text_encodings(SECRET)
                engine._install_response_credential_guard(flow, guard)
            return flow

        def admit(self, flow):
            for check in (lambda: engine._validate_response_content_encoding(flow),
                    lambda: engine._evaluate_response_envelope(flow, self.route),
                    lambda: self.adapter.prepare_response(flow, self.route, self.params),
                    lambda: self.adapter.validate_response(flow, self.route, self.params)):
                result = check()
                if not result.allowed: return result
            return result

        def test_real_adapter_scoped_request_and_operation_binding(self):
            for package in (PACKAGE, "@fixture/package"):
                route = compile_route(document(package))
                flow = self.flow(body=encoded(stock_document(package)), url=target(package))
                params = {"package": package.replace("/", "%2f")}
                self.assertTrue(self.adapter.validate_request(flow, route, params).allowed)
                self.assertEqual(self.adapter.operation_fields(flow, route, params), operation(flow.request.raw_content, package=package))
                pb.validated_request_urlsplit_for_route(flow.request.pretty_url, route)
                self.assertEqual(engine._npm_publish_scoped_target(flow, route), package.startswith("@"))
                self.assertFalse(self.adapter.validate_request(flow, route, {}).allowed)
            wrong = stock_document(); wrong["dist-tags"] = {"next": VERSION}
            self.assertFalse(self.adapter.validate_request(self.flow(body=encoded(wrong)), self.route, self.params).allowed)
            self.assertFalse(self.adapter.validate_request(self.flow(method="GET"), self.route, self.params).allowed)

        def test_actual_utc_daily_window_boundaries_without_implicit_weekdays(self):
            route = compile_route(document(window={"start": "09:00", "end": "17:00"}))
            window = next(c for c in route.constraints if c["type"] == "requestTimeWindow")
            for hour, minute, allowed in ((8, 59, False), (9, 0, True), (16, 59, True), (17, 0, False)):
                for day in (10, 11):  # Saturday and Sunday: no implicit weekday policy.
                    now = datetime(2026, 10, day, hour, minute, tzinfo=timezone.utc)
                    self.assertEqual(_enforce_request_time_window(window, now=now).allowed, allowed)

        def test_actual_header_discard_and_canonical_body_commitments(self):
            flow = self.flow(fields=[(b"Accept", b"*/*"), (b"Npm-Command", b"publish"),
                (b"Npm-Session", b"synthetic-session"), (b"Accept-Encoding", b"gzip,deflate"),
                (b"X-Catchplate-Agent", b"fixture")])
            principal = self.snapshot.principals["agent:fixture"]
            credential = self.snapshot.credentials[self.route.credential_ref]
            self.assertTrue(adapters.preflight_request_admission(flow, self.route,
                engine._normalized_request_headers(flow)).allowed)
            discarded = engine._discard_declared_request_headers(flow, self.route, principal, credential)
            engine._strip_identity_headers(flow, principal)
            self.assertNotIn("npm-session", flow.request.headers)
            self.assertNotIn("accept-encoding", flow.request.headers)
            self.assertTrue(self.adapter.validate_request(flow, self.route, self.params).allowed)
            canonical = engine._canonical_request(flow, principal=principal, route=self.route,
                credential_version="1", policy_hash=self.snapshot.hash,
                operation_fields=self.adapter.operation_fields(flow, self.route, self.params),
                forwarded_headers=engine._canonical_forwarded_request_headers(flow, credential, route=self.route),
                discard_headers=discarded)
            self.assertIn("tarballShasum", json.dumps(canonical))
            self.assertNotIn("synthetic-session", json.dumps(canonical))
            for fields in ([(b"Npm-Command", b"publish"), (b"npm-command", b"publish")],
                    [(b"Content-Type", b"application/json")], [(b"Npm-Otp", b"123456")]):
                self.assertFalse(self.adapter.validate_request(self.flow(fields=fields), self.route, self.params).allowed)

        def test_full_response_status_media_and_bounded_json_not_success_claim(self):
            for status in STATUSES:
                flow = self.response(status=status, media=b"Application/JSON; charset=UTF-8",
                    fields=[(b"Date", b"synthetic-date"), (b"X-Cache", b"one"), (b"x-cache", b"two")])
                original = flow.response.raw_content
                self.assertTrue(self.admit(flow).allowed)
                self.assertEqual(flow.response.raw_content, original)
                self.assertEqual(flow.response.headers["Content-Type"], "application/json")
                self.assertEqual(set(flow.response.headers), {"content-type", "content-length"})
            for status in (202, 204, 206, 301, 418, 501):
                self.assertFalse(self.admit(self.response(status=status)).allowed)
            body = b'{"padding":"' + b"x" * (65536 - 14) + b'"}'
            self.assertEqual(len(body), 65536)
            self.assertTrue(self.admit(self.response(body)).allowed)
            self.assertFalse(self.admit(self.response(body + b" ")).allowed)
            for media in (None, b"text/html", b"application/problem+json", b"application/vnd.npm.install-v1+json",
                    b"application/json; charset=latin-1", b"application/json;charset=utf-8;charset=utf-8"):
                self.assertFalse(self.admit(self.response(media=media)).allowed)

        def test_response_strict_json_reflection_and_unselected_metadata_scan(self):
            for body in (b"[]", b"null", b'{"id":"one","id":"two"}', b'{"n":NaN}', b'{"n":1e999}',
                    b'{"x":"\\ud800"}', b"\xef\xbb\xbf{}", b"{} trailing",
                    encoded({"message": SECRET}), ('{"x":"' + ''.join('\\u%04x' % ord(c) for c in SECRET) + '"}').encode()):
                self.assertFalse(self.admit(self.response(body)).allowed)
            for fields in ([(b"X-Metadata", SECRET.encode())],
                    [(b"X-Metadata", b"safe"), (b"x-metadata", SECRET.encode())],
                    [(b"Set-Cookie", b"session=synthetic")], [(b"Content-Encoding", b"gzip")],
                    [(b"Content-Type", b"application/json")], [(b"X_Large", b"x" * 8193)]):
                self.assertFalse(self.admit(self.response(fields=fields)).allowed)
            self.assertFalse(self.admit(self.response(guarded=False)).allowed)
            self.assertIsInstance(adapters.get_adapter("npm.registry"), adapters.NpmRegistryAdapter)


if __name__ == "__main__":
    unittest.main(verbosity=2)

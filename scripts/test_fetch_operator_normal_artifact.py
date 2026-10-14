#!/usr/bin/env python3
"""In-memory provenance and archive controls; no requests, files or execution."""
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import unittest
import urllib.error
import zipfile

spec = importlib.util.spec_from_file_location("normal_fetch", Path(__file__).with_name("fetch_operator_normal_artifact.py"))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


class ArtifactControls(unittest.TestCase):
    def run_record(self):
        return {"id":123, "run_attempt":1, "event":"workflow_dispatch", "status":"completed",
            "conclusion":"success", "path":".github/workflows/native-review-rust.yml", "head_branch":"main",
            "head_sha":"a"*40, "repository":{"full_name":fetch.REPOSITORY},
            "head_repository":{"full_name":fetch.REPOSITORY}}

    def artifact(self):
        return {"id":456, "name":"serverware-normal-proxy-"+"b"*64, "expired":False,
            "size_in_bytes":100, "digest":"sha256:"+"c"*64,
            "workflow_run":{"id":123, "head_sha":"a"*40, "head_branch":"main"}}

    def archive(self, names=None, *, symlink=False):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name in names or ("normal.json", "serverware-decision-gate"):
                row = zipfile.ZipInfo(name)
                row.external_attr = ((stat.S_IFLNK if symlink else stat.S_IFREG) | 0o555) << 16
                archive.writestr(row, b"payload")
        raw = stream.getvalue()
        return raw, {"digest":"sha256:"+hashlib.sha256(raw).hexdigest()}

    def test_trusted_run(self):
        fetch.validate_run(self.run_record(), 123, ".github/workflows/native-review-rust.yml")

    def test_untrusted_or_incomplete_run_refused(self):
        for key, value in (("id",124), ("event","pull_request"), ("status","in_progress"),
                ("conclusion","failure"), ("path","other.yml"), ("head_branch","other"),
                ("head_sha","unknown"), ("run_attempt",False),
                ("head_repository",{"full_name":"fork/serverware"})):
            record = self.run_record(); record[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                fetch.validate_run(record, 123, ".github/workflows/native-review-rust.yml")

    def test_unique_input_named_artifact(self):
        artifact = self.artifact()
        self.assertEqual(fetch.select_artifact({"total_count":1,"artifacts":[artifact]},
            self.run_record(), "b"*64), artifact)

    def test_bad_artifact_or_ambiguous_inventory_refused(self):
        for key, value in (("expired",True), ("size_in_bytes",fetch.ZIP_LIMIT+1), ("digest","unknown"),
                ("name","other"), ("id",False), ("workflow_run",{"id":124,"head_sha":"a"*40,"head_branch":"main"})):
            artifact = self.artifact(); artifact[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                fetch.select_artifact({"total_count":1,"artifacts":[artifact]}, self.run_record(), "b"*64)
        for payload in ({"total_count":2,"artifacts":[self.artifact()]},
                {"total_count":2,"artifacts":[self.artifact(),self.artifact()]}):
            with self.assertRaises(ValueError):
                fetch.select_artifact(payload,self.run_record(),"b"*64)

    def test_archive_is_exactly_two_regular_files(self):
        raw, artifact = self.archive()
        self.assertEqual(fetch.archive_files(raw,artifact),
            {"normal.json":b"payload", "serverware-decision-gate":b"payload"})

    def test_archive_digest_names_and_symlinks_refused(self):
        raw, artifact = self.archive()
        with self.assertRaises(ValueError):
            fetch.archive_files(raw+b"changed",artifact)
        for names in (("../normal.json","serverware-decision-gate"),
                ("normal.json","serverware-decision-gate","secret.log"), ("normal.json",)):
            raw, artifact = self.archive(names)
            with self.subTest(names=names), self.assertRaises(ValueError):
                fetch.archive_files(raw,artifact)
        raw, artifact = self.archive(symlink=True)
        with self.assertRaises(ValueError):
            fetch.archive_files(raw,artifact)

    def test_duplicate_json_keys_refused(self):
        with self.assertRaises(ValueError):
            fetch.document(b'{"ok":true,"ok":false}')

    def test_signed_redirect_does_not_receive_github_token(self):
        calls = []
        class Response(io.BytesIO):
            status = 200
        class Opener:
            def open(self, request, timeout):
                calls.append(request)
                if len(calls) == 1:
                    raise urllib.error.HTTPError(request.full_url,302,"redirect",
                        {"Location":"https://production.blob.core.windows.net/artifact?sig=private"},None)
                return Response(b"archive")
        github = fetch.GitHub("test-token"); github.opener = Opener()
        self.assertEqual(github.request("/actions/artifacts/456/zip",archive=True),b"archive")
        self.assertEqual(calls[0].get_header("Authorization"),"Bearer test-token")
        self.assertIsNone(calls[1].get_header("Authorization"))

    def test_untrusted_redirect_refused_before_second_request(self):
        for target in ("http://production.blob.core.windows.net/a", "https://evil.example/a",
                "https://user@production.blob.core.windows.net/a", "https://production.blob.core.windows.net:444/a"):
            calls = []
            class Opener:
                def open(self, request, timeout):
                    calls.append(request)
                    raise urllib.error.HTTPError(request.full_url,302,"redirect",{"Location":target},None)
            github = fetch.GitHub("test-token"); github.opener = Opener()
            with self.subTest(target=target), self.assertRaises(ValueError):
                github.request("/actions/artifacts/456/zip",archive=True)
            self.assertEqual(len(calls),1)


if __name__ == "__main__":
    unittest.main()

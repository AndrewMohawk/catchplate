#!/usr/bin/env python3
"""In-memory provenance and archive controls; no requests, files or execution."""
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
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

    def invocation(self, *, local_operator=False):
        return {"local_operator":local_operator,
            "environment":{} if local_operator else {"GITHUB_ACTIONS":"true", "GITHUB_REPOSITORY":fetch.REPOSITORY},
            "platform":"linux", "uid":1000, "euid":1000,
            "source":fetch.LOCAL_SOURCE, "run_id":"123"}

    def local_output(self):
        return fetch.LOCAL_OUTPUT_ROOT / "serverware-normal-artifact.Abc12345" / "serverware-normal-proxy"

    def test_explicit_local_flag_never_changes_hosted_default(self):
        arguments = ["--run-id", "123", "--output", str(self.local_output())]
        self.assertIs(fetch.parse_arguments(arguments).local_operator, False)
        self.assertIs(fetch.parse_arguments([*arguments, "--local-operator"]).local_operator, True)
        fetch.validate_invocation(**self.invocation())
        fetch.validate_invocation(**self.invocation(local_operator=True))
        absent = self.invocation(); absent["environment"] = {}
        with self.assertRaises(ValueError):
            fetch.validate_invocation(**absent)

    def test_local_mode_refuses_hosted_spoof_other_checkout_and_privilege(self):
        for changes in ({"environment":{"GITHUB_ACTIONS":"true", "GITHUB_REPOSITORY":fetch.REPOSITORY}},
                {"environment":{"GITHUB_ACTIONS":"false"}}, {"source":Path("/other/serverware")},
                {"platform":"darwin"}, {"uid":0, "euid":0}, {"euid":0},
                {"run_id":"0123"}, {"run_id":"123/attempts/2"}, {"local_operator":"true"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                fetch.validate_invocation(**{**self.invocation(local_operator=True), **changes})
        for environment in ({}, {"GITHUB_ACTIONS":"true", "GITHUB_REPOSITORY":"fork/serverware"},
                {"GITHUB_ACTIONS":"false", "GITHUB_REPOSITORY":fetch.REPOSITORY}):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                fetch.validate_invocation(**{**self.invocation(), "environment":environment})

    def test_local_output_has_one_fixed_private_job_shape(self):
        fetch.validate_local_output_shape(self.local_output())
        for output in (Path("serverware-normal-proxy"), fetch.LOCAL_OUTPUT_ROOT / "serverware-normal-proxy",
                self.local_output().with_name("arbitrary"),
                Path("/tmp/serverware-normal-artifact.Abc12345/serverware-normal-proxy"),
                fetch.LOCAL_OUTPUT_ROOT / "other.Abc12345" / "serverware-normal-proxy",
                fetch.LOCAL_OUTPUT_ROOT / "serverware-normal-artifact.short" / "serverware-normal-proxy",
                fetch.LOCAL_OUTPUT_ROOT / ("serverware-normal-artifact." + "a" * 33) / "serverware-normal-proxy"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                fetch.validate_local_output_shape(output)

    def test_local_parent_requires_actual_owner_only_directory(self):
        fetch.validate_private_directory(SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000), 1000)
        for mode, uid in ((stat.S_IFDIR | 0o755,1000), (stat.S_IFDIR | 0o770,1000),
                (stat.S_IFDIR | 0o1700,1000), (stat.S_IFDIR | 0o700,0),
                (stat.S_IFLNK | 0o700,1000), (stat.S_IFREG | 0o700,1000)):
            with self.subTest(mode=mode, uid=uid), self.assertRaises(ValueError):
                fetch.validate_private_directory(SimpleNamespace(st_mode=mode, st_uid=uid), 1000)

    def test_local_output_refuses_existing_alias_and_changed_parent(self):
        output = self.local_output()
        private = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000)
        with patch.object(fetch.Path, "exists", return_value=False) as exists, \
                patch.object(fetch.Path, "is_symlink", return_value=False) as symlink, \
                patch.object(fetch.Path, "resolve", return_value=output.parent) as resolve, \
                patch.object(fetch.Path, "lstat", return_value=private) as metadata, \
                patch.object(fetch.os, "getuid", return_value=1000):
            fetch.validate_output(output, local_operator=True, environment={})
            resolve.assert_called_with(strict=True)
            exists.return_value = True
            with self.assertRaises(ValueError):
                fetch.validate_output(output, local_operator=True, environment={})
            exists.return_value = False; symlink.return_value = True
            with self.assertRaises(ValueError):
                fetch.validate_output(output, local_operator=True, environment={})
            symlink.return_value = False; resolve.return_value = Path("/other/parent")
            with self.assertRaises(ValueError):
                fetch.validate_output(output, local_operator=True, environment={})
            resolve.return_value = output.parent
            metadata.return_value = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000)
            with self.assertRaises(ValueError):
                fetch.validate_output(output, local_operator=True, environment={})

    def test_local_checkout_is_committed_clean_main_and_exact_origin(self):
        values = ("a" * 40, b"refs/heads/main\n",
            b"https://github.com/AndrewMohawk/serverware.git\n", b"")
        fetch.validate_local_checkout(*values)
        for index, value in ((0,"not-a-commit"), (1,b"HEAD\n"), (1,b"refs/heads/other\n"),
                (2,b"https://github.com/fork/serverware.git\n"),
                (2,b"https://github.com/AndrewMohawk/serverware.git/\n"),
                (3,b" M scripts/fetch_operator_normal_artifact.py\n"), (3,b"?? new-file\n")):
            changed = list(values); changed[index] = value
            with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                fetch.validate_local_checkout(*changed)

    def test_local_remote_main_must_equal_current_committed_source(self):
        current = "a" * 40
        reference = {"ref":"refs/heads/main", "object":{"type":"commit", "sha":current}}
        fetch.validate_remote_main(reference, current)
        for changed in ({**reference, "ref":"refs/heads/other"},
                {**reference, "object":{"type":"tag", "sha":current}},
                {**reference, "object":{"type":"commit", "sha":"b" * 40}},
                {**reference, "object":None}, {}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                fetch.validate_remote_main(changed, current)

    def test_local_credential_environment_excludes_tokens_debug_and_overrides(self):
        environment = {"HOME":str(fetch.LOCAL_SOURCE.parent), "GH_TOKEN":"private-canary",
            "GITHUB_TOKEN":"private-canary", "GH_DEBUG":"api", "HTTPS_PROXY":"https://other",
            "GH_HOST":"other", "PATH":"/other/bin"}
        admitted = fetch.local_credential_environment(environment)
        self.assertEqual(admitted, {"HOME":"/home/catchplate", "PATH":"/usr/bin:/bin", "LANG":"C.UTF-8",
            "GH_HOST":"github.com", "GH_PROMPT_DISABLED":"1", "GIT_TERMINAL_PROMPT":"0"})
        self.assertNotIn("private-canary", repr(admitted))
        for changes in ({"HOME":"/other"}, {"GH_CONFIG_DIR":"/other"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                fetch.local_credential_environment({**environment, **changes})

    def test_local_token_is_one_bounded_ascii_value(self):
        self.assertEqual(fetch.local_token(b"ghp_syntheticOnly\n"), "ghp_syntheticOnly")
        self.assertEqual(fetch.local_token(b"ghp_syntheticOnly"), "ghp_syntheticOnly")
        for raw in (b"", b"\n", b"secret\n\n", b"secret\r\n", b"secret value", b"\xff", b"a" * 8193, "secret"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                fetch.local_token(raw)

    def test_local_token_capture_uses_existing_cli_login_only_in_memory(self):
        environment = {"HOME":str(fetch.LOCAL_SOURCE.parent), "GH_TOKEN":"ignoredAmbient"}
        with patch.object(fetch.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=b"ghp_syntheticOnly\n")) as run:
            self.assertEqual(fetch.read_local_token(environment), "ghp_syntheticOnly")
            run.assert_called_once_with(["/usr/bin/gh", "auth", "token", "--hostname", "github.com"],
                env=fetch.local_credential_environment(environment), stdin=fetch.subprocess.DEVNULL,
                stdout=fetch.subprocess.PIPE, stderr=fetch.subprocess.DEVNULL, timeout=20, check=False)
        with patch.object(fetch.subprocess, "run", return_value=SimpleNamespace(
                returncode=1, stdout=b"privateFailureCanary")), patch.object(fetch, "local_token") as parse:
            with self.assertRaises(ValueError):
                fetch.read_local_token(environment)
            parse.assert_not_called()

    def test_local_provenance_does_not_relabel_hosted_producer(self):
        receipt = {"sourceRevision":"a" * 40, "buildInputIdentity":"b" * 64,
            "binary":{"sha256":"d" * 64, "bytes":123}}
        values = (receipt, self.run_record(), self.artifact(), b"original-receipt", "e" * 40)
        hosted = fetch.selection_receipt(*values, local_operator=False)
        local = fetch.selection_receipt(*values, local_operator=True)
        self.assertEqual(set(hosted), {"schema", "ok", "appCommit", "buildCommit", "buildRunId", "buildRunAttempt",
            "artifactId", "artifactZipSha256", "receiptSha256", "buildInputIdentity", "binarySha256", "binaryBytes",
            "reusedArtifact", "compiledInThisRun", "executed", "deployed"})
        self.assertEqual(local.pop("consumer"), {"mode":"local-operator", "githubActions":False,
            "sourceBranch":"main", "remoteMainCommit":"e" * 40})
        self.assertEqual(local, hosted)
        self.assertEqual(hosted["buildCommit"], "a" * 40)
        self.assertEqual(hosted["appCommit"], "e" * 40)
        self.assertTrue(all(hosted[key] is False for key in ("compiledInThisRun", "executed", "deployed")))

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

    def test_local_signed_redirect_is_labeled_local_and_never_receives_token(self):
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
        github = fetch.GitHub("test-token", local_operator=True); github.opener = Opener()
        self.assertEqual(github.request("/actions/artifacts/456/zip",archive=True),b"archive")
        self.assertEqual(calls[0].get_header("Authorization"), "Bearer test-token")
        self.assertIsNone(calls[1].get_header("Authorization"))
        self.assertEqual([call.get_header("User-agent") for call in calls],
            ["Serverware-local-normal-artifact/1"] * 2)

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

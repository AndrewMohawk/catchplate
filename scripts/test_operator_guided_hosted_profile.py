"""Pure hosted-profile controls: no Docker, browser, application or network."""
from __future__ import annotations

import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def forbid_runtime(event, args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn", "os.posix_spawn")) \
            or event in {"os.system", "os.fork", "os.forkpty", "os.kill", "os.killpg"}:
        raise AssertionError("pure hosted profile attempted runtime I/O")


sys.addaudithook(forbid_runtime)
from scripts import operator_guided_hosted_profile as profile
from scripts import provision_operator_guided_hosted as provisioner
from scripts import prepare_operator_guided_fixture as recipe
from scripts import run_operator_guided_fixture as runner

REVISION = "a" * 40
IDENTITY = "b" * 64
GITHUB = {"repository": "owner/repository", "runId": "12345", "runAttempt": "1"}
CURL = {"path": "/usr/bin/curl", "sha256": "c" * 64, "bytes": 300000,
    "version": "curl 7.88.1 (x86_64-pc-linux-gnu) libcurl/7.88.1 OpenSSL/3",
    "protocols": ["http", "https"], "features": ["HTTPS-proxy", "SSL"]}
ARGS = (Path("/synthetic/source"), Path("/synthetic/gate"), Path("/synthetic/initializer.py"),
    Path("/srv/catchplate-fast/tmp/serverware-guided-private.abcdefgh"))


def receipt():
    return {"schema": profile.SCHEMA, "profile": profile.PROFILE, "sourceRevision": REVISION,
        "sourcePins": {name: "d" * 64 for name in profile.PIN_FILES}, "github": dict(GITHUB),
        "app": {"id": "sha256:" + "e" * 64, "tag": profile.namespace(GITHUB) + ":runtime",
            "target": "production-runtime", "labels": {profile.LABEL: profile.namespace(GITHUB),
                profile.LABEL + ".source": REVISION}},
        "client": {"reference": profile.CLIENT_IMAGE, "id": profile.CLIENT_ID,
            "python": profile.PYTHON, "entrypoint": None},
        "gate": {"reference": profile.GATE_IMAGE, "id": "sha256:" + "f" * 64}, "curl": deepcopy(CURL),
        "metadataContainerRemoved": True, "nativeAuthority": False, "journeyExecuted": False}


def metadata_row(status="created"):
    return {"Id": IDENTITY, "Name": "/" + profile.namespace(GITHUB) + "-curl", "Image": profile.CLIENT_ID,
        "Config": {"Labels": {profile.LABEL: profile.namespace(GITHUB)}, "User": "65534:65534",
            "Entrypoint": [profile.PYTHON], "Cmd": ["-I", "-S", "-B", "-c", profile.CURL_PROBE]},
        "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Memory": 134217728,
            "MemorySwap": 134217728, "NanoCpus": 250000000, "PidsLimit": 16, "CapDrop": ["ALL"],
            "CapAdd": None, "Privileged": False, "PortBindings": {}, "Init": True,
            "RestartPolicy": {"Name": "no"}, "SecurityOpt": ["no-new-privileges"],
            "LogConfig": {"Type": "none", "Config": {}}}, "Mounts": [], "RestartCount": 0,
        "State": {"Status": status, "ExitCode": 0, "OOMKilled": False}}


class HostedProfileTests(unittest.TestCase):
    def test_closed_receipt_is_runtime_provenance_only(self):
        value = receipt()
        self.assertIs(profile.validate(value, revision=REVISION, github=GITHUB), value)
        for mutate in (lambda v: v.update(nativeAuthority=True), lambda v: v.update(journeyExecuted=True),
                lambda v: v.update(metadataContainerRemoved=False), lambda v: v.update(extra=True)):
            changed = deepcopy(value); mutate(changed)
            with self.assertRaises(ValueError): profile.validate(changed)

    def test_public_client_and_gate_are_not_overrides(self):
        for key, replacement in (("reference", "python:latest"), ("id", "sha256:" + "1" * 64),
                ("python", "/usr/bin/python3"), ("entrypoint", ["/entrypoint.sh"])):
            changed = receipt(); changed["client"][key] = replacement
            with self.assertRaises(ValueError): profile.validate(changed)
        changed = receipt(); changed["gate"]["reference"] = "python:latest"
        with self.assertRaises(ValueError): profile.validate(changed)

    def test_app_build_is_fixed_target_and_run_namespace(self):
        for key, replacement in (("target", "production-test"), ("tag", "arbitrary:latest"),
                ("labels", {profile.LABEL: "another-run"}), ("id", "latest")):
            changed = receipt(); changed["app"][key] = replacement
            with self.assertRaises(ValueError): profile.validate(changed)

    def test_current_source_and_original_run_are_joined(self):
        with patch.object(profile, "source_pins", return_value=receipt()["sourcePins"]):
            profile.validate(receipt(), source=Path("/synthetic"))
        with patch.object(profile, "source_pins", return_value={}):
            with self.assertRaises(ValueError): profile.validate(receipt(), source=Path("/synthetic"))
        with self.assertRaises(ValueError): profile.validate(receipt(), revision="0" * 40)
        with self.assertRaises(ValueError): profile.validate(receipt(), github={**GITHUB, "runAttempt": "2"})

    def test_curl_requires_real_https_proxy_features_and_exact_shape(self):
        for key, replacement in (("path", "/tmp/curl"), ("sha256", "not-a-digest"), ("bytes", True),
                ("protocols", ["http"]), ("features", ["SSL"]), ("features", ["SSL", "HTTPS-proxy"]),
                ("version", "curl test\nprivate")):
            changed = deepcopy(CURL); changed[key] = replacement
            with self.assertRaises(ValueError): profile.validate_curl(changed)

    def test_github_identity_is_exact_numeric_and_hosted(self):
        environment = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "GITHUB_REPOSITORY": GITHUB["repository"],
            "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1"}
        self.assertEqual(profile.github_identity(environment), GITHUB)
        for key, replacement in (("GITHUB_ACTIONS", "false"), ("RUNNER_OS", "Windows"),
                ("GITHUB_RUN_ID", "../12345"), ("GITHUB_RUN_ATTEMPT", "0")):
            with self.assertRaises(ValueError): profile.github_identity({**environment, key: replacement})

    def test_receipt_read_rejects_duplicate_fields_symlinks_and_writable_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_text(json.dumps(receipt())); path.chmod(0o444)
            self.assertEqual(profile.read(path), receipt())
            link = path.with_name("link.json"); link.symlink_to(path)
            with self.assertRaises(ValueError): profile.read(link)
            path.chmod(0o666)
            with self.assertRaises(ValueError): profile.read(path)
            path.write_text('{"schema":"one","schema":"two"}'); path.chmod(0o444)
            with self.assertRaises(ValueError): profile.read(path)

    def test_hosted_recipe_changes_only_fixed_runtime_inputs(self):
        legacy = recipe.build(*ARGS, expected_binary_sha256=IDENTITY)
        value = receipt(); path = Path("/synthetic/provision.json")
        current = recipe.build(*ARGS, expected_binary_sha256=IDENTITY, hosted_profile=value, hosted_provision=path)
        expected = deepcopy(legacy)
        for service in expected["services"].values():
            if service["image"] in {recipe.base.APP_IMAGE, recipe.base.FIXTURE_IMAGE}:
                service["image"] = value["app"]["id"]
        check = expected["services"]["check"]
        check["image"] = profile.CLIENT_IMAGE; check["entrypoint"] = [profile.PYTHON, "-B"]
        check["command"][check["command"].index("--expected-curl-sha256") + 1] = CURL["sha256"]
        check["command"] += ["--profile", profile.PROFILE, "--hosted-provision", profile.PROVISION_MOUNT]
        # The receipt precedes the two shared hosts/resolver mounts.
        check["volumes"].insert(len(check["volumes"]) - 2, recipe.base.bind(path, profile.PROVISION_MOUNT))
        self.assertEqual(current, expected)
        self.assertEqual((runner.WORK_SECONDS, runner.CLEANUP_SECONDS, recipe.CHECKER_OUTER_SECONDS,
            recipe.PRECHECK_SECONDS), (300, 60, 190, 75))

    def test_recipe_pairing_and_entrypoint_admission_are_closed(self):
        for kwargs in ({"hosted_profile": receipt()}, {"hosted_provision": Path("/synthetic/provision.json")},
                {"hosted_profile": receipt(), "hosted_provision": Path("relative")}):
            with self.assertRaises(ValueError): recipe.build(*ARGS, expected_binary_sha256=IDENTITY, **kwargs)
        self.assertTrue(runner.admitted_image_entrypoint(profile.CLIENT_IMAGE, None, receipt()))
        self.assertFalse(runner.admitted_image_entrypoint(profile.CLIENT_IMAGE, ["/entrypoint.sh"], receipt()))
        self.assertFalse(runner.admitted_image_entrypoint("sha256:" + "0" * 64, None, receipt()))
        self.assertTrue(runner.admitted_image_entrypoint(recipe.basic.CLIENT_IMAGE, ["/entrypoint.sh"]))

    def test_metadata_real_method_has_fixed_flags_and_effective_limits(self):
        owner = provisioner.Provision(Path("/synthetic"), GITHUB, Path("/synthetic/tmp"))
        owner.discover = Mock(side_effect=[None, metadata_row(), metadata_row("exited")])
        owner.command = Mock(side_effect=[IDENTITY.encode(), json.dumps(CURL).encode()])
        self.assertEqual(owner.metadata(), CURL)
        create = owner.command.call_args_list[0].args
        self.assertEqual(create[0], "metadata-create")
        self.assertIn(profile.CLIENT_IMAGE, create[1])
        for flag, value in (("--network", "none"), ("--user", "65534:65534"), ("--pids-limit", "16"),
                ("--log-driver", "none"), ("--pull", "never"), ("--entrypoint", profile.PYTHON)):
            self.assertEqual(create[1][create[1].index(flag) + 1], value)
        self.assertFalse(any(key.startswith("GITHUB_") for key in owner.environment))

    def test_metadata_effective_drift_refuses_before_execution(self):
        for mutate in (lambda r: r["Config"].update(User="0:0"), lambda r: r["HostConfig"].update(PidsLimit=17),
                lambda r: r["HostConfig"].update(NetworkMode="host"), lambda r: r.update(Mounts=[{}])):
            owner = provisioner.Provision(Path("/synthetic"), GITHUB, Path("/synthetic/tmp"))
            row = metadata_row(); mutate(row)
            owner.discover = Mock(side_effect=[None, row]); owner.command = Mock(return_value=IDENTITY.encode())
            with self.assertRaises(ValueError): owner.metadata()
            self.assertEqual(owner.command.call_count, 1)

    def test_lost_create_absence_does_not_claim_cleanup(self):
        owner = provisioner.Provision(Path("/synthetic"), GITHUB, Path("/synthetic/tmp"))
        owner.armed = True; owner.discover = Mock(return_value=None)
        self.assertFalse(owner.cleanup())

    def test_unfinished_build_never_claims_cleanup_from_absent_metadata(self):
        owner = provisioner.Provision(Path("/synthetic"), GITHUB, Path("/synthetic/tmp"))
        owner.build_pending = True
        self.assertFalse(owner.cleanup())

    def test_cleanup_uses_exact_identity_and_requires_absence(self):
        owner = provisioner.Provision(Path("/synthetic"), GITHUB, Path("/synthetic/tmp"))
        owner.armed = True; owner.identity = IDENTITY
        owner.discover = Mock(side_effect=[metadata_row("exited"), None]); owner.command = Mock()
        self.assertTrue(owner.cleanup())
        owner.command.assert_called_once_with("metadata-remove", ["/usr/bin/docker", "rm", "--force", IDENTITY], 8)

    def test_discovery_rejects_unowned_image_label_or_identity(self):
        for mutate in (lambda r: r.update(Image="sha256:" + "0" * 64),
                lambda r: r["Config"].update(Labels={}), lambda r: r.update(Name="/other")):
            owner = provisioner.Provision(Path("/synthetic"), GITHUB, Path("/synthetic/tmp"))
            row = metadata_row(); mutate(row)
            owner.command = Mock(side_effect=[IDENTITY.encode(), json.dumps([row]).encode()])
            with self.assertRaises(ValueError): owner.discover()
            self.assertIsNone(owner.identity)

    def test_embedded_metadata_program_parses_without_execution(self):
        ast.parse(profile.CURL_PROBE)
        self.assertIn("signal.alarm(10)", profile.CURL_PROBE)
        self.assertIn("timeout=3", profile.CURL_PROBE)
        self.assertEqual((provisioner.WORK_SECONDS, provisioner.CLEANUP_SECONDS), (840, 20))


if __name__ == "__main__":
    unittest.main()

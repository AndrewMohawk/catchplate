"""Pure/mocked closed-profile controls; never prepare or launch a real runtime."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import prepare_operator_google_fixture as prepare


SOURCE = Path("/srv/catchplate-fast/projects/serverware-operator-workspace")
INITIALIZER = Path("/srv/catchplate-fast/projects/serverware-operator-audit-integration/scripts/private_operator_audit/initialize.py")
ROOT = prepare.base.SCRATCH / "serverware-google-private.mEXqYbMf"
ARTIFACTS = Path("/srv/catchplate-fast/projects/serverware-operator-artifacts")
OLD_BINARY = ARTIFACTS / ("sha256-" + prepare.BINARY_SHA256) / "serverware-decision-gate"
NEW_SHA = "a" * 64  # Synthetic digest input, never a release/artifact assertion.
NEW_BINARY = ARTIFACTS / ("sha256-" + NEW_SHA) / "serverware-decision-gate"
ENV_KEY = "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"


class GmailJobPreparationTests(unittest.TestCase):
    def build(self):
        return prepare.build(SOURCE, NEW_BINARY, INITIALIZER, ROOT,
            profile=prepare.GMAIL_JOB_PROFILE, expected_binary_sha256=NEW_SHA,
            client_dependencies=prepare.GMAIL_CLIENT_DEPENDENCIES,
            client_dependencies_manifest_sha256=prepare.GMAIL_CLIENT_MANIFEST_SHA256)

    def validate(self, config):
        prepare.validate(config, SOURCE, NEW_BINARY, INITIALIZER, ROOT,
            profile=prepare.GMAIL_JOB_PROFILE, expected_binary_sha256=NEW_SHA,
            client_dependencies=prepare.GMAIL_CLIENT_DEPENDENCIES,
            client_dependencies_manifest_sha256=prepare.GMAIL_CLIENT_MANIFEST_SHA256)

    def args(self, **updates):
        values = dict(source=SOURCE, binary=NEW_BINARY, initializer=INITIALIZER,
            job_root=ROOT, write=False, profile=prepare.GMAIL_JOB_PROFILE,
            expected_binary_sha256=NEW_SHA, client_dependencies=prepare.GMAIL_CLIENT_DEPENDENCIES,
            client_dependencies_manifest_sha256=prepare.GMAIL_CLIENT_MANIFEST_SHA256)
        values.update(updates)
        return SimpleNamespace(**values)

    def test_default_refresh_matches_retained_successful_compose_bytes(self):
        # Recorded composeSha256 from google-private-v2-prepared.TqW0crbQ;
        # inputs above are the exact successful legacy paths, not new runtime.
        config = prepare.build(SOURCE, OLD_BINARY, INITIALIZER, ROOT)
        encoded = (json.dumps(config, indent=2, sort_keys=True) + "\n").encode()
        self.assertEqual(hashlib.sha256(encoded).hexdigest(),
            "6c5da6e48412fdcf0ddef79ae4dd0e375b864e3da071717d4d122fd6b576ac69")
        self.assertEqual(config, prepare.build(SOURCE, OLD_BINARY, INITIALIZER, ROOT,
            profile=prepare.REFRESH_PROFILE, expected_binary_sha256=prepare.BINARY_SHA256))

    def test_new_profile_changes_only_fixed_commands_and_matching_pin(self):
        expected = prepare.build(SOURCE, NEW_BINARY, INITIALIZER, ROOT)
        services = expected["services"]
        services["serverware"]["environment"][ENV_KEY] = "sha256:" + NEW_SHA
        services["provider"]["command"] = ["python", "-B", "-m",
            "scripts.operator_gmail_job_fixture", "--lifetime-seconds", "300"]
        command = services["check"]["command"]
        command[2] = "scripts/check_operator_gmail_job.py"
        command[command.index("--expected-binary-sha256") + 1] = "sha256:" + NEW_SHA
        services["check"]["volumes"].append(prepare.base.bind(prepare.GMAIL_CLIENT_DEPENDENCIES, "/client-dependencies"))
        services["check"]["environment"]["PYTHONPATH"] = "/app:/client-dependencies/site-packages"
        actual = self.build()
        self.assertEqual(actual, expected)
        self.validate(actual)

    def test_new_profile_requires_bare_lowercase_digest_before_any_commands(self):
        for digest in (None, "", "a" * 63, "a" * 65, "A" * 64, "sha256:" + NEW_SHA,
                       "g" * 64, 123, NEW_SHA + "\n"):
            with self.subTest(digest=digest), patch.object(prepare.base, "command") as command, \
                    patch.object(prepare.base, "fresh_root") as fresh, \
                    patch.object(prepare.os, "open") as opened, self.assertRaises(ValueError):
                prepare.prepare(self.args(expected_binary_sha256=digest))
            command.assert_not_called()
            fresh.assert_not_called()
            opened.assert_not_called()

    def test_unknown_profiles_and_legacy_pin_override_refused(self):
        for profile, digest in (("arbitrary.module", NEW_SHA), ("", NEW_SHA), (None, NEW_SHA),
                                (prepare.REFRESH_PROFILE, NEW_SHA)):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                prepare.build(SOURCE, NEW_BINARY, INITIALIZER, ROOT,
                    profile=profile, expected_binary_sha256=digest)

    def test_cross_profile_commands_and_binary_pin_mutations_refused(self):
        original = self.build()
        replacements = (("provider", ["python", "-B", "-m", "scripts.operator_google_fixture"]),
            ("provider", ["python", "-B", "-m", "arbitrary.module"]),
            ("provider", ["python", "-B", "-m", "scripts.operator_gmail_job_fixture", "--lifetime-seconds", "360"]),
            ("check", ["python", "-B", "scripts/check_operator_google_refresh.py"]),
            ("network", ["python", "-B", "-m", "scripts.operator_google_fixture_setup", "network", "--lifetime-seconds", "360"]))
        for name, command in replacements:
            modified = deepcopy(original)
            modified["services"][name]["command"] = command
            with self.subTest(service=name, command=command), self.assertRaises(ValueError):
                self.validate(modified)
        for name in ("serverware", "check"):
            modified = deepcopy(original)
            if name == "serverware":
                modified["services"][name]["environment"][ENV_KEY] = "sha256:" + prepare.BINARY_SHA256
            else:
                command = modified["services"][name]["command"]
                command[command.index("--expected-binary-sha256") + 1] = "sha256:" + prepare.BINARY_SHA256
            with self.subTest(pin=name), self.assertRaises(ValueError):
                self.validate(modified)
        with self.assertRaises(ValueError):
            prepare.validate(original, SOURCE, NEW_BINARY, INITIALIZER, ROOT)

    def test_isolation_trust_and_source_mutations_refused(self):
        for name, key, value in (("network", "network_mode", "host"),
                ("provider", "ports", ["443:443"]), ("check", "cap_add", ["NET_ADMIN"]),
                ("serverware", "restart", "always"), ("check", "memswap_limit", "1g")):
            modified = self.build()
            modified["services"][name][key] = value
            with self.subTest(service=name, key=key), self.assertRaises(ValueError):
                self.validate(modified)
        for name in ("serverware", "provider", "check"):
            modified = self.build()
            modified["services"][name]["volumes"][0]["read_only"] = False
            with self.subTest(writable_source=name), self.assertRaises(ValueError):
                self.validate(modified)

    def test_actual_binary_mismatch_refuses_before_docker_or_writes(self):
        with patch.object(prepare.base, "fresh_root"), patch.object(Path, "resolve", lambda value: value), \
                patch.object(Path, "is_symlink", return_value=False), \
                patch.object(prepare.base, "digest", return_value="b" * 64), \
                patch.object(prepare.base, "command") as command, \
                patch.object(prepare.os, "open") as opened, self.assertRaises(ValueError):
            prepare.prepare(self.args())
        command.assert_not_called()
        opened.assert_not_called()

    def test_new_manifest_binds_budget_pin_and_source_inputs_without_writes(self):
        names = ["scripts/operator_gmail_job_fixture.py", "scripts/check_operator_gmail_job.py"]

        def command(argv):
            if argv[:3] == ["docker", "image", "inspect"]:
                return "sha256:" + "b" * 64
            if argv[:3] == ["docker", "ps", "-a"]:
                return ""
            if argv[0] == "findmnt":
                return '{"filesystems":[]}'
            if argv[:3] == ["git", "-C", str(SOURCE)] and argv[3] == "ls-files":
                return "\n".join(names)
            if argv == ["git", "-C", str(SOURCE), "rev-parse", "HEAD"]:
                return "c" * 40
            raise AssertionError("unreviewed command")

        def digest(path):
            return NEW_SHA if path == NEW_BINARY else prepare.base.INITIALIZER_SHA256 if path == INITIALIZER else "d" * 64

        with patch.object(prepare.base, "fresh_root"), patch.object(Path, "resolve", lambda value: value), \
                patch.object(Path, "is_symlink", return_value=False), patch.object(Path, "is_file", return_value=True), \
                patch.object(prepare.base, "digest", side_effect=digest), \
                patch.object(prepare.base, "command", side_effect=command), \
                patch.object(prepare, "verify_client_dependencies") as verified, \
                patch.object(prepare.os, "statvfs", return_value=SimpleNamespace(f_bavail=2**20, f_frsize=4096)), \
                patch.object(prepare.os, "open") as opened:
            result = prepare.prepare(self.args())
        opened.assert_not_called()
        verified.assert_called_once_with(prepare.GMAIL_CLIENT_DEPENDENCIES)
        manifest = result["preparation"]
        self.assertEqual(manifest["fixtureProfile"], "gmail-job")
        self.assertEqual(manifest["binarySha256"], NEW_SHA)
        self.assertEqual(manifest["clientDependencies"], {"root": str(prepare.GMAIL_CLIENT_DEPENDENCIES),
            "manifestSha256": prepare.GMAIL_CLIENT_MANIFEST_SHA256, "moduleSubdirectory": "site-packages",
            "mount": "/client-dependencies", "readOnly": True, "scope": "checker-only"})
        self.assertEqual(manifest["sourceSha256"], {name: "d" * 64 for name in names})
        self.assertEqual(manifest["budgets"], {"checkerTimeoutSeconds": 180,
            "checkerOuterBudgetSeconds": 210, "keeperLifetimeSeconds": 300,
            "providerLifetimeSeconds": 300, "keeperMarginSeconds": 15,
            "maximumPrecheckElapsedSeconds": 75})
        self.assertFalse(manifest["launched"])
        self.assertEqual(manifest["composeSha256"], hashlib.sha256(
            (json.dumps(result["compose"], indent=2, sort_keys=True) + "\n").encode()).hexdigest())

    def test_dependency_overlay_is_closed_and_refused_by_legacy(self):
        for profile, directory, digest in ((prepare.GMAIL_JOB_PROFILE, None, None),
                (prepare.GMAIL_JOB_PROFILE, Path("/tmp/arbitrary"), prepare.GMAIL_CLIENT_MANIFEST_SHA256),
                (prepare.GMAIL_JOB_PROFILE, prepare.GMAIL_CLIENT_DEPENDENCIES, "b" * 64),
                (prepare.REFRESH_PROFILE, prepare.GMAIL_CLIENT_DEPENDENCIES, prepare.GMAIL_CLIENT_MANIFEST_SHA256)):
            pin = NEW_SHA if profile == prepare.GMAIL_JOB_PROFILE else prepare.BINARY_SHA256
            with self.subTest(profile=profile, directory=directory), patch.object(prepare.base, "command") as command, \
                    patch.object(prepare.base, "fresh_root") as fresh, self.assertRaises(ValueError):
                prepare.prepare(self.args(profile=profile, expected_binary_sha256=pin,
                    client_dependencies=directory, client_dependencies_manifest_sha256=digest))
            command.assert_not_called()
            fresh.assert_not_called()

    def test_dependency_mount_is_readonly_checker_only_and_import_path_is_closed(self):
        original = self.build()
        mount = prepare.base.bind(prepare.GMAIL_CLIENT_DEPENDENCIES, "/client-dependencies")
        for name, service in original["services"].items():
            self.assertEqual(mount in service["volumes"], name == "check")
        for scenario in ("app_mount", "provider_mount", "gate_mount", "checker_writable", "alternate_import"):
            modified = deepcopy(original)
            if scenario == "checker_writable":
                modified["services"]["check"]["volumes"][-1]["read_only"] = False
            elif scenario == "alternate_import":
                modified["services"]["check"]["environment"]["PYTHONPATH"] += ":/tmp"
            else:
                name = {"app_mount": "serverware", "provider_mount": "provider", "gate_mount": "decision-gate-rs"}[scenario]
                modified["services"][name]["volumes"].append(mount)
            with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                self.validate(modified)

    def test_dependency_verification_failure_precedes_docker_and_writes(self):
        def digest(path):
            return NEW_SHA if path == NEW_BINARY else prepare.base.INITIALIZER_SHA256

        with patch.object(prepare.base, "fresh_root"), patch.object(Path, "resolve", lambda value: value), \
                patch.object(Path, "is_symlink", return_value=False), \
                patch.object(prepare.base, "digest", side_effect=digest), \
                patch.object(prepare, "verify_client_dependencies", side_effect=ValueError("payload differs")), \
                patch.object(prepare.base, "command") as command, patch.object(prepare.os, "open") as opened, \
                self.assertRaises(ValueError):
            prepare.prepare(self.args())
        command.assert_not_called()
        opened.assert_not_called()

    def test_closed_payload_inventory_and_hashes_reject_mutations(self):
        root = prepare.GMAIL_CLIENT_DEPENDENCIES
        paths = [root / ("payload-" + str(number) + ".py") for number in range(143)]
        manifest_path = root / "manifest.json"
        manifest = {"schema": "serverware.syntheticRequestsDependencies/v1", "moduleSubdirectory": "site-packages",
            "files": [{"path": path.name, "size": 1, "sha256": "a" * 64} for path in paths]}
        encoded = json.dumps(manifest)
        for scenario in ("valid", "missing", "extra", "hash", "symlink", "hardlink", "writable", "manifest"):
            observed = paths + [manifest_path]
            if scenario == "missing":
                observed = observed[1:]
            if scenario == "extra":
                observed = observed + [root / "unexpected.py"]

            def info(path):
                mode = 0o040555 if path == root else 0o100444
                links = 1
                if path == paths[0]:
                    mode = 0o120444 if scenario == "symlink" else 0o100644 if scenario == "writable" else mode
                    links = 2 if scenario == "hardlink" else 1
                return SimpleNamespace(st_mode=mode, st_nlink=links, st_size=len(encoded) if path == manifest_path else 1)

            def digest(path):
                if path == manifest_path:
                    return "b" * 64 if scenario == "manifest" else prepare.GMAIL_CLIENT_MANIFEST_SHA256
                return "b" * 64 if scenario == "hash" and path == paths[0] else "a" * 64

            with self.subTest(scenario=scenario), patch.object(Path, "resolve", lambda value: value), \
                    patch.object(Path, "lstat", info), patch.object(Path, "stat", info), \
                    patch.object(Path, "iterdir", lambda value: iter(observed)), \
                    patch.object(Path, "read_text", return_value=encoded), \
                    patch.object(prepare.base, "digest", side_effect=digest):
                if scenario == "valid":
                    prepare.verify_client_dependencies(root)
                else:
                    with self.assertRaises(ValueError):
                        prepare.verify_client_dependencies(root)


if __name__ == "__main__":
    unittest.main()

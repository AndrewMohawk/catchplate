#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shlex
import stat
import sys
import tempfile
from pathlib import Path

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))
import generate_production_launch_manifest as generator


ROOT = SCRIPT_DIRECTORY.parent
EXPECTED_INPUTS = {name for name, _argument in generator.INPUT_ARGUMENTS}
EXPECTED_OUTPUTS = {name for name, _argument in generator.OUTPUT_ARGUMENTS}


class Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.release = base / "release"
        self.state = base / "state"
        self.etc = base / "etc" / "serverware"
        self.release.mkdir()
        self.state.mkdir()
        self.etc.mkdir(parents=True)

        self.import_roots = [
            self.release,
            self.release / "runtime" / "stdlib",
            self.release / "vendor",
        ]
        for path in self.import_roots:
            path.mkdir(parents=True, exist_ok=True)

        self.files: dict[str, Path] = {}
        self.files["production_env"] = self.write(self.etc / "production-readiness.env", b"MODE=final\n")
        self.files["python"] = self.write(self.release / "runtime" / "bin" / "python3", b"python-fixture\n")
        self.files["preflight_script"] = self.write(
            self.release / "scripts" / "production_host_preflight.py", b"print('preflight')\n"
        )
        self.files["runner_script"] = self.write(
            self.release / "scripts" / "run_production_readiness.py", b"print('runner')\n"
        )
        self.files["compose_file"] = self.write(
            self.release / "docker-compose.production.yml", b"services: {}\n"
        )
        for index, (manifest_name, argument_name) in enumerate(generator.INPUT_ARGUMENTS):
            self.files[argument_name.replace("-", "_")] = self.write(
                self.release / "evidence" / f"{argument_name}.fixture", f"{index}:{manifest_name}\n".encode("ascii")
            )

        self.output_paths = {
            argument_name.replace("-", "_"): self.state / f"{argument_name}.json"
            for _manifest_name, argument_name in generator.OUTPUT_ARGUMENTS
        }

    @staticmethod
    def write(path: Path, content: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def argv(self, manifest_path: Path) -> list[str]:
        argv = [
            "--output",
            str(manifest_path),
            "--release-root",
            str(self.release),
            "--state-directory",
            str(self.state),
            "--source-tree-digest",
            "sha256:" + "01" * 32,
            "--production-env",
            str(self.files["production_env"]),
            "--python",
            str(self.files["python"]),
        ]
        for path in self.import_roots:
            argv.extend(("--python-import-root", str(path)))
        argv.extend(
            (
                "--preflight-script",
                str(self.files["preflight_script"]),
                "--runner-script",
                str(self.files["runner_script"]),
                "--compose-file",
                str(self.files["compose_file"]),
            )
        )
        for _manifest_name, argument_name in generator.INPUT_ARGUMENTS:
            argv.extend((f"--{argument_name}", str(self.files[argument_name.replace("-", "_")])))
        for _manifest_name, argument_name in generator.OUTPUT_ARGUMENTS:
            argv.extend((f"--{argument_name}", str(self.output_paths[argument_name.replace("-", "_")])))
        return argv


def replace_argument(argv: list[str], name: str, value: str) -> list[str]:
    changed = list(argv)
    index = changed.index(name)
    changed[index + 1] = value
    return changed


def parsed(argv: list[str]):
    return generator.build_parser().parse_args(argv)


def expect_manifest_error(argv: list[str], message: str) -> None:
    try:
        generator.generate(parsed(argv))
    except generator.ManifestError:
        return
    raise AssertionError(message)


def expect_main_error(argv: list[str], message: str) -> None:
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            generator.main(argv)
        except SystemExit as exc:
            if exc.code != 0:
                return
    raise AssertionError(message)


def test_generator() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary).resolve()
        fixture = Fixture(base)
        original_env_root = generator.PRODUCTION_ENV_ROOT
        generator.PRODUCTION_ENV_ROOT = fixture.etc
        try:
            first = base / "launch-one.json"
            second = base / "launch-two.json"
            first_unit = base / "serverware-one.service"
            second_unit = base / "serverware-two.service"
            launcher_path = "/opt/serverware/launchers/sha256-" + "ab" * 32 + "/serverware-production-launcher"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                if generator.main(
                    fixture.argv(first)
                    + [
                        "--systemd-unit-out",
                        str(first_unit),
                        "--launcher-path",
                        launcher_path,
                        "--print-sha256",
                    ]
                ) != 0:
                    raise AssertionError("generator returned a non-zero status")
            if generator.main(fixture.argv(second)) != 0:
                raise AssertionError("second generator invocation returned a non-zero status")
            if generator.main(
                fixture.argv(first)
                + ["--systemd-unit-out", str(second_unit), "--launcher-path", launcher_path]
            ) != 0:
                raise AssertionError("repeated concrete-unit generation returned a non-zero status")

            first_bytes = first.read_bytes()
            if first_bytes != second.read_bytes():
                raise AssertionError("identical inputs did not produce deterministic manifest bytes")
            expected_printed_digest = f"sha256:{hashlib.sha256(first_bytes).hexdigest()}"
            if stdout.getvalue().strip() != expected_printed_digest:
                raise AssertionError("--print-sha256 did not print the exact manifest-byte digest")
            if stat.S_IMODE(os.lstat(first).st_mode) != 0o400:
                raise AssertionError("manifest output mode is not 0400")
            if stat.S_IMODE(os.lstat(first_unit).st_mode) != 0o444:
                raise AssertionError("generated systemd unit mode is not 0444")
            if first_unit.read_bytes() != second_unit.read_bytes():
                raise AssertionError("identical launcher inputs did not produce deterministic systemd unit bytes")
            unit_text = first_unit.read_text(encoding="utf-8")
            if "<launcher-sha256>" in unit_text or "<manifest-sha256>" in unit_text:
                raise AssertionError("generated systemd unit contains an unresolved placeholder")
            expected_exec_start = (
                f"ExecStart={launcher_path} --manifest {first} "
                f"--manifest-sha256 {expected_printed_digest}"
            )
            if expected_exec_start not in unit_text:
                raise AssertionError("generated systemd unit does not bind the concrete launcher and manifest digest")
            if f"ConditionFileIsExecutable={launcher_path}" not in unit_text:
                raise AssertionError("generated systemd unit does not use the valid executable condition directive")
            if "ConditionPathIsExecutable=" in unit_text:
                raise AssertionError("generated systemd unit contains an invalid executable condition directive")
            if f"ConditionPathIsReadWrite={fixture.state}" not in unit_text:
                raise AssertionError("generated systemd unit does not bind the manifest state directory")
            if f"ReadWritePaths={fixture.state} /run/serverware /run/docker.sock" not in unit_text:
                raise AssertionError("generated systemd unit does not restrict writes to the selected state directory")
            if any(shell in unit_text for shell in ("/bin/sh", "/bin/bash", "/usr/bin/env", "ExecStartPre=")):
                raise AssertionError("generated systemd unit contains a shell or preparatory command")

            manifest = json.loads(first_bytes)
            if first_bytes != generator.canonical_json(manifest):
                raise AssertionError("manifest output is not canonical JSON")
            if set(manifest) != {
                "apiVersion",
                "kind",
                "releaseRoot",
                "stateDirectory",
                "sourceTreeDigest",
                "productionEnv",
                "python",
                "scripts",
                "composeFile",
                "inputs",
                "outputs",
            }:
                raise AssertionError(f"manifest has an open or incomplete top-level schema: {set(manifest)}")
            if manifest["apiVersion"] != generator.API_VERSION or manifest["kind"] != generator.KIND:
                raise AssertionError("manifest identity is incorrect")
            if set(manifest["inputs"]) != EXPECTED_INPUTS or set(manifest["outputs"]) != EXPECTED_OUTPUTS:
                raise AssertionError("manifest input/output maps are not closed")
            if set(manifest["scripts"]) != {"preflight", "runner"}:
                raise AssertionError("manifest script roles are not closed")
            if set(manifest["python"]) != {"path", "sha256", "importRoots"}:
                raise AssertionError("python record is not closed")
            import_roots = manifest["python"]["importRoots"]
            if [record.get("path") for record in import_roots] != [
                str(path) for path in fixture.import_roots
            ]:
                raise AssertionError("python import-root order was not preserved")
            if any(
                set(record) != {"path", "sha256"}
                or generator.DIGEST_RE.fullmatch(str(record.get("sha256", ""))) is None
                for record in import_roots
            ):
                raise AssertionError("python import roots are not closed tree-digest records")
            added_module = fixture.import_roots[0] / "added_module.py"
            added_module.write_bytes(b"VALUE = 1\n")
            changed_manifest, _ = generator.generate(parsed(fixture.argv(base / "changed.json")))
            if (
                changed_manifest["python"]["importRoots"][0]["sha256"]
                == import_roots[0]["sha256"]
            ):
                raise AssertionError("python import-root digest ignored added executable code")
            added_module.unlink()
            expected_python_digest = "sha256:" + hashlib.sha256(fixture.files["python"].read_bytes()).hexdigest()
            if manifest["python"]["sha256"] != expected_python_digest:
                raise AssertionError("python executable was not hashed correctly")
            if any(not Path(value).is_relative_to(fixture.state) for value in manifest["outputs"].values()):
                raise AssertionError("an output escaped the state directory")
            if "argv" in first_bytes.decode("utf-8") or "arguments" in first_bytes.decode("utf-8"):
                raise AssertionError("manifest exposes an arbitrary argument surface")

            symlink = fixture.release / "evidence" / "symlink.fixture"
            symlink.symlink_to(fixture.files["production_images_build"])
            expect_manifest_error(
                replace_argument(fixture.argv(base / "bad-symlink.json"), "--production-images-build", str(symlink)),
                "generator accepted a symlink input",
            )

            target = fixture.files["production_images_build"]
            traversal = str(target.parent / ".." / target.parent.name / target.name)
            expect_manifest_error(
                replace_argument(fixture.argv(base / "bad-traversal.json"), "--production-images-build", traversal),
                "generator accepted a non-normalized traversal path",
            )
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "bad-output.json"), "--config-out", str(base / "outside-state.json")
                ),
                "generator accepted an output outside the state directory",
            )
            symlink_output = fixture.state / "symlink-output.json"
            symlink_output.symlink_to(base / "outside-state.json")
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "bad-symlink-output.json"), "--config-out", str(symlink_output)
                ),
                "generator accepted a symlink output",
            )
            nested_output = fixture.state / "nested" / "config.json"
            nested_output.parent.mkdir()
            expect_manifest_error(
                replace_argument(fixture.argv(base / "bad-nested-output.json"), "--config-out", str(nested_output)),
                "generator accepted an unknown nested output path",
            )
            duplicate_output_argv = replace_argument(
                fixture.argv(base / "bad-duplicate-output.json"),
                "--claims-file",
                str(fixture.output_paths["config_out"]),
            )
            expect_manifest_error(duplicate_output_argv, "generator accepted duplicate output paths")
            expect_manifest_error(
                replace_argument(fixture.argv(base / "bad-directory.json"), "--bench", str(fixture.release / "evidence")),
                "generator accepted a non-file immutable input",
            )

            expect_main_error(
                fixture.argv(base / "missing-launcher.json") + ["--systemd-unit-out", str(base / "missing.service")],
                "generator accepted --systemd-unit-out without --launcher-path",
            )
            expect_main_error(
                fixture.argv(base / "relative-launcher.json")
                + ["--systemd-unit-out", str(base / "relative.service"), "--launcher-path", "relative/launcher"],
                "generator accepted a relative launcher path",
            )
            expect_main_error(
                fixture.argv(base / "whitespace-launcher.json")
                + [
                    "--systemd-unit-out",
                    str(base / "whitespace.service"),
                    "--launcher-path",
                    "/opt/serverware/launcher path",
                ],
                "generator accepted whitespace in the launcher path",
            )
            expect_main_error(
                fixture.argv(base / "control-launcher.json")
                + [
                    "--systemd-unit-out",
                    str(base / "control.service"),
                    "--launcher-path",
                    "/opt/serverware/launcher\npath",
                ],
                "generator accepted a control character in the launcher path",
            )
            expect_main_error(
                fixture.argv(base / "manifest with space.json"),
                "generator accepted whitespace in the manifest output path",
            )
            expect_main_error(
                fixture.argv(base / "unsafe-percent.json")
                + [
                    "--systemd-unit-out",
                    str(base / "unsafe-percent.service"),
                    "--launcher-path",
                    "/opt/serverware/launcher%p",
                ],
                "generator accepted a systemd specifier in the launcher path",
            )
            unit_symlink = base / "unit-symlink.service"
            unit_symlink.symlink_to(base / "outside.service")
            expect_main_error(
                fixture.argv(base / "unit-symlink-manifest.json")
                + ["--systemd-unit-out", str(unit_symlink), "--launcher-path", launcher_path],
                "generator replaced a symlink systemd-unit output",
            )

            with contextlib.redirect_stderr(io.StringIO()):
                try:
                    generator.build_parser().parse_args(fixture.argv(base / "bad-argv.json") + ["--arbitrary-argv", "x"])
                except SystemExit as exc:
                    if exc.code == 0:
                        raise AssertionError("unknown launcher argument exited successfully")
                else:
                    raise AssertionError("generator accepted an arbitrary launcher argument")
        finally:
            generator.PRODUCTION_ENV_ROOT = original_env_root


def assert_file_record(record: object, label: str) -> None:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise AssertionError(f"{label} is not a closed file record")
    if not isinstance(record["path"], str) or not record["path"].startswith("/"):
        raise AssertionError(f"{label} path is not absolute")
    if record["sha256"] != "sha256:<64-lowercase-hex>":
        raise AssertionError(f"{label} does not document its required SHA-256 pin")


def test_example() -> None:
    example = json.loads((ROOT / "ops" / "production-release-launch.json.example").read_text(encoding="utf-8"))
    expected_top_level = {
        "apiVersion",
        "kind",
        "releaseRoot",
        "stateDirectory",
        "sourceTreeDigest",
        "productionEnv",
        "python",
        "scripts",
        "composeFile",
        "inputs",
        "outputs",
    }
    if set(example) != expected_top_level:
        raise AssertionError(f"example top-level schema is not closed: {set(example)}")
    if example["apiVersion"] != generator.API_VERSION or example["kind"] != generator.KIND:
        raise AssertionError("example manifest identity is incorrect")
    release_root = "/opt/serverware/releases/<source-digest>"
    state_directory = "/var/lib/serverware/production-proof"
    if example["releaseRoot"] != release_root or example["stateDirectory"] != state_directory:
        raise AssertionError("example does not use the documented immutable release and mutable state roots")
    assert_file_record(example["productionEnv"], "productionEnv")
    if not example["productionEnv"]["path"].startswith("/etc/serverware/"):
        raise AssertionError("example production env is not under /etc/serverware")
    assert_file_record({key: example["python"][key] for key in ("path", "sha256")}, "python")
    if set(example["python"]) != {"path", "sha256", "importRoots"}:
        raise AssertionError("example python record is not closed")
    if not example["python"]["importRoots"]:
        raise AssertionError("example omits closed Python import roots")
    if any(
        set(value) != {"path", "sha256"}
        or (
            str(value["path"]) != release_root
            and not str(value["path"]).startswith(release_root + "/")
        )
        or not str(value["sha256"]).startswith("sha256:")
        for value in example["python"]["importRoots"]
    ):
        raise AssertionError("example Python import root escapes the immutable release")
    if set(example["scripts"]) != {"preflight", "runner"}:
        raise AssertionError("example script map is not closed")
    for name, record in example["scripts"].items():
        assert_file_record(record, f"scripts.{name}")
    assert_file_record(example["composeFile"], "composeFile")
    if set(example["inputs"]) != EXPECTED_INPUTS:
        raise AssertionError("example immutable input map is incomplete")
    for name, record in example["inputs"].items():
        assert_file_record(record, f"inputs.{name}")
        if not record["path"].startswith(release_root + "/"):
            raise AssertionError(f"example immutable input escapes releaseRoot: {name}")
    if set(example["outputs"]) != EXPECTED_OUTPUTS:
        raise AssertionError("example output map is incomplete")
    for name, value in example["outputs"].items():
        if Path(value).parent != Path(state_directory):
            raise AssertionError(f"example output is not a direct state-directory child: {name}")


def test_systemd_unit() -> None:
    unit = (ROOT / "ops" / "systemd" / "serverware-production-release-proof.service").read_text(encoding="utf-8")
    if unit != generator.SYSTEMD_UNIT_TEMPLATE:
        raise AssertionError("embedded concrete-unit template drifted from the checked-in audited systemd unit")
    active = [line.strip() for line in unit.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    directives: dict[str, list[str]] = {}
    for line in active:
        if line.startswith("["):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise AssertionError(f"invalid active systemd line: {line}")
        directives.setdefault(key, []).append(value)

    for forbidden in ("Environment", "EnvironmentFile", "PassEnvironment", "ExecStartPre", "WorkingDirectory"):
        if forbidden in directives:
            raise AssertionError(f"systemd unit includes forbidden ambient launcher directive: {forbidden}")
    if directives.get("Type") != ["oneshot"] or directives.get("User") != ["root"] or directives.get("Group") != ["root"]:
        raise AssertionError("systemd service is not a root oneshot")
    if directives.get("UMask") != ["0077"]:
        raise AssertionError("systemd service does not set UMask=0077")

    exec_start = directives.get("ExecStart", [])
    if len(exec_start) != 1:
        raise AssertionError("systemd service must have exactly one ExecStart")
    command = shlex.split(exec_start[0])
    if command[1:] != [
        "--manifest",
        "/etc/serverware/production-release-launch.json",
        "--manifest-sha256",
        "sha256:<manifest-sha256>",
    ]:
        raise AssertionError(f"launcher receives arguments outside the closed pair: {command}")
    if not re.fullmatch(
        r"/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher", command[0]
    ):
        raise AssertionError("ExecStart does not select a content-addressed native launcher")
    if any(shell in exec_start[0] for shell in ("/bin/sh", "/bin/bash", "/usr/bin/env", " -c ")):
        raise AssertionError("ExecStart uses a shell or environment trampoline")

    required_exact = {
        "NoNewPrivileges": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "PrivateDevices": "yes",
        "PrivateIPC": "yes",
        "RestrictSUIDSGID": "yes",
        "LockPersonality": "yes",
        "MemoryDenyWriteExecute": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelLogs": "yes",
        "ProtectControlGroups": "yes",
        "ProtectClock": "yes",
        "ProtectHostname": "yes",
        "RestrictNamespaces": "yes",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "DevicePolicy": "closed",
    }
    for key, expected in required_exact.items():
        if directives.get(key) != [expected]:
            raise AssertionError(f"systemd hardening mismatch for {key}: {directives.get(key)}")
    if directives.get("CapabilityBoundingSet") != [""] or directives.get("AmbientCapabilities") != [""]:
        raise AssertionError("systemd service does not drop all capabilities")
    if directives.get("DeviceAllow") != ["/dev/nsm rw"] or directives.get("BindReadOnlyPaths") != ["-/dev/nsm"]:
        raise AssertionError("systemd service does not document and constrain the NSM exception")
    if "AWS Nitro Secure Module" not in unit:
        raise AssertionError("systemd service does not explain its NSM device exception")
    expected_writes = {
        "/var/lib/serverware/production-proof",
        "/run/serverware",
        "/run/docker.sock",
    }
    write_paths = directives.get("ReadWritePaths", [])
    if len(write_paths) != 1 or set(shlex.split(write_paths[0])) != expected_writes:
        raise AssertionError(f"systemd service has an open or incomplete write set: {write_paths}")


def main() -> None:
    test_generator()
    test_example()
    test_systemd_unit()
    print("production launch asset tests passed")


if __name__ == "__main__":
    main()

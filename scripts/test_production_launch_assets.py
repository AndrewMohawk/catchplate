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
import struct
import sys
import tempfile
from pathlib import Path

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))
import generate_production_launch_manifest as generator


ROOT = SCRIPT_DIRECTORY.parent
EXPECTED_INPUTS = {name for name, _argument in generator.INPUT_ARGUMENTS}
EXPECTED_OUTPUTS = {name for name, _argument in generator.OUTPUT_ARGUMENTS}
EXPECTED_AUTHORIZATION = {
    "deploymentAudience",
    "deploymentIdentitySha256",
    "releaseSequence",
    "rollbackEpoch",
}
FORBIDDEN_AUTHORIZATION_KEYS = {
    "authorizationenvelope",
    "authorizationkey",
    "authorizationkeypath",
    "authorizationpublickey",
    "authorizationresponse",
    "authorizationsignature",
    "authorizationsocket",
    "authorizationsocketpath",
    "authoritykey",
    "authoritykeypath",
    "authoritypublickey",
    "authoritysocket",
    "authoritysocketpath",
    "launchauthoritykey",
    "launchauthoritypublickey",
    "launchauthoritysocket",
    "launchauthorization",
    "launchauthorizationresponse",
}
FORBIDDEN_UNIT_AUTHORIZATION_PATTERNS = (
    re.compile(r"--(?:launch-)?authority-(?:key|public-key|socket)(?:=|\s|$)", re.IGNORECASE),
    re.compile(r"--authorization-(?:response|signature|key|public-key|socket)(?:=|\s|$)", re.IGNORECASE),
    re.compile(
        r"(?:launch[-_.]?authority|authorization)[-_.]?(?:response|signature|key|public[-_.]?key|socket)",
        re.IGNORECASE,
    ),
    re.compile(r"\bauthority[-_.]?(?:key|public[-_.]?key|socket)\b", re.IGNORECASE),
    re.compile(r"\b(?:SERVERWARE_)?(?:LAUNCH_)?AUTHORITY_(?:KEY|PUBLIC_KEY|SOCKET)\b"),
    re.compile(r"/run/serverware/launch-authority\.sock"),
    re.compile(r"serverware\.launchAuthorization/"),
)


def minimal_cpython_elf(
    *,
    machine: int = generator.ELF_MACHINE_X86_64,
    symbol: bytes = b"Py_BytesMain",
    needed: bytes = b"libpython3.11.so.1.0",
) -> bytes:
    dynamic_strings = b"\0" + symbol + b"\0" + needed + b"\0"
    symbol_offset = 1
    needed_offset = 1 + len(symbol) + 1
    dynamic_symbols = b"\0" * generator.ELF64_SYMBOL_SIZE + struct.pack(
        "<IBBHQQ", symbol_offset, 0, 0, 0, 0, 0
    )
    dynamic_entries = struct.pack("<qQqQ", generator.ELF_DYNAMIC_NEEDED, needed_offset, 0, 0)
    program_offset = generator.ELF64_HEADER_SIZE
    data_offset = program_offset + generator.ELF64_PROGRAM_HEADER_SIZE
    string_offset = data_offset
    symbol_table_offset = string_offset + len(dynamic_strings)
    dynamic_offset = symbol_table_offset + len(dynamic_symbols)
    section_offset = dynamic_offset + len(dynamic_entries)
    section_count = 4
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\0" * 9,
        3,
        machine,
        1,
        0,
        program_offset,
        section_offset,
        0,
        generator.ELF64_HEADER_SIZE,
        generator.ELF64_PROGRAM_HEADER_SIZE,
        1,
        generator.ELF64_SECTION_HEADER_SIZE,
        section_count,
        0,
    )
    program_header = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, section_offset, section_offset, 4096)

    def section(
        section_type: int,
        offset: int,
        size: int,
        *,
        link: int = 0,
        entry_size: int = 0,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            0,
            section_type,
            0,
            0,
            offset,
            size,
            link,
            0,
            1,
            entry_size,
        )

    sections = b"".join(
        (
            section(0, 0, 0),
            section(generator.ELF_SECTION_STRTAB, string_offset, len(dynamic_strings)),
            section(
                generator.ELF_SECTION_DYNSYM,
                symbol_table_offset,
                len(dynamic_symbols),
                link=1,
                entry_size=generator.ELF64_SYMBOL_SIZE,
            ),
            section(
                generator.ELF_SECTION_DYNAMIC,
                dynamic_offset,
                len(dynamic_entries),
                link=1,
                entry_size=generator.ELF64_DYNAMIC_SIZE,
            ),
        )
    )
    return header + program_header + dynamic_strings + dynamic_symbols + dynamic_entries + sections


class Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.release = base / "release"
        self.state = base / "state"
        self.etc = base / "etc" / "serverware"
        self.release.mkdir()
        self.state.mkdir()
        self.etc.mkdir(parents=True)

        self.stdlib = self.release / "runtime" / "python" / "lib" / "python3.11"
        self.lib_dynload = self.stdlib / "lib-dynload"
        self.vendor = self.release / "vendor"
        self.import_roots = [self.release, self.stdlib, self.lib_dynload, self.vendor]
        for path in self.import_roots:
            path.mkdir(parents=True, exist_ok=True)

        self.files: dict[str, Path] = {}
        self.files["production_env"] = self.write(self.etc / "production-readiness.env", b"MODE=final\n")
        self.files["python"] = self.write(
            self.release / "runtime" / "python" / "bin" / "python3",
            minimal_cpython_elf(),
        )
        self.files["python"].chmod(0o755)
        self.files["extension_module"] = self.write(
            self.lib_dynload / "_ssl.cpython-311-x86_64-linux-gnu.so",
            b"extension-module-fixture\n",
        )
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
            "--deployment-audience",
            "production.us-east-1:primary",
            "--deployment-identity-sha256",
            "sha256:" + "23" * 32,
            "--release-sequence",
            "42",
            "--rollback-epoch",
            "0",
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


def remove_argument(argv: list[str], name: str) -> list[str]:
    changed = list(argv)
    index = changed.index(name)
    del changed[index : index + 2]
    return changed


def remove_argument_value(argv: list[str], name: str, value: str) -> list[str]:
    changed = list(argv)
    for index in range(len(changed) - 1):
        if changed[index] == name and changed[index + 1] == value:
            del changed[index : index + 2]
            return changed
    raise AssertionError(f"argument pair not found: {name} {value}")


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


def assert_closed_authorization(record: object, label: str, *, example: bool = False) -> None:
    if not isinstance(record, dict) or set(record) != EXPECTED_AUTHORIZATION:
        raise AssertionError(f"{label} is not a closed authorization configuration")
    audience = record["deploymentAudience"]
    if not isinstance(audience, str) or generator.DEPLOYMENT_AUDIENCE_RE.fullmatch(audience) is None:
        raise AssertionError(f"{label}.deploymentAudience is invalid")
    identity = record["deploymentIdentitySha256"]
    if not isinstance(identity, str) or (
        generator.DIGEST_RE.fullmatch(identity) is None
        and not (example and identity == "sha256:<64-lowercase-hex>")
    ):
        raise AssertionError(f"{label}.deploymentIdentitySha256 is invalid")
    release_sequence = record["releaseSequence"]
    rollback_epoch = record["rollbackEpoch"]
    if (
        isinstance(release_sequence, bool)
        or not isinstance(release_sequence, int)
        or not 1 <= release_sequence <= generator.JSON_SAFE_INTEGER_MAX
    ):
        raise AssertionError(f"{label}.releaseSequence is not a positive JSON-safe integer")
    if (
        isinstance(rollback_epoch, bool)
        or not isinstance(rollback_epoch, int)
        or not 0 <= rollback_epoch <= generator.JSON_SAFE_INTEGER_MAX
    ):
        raise AssertionError(f"{label}.rollbackEpoch is not a nonnegative JSON-safe integer")


def assert_no_authorization_material(value: object, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in FORBIDDEN_AUTHORIZATION_KEYS:
                raise AssertionError(f"{label} embeds forbidden authorization material at {key}")
            assert_no_authorization_material(child, label)
    elif isinstance(value, list):
        for child in value:
            assert_no_authorization_material(child, label)
    elif isinstance(value, str) and value == "/run/serverware/launch-authority.sock":
        raise AssertionError(f"{label} configures the launcher-compiled authority socket")


def assert_no_unit_authorization_overrides(unit: str, label: str) -> None:
    for pattern in FORBIDDEN_UNIT_AUTHORIZATION_PATTERNS:
        if pattern.search(unit):
            raise AssertionError(f"{label} embeds or configures launch authorization material: {pattern.pattern}")


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
            expected_exec_start = f"ExecStart={launcher_path} --manifest {first}"
            generated_exec = [line for line in unit_text.splitlines() if line.startswith("Exec")]
            if generated_exec != [expected_exec_start]:
                raise AssertionError(f"generated systemd unit has an open launcher command: {generated_exec}")
            if "--manifest-sha256" in unit_text:
                raise AssertionError("generated systemd unit bypasses launcher measurement of the manifest bytes")
            assert_no_unit_authorization_overrides(unit_text, "generated systemd unit")
            for dependency in ("After", "Wants", "Requires"):
                line = next((line for line in unit_text.splitlines() if line.startswith(f"{dependency}=")), "")
                if "serverware-launch-authority-relay.socket" not in line:
                    raise AssertionError(f"generated systemd unit omits the authority relay {dependency} dependency")
            if f"ConditionFileIsExecutable={launcher_path}" not in unit_text:
                raise AssertionError("generated systemd unit does not use the valid executable condition directive")
            if "ConditionPathIsExecutable=" in unit_text:
                raise AssertionError("generated systemd unit contains an invalid executable condition directive")
            if f"ConditionPathIsReadWrite={fixture.state}" not in unit_text:
                raise AssertionError("generated systemd unit does not bind the manifest state directory")
            if f"ReadWritePaths={fixture.state} /run/docker.sock" not in unit_text:
                raise AssertionError("generated systemd unit does not restrict writes to the selected state directory")
            if "ReadOnlyPaths=/run/serverware" not in unit_text:
                raise AssertionError("generated systemd unit does not mount the relay directory read-only")
            if "RuntimeDirectory=" in unit_text:
                raise AssertionError("generated proof unit claims relay runtime-directory lifecycle")
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
                "authorization",
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
            assert_closed_authorization(manifest["authorization"], "manifest.authorization")
            assert_no_authorization_material(manifest, "manifest")
            if manifest["authorization"] != {
                "deploymentAudience": "production.us-east-1:primary",
                "deploymentIdentitySha256": "sha256:" + "23" * 32,
                "releaseSequence": 42,
                "rollbackEpoch": 0,
            }:
                raise AssertionError("manifest authorization fields do not match the required CLI inputs")
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
            extension_module = fixture.files["extension_module"]
            original_extension_bytes = extension_module.read_bytes()
            extension_module.write_bytes(original_extension_bytes + b"changed\n")
            extension_manifest, _ = generator.generate(
                parsed(fixture.argv(base / "changed-extension.json"))
            )
            if (
                extension_manifest["python"]["importRoots"][2]["sha256"]
                == import_roots[2]["sha256"]
            ):
                raise AssertionError(
                    "python lib-dynload digest ignored changed extension-module bytes"
                )
            extension_module.write_bytes(original_extension_bytes)
            expected_python_digest = "sha256:" + hashlib.sha256(fixture.files["python"].read_bytes()).hexdigest()
            if manifest["python"]["sha256"] != expected_python_digest:
                raise AssertionError("python executable was not hashed correctly")

            valid_python = fixture.files["python"].read_bytes()
            invalid_python_cases = (
                ("shebang", b"#!/usr/bin/python3\n"),
                ("non-ELF", b"arbitrary executable bytes\n"),
                (
                    "wrong architecture",
                    minimal_cpython_elf(machine=183),
                ),
                (
                    "generic ELF executable",
                    minimal_cpython_elf(symbol=b"main", needed=b"libc.so.6"),
                ),
                (
                    "CPython symbol without compatible libpython",
                    minimal_cpython_elf(needed=b"libpython3.12.so.1.0"),
                ),
            )
            for label, invalid_python in invalid_python_cases:
                fixture.files["python"].write_bytes(invalid_python)
                expect_manifest_error(
                    fixture.argv(base / f"bad-python-{label.replace(' ', '-')}.json"),
                    f"generator accepted {label} as production Python",
                )
            fixture.files["python"].write_bytes(valid_python)
            fixture.files["python"].chmod(0o644)
            expect_manifest_error(
                fixture.argv(base / "non-executable-python.json"),
                "generator accepted a non-executable production Python",
            )
            fixture.files["python"].chmod(0o755)
            if any(not Path(value).is_relative_to(fixture.state) for value in manifest["outputs"].values()):
                raise AssertionError("an output escaped the state directory")
            if "argv" in first_bytes.decode("utf-8") or "arguments" in first_bytes.decode("utf-8"):
                raise AssertionError("manifest exposes an arbitrary argument surface")

            boundary_argv = replace_argument(
                fixture.argv(base / "boundary.json"),
                "--release-sequence",
                str(generator.JSON_SAFE_INTEGER_MAX),
            )
            boundary_argv = replace_argument(
                boundary_argv,
                "--rollback-epoch",
                str(generator.JSON_SAFE_INTEGER_MAX),
            )
            boundary_manifest, _ = generator.generate(parsed(boundary_argv))
            if boundary_manifest["authorization"]["releaseSequence"] != generator.JSON_SAFE_INTEGER_MAX:
                raise AssertionError("generator rejected or changed the maximum JSON-safe release sequence")
            if boundary_manifest["authorization"]["rollbackEpoch"] != generator.JSON_SAFE_INTEGER_MAX:
                raise AssertionError("generator rejected or changed the maximum JSON-safe rollback epoch")

            for value in ("", ".production", "Production", "production/east", "production-\N{LATIN SMALL LETTER E WITH ACUTE}", "a" * 129):
                expect_manifest_error(
                    replace_argument(fixture.argv(base / "bad-audience.json"), "--deployment-audience", value),
                    f"generator accepted invalid deployment audience {value!r}",
                )
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "bad-identity.json"),
                    "--deployment-identity-sha256",
                    "sha256:" + "AB" * 32,
                ),
                "generator accepted an invalid deployment identity digest",
            )
            for value in ("0", "-1", "01", "1.0", str(generator.JSON_SAFE_INTEGER_MAX + 1)):
                expect_manifest_error(
                    replace_argument(fixture.argv(base / "bad-release-sequence.json"), "--release-sequence", value),
                    f"generator accepted invalid release sequence {value!r}",
                )
            for value in ("-1", "00", "1.0", str(generator.JSON_SAFE_INTEGER_MAX + 1)):
                expect_manifest_error(
                    replace_argument(fixture.argv(base / "bad-rollback-epoch.json"), "--rollback-epoch", value),
                    f"generator accepted invalid rollback epoch {value!r}",
                )

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

            for required_argument in (
                "--deployment-audience",
                "--deployment-identity-sha256",
                "--release-sequence",
                "--rollback-epoch",
            ):
                expect_main_error(
                    remove_argument(fixture.argv(base / "missing-authorization-field.json"), required_argument),
                    f"generator accepted missing required argument {required_argument}",
                )

            without_release_root = remove_argument(
                fixture.argv(base / "missing-release-root-import.json"),
                "--python-import-root",
            )
            expect_manifest_error(
                without_release_root,
                "generator accepted an import closure that omitted the complete release root",
            )

            without_lib_dynload = remove_argument_value(
                fixture.argv(base / "missing-lib-dynload.json"),
                "--python-import-root",
                str(fixture.lib_dynload),
            )
            expect_manifest_error(
                without_lib_dynload,
                "generator accepted an import closure that omitted lib-dynload",
            )
            without_vendor = remove_argument_value(
                fixture.argv(base / "missing-vendor.json"),
                "--python-import-root",
                str(fixture.vendor),
            )
            expect_manifest_error(
                without_vendor,
                "generator accepted an import closure that omitted vendor",
            )

            reordered = fixture.argv(base / "reordered-import-roots.json")
            stdlib_index = reordered.index(str(fixture.stdlib))
            dynload_index = reordered.index(str(fixture.lib_dynload))
            reordered[stdlib_index], reordered[dynload_index] = (
                reordered[dynload_index],
                reordered[stdlib_index],
            )
            expect_manifest_error(
                reordered,
                "generator accepted Python import roots in a different sys.path order",
            )

            if generator.PYTHON_STDLIB_DIRECTORY_RE.fullmatch("python3.011") is not None:
                raise AssertionError("generator accepted a non-canonical CPython stdlib version")

            extra_root = fixture.release / "extra-python-root"
            extra_root.mkdir()
            expect_manifest_error(
                fixture.argv(base / "extra-import-root.json")
                + ["--python-import-root", str(extra_root)],
                "generator accepted an extra Python import root",
            )

            extension_module.unlink()
            expect_manifest_error(
                fixture.argv(base / "empty-lib-dynload.json"),
                "generator accepted lib-dynload without extension modules",
            )
            extension_module.write_bytes(original_extension_bytes)

            alternate_python = fixture.write(
                fixture.release / "runtime" / "python" / "bin" / "python3.11",
                minimal_cpython_elf(),
            )
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "alternate-python.json"),
                    "--python",
                    str(alternate_python),
                ),
                "generator accepted a Python executable outside the fixed runtime path",
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
                fixture.argv(base / "python-launcher.json")
                + [
                    "--systemd-unit-out",
                    str(base / "python.service"),
                    "--launcher-path",
                    "/usr/bin/python3",
                ],
                "generator allowed systemd to invoke Python directly",
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
            for forbidden_argument in (
                "--authorization-response",
                "--authorization-signature",
                "--authorization-key",
                "--authority-socket",
                "--launch-authority-public-key",
            ):
                expect_main_error(
                    fixture.argv(base / "forbidden-authorization-argument.json")
                    + [forbidden_argument, "forbidden"],
                    f"generator accepted forbidden authorization override {forbidden_argument}",
                )
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
        "authorization",
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
    assert_closed_authorization(example["authorization"], "example.authorization", example=True)
    assert_no_authorization_material(example, "example manifest")
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
    expected_import_root_paths = [
        release_root,
        release_root + "/runtime/python/lib/python3.11",
        release_root + "/runtime/python/lib/python3.11/lib-dynload",
        release_root + "/vendor",
    ]
    if [value.get("path") for value in example["python"]["importRoots"]] != expected_import_root_paths:
        raise AssertionError("example Python import roots do not match the closed sys.path order")
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


def test_make_python_runtime_contract() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    variable = (
        "PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD ?= "
        "$(PRODUCTION_RELEASE_PYTHON_STDLIB)/lib-dynload"
    )
    if variable not in makefile:
        raise AssertionError("Makefile does not define the exact production lib-dynload root")
    if (
        "PRODUCTION_RELEASE_PYTHON_STDLIB ?= "
        "$(PRODUCTION_RELEASE_ROOT)/runtime/python/lib/python3.11"
    ) not in makefile:
        raise AssertionError("Makefile production Python default is not aligned to 3.11")
    expected_order = [
        '--python-import-root "$(PRODUCTION_RELEASE_ROOT)"',
        '--python-import-root "$(PRODUCTION_RELEASE_PYTHON_STDLIB)"',
        '--python-import-root "$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)"',
        '--python-import-root "$(PRODUCTION_RELEASE_PYTHON_VENDOR)"',
    ]
    positions = [makefile.find(value) for value in expected_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AssertionError("Makefile does not preserve the closed production sys.path order")
    if 'test -d "$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)"' not in makefile:
        raise AssertionError("Makefile does not fail closed when production lib-dynload is missing")
    for required in (
        "build-production-python-runtime:",
        "--target production-python-runtime-artifact",
        "SERVERWARE_PRODUCTION_PYTHON_RUNTIME_ARTIFACT=",
    ):
        if required not in makefile:
            raise AssertionError(f"Makefile omits production Python artifact wiring: {required}")


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

    for forbidden in (
        "Environment",
        "EnvironmentFile",
        "PassEnvironment",
        "LoadCredential",
        "LoadCredentialEncrypted",
        "SetCredential",
        "SetCredentialEncrypted",
        "ImportCredential",
        "ExecStartPre",
        "WorkingDirectory",
    ):
        if forbidden in directives:
            raise AssertionError(f"systemd unit includes forbidden ambient launcher directive: {forbidden}")
    unexpected_exec = sorted(key for key in directives if key.startswith("Exec") and key != "ExecStart")
    if unexpected_exec:
        raise AssertionError(f"systemd unit includes additional executable directives: {unexpected_exec}")
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
    ]:
        raise AssertionError(f"launcher receives arguments outside the closed manifest path: {command}")
    if not re.fullmatch(
        r"/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher", command[0]
    ):
        raise AssertionError("ExecStart does not select a content-addressed native launcher")
    if any(shell in exec_start[0] for shell in ("/bin/sh", "/bin/bash", "/usr/bin/env", " -c ")):
        raise AssertionError("ExecStart uses a shell or environment trampoline")
    if "python" in Path(command[0]).name.lower() or any(".py" in argument.lower() for argument in command[1:]):
        raise AssertionError("systemd unit invokes Python directly instead of the native launcher")
    assert_no_unit_authorization_overrides(unit, "checked-in systemd unit")

    expected_dependencies = {
        "After": {"network-online.target", "docker.service", "serverware-launch-authority-relay.socket"},
        "Wants": {"network-online.target", "serverware-launch-authority-relay.socket"},
        "Requires": {"docker.service", "serverware-launch-authority-relay.socket"},
    }
    for directive, expected in expected_dependencies.items():
        values = directives.get(directive, [])
        if len(values) != 1 or set(shlex.split(values[0])) != expected:
            raise AssertionError(f"systemd dependency mismatch for {directive}: {values}")

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
        "/run/docker.sock",
    }
    write_paths = directives.get("ReadWritePaths", [])
    if len(write_paths) != 1 or set(shlex.split(write_paths[0])) != expected_writes:
        raise AssertionError(f"systemd service has an open or incomplete write set: {write_paths}")
    if directives.get("ReadOnlyPaths") != ["/run/serverware"]:
        raise AssertionError("proof service does not keep the relay socket directory read-only")
    if "RuntimeDirectory" in directives or "RuntimeDirectoryMode" in directives:
        raise AssertionError("proof service must not own or remove the relay runtime directory")

    relay_socket_unit = (
        ROOT / "ops/systemd/serverware-launch-authority-relay.socket"
    ).read_text(encoding="utf-8")
    for required in (
        "ListenSequentialPacket=/run/serverware/launch-authority.sock",
        "SocketUser=root",
        "SocketGroup=root",
        "SocketMode=0600",
        "DirectoryMode=0711",
        "RemoveOnStop=yes",
    ):
        if required not in relay_socket_unit:
            raise AssertionError(
                f"relay socket unit does not exclusively own runtime lifecycle: {required}"
            )


def main() -> None:
    test_generator()
    test_example()
    test_make_python_runtime_contract()
    test_systemd_unit()
    print("production launch asset tests passed")


if __name__ == "__main__":
    main()

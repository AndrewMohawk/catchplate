#!/usr/bin/env python3
"""Pure local/native contract controls; no installed package or live launch claim."""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jsonschema import Draft202012Validator, ValidationError
from catchplate import authority_artifact_spec as artifact
from catchplate import authority_stage_zero_contract as stage


def fixture():
    # Explicit synthetic schema data, not observations or signed receipts.
    interpreter = {"path": "python/bin/python3", "runtimePath": "/runtime/python/bin/python3",
                   "sha256": "sha256:" + "1" * 64, "size": 4096}
    native = {key: interpreter[key] for key in ("path", "runtimePath", "sha256")}
    native.update(elfClass="ELF64", machine=62, ptInterp="/runtime/lib/ld-linux.so.2",
                  needed=["/runtime/lib/libc.so.6"])
    source = {"path": "catchplate/authority_launcher.py", "runtimePath": "/runtime/authority_launcher.py",
              "sha256": "sha256:" + "2" * 64, "size": 8192,
              "interfaceSchema": stage.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA, "interpreter": interpreter}
    return source, [native]


class CPythonSysconfigImportTests(unittest.TestCase):
    @staticmethod
    def entry():
        return dict(module="_sysconfigdata__linux_x86_64-linux-gnu",
                    path="python/lib/python3.11/_sysconfigdata__linux_x86_64-linux-gnu.py",
                    kind="source", isPackage=False, sha256="sha256:" + "1" * 64)

    def test_exact_selected_cpython_build_data_is_a_source_import(self):
        entry = self.entry()
        self.assertEqual(artifact.CPYTHON_SYSCONFIG_DATA_MODULE, entry["module"])
        self.assertEqual(artifact.CPYTHON_SYSCONFIG_DATA_PATH, entry["path"])
        artifact._validate_python_import(entry)

    def test_sysconfig_exception_refuses_other_names_paths_kinds_and_packages(self):
        changes = (
            {"module": "arbitrary-hyphen"},
            {"module": "_sysconfigdata__linux_aarch64-linux-gnu"},
            {"module": "_sysconfigdata__linux_x86_64-linux-gnu.extra"},
            {"module": "package._sysconfigdata__linux_x86_64-linux-gnu"},
            {"path": "source/_sysconfigdata__linux_x86_64-linux-gnu.py"},
            {"path": "python/lib/python3.12/_sysconfigdata__linux_x86_64-linux-gnu.py"},
            {"path": "python/lib/python3.11/site-packages/_sysconfigdata__linux_x86_64-linux-gnu.py"},
            {"path": "python/lib/python3.11/_sysconfigdata__linux_x86_64-linux-gnu/__init__.py"},
            {"path": "python/lib/python3.11/../_sysconfigdata__linux_x86_64-linux-gnu.py"},
            {"kind": "bytecode"}, {"kind": "extension"}, {"kind": "data"},
            {"isPackage": True}, {"isPackage": 0}, {"isPackage": None},
            {"sha256": "not-a-digest"},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(artifact.ArtifactContractError):
                artifact._validate_python_import(dict(self.entry(), **change))

    def test_ordinary_module_identifier_validation_is_unchanged(self):
        for module in ("sysconfig", "zoneinfo._tzpath", "_ordinary_build_data"):
            with self.subTest(module=module):
                artifact._validate_python_import(dict(self.entry(), module=module,
                                                     path="source/ordinary.py"))
        for module in ("", "0module", "package..module", "ordinary-module", "module.\N{SNOWMAN}"):
            with self.subTest(module=module), self.assertRaises(artifact.ArtifactContractError):
                artifact._validate_python_import(dict(self.entry(), module=module))


class TrustedHostLocalContractTests(unittest.TestCase):
    def test_request_role_manifest_path_call_preserves_path_validation(self):
        tree = ast.parse(Path(stage.__file__).read_text())
        validator = next(node for node in tree.body
                         if isinstance(node, ast.FunctionDef) and node.name == "validate_stage_zero_request")
        calls = [node for node in ast.walk(validator)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "_runtime_path"
                 and any(isinstance(value, ast.Subscript) and isinstance(value.value, ast.Name)
                         and value.value.id == "role" and isinstance(value.slice, ast.Constant)
                         and value.slice.value == "path" for value in ast.walk(node))]
        self.assertEqual(len(calls), 1)
        expression = compile(ast.Expression(calls[0]), str(stage.__file__), "eval")

        def validate(path):
            return eval(expression, {"_runtime_path": stage._runtime_path, "_ascii": stage._ascii,
                                     "role": {"path": path}})

        # Execute the shared request validator's real call, not a replacement
        # expression. This catches a missing required keyword before launch.
        for path in ("roles/issuer.json", "roles/policy-finalizer.json"):
            with self.subTest(path=path):
                self.assertEqual(validate(path), "/" + path)
        for path in ("", None, True, "../roles/issuer.json", "roles/../issuer.json",
                     "roles/./issuer.json", "roles//issuer.json", "roles/issuer.json/",
                     "roles/\N{SNOWMAN}.json", "roles/" + "x" * 4096):
            with self.subTest(path=path), self.assertRaises(stage.StageZeroContractError):
                validate(path)

    def test_local_reference_binds_dynamic_interpreter_without_static_claim(self):
        source, native = fixture()
        self.assertTrue(artifact.validate_stage_zero_reference(source,
            native_executables=native, trust_mode="trusted-host-local"))
        Draft202012Validator(artifact.LOCAL_STAGE_ZERO_REFERENCE_JSON_SCHEMA).validate(source)
        self.assertNotIn("staticElf", source)
        self.assertNotIn("elfEvidenceDigest", source)

    def test_local_reference_cannot_select_production_assurance(self):
        source, native = fixture()
        for mode in ("external-production", "tee-hardware", "unknown"):
            with self.subTest(mode=mode), self.assertRaises(artifact.ArtifactContractError):
                artifact.validate_stage_zero_reference(source, native_executables=native, trust_mode=mode)

    def test_interpreter_must_be_unique_exact_native_closure_entry(self):
        source, native = fixture()
        for field, value in (("path", "other/python"), ("runtimePath", "/other/python"),
                             ("sha256", "sha256:" + "3" * 64)):
            changed = copy.deepcopy(source)
            changed["interpreter"][field] = value
            with self.subTest(field=field), self.assertRaises(artifact.ArtifactContractError):
                artifact.validate_stage_zero_reference(changed, native_executables=native)
        for entries in ([], native + copy.deepcopy(native)):
            with self.assertRaises(artifact.ArtifactContractError):
                artifact.validate_stage_zero_reference(source, native_executables=entries)

    def test_local_reference_rejects_native_fields_and_source_aliases(self):
        source, native = fixture()
        for change in (
            lambda value: value.update(staticElf=True),
            lambda value: value.pop("interpreter"),
            lambda value: value["interpreter"].update(path=value["path"]),
            lambda value: value["interpreter"].update(runtimePath=value["runtimePath"]),
            lambda value: value["interpreter"].update(size=True),
        ):
            changed = copy.deepcopy(source)
            change(changed)
            with self.assertRaises(artifact.ArtifactContractError):
                artifact.validate_stage_zero_reference(changed, native_executables=native)

    def test_native_static_elf_requirements_remain_closed(self):
        source, _ = fixture()
        source.pop("interpreter")
        source.update(interfaceSchema=stage.STAGE_ZERO_INTERFACE_SCHEMA, staticElf=True,
                      ptInterp=None, needed=[], elfEvidenceDigest="sha256:" + "4" * 64)
        self.assertFalse(artifact.validate_stage_zero_reference(source, native_executables=[]))
        for changes in ({"staticElf": False}, {"ptInterp": "/runtime/ld.so"},
                        {"needed": ["/runtime/libc.so"]}, {"interpreter": fixture()[0]["interpreter"]}):
            with self.subTest(changes=changes), self.assertRaises(artifact.ArtifactContractError):
                artifact.validate_stage_zero_reference(dict(source, **changes), native_executables=[])

    def test_pathname_and_native_execution_schemas_are_not_interchangeable(self):
        source, _ = fixture()
        value = {"executableFd": 40, "executableDigest": source["interpreter"]["sha256"],
                 "pathname": source["interpreter"]["runtimePath"], "transition": "pathname-execve",
                 "descriptorBoundary": "post-local-admission",
                 "argv": [source["interpreter"]["runtimePath"], *stage.REQUIRED_PYTHON_ISOLATION_FLAGS,
                          "/proc/self/fd/41"], "cwd": "/runtime", "noNewPrivileges": True,
                 "pythonIsolationFlags": list(stage.REQUIRED_PYTHON_ISOLATION_FLAGS),
                 "closeRangeFrom": 3, "preserveFds": [40, 41]}
        local = stage.LOCAL_STAGE_ZERO_REQUEST_JSON_SCHEMA["properties"]["execution"]
        Draft202012Validator(local).validate(value)
        with self.assertRaises(ValidationError):
            Draft202012Validator(stage.EXECUTION_JSON_SCHEMA).validate(value)
        native = dict(value, pathname="", execveatFlags=["AT_EMPTY_PATH"])
        native.pop("transition")
        native.pop("descriptorBoundary")
        Draft202012Validator(stage.EXECUTION_JSON_SCHEMA).validate(native)
        with self.assertRaises(ValidationError):
            Draft202012Validator(local).validate(native)

    def test_local_certificate_names_and_domains_are_separate(self):
        for local, native in (
            (stage.LOCAL_STAGE_ZERO_REQUEST_SCHEMA, stage.STAGE_ZERO_REQUEST_SCHEMA),
            (stage.LOCAL_STAGE_ZERO_REQUEST_DIGEST_DOMAIN, stage.STAGE_ZERO_REQUEST_DIGEST_DOMAIN),
            (stage.LOCAL_LAUNCH_ID_DOMAIN, stage.LAUNCH_ID_DOMAIN),
            (stage.LOCAL_LAUNCH_CERTIFICATE_SIGNATURE_DOMAIN, stage.LAUNCH_CERTIFICATE_SIGNATURE_DOMAIN),
        ):
            self.assertNotEqual(local, native)
        payload = stage.LOCAL_LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA["properties"]
        self.assertEqual(payload["trustMode"], {"const": "trusted-host-local"})
        self.assertEqual(payload["hardwareBacked"], {"const": False})
        self.assertEqual(stage.SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA["properties"]["schema"],
                         {"const": stage.SIGNED_LAUNCH_IDENTITY_SCHEMA})

    def test_local_schema_copies_final_native_shared_constraints(self):
        for native, local, changed in (
            (stage.STAGE_ZERO_REQUEST_JSON_SCHEMA, stage.LOCAL_STAGE_ZERO_REQUEST_JSON_SCHEMA,
             {"schema", "trustMode", "stageZero", "execution", "role", "startupDescriptors", "retainedFiles", "retainedDirectories"}),
            (stage.LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA, stage.LOCAL_LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA,
             {"schema", "stageZeroContract", "trustMode", "coLocated", "hardwareBacked"}),
            (stage.SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA, stage.LOCAL_SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA,
             {"schema", "payload"}),
        ):
            extra = {"startupDescriptors"} if native is stage.STAGE_ZERO_REQUEST_JSON_SCHEMA else set()
            self.assertEqual(set(local["required"]), set(native["required"]) | extra)
            self.assertEqual(local.get("allOf"), native.get("allOf"))
            for field in set(native["properties"]) - changed:
                self.assertEqual(local["properties"][field], native["properties"][field])
                self.assertIsNot(local["properties"][field], native["properties"][field])

    def test_static_local_argument_profile_is_closed(self):
        profile = {"schema": artifact.LOCAL_ARGUMENTS_SCHEMA}
        schema = stage.LOCAL_ROLE_BINDING_JSON_SCHEMA["properties"]["argv"]
        Draft202012Validator(schema).validate(profile)
        for value in (dict(profile, argv=["arbitrary"]), ["python", "-c", "arbitrary"],
                      {"schema": "another-profile"}):
            with self.assertRaises(ValidationError):
                Draft202012Validator(schema).validate(value)
        with self.assertRaises(ValidationError):
            Draft202012Validator(stage.ROLE_BINDING_JSON_SCHEMA["properties"]["argv"]).validate(profile)

    def test_fixed_local_argv_binds_observed_slots_without_static_setup_digest(self):
        startup = {"setup": {"fd": 50, "sha256": "sha256:" + "5" * 64}, "channel": {"fd": 51}}
        bindings = {stage.BOOTSTRAP_CONTROL_NAME: 256, "ROLE_PUBLIC_FD": 52}
        argv = ["/runtime/python/bin/python3", *stage.REQUIRED_PYTHON_ISOLATION_FLAGS,
            "/proc/self/fd/41", "--bootstrap-fd", "41", "--trusted-host-local",
            "--local-admission-fd", "50", "--local-admission-sha256", startup["setup"]["sha256"],
            "--local-admission-channel-fd", "51", "--descriptor", "ROLE_PUBLIC_FD=52",
            "--descriptor", stage.BOOTSTRAP_CONTROL_NAME + "=256", "runtime"]
        arguments = dict(role="runtime", entrypoint=argv[0], bootstrap_fd=41,
                         startup=startup, descriptor_bindings=bindings)
        stage.validate_local_argument_vector(argv, **arguments)
        for index, replacement in ((8, "42"), (11, "51"), (13, "sha256:" + "6" * 64),
                                   (17, "ROLE_PUBLIC_FD=053"), (19, "ROLE_PUBLIC_FD=52"), (20, "issuer")):
            changed = list(argv)
            changed[index] = replacement
            with self.subTest(index=index), self.assertRaises(stage.StageZeroContractError):
                stage.validate_local_argument_vector(changed, **arguments)
        with self.assertRaises(stage.StageZeroContractError):
            stage.validate_local_argument_vector(argv + ["--unknown"], **arguments)

    def test_local_startup_descriptor_data_is_closed_and_boot_bound(self):
        process = {"processId": 100, "bootIdDigest": "sha256:" + "7" * 64}
        value = {"setup": {"fd": 50, "device": 1, "inode": 2, "size": 20, "sha256": "sha256:" + "5" * 64},
                 "channel": {"fd": 51, "device": 2, "inode": 3},
                 "producerPidfd": {"fd": 53, "device": 3, "inode": 4, "processId": 99,
                                   "processStartTicks": 10, "bootIdDigest": process["bootIdDigest"]}}
        stage._validate_local_startup(value, process)
        for change in (lambda v: v["producerPidfd"].update(processId=100),
                       lambda v: v["producerPidfd"].update(bootIdDigest="sha256:" + "8" * 64),
                       lambda v: v["channel"].update(fd=50),
                       lambda v: v["setup"].update(extra=True)):
            changed = copy.deepcopy(value)
            change(changed)
            with self.assertRaises(stage.StageZeroContractError):
                stage._validate_local_startup(changed, process)

    def test_local_static_descriptors_cannot_claim_closed_at_admission(self):
        directory = dict(name="generation", fd=60, purpose="artifact-generation-root", runtimePath="/runtime/generation",
                         device=1, inode=2, generation=1, mode=0o555, uid=0, gid=0, surviveExec=True)
        file = dict(directory, name="source", purpose="python-import", runtimePath="/runtime/generation/source.py",
                    size=20, sha256="sha256:" + "9" * 64, fsVerityDigest=None)
        for field, row, validate in (("retainedDirectories", directory, stage._validate_retained_directory),
                                     ("retainedFiles", file, stage._validate_retained_file)):
            local = stage.LOCAL_STAGE_ZERO_REQUEST_JSON_SCHEMA["properties"][field]["items"]
            native = stage.STAGE_ZERO_REQUEST_JSON_SCHEMA["properties"][field]["items"]
            validate(row, local=True)
            Draft202012Validator(local).validate(row)
            changed = dict(row, surviveExec=False)
            validate(changed)
            Draft202012Validator(native).validate(changed)
            with self.assertRaises(stage.StageZeroContractError):
                validate(changed, local=True)
            with self.assertRaises(ValidationError):
                Draft202012Validator(local).validate(changed)
            for key in set(native["properties"]) - {"surviveExec"}:
                self.assertEqual(local["properties"][key], native["properties"][key])

    def test_native_handoff_refuses_local_request_before_package_admission(self):
        with self.assertRaises(stage.StageZeroContractError):
            stage.validate_stage_zero_handoff({}, request={"schema": stage.LOCAL_STAGE_ZERO_REQUEST_SCHEMA},
                verified_package=None, expected_listen_pid=1, expected_peer_pid=1,
                expected_peer_start_ticks=1, validation_time="2026-10-01T00:00:00Z",
                private_key_seed=b"", certificate_bytes=b"")


if __name__ == "__main__":
    unittest.main()

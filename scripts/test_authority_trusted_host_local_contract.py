#!/usr/bin/env python3
"""Pure local/native contract controls; no installed package or live launch claim."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jsonschema import Draft202012Validator, ValidationError
from serverware import authority_artifact_spec as artifact
from serverware import authority_stage_zero_contract as stage


def fixture():
    # Explicit synthetic schema data, not observations or signed receipts.
    interpreter = {"path": "python/bin/python3", "runtimePath": "/runtime/python/bin/python3",
                   "sha256": "sha256:" + "1" * 64, "size": 4096}
    native = {key: interpreter[key] for key in ("path", "runtimePath", "sha256")}
    native.update(elfClass="ELF64", machine=62, ptInterp="/runtime/lib/ld-linux.so.2",
                  needed=["/runtime/lib/libc.so.6"])
    source = {"path": "serverware/authority_launcher.py", "runtimePath": "/runtime/authority_launcher.py",
              "sha256": "sha256:" + "2" * 64, "size": 8192,
              "interfaceSchema": stage.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA, "interpreter": interpreter}
    return source, [native]


class TrustedHostLocalContractTests(unittest.TestCase):
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
             {"schema", "trustMode", "stageZero", "execution"}),
            (stage.LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA, stage.LOCAL_LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA,
             {"schema", "stageZeroContract", "trustMode", "coLocated", "hardwareBacked"}),
            (stage.SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA, stage.LOCAL_SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA,
             {"schema", "payload"}),
        ):
            self.assertEqual(set(local["required"]), set(native["required"]))
            self.assertEqual(local.get("allOf"), native.get("allOf"))
            for field in set(native["properties"]) - changed:
                self.assertEqual(local["properties"][field], native["properties"][field])
                self.assertIsNot(local["properties"][field], native["properties"][field])

    def test_native_handoff_refuses_local_request_before_package_admission(self):
        with self.assertRaises(stage.StageZeroContractError):
            stage.validate_stage_zero_handoff({}, request={"schema": stage.LOCAL_STAGE_ZERO_REQUEST_SCHEMA},
                verified_package=None, expected_listen_pid=1, expected_peer_pid=1,
                expected_peer_start_ticks=1, validation_time="2026-10-01T00:00:00Z",
                private_key_seed=b"", certificate_bytes=b"")


if __name__ == "__main__":
    unittest.main()

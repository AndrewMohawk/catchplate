#!/usr/bin/env python3
"""Public bootstrap controls, not native admission, key loading or a launch.

The small generation documents are synthetic inputs to the real selector. The
source-order check ensures its production caller first authenticates them; the
service remains responsible for the full configuration signature and policy.
"""
import ast
from copy import deepcopy
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import authority_launcher as subject
from serverware import authority_stage_zero_contract as stage_zero
from serverware import authority_fd_entrypoint as local_entrypoint

AUTHOR = "SERVERWARE_NATIVE_JIT_REVIEW_AUTHORIZER_KEY_FD"
COMMIT = "SERVERWARE_NATIVE_JIT_REVIEW_COMMIT_KEY_FD"
FIELD = "nativeJitReviewOpeningPolicy"
ENROLLMENT = "SERVERWARE_NATIVE_JIT_REVIEW_CURRENT_ROOT_ENROLLMENT_FD"
AUTHORITY_FIELD = "nativeJitReviewAuthorityPolicy"
MANIFEST = "sha256:" + "a" * 64


def fixture(*, policy=True, authority_policy=False):
    payload = {"schema": subject.AUTHORITY_CONFIG_SCHEMA,
        "generationSequence": 2, "generationPredecessorDigest": "sha256:" + "b" * 64,
        "generationMinimumRollbackSequence": 1,
        "generationBindingDigest": "sha256:" + "c" * 64}
    if policy:
        payload[FIELD] = {"schema": "serverware.nativeJitReviewOpeningPolicy/v1",
            "sourceContractDigest": MANIFEST}
    if authority_policy:
        payload[AUTHORITY_FIELD] = {"schema": "serverware.nativeJitReviewAuthorityPolicy/v1",
            "sourceContractDigest": MANIFEST, "authenticationPolicy": {},
            "trustPolicy": {}, "stateEndpoint": {}}
    return bound(payload)


def bound(payload):
    original = subject._canonical({"schema": subject.SIGNED_AUTHORITY_CONFIG_SCHEMA,
        "payload": payload, "signature": "synthetic-not-an-admission"})
    file_digest = "sha256:" + hashlib.sha256(original).hexdigest()
    generation = {"schema": subject.GENERATION_CONTEXT_SCHEMA,
        "trustMode": "external-production", "sequence": 2,
        "predecessorDigest": "sha256:" + "b" * 64, "minimumRollbackSequence": 1,
        "configurationBindingDigest": "sha256:" + "c" * 64,
        "operationManifestDigest": MANIFEST, "configurationDigests": [file_digest],
        "configurationPayloadBindings": [{"fileDigest": file_digest,
            "payloadDigest": subject._domain_digest(subject.AUTHORITY_CONFIG_SCHEMA,
                subject._canonical(payload)), "payloadSchema": subject.AUTHORITY_CONFIG_SCHEMA,
            "role": "authority-service"}]}
    return original, generation


def literal(path, name):
    for node in ast.parse((ROOT / path).read_text()).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("missing literal contract")


class NativeReviewCredentialTests(unittest.TestCase):
    def select(self, original, generation, role="planner", native=True):
        return subject._native_review_credentials(role, original, generation,
            native_stage_zero=native)

    def test_old_role_rosters_are_exact_and_never_gain_optional_keys(self):
        prefix = "SERVERWARE_POLICY_AUTHORITY_"
        roles = {
            "runtime": "LAUNCH_ROOT_PUBLIC_KEY RUNTIME_ROOT_PUBLIC_KEY RUNTIME_TRUST",
            "verifier": "LAUNCH_ROOT_PUBLIC_KEY ROOT_PUBLIC_KEY CONFIG VERIFIER_SIGNING_KEY VERIFIER_READ_POSTGRES_DSN",
            "planner": "LAUNCH_ROOT_PUBLIC_KEY ROOT_PUBLIC_KEY CONFIG PLANNER_SIGNING_KEY PLANNER_READ_POSTGRES_DSN",
            "planner-writer": "LAUNCH_ROOT_PUBLIC_KEY ROOT_PUBLIC_KEY CONFIG PLANNER_WRITER_SIGNING_KEY PLANNER_WRITER_POSTGRES_DSN",
            "issuer": "LAUNCH_ROOT_PUBLIC_KEY ROOT_PUBLIC_KEY CONFIG CAPABILITY_ISSUER_POSTGRES_DSN",
            "executor": "LAUNCH_ROOT_PUBLIC_KEY ROOT_PUBLIC_KEY CONFIG EXECUTOR_POSTGRES_DSN",
            "witness": "LAUNCH_ROOT_PUBLIC_KEY WITNESS_ROOT_PUBLIC_KEY WITNESS_CONFIG WITNESS_SIGNING_KEY"}
        expected = {role: frozenset(prefix + item + "_FD" for item in names.split())
            for role, names in roles.items()}
        for role in ("verifier", "planner", "executor"):
            expected[role] |= frozenset("SERVERWARE_RBAC_WITNESS_" + name + "_FD"
                for name in ("CONFIG", "ROOT", "TLS_ROOT", "CLIENT_CERTIFICATE", "CLIENT_KEY"))
        self.assertEqual(subject.ROLE_CREDENTIAL_DESCRIPTOR_NAMES, expected)

    def test_literal_names_join_signer_stage_zero_and_config_contracts(self):
        slots = literal("serverware/authority_native_jit_review_open_signers.py", "_SLOTS")
        self.assertEqual(subject.NATIVE_REVIEW_CREDENTIAL_NAMES,
            {role: item[1] + "_FD" for role, item in slots.items()})
        self.assertEqual(stage_zero.NATIVE_REVIEW_CREDENTIAL_ROLES,
            {AUTHOR: "planner", COMMIT: "executor"})
        self.assertEqual(subject.NATIVE_REVIEW_POLICY_FIELD,
            literal("serverware/authority_native_jit_review_open_custody.py", "FIELD"))
        for name, target in (("CONFIG_SCHEMA", "AUTHORITY_CONFIG_SCHEMA"),
                ("SIGNED_CONFIG_SCHEMA", "SIGNED_AUTHORITY_CONFIG_SCHEMA")):
            self.assertEqual(literal("serverware/authority_service.py", name), getattr(subject, target))

    def test_provisional_candidate_is_exact_role_native_only(self):
        for role, name in (("planner", AUTHOR), ("executor", COMMIT)):
            self.assertEqual(subject._native_review_candidates(role, [name],
                trusted_host_local=False, handoff_descriptor=91), {name})
            for other, names, local, handoff in ((role, [name], True, None),
                    (role, [name], False, None), ("verifier", [name], False, 91),
                    (role, [AUTHOR, COMMIT], False, 91)):
                with self.subTest(role=role, other=other, local=local, handoff=handoff):
                    with self.assertRaises(subject.LaunchError):
                        subject._native_review_candidates(other, names,
                            trusted_host_local=local, handoff_descriptor=handoff)
        self.assertEqual(subject._native_review_candidates("planner", [],
            trusted_host_local=True, handoff_descriptor=None), frozenset())

    def test_ambient_fd_and_path_are_refused_even_when_empty(self):
        for name in (AUTHOR, COMMIT, AUTHOR.removesuffix("_FD") + "_PATH",
                ENROLLMENT, ENROLLMENT.removesuffix("_FD") + "_PATH"):
            with patch.dict(os.environ, {name: ""}, clear=True):
                with self.assertRaises(subject.LaunchError):
                    subject.main([])

    def test_admitted_policy_selects_only_its_role_and_absence_stays_empty(self):
        for role, name in (("planner", AUTHOR), ("executor", COMMIT)):
            self.assertEqual(self.select(*fixture(), role=role), {name})
            self.assertEqual(self.select(*fixture(policy=False), role=role), frozenset())
        with self.assertRaises(subject.LaunchError):
            self.select(*fixture(), role="verifier")
        with self.assertRaises(subject.LaunchError):
            self.select(*fixture(), native=False)

    def test_exact_original_file_and_payload_bindings_are_both_required(self):
        original, generation = fixture()
        with self.assertRaises(subject.LaunchError):
            self.select(original + b" ", generation)
        for key in ("fileDigest", "payloadDigest", "payloadSchema", "role"):
            changed = deepcopy(generation)
            changed["configurationPayloadBindings"][0][key] = "different"
            with self.subTest(key=key), self.assertRaises(subject.LaunchError):
                self.select(original, changed)
        for key in ("configurationPayloadBindings", "configurationDigests"):
            changed = deepcopy(generation)
            changed[key] = []
            with self.subTest(key=key), self.assertRaises(subject.LaunchError):
                self.select(original, changed)

    def test_generation_and_source_selection_must_match(self):
        original, generation = fixture()
        for key in ("sequence", "predecessorDigest", "minimumRollbackSequence",
                "configurationBindingDigest", "operationManifestDigest", "schema", "trustMode"):
            changed = deepcopy(generation)
            changed[key] = "different"
            with self.subTest(key=key), self.assertRaises(subject.LaunchError):
                self.select(original, changed)

    def test_null_unknown_or_malformed_policy_never_selects_a_key(self):
        import json
        payload = json.loads(fixture()[0])["payload"]
        for value in (None, [], {}, {"schema": "future"},
                {"schema": subject.NATIVE_REVIEW_POLICY_SCHEMA, "sourceContractDigest": "wrong"}):
            changed = deepcopy(payload)
            changed[FIELD] = value
            with self.subTest(value=value), self.assertRaises(subject.LaunchError):
                self.select(*bound(changed))

    def test_new_keys_require_exact_stage_zero_metadata(self):
        for name, role in ((AUTHOR, "planner"), (COMMIT, "executor")):
            value = {"name": name, "fd": 99, "purpose": "role-signing-key",
                "ownerRole": role, "ownerUid": 0, "mode": 0o400, "size": 32,
                "sha256": MANIFEST, "seals": stage_zero.REQUIRED_MEMFD_SEALS,
                "delivery": "retained-sealed-memfd"}
            stage_zero._validate_credential(value)
            for key, wrong in (("ownerRole", "verifier"), ("mode", 0o600),
                    ("size", 0), ("size", 65537), ("purpose", "configuration"), ("seals", 0)):
                with self.subTest(key=key, wrong=wrong), self.assertRaises(stage_zero.StageZeroContractError):
                    stage_zero._validate_credential(dict(value, **{key: wrong}))

    def test_readonly_reseal_has_real_seals_identity_and_public_bytes(self):
        raw = b"public synthetic descriptor bytes, not a key"
        fd = subject._seal_readonly_native_review_key(raw)
        try:
            metadata = os.fstat(fd)
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
            self.assertEqual(metadata.st_nlink, 0)
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & subject.REQUIRED_MEMFD_SEALS,
                subject.REQUIRED_MEMFD_SEALS)
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(os.pread(fd, len(raw) + 1, 0), raw)
            with self.assertRaises(OSError):
                os.write(fd, b"x")
        finally:
            os.close(fd)
        for value in (b"", b"x" * 65537):
            with self.assertRaises(subject.LaunchError):
                subject._seal_readonly_native_review_key(value)

    def test_legacy_reseal_access_mode_is_unchanged(self):
        fd = subject._seal_bytes("public legacy fixture", b"public")
        try:
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDWR)
        finally:
            os.close(fd)

    def test_enrollment_roster_is_separate_literal_and_exact(self):
        for module in (subject, stage_zero):
            self.assertEqual(module.NATIVE_REVIEW_CURRENT_ROOT_ENROLLMENT_NAME, ENROLLMENT)
            self.assertEqual(module.NATIVE_REVIEW_CURRENT_ROOT_ENROLLMENT_ROLES, ("verifier", "planner"))
            self.assertEqual(module.MAX_NATIVE_REVIEW_CURRENT_ROOT_ENROLLMENT_BYTES, 128 * 1024)
        self.assertEqual(local_entrypoint.NATIVE_REVIEW_CURRENT_ROOT_ENROLLMENT_NAME, ENROLLMENT)
        self.assertEqual(subject.NATIVE_REVIEW_DESCRIPTOR_NAMES, {AUTHOR, COMMIT, ENROLLMENT})
        self.assertEqual(subject.NATIVE_REVIEW_AUTHORITY_POLICY_FIELD, AUTHORITY_FIELD)
        self.assertEqual(subject.NATIVE_REVIEW_AUTHORITY_POLICY_SCHEMA,
            "serverware.nativeJitReviewAuthorityPolicy/v1")
        for role in subject.ROLE_CREDENTIAL_DESCRIPTOR_NAMES:
            self.assertNotIn(ENROLLMENT, subject.ROLE_CREDENTIAL_DESCRIPTOR_NAMES[role])

    def test_enrollment_candidates_require_their_native_role(self):
        for role, names in (("verifier", [ENROLLMENT]), ("planner", [ENROLLMENT]),
                ("planner", [AUTHOR, ENROLLMENT])):
            self.assertEqual(subject._native_review_candidates(role, names,
                trusted_host_local=False, handoff_descriptor=91), set(names))
            for local, handoff in ((True, 91), (True, None), (False, None)):
                with self.subTest(role=role, local=local, handoff=handoff), self.assertRaises(subject.LaunchError):
                    subject._native_review_candidates(role, names,
                        trusted_host_local=local, handoff_descriptor=handoff)
        for role in ("runtime", "planner-writer", "issuer", "executor", "witness"):
            with self.subTest(role=role), self.assertRaises(subject.LaunchError):
                subject._native_review_candidates(role, [ENROLLMENT],
                    trusted_host_local=False, handoff_descriptor=91)

    def test_enrollment_policy_is_independent_of_opening_keys(self):
        select = subject._native_review_current_root_credentials
        for role in ("verifier", "planner"):
            self.assertEqual(select(role, *fixture(authority_policy=True), native_stage_zero=True), {ENROLLMENT})
            self.assertEqual(select(role, *fixture(policy=False, authority_policy=True), native_stage_zero=True), {ENROLLMENT})
            self.assertEqual(select(role, *fixture(), native_stage_zero=True), frozenset())
            with self.assertRaises(subject.LaunchError):
                select(role, *fixture(authority_policy=True), native_stage_zero=False)
        self.assertEqual(self.select(*fixture(policy=False, authority_policy=True)), frozenset())
        for role in ("runtime", "planner-writer", "issuer", "executor", "witness"):
            with self.subTest(role=role), self.assertRaises(subject.LaunchError):
                select(role, *fixture(authority_policy=True), native_stage_zero=True)

    def test_enrollment_selector_requires_exact_original_generation_and_policy(self):
        import json
        original, generation = fixture(authority_policy=True)
        select = lambda raw, gen: subject._native_review_current_root_credentials(
            "verifier", raw, gen, native_stage_zero=True)
        with self.assertRaises(subject.LaunchError):
            select(original + b" ", generation)
        for key in ("sequence", "predecessorDigest", "minimumRollbackSequence", "configurationBindingDigest",
                "operationManifestDigest", "schema", "trustMode", "configurationDigests", "configurationPayloadBindings"):
            changed = deepcopy(generation)
            changed[key] = "different"
            with self.subTest(key=key), self.assertRaises(subject.LaunchError):
                select(original, changed)
        payload = json.loads(original)["payload"]
        policy = payload[AUTHORITY_FIELD]
        for value in (None, [], {}, {**policy, "schema": "future"},
                {**policy, "sourceContractDigest": "wrong"},
                {key: item for key, item in policy.items() if key != "stateEndpoint"},
                {**policy, "enrollment": "must remain a separate original"}):
            changed = deepcopy(payload)
            changed[AUTHORITY_FIELD] = value
            with self.subTest(value=value), self.assertRaises(subject.LaunchError):
                select(*bound(changed))

    def test_enrollment_stage_zero_metadata_and_credential_set_binding(self):
        for role in ("verifier", "planner"):
            value = {"name": ENROLLMENT, "fd": 99, "purpose": "service-client-credential",
                "ownerRole": role, "ownerUid": 0, "mode": 0o400, "size": 128 * 1024,
                "sha256": MANIFEST, "seals": stage_zero.REQUIRED_MEMFD_SEALS,
                "delivery": "retained-sealed-memfd"}
            stage_zero._validate_credential(value)
            original = stage_zero.credential_set_digest([value])
            for key, changed in (("sha256", "sha256:" + "b" * 64), ("size", 100),
                    ("ownerRole", "planner" if role == "verifier" else "verifier")):
                self.assertNotEqual(original, stage_zero.credential_set_digest([{**value, key: changed}]))
            for key, wrong in (("ownerRole", "executor"), ("mode", 0o600), ("ownerUid", 1000),
                    ("size", 0), ("size", 128 * 1024 + 1), ("purpose", "role-signing-key"),
                    ("delivery", "path"), ("seals", 0)):
                with self.subTest(role=role, key=key), self.assertRaises(stage_zero.StageZeroContractError):
                    stage_zero._validate_credential({**value, key: wrong})

    def test_enrollment_reseal_is_bounded_readonly_and_exact(self):
        raw = b"public unsigned enrollment fixture".ljust(128 * 1024, b" ")
        descriptor = subject._seal_readonly_native_review_key(raw, maximum_bytes=128 * 1024)
        try:
            binding = {"descriptor": descriptor, "environmentName": ENROLLMENT, "ownerUid": 0,
                "mode": 0o400, "size": len(raw), "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
            with patch.dict(os.environ, {ENROLLMENT: str(descriptor)}, clear=True):
                for key, wrong in (("sha256", MANIFEST), ("ownerUid", 1000),
                        ("size", 128 * 1024 + 1), ("environmentName", AUTHOR)):
                    with self.subTest(key=key), self.assertRaises(subject.LaunchError):
                        subject._retain_native_review_credential({**binding, key: wrong})
                with patch.dict(os.environ, {ENROLLMENT.removesuffix("_FD") + "_PATH": ""}):
                    with self.assertRaises(subject.LaunchError):
                        subject._retain_native_review_credential(binding)
                if os.geteuid() == 0:
                    subject._retain_native_review_credential(binding)
                else:
                    with self.assertRaises(subject.LaunchError):
                        subject._retain_native_review_credential(binding)
            self.assertEqual(os.pread(descriptor, len(raw) + 1, 0), raw)
            self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS), subject.REQUIRED_MEMFD_SEALS)
            with self.assertRaises(OSError):
                os.write(descriptor, b"x")
        finally:
            os.close(descriptor)
        with self.assertRaises(subject.LaunchError):
            subject._seal_readonly_native_review_key(raw)
        with self.assertRaises(subject.LaunchError):
            subject._seal_readonly_native_review_key(raw + b"x", maximum_bytes=128 * 1024)

    def test_local_entrypoint_refuses_enrollment_before_credential_access(self):
        for name in (ENROLLMENT, ENROLLMENT.removesuffix("_FD") + "_PATH"):
            for role in ("verifier", "planner", "control-plane"):
                with patch.dict(os.environ, {name: "", "SERVERWARE_AUTHORITY_TRUST_MODE": "trusted-host-local"}, clear=True):
                    with patch.object(local_entrypoint, "_open_systemd_credential") as read:
                        with self.assertRaisesRegex(RuntimeError, "actual native stage zero"):
                            local_entrypoint._normal_main(role)
                        read.assert_not_called()

    def test_actual_call_order_authenticates_before_selection_read_and_drop(self):
        tree = ast.parse((ROOT / "serverware/authority_launcher.py").read_text())
        enter = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_enter")
        calls = {node.func.id: node.lineno for node in ast.walk(enter)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        order = [calls[name] for name in ("_validate_canonical_launch_evidence",
            "_load_canonical_stage_zero_handoff", "_native_review_credentials",
            "_native_review_current_root_credentials", "_retain_native_review_credential", "_drop_role_identity")]
        self.assertEqual(order, sorted(order))
        stage = (ROOT / "serverware/authority_stage_zero_contract.py").read_text()
        self.assertIn('if local and entry["name"] in NATIVE_REVIEW_CREDENTIAL_ROLES:', stage)
        self.assertIn('if local and entry["name"] == NATIVE_REVIEW_CURRENT_ROOT_ENROLLMENT_NAME:', stage)
        self.assertIn('if selected_native_review != native_review_credentials:',
            (ROOT / "serverware/authority_launcher.py").read_text())
        local = (ROOT / "serverware/authority_fd_entrypoint.py").read_text()
        self.assertNotIn(AUTHOR, local)
        self.assertNotIn(COMMIT, local)


if __name__ == "__main__":
    unittest.main()

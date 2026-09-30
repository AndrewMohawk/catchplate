#!/usr/bin/env python3
"""Synthetic static closure-set regression controls; never runtime evidence.

All image/provenance/runtime values below are labelled synthetic hash inputs.
The two literal seccomp instruction fixtures follow the existing source's
fixed x86-64 compiler layout; neither filter is installed or executed. Passing
these controls is not independent approval, measured provenance, an admitted
assignment/guest, or a successful native pilot. No key or signature is created.
"""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import native_pilot_closure_set as closure_set

EXPECTED_ROLES = (
    "retrieval", "persistence", "trustedTime", "generationInstall", "commitRequest",
    "ingressAdmission", "terminalAppend", "dispatchBarrier", "activeEffectBarrier",
    "activeEffectCommit", "bridge",
)
MANIFEST_FIELDS = ("apiVersion", "profile", "imageSha256", "workerExecutableSha256", "seccompPolicy",
    "runtimeConfigurationSha256", "buildProvenance", "manifestSha256")
PROVENANCE_FIELDS = ("sourceTreeSha256", "dependencyLockSha256", "buildRecipeSha256", "toolchainClosureSha256",
    "provenanceStatementSha256", "transparencyLogEntrySha256", "reproducibleBuildRequired", "provenanceSha256")
KILL = 0x80000000

# Literal no-argument programs for rules {execve:kill,execveat:kill}, and the
# distinct {read:allow,execve:kill,execveat:kill}, both default-kill. Correspond
# to compile_custody_seccomp_rules in policy_shadow.rs; not a test-side compiler.
DENY_PROGRAM = (
    (0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, KILL),
    (0x20, 0, 0, 0), (0x15, 0, 1, 59), (0x06, 0, 0, KILL),
    (0x20, 0, 0, 0), (0x15, 0, 1, 322), (0x06, 0, 0, KILL),
    (0x06, 0, 0, KILL),
)
READ_PROGRAM = (
    (0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, KILL),
    (0x20, 0, 0, 0), (0x15, 0, 1, 0), (0x06, 0, 0, 0x7FFF0000),
    (0x20, 0, 0, 0), (0x15, 0, 1, 59), (0x06, 0, 0, KILL),
    (0x20, 0, 0, 0), (0x15, 0, 1, 322), (0x06, 0, 0, KILL),
    (0x06, 0, 0, KILL),
)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def frame(domain, value):
    raw = canonical(value)
    return sha(domain.encode("ascii") + b"\0" + len(raw).to_bytes(8, "big") + raw)


def synthetic(label):
    return sha(("SYNTHETIC STATIC TEST ONLY / " + label).encode("ascii"))


def seccomp_fixture(*, read_allowed=False):
    program = READ_PROGRAM if read_allowed else DENY_PROGRAM
    instructions = [{"ordinal": ordinal, "code": code, "jumpIfTrue": yes, "jumpIfFalse": no, "operand": operand}
        for ordinal, (code, yes, no, operand) in enumerate(program)]
    rules = [{"syscallNumber": number, "action": action, "errno": 0, "argumentRules": []}
        for number, action in (((0, "allow"), (59, "kill-process"), (322, "kill-process")) if read_allowed
            else ((59, "kill-process"), (322, "kill-process")))]
    instruction_hash = frame("serverware.policyShadowCustodySeccompInstructions/v1", instructions)
    raw_hash = sha(b"".join(struct.pack("<HBBI", *instruction) for instruction in program))
    semantics_hash = frame("serverware.policyShadowCustodySeccompSemantics/v1",
        ["x86-64", "kill-process", True, True, rules])
    return {"architecture": "x86-64", "defaultAction": "kill-process", "noNewPrivilegesRequired": True,
        "installedBeforeUntrustedInput": True, "instructions": instructions, "syscallRules": rules,
        "exactInstructionStreamSha256": instruction_hash, "rawBpfSha256": raw_hash,
        "exactArgumentSemanticsSha256": semantics_hash,
        "structurallyVerifiedPolicySha256": frame("serverware.policyShadowCustodySeccompPolicy/v2",
            [instruction_hash, raw_hash, semantics_hash])}


def manifest_fixture(role, *, read_allowed=False):
    provenance = {name: synthetic("provenance/" + name) for name in PROVENANCE_FIELDS[:-2]}
    provenance["reproducibleBuildRequired"] = True
    provenance["provenanceSha256"] = frame("serverware.policyShadowCustodyBuildProvenance/v1",
        [provenance[name] for name in PROVENANCE_FIELDS[:-1]])
    version = "2" if role == "bridge" else "1"
    value = {"apiVersion": "serverware.nativeCustodyExecutionClosure/v" + version,
        "profile": "measured-bootstrap-late-runtime-static-amd64-v1" if role == "bridge"
            else "sealed-memfd-squashfs-static-amd64-v1",
        "imageSha256": synthetic("image/" + role), "workerExecutableSha256": synthetic("executable/" + role),
        "seccompPolicy": seccomp_fixture(read_allowed=read_allowed),
        "runtimeConfigurationSha256": synthetic("runtime/" + role), "buildProvenance": provenance}
    value["manifestSha256"] = frame(value["apiVersion"], [value[name] for name in MANIFEST_FIELDS[:-1]])
    return value


def members_fixture():
    return [{"role": role, "manifest": manifest_fixture(role)} for role in EXPECTED_ROLES]


class ClosureSetStaticTests(unittest.TestCase):
    def setUp(self):
        self.members = members_fixture()
        self.raw = closure_set.set_original(self.members)
        self.value = closure_set.validate(self.raw)

    def test_exact_eleven_order_and_independent_hash_recipes(self):
        self.assertEqual(closure_set.ROLES, EXPECTED_ROLES)
        self.assertEqual(tuple(row["role"] for row in self.value["members"]), EXPECTED_ROLES)
        self.assertEqual(self.raw, canonical(self.value))
        leaves = [frame("serverware.nativeCustodyExecutionClosureSetLeaf/v1", [row["role"], row["manifest"]])
            for row in self.members]
        policies = [[row["role"], row["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"]]
            for row in self.members]
        self.assertEqual(self.value["setRootSha256"], frame("serverware.nativeCustodyExecutionClosureSetRoot/v1", leaves))
        self.assertEqual(self.value["seccompSetRootSha256"], frame("serverware.nativeCustodySeccompSetRoot/v1", policies))
        for index, role in enumerate(EXPECTED_ROLES):
            binding = closure_set.leaf_binding(self.value, role)
            self.assertEqual(binding["role"], role)
            self.assertEqual(binding["leafSha256"], leaves[index])
            self.assertEqual(binding["manifestSha256"], self.members[index]["manifest"]["manifestSha256"])

    def test_both_external_root_pins_are_required_separately(self):
        root, policy_root = self.value["setRootSha256"], self.value["seccompSetRootSha256"]
        self.assertEqual(closure_set.require_binding(self.raw, expected_set_root=root,
            expected_seccomp_set_root=policy_root), self.value)
        self.assertNotEqual(root, policy_root)
        for wrong_root, wrong_policy in ((synthetic("wrong-root"), policy_root),
                (root, synthetic("wrong-seccomp-root")), (policy_root, root)):
            with self.subTest(root=wrong_root, seccomp=wrong_policy), self.assertRaises(ValueError):
                closure_set.require_binding(self.raw, expected_set_root=wrong_root,
                    expected_seccomp_set_root=wrong_policy)
        with self.assertRaises(TypeError):
            closure_set.require_binding(self.raw, expected_set_root=root)

    def test_missing_duplicate_unknown_extra_and_reordered_roles_reject(self):
        changed = {}
        changed["missing"] = self.members[:-1]
        changed["extra"] = self.members + [copy.deepcopy(self.members[0])]
        changed["duplicate"] = copy.deepcopy(self.members)
        changed["duplicate"][1]["role"] = "retrieval"
        changed["unknown"] = copy.deepcopy(self.members)
        changed["unknown"][0]["role"] = "caller-selected"
        changed["reordered"] = copy.deepcopy(self.members)
        changed["reordered"][0], changed["reordered"][1] = changed["reordered"][1], changed["reordered"][0]
        for name, members in changed.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                closure_set.set_original(members)
            value = dict(self.value, members=members)
            with self.subTest(wire=name), self.assertRaises(ValueError):
                closure_set.validate(canonical(value))

    def test_endpoint_and_bridge_profile_swap_rejects(self):
        for index, wrong_role in ((0, "bridge"), (10, "retrieval")):
            members = copy.deepcopy(self.members)
            members[index]["manifest"] = manifest_fixture(wrong_role)
            with self.subTest(index=index), self.assertRaises(ValueError):
                closure_set.set_original(members)

    def test_noncanonical_and_duplicate_fields_reject(self):
        variants = (self.raw + b"\n", b" " + self.raw,
            json.dumps(self.value, indent=2, sort_keys=True).encode("ascii"),
            self.raw.replace(b'{"apiVersion":',
                b'{"apiVersion":"serverware.nativeCustodyExecutionClosureSet/v1","apiVersion":', 1),
            self.raw.replace(b'"members":', b'"members":[],"members":', 1))
        for raw in variants:
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                closure_set.validate(raw)

    def test_manifest_and_provenance_commitments_are_not_just_shape(self):
        for field in ("manifestSha256", "runtimeConfigurationSha256"):
            members = copy.deepcopy(self.members)
            members[0]["manifest"][field] = synthetic("tamper/" + field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                closure_set.set_original(members)
        members = copy.deepcopy(self.members)
        members[0]["manifest"]["buildProvenance"]["sourceTreeSha256"] = synthetic("tampered-provenance")
        with self.assertRaises(ValueError):
            closure_set.set_original(members)

    def test_distinct_policy_leaf_is_not_a_common_seccomp_root(self):
        members = copy.deepcopy(self.members)
        members[0]["manifest"] = manifest_fixture("retrieval", read_allowed=True)
        alternate_raw = closure_set.set_original(members)
        alternate = closure_set.validate(alternate_raw)
        self.assertNotEqual(alternate["setRootSha256"], self.value["setRootSha256"])
        self.assertNotEqual(alternate["seccompSetRootSha256"], self.value["seccompSetRootSha256"])
        binding = closure_set.leaf_binding(alternate, "retrieval")
        single_policy = members[0]["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"]
        self.assertEqual(binding["structurallyVerifiedPolicySha256"], single_policy)
        self.assertNotEqual(binding["seccompSetRootSha256"], single_policy)
        self.assertNotEqual(single_policy, members[1]["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"])
        with self.assertRaises(ValueError):
            closure_set.require_binding(alternate_raw, expected_set_root=alternate["setRootSha256"],
                expected_seccomp_set_root=single_policy)
        with self.assertRaises(ValueError):
            closure_set.require_binding(alternate_raw, expected_set_root=alternate["setRootSha256"],
                expected_seccomp_set_root=self.value["seccompSetRootSha256"])

    def test_assignment_or_guest_fields_do_not_enter_static_set(self):
        for name in ("assignmentPayloadSha256", "guest", "signature"):
            value = copy.deepcopy(self.value)
            value[name] = synthetic("forbidden/" + name)
            with self.subTest(field=name), self.assertRaises(ValueError):
                closure_set.validate(canonical(value))


if __name__ == "__main__":
    unittest.main(verbosity=2)

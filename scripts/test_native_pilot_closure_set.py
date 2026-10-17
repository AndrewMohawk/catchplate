#!/usr/bin/env python3
"""Synthetic static closure-set/assignment/transcript controls; never evidence.

All image/provenance/runtime values below are labelled synthetic hash inputs.
The two literal seccomp instruction fixtures follow the existing source's
fixed x86-64 compiler layout; neither filter is installed or executed. Passing
these controls is not independent approval, measured provenance, an admitted
assignment/guest, or a successful native pilot. No key or signature is created.
Envelope shape fixtures use an explicitly invalid all-zero signature sentinel:
they test grammar and preimage binding only, never signature verification. The
label-derived key-identity hashes are not public keys or provisioned authority.
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
sys.path.insert(0, str(ROOT / "scripts" / "authority"))

import prepare_native_pilot_closure_set as preparation
from catchplate import native_pilot_closure_set as closure_set
from catchplate import native_pilot_assignment as assignment_profile
from catchplate import native_pilot_launch_publication as launch
from catchplate import authority_policy_canary_native_opening as opening
from catchplate import native_shadow_retrieval_artifacts as retrieval

EXPECTED_ROLES = (
    "retrieval", "persistence", "trustedTime", "generationInstall", "commitRequest",
    "ingressAdmission", "terminalAppend", "dispatchBarrier", "activeEffectBarrier",
    "activeEffectCommit", "bridge",
)
EXPECTED_GENESIS_ROLES = ("publicationGenesisRetrieval", "publicationGenesis", "publicationGenesisCoordinator")
EXPECTED_PUBLICATION_ROLES = EXPECTED_ROLES[:-1] + ("publicationReconciliation", "bridge")
MANIFEST_FIELDS = ("apiVersion", "profile", "imageSha256", "workerExecutableSha256", "seccompPolicy",
    "runtimeConfigurationSha256", "buildProvenance", "manifestSha256")
PROVENANCE_FIELDS = ("sourceTreeSha256", "dependencyLockSha256", "buildRecipeSha256", "toolchainClosureSha256",
    "provenanceStatementSha256", "transparencyLogEntrySha256", "reproducibleBuildRequired", "provenanceSha256")
KILL = 0x80000000
INVALID_SIGNATURE_SENTINEL = "A" * 86  # 64 zero bytes, never signed or verified.
EXPECTED_SCOPE_VALUES = ("assignment_id", "assignment_payload_sha256", "assignment_revision", "authority_id",
    "storage_realm_sha256", "retrieval_namespace_sha256", "authority_key_independence_sha256",
    "production_configuration_binding_sha256", "asserted_custody_key_set_root_sha256",
    "execution_closure_manifest_sha256", "structurally_verified_seccomp_policy_sha256")
EXPECTED_SCOPE_ROOTS = ("execution_closure_set_root_sha256", "structurally_verified_seccomp_set_root_sha256")
KEY_ROLES = ("compiler-analysis", "activation-readiness", "activation-approval", "fleet-tee-attestation",
    "fleet-ingress", "fleet-active-decision", "fleet-shadow") + tuple("custody-" + name for name in (
        "ingress-admission", "unavailable-ingress", "dispatch-barrier", "terminal-append", "ledger-append",
        "spool-compaction", "active-effect-barrier", "active-effect-commit", "publication-reconciliation",
        "activation-publication", "result-envelope", "store-response", "signer-response", "retrieval-response",
        "trusted-time-response", "provider-response", "attestation-verifier", "supervisor-capability"))

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
    instruction_hash = frame("catchplate.policyShadowCustodySeccompInstructions/v1", instructions)
    raw_hash = sha(b"".join(struct.pack("<HBBI", *instruction) for instruction in program))
    semantics_hash = frame("catchplate.policyShadowCustodySeccompSemantics/v1",
        ["x86-64", "kill-process", True, True, rules])
    return {"architecture": "x86-64", "defaultAction": "kill-process", "noNewPrivilegesRequired": True,
        "installedBeforeUntrustedInput": True, "instructions": instructions, "syscallRules": rules,
        "exactInstructionStreamSha256": instruction_hash, "rawBpfSha256": raw_hash,
        "exactArgumentSemanticsSha256": semantics_hash,
        "structurallyVerifiedPolicySha256": frame("catchplate.policyShadowCustodySeccompPolicy/v2",
            [instruction_hash, raw_hash, semantics_hash])}


def manifest_fixture(role, *, read_allowed=False):
    provenance = {name: synthetic("provenance/" + name) for name in PROVENANCE_FIELDS[:-2]}
    provenance["reproducibleBuildRequired"] = True
    provenance["provenanceSha256"] = frame("catchplate.policyShadowCustodyBuildProvenance/v1",
        [provenance[name] for name in PROVENANCE_FIELDS[:-1]])
    version = "2" if role == "bridge" else "1"
    value = {"apiVersion": "catchplate.nativeCustodyExecutionClosure/v" + version,
        "profile": "measured-bootstrap-late-runtime-static-amd64-v1" if role == "bridge"
            else "sealed-memfd-squashfs-static-amd64-v1",
        "imageSha256": synthetic("image/" + role), "workerExecutableSha256": synthetic("executable/" + role),
        "seccompPolicy": seccomp_fixture(read_allowed=read_allowed),
        "runtimeConfigurationSha256": synthetic("runtime/" + role), "buildProvenance": provenance}
    value["manifestSha256"] = frame(value["apiVersion"], [value[name] for name in MANIFEST_FIELDS[:-1]])
    return value


def members_fixture():
    return [{"role": role, "manifest": manifest_fixture(role)} for role in EXPECTED_ROLES]


def merkle_fixture(values):
    """Independent exact digest arithmetic; hashes are not key material."""
    leaves = [hashlib.sha256(b"catchplate.policyShadowMerkleLeaf/v1\0" + ordinal.to_bytes(8, "big")
        + bytes.fromhex(value[7:])).digest() for ordinal, value in enumerate(values, 1)]
    while len(leaves) > 1:
        leaves = [leaves[index] if index + 1 == len(leaves) else hashlib.sha256(
            b"catchplate.policyShadowMerkleNode/v1\1" + leaves[index] + leaves[index + 1]).digest()
            for index in range(0, len(leaves), 2)]
    return "sha256:" + leaves[0].hex()


def assignment_fixture(selected, *, version=2):
    """Closed shape plus pure key-identity commitments, NOT an admitted policy."""
    assignment_id = synthetic("assignment-id")
    bindings = [{"role": role, "scopeSha256": assignment_id, "keyAlgorithm": "ed25519",
        **{name: synthetic(role + "/" + name) for name in ("keyId", "keySpkiSha256", "keyMaterialSha256")}}
        for role in KEY_ROLES]
    independence = {"bindings": bindings}
    for name, root in (("keyId", "keyIdSetRootSha256"), ("keySpkiSha256", "spkiSetRootSha256"),
                       ("keyMaterialSha256", "keyMaterialSetRootSha256")):
        independence[root] = merkle_fixture(sorted(row[name] for row in bindings))
    independence["independenceRootSha256"] = frame("catchplate.policyAuthorityKeyIndependence/v1",
        [bindings, independence["keyIdSetRootSha256"], independence["spkiSetRootSha256"],
            independence["keyMaterialSetRootSha256"]])
    bridge = selected["members"][-1]["manifest"]
    custody = {"authorityId": synthetic("authority"), "storageRealmSha256": synthetic("storage"),
        "retrievalNamespaceSha256": synthetic("namespace"),
        "executionClosureManifestSha256": bridge["manifestSha256"],
        "structurallyVerifiedSeccompPolicySha256": bridge["seccompPolicy"]["structurallyVerifiedPolicySha256"],
        "attestationMode": {"mode": "tee", "platform": "aws-nitro-enclave",
            **{name: synthetic("attestation/" + name) for name in ("expectedMeasurementSha256",
                "endorsementRootSha256", "collateralPolicySha256", "revocationSourceSha256")}}}
    for row in bindings[7:]:
        parts = row["role"].removeprefix("custody-").split("-")
        prefix = parts[0] + "".join(part.title() for part in parts[1:])
        custody[prefix + "KeyId"] = row["keyId"]
        custody[prefix + "KeySpkiSha256"] = row["keySpkiSha256"]
    # Empty unrelated nested objects intentionally make no full native-policy
    # validity claim. These helpers admit shape/transcript, not operational state.
    payload = {"assignmentId": assignment_id, "canaryId": synthetic("canary-id"), "assignmentRevision": 1,
        "generationEpoch": 1, "minimumGenerationTombstoneEpoch": 1, "policyIdentity": {},
        "expectedLoadedSnapshots": {}, "responseValidationObligations": [],
        "responseValidationObligationsRootSha256": synthetic("obligations"), "fleet": {},
        "custodyAuthority": custody, "authorityKeyIndependence": independence, "observationWindow": {},
        "readinessThresholds": {}, "issuedAtUnixNanos": 1, "expiresAtUnixNanos": 2}
    if version == 2:
        payload["nativeClosureSet"] = {name: selected[name] for name in ("setRootSha256", "seccompSetRootSha256")}
    domain = "catchplate.policyShadowAssignment/v" + str(version)
    return {"apiVersion": domain, "kind": "PolicyShadowAssignment",
        "canonicalProfile": "catchplate.canonicalJson/ascii-integer-v1", "signatureDomain": domain,
        "payload": payload, "payloadSha256": sha(canonical(payload)), "signatureAlgorithm": "Ed25519",
        "signingKeyId": synthetic("assignment-key"), "signingKeySpkiSha256": synthetic("assignment-spki"),
        "signature": INVALID_SIGNATURE_SENTINEL}


def rehash_payload(envelope):
    envelope["payloadSha256"] = sha(canonical(envelope["payload"]))
    return envelope


def scope_fixture(envelope):
    payload = envelope["payload"]
    authority = payload["custodyAuthority"]
    rows = payload["authorityKeyIndependence"]["bindings"][7:]
    key_root = merkle_fixture([frame("catchplate.policyShadowCustodyAssertedKey/v1",
        [row[name] for name in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")]) for row in rows])
    scope = {"assignment_id": payload["assignmentId"], "assignment_payload_sha256": envelope["payloadSha256"],
        "assignment_revision": payload["assignmentRevision"], "authority_id": authority["authorityId"],
        "storage_realm_sha256": authority["storageRealmSha256"], "retrieval_namespace_sha256": authority["retrievalNamespaceSha256"],
        "authority_key_independence_sha256": payload["authorityKeyIndependence"]["independenceRootSha256"],
        "production_configuration_binding_sha256": synthetic("production-configuration"),
        "asserted_custody_key_set_root_sha256": key_root,
        "execution_closure_manifest_sha256": authority["executionClosureManifestSha256"],
        "structurally_verified_seccomp_policy_sha256": authority["structurallyVerifiedSeccompPolicySha256"]}
    for name, role in (("store_response_authority", "custody-store-response"),
                       ("retrieval_response_authority", "custody-retrieval-response")):
        row = next(row for row in rows if row["role"] == role)
        scope[name] = {"role": role, "key_id": row["keyId"], "key_spki_sha256": row["keySpkiSha256"],
            "key_material_sha256": row["keyMaterialSha256"]}
    values, domain = EXPECTED_SCOPE_VALUES, "catchplate.policyShadowProductionCustodyProofScope/v1"
    if envelope["apiVersion"].endswith("/v2"):
        domain = "catchplate.policyShadowProductionCustodyProofScope/v2"
        scope.update(api_version=domain, execution_closure_set_root_sha256=payload["nativeClosureSet"]["setRootSha256"],
            structurally_verified_seccomp_set_root_sha256=payload["nativeClosureSet"]["seccompSetRootSha256"])
        values += EXPECTED_SCOPE_ROOTS
    scope["binding_sha256"] = frame(domain, [scope[name] for name in values])
    return scope


def closure_fixture(selected, *, role="retrieval", multi=True):
    index = EXPECTED_ROLES.index(role)
    manifest = copy.deepcopy(selected["members"][index]["manifest"])
    version = "3" if multi else ("2" if role == "bridge" else "1")
    payload = {"apiVersion": "catchplate.nativeCustodyClosureAssignment/v" + version,
        "purpose": "shadow-custody-closure-set-member" if multi else (
            "shadow-custody-bootstrap-late-runtime" if role == "bridge" else "shadow-custody-execution-closure"),
        "profile": "native-multi-guest-closure-set-v1" if multi else manifest["profile"],
        "assignmentId": synthetic("assignment-id"), "assignmentPayloadSha256": synthetic("assignment-payload"),
        "assignmentRevision": 1, "manifestSha256": manifest["manifestSha256"], "guest": {},
        "trustCheckpointId": synthetic("checkpoint"), "revocationGeneration": 0,
        "revocationRootSha256": synthetic("revocation"), "issuedAtUnixNanos": 1, "expiresAtUnixNanos": 2,
        "signingKeyId": synthetic("supervisor-key"), "signingKeySpkiSha256": synthetic("supervisor-spki")}
    if multi:
        payload.update(guestRole=role, setRootSha256=selected["setRootSha256"],
            seccompSetRootSha256=selected["seccompSetRootSha256"],
            leafSha256=frame("catchplate.nativeCustodyExecutionClosureSetLeaf/v1", [role, manifest]))
    value = {"apiVersion": "catchplate.nativeCustodyClosure/v" + version, "manifest": manifest,
        "authorization": {"payload": payload, "signature": INVALID_SIGNATURE_SENTINEL}}
    if multi:
        value["closureSet"] = copy.deepcopy(selected)
    return value


class ClosureSetStaticTests(unittest.TestCase):
    def setUp(self):
        self.members = members_fixture()
        self.raw = closure_set.set_original(self.members)
        self.value = closure_set.validate(self.raw)

    def test_exact_eleven_order_and_independent_hash_recipes(self):
        self.assertEqual(closure_set.ROLES, EXPECTED_ROLES)
        self.assertEqual(tuple(row["role"] for row in self.value["members"]), EXPECTED_ROLES)
        self.assertEqual(self.raw, canonical(self.value))
        leaves = [frame("catchplate.nativeCustodyExecutionClosureSetLeaf/v1", [row["role"], row["manifest"]])
            for row in self.members]
        policies = [[row["role"], row["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"]]
            for row in self.members]
        self.assertEqual(self.value["setRootSha256"], frame("catchplate.nativeCustodyExecutionClosureSetRoot/v1", leaves))
        self.assertEqual(self.value["seccompSetRootSha256"], frame("catchplate.nativeCustodySeccompSetRoot/v1", policies))
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
                b'{"apiVersion":"catchplate.nativeCustodyExecutionClosureSet/v1","apiVersion":', 1),
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


class ClosureSetSuccessorTests(unittest.TestCase):
    # These exercise static bytes and public schema only. They do not run a
    # protected FD command, sign a closure, or admit any native owner.
    PROFILES = (
        ("catchplate.nativePublicationGenesisClosureSet/v1", EXPECTED_GENESIS_ROLES,
            "catchplate.nativePublicationGenesisClosureSetLeaf/v1",
            "catchplate.nativePublicationGenesisClosureSetRoot/v1",
            "catchplate.nativePublicationGenesisSeccompSetRoot/v1"),
        ("catchplate.nativeCustodyExecutionClosureSet/v2", EXPECTED_PUBLICATION_ROLES,
            "catchplate.nativeCustodyExecutionClosureSetLeaf/v2",
            "catchplate.nativeCustodyExecutionClosureSetRoot/v2",
            "catchplate.nativeCustodySeccompSetRoot/v2"),
    )

    def members(self, roles):
        return [{"role": role, "manifest": manifest_fixture(role)} for role in roles]

    def assert_recipe(self, profile):
        api, roles, leaf_domain, root_domain, seccomp_domain = profile
        members = self.members(roles)
        raw = closure_set.set_original(members, api_version=api)
        value = closure_set.validate(raw, api_version=api)
        leaves = [frame(leaf_domain, [row["role"], row["manifest"]]) for row in members]
        policies = [[row["role"], row["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"]]
            for row in members]
        self.assertEqual(tuple(row["role"] for row in value["members"]), roles)
        self.assertEqual(raw, canonical(value))
        self.assertEqual(value["setRootSha256"], frame(root_domain, leaves))
        self.assertEqual(value["seccompSetRootSha256"], frame(seccomp_domain, policies))
        self.assertEqual(closure_set.require_binding(raw, api_version=api,
            expected_set_root=value["setRootSha256"], expected_seccomp_set_root=value["seccompSetRootSha256"]), value)
        for index, role in enumerate(roles):
            binding = closure_set.leaf_binding(value, role, api_version=api)
            self.assertEqual(binding["leafSha256"], leaves[index])
            self.assertEqual(binding["manifestSha256"], members[index]["manifest"]["manifestSha256"])
        return value

    def test_cold_three_exact_order_native_hashes_and_immutable_coordinator(self):
        self.assertEqual(closure_set.GENESIS_API, self.PROFILES[0][0])
        self.assertEqual(closure_set.GENESIS_ROLES, EXPECTED_GENESIS_ROLES)
        value = self.assert_recipe(self.PROFILES[0])
        self.assertTrue(all(row["manifest"]["apiVersion"] == "catchplate.nativeCustodyExecutionClosure/v1"
            for row in value["members"]))

    def test_hot_twelve_exact_order_native_hashes_and_distinct_publication_member(self):
        self.assertEqual(closure_set.PUBLICATION_API, self.PROFILES[1][0])
        self.assertEqual(closure_set.PUBLICATION_ROLES, EXPECTED_PUBLICATION_ROLES)
        value = self.assert_recipe(self.PROFILES[1])
        publication, bridge = value["members"][-2:]
        self.assertEqual(publication["manifest"]["apiVersion"], "catchplate.nativeCustodyExecutionClosure/v1")
        self.assertEqual(bridge["manifest"]["apiVersion"], "catchplate.nativeCustodyExecutionClosure/v2")
        self.assertNotEqual(publication["manifest"]["manifestSha256"], bridge["manifest"]["manifestSha256"])

    def test_successor_selection_is_explicit_and_legacy_default_stays_closed(self):
        legacy = closure_set.set_original(members_fixture())
        self.assertEqual(legacy, closure_set.set_original(members_fixture(), api_version=closure_set.API))
        for api, roles, *_ in self.PROFILES:
            members = self.members(roles)
            raw = closure_set.set_original(members, api_version=api)
            value = closure_set.validate(raw, api_version=api)
            for call in (lambda: closure_set.set_original(members), lambda: closure_set.validate(raw),
                    lambda: closure_set.leaf_binding(value, roles[0]),
                    lambda: closure_set.require_binding(raw, expected_set_root=value["setRootSha256"],
                        expected_seccomp_set_root=value["seccompSetRootSha256"])):
                with self.subTest(api=api), self.assertRaises(ValueError):
                    call()
            with self.assertRaises(ValueError):
                closure_set.validate(legacy, api_version=api)
        for api in (None, False, 2, [], "catchplate.nativeCustodyExecutionClosureSet/v3"):
            with self.subTest(api=api), self.assertRaises(ValueError):
                closure_set.set_original(members_fixture(), api_version=api)

    def test_successor_inventory_rejects_missing_extra_duplicate_and_reordered_members(self):
        for api, roles, *_ in self.PROFILES:
            members = self.members(roles)
            duplicate = copy.deepcopy(members)
            duplicate[1] = copy.deepcopy(duplicate[0])
            reordered = copy.deepcopy(members)
            reordered[0], reordered[1] = reordered[1], reordered[0]
            unknown = copy.deepcopy(members)
            unknown[0]["role"] = "bridge" if api == self.PROFILES[0][0] else "publicationGenesis"
            for changed in (members[:-1], members + [members[0]], duplicate, reordered, unknown):
                with self.subTest(api=api), self.assertRaises(ValueError):
                    closure_set.set_original(changed, api_version=api)

    def test_successor_manifest_profiles_commitments_and_wire_are_not_inferred(self):
        for api, roles, *_ in self.PROFILES:
            members = self.members(roles)
            raw = closure_set.set_original(members, api_version=api)
            for index in (0, len(members) - 1):
                changed = copy.deepcopy(members)
                changed[index]["manifest"] = manifest_fixture("retrieval" if roles[index] == "bridge" else "bridge")
                with self.subTest(api=api, index=index), self.assertRaises(ValueError):
                    closure_set.set_original(changed, api_version=api)
            changed = copy.deepcopy(members)
            changed[0]["manifest"]["buildProvenance"]["sourceTreeSha256"] = synthetic("successor-tamper")
            with self.assertRaises(ValueError):
                closure_set.set_original(changed, api_version=api)
            value = json.loads(raw)
            value["guest"] = {}
            for changed_raw in (raw + b"\n", canonical(value), raw.replace(b'"members":', b'"members":[],"members":', 1)):
                with self.subTest(api=api), self.assertRaises(ValueError):
                    closure_set.validate(changed_raw, api_version=api)
        self.assertEqual(closure_set.MAX_BYTES, 12 * 1024 * 1024)
        self.assertEqual(closure_set.MAX_MANIFEST, 1024 * 1024)
        with self.assertRaises(ValueError):
            closure_set.validate(b" " * (closure_set.MAX_BYTES + 1), api_version=closure_set.GENESIS_API)

    def test_successor_domains_and_both_expected_roots_are_not_interchangeable(self):
        for api, roles, *_ in self.PROFILES:
            members = self.members(roles)
            raw = closure_set.set_original(members, api_version=api)
            value = closure_set.validate(raw, api_version=api)
            for wrong_root, wrong_seccomp in ((synthetic("wrong-set"), value["seccompSetRootSha256"]),
                    (value["setRootSha256"], synthetic("wrong-seccomp")),
                    (value["seccompSetRootSha256"], value["setRootSha256"])):
                with self.assertRaises(ValueError):
                    closure_set.require_binding(raw, api_version=api, expected_set_root=wrong_root,
                        expected_seccomp_set_root=wrong_seccomp)
            old_leaves = [frame("catchplate.nativeCustodyExecutionClosureSetLeaf/v1", [row["role"], row["manifest"]])
                for row in members]
            value["setRootSha256"] = frame("catchplate.nativeCustodyExecutionClosureSetRoot/v1", old_leaves)
            with self.assertRaises(ValueError):
                closure_set.validate(canonical(value), api_version=api)

    def test_preparation_original_selects_exact_api_and_keeps_pin_and_canonical_checks(self):
        legacy = {"apiVersion": preparation.INPUT_API, "members": members_fixture()}
        raw = canonical(legacy)
        self.assertEqual(preparation.prepare(raw, sha(raw)), closure_set.set_original(legacy["members"]))
        for api, roles, *_ in self.PROFILES:
            value = {"apiVersion": "catchplate.nativePilotClosureSetPreparation/v2",
                "setApiVersion": api, "members": self.members(roles)}
            raw = canonical(value)
            self.assertEqual(preparation.prepare(raw, sha(raw)), closure_set.set_original(value["members"], api_version=api))
            cases = [dict(value, apiVersion=preparation.INPUT_API), dict(value, setApiVersion=closure_set.API),
                dict(value, setApiVersion=None), dict(value, guest={}),
                {key: item for key, item in value.items() if key != "setApiVersion"},
                {"apiVersion": preparation.INPUT_API, "members": value["members"]}]
            for changed in cases:
                changed_raw = canonical(changed)
                with self.subTest(api=api), self.assertRaises(ValueError):
                    preparation.prepare(changed_raw, sha(changed_raw))
            with self.assertRaises(ValueError):
                preparation.prepare(raw, synthetic("not-the-pinned-original"))
            for changed_raw in (raw + b"\n", raw.replace(b'"setApiVersion":', b'"setApiVersion":null,"setApiVersion":', 1)):
                with self.assertRaises(ValueError):
                    preparation.prepare(changed_raw, sha(changed_raw))

    def test_successor_schemas_match_exact_closed_profile_selection(self):
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        names = ("native-custody-closure.v1.schema.json", "native-custody-closure.v2.schema.json",
            "native-custody-execution-closure-set.v1.schema.json", "native-custody-execution-closure-set.v2.schema.json",
            "native-publication-genesis-closure-set.v1.schema.json", "native-pilot-closure-set-preparation.v1.schema.json",
            "native-pilot-closure-set-preparation.v2.schema.json")
        schemas = {name: json.loads((ROOT / "schemas" / name).read_text()) for name in names}
        registry = Registry().with_resources((value["$id"], Resource.from_contents(value)) for value in schemas.values())
        for value in schemas.values():
            Draft202012Validator.check_schema(value)
        prepared_schema = schemas["native-pilot-closure-set-preparation.v2.schema.json"]
        for profile, schema_name in zip(self.PROFILES, ("native-publication-genesis-closure-set.v1.schema.json",
                "native-custody-execution-closure-set.v2.schema.json"), strict=True):
            api, roles, *_ = profile
            value = closure_set.validate(closure_set.set_original(self.members(roles), api_version=api), api_version=api)
            validator = Draft202012Validator(schemas[schema_name], registry=registry)
            validator.validate(value)
            prepared = {"apiVersion": preparation.SUCCESSOR_INPUT_API, "setApiVersion": api, "members": value["members"]}
            preparation_validator = Draft202012Validator(prepared_schema, registry=registry)
            preparation_validator.validate(prepared)
            changed = copy.deepcopy(value)
            changed["members"][0], changed["members"][1] = changed["members"][1], changed["members"][0]
            self.assertTrue(list(validator.iter_errors(changed)))
            self.assertTrue(list(preparation_validator.iter_errors(dict(prepared, setApiVersion=closure_set.API))))
            self.assertTrue(list(preparation_validator.iter_errors(dict(prepared, members=changed["members"]))))
            legacy_validator = Draft202012Validator(schemas["native-custody-execution-closure-set.v1.schema.json"], registry=registry)
            self.assertTrue(list(legacy_validator.iter_errors(value)))


class AssignmentClosureContractTests(unittest.TestCase):
    def setUp(self):
        # Give retrieval a genuinely different static policy commitment so
        # endpoint-vs-bridge confusion cannot pass on coincidentally equal hashes.
        members = members_fixture()
        members[0]["manifest"] = manifest_fixture("retrieval", read_allowed=True)
        self.raw = closure_set.set_original(members)
        self.selected = closure_set.validate(self.raw)
        self.v1 = assignment_fixture(self.selected, version=1)
        self.v2 = assignment_fixture(self.selected, version=2)

    def test_explicit_assignment_versions_preserve_v1_shape(self):
        for version, envelope in ((1, self.v1), (2, self.v2)):
            with self.subTest(version=version):
                self.assertEqual(len(envelope), 10)
                self.assertEqual(len(envelope["payload"]), 16 if version == 1 else 17)
                self.assertEqual(assignment_profile.shape(envelope), envelope)
                self.assertEqual(assignment_profile.version(envelope), version)
                self.assertEqual(assignment_profile.domain(envelope), "catchplate.policyShadowAssignment/v" + str(version))
                self.assertEqual(launch.shape("native-bridge-assignment", canonical(envelope)), envelope)
        self.assertEqual(opening.assignment_payload(self.v1["payload"]), self.v1["payload"])
        with self.assertRaises(ValueError):
            opening.assignment_payload(self.v2["payload"])  # explicit version2 is required
        self.assertEqual(opening.assignment_payload(self.v2["payload"], version=2), self.v2["payload"])
        legacy = {name: value for name, value in self.v1["payload"].items()
            if name not in ("custodyAuthority", "authorityKeyIndependence")}
        self.assertEqual(len(legacy), 14)
        self.assertEqual(opening.assignment_payload(legacy), legacy)
        with self.assertRaises(ValueError):
            opening.assignment_payload(legacy, version=2)

    def test_assignment_null_missing_extra_and_mixed_versions_reject(self):
        cases = []
        for binding in (None, {}, {"setRootSha256": self.selected["setRootSha256"]},
                        {"setRootSha256": None, "seccompSetRootSha256": self.selected["seccompSetRootSha256"]}):
            changed = copy.deepcopy(self.v2)
            changed["payload"]["nativeClosureSet"] = binding
            cases.append(rehash_payload(changed))
        missing = copy.deepcopy(self.v2)
        del missing["payload"]["nativeClosureSet"]
        cases.append(rehash_payload(missing))
        extra = copy.deepcopy(self.v2)
        extra["payload"]["nativeClosureSet"]["manifestSha256"] = synthetic("unexpected-leaf")
        cases.append(rehash_payload(extra))
        for original, field, replacement in ((self.v1, "apiVersion", self.v2["apiVersion"]),
                (self.v2, "apiVersion", self.v1["apiVersion"]),
                (self.v1, "signatureDomain", self.v2["signatureDomain"]),
                (self.v2, "signatureDomain", self.v1["signatureDomain"]),
                (self.v2, "apiVersion", "catchplate.policyShadowAssignment/v3")):
            changed = copy.deepcopy(original)
            changed[field] = replacement
            cases.append(changed)
        extra_v1 = copy.deepcopy(self.v1)
        extra_v1["payload"]["nativeClosureSet"] = None
        cases.append(rehash_payload(extra_v1))
        for index, envelope in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                assignment_profile.shape(envelope)

    def test_both_roots_are_in_signature_preimage_and_member_join(self):
        original_message = assignment_profile.p.preimage(assignment_profile.domain(self.v2), self.v2["payload"])
        expected = (b"catchplate.signedEnvelope/v1\0catchplate.policyShadowAssignment/v2\0"
            b"catchplate.canonicalJson/ascii-integer-v1\0" + canonical(self.v2["payload"]))
        self.assertEqual(original_message, expected)
        self.assertNotEqual(original_message,
            assignment_profile.p.preimage(assignment_profile.domain(self.v1), self.v1["payload"]))
        binding = assignment_profile.closure_binding(self.v2, self.raw, "retrieval")
        self.assertEqual(binding["manifestSha256"], self.selected["members"][0]["manifest"]["manifestSha256"])
        self.assertNotEqual(binding["manifestSha256"], self.v2["payload"]["custodyAuthority"]["executionClosureManifestSha256"])
        for field in ("setRootSha256", "seccompSetRootSha256"):
            changed = copy.deepcopy(self.v2)
            changed["payload"]["nativeClosureSet"][field] = synthetic("changed-signed/" + field)
            with self.subTest(stale_payload_hash=field), self.assertRaises(ValueError):
                assignment_profile.shape(changed)
            rehash_payload(changed)
            self.assertNotEqual(original_message,
                assignment_profile.p.preimage(assignment_profile.domain(changed), changed["payload"]))
            with self.subTest(member_root=field), self.assertRaises(ValueError):
                assignment_profile.closure_binding(changed, self.raw, "retrieval")
        with self.assertRaises(ValueError):
            assignment_profile.closure_binding(self.v1, self.raw, "retrieval")

    def test_legacy_bridge_anchors_cannot_be_endpoint_leaves_or_set_roots(self):
        endpoint = self.selected["members"][0]["manifest"]
        replacements = (
            ("executionClosureManifestSha256", endpoint["manifestSha256"]),
            ("executionClosureManifestSha256", self.selected["setRootSha256"]),
            ("structurallyVerifiedSeccompPolicySha256", endpoint["seccompPolicy"]["structurallyVerifiedPolicySha256"]),
            ("structurallyVerifiedSeccompPolicySha256", self.selected["seccompSetRootSha256"]),
        )
        for field, value in replacements:
            changed = copy.deepcopy(self.v2)
            changed["payload"]["custodyAuthority"][field] = value
            rehash_payload(changed)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                assignment_profile.closure_binding(changed, self.raw, "retrieval")

    def test_canonical_assignment_original_and_duplicate_fields(self):
        raw = canonical(self.v2)
        cases = (raw + b"\n", b" " + raw, json.dumps(self.v2, indent=2).encode("ascii"),
            raw.replace(b'"nativeClosureSet":', b'"nativeClosureSet":null,"nativeClosureSet":', 1),
            raw.replace(b'"setRootSha256":', b'"setRootSha256":null,"setRootSha256":', 1))
        for index, changed in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                launch.shape("native-bridge-assignment", changed)

    def test_legacy_closures_and_v3_each_select_the_exact_role(self):
        for role in EXPECTED_ROLES:
            for multi in (False, True):
                value = closure_fixture(self.selected, role=role, multi=multi)
                with self.subTest(role=role, multi=multi):
                    self.assertEqual(len(value), 4 if multi else 3)
                    self.assertEqual(launch.shape("native-" + role + "-closure", canonical(value)), value)
        wrong = closure_fixture(self.selected, role="retrieval")
        with self.assertRaises(ValueError):
            launch.shape("native-persistence-closure", canonical(wrong))

    def test_v3_closure_null_missing_member_hash_and_mixed_versions_reject(self):
        original = closure_fixture(self.selected)
        cases = []
        for field in ("guestRole", "setRootSha256", "seccompSetRootSha256", "leafSha256"):
            changed = copy.deepcopy(original)
            changed["authorization"]["payload"][field] = "persistence" if field == "guestRole" else synthetic("wrong/" + field)
            cases.append(changed)
        for name in ("apiVersion", "purpose", "profile"):
            changed = copy.deepcopy(original)
            changed["authorization"]["payload"][name] = closure_fixture(self.selected, multi=False)["authorization"]["payload"][name]
            cases.append(changed)
        missing = copy.deepcopy(original)
        del missing["closureSet"]
        cases.append(missing)
        null = copy.deepcopy(original)
        null["closureSet"] = None
        cases.append(null)
        stale = copy.deepcopy(original)
        stale["manifest"]["runtimeConfigurationSha256"] = synthetic("tampered-member")
        cases.append(stale)
        legacy = copy.deepcopy(original)
        legacy["apiVersion"] = "catchplate.nativeCustodyClosure/v1"
        cases.append(legacy)
        for index, value in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                launch.shape("native-retrieval-closure", canonical(value))


class ScopeReceiptContractTests(unittest.TestCase):
    def setUp(self):
        self.selected = closure_set.validate(closure_set.set_original(members_fixture()))
        self.v1 = assignment_fixture(self.selected, version=1)
        self.v2 = assignment_fixture(self.selected, version=2)
        self.receipt = canonical({"fixture": "SYNTHETIC RECEIPT BYTES ONLY"})

    def test_v2_exact17_scope_13_value_hash_and_8_value_receipt(self):
        scope = scope_fixture(self.v2)
        self.assertEqual(len(scope), 17)
        self.assertEqual(retrieval.SCOPE_VALUES, EXPECTED_SCOPE_VALUES)
        self.assertEqual(retrieval.SCOPE_SET_VALUES, EXPECTED_SCOPE_ROOTS)
        values = [scope[name] for name in EXPECTED_SCOPE_VALUES + EXPECTED_SCOPE_ROOTS]
        self.assertEqual(len(values), 13)
        expected_hash = frame("catchplate.policyShadowProductionCustodyProofScope/v2", values)
        self.assertEqual(scope["binding_sha256"], expected_hash)
        self.assertEqual(retrieval.scope_original(canonical(scope)), scope)
        expected = ["catchplate.policyShadowAssignmentBoundCustodyReceipt/v2", expected_hash,
            scope["execution_closure_manifest_sha256"], scope["structurally_verified_seccomp_policy_sha256"],
            scope["execution_closure_set_root_sha256"], scope["structurally_verified_seccomp_set_root_sha256"],
            "ingress-admission", sha(self.receipt)]
        self.assertEqual(len(expected), 8)
        self.assertEqual(retrieval._authority(scope, "ingress-admission", self.receipt), canonical(expected))
        actual = opening.receipt_authority_payload(assignment=self.v2["payload"],
            assignment_payload_sha256=self.v2["payloadSha256"],
            configuration_binding_sha256=scope["production_configuration_binding_sha256"],
            key_root=scope["asserted_custody_key_set_root_sha256"], role="ingress-admission", receipt_payload=self.receipt)
        self.assertEqual(actual, expected)
        self.assertEqual(retrieval.require_assignment_scope(scope, canonical(self.v2["payload"])), self.v2["payload"])

    def test_v1_keeps_14_fields_11_value_hash_and_6_value_receipt(self):
        scope = scope_fixture(self.v1)
        self.assertEqual(len(scope), 14)
        values = [scope[name] for name in EXPECTED_SCOPE_VALUES]
        self.assertEqual(len(values), 11)
        expected_hash = frame("catchplate.policyShadowProductionCustodyProofScope/v1", values)
        self.assertEqual(scope["binding_sha256"], expected_hash)
        self.assertEqual(retrieval.scope_original(canonical(scope)), scope)
        expected = ["catchplate.policyShadowAssignmentBoundCustodyReceipt/v1", expected_hash,
            scope["execution_closure_manifest_sha256"], scope["structurally_verified_seccomp_policy_sha256"],
            "ingress-admission", sha(self.receipt)]
        self.assertEqual(len(expected), 6)
        self.assertEqual(retrieval._authority(scope, "ingress-admission", self.receipt), canonical(expected))
        self.assertEqual(opening.receipt_authority_payload(assignment=self.v1["payload"],
            assignment_payload_sha256=self.v1["payloadSha256"],
            configuration_binding_sha256=scope["production_configuration_binding_sha256"],
            key_root=scope["asserted_custody_key_set_root_sha256"], role="ingress-admission", receipt_payload=self.receipt), expected)

    def test_v2_scope_missing_null_wrong_version_or_old_hash_reject(self):
        original = scope_fixture(self.v2)
        cases = []
        for name in ("api_version",) + EXPECTED_SCOPE_ROOTS:
            missing = copy.deepcopy(original)
            del missing[name]
            cases.append(missing)
            null = copy.deepcopy(original)
            null[name] = None
            cases.append(null)
        for version in ("v1", "v3"):
            changed = copy.deepcopy(original)
            changed["api_version"] = "catchplate.policyShadowProductionCustodyProofScope/" + version
            cases.append(changed)
        old_hash = copy.deepcopy(original)
        old_hash["binding_sha256"] = frame("catchplate.policyShadowProductionCustodyProofScope/v1",
            [original[name] for name in EXPECTED_SCOPE_VALUES])
        cases.append(old_hash)
        for index, scope in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                retrieval.scope_original(canonical(scope))

    def test_v2_roots_remain_assignment_bound_after_local_hash_recompute(self):
        original = scope_fixture(self.v2)
        for field in EXPECTED_SCOPE_ROOTS:
            changed = copy.deepcopy(original)
            changed[field] = synthetic("changed-proof/" + field)
            with self.subTest(stale_scope_hash=field), self.assertRaises(ValueError):
                retrieval.scope_original(canonical(changed))
            changed["binding_sha256"] = frame("catchplate.policyShadowProductionCustodyProofScope/v2",
                [changed[name] for name in EXPECTED_SCOPE_VALUES + EXPECTED_SCOPE_ROOTS])
            self.assertEqual(retrieval.scope_original(canonical(changed)), changed)
            with self.subTest(assignment_join=field), self.assertRaises(ValueError):
                retrieval.require_assignment_scope(changed, canonical(self.v2["payload"]))
            self.assertNotEqual(retrieval._authority(changed, "ingress-admission", self.receipt),
                retrieval._authority(original, "ingress-admission", self.receipt))
        with self.assertRaises(ValueError):
            retrieval.require_assignment_scope(original, canonical(self.v1["payload"]))

    def test_v2_admitted_endpoint_leaf_is_not_reinterpreted_as_bridge_anchor(self):
        scope = scope_fixture(self.v2)
        endpoint = self.selected["members"][0]["manifest"]
        admitted = {"assignmentId": scope["assignment_id"], "assignmentPayloadSha256": scope["assignment_payload_sha256"],
            "assignmentRevision": scope["assignment_revision"], "fullKeySetRootSha256": scope["asserted_custody_key_set_root_sha256"],
            "executionClosureManifestSha256": endpoint["manifestSha256"],
            "structurallyVerifiedSeccompPolicySha256": endpoint["seccompPolicy"]["structurallyVerifiedPolicySha256"]}
        self.assertNotEqual(admitted["executionClosureManifestSha256"], scope["execution_closure_manifest_sha256"])
        retrieval.require_admitted_scope(scope, admitted, assignment_payload_original=canonical(self.v2["payload"]))
        with self.assertRaises(ValueError):
            retrieval.require_admitted_scope(scope, admitted)  # no unsigned-hash shortcut
        legacy = scope_fixture(self.v1)
        legacy_admitted = dict(admitted, assignmentPayloadSha256=legacy["assignment_payload_sha256"])
        with self.assertRaises(ValueError):
            retrieval.require_admitted_scope(legacy, legacy_admitted)


if __name__ == "__main__":
    unittest.main(verbosity=2)

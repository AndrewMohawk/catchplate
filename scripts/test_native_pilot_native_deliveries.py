#!/usr/bin/env python3
"""Pure seven-endpoint controls using deliberately synthetic public originals.

Real deterministic test-key signatures exercise the existing wire verifiers;
none is an independently approved original, live owner or provenance statement.
No signer entrypoint, credential read, process creation, installation or clock
syscall is invoked. The reused assignment fixture deliberately leaves unrelated
policy fields empty and is not a complete native runtime-admission fixture.
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))
from catchplate import native_pilot_closure_set as closure_set
from catchplate import native_pilot_native_delivery_profile as profile
from test_native_pilot_closure_set import (EXPECTED_SCOPE_ROOTS, EXPECTED_SCOPE_VALUES,
    MANIFEST_FIELDS, canonical, frame, scope_fixture, sha, synthetic)
from test_native_pilot_generation_scope import (ASSIGNMENT_DOMAIN, NOW, encoded,
    fixture as scope_inputs, key_fixture, signed_message)

ROLES = ("generationInstall", "commitRequest", "ingressAdmission", "terminalAppend",
    "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
ALL_ROLES = ("retrieval", "persistence", "trustedTime") + ROLES
INPUT_FIELDS = ("apiVersion", "role", "configurationOriginal", "ownerConfigurationOriginal",
    "windowOriginal", "observationOriginal", "runtimeOriginal", "payloadOriginal", "activationOriginal")
WINDOW_FIELDS = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")
PRECREATION_DOMAIN = b"catchplate.nativeShadowProofCohortPrecreation.signature/v1\0"
DELIVERY_DOMAIN = b"catchplate.policyCustodyGuestDelivery.signature/v1\0"
ACTIVATION = {
    "generationInstall": (("shadow-generation-install-listener", stat.S_IFSOCK),
        ("generation-install-journal", stat.S_IFDIR)),
    "commitRequest": (("commit-request-listener", stat.S_IFSOCK),),
    "ingressAdmission": (("ingress-admission-listener", stat.S_IFSOCK),),
    "terminalAppend": (("terminal-append-listener", stat.S_IFSOCK),),
    "dispatchBarrier": (("dispatch-barrier-listener", stat.S_IFSOCK),),
    "activeEffectBarrier": (("active-effect-barrier-listener", stat.S_IFSOCK),),
    "activeEffectCommit": (("active-effect-commit-listener", stat.S_IFSOCK),),
}


def cold_key(label):
    key, public = key_fixture("native-delivery/" + label)
    raw = base64.urlsafe_b64decode(public["publicKeyBase64url"] + "==")
    return key, {"publicKeyBase64url": encoded(raw), "keyId": sha(raw)}


def bind_set(f, selected):
    """Re-sign a test assignment and independently refresh its measured hashes."""
    raw = closure_set.set_original(selected["members"])
    selected = json.loads(raw)
    originals, measured = f["recipe_originals"], f["measured"]
    envelope = json.loads(originals["assignmentOriginal"])
    envelope["payload"]["nativeClosureSet"] = {
        name: selected[name] for name in ("setRootSha256", "seccompSetRootSha256")}
    envelope["payloadSha256"] = sha(canonical(envelope["payload"]))
    envelope["signature"] = encoded(key_fixture("assignment")[0].sign(
        signed_message(ASSIGNMENT_DOMAIN, envelope["payload"])))
    originals.update(assignmentOriginal=canonical(envelope).decode("ascii"),
        closureSetOriginal=raw.decode("ascii"))
    binding = json.loads(measured["configurationBindingOriginal"])
    binding.update(assignmentPayloadSha256=envelope["payloadSha256"],
        nativeClosureSet=copy.deepcopy(envelope["payload"]["nativeClosureSet"]))
    binding_sha = frame("catchplate.policyShadowProductionCustodyConfiguration/v2", binding)
    proof = scope_fixture(envelope)
    proof["production_configuration_binding_sha256"] = binding_sha
    proof["binding_sha256"] = frame("catchplate.policyShadowProductionCustodyProofScope/v2",
        [proof[name] for name in EXPECTED_SCOPE_VALUES + EXPECTED_SCOPE_ROOTS])
    measured.update(configurationBindingOriginal=canonical(binding).decode("ascii"),
        configurationBindingSha256=binding_sha, proofScopeOriginal=canonical(proof).decode("ascii"))
    measured["production"]["expectedConfigurationBindingSha256"] = binding_sha


def refresh_window(f):
    signed = {"apiVersion": "catchplate.nativeShadowProofCohortPrecreation/v1", "payload": f["window"],
        "signatureBase64url": encoded(f["key"].sign(PRECREATION_DOMAIN + canonical(f["window"])))}
    f["window_raw"] = canonical(signed)
    f["observed"]["precreationSha256"] = sha(f["window_raw"])
    f["observation_raw"] = canonical(f["observed"])


def fixture():
    _, existing, _ = scope_inputs()
    key, authority = cold_key("cohort")
    f = {"key": key, "authority": authority, "cold": {}, "fragment": {}, "activations": {},
        "measured": existing["measured"], "recipe_originals": existing["recipe_originals"],
        "boot": (encoded(b"0123456789abcdef"), 4, 5), "now_boottime_ns": 2_000_000_000}
    for index, role in enumerate(ALL_ROLES):
        cold = {"apiVersion": "catchplate.policyCustodyGuestConfiguration/v1", "authority": authority,
            "serviceRole": "production-bridge", "uid": 62000 + index, "gid": 62000 + index}
        f["cold"][role] = canonical(cold).decode("ascii")
        if role not in ROLES:
            continue
        runtime = canonical({"apiVersion": "catchplate.nativePilotEndpointRuntime/v1", "role": role})
        signing = cold_key("credential/" + role)[1]
        f["fragment"][role] = {"runtimeOriginal": runtime.decode("ascii"),
            "runtimeConfig": {"path": "/etc/catchplate/native-pilot-inputs/native-runtime-" + role + ".json",
                "sha256": sha(runtime)}, "credentials": [
                {"name": "synthetic-public-policy", "original": {
                    "path": "/etc/catchplate/synthetic-" + role + "-policy.json", "sha256": synthetic(role + "/policy")},
                    "length": 128, "signing": None},
                {"name": "synthetic-private-seed-metadata", "original": {
                    "path": "/etc/catchplate/synthetic-" + role + "-seed", "sha256": synthetic(role + "/seed")},
                    "length": 32, "signing": signing}]}
        f["activations"][role] = [{"name": name, "fd": ordinal, "device": 7,
            "inode": 1000 + index * 10 + ordinal, "mode": kind | (0o700 if kind == stat.S_IFDIR else 0o600),
            "uid": cold["uid"], "gid": cold["gid"]}
            for ordinal, (name, kind) in enumerate(ACTIVATION[role], 6)]
    selected = json.loads(f["recipe_originals"]["closureSetOriginal"])
    for member in selected["members"]:
        if member["role"] in ROLES:
            manifest = member["manifest"]
            manifest["runtimeConfigurationSha256"] = sha(f["fragment"][member["role"]]["runtimeOriginal"].encode("ascii"))
            manifest["manifestSha256"] = frame(manifest["apiVersion"], [manifest[name] for name in MANIFEST_FIELDS[:-1]])
    bind_set(f, selected)
    external = {"configurationSha256": sha(existing["bootstrap_configuration_original"]),
        "windowSha256": synthetic("native-delivery/driver-window"),
        "observationSha256": sha(existing["driver_observation_original"]),
        "supervisorExecutableSha256": synthetic("native-delivery/supervisor")}
    f["config"] = {"apiVersion": "catchplate.nativeShadowProofCohortConfiguration/v7", "authority": authority,
        "executableSha256": synthetic("native-delivery/endpoint-executable"), "externalDriver": external,
        "cleanup": {"authority": cold_key("cleanup")[1], "scopeId": synthetic("cleanup-scope"),
            "genesisSha256": synthetic("cleanup-genesis"),
            "journal": {"device": 7, "inode": 9, "mode": stat.S_IFDIR | 0o700, "uid": 0, "gid": 0}},
        **{role + "Configuration": {"path": "/etc/catchplate/native-pilot-inputs/native-cold-" + role + ".json",
            "sha256": sha(raw.encode("ascii"))} for role, raw in f["cold"].items()}}
    f["owner_configuration_raw"] = canonical(f["config"])
    f["window"] = {"configurationSha256": sha(f["owner_configuration_raw"]), "authorityKeyId": authority["keyId"],
        "bootIdBase64url": f["boot"][0], "timeNamespaceDevice": 4, "timeNamespaceInode": 5,
        "issuedAtBoottimeNs": "1000000000", "startupDeadlineBoottimeNs": "20000000000",
        "lifetimeDeadlineBoottimeNs": "60000000000", "invocationId": "1" * 32}
    f["observed"] = {"apiVersion": "catchplate.nativeShadowProofCohortOriginals/v6",
        "configurationSha256": sha(f["owner_configuration_raw"]), "invocationId": "1" * 32,
        **{role: {"processId": 100 + index, "startTimeTicks": 200 + index,
            "executable": {"device": 7, "inode": 500 + index, "length": 4096,
                "sha256": f["config"]["executableSha256"]}} for index, role in enumerate(ALL_ROLES)},
        "externalDriver": {"apiVersion": "catchplate.nativeShadowEndpointDriverOriginal/v1",
            "bindingSha256": synthetic("native-delivery/external-binding"),
            **{name: external[name] for name in ("configurationSha256", "windowSha256", "observationSha256")},
            "supervisor": {"processId": 42, "startTimeTicks": 99, "pidfdDevice": 0, "pidfdInode": 77},
            "driver": {"processId": 43, "startTimeTicks": 100, "pidfdDevice": 0, "pidfdInode": 101},
            "executable": {"device": 7, "inode": 19, "length": 4096, "sha256": synthetic("driver-executable")}}}
    refresh_window(f)
    return f


def arguments(f, role):
    return {"fragment": f["fragment"], "configuration_raw": f["cold"][role].encode("ascii"),
        **{name: f[name] for name in ("owner_configuration_raw", "window_raw", "observation_raw",
            "measured", "recipe_originals", "boot", "now_boottime_ns")},
        "activation": f["activations"][role], "now_unix_ns": NOW}


def result_for(f, role, input_raw, *, payload=None, key=None):
    selected = json.loads(json.loads(input_raw)["payloadOriginal"]) if payload is None else payload
    raw = canonical({"apiVersion": "catchplate.policyCustodyGuestDelivery/v1", "payload": selected,
        "signatureBase64url": encoded((key or f["key"]).sign(DELIVERY_DOMAIN + canonical(selected)))})
    return {"original": raw.decode("ascii"), "sha256": sha(raw),
        "pin": {"path": "/etc/catchplate/native-pilot-inputs/native-delivery-" + role + ".json", "sha256": sha(raw)}}


class NativeDeliveryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()

    def setUp(self):
        # cryptography keys are immutable; do not copy their native handles.
        self.f = {name: value if name == "key" else copy.deepcopy(value) for name, value in self.original.items()}

    def test_exact_seven_role_policy_returns_independent_copy(self):
        self.assertEqual(profile.ROLES, ROLES)
        checked = profile.validate_policy(self.f["fragment"], native_cold_originals=self.f["cold"])
        self.assertEqual(tuple(checked), ROLES)
        self.assertEqual(checked, self.f["fragment"])
        checked[ROLES[0]]["credentials"][0]["length"] = 1
        self.assertEqual(self.f["fragment"][ROLES[0]]["credentials"][0]["length"], 128)

    def test_role_inventory_and_row_grammar_are_closed(self):
        cases = []
        missing = copy.deepcopy(self.f["fragment"]); missing.pop(ROLES[0]); cases.append(missing)
        extra = copy.deepcopy(self.f["fragment"]); extra["retrieval"] = extra[ROLES[0]]; cases.append(extra)
        null = copy.deepcopy(self.f["fragment"]); null[ROLES[0]] = None; cases.append(null)
        row = copy.deepcopy(self.f["fragment"]); row[ROLES[0]]["approval"] = True; cases.append(row)
        for candidate in cases:
            with self.subTest(candidate=list(candidate)), self.assertRaises(ValueError):
                profile.validate_policy(candidate, native_cold_originals=self.f["cold"])

    def test_runtime_pin_marker_and_role_cannot_be_substituted(self):
        for change in ("path", "hash", "role", "extra", "newline", "null"):
            selected = copy.deepcopy(self.f["fragment"]); row = selected[ROLES[0]]
            if change == "path": row["runtimeConfig"]["path"] = "/etc/catchplate/unselected.json"
            elif change == "hash": row["runtimeConfig"]["sha256"] = synthetic("wrong-runtime")
            else:
                marker = json.loads(row["runtimeOriginal"])
                if change == "role": marker["role"] = ROLES[1]
                elif change == "extra": marker["configuration"] = {}
                elif change == "null": marker["role"] = None
                row["runtimeOriginal"] = canonical(marker).decode("ascii") + ("\n" if change == "newline" else "")
                row["runtimeConfig"]["sha256"] = sha(row["runtimeOriginal"].encode("ascii"))
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.validate_policy(selected, native_cold_originals=self.f["cold"])

    def test_metadata_is_bounded_nonempty_and_signer_separated(self):
        for change in ("empty", "duplicate", "bool-length", "too-long", "relative", "same-key", "extra"):
            selected = copy.deepcopy(self.f["fragment"]); entries = selected[ROLES[0]]["credentials"]
            if change == "empty": entries.clear()
            elif change == "duplicate": entries.append(copy.deepcopy(entries[0]))
            elif change == "bool-length": entries[0]["length"] = True
            elif change == "too-long": entries[0]["length"] = 4 * 1024 * 1024 + 1
            elif change == "relative": entries[0]["original"]["path"] = "relative.json"
            elif change == "same-key": entries[1]["signing"] = self.f["authority"]
            else: entries[0]["secret"] = "not-accepted"
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.validate_policy(selected, native_cold_originals=self.f["cold"])

    def test_all_seven_inputs_and_real_fixed_result_signatures(self):
        for role in ROLES:
            with self.subTest(role=role):
                raw = profile.build(role, **arguments(self.f, role)); value = json.loads(raw)
                self.assertEqual(set(value), set(INPUT_FIELDS)); self.assertEqual(len(value), 9)
                self.assertEqual(value["apiVersion"], "catchplate.nativePilotDeliverySigningInput/v1")
                self.assertEqual(value["role"], role)
                for field in ("ownerConfigurationOriginal", "windowOriginal", "observationOriginal"):
                    source = {"ownerConfigurationOriginal": "owner_configuration_raw", "windowOriginal": "window_raw",
                        "observationOriginal": "observation_raw"}[field]
                    self.assertEqual(value[field].encode("ascii"), self.f[source])
                payload = json.loads(value["payloadOriginal"])
                cold = json.loads(self.f["cold"][role])
                expected = {"configurationSha256": sha(self.f["cold"][role].encode("ascii")),
                    "authorityKeyId": self.f["authority"]["keyId"],
                    **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
                    **{name: self.f["window"][name] for name in WINDOW_FIELDS},
                    "runtimeConfig": self.f["fragment"][role]["runtimeConfig"],
                    "credentials": self.f["fragment"][role]["credentials"], "activation": self.f["activations"][role]}
                self.assertEqual(payload, expected)
                self.assertEqual(value["activationOriginal"], canonical(expected["activation"]).decode("ascii"))
                result = result_for(self.f, role, raw)
                self.assertEqual(profile.checked_result(role, raw, result), result["original"].encode("ascii"))

    def test_cold_and_observation_originals_are_not_replaceable(self):
        for change in ("cold-role", "observed-config", "duplicate-pid", "duplicate-executable", "executable-hash"):
            args = arguments(self.f, ROLES[0]); observed = copy.deepcopy(self.f["observed"])
            if change == "cold-role": args["configuration_raw"] = self.f["cold"][ROLES[1]].encode("ascii")
            elif change == "observed-config": observed["configurationSha256"] = synthetic("other-config")
            elif change == "duplicate-pid": observed[ROLES[0]]["processId"] = observed[ROLES[1]]["processId"]
            elif change == "duplicate-executable": observed[ROLES[0]]["executable"] = observed[ROLES[1]]["executable"]
            else: observed[ROLES[0]]["executable"]["sha256"] = synthetic("other-executable")
            args["observation_raw"] = canonical(observed)
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.build(ROLES[0], **args)

    def test_activation_descriptor_inventory_is_fixed(self):
        for change in ("name", "fd", "kind", "duplicate", "extra"):
            args = arguments(self.f, ROLES[0]); activation = copy.deepcopy(args["activation"])
            if change == "name": activation[0]["name"] = "commit-request-listener"
            elif change == "fd": activation[0]["fd"] = 9
            elif change == "kind": activation[1]["mode"] = stat.S_IFREG | 0o700
            elif change == "duplicate": activation[1]["inode"] = activation[0]["inode"]
            else: activation.append(copy.deepcopy(activation[1]))
            args["activation"] = activation
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.build(ROLES[0], **args)

    def test_original_boot_and_startup_window_are_not_renewed(self):
        for change in ("before-issued", "at-startup", "boot", "over-thirty-seconds"):
            args = arguments(self.f, ROLES[0])
            if change == "before-issued": args["now_boottime_ns"] = 999_999_999
            elif change == "at-startup": args["now_boottime_ns"] = 20_000_000_000
            elif change == "boot": args["boot"] = (encoded(b"fedcba9876543210"), 4, 5)
            else:
                f = {name: value if name == "key" else copy.deepcopy(value) for name, value in self.f.items()}
                f["window"]["startupDeadlineBoottimeNs"] = "31000000001"
                refresh_window(f); args = arguments(f, ROLES[0])
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.build(ROLES[0], **args)
        raw = profile.build(ROLES[0], **arguments(self.f, ROLES[0]))
        for field in WINDOW_FIELDS[3:6]:
            value = json.loads(raw); payload = json.loads(value["payloadOriginal"])
            payload[field] = str(int(payload[field]) + 1)
            value["payloadOriginal"] = canonical(payload).decode("ascii")
            changed = canonical(value)
            with self.subTest(extended=field), self.assertRaises(ValueError):
                profile.checked_result(ROLES[0], changed, result_for(self.f, ROLES[0], changed))

    def test_precreation_signature_and_literal_observation_pin_are_required(self):
        args = arguments(self.f, ROLES[0]); signed = json.loads(args["window_raw"])
        signed["signatureBase64url"] = encoded(cold_key("wrong-precreation")[0].sign(
            PRECREATION_DOMAIN + canonical(signed["payload"])))
        args["window_raw"] = canonical(signed)
        with self.assertRaises(InvalidSignature): profile.build(ROLES[0], **args)
        args = arguments(self.f, ROLES[0]); observed = copy.deepcopy(self.f["observed"])
        observed["precreationSha256"] = synthetic("wrong-precreation-original")
        args["observation_raw"] = canonical(observed)
        with self.assertRaises(ValueError): profile.build(ROLES[0], **args)

    def test_result_signature_payload_hash_pin_and_role_are_checked(self):
        role = ROLES[0]; raw = profile.build(role, **arguments(self.f, role))
        wrong = result_for(self.f, role, raw, key=cold_key("wrong-result")[0])
        with self.assertRaises(InvalidSignature): profile.checked_result(role, raw, wrong)
        payload = json.loads(json.loads(raw)["payloadOriginal"]); payload["uid"] += 1
        with self.assertRaises(ValueError):
            profile.checked_result(role, raw, result_for(self.f, role, raw, payload=payload))
        for change in ("hash", "pin-hash", "pin-path", "extra"):
            result = result_for(self.f, role, raw)
            if change == "hash": result["sha256"] = synthetic("wrong-result-hash")
            elif change == "pin-hash": result["pin"]["sha256"] = synthetic("wrong-pin-hash")
            elif change == "pin-path": result["pin"]["path"] = "/etc/catchplate/unselected.json"
            else: result["approved"] = True
            with self.subTest(change=change), self.assertRaises(ValueError): profile.checked_result(role, raw, result)
        with self.assertRaises(ValueError): profile.checked_result(ROLES[1], raw, result_for(self.f, role, raw))

    def test_each_role_runtime_binds_its_signed_leaf_not_the_bridge_anchor(self):
        for role in ROLES:
            self.assertIsNone(profile.require_runtime_bindings(role,
                runtime_raw=self.f["fragment"][role]["runtimeOriginal"].encode("ascii"), measured=self.f["measured"],
                recipe_originals=self.f["recipe_originals"], now_unix_ns=NOW))
        original_bridge = json.loads(self.f["recipe_originals"]["assignmentOriginal"])["payload"]["custodyAuthority"][
            "executionClosureManifestSha256"]
        selected = json.loads(self.f["recipe_originals"]["closureSetOriginal"])
        member = next(row for row in selected["members"] if row["role"] == ROLES[0])
        member["manifest"]["runtimeConfigurationSha256"] = self.f["fragment"][ROLES[1]]["runtimeConfig"]["sha256"]
        manifest = member["manifest"]
        manifest["manifestSha256"] = frame(manifest["apiVersion"], [manifest[name] for name in MANIFEST_FIELDS[:-1]])
        bind_set(self.f, selected)
        self.assertEqual(json.loads(self.f["recipe_originals"]["assignmentOriginal"])["payload"]["custodyAuthority"][
            "executionClosureManifestSha256"], original_bridge)
        with self.assertRaises(ValueError): profile.build(ROLES[0], **arguments(self.f, ROLES[0]))

    def test_assignment_signature_trust_currentness_and_measured_roots_are_required(self):
        for change in ("assignment-signature", "trust-pin", "expired", "set-root", "measured-hash", "scope-root"):
            args = arguments(self.f, ROLES[0])
            args["recipe_originals"] = copy.deepcopy(args["recipe_originals"])
            args["measured"] = copy.deepcopy(args["measured"])
            if change == "assignment-signature":
                envelope = json.loads(args["recipe_originals"]["assignmentOriginal"])
                envelope["signature"] = encoded(cold_key("wrong-assignment")[0].sign(
                    signed_message(ASSIGNMENT_DOMAIN, envelope["payload"])))
                args["recipe_originals"]["assignmentOriginal"] = canonical(envelope).decode("ascii")
            elif change == "trust-pin": args["recipe_originals"]["trustSha256"] = synthetic("wrong-trust")
            elif change == "expired": args["now_unix_ns"] = NOW + 60_000_000_000
            elif change == "set-root":
                selected = json.loads(args["recipe_originals"]["closureSetOriginal"])
                selected["setRootSha256"] = synthetic("wrong-set")
                args["recipe_originals"]["closureSetOriginal"] = canonical(selected).decode("ascii")
            elif change == "measured-hash": args["measured"]["configurationBindingSha256"] = synthetic("wrong-measured")
            else:
                proof = json.loads(args["measured"]["proofScopeOriginal"])
                proof["execution_closure_set_root_sha256"] = synthetic("wrong-proof-set")
                proof["binding_sha256"] = frame("catchplate.policyShadowProductionCustodyProofScope/v2",
                    [proof[name] for name in EXPECTED_SCOPE_VALUES + EXPECTED_SCOPE_ROOTS])
                args["measured"]["proofScopeOriginal"] = canonical(proof).decode("ascii")
            expected = InvalidSignature if change == "assignment-signature" else ValueError
            with self.subTest(change=change), self.assertRaises(expected): profile.build(ROLES[0], **args)


if __name__ == "__main__":
    unittest.main()

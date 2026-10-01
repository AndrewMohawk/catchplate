#!/usr/bin/env python3
"""Synthetic hot12 bridge measurements and signed public admission controls.

Real deterministic test signatures authenticate the assignment, driver window,
C9, role-key pair and closure. Runtime14's nested operational receipts are
explicit shape fixtures, not native receipt acceptance or live owner evidence.
No MeasuredConfigurationRecipe owner, protected FD, process or signing endpoint
is fabricated. The public fixture is shared with the late-consumer controls.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_bridge_key_profile as keys
from serverware import native_pilot_closure_authority as closure
from serverware import native_pilot_closure_set as sets
from serverware import native_pilot_measured_configuration as measured
from test_native_pilot_adopted_bridge import fixture as runtime_fixture
from test_native_pilot_bridge_authorizations import (fixture as old_fixture, clocks, _cold_key,
    expected_key, pair, signed, DOMAINS)
from test_native_pilot_closure_set import (canonical, frame, sha, manifest_fixture, scope_fixture,
    EXPECTED_SCOPE_VALUES, EXPECTED_SCOPE_ROOTS)
from test_native_pilot_generation_scope import ASSIGNMENT_DOMAIN, encoded, key_fixture, signed_message


def fixture():
    value, guest, manifest = old_fixture()
    originals = value["recipeOriginals"]
    selected = json.loads(originals["closureSetOriginal"])
    selected["members"].insert(-1, {"role": "publicationReconciliation",
        "manifest": manifest_fixture("publicationReconciliation")})
    selected = json.loads(sets.set_original(selected["members"], api_version=sets.PUBLICATION_API))
    envelope = json.loads(originals["assignmentOriginal"])
    envelope["payload"]["nativeClosureSet"] = {name: selected[name]
        for name in ("setRootSha256", "seccompSetRootSha256")}
    envelope["payloadSha256"] = sha(canonical(envelope["payload"]))
    envelope["signature"] = encoded(key_fixture("assignment")[0].sign(
        signed_message(ASSIGNMENT_DOMAIN, envelope["payload"])))
    originals.update(assignmentOriginal=canonical(envelope).decode("ascii"),
        closureSetOriginal=canonical(selected).decode("ascii"))
    binding = json.loads(value["measured"]["configurationBindingOriginal"])
    binding.update(assignmentPayloadSha256=envelope["payloadSha256"],
        nativeClosureSet=copy.deepcopy(envelope["payload"]["nativeClosureSet"]))
    binding_sha = frame("serverware.policyShadowProductionCustodyConfiguration/v2", binding)
    proof = scope_fixture(envelope)
    proof["production_configuration_binding_sha256"] = binding_sha
    proof["binding_sha256"] = frame("serverware.policyShadowProductionCustodyProofScope/v2",
        [proof[name] for name in EXPECTED_SCOPE_VALUES + EXPECTED_SCOPE_ROOTS])
    value["measured"].update(configurationBindingOriginal=canonical(binding).decode("ascii"),
        configurationBindingSha256=binding_sha, proofScopeOriginal=canonical(proof).decode("ascii"))
    value["measured"]["production"]["expectedConfigurationBindingSha256"] = binding_sha

    source = json.loads(value["deliveryInputOriginal"])
    payload = json.loads(source["payloadOriginal"])
    runtime_raw = canonical(runtime_fixture())
    cold = json.loads(source["configurationOriginal"])
    # This helper only computes the fixed41-name grammar, not actual descriptors.
    inventory, _ = closure.c9._bridge_inventory(runtime_raw, cold, adopted=True)
    activation = [{"name": name, "fd": fd, "device": 7, "inode": 9000 + fd,
        "mode": kind | 0o700, "uid": cold["uid"], "gid": cold["gid"]}
        for fd, (name, kind) in enumerate(inventory, 6)]
    payload.update(runtimeConfig={"path": "/etc/serverware/native-pilot-inputs/bridge-runtime.json",
        "sha256": sha(runtime_raw)}, activation=activation)
    raw = canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1", "payload": payload,
        "signatureBase64url": encoded(_cold_key("bridge-c9")[0].sign(
            b"serverware.policyCustodyGuestDelivery.signature/v1\0" + canonical(payload)))})
    source.update(apiVersion="serverware.nativePilotDeliverySigningInput/v3", runtimeOriginal=runtime_raw.decode("ascii"),
        payloadOriginal=canonical(payload).decode("ascii"), activationOriginal=canonical(activation).decode("ascii"))
    value.update(apiVersion=keys.ADOPTED_API, deliveryInputOriginal=canonical(source).decode("ascii"),
        deliveryOriginal=raw.decode("ascii"))
    guest.update(deliverySha256=sha(raw), runtimeConfigurationSha256=sha(runtime_raw))
    return value, guest, manifest


def closure_input(value, guest, manifest):
    source = json.loads(value["deliveryInputOriginal"])
    selected = json.loads(value["recipeOriginals"]["closureSetOriginal"])
    key = expected_key(value, guest, manifest)
    payload = {name: key[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "guest",
        "trustCheckpointId", "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos",
        "signingKeyId", "signingKeySpkiSha256")}
    payload.update(apiVersion="serverware.nativeCustodyClosureAssignment/v5", purpose="shadow-custody-closure-set-member",
        profile="native-multi-guest-closure-set-v2", guestRole="bridge", manifestSha256=manifest["manifestSha256"],
        **{name: selected[name] for name in ("setRootSha256", "seccompSetRootSha256")},
        leafSha256=frame("serverware.nativeCustodyExecutionClosureSetLeaf/v2", ["bridge", manifest]))
    return {"apiVersion": closure.ADOPTED_BRIDGE_API, "guestRole": "bridge",
        "controlOriginal": value["controlOriginal"], "deliveryInputOriginal": value["deliveryInputOriginal"],
        "configurationOriginal": source["ownerConfigurationOriginal"], "windowOriginal": source["windowOriginal"],
        "observationOriginal": source["observationOriginal"], "deliveryConfigurationOriginal": source["configurationOriginal"],
        "deliveryOriginal": value["deliveryOriginal"], "runtimeOriginal": source["runtimeOriginal"],
        **value["recipeOriginals"], "manifestOriginal": canonical(manifest).decode("ascii"),
        "payloadOriginal": canonical(payload).decode("ascii")}


def closure_result(value, *, domain="serverware.nativeCustodyClosureAssignment.signature/v5"):
    payload = json.loads(value["payloadOriginal"])
    raw = canonical({"apiVersion": "serverware.nativeCustodyClosure/v5",
        "manifest": json.loads(value["manifestOriginal"]), "closureSet": json.loads(value["closureSetOriginal"]),
        "authorization": {"payload": payload, "signature": encoded(key_fixture("custody-supervisor-capability")[0].sign(
            signed_message(domain, payload)))}})
    return {"original": raw.decode("ascii"), "sha256": sha(raw)}


class AdoptedBridgeKeyControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.value, cls.guest, cls.manifest = fixture()

    def test_explicit_measured_recipe_recomputes_exact_native_v2_data(self):
        value = self.value
        recipe = {"apiVersion": measured.ADOPTED_API, **value["recipeOriginals"]}
        envelope, bindings, root = measured._assignment(recipe, clocks()["now_unix_ns"])
        self.assertEqual(measured._closure_set(recipe, envelope, self.manifest), envelope["payload"]["nativeClosureSet"])
        with self.assertRaises(ValueError):
            measured._closure_set({**recipe, "apiVersion": measured.SET_API}, envelope, self.manifest)
        with self.assertRaises(ValueError): measured._assignment({**recipe, "apiVersion": "unknown"}, clocks()["now_unix_ns"])
        source = json.loads(value["deliveryInputOriginal"])
        result = measured.derive_configuration(envelope=envelope, keys=bindings, key_root=root, manifest=self.manifest,
            observed=json.loads(source["observationOriginal"]),
            production={name: value["measured"]["production"][name] for name in measured.PRODUCTION_FIELDS},
            window=json.loads(source["windowOriginal"])["payload"], recipe_sha=value["measured"]["recipeSha256"], successor=True)
        self.assertEqual(result, value["measured"])

    def test_actual_signed_key_and_bridge_admission_keep_native_wires(self):
        records = pair(self.value, self.guest, self.manifest)
        values = tuple(records[name].encode("ascii") for name in
            ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal"))
        result = keys.admitted_adopted_pair(*values, **clocks())
        self.assertEqual(result["authorization"]["payload"]["apiVersion"], "serverware.nativeShadowRoleKeyAssignment/v2")
        self.assertEqual(result["admissionAuthorization"]["payload"]["apiVersion"], "serverware.nativeShadowBridgeAdmissionAssignment/v1")
        self.assertEqual(result["expectedScope"]["productionConfigurationBindingSha256"], self.value["measured"]["configurationBindingSha256"])
        with self.assertRaises(ValueError): keys.admitted_pair(*values, **clocks())
        old, guest, manifest = old_fixture(); old_records = pair(old, guest, manifest)
        with self.assertRaises(ValueError):
            keys.admitted_adopted_pair(*(old_records[name].encode("ascii") for name in
                ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")), **clocks())

    def test_closure_v5_authenticates_bootstrap_separately_from_late_runtime(self):
        value = closure_input(self.value, self.guest, self.manifest)
        prepared = closure.prepare_input(canonical(value), **clocks())
        self.assertNotEqual(self.manifest["runtimeConfigurationSha256"], self.guest["runtimeConfigurationSha256"])
        self.assertEqual(prepared["result"]["apiVersion"], "serverware.nativeCustodyClosure/v5")
        result = closure_result(value)
        self.assertEqual(closure.checked_result(canonical(value), result, **clocks()), result["original"].encode("ascii"))
        with self.assertRaises(InvalidSignature):
            closure.checked_result(canonical(value), closure_result(value, domain=closure.SET_DOMAIN), **clocks())

    def test_old_selectors_and_nonbridge_roles_remain_closed(self):
        value = closure_input(self.value, self.guest, self.manifest)
        for change in ({"apiVersion": "serverware.nativePilotClosureAuthorityInput/v2"},
                {"apiVersion": closure.ADOPTED_API}, {"guestRole": "publicationReconciliation"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                closure.prepare_input(canonical({**value, **change}), **clocks())
        old = {**self.value, "apiVersion": keys.API}
        with self.assertRaises(ValueError): keys.prepare_input("role-keys", canonical(old), **clocks())
        wrong = copy.deepcopy(self.value); source = json.loads(wrong["deliveryInputOriginal"])
        source["apiVersion"] = "serverware.nativePilotDeliverySigningInput/v1"
        wrong["deliveryInputOriginal"] = canonical(source).decode("ascii")
        with self.assertRaises(ValueError): keys.prepare_input("role-keys", canonical(wrong), **clocks())

    def test_assignment_c9_signatures_and_measured_join_are_not_optional(self):
        for source_name, signature_name in (("deliveryOriginal", "signatureBase64url"), ("assignmentOriginal", "signature")):
            wrong = copy.deepcopy(self.value)
            parent = wrong["recipeOriginals"] if source_name == "assignmentOriginal" else wrong
            source = json.loads(parent[source_name]); source[signature_name] = encoded(bytes(64))
            parent[source_name] = canonical(source).decode("ascii")
            with self.subTest(source=source_name), self.assertRaises(InvalidSignature):
                keys.prepare_input("role-keys", canonical(wrong), **clocks())
        wrong = copy.deepcopy(self.value); wrong["measured"]["configurationBindingSha256"] = sha(b"different-measurement")
        with self.assertRaises(ValueError): keys.prepare_input("role-keys", canonical(wrong), **clocks())

    def test_original_time_and_source_bounds_refuse(self):
        supplied = closure_input(self.value, self.guest, self.manifest)
        prepared = closure.prepare_input(canonical(supplied), **clocks())
        for changes in ({"now_boottime_ns": prepared["deadline"]}, {"now_unix_ns": prepared["epochLimit"]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                closure.prepare_input(canonical(supplied), **(clocks() | changes))
        wrong = copy.deepcopy(supplied); wrong["windowOriginal"] = "{}"
        with self.assertRaises(ValueError): closure.prepare_input(canonical(wrong), **clocks())
        self.assertEqual(closure.MAX_BRIDGE_INPUT, 16 * 1024 * 1024)
        self.assertEqual(closure.MAX_BYTES, 1024 * 1024)
        self.assertEqual(keys.MAX_INPUT, 32 * 1024 * 1024)


if __name__ == "__main__": unittest.main()

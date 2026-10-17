#!/usr/bin/env python3
"""Synthetic signed endpoint closure controls, not native admission or owners.

The reused assignment deliberately omits unrelated operational policy fields.
Images, PIDs, C9 resources and provenance are labelled in-memory fixtures. Real
deterministic test signatures exercise the complete public verifier, never a
mocked success, protected installer, live signer or native service. The shared
fixture offers adopted non-Retrieval endpoints only: its old Retrieval row is
not upgraded without an actual core custody source. B's separate full5 controls
cover that source grammar; this suite does not invent a received-core owner.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_closure_authority as authority
from catchplate import native_pilot_closure_set as sets
from test_native_pilot_key_authorizations import fixture as old_fixture, clocks
from test_native_pilot_closure_set import (MANIFEST_FIELDS, EXPECTED_SCOPE_VALUES, EXPECTED_SCOPE_ROOTS,
    canonical, frame, manifest_fixture, scope_fixture, sha, synthetic)
from test_native_pilot_generation_scope import ASSIGNMENT_DOMAIN, NOW, encoded, key_fixture, signed_message
from test_native_pilot_native_deliveries import WINDOW_FIELDS, refresh_window, result_for

ROLE = "publicationReconciliation"
DOMAIN = "catchplate.nativeCustodyClosureAssignment.signature/v5"


def fixture():
    """Compatible key fixture plus authenticated hot12/config8 non-core rows."""
    f = old_fixture()
    cold = {**json.loads(f["cold"]["trustedTime"]), "uid": 62010, "gid": 62010}
    f["cold"][ROLE] = canonical(cold).decode("ascii")
    runtime = canonical({"apiVersion": "catchplate.nativePilotEndpointRuntime/v1", "role": ROLE})
    f["fragment"][ROLE] = {"runtimeOriginal": runtime.decode("ascii"),
        "runtimeConfig": {"path": "/etc/catchplate/native-pilot-inputs/native-runtime-" + ROLE + ".json",
            "sha256": sha(runtime)}, "credentials": copy.deepcopy(f["fragment"]["trustedTime"]["credentials"])}
    f["activations"][ROLE] = [{"name": "publication-reconciliation-listener", "fd": 6,
        "device": 7, "inode": 8110, "mode": stat.S_IFSOCK | 0o777, "uid": 0, "gid": 0}]
    selected = json.loads(f["recipe_originals"]["closureSetOriginal"])
    manifest = manifest_fixture(ROLE)
    manifest.update(workerExecutableSha256=f["config"]["executableSha256"], runtimeConfigurationSha256=sha(runtime))
    manifest["manifestSha256"] = frame(manifest["apiVersion"], [manifest[name] for name in MANIFEST_FIELDS[:-1]])
    selected["members"].insert(-1, {"role": ROLE, "manifest": manifest})
    set_raw = sets.set_original(selected["members"], api_version=sets.PUBLICATION_API)
    selected = json.loads(set_raw)
    envelope = json.loads(f["recipe_originals"]["assignmentOriginal"])
    envelope["payload"]["nativeClosureSet"] = {
        name: selected[name] for name in ("setRootSha256", "seccompSetRootSha256")}
    envelope["payloadSha256"] = sha(canonical(envelope["payload"]))
    envelope["signature"] = encoded(key_fixture("assignment")[0].sign(signed_message(ASSIGNMENT_DOMAIN, envelope["payload"])))
    f["recipe_originals"].update(assignmentOriginal=canonical(envelope).decode("ascii"), closureSetOriginal=set_raw.decode("ascii"))
    binding = json.loads(f["measured"]["configurationBindingOriginal"])
    binding.update(assignmentPayloadSha256=envelope["payloadSha256"], nativeClosureSet=copy.deepcopy(envelope["payload"]["nativeClosureSet"]))
    binding_sha = frame("catchplate.policyShadowProductionCustodyConfiguration/v2", binding)
    proof = scope_fixture(envelope)
    proof["production_configuration_binding_sha256"] = binding_sha
    proof["binding_sha256"] = frame("catchplate.policyShadowProductionCustodyProofScope/v2",
        [proof[name] for name in EXPECTED_SCOPE_VALUES + EXPECTED_SCOPE_ROOTS])
    f["measured"].update(configurationBindingOriginal=canonical(binding).decode("ascii"),
        configurationBindingSha256=binding_sha, proofScopeOriginal=canonical(proof).decode("ascii"))
    f["measured"]["production"]["expectedConfigurationBindingSha256"] = binding_sha
    f["config"]["apiVersion"] = "catchplate.nativeShadowProofCohortConfiguration/v8"
    f["config"][ROLE + "Configuration"] = {"path": "/etc/catchplate/native-pilot-inputs/native-cold-" + ROLE + ".json",
        "sha256": sha(f["cold"][ROLE].encode("ascii"))}
    f["owner_configuration_raw"] = canonical(f["config"])
    f["window"]["configurationSha256"] = sha(f["owner_configuration_raw"])
    f["observed"].update(apiVersion="catchplate.nativeShadowProofCohortOriginals/v7",
        configurationSha256=sha(f["owner_configuration_raw"]))
    f["observed"][ROLE] = {"processId": 110, "startTimeTicks": 210,
        "executable": {"device": 7, "inode": 510, "length": 4096, "sha256": f["config"]["executableSha256"]}}
    refresh_window(f)
    f["policy"][ROLE] = {"localRoles": ["custody-publication-reconciliation"],
        "challengeBase64url": encoded(bytes([17]) * 32),
        "issuedAtUnixNanos": NOW - 1_000_000_000, "expiresAtUnixNanos": NOW + 1_000_000_000}
    f["adopted_roles"] = tuple(role for role in sets.PUBLICATION_ROLES[:-1] if role != "retrieval")
    for role in f["adopted_roles"]:
        row, cold = f["fragment"][role], json.loads(f["cold"][role])
        payload = {"configurationSha256": sha(f["cold"][role].encode("ascii")), "authorityKeyId": cold["authority"]["keyId"],
            **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
            **{name: f["window"][name] for name in WINDOW_FIELDS}, "runtimeConfig": row["runtimeConfig"],
            "credentials": row["credentials"], "activation": f["activations"][role]}
        value = {"apiVersion": "catchplate.nativePilotDeliverySigningInput/v2", "role": role,
            "configurationOriginal": f["cold"][role], "ownerConfigurationOriginal": f["owner_configuration_raw"].decode("ascii"),
            "windowOriginal": f["window_raw"].decode("ascii"), "observationOriginal": f["observation_raw"].decode("ascii"),
            "runtimeOriginal": row["runtimeOriginal"], "payloadOriginal": canonical(payload).decode("ascii"),
            "activationOriginal": canonical(payload["activation"]).decode("ascii")}
        raw = canonical(value); signed = result_for(f, role, raw)["original"].encode("ascii")
        f["delivery_inputs"][role], f["deliveries"][role] = raw, signed
        f["guests"][role] = {name: payload[name] for name in authority.p.GUEST_FIELDS
            if name not in ("deliverySha256", "runtimeConfigurationSha256")}
        f["guests"][role].update(deliverySha256=sha(signed), runtimeConfigurationSha256=row["runtimeConfig"]["sha256"])
    return f


def input_for(f, role=ROLE):
    source = json.loads(f["delivery_inputs"][role])
    selected = json.loads(f["recipe_originals"]["closureSetOriginal"])
    envelope = json.loads(f["recipe_originals"]["assignmentOriginal"])
    trust = json.loads(f["recipe_originals"]["trustOriginal"])
    manifest = next(row["manifest"] for row in selected["members"] if row["role"] == role)
    key = key_fixture("custody-supervisor-capability")[1]
    payload = {"apiVersion": "catchplate.nativeCustodyClosureAssignment/v5",
        "purpose": "shadow-custody-closure-set-member", "profile": "native-multi-guest-closure-set-v2",
        "assignmentId": envelope["payload"]["assignmentId"], "assignmentPayloadSha256": envelope["payloadSha256"],
        "assignmentRevision": envelope["payload"]["assignmentRevision"], "manifestSha256": manifest["manifestSha256"],
        "guest": f["guests"][role], "trustCheckpointId": trust["checkpoint"]["checkpointId"],
        **{name: trust["checkpoint"][name] for name in ("revocationGeneration", "revocationRootSha256")},
        "issuedAtUnixNanos": NOW - 500_000_000, "expiresAtUnixNanos": NOW + 500_000_000,
        "signingKeyId": key["keyId"], "signingKeySpkiSha256": key["keySpkiSha256"], "guestRole": role,
        **{name: selected[name] for name in ("setRootSha256", "seccompSetRootSha256")},
        "leafSha256": frame("catchplate.nativeCustodyExecutionClosureSetLeaf/v2", [role, manifest])}
    return {"apiVersion": authority.ADOPTED_API, "guestRole": role,
        "deliveryInputOriginal": f["delivery_inputs"][role].decode("ascii"),
        "configurationOriginal": source["ownerConfigurationOriginal"],
        "deliveryConfigurationOriginal": source["configurationOriginal"],
        **{name: source[name] for name in ("windowOriginal", "observationOriginal", "runtimeOriginal")},
        "deliveryOriginal": f["deliveries"][role].decode("ascii"), **f["recipe_originals"],
        "manifestOriginal": canonical(manifest).decode("ascii"), "payloadOriginal": g.canonical(payload).decode("ascii")}


def signed(value, *, domain=DOMAIN):
    payload = json.loads(value["payloadOriginal"])
    raw = g.canonical({"apiVersion": "catchplate.nativeCustodyClosure/v5",
        "manifest": json.loads(value["manifestOriginal"]), "closureSet": json.loads(value["closureSetOriginal"]),
        "authorization": {"payload": payload, "signature": encoded(key_fixture("custody-supervisor-capability")[0].sign(
            b"catchplate.signedEnvelope/v1\0" + domain.encode("ascii")
            + b"\0catchplate.canonicalJson/ascii-integer-v1\0" + g.canonical(payload)))}})
    return raw, {"original": raw.decode("ascii"), "sha256": sha(raw)}


class AdoptedClosureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.f = fixture()

    def prepare(self, value, **changes):
        return authority.prepare_input(canonical(value), **{**clocks(self.f), **changes})

    def test_all_ten_non_core_endpoints_require_real_test_signatures_and_v5(self):
        self.assertEqual(len(self.f["adopted_roles"]), 10)
        for role in self.f["adopted_roles"]:
            with self.subTest(role=role):
                value = input_for(self.f, role); prepared = self.prepare(value)
                raw, result = signed(value)
                self.assertEqual(prepared["payload"], json.loads(value["payloadOriginal"]))
                self.assertEqual(prepared["domain"], DOMAIN)
                self.assertEqual(prepared["deadline"], int(self.f["window"]["startupDeadlineBoottimeNs"]))
                self.assertEqual(prepared["epochLimit"], NOW + 500_000_000)
                self.assertEqual(authority.checked_result(canonical(value), result, **clocks(self.f)), raw)

    def test_old_profiles_extra_fields_and_bridge_are_not_upgraded(self):
        value = input_for(self.f)
        for change in ({"apiVersion": "catchplate.nativePilotClosureAuthorityInput/v2"},
                {"guestRole": "bridge"}, {"controlOriginal": "{}"}, {"deliveryInputOriginal": None}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare({**value, **change})

    def test_c9_signature_profile_and_duplicate_source_joins_are_required(self):
        value = input_for(self.f)
        for field in ("configurationOriginal", "windowOriginal", "observationOriginal", "runtimeOriginal"):
            with self.subTest(field=field), self.assertRaises(ValueError): self.prepare({**value, field: "{}"})
        bad = copy.deepcopy(value); delivery = json.loads(bad["deliveryOriginal"])
        delivery["signatureBase64url"] = encoded(bytes(64)); bad["deliveryOriginal"] = canonical(delivery).decode("ascii")
        with self.assertRaises(InvalidSignature): self.prepare(bad)
        bad = copy.deepcopy(value); source = json.loads(bad["deliveryInputOriginal"])
        source["apiVersion"] = "catchplate.nativePilotDeliverySigningInput/v1"
        bad["deliveryInputOriginal"] = canonical(source).decode("ascii")
        with self.assertRaises(ValueError): self.prepare(bad)

    def test_old_set_and_same_signer_payload_substitution_refuse(self):
        value = input_for(self.f)
        old = old_fixture()["recipe_originals"]["closureSetOriginal"]
        with self.assertRaises(ValueError): self.prepare({**value, "closureSetOriginal": old})
        for field, replacement in (("guestRole", "persistence"), ("profile", "native-multi-guest-closure-set-v1"),
                ("apiVersion", "catchplate.nativeCustodyClosureAssignment/v3"), ("leafSha256", synthetic("other-leaf"))):
            changed = copy.deepcopy(value); payload = json.loads(changed["payloadOriginal"])
            payload[field] = replacement; changed["payloadOriginal"] = canonical(payload).decode("ascii")
            _, result = signed(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                authority.checked_result(canonical(value), result, **clocks(self.f))

    def test_native_signature_domain_and_result_pin_are_exact(self):
        value = input_for(self.f)
        _, result = signed(value, domain="catchplate.nativeCustodyClosureAssignment.signature/v3")
        with self.assertRaises(InvalidSignature): authority.checked_result(canonical(value), result, **clocks(self.f))
        _, result = signed(value); result["sha256"] = synthetic("other-result")
        with self.assertRaises(ValueError): authority.checked_result(canonical(value), result, **clocks(self.f))

    def test_original_boottime_wall_bounds_and_input_limit_remain_closed(self):
        value = input_for(self.f); prepared = self.prepare(value)
        for change in ({"now_boottime_ns": prepared["deadline"]}, {"now_unix_ns": prepared["epochLimit"]},
                {"boot": (encoded(bytes([9]) * 16), 4, 5)}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(value, **change)
        self.assertEqual(authority.MAX_INPUT, 8 * 1024 * 1024)
        self.assertEqual(authority.MAX_BYTES, 1024 * 1024)
        value["deliveryInputOriginal"] = "x" * authority.MAX_INPUT
        with self.assertRaises(ValueError): authority.input_document(canonical(value))

    def test_source_u64_namespace_refuses_before_native_closure_signing(self):
        f = {name: value if name == "key" else copy.deepcopy(value) for name, value in self.f.items()}
        inode = (1 << 63) + 123
        f["boot"] = (f["boot"][0], f["boot"][1], inode)
        f["window"]["timeNamespaceInode"] = inode
        window = {"apiVersion": "catchplate.nativeShadowProofCohortPrecreation/v1", "payload": f["window"],
            "signatureBase64url": encoded(f["key"].sign(
                b"catchplate.nativeShadowProofCohortPrecreation.signature/v1\0" + g.canonical(f["window"])))}
        f["window_raw"] = g.canonical(window)
        f["observed"]["precreationSha256"] = sha(f["window_raw"])
        f["observation_raw"] = canonical(f["observed"])
        source = json.loads(f["delivery_inputs"][ROLE]); payload = json.loads(source["payloadOriginal"])
        payload["timeNamespaceInode"] = inode
        source.update(windowOriginal=f["window_raw"].decode("ascii"), observationOriginal=f["observation_raw"].decode("ascii"),
            payloadOriginal=g.canonical(payload).decode("ascii"))
        raw = g.canonical({"apiVersion": "catchplate.policyCustodyGuestDelivery/v1", "payload": payload,
            "signatureBase64url": encoded(f["key"].sign(b"catchplate.policyCustodyGuestDelivery.signature/v1\0" + g.canonical(payload)))})
        f["delivery_inputs"][ROLE], f["deliveries"][ROLE] = canonical(source), raw
        f["guests"][ROLE].update(timeNamespaceInode=inode, deliverySha256=sha(raw))
        # These source reader fixtures can preserve u64 values, but native
        # policy_shadow::canonical_json_bytes rejects them in closure payloads.
        # Never turn this wider source grammar into a native-positive signature.
        value = input_for(f)
        self.assertEqual(json.loads(value["payloadOriginal"])["guest"]["timeNamespaceInode"], inode)
        with self.assertRaises(ValueError):
            authority.prepare_input(canonical(value), **clocks(f))


if __name__ == "__main__": unittest.main()

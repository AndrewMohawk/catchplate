#!/usr/bin/env python3
"""Synthetic cold key transcripts, not owners, key provisioning or attestation.

Complete public source inputs and deterministic test signatures exercise the
pure preparation/checking boundary. Process, image and C9 observations remain
explicitly synthetic. No protected input, live signer or native guest runs.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from serverware import custody_generation_grants as g
from serverware import native_pilot_closure_set as sets
from serverware import native_pilot_genesis_key_profile as profile
import test_native_pilot_closure_set as manifests
import test_native_pilot_genesis_bootstrap_profiles as bootstrap
import test_native_pilot_genesis_delivery as delivery_tests
import test_native_pilot_publication_cold_binding as binding_tests
from test_native_pilot_generation_scope import NOW, key_fixture

p = g.p
ROLE_DOMAIN = "serverware.nativeShadowRoleKeyAssignment.signature/v2"
ADMISSION_DOMAIN = "serverware.nativeShadowKeyAdmissionAssignment.signature/v1"
PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")


def labelled(value):
    return p.sha(("SYNTHETIC COLD KEY ISSUER / " + value).encode("ascii"))


def independent_signed(domain, payload, key):
    message = (b"serverware.signedEnvelope/v1\0" + domain.encode("ascii")
        + b"\0serverware.canonicalJson/ascii-integer-v1\0" + g.canonical(payload))
    return g.canonical({"payload": payload, "signature": p.encoded(key.sign(message))})


def fixture():
    """One common signed assignment/set for all three synthetic C9 originals."""
    deliveries = {role: delivery_tests.fixture(role) for role in profile.ROLES}
    selected = bootstrap.members()
    for row in selected:
        role, manifest = row["role"], row["manifest"]
        source = deliveries[role]
        manifest.update(imageSha256=source["image_sha256"], workerExecutableSha256=source["executable_sha256"],
            runtimeConfigurationSha256=p.sha(g.canonical(profile.BOOTSTRAP)) if role == profile.ROLES[-1]
            else p.sha(source["runtime_raw"]))
        manifest["manifestSha256"] = manifests.frame(manifest["apiVersion"],
            [manifest[name] for name in manifests.MANIFEST_FIELDS[:-1]])
    approved = binding_tests.fixture()
    binding_tests.select_set(approved, sets.set_original(selected, api_version=sets.GENESIS_BOOTSTRAP_API))
    first = deliveries[profile.ROLES[0]]
    boot, now = first["boot"], first["now"]
    for source in deliveries.values():
        assert source["boot"] == boot and source["now"] == now
        assert source["parentOriginals"] == first["parentOriginals"]
    approved["window"].update(bootIdBase64url=boot[0], timeNamespaceDevice=boot[1], timeNamespaceInode=boot[2],
        issuedAtBoottimeNanos=max(p.ns(source["window"]["issuedAtBoottimeNs"]) for source in deliveries.values()),
        expiresAtBoottimeNanos=min(9_000_000_000,
            *(p.ns(source["window"]["lifetimeDeadlineBoottimeNs"]) for source in deliveries.values())))
    binding_raw = g.canonical(approved)
    # Only the coordinator's complete late runtime changes. Its measured
    # bootstrap manifest and both endpoint manifests remain assignment-free.
    deliveries[profile.ROLES[-1]] = delivery_tests.fixture(profile.ROLES[-1], cold_binding_input=binding_raw)
    key = key_fixture("custody-supervisor-capability")[0]
    clocks = {"boot": boot, "now_boottime_ns": now, "now_unix_ns": NOW}
    pairs = {}
    for number, role in enumerate(profile.ROLES):
        source = deliveries[role]
        # The coordinator's role is an explicit test policy choice, not a
        # default assigned by the producer or a claim that this key is loaded.
        local = [profile.REQUIRED_ROLES[role]] if role in profile.REQUIRED_ROLES else ["custody-trusted-time-response"]
        value = {"apiVersion": profile.API, "operation": "role-keys", "role": role,
            "deliveryInputOriginal": p.canonical(source["input"]).decode("ascii"),
            "deliveryOriginal": source["raw"].decode("ascii"),
            "coldBindingInputOriginal": binding_raw.decode("ascii"), "coldBindingInputSha256": p.sha(binding_raw),
            "policy": {"localRoles": local, "challengeBase64url": p.encoded(bytes([number + 21]) * 32),
                "issuedAtUnixNanos": NOW, "expiresAtUnixNanos": NOW + 10_000_000_000}}
        role_input = p.canonical(value)
        prepared = profile.prepare_input("role-keys", role, role_input, **clocks)
        role_raw = independent_signed(ROLE_DOMAIN, prepared["payload"], key)
        admission_input = p.canonical({**value, "operation": "admission", "roleKeyOriginal": role_raw.decode("ascii")})
        prepared = profile.prepare_input("admission", role, admission_input, **clocks)
        admission_raw = independent_signed(ADMISSION_DOMAIN, prepared["payload"], key)
        pairs[role] = dict(zip(PAIR_FIELDS, (role_input, role_raw, admission_input, admission_raw), strict=True))
    return {"deliveries": deliveries, "coldBindingInputOriginal": binding_raw,
        "coldBindingInputSha256": p.sha(binding_raw), "pairs": pairs, "supervisor_key": key, **clocks}


class GenesisKeyAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture()
        cls.clocks = {name: cls.f[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}

    def value(self, role=None, operation="role-keys"):
        role = role or profile.ROLES[0]
        field = "roleKeyInputOriginal" if operation == "role-keys" else "admissionInputOriginal"
        return p.document(self.f["pairs"][role][field], profile.MAX_INPUT)

    def prepare(self, value, **clocks):
        return profile.prepare_input(value["operation"], value["role"], p.canonical(value), **(clocks or self.clocks))

    def refused(self, value, **clocks):
        with self.assertRaises((ValueError, InvalidSignature, TypeError, KeyError)):
            self.prepare(value, **clocks)

    def test_exact_cold_pair_uses_native_domains_and_actual_literal_sources(self):
        for role in profile.ROLES:
            with self.subTest(role=role):
                pair = self.f["pairs"][role]
                checked = profile.admitted_pair(role, *(pair[field] for field in PAIR_FIELDS), **self.clocks)
                payload = checked["authorization"]["payload"]
                admission = checked["admissionAuthorization"]["payload"]
                self.assertEqual(payload["apiVersion"], "serverware.nativeShadowRoleKeyAssignment/v2")
                self.assertEqual(admission["apiVersion"], "serverware.nativeShadowKeyAdmissionAssignment/v1")
                self.assertEqual(admission["keyAuthorizationSha256"], p.sha(pair["roleKeyOriginal"]))
                self.assertEqual(checked["expectedScope"]["admissionAuthorizationSha256"], p.sha(pair["admissionOriginal"]))
                self.assertEqual(checked["source"]["coldBindingInputOriginal"], self.f["coldBindingInputOriginal"])
                self.assertEqual(checked["source"]["deliveryOriginal"], self.f["deliveries"][role]["raw"])
                self.assertEqual(payload["fullKeySetRootSha256"], p.key_root(checked["authorityKeys"]))
                self.assertEqual(admission["localKeySetRootSha256"], p.key_root(checked["expectedScope"]["localKeys"]))
                self.assertNotIn("productionConfigurationBindingSha256", admission)

    def test_local_roles_are_explicit_ordered_nonempty_and_endpoint_singletons(self):
        for role in profile.ROLES:
            for local in ([], ["custody-supervisor-capability"], ["custody-attestation-verifier"],
                    ["custody-trusted-time-response", "custody-retrieval-response"], ["custody-retrieval-response"] * 2):
                value = self.value(role); value["policy"]["localRoles"] = local
                self.refused(value)
        value = self.value(profile.ROLES[1]); value["policy"]["localRoles"] = ["custody-retrieval-response"]
        self.refused(value)
        value = self.value(profile.ROLES[-1]); del value["policy"]["localRoles"]
        self.refused(value)

    def test_old_hot_selector_extra_fields_and_zero_challenge_refuse(self):
        for changes in ({"apiVersion": "serverware.nativePilotKeyAuthorityInput/v1"}, {"role": "retrieval"},
                {"futureGrantSha256": labelled("not authority")}, {"operation": "possession"}):
            self.refused({**self.value(), **changes})
        value = self.value(); value["policy"]["challengeBase64url"] = p.encoded(bytes(32))
        self.refused(value)

    def test_complete_source_pins_and_signed_assignment_cannot_be_substituted(self):
        value = self.value(); value["coldBindingInputSha256"] = labelled("wrong complete input")
        self.refused(value)
        value = self.value(); value["deliveryOriginal"] = self.f["deliveries"][profile.ROLES[1]]["raw"].decode("ascii")
        self.refused(value)
        value = self.value()
        approved = g.document(value["coldBindingInputOriginal"].encode("ascii"), g.MAX_BYTES)
        assignment = g.document(approved["assignmentOriginal"].encode("ascii"), g.MAX_BYTES)
        assignment["signature"] = p.encoded(bytes(64))
        approved["assignmentOriginal"] = g.canonical(assignment).decode("ascii")
        raw = g.canonical(approved)
        value.update(coldBindingInputOriginal=raw.decode("ascii"), coldBindingInputSha256=p.sha(raw))
        self.refused(value)
        # Both C9 and its ordinary grants are correctly signed, but for a
        # different complete cold binding. Shared boot/window is insufficient.
        unrelated = delivery_tests.fixture(profile.ROLES[-1])
        value = self.value(profile.ROLES[-1])
        value.update(deliveryInputOriginal=p.canonical(unrelated["input"]).decode("ascii"),
            deliveryOriginal=unrelated["raw"].decode("ascii"))
        self.refused(value)

    def test_admission_requires_exact_preceding_signed_role_original(self):
        value = self.value(operation="admission")
        value["roleKeyOriginal"] = self.f["pairs"][profile.ROLES[1]]["roleKeyOriginal"].decode("ascii")
        self.refused(value)
        value = self.value(operation="admission")
        signed = g.document(value["roleKeyOriginal"].encode("ascii"), profile.MAX_OUTPUT)
        for raw in (g.canonical(signed["payload"]),
                independent_signed(ADMISSION_DOMAIN, signed["payload"], self.f["supervisor_key"])):
            self.refused({**value, "roleKeyOriginal": raw.decode("ascii")})

    def test_same_key_wrong_payload_domain_or_result_pin_refuses(self):
        role, pair = profile.ROLES[0], self.f["pairs"][profile.ROLES[0]]
        payload = g.document(pair["roleKeyOriginal"], profile.MAX_OUTPUT)["payload"]
        changed = copy.deepcopy(payload); changed["guest"]["deliverySha256"] = labelled("other C9")
        for raw in (independent_signed(ADMISSION_DOMAIN, payload, self.f["supervisor_key"]),
                independent_signed(ROLE_DOMAIN, changed, self.f["supervisor_key"])):
            with self.assertRaises((ValueError, InvalidSignature)):
                profile.checked_result("role-keys", role, pair["roleKeyInputOriginal"],
                    {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.clocks)
        with self.assertRaises(ValueError):
            profile.checked_result("role-keys", role, pair["roleKeyInputOriginal"],
                {"original": pair["roleKeyOriginal"].decode("ascii"), "sha256": labelled("wrong pin")}, **self.clocks)

    def test_pair_common_input_policy_and_literal_originals_cannot_be_spliced(self):
        role, pair = profile.ROLES[0], self.f["pairs"][profile.ROLES[0]]
        first = self.value(); first["policy"]["challengeBase64url"] = p.encoded(bytes([99]) * 32)
        with self.assertRaises(ValueError):
            profile.admitted_pair(role, p.canonical(first), pair["roleKeyOriginal"], pair["admissionInputOriginal"],
                pair["admissionOriginal"], **self.clocks)
        with self.assertRaises(ValueError):
            profile.admitted_pair(role, pair["roleKeyInputOriginal"], pair["roleKeyOriginal"] + b"\n",
                pair["admissionInputOriginal"], pair["admissionOriginal"], **self.clocks)

    def test_original_boot_startup_and_unix_bounds_are_not_renewed(self):
        value = self.value(); context = self.prepare(value)
        self.assertLessEqual(context["deadline"], p.ns(context["window"]["startupDeadlineBoottimeNs"]))
        self.refused(value, **{**self.clocks, "now_boottime_ns": context["deadline"]})
        self.refused(value, **{**self.clocks, "now_unix_ns": context["epochLimit"]})
        self.refused(value, **{**self.clocks, "boot": (p.encoded(bytes([88]) * 16), *self.clocks["boot"][1:])})
        changed = copy.deepcopy(value); changed["policy"]["expiresAtUnixNanos"] += 100_000_000_000
        self.refused(changed)


if __name__ == "__main__":
    unittest.main()

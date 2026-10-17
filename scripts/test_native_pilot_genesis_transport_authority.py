#!/usr/bin/env python3
"""Synthetic signed cold transport transcripts, not KMS/native acceptance.

The encrypted bytes are labelled opaque test ciphertext, not a working cipher
or provisioned secret. Exact canonical ciphertext originals are bound by real
test signatures in C9 and both key authorizations. No successful validator is
mocked; no production signer, key provisioning, owner or network call runs.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_encrypted_authority as encrypted
from catchplate import native_pilot_genesis_verifier_authority as verifier
from catchplate import native_pilot_genesis_key_profile as keys
from catchplate import native_shadow_key_contract as contract
import test_native_pilot_genesis_key_authority as key_tests
import test_native_pilot_genesis_parent_authority as parents

p = g.p
ENCRYPTED_DOMAIN = "catchplate.nativeShadowEncryptedKeyDelivery.signature/v1"
VERIFIER_DOMAIN = "catchplate.nativeShadowVerifierTransport.signature/v1"


def clocks_for(base):
    return {name: base[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}


def independent_signed(api, domain, payload, key):
    message = (b"catchplate.signedEnvelope/v1\0" + domain.encode("ascii")
        + b"\0catchplate.canonicalJson/ascii-integer-v1\0" + g.canonical(payload))
    return g.canonical({"apiVersion": api, "authorization": {"payload": payload,
        "signature": p.encoded(key.sign(message))}})


def rebind_pair(base, role, delivery):
    """Re-sign test key purposes after an actual-format test C9 has changed."""
    value = p.document(base["pairs"][role]["roleKeyInputOriginal"], keys.MAX_INPUT)
    value.update(deliveryInputOriginal=p.canonical(delivery["input"]).decode("ascii"),
        deliveryOriginal=delivery["raw"].decode("ascii"))
    role_input = p.canonical(value)
    prepared = keys.prepare_input("role-keys", role, role_input, **clocks_for(base))
    role_raw = key_tests.independent_signed(key_tests.ROLE_DOMAIN, prepared["payload"], base["supervisor_key"])
    admission_input = p.canonical({**value, "operation": "admission", "roleKeyOriginal": role_raw.decode("ascii")})
    prepared = keys.prepare_input("admission", role, admission_input, **clocks_for(base))
    admission_raw = key_tests.independent_signed(key_tests.ADMISSION_DOMAIN, prepared["payload"], base["supervisor_key"])
    return dict(zip(encrypted.PAIR_FIELDS, (role_input, role_raw, admission_input, admission_raw), strict=True))


def replace_c9(source, payload, *, runtime_raw=None):
    # Cryptography keys are existing test objects, never deep-copied owners.
    result = {**source, "input": copy.deepcopy(source["input"])}
    if runtime_raw is not None:
        result["runtime_raw"] = runtime_raw
        result["input"]["runtimeOriginal"] = runtime_raw.decode("ascii")
        payload["runtimeConfig"]["sha256"] = p.sha(runtime_raw)
    result["input"]["payloadOriginal"] = g.canonical(payload).decode("ascii")
    result["raw"] = g.canonical({"apiVersion": "catchplate.policyCustodyGuestDelivery/v1", "payload": payload,
        "signatureBase64url": p.encoded(source["key"].sign(b"catchplate.policyCustodyGuestDelivery.signature/v1\0" + g.canonical(payload)))})
    return result


def attach_ciphertext(base, role, *, runtime_raw=None):
    """For launch controls: endpoints first, rebuilt coordinator runtime last.

    The optional complete runtime must already satisfy the real cold validators.
    This helper changes no approved scope, parent observation or static manifest.
    """
    clocks = clocks_for(base)
    pair = keys.admitted_pair(role, *(base["pairs"][role][name] for name in encrypted.PAIR_FIELDS), **clocks)
    scope = pair["expectedScope"]
    inventory_raw = g.canonical({"apiVersion": "catchplate.nativeShadowLocalKeyInventory/v1",
        **{name: scope[name] for name in ("fullKeySetRootSha256", "localKeySetRootSha256", "localKeys")}})
    ciphertext_raw = g.canonical({"apiVersion": "catchplate.nativeShadowEncryptedLocalKeys/v1",
        "inventorySha256": p.sha(inventory_raw), "nonce": p.encoded(bytes([41 + keys.ROLES.index(role)]) * 12),
        "ciphertext": p.encoded(b"SYNTHETIC OPAQUE CIPHERTEXT, NOT A SECRET / " + role.encode("ascii"))})
    source = base["deliveries"][role]
    payload = g.document(source["raw"], 65536)["payload"]
    payload["credentials"] = [{"name": "shadow-encrypted-role-inventory",
        "original": parents.pin(role + "-synthetic-ciphertext", p.sha(ciphertext_raw)),
        "length": len(ciphertext_raw), "signing": None}]
    delivery = replace_c9(source, payload, runtime_raw=runtime_raw)
    pair_raws = rebind_pair(base, role, delivery)
    transport = {"apiVersion": "catchplate.nativeShadowKeyKmsTransport/v1", "kmsParentPort": 2048,
        "kmsKeyId": "synthetic-kms-key-not-contacted", "ciphertextBlobSha256": key_tests.labelled(role + "-unexecuted-kms-blob"),
        "encryptionContext": {"catchplatePurpose": "native-shadow-local-role-keys/v1", "testOnly": role},
        "kekSha256": key_tests.labelled(role + "-unexecuted-kek"), "encryptedInventorySha256": p.sha(ciphertext_raw),
        "helperImage": {"profile": "sealed-memfd-squashfs-v1", "imagePath": contract.IMAGE,
            "imageSha256": key_tests.labelled("unexecuted-helper-image"),
            "interpreterSha256": key_tests.labelled("unexecuted-interpreter"), "helperSha256": key_tests.labelled("unexecuted-helper")}}
    transport_raw = g.canonical(transport)
    common = {"role": role, **{name: raw.decode("ascii") for name, raw in pair_raws.items()},
        "issuedAtUnixNanos": base["now_unix_ns"], "expiresAtUnixNanos": base["now_unix_ns"] + 5_000_000_000}
    encrypted_input = p.canonical({"apiVersion": encrypted.API, **common,
        "transportOriginal": transport_raw.decode("ascii"), "encryptedInventoryOriginal": ciphertext_raw.decode("ascii")})
    checked = encrypted.prepare_input(role, encrypted_input, **clocks)
    encrypted_raw = independent_signed("catchplate.nativeShadowEncryptedKeyDelivery/v1", ENCRYPTED_DOMAIN,
        checked["payload"], base["supervisor_key"])
    verifier_input = p.canonical({"apiVersion": verifier.API, **common, "parentPort": 4096 + keys.ROLES.index(role)})
    checked = verifier.prepare_input(role, verifier_input, **clocks)
    verifier_raw = independent_signed("catchplate.nativeShadowVerifierTransport/v1", VERIFIER_DOMAIN,
        checked["payload"], base["supervisor_key"])
    return {"delivery": delivery, "pair": pair_raws, "inventory_raw": inventory_raw, "ciphertext_raw": ciphertext_raw,
        "transport_raw": transport_raw, "encrypted_input_raw": encrypted_input, "encrypted_raw": encrypted_raw,
        "verifier_input_raw": verifier_input, "verifier_raw": verifier_raw}


def fixture():
    base = key_tests.fixture()
    return {"base": base, "clocks": clocks_for(base),
        "roles": {role: attach_ciphertext(base, role) for role in keys.ROLES}}


class GenesisTransportAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture()

    def input(self, kind, role=None):
        role = role or keys.ROLES[0]
        module = encrypted if kind == "encrypted" else verifier
        return module.input_document(self.f["roles"][role][kind + "_input_raw"])

    def prepare(self, kind, value, **clocks):
        module = encrypted if kind == "encrypted" else verifier
        return module.prepare_input(value["role"], p.canonical(value), **(clocks or self.f["clocks"]))

    def refused(self, kind, value, **clocks):
        with self.assertRaises((ValueError, InvalidSignature, KeyError, TypeError)):
            self.prepare(kind, value, **clocks)

    def test_all_three_encrypted_outputs_bind_exact_signed_c9_ciphertext_and_assigned_inventory(self):
        for role, row in self.f["roles"].items():
            context = encrypted.prepare_input(role, row["encrypted_input_raw"], **self.f["clocks"])
            payload, pair = context["payload"], context["pair"]
            self.assertEqual(context["encrypted_inventory_raw"], row["ciphertext_raw"])
            self.assertEqual(context["inventory_raw"], row["inventory_raw"])
            self.assertEqual(payload["transport"]["encryptedInventorySha256"], p.sha(row["ciphertext_raw"]))
            self.assertEqual(payload["guest"]["deliverySha256"], p.sha(row["delivery"]["raw"]))
            self.assertEqual(payload["keyAuthorizationSha256"], p.sha(row["pair"]["roleKeyOriginal"]))
            self.assertEqual(payload["localKeySetRootSha256"], pair["expectedScope"]["localKeySetRootSha256"])
            self.assertEqual(encrypted.checked_result(role, row["encrypted_input_raw"],
                {"original": row["encrypted_raw"].decode("ascii"), "sha256": p.sha(row["encrypted_raw"])}, **self.f["clocks"]), row["encrypted_raw"])

    def test_all_three_verifier_outputs_select_actual_assigned_verifier_and_fixed_native_paths(self):
        for role, row in self.f["roles"].items():
            context = verifier.prepare_input(role, row["verifier_input_raw"], **self.f["clocks"])
            payload, selected = context["payload"], context["pair"]["authorityKeys"][-2]
            for target, source in (("verifierKeyId", "keyId"), ("verifierKeySpkiSha256", "keySpkiSha256"),
                    ("verifierKeyMaterialSha256", "keyMaterialSha256")):
                self.assertEqual(payload[target], selected[source])
            self.assertEqual(selected["role"], "custody-attestation-verifier")
            self.assertEqual(context["path"], "/etc/catchplate/native-pilot-inputs/native-" + role + "-verifier.json")
            self.assertEqual(verifier.checked_result(role, row["verifier_input_raw"],
                {"original": row["verifier_raw"].decode("ascii"), "sha256": p.sha(row["verifier_raw"])}, **self.f["clocks"]), row["verifier_raw"])

    def test_missing_ciphertext_c9_slot_cannot_be_replaced_by_a_public_hash_claim(self):
        value = self.input("encrypted")
        value.update({name: raw.decode("ascii") for name, raw in self.f["base"]["pairs"][keys.ROLES[0]].items()})
        self.refused("encrypted", value)

    def test_ciphertext_literal_inventory_digest_and_transport_pin_all_join(self):
        original = self.input("encrypted")
        for field, mutate in (("encryptedInventoryOriginal", lambda v: v.update(inventorySha256=key_tests.labelled("other inventory"))),
                ("encryptedInventoryOriginal", lambda v: v.update(ciphertext=p.encoded(bytes(16)))),
                ("encryptedInventoryOriginal", lambda v: v.update(nonce=p.encoded(bytes(11)))),
                ("transportOriginal", lambda v: v.update(encryptedInventorySha256=key_tests.labelled("other ciphertext")))):
            value = copy.deepcopy(original); wire = g.document(value[field].encode("ascii"), 32768)
            mutate(wire); value[field] = g.canonical(wire).decode("ascii")
            self.refused("encrypted", value)

    def test_authentic_c9_wrong_length_or_plaintext_role_slot_still_refuses(self):
        role = keys.ROLES[0]; row = self.f["roles"][role]
        for mutate in (lambda payload: payload["credentials"][0].update(length=1),
                lambda payload: payload["credentials"].append({"name": "shadow-key-custody-ingress-admission",
                    "original": parents.pin("forbidden-plaintext-slot"), "length": 32, "signing": None})):
            payload = g.document(row["delivery"]["raw"], 65536)["payload"]
            mutate(payload)
            delivery = replace_c9(row["delivery"], payload)
            pair = rebind_pair(self.f["base"], role, delivery)
            value = self.input("encrypted"); value.update({name: raw.decode("ascii") for name, raw in pair.items()})
            self.refused("encrypted", value)

    def test_only_v1_kms_local_role_profile_and_exact_supplied_helper_are_accepted(self):
        original = self.input("encrypted")
        for mutate in (lambda v: v.update(apiVersion="catchplate.nativeShadowKeyKmsTransport/v2"),
                lambda v: v["encryptionContext"].update(catchplatePurpose="native-shadow-local-role-keys-and-request-commitment/v2"),
                lambda v: v["helperImage"].update(imagePath="/approved/arbitrary-helper.squashfs"),
                lambda v: v.update(kmsParentPort=(1 << 32) - 1)):
            value = copy.deepcopy(original); wire = g.document(value["transportOriginal"].encode("ascii"), 16384)
            mutate(wire); value["transportOriginal"] = g.canonical(wire).decode("ascii")
            self.refused("encrypted", value)
        value = self.input("encrypted"); value["requestCommitmentOriginal"] = "{}"
        self.refused("encrypted", value)

    def test_hot_role_fallback_unknown_fields_and_output_apis_are_closed(self):
        for kind, old_api in (("encrypted", "catchplate.nativePilotEncryptedAuthorityInput/v1"),
                ("verifier", "catchplate.nativePilotVerifierAuthorityInput/v1")):
            for changes in ({"apiVersion": old_api}, {"role": "retrieval"}, {"path": "/etc/catchplate/native-shadow-public-exchange.json"}):
                self.refused(kind, {**self.input(kind), **changes})
        role, row = keys.ROLES[0], self.f["roles"][keys.ROLES[0]]
        value = g.document(row["encrypted_raw"], 65536); value["apiVersion"] = "catchplate.nativeShadowEncryptedKeyDelivery/v2"
        raw = g.canonical(value)
        with self.assertRaises(ValueError):
            encrypted.checked_result(role, row["encrypted_input_raw"], {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.f["clocks"])

    def test_verifier_port_range_key_selection_and_same_key_wrong_purpose_refuse(self):
        for port in (True, 1023, (1 << 32) - 1):
            self.refused("verifier", {**self.input("verifier"), "parentPort": port})
        role, row = keys.ROLES[0], self.f["roles"][keys.ROLES[0]]
        context = verifier.prepare_input(role, row["verifier_input_raw"], **self.f["clocks"])
        wrong_domain = independent_signed(verifier.OUTPUT_API, ENCRYPTED_DOMAIN, context["payload"], self.f["base"]["supervisor_key"])
        payload = copy.deepcopy(context["payload"]); payload["verifierKeyId"] = payload["signingKeyId"]
        wrong_key = independent_signed(verifier.OUTPUT_API, VERIFIER_DOMAIN, payload, self.f["base"]["supervisor_key"])
        for raw in (wrong_domain, wrong_key):
            with self.assertRaises((ValueError, InvalidSignature)):
                verifier.checked_result(role, row["verifier_input_raw"], {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.f["clocks"])

    def test_original_pair_and_own_boot_unix_limits_cannot_be_renewed(self):
        for kind in ("encrypted", "verifier"):
            value = self.input(kind); context = self.prepare(kind, value)
            self.assertLessEqual(context["deadline"], context["pair"]["deadline"])
            self.assertLessEqual(context["epochLimit"], context["pair"]["epochLimit"])
            self.assertEqual(context["epochLimit"], value["expiresAtUnixNanos"])
            self.refused(kind, value, **{**self.f["clocks"], "now_boottime_ns": context["deadline"]})
            self.refused(kind, value, **{**self.f["clocks"], "now_unix_ns": context["epochLimit"]})
            self.refused(kind, {**value, "expiresAtUnixNanos": value["expiresAtUnixNanos"] + 100_000_000_000})
            self.refused(kind, value, **{**self.f["clocks"], "boot": (p.encoded(bytes([55]) * 16), *self.f["clocks"]["boot"][1:])})

    def test_pair_splice_signed_result_drift_and_false_output_pins_refuse(self):
        for kind, module in (("encrypted", encrypted), ("verifier", verifier)):
            value = self.input(kind)
            value["admissionOriginal"] = self.f["roles"][keys.ROLES[1]]["pair"]["admissionOriginal"].decode("ascii")
            self.refused(kind, value)
            role, row = keys.ROLES[0], self.f["roles"][keys.ROLES[0]]
            raw = row[kind + "_raw"]
            with self.assertRaises(ValueError):
                module.checked_result(role, row[kind + "_input_raw"],
                    {"original": raw.decode("ascii"), "sha256": key_tests.labelled("false-output-pin")}, **self.f["clocks"])
            value = g.document(raw, module.MAX_OUTPUT)
            value["authorization"]["payload"]["guest"]["deliverySha256"] = key_tests.labelled("other delivery")
            raw = independent_signed(module.OUTPUT_API, module.DOMAIN, value["authorization"]["payload"], self.f["base"]["supervisor_key"])
            with self.assertRaises(ValueError):
                module.checked_result(role, row[kind + "_input_raw"],
                    {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.f["clocks"])


if __name__ == "__main__":
    unittest.main()

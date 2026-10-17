#!/usr/bin/env python3
"""Bounded synthetic public controls, not a complete constructed transcript.

Bootstrap/window and bridge key/admission signatures use deterministic test
keys. Process facts, Nitro policy and origin notices are synthetic data. The
inner verifier/origin projections do not claim complete constructed-evidence
authentication, a retained owner, live signer, installation or cleanup.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from catchplate import native_pilot_continuation_profile as profile
from catchplate import native_pilot_driver_authority as driver
from test_native_pilot_bridge_authorizations import fixture as bridge_fixture, pair, clocks
from test_native_pilot_native_services import fixture as native_policy_fixture
from test_native_pilot_generation_scope import key_fixture, signed_message, encoded, NOW
from test_native_pilot_closure_set import canonical, sha, synthetic


def policy_fixture(value):
    trust = json.loads(value["recipeOriginals"]["trustOriginal"])
    public = Ed25519PublicKey.from_public_bytes(profile.p.decoded(trust["assignmentKey"]["publicKeyBase64url"], size=32))
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"apiVersion": profile.API,
        "verifierSettings": native_policy_fixture()["verifierSettings"]["retrieval"],
        "assignmentPublicKeyOriginal": pem.decode("ascii"), "assignmentPublicKeySha256": sha(pem)}


def bootstrap_fixture():
    bridge, _, _ = bridge_fixture()
    delivered = json.loads(bridge["deliveryInputOriginal"])
    control = json.loads(bridge["controlOriginal"])
    config = json.loads(delivered["ownerConfigurationOriginal"])
    window = json.loads(delivered["windowOriginal"])["payload"]
    key = config["lifecycle"]["constructedAdmissionAuthority"]
    early = {"apiVersion": "catchplate.nativeShadowBootstrapDriverAdmission/v1",
        "purpose": "native-driver-bootstrap-admission", "configurationSha256": control["configurationSha256"],
        "windowSha256": control["windowSha256"], "bootstrapObservationOriginal": delivered["observationOriginal"],
        "parent": {"processId": 42, "startTimeTicks": 99, "parentId": 2, "pidfdDevice": 0, "pidfdInode": 77},
        "parentExecutableSha256": control["supervisorExecutableSha256"], "pidNamespaceSha256": synthetic("pid-namespace"),
        "issuedAtUnixNanos": NOW - 1_000_000, "expiresAtUnixNanos": NOW - 1_000_000 + 30_000_000_000,
        **{name: window[name] for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")},
        "signingKeyId": key["keyId"], "signingKeySpkiSha256": key["keySpkiSha256"]}
    value = {"apiVersion": "catchplate.nativePilotDriverAuthorityInput/v1", "operation": "bootstrap",
        "controlOriginal": bridge["controlOriginal"], "configurationOriginal": delivered["ownerConfigurationOriginal"],
        "windowOriginal": delivered["windowOriginal"], "deliveryConfigurationOriginal": delivered["configurationOriginal"],
        "observationOriginal": delivered["observationOriginal"], "payloadOriginal": canonical(early).decode("ascii")}
    signature = key_fixture("custody-supervisor-capability")[0].sign(signed_message(driver.admission.BOOTSTRAP_DOMAIN, early))
    signed = canonical({"payload": early, "signature": encoded(signature)})
    return canonical(value), {"original": signed.decode("ascii"), "sha256": sha(signed)}, early


class ContinuationProfileControls(unittest.TestCase):
    def test_closed_static_settings_and_canonical_assignment_public_pin(self):
        value, _, _ = bridge_fixture()
        fragment = policy_fixture(value)
        before = copy.deepcopy(fragment)
        self.assertEqual(profile.validate_policy(fragment), before)
        self.assertEqual(fragment, before)
        for field, replacement in (("verifierConfigurationOriginal", "{}"),
                                   ("assignmentPublicKeySha256", synthetic("wrong-key")),
                                   ("assignmentPublicKeyOriginal", fragment["assignmentPublicKeyOriginal"] + "\n")):
            bad = copy.deepcopy(fragment); bad[field] = replacement
            if field == "assignmentPublicKeyOriginal":
                bad["assignmentPublicKeySha256"] = sha(replacement.encode("ascii"))
            with self.subTest(field=field), self.assertRaises(ValueError):
                profile.validate_policy(bad)

    def test_verifier_projection_uses_authenticated_bridge_pair_not_static_scope(self):
        value, guest, manifest = bridge_fixture()
        fragment = policy_fixture(value)
        context = pair(value, guest, manifest)
        records = {}
        for job, input_field, result_field in (
                ("native-role-keys-bridge", "roleKeyInputOriginal", "roleKeyOriginal"),
                ("native-key-admission-bridge", "admissionInputOriginal", "admissionOriginal")):
            raw = context[result_field].encode("ascii")
            records[job] = {"inputOriginal": context[input_field].encode("ascii"),
                "result": {"original": context[result_field], "sha256": sha(raw)}}
        delivered = json.loads(value["deliveryInputOriginal"])
        digest = sha(value["deliveryOriginal"].encode("ascii"))
        records["native-delivery-bridge"] = {"inputOriginal": value["deliveryInputOriginal"].encode("ascii"),
            "result": {"original": value["deliveryOriginal"], "sha256": digest,
                "pin": {"path": profile.publication.DESTINATIONS["native-delivery-bridge"], "sha256": digest}}}
        source = {"recipeOriginals": value["recipeOriginals"], "measured": value["measured"]}
        bootstrap = {"control": value["controlOriginal"].encode("ascii"),
            "configuration": delivered["ownerConfigurationOriginal"].encode("ascii"),
            "window": delivered["windowOriginal"].encode("ascii"),
            "deliveryConfiguration": delivered["configurationOriginal"].encode("ascii")}
        raw, actual_pair = profile._verifier(fragment, source, records, bootstrap, clocks=clocks())
        config = json.loads(raw)
        self.assertEqual(actual_pair, context)
        self.assertEqual(config["apiVersion"], "catchplate.nativeShadowNitroVerifierConfiguration/v3")
        self.assertEqual(config["expectedScope"]["guest"], guest)
        self.assertEqual(config["operation"]["deadlineBoottimeNs"], guest["startupDeadlineBoottimeNs"])
        bad = copy.deepcopy(fragment)
        pem = key_fixture("unrelated-assignment")[0].public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        bad.update(assignmentPublicKeyOriginal=pem.decode("ascii"), assignmentPublicKeySha256=sha(pem))
        with self.assertRaises(ValueError):
            profile._verifier(bad, source, records, bootstrap, clocks=clocks())

    def test_complete_bootstrap_shared_prepare_and_real_fixture_signature(self):
        raw, result, payload = bootstrap_fixture()
        prepared = driver.prepare_input("bootstrap", raw, **clocks())
        self.assertEqual(set(prepared), {"payload", "authority", "window", "deadline", "epochLimit", "domain"})
        self.assertEqual(prepared["payload"], payload)
        self.assertEqual(prepared["deadline"], int(payload["startupDeadlineBoottimeNs"]))
        self.assertEqual(driver.checked_result("bootstrap", raw, result, **clocks()), result["original"].encode("ascii"))

    def test_shared_prepare_rejects_wrong_boot_startup_expiry_and_changed_original(self):
        raw, _, payload = bootstrap_fixture()
        for change in ({"boot": (encoded(b"another-boot-16!"), 4, 5)},
                       {"now_boottime_ns": int(payload["startupDeadlineBoottimeNs"])},
                       {"now_unix_ns": payload["expiresAtUnixNanos"]}, {"now_boottime_ns": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                driver.prepare_input("bootstrap", raw, **(clocks() | change))
        value = json.loads(raw)
        value["observationOriginal"] = value["observationOriginal"] + "\n"
        with self.assertRaises(ValueError):
            driver.prepare_input("bootstrap", canonical(value), **clocks())

    def test_shared_result_rejects_rehashed_payload_bad_signature_and_unknown_field(self):
        raw, result, _ = bootstrap_fixture()
        for mutation in ("payload", "signature", "unknown"):
            altered = json.loads(result["original"])
            if mutation == "payload": altered["payload"]["pidNamespaceSha256"] = synthetic("another-namespace")
            elif mutation == "signature": altered["signature"] = encoded(bytes(64))
            else: altered["bootstrapAdmissionOriginal"] = "{}"
            changed = canonical(altered)
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, InvalidSignature)):
                driver.checked_result("bootstrap", raw, {"original": changed.decode("ascii"), "sha256": sha(changed)}, **clocks())

    def test_inner_origin_and_handoff_associations_never_claim_installed_or_cleanup(self):
        # Deliberately inner-only data: not a complete signed constructed input.
        observation = b'{"synthetic":"original-driver-observation"}'
        scope_raw, admitted = b'{"synthetic":"signed-scope-slot"}', b'{"synthetic":"signed-admission-slot"}'
        raw = canonical({"publicAdmissionOriginal": canonical({
            "bootstrapObservationOriginal": observation.decode("ascii")}).decode("ascii")})
        observed = {"constructedObservation": {"apiVersion": "catchplate.nativeShadowDriverBridgeConstructed/v1",
            "observationSha256": sha(observation), "scopeSha256": sha(scope_raw)}, "constructedAdmissionSha256": sha(admitted)}
        profile._origin(observed, input_raw=raw, admission_raw=admitted, scope_raw=scope_raw)
        bad = copy.deepcopy(observed); bad["constructedAdmissionSha256"] = synthetic("different-actual-output")
        with self.assertRaises(ValueError): profile._origin(bad, input_raw=raw, admission_raw=admitted, scope_raw=scope_raw)
        handoff = {"originHandoff": {"apiVersion": "catchplate.nativeGenerationOriginHandoff/v1",
            "okForAction": False, "automaticRetryAllowed": False, "originSha256": synthetic("relay-original")}}
        profile._handoff(handoff)
        for field in ("okForAction", "automaticRetryAllowed", "installed", "cleanupComplete"):
            bad = copy.deepcopy(handoff); bad["originHandoff"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError): profile._handoff(bad)

    def test_only_ordinary_generation_original_codec_accepts_canonical_u64(self):
        # Codec boundary only, not admission of this intentionally non-grant DTO.
        raw = canonical({"operationGeneration": (1 << 64) - 1})
        self.assertEqual(profile.scope_authority._generation_original(raw.decode("ascii"))[0], raw)
        with self.assertRaises(ValueError): driver._original(raw.decode("ascii"), 65536)
        with self.assertRaises(ValueError): profile.scope_authority._generation_original((raw + b"\n").decode("ascii"))


if __name__ == "__main__":
    unittest.main()

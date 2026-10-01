#!/usr/bin/env python3
"""Synthetic bridge launch public-original controls, not live installation.

The deterministic test keys sign independently framed fixture payloads, never
an issuer entrypoint. Existing bridge fixtures supply labelled synthetic C9,
process, activation and operational runtime data. Nested runtime/history and
TrustedTime fixtures do not claim native admission, live peers, clock service,
KMS, independently approved policy or filesystem publication.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_launch_publication as launch
from test_native_pilot_bridge_authorizations import (
    fixture as bridge_fixture, pair, expected_key, signed, clocks, public_keys)
from test_native_pilot_bridge_runtime import helper_fixture
from test_native_pilot_closure_set import canonical, sha, synthetic
from test_native_pilot_generation_scope import key_fixture, signed_message, encoded, NOW

COMPONENTS = {"trust": "trust", "timeBootstrap": "time-bootstrap", "assignment": "assignment",
    "closure": "closure", "keys": "keys", "encryptedKeys": "encrypted-keys",
    "admission": "admission", "verifierTransport": "verifier"}
CLOCK = {"parentPort": 10444, "maximumBracketNanos": "1000000", "timestampErrorNanos": 1000,
    "maximumClockRateErrorPpm": 10}
GRANT_DOMAIN = "serverware.nativeShadowTrustedTimeServiceAssignment.signature/v1"
CLOSURE_DOMAIN = "serverware.nativeCustodyClosureAssignment.signature/v3"


def detached(payload, domain):
    return {"payload": payload, "signature": encoded(key_fixture("custody-supervisor-capability")[0].sign(
        signed_message(domain, payload)))}


def set_original(bundle, name, value):
    raw = canonical(value)
    bundle["originals"][name] = raw.decode("ascii")
    bundle["keyAdmission"][name]["sha256"] = sha(raw)


def fixture(*, version=10, large=False):
    first, guest, manifest = bridge_fixture(large=large)
    source = json.loads(first["deliveryInputOriginal"])
    runtime = json.loads(source["runtimeOriginal"])
    trusted_key = next(key for key in public_keys() if key["role"] == "custody-trusted-time-response")
    endpoint = next(row for row in runtime["proofEndpoints"] if row["endpointKind"] == "trusted-time")
    endpoint.update(authorityKeyId=trusted_key["keyId"], authorityKeySpkiSha256=trusted_key["keySpkiSha256"])
    if version == 9:
        runtime["apiVersion"] = "serverware.policyCustodyProductionRpcRuntime/v9"
        del runtime["ordinaryInitialHistories"]
    elif version == 11:
        runtime["apiVersion"] = "serverware.policyCustodyProductionRpcRuntime/v11"
        runtime["helperBootstrap"] = helper_fixture()
    runtime_raw = canonical(runtime)
    source["runtimeOriginal"] = runtime_raw.decode("ascii")
    c9 = json.loads(first["deliveryOriginal"])
    c9["payload"]["runtimeConfig"]["sha256"] = sha(runtime_raw)
    c9["signatureBase64url"] = encoded(key_fixture("bridge-c9")[0].sign(
        b"serverware.policyCustodyGuestDelivery.signature/v1\0" + canonical(c9["payload"])))
    delivery_raw = canonical(c9)
    source["payloadOriginal"] = canonical(c9["payload"]).decode("ascii")
    first.update(deliveryInputOriginal=canonical(source).decode("ascii"), deliveryOriginal=delivery_raw.decode("ascii"))
    guest.update(deliverySha256=sha(delivery_raw), runtimeConfigurationSha256=sha(runtime_raw))
    pair_context = pair(first, guest, manifest)
    key = expected_key(first, guest, manifest)
    recipe = first["recipeOriginals"]
    trust = json.loads(recipe["trustOriginal"])
    selected = json.loads(recipe["closureSetOriginal"])
    leaf = launch.assignment_profile.closure_binding(json.loads(recipe["assignmentOriginal"]), canonical(selected), "bridge")
    closure_payload = {name: key[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision",
        "guest", "trustCheckpointId", "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos",
        "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256")}
    closure_payload.update(apiVersion="serverware.nativeCustodyClosureAssignment/v3", purpose="shadow-custody-closure-set-member",
        profile="native-multi-guest-closure-set-v1", guestRole="bridge",
        **{name: leaf[name] for name in ("manifestSha256", "setRootSha256", "seccompSetRootSha256", "leafSha256")})
    closure = {"apiVersion": "serverware.nativeCustodyClosure/v3", "manifest": manifest,
        "closureSet": selected, "authorization": detached(closure_payload, CLOSURE_DOMAIN)}
    common = {name: key[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "guest",
        "fullKeySetRootSha256", "challengeBase64url", "trustCheckpointId", "revocationGeneration",
        "revocationRootSha256", "signingKeyId", "signingKeySpkiSha256")}
    common.update(keyAuthorizationSha256=sha(pair_context["roleKeyOriginal"].encode("ascii")),
        issuedAtUnixNanos=NOW - 100_000_000, expiresAtUnixNanos=NOW + 100_000_000)
    config = json.loads(source["ownerConfigurationOriginal"])
    encrypted_payload = dict(common, apiVersion="serverware.nativeShadowEncryptedKeyDeliveryAssignment/v1",
        purpose="kms-recipient-shadow-local-keys", transport=config["continuation"]["keyTransport"],
        localKeySetRootSha256=json.loads(pair_context["admissionOriginal"])["payload"]["localKeySetRootSha256"])
    encrypted_raw, _ = signed("encrypted-delivery", encrypted_payload)
    verifier_key = public_keys()[-2]
    verifier_payload = dict(common, apiVersion="serverware.nativeShadowVerifierTransportAssignment/v1",
        purpose="public-shadow-nitro-verification", parentPort=11443, verifierKeyId=verifier_key["keyId"],
        verifierKeySpkiSha256=verifier_key["keySpkiSha256"], verifierKeyMaterialSha256=verifier_key["keyMaterialSha256"])
    verifier_raw, _ = signed("verifier-transport", verifier_payload)
    clock = {"apiVersion": "serverware.nativeShadowGuestTimeBootstrap/v1", "guest": guest,
        "signingKeyId": trust["timeKey"]["keyId"], **CLOCK}

    # This is a different guest's grant: the bridge is its allowed client.
    # No endpoint C9/clock-service transcript or executing process is claimed.
    time_guest = dict(guest, uid=endpoint["expectedPeer"]["uid"], gid=endpoint["expectedPeer"]["gid"],
        **{name: synthetic("trusted-time/" + name) for name in
            ("configurationSha256", "deliverySha256", "runtimeConfigurationSha256")})
    observed = json.loads(source["observationOriginal"])
    peer = dict(endpoint["expectedPeer"], uid=guest["uid"], gid=guest["gid"], pid=observed["processId"],
        startTimeTicks=observed["driver"]["processStartTimeTicks"])
    grant_payload = {name: key[name] for name in ("assignmentPayloadSha256", "trustCheckpointId",
        "revocationGeneration", "revocationRootSha256", "signingKeyId", "signingKeySpkiSha256")}
    grant_payload.update(apiVersion="serverware.nativeShadowTrustedTimeServiceAssignment/v1",
        purpose="native-shadow-trusted-time-response", guest=time_guest,
        keyAuthorizationSha256=synthetic("actual-other-guest-authorization"), expectedPeer=peer,
        clockBootstrapSha256=synthetic("other-guest-clock-bootstrap"),
        issuedAtUnixNanos=NOW - 200_000_000, expiresAtUnixNanos=NOW + 200_000_000)
    grant_raw = canonical(detached(grant_payload, GRANT_DOMAIN))
    originals = {"trust": recipe["trustOriginal"], "timeBootstrap": canonical(clock).decode("ascii"),
        "assignment": recipe["assignmentOriginal"], "closure": canonical(closure).decode("ascii"),
        "keys": canonical({"apiVersion": "serverware.nativeShadowRoleKeys/v2",
            "authorization": json.loads(pair_context["roleKeyOriginal"])}).decode("ascii"),
        "encryptedKeys": encrypted_raw.decode("ascii"), "admission": pair_context["admissionOriginal"],
        "verifierTransport": verifier_raw.decode("ascii")}
    inner = {"apiVersion": "serverware.nativeShadowGuestLaunch/v1",
        "deliveryConfiguration": config["deliveryConfiguration"], "delivery": {
            "path": "/etc/serverware/native-pilot-inputs/native-delivery-bridge.json", "sha256": sha(delivery_raw)}}
    for name, suffix in COMPONENTS.items():
        inner[name] = {"path": "/etc/serverware/native-pilot-inputs/native-bridge-" + suffix + ".json",
            "sha256": sha(originals[name].encode("ascii"))}
    bundle = {"apiVersion": "serverware.nativePilotLaunchBundle/v1", "role": "bridge",
        "ownerConfigurationSha256": sha(source["ownerConfigurationOriginal"].encode("ascii")),
        "windowSha256": sha(source["windowOriginal"].encode("ascii")),
        "observationOriginal": source["observationOriginal"], "runtimeOriginal": source["runtimeOriginal"],
        "keyAdmission": inner, "originals": originals, "serviceGrant": {
            "path": "/etc/serverware/native-pilot-inputs/native-service-trustedTime.json", "sha256": sha(grant_raw)}}
    return bundle, pair_context, grant_raw


class BridgeLaunchControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle, cls.pair, cls.grant = fixture()

    def options(self, *, pair_context=None, grant=None):
        return dict(pair_context=self.pair if pair_context is None else pair_context,
            service_grant_original=self.grant if grant is None else grant, **clocks())

    def test_complete_public_preparation_exact_nine_pins_and_result(self):
        bundle, pair_context = copy.deepcopy(self.bundle), copy.deepcopy(self.pair)
        raw = canonical(bundle)
        context = launch.prepare_bridge_bundle(raw, **self.options(pair_context=pair_context))
        purposes = tuple("native-bridge-" + suffix for suffix in COMPONENTS.values()) + ("native-launch-bridge",)
        self.assertEqual(tuple(context["prepared"]), purposes)
        pins = {name: {"path": "/etc/serverware/native-pilot-inputs/" + name + ".json", "sha256": sha(value)}
            for name, value in context["prepared"].items()}
        self.assertEqual(context["pins"], pins)
        self.assertEqual(set(context), {"role", "window", "deadline", "epochLimit", "prepared", "pins", "launch"})
        self.assertEqual(json.loads(context["prepared"]["native-launch-bridge"])["apiVersion"], "serverware.nativeProofBridgeLaunch/v6")
        self.assertEqual(json.loads(context["prepared"]["native-bridge-keys"])["apiVersion"], "serverware.nativeShadowRoleKeys/v2")
        self.assertEqual(context["deadline"], 2_000_000_000)
        self.assertEqual(context["epochLimit"], NOW + 100_000_000)
        result = {"apiVersion": "serverware.nativePilotLaunchInstallation/v1", "role": "bridge",
            "bundleSha256": sha(raw), "startupDeadlineBoottimeNs": "2000000000", "lifetimeDeadlineBoottimeNs": "60000000000",
            "launch": pins["native-launch-bridge"], "pins": pins}
        self.assertEqual(launch.checked_bridge_result(raw, result, **self.options()), result)
        self.assertEqual(bundle, self.bundle); self.assertEqual(pair_context, self.pair)

    def test_result_hash_deadlines_and_runtime_republication_are_rejected(self):
        raw = canonical(self.bundle); context = launch.prepare_bridge_bundle(raw, **self.options())
        result = {"apiVersion": "serverware.nativePilotLaunchInstallation/v1", "role": "bridge",
            "bundleSha256": sha(raw), "startupDeadlineBoottimeNs": "2000000000", "lifetimeDeadlineBoottimeNs": "60000000000",
            "launch": context["launch"], "pins": context["pins"]}
        cases = [dict(result, bundleSha256=synthetic("other-bundle")), dict(result, installed=True),
            dict(result, startupDeadlineBoottimeNs="2000000001"), dict(result, role="retrieval")]
        changed = copy.deepcopy(result); changed["pins"]["bridge-runtime"] = {"path": "/etc/other.json", "sha256": synthetic("other")}
        cases.append(changed)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                launch.checked_bridge_result(raw, value, **self.options())

    def test_original_control_c9_activation_and_windows_are_authenticated(self):
        for change in ("control", "delivery", "activation"):
            pair_context = copy.deepcopy(self.pair)
            for field in ("roleKeyInputOriginal", "admissionInputOriginal"):
                value = json.loads(pair_context[field]); source = json.loads(value["deliveryInputOriginal"])
                if change == "control":
                    control = json.loads(value["controlOriginal"]); control["windowSha256"] = synthetic("different-window")
                    value["controlOriginal"] = canonical(control).decode("ascii")
                elif change == "delivery":
                    delivered = json.loads(value["deliveryOriginal"]); delivered["signatureBase64url"] = encoded(b"x" * 64)
                    value["deliveryOriginal"] = canonical(delivered).decode("ascii")
                else:
                    activation = json.loads(source["activationOriginal"]); activation[0]["inode"] += 1
                    source["activationOriginal"] = canonical(activation).decode("ascii")
                value["deliveryInputOriginal"] = canonical(source).decode("ascii")
                pair_context[field] = canonical(value).decode("ascii")
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                launch.prepare_bridge_bundle(canonical(self.bundle), **self.options(pair_context=pair_context))
        for field, value in (("now_boottime_ns", 2_000_000_000), ("now_unix_ns", NOW + 500_000_000)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                launch.prepare_bridge_bundle(canonical(self.bundle), **dict(self.options(), **{field: value}))

    def test_resigned_admission_cannot_replace_measured_production(self):
        bundle, pair_context = copy.deepcopy(self.bundle), copy.deepcopy(self.pair)
        value = json.loads(pair_context["admissionOriginal"])
        value["payload"]["productionConfigurationBindingSha256"] = synthetic("unapproved-production")
        raw, _ = signed("admission", value["payload"])
        pair_context["admissionOriginal"] = raw.decode("ascii")
        set_original(bundle, "admission", json.loads(raw))
        with self.assertRaises(ValueError):
            launch.prepare_bridge_bundle(canonical(bundle), **self.options(pair_context=pair_context))

    def test_late_signatures_and_bootstrap_transport_cannot_be_substituted(self):
        for name in ("closure", "encryptedKeys", "verifierTransport"):
            bundle = copy.deepcopy(self.bundle); value = json.loads(bundle["originals"][name])
            value["authorization"]["signature"] = encoded(b"x" * 64)
            set_original(bundle, name, value)
            with self.subTest(name=name), self.assertRaises(InvalidSignature):
                launch.prepare_bridge_bundle(canonical(bundle), **self.options())
        bundle = copy.deepcopy(self.bundle); value = json.loads(bundle["originals"]["encryptedKeys"])
        value["authorization"]["payload"]["transport"]["kmsKeyId"] = "different-synthetic-kms-key"
        raw, _ = signed("encrypted-delivery", value["authorization"]["payload"])
        set_original(bundle, "encryptedKeys", json.loads(raw))
        with self.assertRaises(ValueError): launch.prepare_bridge_bundle(canonical(bundle), **self.options())

    def test_recipe_time_bootstrap_and_fixed_delivery_pins_are_not_replaceable(self):
        for change in ("trust", "assignment", "time-key", "time-guest", "time-extra", "cold-path", "delivery-hash"):
            bundle = copy.deepcopy(self.bundle)
            if change in ("trust", "assignment"):
                value = json.loads(bundle["originals"][change]); value["apiVersion"] += "-other"
                set_original(bundle, change, value)
            elif change.startswith("time-"):
                value = json.loads(bundle["originals"]["timeBootstrap"])
                if change == "time-key": value["signingKeyId"] = synthetic("different-time-key")
                elif change == "time-guest": value["guest"]["uid"] += 1
                else: value["renewWindow"] = True
                set_original(bundle, "timeBootstrap", value)
            elif change == "cold-path": bundle["keyAdmission"]["deliveryConfiguration"]["path"] = "/etc/other.json"
            else: bundle["keyAdmission"]["delivery"]["sha256"] = synthetic("different-delivery")
            with self.subTest(change=change), self.assertRaises(ValueError):
                launch.prepare_bridge_bundle(canonical(bundle), **self.options())

    def test_trusted_time_signature_and_distinct_guest_client_binding(self):
        for change in ("signature", "client-pid", "time-uid", "assignment"):
            bundle = copy.deepcopy(self.bundle); grant = json.loads(self.grant)
            if change == "signature": grant["signature"] = encoded(b"x" * 64)
            else:
                if change == "client-pid": grant["payload"]["expectedPeer"]["pid"] += 1
                elif change == "time-uid": grant["payload"]["guest"]["uid"] += 1
                else: grant["payload"]["assignmentPayloadSha256"] = synthetic("different-assignment")
                grant = detached(grant["payload"], GRANT_DOMAIN)
            raw = canonical(grant); bundle["serviceGrant"]["sha256"] = sha(raw)
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                launch.prepare_bridge_bundle(canonical(bundle), **self.options(grant=raw))

    def test_version_selected_runtime_and_endpoint_api_remain_separate(self):
        for version, large, launch_version in ((9, False, 5), (10, True, 6), (11, True, 7)):
            bundle, pair_context, grant = fixture(version=version, large=large)
            context = launch.prepare_bridge_bundle(canonical(bundle), **self.options(pair_context=pair_context, grant=grant))
            self.assertEqual(json.loads(context["prepared"]["native-launch-bridge"])["apiVersion"],
                "serverware.nativeProofBridgeLaunch/v" + str(launch_version))
            self.assertNotIn("bridge-runtime", context["prepared"])
        bundle, pair_context, grant = fixture(version=9, large=True)
        with self.assertRaises(ValueError):
            launch.prepare_bridge_bundle(canonical(bundle), **self.options(pair_context=pair_context, grant=grant))
        with self.assertRaises(ValueError):
            launch.prepare_endpoint_bundle(canonical(self.bundle), delivery_input_original=b"{}", delivery_original=b"{}",
                service_grant_original=self.grant, commit_request_original=None, **clocks())
        for bundle in (dict(self.bundle, role="retrieval"), dict(self.bundle, unused=True)):
            with self.assertRaises(ValueError): launch.prepare_bridge_bundle(canonical(bundle), **self.options())


if __name__ == "__main__":
    unittest.main()

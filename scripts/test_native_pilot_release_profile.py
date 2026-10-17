#!/usr/bin/env python3
"""Synthetic release/scope primitives, not an operational release transcript.

Existing public fixtures supply real deterministic test signatures for C9,
bootstrap, ordinary grants and precreation. Runtime peers and descriptors are
labelled synthetic data. No live owner, issuer entrypoint, image, credential or
kernel operation runs. The complete retained commissioning composer is not
accepted by a fabricated handoff; only its shared pure wire helpers are tested.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from catchplate import native_pilot_release_profile as release
from catchplate import native_pilot_scope_authority as scope
from test_native_pilot_bridge_launches import fixture as bridge_fixture
from test_native_pilot_bridge_authorizations import clocks
from test_native_pilot_closure_set import canonical, sha, synthetic
from test_native_pilot_generation_scope import fixture as generation_fixture, key_fixture, signed_message, encoded
from test_native_pilot_native_deliveries import fixture as cohort_fixture
from test_native_pilot_ordinary_generations import context as ordinary_fixture, build as ordinary_input, result as ordinary_result

SCOPE_DOMAIN = b"catchplate.nativeShadowDriverScope.signature/v4\0"
RELEASE_DOMAIN = b"catchplate.nativeShadowProofCohortRelease.signature/v6\0"
BOOTSTRAP_DOMAIN = "catchplate.nativeShadowBootstrapDriverAdmission.signature/v1"


@lru_cache(maxsize=1)
def _scope_fixture():
    bundle, pair, time_grant = bridge_fixture(version=11)
    first = json.loads(pair["roleKeyInputOriginal"])
    source = json.loads(first["deliveryInputOriginal"])
    config, window = json.loads(source["ownerConfigurationOriginal"]), json.loads(source["windowOriginal"])["payload"]
    observed = json.loads(source["observationOriginal"])
    runtime = json.loads(source["runtimeOriginal"])
    ordinary = ordinary_fixture()
    grants = {}
    for role in scope.driver.ROLES:
        value = json.loads(ordinary_input(ordinary, role))
        payload = json.loads(value["payloadOriginal"])
        # Native ordinary counters are u64, not the generic profile's i64.
        payload["scope"]["trustedTimeRevocationGeneration"] = (1 << 63) + 9
        original = ordinary_result(role, payload)["original"]
        grants[role] = original
        runtime["generationAdmission"]["grants"][role] = sha(original.encode("ascii"))
        runtime["ordinaryInitialHistories"][role] = {"runtimeOriginal": ordinary["runtimes"][role].decode("ascii"),
            "generationGrantOriginal": original}
    runtime_raw = canonical(runtime)
    signed_c9 = json.loads(first["deliveryOriginal"])
    signed_c9["payload"]["runtimeConfig"]["sha256"] = sha(runtime_raw)
    signed_c9["signatureBase64url"] = encoded(key_fixture("bridge-c9")[0].sign(
        b"catchplate.policyCustodyGuestDelivery.signature/v1\0" + canonical(signed_c9["payload"])))
    c9_raw = canonical(signed_c9)
    inner = copy.deepcopy(bundle["keyAdmission"])
    inner["delivery"]["sha256"] = sha(c9_raw)
    launch_raw = canonical({"apiVersion": "catchplate.nativeProofBridgeLaunch/v7",
        "keyAdmission": inner, "trustedTime": bundle["serviceGrant"]})
    public_raw = canonical({"runtimeOriginal": runtime_raw.decode("ascii"),
        "deliveryOriginal": c9_raw.decode("ascii"), "generationOriginals": grants})
    _, previous, _ = generation_fixture()
    early = json.loads(previous["bootstrap_original"])["payload"]
    early.update(configurationSha256=sha(source["ownerConfigurationOriginal"].encode("ascii")),
        windowSha256=sha(source["windowOriginal"].encode("ascii")), bootstrapObservationOriginal=source["observationOriginal"])
    early_raw = canonical({"payload": early, "signature": encoded(key_fixture("custody-supervisor-capability")[0].sign(
        signed_message(BOOTSTRAP_DOMAIN, early)))})
    files = {"launch": launch_raw, "c9-configuration": source["configurationOriginal"].encode("ascii"),
        "c9-delivery": c9_raw, "c9-runtime": runtime_raw, "time-grant": time_grant}
    for name, field in (("trust", "trust"), ("time", "timeBootstrap"), ("assignment", "assignment"),
            ("closure", "closure"), ("keys", "keys"), ("encrypted", "encryptedKeys"),
            ("admission", "admission"), ("verifier", "verifierTransport")):
        files[name] = bundle["originals"][field].encode("ascii")
    records = [{"name": name, "device": 19, "inode": 20000 + index, "mode": stat.S_IFREG | 0o400,
        "uid": 0, "gid": 0, "length": len(raw)} for index, (name, raw) in enumerate(files.items())]
    for index, row in enumerate(signed_c9["payload"]["credentials"]):
        records.append({"name": "credential:" + row["name"], "device": 23, "inode": 30000 + index,
            "mode": stat.S_IFREG | 0o400, "uid": config["uid"], "gid": config["gid"], "length": row["length"]})
    for row in signed_c9["payload"]["activation"]:
        records.append({"name": "activation:" + row["name"], **{name: row[name]
            for name in ("device", "inode", "mode", "uid", "gid")}, "length": 0})
    operation = {"apiVersion": "catchplate.nativeShadowDriverOperation/v1", "launch": {
        "path": "/etc/catchplate/native-pilot-inputs/native-launch-bridge.json", "sha256": sha(launch_raw)},
        "descriptors": sorted(records, key=lambda row: row["name"]), "production": first["measured"]["production"]}
    value = {"apiVersion": "catchplate.nativePilotScopeSigningInput/v1",
        "configurationOriginal": source["ownerConfigurationOriginal"], "windowOriginal": source["windowOriginal"],
        "observationOriginal": source["observationOriginal"], "operationOriginal": canonical(operation).decode("ascii"),
        "publicBundleOriginal": public_raw.decode("ascii"), "deliveryConfigurationOriginal": source["configurationOriginal"],
        "launchOriginal": launch_raw.decode("ascii"), "bootstrapAdmissionOriginal": early_raw.decode("ascii")}
    expected = {"apiVersion": "catchplate.nativeShadowDriverScope/v4",
        "configurationSha256": sha(source["ownerConfigurationOriginal"].encode("ascii")),
        "windowSha256": sha(source["windowOriginal"].encode("ascii")),
        "observationSha256": sha(source["observationOriginal"].encode("ascii")),
        "kernelDriverIdentitySha256": observed["driver"]["identitySha256"], "invocationId": window["invocationId"],
        "startupDeadlineBoottimeNs": window["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": window["lifetimeDeadlineBoottimeNs"], "originals": {
            "runtimeSha256": sha(runtime_raw), "deliverySha256": sha(c9_raw),
            "generationGrants": {role: sha(raw.encode("ascii")) for role, raw in grants.items()}},
        "publicBundleSha256": sha(public_raw), "signingKeyId": config["phaseTwoAuthority"]["keyId"], "operation": operation}
    return canonical(value), clocks(), expected


def scope_fixture():
    """Complete public grant grammar; not a full native runtime/launch proof."""
    return copy.deepcopy(_scope_fixture())


def release_fixture():
    f = cohort_fixture()
    payload = {"apiVersion": "catchplate.nativeShadowProofCohortRelease/v6",
        "configurationSha256": sha(f["owner_configuration_raw"]), "precreationSha256": sha(f["window_raw"]),
        "observationSha256": sha(f["observation_raw"]), "invocationId": f["window"]["invocationId"],
        "signingKeyId": f["authority"]["keyId"], "externalDriverSha256": sha(canonical(f["observed"]["externalDriver"]))}
    for role in release.cohort.ENDPOINT_ROLES:
        payload[role] = {name: {"path": "/etc/catchplate/synthetic-" + role + "-" + name,
            "sha256": synthetic(role + "/" + name)} for name in ("launch", "image")}
    value = {"apiVersion": "catchplate.nativePilotCohortAuthorityInput/v1", "operation": "release",
        "configurationOriginal": f["owner_configuration_raw"].decode("ascii"),
        "configurationSha256": sha(f["owner_configuration_raw"]), "coldOriginals": f["cold"],
        "payloadOriginal": canonical(payload).decode("ascii"), "precreationOriginal": f["window_raw"].decode("ascii"),
        "observationsOriginal": f["observation_raw"].decode("ascii")}
    return f, value, payload


class ReleaseProfileControls(unittest.TestCase):
    def test_scope_exact_native_payload_domain_and_signature(self):
        raw, kw, expected = scope_fixture()
        prepared = scope.prepare_input(raw, **kw)
        self.assertEqual(prepared["payload"], expected)
        self.assertEqual(prepared["message"], SCOPE_DOMAIN + canonical(expected))
        self.assertEqual(prepared["deadline"], 2_000_000_000)
        signed = canonical({"payload": expected, "signatureBase64url": encoded(
            key_fixture("phase")[0].sign(SCOPE_DOMAIN + canonical(expected)))})
        self.assertEqual(scope.checked_result(raw, {"original": signed.decode("ascii"), "sha256": sha(signed)}, **kw), signed)

    def test_scope_wrong_signature_payload_and_pin_refuse(self):
        raw, kw, payload = scope_fixture()
        for change in ("signature", "payload", "pin"):
            selected = copy.deepcopy(payload)
            if change == "payload": selected["publicBundleSha256"] = synthetic("different-public")
            signed = canonical({"payload": selected, "signatureBase64url": encoded(
                key_fixture("other" if change == "signature" else "phase")[0].sign(SCOPE_DOMAIN + canonical(selected)))})
            result = {"original": signed.decode("ascii"), "sha256": synthetic("different-pin") if change == "pin" else sha(signed)}
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                scope.checked_result(raw, result, **kw)

    def test_scope_original_boot_window_and_bootstrap_are_not_renewed(self):
        raw, kw, _ = scope_fixture()
        for update in ({"boot": (encoded(b"other-boot-value"), 4, 5)}, {"now_boottime_ns": 2_000_000_000},
                {"now_unix_ns": kw["now_unix_ns"] + 20_000_000_000}):
            with self.subTest(update=update), self.assertRaises(ValueError): scope.prepare_input(raw, **(kw | update))
        value = json.loads(raw); early = json.loads(value["bootstrapAdmissionOriginal"])
        early["signature"] = encoded(b"x" * 64); value["bootstrapAdmissionOriginal"] = canonical(early).decode("ascii")
        with self.assertRaises(InvalidSignature): scope.prepare_input(canonical(value), **kw)

    def test_scope_descriptor_and_c9_original_mismatch_refuse(self):
        raw, kw, _ = scope_fixture()
        for change in ("length", "runtime", "launch", "extra"):
            value = json.loads(raw)
            if change == "length":
                operation = json.loads(value["operationOriginal"])
                next(row for row in operation["descriptors"] if row["name"] == "launch")["length"] += 1
                value["operationOriginal"] = canonical(operation).decode("ascii")
            elif change == "runtime":
                public = json.loads(value["publicBundleOriginal"]); runtime = json.loads(public["runtimeOriginal"])
                runtime["startupTimeoutMillis"] += 1; public["runtimeOriginal"] = canonical(runtime).decode("ascii")
                value["publicBundleOriginal"] = canonical(public).decode("ascii")
            elif change == "launch":
                launch = json.loads(value["launchOriginal"]); launch["apiVersion"] = "catchplate.nativeProofBridgeLaunch/v6"
                value["launchOriginal"] = canonical(launch).decode("ascii")
            else: value["approved"] = True
            with self.subTest(change=change), self.assertRaises(ValueError): scope.prepare_input(canonical(value), **kw)

    def test_ordinary_u64_codec_remains_separate_and_bounded(self):
        raw = canonical({"nativeCounter": (1 << 64) - 1})
        self.assertEqual(scope._generation_original(raw.decode("ascii")), (raw, json.loads(raw)))
        with self.assertRaises(ValueError): scope._original(raw.decode("ascii"), 65536)
        for text in (canonical({"nativeCounter": 1 << 64}).decode("ascii"), '{"padding":"' + "x" * 65536 + '"}'):
            with self.assertRaises(ValueError): scope._generation_original(text)

    def test_cohort_release_exact_payload_and_existing_domain(self):
        f, value, expected = release_fixture()
        prepared = release.prepare_release_input(canonical(value), boot=f["boot"], now_boottime_ns=f["now_boottime_ns"])
        self.assertEqual(prepared["payload"], expected)
        self.assertEqual(prepared["message"], RELEASE_DOMAIN + canonical(expected))
        prepared["key"].verify(f["key"].sign(RELEASE_DOMAIN + canonical(expected)), prepared["message"])
        self.assertEqual(prepared["deadline"], int(f["window"]["startupDeadlineBoottimeNs"]))

    def test_cohort_release_role_observation_and_precreation_refuse(self):
        for change in ("role", "process", "precreation", "external", "extra"):
            f, value, payload = release_fixture()
            if change == "role": payload.pop("retrieval")
            elif change == "process":
                observed = json.loads(value["observationsOriginal"])
                observed["persistence"]["processId"] = observed["retrieval"]["processId"]
                value["observationsOriginal"] = canonical(observed).decode("ascii")
                payload["observationSha256"] = sha(value["observationsOriginal"].encode("ascii"))
            elif change == "precreation":
                signed = json.loads(value["precreationOriginal"]); signed["signatureBase64url"] = encoded(b"x" * 64)
                value["precreationOriginal"] = canonical(signed).decode("ascii")
            elif change == "external": payload["externalDriverSha256"] = synthetic("other-driver")
            else: value["approved"] = True
            value["payloadOriginal"] = canonical(payload).decode("ascii")
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                release.prepare_release_input(canonical(value), boot=f["boot"], now_boottime_ns=f["now_boottime_ns"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Synthetic public version/bound controls, not grant or native admission.

The nested originals are grammar-only fixtures with explicit placeholder
signatures. No protected file, signer, owner, socket, service or installer runs.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import custody_generation_grants as generation
from serverware import native_pilot_bridge_runtime as bridge
from serverware import native_pilot_bridge_install as installer
from serverware import native_pilot_delivery_authority as delivery
from serverware import native_pilot_launch_publication as launch
from serverware import native_pilot_publication_profiles as publication
from serverware import native_shadow_driver_outgoing as outgoing

p = generation.p


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def fixture(version=10):
    # The unused header values deliberately make this only a shape fixture.
    value = {field: None for field in bridge.BASE_FIELDS}
    value.update(apiVersion=bridge.PREFIX + str(version), startupTimeoutMillis=30000,
        listenerSocketPath="/run/serverware-native-pilot-bridge/listener.sock")
    if version >= 5:
        value["generationAdmission"] = {"apiVersion": "serverware.custodyGenerationServices/v1",
            "grants": {role: p.sha(role.encode("ascii")) for role in generation.ROLES}}
    if version >= 6:
        value["commitRequest"] = {"apiVersion": "serverware.nativeCommitRequestServices/v1",
            "serviceGrantOriginals": {role: "{}" for role in (generation.ROLES[0], generation.ROLES[3])}}
    if version >= 7:
        value["spool"] = {"apiVersion": "serverware.nativeSpoolServices/v" + str(min(version - 6, 3)),
            "headGrantOriginal": "{}", "currentGrantOriginal": "{}", "originFdName": "generation-origin"}
        if version >= 9:
            value["spool"]["cleanupGrantOriginal"] = "{}"
    if version == 10:
        rows = {}
        for role in generation.ROLES:
            payload = {name: None for name in generation.GRANT}
            payload.update(apiVersion="serverware.custodyServiceGenerationGrant/v1", serviceRole=role)
            rows[role] = {"runtimeOriginal": '{"runtime":{}}', "generationGrantOriginal": canonical(
                {"payload": payload, "signatureBase64url": p.encoded(bytes(64))}).decode("ascii")}
        value["ordinaryInitialHistories"] = rows
    return value


def padded(size):
    return canonical({"syntheticPadding": "x" * (size - len(canonical({"syntheticPadding": ""})))}).decode("ascii")


class BridgeRuntimeControls(unittest.TestCase):
    def test_explicit_versions_and_launch_mapping_preserve_legacy(self):
        for version in range(4, 11):
            raw = canonical(fixture(version))
            self.assertEqual(bridge.runtime_version(raw), version)
            self.assertEqual(bridge.maximum_for_version(version), 4 * 1024 * 1024 if version == 10 else 65536)
            if version >= 5:
                api = "serverware.nativeProofBridgeLaunch/v" + str(version - 4)
                self.assertEqual(bridge.launch_for_runtime(raw), api)
                self.assertEqual(bridge.maximum_for_launch(api), bridge.maximum_for_version(version))
        for version in (3, 11, True):
            with self.assertRaises(ValueError): bridge.maximum_for_version(version)
        with self.assertRaises(ValueError): bridge.maximum_for_launch("serverware.nativeProofBridgeLaunch/v7")

    def test_successor_requires_exact_five_role_rows_and_original_shapes(self):
        original = fixture(); frozen = copy.deepcopy(original)
        self.assertEqual(bridge.shape(canonical(original)), original)
        self.assertEqual(original, frozen)
        for change in ("missing-role", "extra-role", "extra-field", "runtime-null", "wrong-role", "bad-signature"):
            value = fixture(); rows = value["ordinaryInitialHistories"]; row = rows[generation.ROLES[0]]
            if change == "missing-role": rows.pop(generation.ROLES[-1])
            elif change == "extra-role": rows["bridge"] = copy.deepcopy(row)
            elif change == "extra-field": row["approved"] = True
            elif change == "runtime-null": row["runtimeOriginal"] = '{"runtime":null}'
            else:
                grant = json.loads(row["generationGrantOriginal"])
                if change == "wrong-role": grant["payload"]["serviceRole"] = generation.ROLES[1]
                else: grant["signatureBase64url"] = "not-a-signature"
                row["generationGrantOriginal"] = canonical(grant).decode("ascii")
            with self.subTest(change=change), self.assertRaises(ValueError): bridge.shape(canonical(value))

    def test_large_current_and_cleanup_are_successor_only_and_individually_bounded(self):
        for field in ("currentGrantOriginal", "cleanupGrantOriginal"):
            value = fixture(); value["spool"][field] = padded(131072)
            bridge.shape(canonical(value))
            value["spool"][field] = padded(131073)
            with self.assertRaises(ValueError): bridge.shape(canonical(value))
            old = fixture(9); old["spool"][field] = padded(70000)
            with self.assertRaises(ValueError): bridge.shape(canonical(old))
        value = fixture(); value["spool"]["headGrantOriginal"] = padded(65537)
        with self.assertRaises(ValueError): bridge.shape(canonical(value))

    def test_per_original_and_aggregate_bounds_do_not_expand_with_role_count(self):
        value = fixture()
        value["ordinaryInitialHistories"][generation.ROLES[0]]["generationGrantOriginal"] = padded(65537)
        with self.assertRaises(ValueError): bridge.shape(canonical(value))
        value = fixture()
        for row in value["ordinaryInitialHistories"].values():
            row["runtimeOriginal"] = canonical({"runtime": {}, "syntheticPadding": "x" * 900000}).decode("ascii")
        self.assertGreater(len(canonical(value)), bridge.MAX_RUNTIME)
        with self.assertRaises(ValueError): bridge.shape(canonical(value))
        old = fixture(9); old["expectedSharedConfigurationSha256"] = "x" * 65536
        with self.assertRaises(ValueError): bridge.shape(canonical(old))

    def test_unknown_fields_versions_duplicates_and_noncanonical_originals_refuse(self):
        raw = canonical(fixture())
        for changed in (raw + b"\n", raw.replace(b'"apiVersion":', b'"extra":null,"apiVersion":', 1),
                raw.replace(b'"apiVersion":', b'"apiVersion":"duplicate","apiVersion":', 1)):
            with self.assertRaises(ValueError): bridge.shape(changed)
        value = fixture(); value["apiVersion"] = bridge.PREFIX + "11"
        with self.assertRaises(ValueError): bridge.shape(canonical(value))
        value = fixture(9); value["ordinaryInitialHistories"] = fixture()["ordinaryInitialHistories"]
        with self.assertRaises(ValueError): bridge.shape(canonical(value))
        value = fixture(); value["ordinaryInitialHistories"][generation.ROLES[0]]["runtimeOriginal"] += "\n"
        with self.assertRaises(ValueError): bridge.shape(canonical(value))
        value = fixture(); value["expectedOperationGeneration"] = 1 << 63
        with self.assertRaises(ValueError): bridge.shape(canonical(value))

    def test_input_and_publication_caps_leave_endpoint_profiles_unchanged(self):
        self.assertEqual(delivery.MAX_INPUT, 1024 * 1024)
        self.assertEqual(delivery.MAX_BRIDGE_INPUT, 16 * 1024 * 1024)
        self.assertEqual(installer.MAX_INPUT, 512 * 1024)
        self.assertEqual(installer.MAX_BRIDGE_INPUT, 16 * 1024 * 1024)
        self.assertEqual(publication.PROFILES["bridge-runtime"][2], bridge.MAX_RUNTIME)
        for role in delivery.ENDPOINTS:
            self.assertEqual(publication.PROFILES["native-runtime-" + role][2], 65536)
        self.assertEqual(outgoing.bridge_runtime.LAUNCH_RUNTIME["serverware.nativeProofBridgeLaunch/v6"], 10)
        value = {name: "{}" for name in delivery.INPUT_FIELDS}
        value.update(apiVersion="serverware.nativePilotDeliverySigningInput/v1", role="bridge",
            runtimeOriginal=canonical(fixture()).decode("ascii"), observationOriginal=padded(delivery.MAX_INPUT))
        delivery.input_document(canonical(value))  # Bounds/grammar only; no signer is called.
        for role in ("retrieval", "bridge"):
            changed = copy.deepcopy(value); changed["role"] = role
            changed["runtimeOriginal"] = canonical(fixture(9)).decode("ascii") if role == "bridge" else "{}"
            with self.assertRaises(ValueError): delivery.input_document(canonical(changed))

    def test_bridge_launch_shape_selects_only_explicit_v5_or_v6(self):
        pins = {name: {"path": launch.DESTINATIONS["native-bridge-" + suffix], "sha256": p.sha(name.encode("ascii"))}
            for name, (suffix, _) in launch.COMPONENTS.items()}
        pins.update(apiVersion="serverware.nativeShadowGuestLaunch/v1",
            deliveryConfiguration={"path": "/etc/serverware/bridge-cold.json", "sha256": p.sha(b"cold")},
            delivery={"path": publication.DESTINATIONS["native-delivery-bridge"], "sha256": p.sha(b"delivery")})
        value = {"apiVersion": "serverware.nativeProofBridgeLaunch/v6", "keyAdmission": pins,
            "trustedTime": {"path": publication.DESTINATIONS["native-service-trustedTime"], "sha256": p.sha(b"grant")}}
        for version in (5, 6):
            value["apiVersion"] = "serverware.nativeProofBridgeLaunch/v" + str(version)
            launch.shape("native-launch-bridge", canonical(value))
        value["apiVersion"] = "serverware.nativeProofBridgeLaunch/v7"
        with self.assertRaises(ValueError): launch.shape("native-launch-bridge", canonical(value))


if __name__ == "__main__":
    unittest.main()

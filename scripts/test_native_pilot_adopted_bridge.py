#!/usr/bin/env python3
"""Closed adopted bridge wires/inventory; no grant, live owner or pilot claim."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import native_pilot_bridge_runtime as runtime
from serverware import native_pilot_bridge_install as install
from serverware import native_pilot_bridge_runtime_policy as policy
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_peer_preparation as peers
from serverware import native_shadow_driver_outgoing as outgoing
from test_native_pilot_bridge_runtime import fixture as legacy_fixture, canonical

p = runtime.p


def publication_grant(role):
    # Shape-only fixture. Placeholder fields/signature do not verify as a grant.
    payload = {name: None for name in ("guest", "runtimeConfigurationSha256", "authorityHistoryManifestSha256",
        "native", "retrieval", "initialTransitionHeadSha256", "initialDurableTransitionHeadSha256",
        "durableAuthorityEpoch", "durablePublicKeyBase64url")}
    payload.update(apiVersion="serverware.nativePublicationServiceGrant/v2",
        purpose="native-policy-publication-state", serviceRole=role, admission={"adoption": {}})
    return canonical({"payload": payload, "signatureBase64url": p.encoded(bytes(64))}).decode("ascii")


def fixture():
    value = legacy_fixture(12)
    value["apiVersion"] = runtime.PREFIX + "14"
    value["publication"] = {"apiVersion": "serverware.nativePublicationServices/v2",
        "durableGrantOriginal": publication_grant(runtime.generation.ROLES[0]),
        "currentGrantOriginal": publication_grant(runtime.generation.ROLES[3])}
    for role in (runtime.generation.ROLES[0], runtime.generation.ROLES[3]):
        value["ordinaryInitialHistories"][role]["runtimeOriginal"] = canonical({"runtime": {
            "apiVersion": "serverware.policyCustodyServiceRuntimeConfig/v12",
            "publicationAdmission": {"grantFdName": "publication-grant"}}}).decode("ascii")
    peer = {name: 2 for name in outgoing._PEER_FIELDS}
    for name in outgoing._PEER_FIELDS:
        if name.endswith("Sha256"):
            peer[name] = p.sha(name.encode("ascii"))
    value["serviceSessions"] = [{"serviceRole": role, "activationFdName": "service-" + role,
        "expectedSocketPath": "/run/synthetic-" + role + "/listener.sock", "expectedPeer": copy.deepcopy(peer),
        "handshakes": [{}]} for role in runtime.generation.ROLES]
    value["parentSignerEndpoints"] = [{"signerRole": role, "activationFdName": "signer-" + role,
        "authorityBindingCredential": role, "authorityKeyId": p.sha(role.encode("ascii")),
        "authorityKeySpkiSha256": p.sha((role + "-spki").encode("ascii")),
        "expectedPeer": copy.deepcopy(peer),
        "expectedSocketPath": outgoing._ADOPTED_NATIVE_SIGNERS[role][0] if role in outgoing._ADOPTED_NATIVE_SIGNERS
            else "/run/synthetic-" + role + "/listener.sock"} for role in sorted(outgoing._SIGNERS)]
    value["proofEndpoints"] = [{"endpointKind": role, "activationFdName": "proof-" + role,
        "authorityBindingCredential": role, "authorityKeyId": p.sha(role.encode("ascii")),
        "authorityKeySpkiSha256": p.sha((role + "-spki").encode("ascii")),
        "expectedPeer": copy.deepcopy(peer), "expectedSocketPath": pair[0]} for role, pair in outgoing._PROOFS.items()]
    return value


class AdoptedBridgeControls(unittest.TestCase):
    def test_policy_successor_requires_native_publication_not_external_signer(self):
        from test_native_pilot_bridge_composition import fragment
        value = fragment()
        value["apiVersion"] = policy.ADOPTED_API
        value["peerExpectations"]["native-endpoints"]["publicationReconciliation"] = copy.deepcopy(
            value["peerExpectations"]["native-endpoints"]["retrieval"])
        previous = value["externalSignerEndpoints"].pop("publication-reconciliation")
        self.assertEqual(policy.validate_policy(value), value)
        invalid = copy.deepcopy(value)
        invalid["externalSignerEndpoints"]["publication-reconciliation"] = previous
        with self.assertRaises(ValueError): policy.validate_policy(invalid)
        for mutation in ("old-policy", "missing-native"):
            invalid = copy.deepcopy(value)
            if mutation == "old-policy": invalid["apiVersion"] = policy.TERMINAL_API
            else: del invalid["peerExpectations"]["native-endpoints"]["publicationReconciliation"]
            with self.assertRaises(ValueError): policy.validate_policy(invalid)

    def test_explicit_runtime_launch_and_native_aggregate_bound(self):
        raw = canonical(fixture())
        self.assertEqual(runtime.runtime_version(raw), 14)
        self.assertEqual(runtime.launch_for_runtime(raw), "serverware.nativeProofBridgeLaunch/v10")
        self.assertEqual(runtime.maximum_for_launch(runtime.ADOPTED_LAUNCH), 4 * 1024 * 1024)
        install.shape("bridge-runtime", raw)
        for version in (13, 15):
            value = fixture(); value["apiVersion"] = runtime.PREFIX + str(version)
            with self.assertRaises(ValueError): runtime.shape(canonical(value))

    def test_exact_eight_generic_eleven_native_and_forty_one_descriptors(self):
        raw = canonical(fixture())
        value, generic, native = outgoing._selection(raw, runtime.ADOPTED_LAUNCH, 1001)
        self.assertEqual((len(generic), len(native)), (8, 11))
        self.assertIn("signer-publication-reconciliation", native)
        self.assertNotIn("signer-publication-reconciliation", dict(generic))
        self.assertEqual(len(outgoing.native_connections(value)), 11)
        inventory, _ = c9._bridge_inventory(raw, {"uid": 1001}, adopted=True)
        self.assertEqual(len(inventory), 41)
        self.assertEqual(len({name for name, _ in inventory}), 41)
        self.assertIn("publication-reconciliation-peer-directory", dict(inventory))
        with self.assertRaises(ValueError): c9._bridge_inventory(raw, {"uid": 1001})

    def test_publication_cannot_remain_external_or_duplicate_a_descriptor(self):
        for mutation in ("path", "name", "missing", "duplicate"):
            value = fixture()
            entry = next(row for row in value["parentSignerEndpoints"] if row["signerRole"] == "publication-reconciliation")
            if mutation == "path": entry["expectedSocketPath"] = "/run/external-publication/listener.sock"
            elif mutation == "name": entry["activationFdName"] = "production-listener"
            elif mutation == "missing": value["parentSignerEndpoints"].remove(entry)
            else: value["parentSignerEndpoints"].append(copy.deepcopy(entry))
            with self.assertRaises(ValueError): outgoing._selection(canonical(value), runtime.ADOPTED_LAUNCH, 1001)

    def test_both_literal_role_selected_adopted_grants_are_required(self):
        for mutation in ("missing", "old-selection", "old-grant", "wrong-role", "no-adoption", "bad-signature"):
            value = fixture(); selected = value["publication"]
            if mutation == "missing": del selected["currentGrantOriginal"]
            elif mutation == "old-selection": selected["apiVersion"] = "serverware.nativePublicationServices/v1"
            else:
                grant = json.loads(selected["durableGrantOriginal"])
                if mutation == "old-grant": grant["payload"]["apiVersion"] = "serverware.nativePublicationServiceGrant/v1"
                elif mutation == "wrong-role": grant["payload"]["serviceRole"] = runtime.generation.ROLES[3]
                elif mutation == "no-adoption": grant["payload"]["admission"]["adoption"] = None
                else: grant["signatureBase64url"] = p.encoded(bytes(63))
                selected["durableGrantOriginal"] = canonical(grant).decode("ascii")
            with self.assertRaises(ValueError): runtime.shape(canonical(value))

    def test_ordinary_target_requires_runtime_twelve_and_fixed_grant_fd(self):
        for role in (runtime.generation.ROLES[0], runtime.generation.ROLES[3]):
            for mutation in ("version", "fd"):
                value = fixture(); row = value["ordinaryInitialHistories"][role]
                target = json.loads(row["runtimeOriginal"])
                if mutation == "version": target["runtime"]["apiVersion"] = "serverware.policyCustodyServiceRuntimeConfig/v8"
                else: target["runtime"]["publicationAdmission"]["grantFdName"] = "dispatch-grant"
                row["runtimeOriginal"] = canonical(target).decode("ascii")
                with self.assertRaises(ValueError): runtime.shape(canonical(value))

    def test_nested_grant_allowance_does_not_widen_native_runtime_cap(self):
        value = fixture()
        for field in ("durableGrantOriginal", "currentGrantOriginal"):
            grant = json.loads(value["publication"][field])
            grant["payload"]["admission"]["adoption"]["syntheticPadding"] = "x" * 2_100_000
            value["publication"][field] = canonical(grant).decode("ascii")
            self.assertLess(len(value["publication"][field]), 3 * 1024 * 1024)
        self.assertGreater(len(canonical(value)), runtime.MAX_RUNTIME)
        with self.assertRaises(ValueError): runtime.shape(canonical(value))

    def test_old_input_wire_does_not_gain_adopted_inventory_by_retagging_runtime(self):
        value = {name: "{}" for name in c9.INPUT_FIELDS}
        value.update(apiVersion="serverware.nativePilotDeliverySigningInput/v3", role="bridge",
            runtimeOriginal=canonical(fixture()).decode("ascii"))
        self.assertEqual(c9.input_document(canonical(value)), value)
        for mutation in ("old-api", "endpoint", "old-runtime"):
            changed = copy.deepcopy(value)
            if mutation == "old-api": changed["apiVersion"] = "serverware.nativePilotDeliverySigningInput/v1"
            elif mutation == "endpoint": changed["role"] = "retrieval"
            else: changed["runtimeOriginal"] = canonical(legacy_fixture(12)).decode("ascii")
            with self.assertRaises(ValueError): c9.input_document(canonical(changed))

    def test_legacy_native_signer_map_is_unchanged(self):
        self.assertEqual(len(outgoing._NATIVE_SIGNERS), 6)
        self.assertNotIn("publication-reconciliation", outgoing.native_signers(12))
        self.assertEqual(len(outgoing.native_signers(14)), 7)
        value = fixture(); value["apiVersion"] = runtime.PREFIX + "12"
        with self.assertRaises(ValueError): runtime.shape(canonical(value))


if __name__ == "__main__":
    unittest.main()

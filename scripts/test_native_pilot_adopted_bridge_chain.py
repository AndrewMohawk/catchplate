#!/usr/bin/env python3
"""Synthetic signed bridge/TrustedTime sources, not native or live evidence.

The complete C9/key/closure/late/TrustedTime issuer signatures are real test
signatures. Runtime14's nested business receipts/history fixtures remain
structural placeholders. No process, owner, ciphertext, installation, independent
approval, attestation, real clock service or successful workload is claimed.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import json
import os
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from catchplate import native_pilot_bridge_authorization_profile as authorizations
from catchplate import native_pilot_bridge_commissioning_policy as policy
from catchplate import native_pilot_bridge_delivery_profile as delivery
from catchplate import native_pilot_bridge_launch_profile as launch
from catchplate import native_pilot_bridge_launch_publication as bundle_profile
from catchplate import native_pilot_launch_publication as publication
from scripts import native_pilot_publication_runtime_entrypoint as entrypoint
from test_native_pilot_adopted_bridge_keys import fixture as key_fixture_source
from test_native_pilot_adopted_endpoints import chain as time_chain, signed as signed_service
from test_native_pilot_bridge_authorizations import public_keys
from test_native_pilot_bridge_launches import CLOCK
from test_native_pilot_closure_set import canonical, sha, synthetic
from test_native_pilot_generation_scope import key_fixture, encoded, signed_message, NOW


def result(raw): return {"original": raw.decode("ascii"), "sha256": sha(raw)}


@lru_cache(maxsize=1)
def _fixture():
    first, _, manifest = key_fixture_source()
    endpoint, service, _, _, _ = time_chain()
    clocks = dict(boot=endpoint["boot"], now_boottime_ns=1_500_000_000, now_unix_ns=NOW)
    source = json.loads(first["deliveryInputOriginal"])
    config = json.loads(source["ownerConfigurationOriginal"])
    cold = json.loads(source["configurationOriginal"])
    signed_window = json.loads(source["windowOriginal"])
    window = signed_window["payload"]
    window["bootIdBase64url"] = endpoint["boot"][0]
    signed_window["signatureBase64url"] = encoded(key_fixture("window")[0].sign(
        b"catchplate.nativeShadowDriverBootstrapWindow.signature/v1\0" + canonical(window)))
    source["windowOriginal"] = canonical(signed_window).decode("ascii")
    observed = json.loads(source["observationOriginal"])
    observed["windowSha256"] = sha(canonical(signed_window))
    observed["driver"]["supervisorBootIdSha256"] = sha(authorizations.p.decoded(endpoint["boot"][0], size=16))
    observed["driver"]["identitySha256"] = authorizations.p.framed(
        b"catchplate.policyShadowCustodyKernelDriverIdentity/v1",
        (canonical([observed["driver"][name] for name in delivery.scope.DRIVER_FIELDS[:-1]]),))
    source["observationOriginal"] = canonical(observed).decode("ascii")
    control = json.loads(first["controlOriginal"]); control["windowSha256"] = observed["windowSha256"]
    first["controlOriginal"] = canonical(control).decode("ascii")

    # The service's authenticated current assignment is shared. Its guest and
    # original invocation remain distinct; only this approved peer changes.
    first["recipeOriginals"] = copy.deepcopy(endpoint["recipe_originals"])
    recipe = {"apiVersion": delivery.measured_profile.ADOPTED_API, **first["recipeOriginals"]}
    envelope, bindings, root = delivery.measured_profile._assignment(recipe, NOW)
    first["measured"] = delivery.measured_profile.derive_configuration(envelope=envelope, keys=bindings,
        key_root=root, manifest=manifest, observed=observed, production={name: first["measured"]["production"][name]
            for name in delivery.measured_profile.PRODUCTION_FIELDS}, window=window,
        recipe_sha=first["measured"]["recipeSha256"], successor=True)
    peer = json.loads(service["peerOriginal"])
    peer.update(uid=cold["uid"], gid=cold["gid"])
    parts = [peer[name].to_bytes(4, "big") for name in ("uid", "gid", "pid")]
    parts += [peer[name].to_bytes(8, "big") for name in ("startTimeTicks", "executableDevice", "executableInode", "executableLength")]
    parts += [bytes.fromhex(peer["executableSha256"][7:]), peer["cgroupPathSha256"].encode("ascii"),
        peer["cgroupMountId"].to_bytes(8, "big"), peer["cgroupInode"].to_bytes(8, "big"),
        peer["securityLabelSha256"].encode("ascii"), peer["configurationGenerationSha256"].encode("ascii")]
    peer["processIdentitySha256"] = authorizations.p.framed(b"catchplate.policyCustodyPeerProcessIdentity/v4", parts)
    service.update(peerOriginal=canonical(peer).decode("ascii"), peerSha256=sha(canonical(peer)))
    service_raw = canonical(service)
    admitted = launch.services.prepare_adopted_input("trustedTime", service_raw, **clocks)
    grant_raw = signed_service(admitted["payload"], admitted["domain"])

    runtime = json.loads(source["runtimeOriginal"])
    runtime.update(expectedDriverProcessIdentitySha256=peer["processIdentitySha256"],
        expectedDriverConfigurationGenerationSha256=peer["configurationGenerationSha256"])
    trusted = next(row for row in runtime["proofEndpoints"] if row["endpointKind"] == "trusted-time")
    trusted["expectedPeer"].update(uid=admitted["payload"]["guest"]["uid"], gid=admitted["payload"]["guest"]["gid"])
    payload = json.loads(source["payloadOriginal"])
    payload["bootIdBase64url"] = window["bootIdBase64url"]
    credentials = copy.deepcopy(payload["credentials"])
    histories = {role: runtime["ordinaryInitialHistories"][role]["historyOriginal"].encode("ascii")
        for role in delivery.generation.ROLES}
    for row in runtime["histories"]:
        raw = histories[row["serviceRole"]]
        credentials.append({"name": row["manifestCredential"], "original": {
            "path": "/etc/catchplate/synthetic-" + row["manifestCredential"], "sha256": sha(raw)},
            "length": len(raw), "signing": None})
    keys = {row["role"]: row for row in public_keys()}
    for group, discriminator in (("parentSignerEndpoints", "signerRole"), ("proofEndpoints", "endpointKind")):
        for row in runtime[group]:
            key = keys[delivery.AUTHORITY_KEY_ROLES[row[discriminator]]]
            row.update(authorityKeyId=key["keyId"], authorityKeySpkiSha256=key["keySpkiSha256"])
            raw = authorizations.p.decoded(key["publicKeyBase64url"], size=32)
            credentials.append({"name": row["authorityBindingCredential"], "original": {
                "path": "/etc/catchplate/synthetic-" + row["authorityBindingCredential"], "sha256": sha(raw)},
                "length": 32, "signing": None})
    journal = next(row for row in payload["activation"] if row["name"] == "production-journal")
    runtime["journalDirectoryIdentity"] = {"mountId": 17, "deviceMajor": os.major(journal["device"]),
        "deviceMinor": os.minor(journal["device"]), **{name: journal[name] for name in ("inode", "uid", "gid", "mode")}}
    source["runtimeOriginal"] = canonical(runtime).decode("ascii")
    payload.update(credentials=credentials, runtimeConfig={"path": "/etc/catchplate/native-pilot-inputs/bridge-runtime.json",
        "sha256": sha(canonical(runtime))})
    source["payloadOriginal"] = canonical(payload).decode("ascii")
    delivery_raw = canonical({"apiVersion": "catchplate.policyCustodyGuestDelivery/v1", "payload": payload,
        "signatureBase64url": encoded(key_fixture("bridge-c9")[0].sign(
            b"catchplate.policyCustodyGuestDelivery.signature/v1\0" + canonical(payload)))})
    interval = {"issuedAtUnixNanos": NOW - 100_000_000, "expiresAtUnixNanos": NOW + 100_000_000}
    fragment = {"apiVersion": policy.ADOPTED_API, "deliveryCredentials": credentials,
        "keyAuthorization": first["policy"], "launchAuthorizations": {"closure": interval,
            "encryptedDelivery": interval, "verifierTransport": dict(interval, parentPort=11443)}, "timeBootstrap": CLOCK}
    common = dict(fragment=fragment, control_original=first["controlOriginal"].encode("ascii"),
        delivery_input_raw=canonical(source), delivery_raw=delivery_raw,
        recipe_originals=first["recipeOriginals"], measured=first["measured"], **clocks)
    records = {}
    for operation in authorizations.OPERATIONS:
        raw = authorizations.build(operation, prior_authorizations=records, **common)
        prepared = authorizations.prepare_adopted_input(operation, raw, **clocks)
        value = copy.deepcopy(prepared["result"])
        signed = value["authorization"] if "authorization" in value else value
        signed["signature"] = encoded(key_fixture("custody-supervisor-capability")[0].sign(
            signed_message(prepared["domain"], prepared["payload"])))
        records[operation] = {"inputOriginal": raw, "authorizationOriginal": canonical(value)}
    value = {"apiVersion": launch.ADOPTED_INPUT_API, "fragment": fragment,
        "controlOriginal": first["controlOriginal"], "deliveryInputOriginal": canonical(source).decode("ascii"),
        "deliveryOriginal": delivery_raw.decode("ascii"), "recipeOriginals": first["recipeOriginals"], "measured": first["measured"],
        "authorizations": {operation: {name: raw.decode("ascii") for name, raw in row.items()}
            for operation, row in records.items()},
        "serviceContext": {"inputOriginal": service_raw.decode("ascii"), "grantOriginal": grant_raw.decode("ascii")}}
    return dict(value=value, common=common, source=source, records=records, clocks=clocks, histories=histories)


def fixture(): return copy.deepcopy(_fixture())


def delivery_options(f):
    source, common = f["source"], f["common"]
    config, window = json.loads(source["ownerConfigurationOriginal"]), json.loads(source["windowOriginal"])["payload"]
    outgoing = {"apiVersion": "catchplate.nativeShadowDriverOutgoingInputs/v1",
        **{target: sha(source[field].encode("ascii")) for target, field in (
            ("driverConfigurationSha256", "ownerConfigurationOriginal"), ("driverWindowSha256", "windowOriginal"),
            ("driverObservationSha256", "observationOriginal"))}, "invocationId": window["invocationId"],
        "deliveryConfiguration": config["deliveryConfiguration"], "runtime": {
            "path": delivery.install.RUNTIME_DESTINATION, "sha256": sha(source["runtimeOriginal"].encode("ascii"))},
        "bridgeLaunchVersion": "catchplate.nativeProofBridgeLaunch/v10"}
    bundle = canonical({"apiVersion": "catchplate.nativePilotBridgeRuntimeBundle/v2",
        "driverControlSha256": sha(common["control_original"]), "driverObservationOriginal": source["observationOriginal"],
        "runtimeOriginal": source["runtimeOriginal"], "outgoingOriginal": canonical(outgoing).decode("ascii")})
    installed = {"apiVersion": "catchplate.nativePilotBridgeRuntimeInstallation/v2", "bundleSha256": sha(bundle),
        "configurationSha256": outgoing["driverConfigurationSha256"], "windowSha256": outgoing["driverWindowSha256"],
        "observationSha256": outgoing["driverObservationSha256"], "invocationId": window["invocationId"],
        **{name: window[name] for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")}, "pins": {
            name: {"path": delivery.publication.DESTINATIONS[name], "sha256": sha(raw)}
            for name, raw in (("bridge-runtime", source["runtimeOriginal"].encode("ascii")), ("bridge-outgoing", canonical(outgoing)))}}
    return dict(fragment=common["fragment"], runtime_bundle_raw=bundle, runtime_result=installed,
        bootstrap_originals={"control": common["control_original"], **{name: source[field].encode("ascii") for name, field in (
            ("configuration", "ownerConfigurationOriginal"), ("window", "windowOriginal"), ("deliveryConfiguration", "configurationOriginal"))}},
        activation=json.loads(source["activationOriginal"]), recipe_originals=common["recipe_originals"],
        measured=common["measured"], history_originals=f["histories"], **f["clocks"])


class AdoptedBridgeChainControls(unittest.TestCase):
    def test_full_c9_input3_public_admission_and_exact_metadata(self):
        f = fixture(); options = delivery_options(f)
        raw = delivery.build(**options)
        self.assertEqual(raw, f["common"]["delivery_input_raw"])
        checked = delivery.prepare_signing_input(raw, **{name: f["clocks"][name] for name in ("boot", "now_boottime_ns")})
        self.assertEqual(checked["deadline"], 2_000_000_000)
        self.assertEqual(len(json.loads(json.loads(raw)["activationOriginal"])), 41)
        reported = result(f["common"]["delivery_raw"])
        reported["pin"] = {"path": delivery.publication.DESTINATIONS["native-delivery-bridge"], "sha256": reported["sha256"]}
        self.assertEqual(delivery.checked_result(raw, reported, **options), f["common"]["delivery_raw"])

    def test_old_runtime_install_and_policy_selectors_cannot_cross(self):
        for change in ("policy", "bundle", "install"):
            options = delivery_options(fixture())
            if change == "policy": options["fragment"]["apiVersion"] = policy.API
            elif change == "install": options["runtime_result"]["apiVersion"] = "catchplate.nativePilotBridgeRuntimeInstallation/v1"
            else:
                value = json.loads(options["runtime_bundle_raw"]); value["apiVersion"] = "catchplate.nativePilotBridgeRuntimeBundle/v1"
                options["runtime_bundle_raw"] = canonical(value)
            with self.subTest(change=change), self.assertRaises(ValueError): delivery.build(**options)

    def test_c9_refuses_actual_activation_journal_or_public_byte_mismatch(self):
        for change in ("descriptor", "journal", "metadata"):
            options = delivery_options(fixture())
            if change == "descriptor": options["activation"].pop()
            elif change == "journal": next(row for row in options["activation"] if row["name"] == "production-journal")["inode"] += 1
            else: options["fragment"]["deliveryCredentials"][-1]["original"]["sha256"] = synthetic("wrong-public-key-bytes")
            with self.subTest(change=change), self.assertRaises(ValueError): delivery.build(**options)

    def test_all_five_authorizations_authenticate_original_predecessors(self):
        f = fixture()
        for operation, row in f["records"].items():
            with self.subTest(operation=operation):
                self.assertEqual(authorizations.checked_result(operation, row["inputOriginal"], result(row["authorizationOriginal"]),
                    **f["clocks"]), row["authorizationOriginal"])
                value = json.loads(row["inputOriginal"]); value["apiVersion"] = value["apiVersion"].rsplit("/", 1)[0] + "/v1"
                with self.assertRaises(ValueError): authorizations.prepare_adopted_input(operation, canonical(value), **f["clocks"])
        records = copy.deepcopy(f["records"]); records["role-keys"]["authorizationOriginal"] = b"{}"
        with self.assertRaises((ValueError, KeyError)):
            authorizations.build("admission", prior_authorizations={"role-keys": records["role-keys"]}, **f["common"])

    def test_complete_launch_input_authenticates_trusted_time_and_emits_nine_fixed_pins(self):
        f = fixture(); raw = canonical(f["value"])
        prepared = launch.prepare_input(raw, **f["clocks"])
        self.assertEqual(json.loads(prepared["bundleOriginal"])["apiVersion"], "catchplate.nativePilotLaunchBundle/v3")
        self.assertEqual(len(prepared["pins"]), 9)
        self.assertEqual(tuple(prepared["prepared"])[-1], "native-launch-bridge")
        self.assertEqual(json.loads(prepared["prepared"]["native-launch-bridge"])["apiVersion"], "catchplate.nativeProofBridgeLaunch/v10")
        self.assertEqual({name for name, _ in prepared["prerequisites"]}, {"control", "owner", "window", "configuration", "runtime", "delivery", "grant"})
        self.assertEqual(prepared["epochLimit"], NOW + 100_000_000)
        installed = publication._installation_result("bridge", sha(prepared["bundleOriginal"]), prepared["window"], prepared["pins"])
        installed["apiVersion"] = "catchplate.nativePilotLaunchInstallation/v3"
        options = dict(pair_context=authorizations._pair_context(f["records"]),
            service_grant_original=f["value"]["serviceContext"]["grantOriginal"].encode("ascii"), **f["clocks"])
        self.assertEqual(bundle_profile.checked_bridge_result(prepared["bundleOriginal"], installed, **options), installed)
        with self.assertRaises(ValueError):
            bundle_profile.checked_bridge_result(prepared["bundleOriginal"], dict(installed, apiVersion="catchplate.nativePilotLaunchInstallation/v1"), **options)

    def test_launch_refuses_signature_and_complete_service_input_substitution(self):
        for change in ("signature", "service-input", "service-api", "source"):
            f = fixture(); value = f["value"]
            if change == "signature":
                grant = json.loads(value["serviceContext"]["grantOriginal"]); grant["signature"] = encoded(bytes(64))
                value["serviceContext"]["grantOriginal"] = canonical(grant).decode("ascii")
            elif change == "service-input": value["serviceContext"]["inputOriginal"] = "{}"
            elif change == "service-api":
                source = json.loads(value["serviceContext"]["inputOriginal"]); source["apiVersion"] = "catchplate.nativePilotNativeServiceAuthorityInput/v1"
                value["serviceContext"]["inputOriginal"] = canonical(source).decode("ascii")
            else: value["deliveryOriginal"] = "{}"
            with self.subTest(change=change), self.assertRaises((ValueError, KeyError, InvalidSignature)):
                launch.prepare_input(canonical(value), **f["clocks"])

    def test_adopted_shape_cannot_select_old_launch_or_nonbridge(self):
        f = fixture(); prepared = launch.prepare_input(canonical(f["value"]), **f["clocks"])
        for purpose in ("native-launch-bridge", "native-bridge-closure"):
            raw = prepared["prepared"][purpose]
            publication.shape_adopted_bridge(purpose, raw)
            with self.assertRaises(ValueError): publication.shape(purpose, raw)
            with self.assertRaises(ValueError): publication.shape_adopted(purpose, raw)
            value = json.loads(raw); value["apiVersion"] = value["apiVersion"].rsplit("/", 1)[0] + "/v3"
            with self.assertRaises(ValueError): publication.shape_adopted_bridge(purpose, canonical(value))

    def test_original_deadlines_and_unknown_input_fields_refuse(self):
        f = fixture(); raw = canonical(f["value"])
        for change in ({"now_boottime_ns": 2_000_000_000}, {"now_unix_ns": NOW + 100_000_000}):
            with self.subTest(change=change), self.assertRaises(ValueError): launch.prepare_input(raw, **(f["clocks"] | change))
        with self.assertRaises(ValueError): launch.input_document(canonical(f["value"] | {"approved": True}))
        with self.assertRaises(ValueError): launch.input_document(canonical(f["value"] | {"apiVersion": "catchplate.nativePilotLaunchBundle/v3"}))

    def test_fixed_packaged_modes_keep_launch_keyless_and_descriptor_purposes_distinct(self):
        self.assertEqual(len(entrypoint.ADOPTED_BRIDGE_MODES), 6)
        base = ["--supervisor-inventory-fd", "3", "--supervisor-inventory-sha256", synthetic("inventory"),
            "--input-fd", "4", "--input-sha256", synthetic("input")]
        for mode in entrypoint.ADOPTED_BRIDGE_MODES:
            self.assertTrue(entrypoint.valid_arguments([mode, *base, "--authority-key-fd", "5"]))
            self.assertFalse(entrypoint.valid_arguments([mode, *base, "--authority-key-fd", "4"]))
        mode = entrypoint.ADOPTED_BRIDGE_LAUNCH_MODE
        self.assertTrue(entrypoint.valid_arguments([mode, *base]))
        self.assertFalse(entrypoint.valid_arguments([mode, *base, "--authority-key-fd", "5"]))
        self.assertTrue(entrypoint.valid_arguments([entrypoint.ADOPTED_CURRENT_HEAD_MODE, *base, "--authority-key-fd", "5"]))


if __name__ == "__main__": unittest.main()

#!/usr/bin/env python3
"""Pure candidate-input controls, not approval or installed-runtime evidence.

The signed assignment/window use existing deterministic test keys. Actual
inventory producers inspect tiny non-executable temporary trees; no protected
owner, sender, receiver, approval, provisioned key or successful pilot is faked.
Public observations are explicitly synthetic, and no validator is mocked.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))

from scripts import native_pilot_runtime_artifacts as artifacts
from scripts import test_native_pilot_adopted_bridge_keys as signed
from scripts import test_native_pilot_supervisor_runtime as runtime_fixture
from serverware import native_pilot_lifecycle_inputs as compiler

p = compiler.p
FAILURES = (ValueError, InvalidSignature)


def fixture(parent):
    inventories = {}
    for role, produce in (("conductor", artifacts.inventory),
            ("authority", artifacts.authority_inventory), ("supervisor", artifacts.supervisor_inventory)):
        directory = parent / role
        directory.mkdir()
        root, source = runtime_fixture.fixture(directory, profile=role)
        inventories[role] = artifacts._canonical(produce(root, source))
    value, _, manifest = signed.fixture()
    clocks = signed.clocks()
    delivery = json.loads(value["deliveryInputOriginal"])
    bootstrap = {"control": value["controlOriginal"],
        "configuration": delivery["ownerConfigurationOriginal"], "window": delivery["windowOriginal"],
        "deliveryConfiguration": delivery["configurationOriginal"]}
    recipe = {"apiVersion": compiler.measured.ADOPTED_API, "source": source,
        "conductorInventorySha256": p.sha(inventories["conductor"]),
        "authorityInventorySha256": p.sha(inventories["authority"]), "bootstrapOriginals": bootstrap,
        **value["recipeOriginals"], "closureManifestOriginal": p.canonical(manifest).decode("ascii"),
        "production": {name: value["measured"]["production"][name]
            for name in compiler.measured.PRODUCTION_FIELDS}}
    recipe_raw = p.canonical(recipe)
    config = json.loads(bootstrap["configuration"])
    keys = {name: p.sha(("synthetic selected key: " + name).encode("ascii"))
        for name in compiler.policy.profile.KEY_PURPOSES}
    keys["driver-bootstrap"] = keys["driver-constructed"] = p.sha(p.decoded(
        config["lifecycle"]["constructedAdmissionAuthority"]["publicKeyBase64url"], size=32))
    keys["driver-scope"] = config["phaseTwoAuthority"]["keyId"]
    window = json.loads(bootstrap["window"])["payload"]
    listener = {"apiVersion": compiler.rendezvous_profile.CONFIGURATION_API, "window": {
        name: window[name] for name in compiler.rendezvous_profile.wire.endpoints.WINDOW},
        "expiresAtUnixNanos": clocks["now_unix_ns"] + 400_000_000}
    listener["window"].update(issuedAtBoottimeNs="1000000", startupDeadlineBoottimeNs="1800000000",
        lifetimeDeadlineBoottimeNs="40000000000")
    listener_raw = p.canonical(listener)
    namespace = {name: listener["window"][name]
        for name in compiler.rendezvous_profile.wire.endpoints.WINDOW[:3]}
    socket = {"device": 21, "inode": 22, "mode": stat.S_IFSOCK | 0o600, "uid": 0, "gid": 0}
    observed = {"apiVersion": compiler.rendezvous_profile.SENDER_API,
        "configurationSha256": p.sha(listener_raw), "processId": 100, "processStartTimeTicks": 123,
        "endpoint": compiler.rendezvous_profile.ENDPOINT, **namespace, "socket": socket}
    observed_raw = p.canonical(observed)
    bounds = {"deadlineBoottimeNs": listener["window"]["startupDeadlineBoottimeNs"],
        "expiresAtUnixNanos": listener["expiresAtUnixNanos"]}
    sender_raw = p.canonical({"apiVersion": compiler.rendezvous_profile.SENDER_REQUEST_API,
        "sequence": 0, "listenerOriginal": observed_raw.decode("ascii"),
        "listenerSha256": p.sha(observed_raw), "configurationSha256": p.sha(listener_raw), **bounds})
    receiver = {"pid": 200, "uid": 0, "gid": 0, "startTimeTicks": 234}
    receiver_raw = p.canonical({"apiVersion": compiler.rendezvous_profile.RECEIVER_API,
        "senderRequestSha256": p.sha(sender_raw), "configurationSha256": p.sha(listener_raw),
        **namespace, "receiver": receiver, "socket": socket | {"inode": 23}, **bounds})
    request_raw = compiler.rendezvous_profile.request(sender_raw, receiver_raw, listener_raw)
    return {"pending": {"senderRequestOriginal": sender_raw.decode("ascii"),
            "listenerConfigurationOriginal": listener_raw.decode("ascii")},
        "parameters": {"recipe_original": recipe_raw, "recipe_sha256": p.sha(recipe_raw),
            "supervisor_inventory_original": inventories["supervisor"],
            "supervisor_inventory_sha256": p.sha(inventories["supervisor"]),
            "conductor_inventory_original": inventories["conductor"],
            "authority_inventory_original": inventories["authority"], "key_bindings": keys,
            "policy_selection": {"apiVersion": compiler.policy.API, "purpose": compiler.policy.PURPOSE},
            "issued_at_unix_ns": clocks["now_unix_ns"] - 100_000_000,
            "expires_at_unix_ns": clocks["now_unix_ns"] + 300_000_000, **clocks},
        "recipe": recipe, "listener": listener, "sender": observed, "receiver": receiver,
        "request_raw": request_raw, "clocks": clocks}


def bootstrap(value, **changes):
    return compiler.bootstrap(value["pending"], **(value["parameters"] | changes))


def rendezvous(value, **changes):
    return compiler.rendezvous(value["request_raw"], **({"expected_request_sha256": p.sha(value["request_raw"]),
        "expected_receiver": value["receiver"], **value["clocks"]} | changes))


class LifecycleInputControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        owner = tempfile.TemporaryDirectory(prefix="lifecycle-input-fixture-")
        parent = Path(owner.name)
        cls.addClassCleanup(owner.cleanup)
        cls.addClassCleanup(runtime_fixture.thaw, parent)
        cls.value = fixture(parent)

    def test_signed_sources_compile_exact_five_candidates_without_approval(self):
        value = copy.deepcopy(self.value)
        before = copy.deepcopy(value)
        result = bootstrap(value)
        self.assertEqual(set(result), {"originals", "pins", "deadline", "epochLimit"})
        self.assertEqual(tuple(result["originals"]), compiler.ORIGINALS)
        self.assertEqual(result["pins"], {name: p.sha(raw) for name, raw in result["originals"].items()})
        for name in ("recipe", "conductor_inventory", "authority_inventory"):
            self.assertEqual(result["originals"][name], value["parameters"][name + "_original"])
        intake = compiler.intake.validate_configuration(result["originals"]["intake_configuration"], **value["clocks"])
        self.assertEqual(intake["sender"], {"pid": 100, "uid": 0, "gid": 0, "startTimeTicks": 123})
        policy = compiler.policy.shape(result["originals"]["policy"])
        self.assertEqual(policy["bootstrapOriginals"], value["recipe"]["bootstrapOriginals"])
        self.assertEqual(policy["measuredRecipeSha256"], value["parameters"]["recipe_sha256"])
        self.assertEqual(policy["intakeConfigurationOriginal"].encode("ascii"), result["originals"]["intake_configuration"])
        self.assertNotIn("approved", policy)
        self.assertEqual(value, before)

    def test_original_clock_intersection_never_renews(self):
        value = self.value
        result = bootstrap(value)
        intake = p.document(result["originals"]["intake_configuration"], compiler.intake.MAX_CONFIGURATION)
        self.assertEqual((intake["issuedAtBoottimeNs"], intake["startupDeadlineBoottimeNs"],
            intake["lifetimeDeadlineBoottimeNs"]), ("1000000", "1800000000", "40000000000"))
        self.assertEqual(result["deadline"], 1_800_000_000)
        self.assertEqual(result["epochLimit"], value["parameters"]["expires_at_unix_ns"])
        for changes in ({"now_boottime_ns": result["deadline"]}, {"now_boottime_ns": 999_999},
                {"now_unix_ns": result["epochLimit"]}, {"issued_at_unix_ns": value["clocks"]["now_unix_ns"] + 1},
                {"expires_at_unix_ns": value["clocks"]["now_unix_ns"]},
                {"boot": (value["clocks"]["boot"][0], 4, 6)}, {"now_boottime_ns": True}):
            with self.subTest(changes=changes), self.assertRaises(FAILURES): bootstrap(value, **changes)
        later = bootstrap(value, expires_at_unix_ns=value["listener"]["expiresAtUnixNanos"] + 1)
        self.assertEqual(later["epochLimit"], value["listener"]["expiresAtUnixNanos"])

    def test_independent_recipe_and_supervisor_pins_cannot_be_overridden(self):
        for name in ("recipe_sha256", "supervisor_inventory_sha256"):
            with self.subTest(name=name), self.assertRaises(FAILURES):
                bootstrap(self.value, **{name: p.sha(b"unrelated independent original")})
        with self.assertRaises(TypeError): bootstrap(self.value, sender={"pid": 999})
        with self.assertRaises(TypeError): bootstrap(self.value, startup_deadline_boottime_ns=99999999999)

    def test_assignment_window_and_closure_authentication_remain_real(self):
        for target in ("assignment", "window", "closure", "recipe-version"):
            recipe = copy.deepcopy(self.value["recipe"])
            if target == "assignment":
                selected = json.loads(recipe["assignmentOriginal"])
                selected["signature"] = p.encoded(bytes(64))
                recipe["assignmentOriginal"] = p.canonical(selected).decode("ascii")
            elif target == "window":
                selected = json.loads(recipe["bootstrapOriginals"]["window"])
                selected["signatureBase64url"] = p.encoded(bytes(64))
                raw = p.canonical(selected)
                recipe["bootstrapOriginals"]["window"] = raw.decode("ascii")
                control = json.loads(recipe["bootstrapOriginals"]["control"])
                control["windowSha256"] = p.sha(raw)
                recipe["bootstrapOriginals"]["control"] = p.canonical(control).decode("ascii")
            elif target == "closure":
                selected = json.loads(recipe["closureManifestOriginal"])
                selected["manifestSha256"] = p.sha(b"different closure")
                recipe["closureManifestOriginal"] = p.canonical(selected).decode("ascii")
            else:
                recipe["apiVersion"] = compiler.measured.SET_API
            raw = p.canonical(recipe)
            with self.subTest(target=target), self.assertRaises(FAILURES):
                bootstrap(self.value, recipe_original=raw, recipe_sha256=p.sha(raw))

    def test_inventory_source_profile_and_literal_record_hash_joins(self):
        for target in ("role", "source", "records"):
            inventory = json.loads(self.value["parameters"]["supervisor_inventory_original"])
            if target == "role": inventory["apiVersion"] = artifacts.AUTHORITY_API_VERSION
            elif target == "source": inventory["source"]["revision"] = "2" * 40
            else: inventory["recordsSha256"] = p.sha(b"wrong records")
            raw = artifacts._canonical(inventory)
            with self.subTest(target=target), self.assertRaises(FAILURES):
                bootstrap(self.value, supervisor_inventory_original=raw, supervisor_inventory_sha256=p.sha(raw))
        with self.assertRaises(FAILURES):
            bootstrap(self.value, conductor_inventory_original=self.value["parameters"]["authority_inventory_original"])

    def test_inventory_codec_accepts_bounded_public_records_beyond_signed_node_limit(self):
        # Codec-only synthetic records, not evidence for actual installed files.
        inventory = json.loads(self.value["parameters"]["conductor_inventory_original"])
        extra = [{"path": "vendor/public-%04d" % index, "type": "file", "mode": "0444",
            "bytes": 0, "sha256": p.sha(b"")} for index in range(3000)]
        inventory["records"] = sorted(inventory["records"] + extra, key=lambda row: row["path"])
        inventory["recordsSha256"] = p.sha(artifacts._canonical(inventory["records"]))
        inventory["counts"]["entries"] += len(extra)
        inventory["counts"]["files"] += len(extra)
        raw = artifacts._canonical(inventory)
        with self.assertRaises(ValueError): p.document(raw, artifacts.MAX_MANIFEST_BYTES)
        self.assertEqual(compiler._inventory(raw, "conductor"), inventory["source"])

    def test_exact_key_purposes_and_configured_driver_keys_are_required(self):
        for target in ("missing", "extra", "bootstrap", "scope"):
            keys = copy.deepcopy(self.value["parameters"]["key_bindings"])
            if target == "missing": del keys[next(iter(keys))]
            elif target == "extra": keys["self-approve"] = p.sha(b"not a purpose")
            else: keys["driver-" + target] = p.sha(b"different configured key")
            with self.subTest(target=target), self.assertRaises(FAILURES): bootstrap(self.value, key_bindings=keys)

    def test_observed_sender_original_is_required_not_a_predicted_pid(self):
        for target in ("hash", "pid", "namespace", "bound", "extra"):
            value = copy.deepcopy(self.value)
            sender = json.loads(value["pending"]["senderRequestOriginal"])
            observation = json.loads(sender["listenerOriginal"])
            if target == "hash": sender["configurationSha256"] = p.sha(b"other listener")
            elif target == "bound": sender["deadlineBoottimeNs"] = "1800000001"
            elif target == "extra": value["pending"]["receiverPid"] = 200
            else:
                observation["processId" if target == "pid" else "timeNamespaceInode"] = 1 if target == "pid" else 6
                raw = p.canonical(observation)
                sender.update(listenerOriginal=raw.decode("ascii"), listenerSha256=p.sha(raw))
            value["pending"]["senderRequestOriginal"] = p.canonical(sender).decode("ascii")
            with self.subTest(target=target), self.assertRaises(FAILURES): bootstrap(value)

    def test_interactive_selection_is_explicit_and_original_interval_is_not_clipped(self):
        now, epoch = (self.value["clocks"][name] for name in ("now_boottime_ns", "now_unix_ns"))
        interval = {"apiVersion": compiler.interactive.API, "stopAtBoottimeNanos": now + 100_000_000,
            "expiresAtUnixNanos": epoch + 200_000_000}
        selected = {"apiVersion": compiler.policy.INTERACTIVE_API,
            "purpose": compiler.policy.INTERACTIVE_PURPOSE, "interactive": interval}
        result = bootstrap(self.value, policy_selection=selected)
        self.assertEqual(compiler.policy.shape(result["originals"]["policy"])["interactive"], interval)
        for changed in (self.value["parameters"]["policy_selection"] | {"interactive": interval},
                selected | {"purpose": compiler.policy.PURPOSE}, selected | {"approved": True},
                selected | {"interactive": interval | {"expiresAtUnixNanos": epoch + 300_000_001}},
                selected | {"interactive": interval | {"stopAtBoottimeNanos": now + 200_000_000}}):
            with self.subTest(selected=changed), self.assertRaises(FAILURES): bootstrap(self.value, policy_selection=changed)

    def test_rendezvous_returns_only_existing_execution_for_exact_observed_receiver(self):
        result = rendezvous(self.value)
        self.assertEqual(set(result), {"input_original", "input_sha256", "deadline", "epochLimit"})
        self.assertEqual(result["input_sha256"], p.sha(result["input_original"]))
        execution = compiler.rendezvous_profile.execution(result["input_original"],
            self.value["request_raw"], **self.value["clocks"])
        self.assertEqual(execution["window"], self.value["listener"]["window"])
        self.assertEqual(execution["coreHandoff"], {"peerPid": 200, "peerUid": 0, "peerGid": 0})
        self.assertNotIn("approval", execution)
        self.assertEqual(result["deadline"], 1_800_000_000)
        self.assertEqual(result["epochLimit"], self.value["listener"]["expiresAtUnixNanos"])

    def test_rendezvous_independent_request_pin_and_all_receiver_fields_are_exact(self):
        with self.assertRaises(FAILURES): rendezvous(self.value, expected_request_sha256=p.sha(b"different request"))
        for name in ("pid", "uid", "gid", "startTimeTicks"):
            expected = self.value["receiver"] | {name: self.value["receiver"][name] + 1}
            with self.subTest(field=name), self.assertRaises(FAILURES): rendezvous(self.value, expected_receiver=expected)
        with self.assertRaises(FAILURES):
            rendezvous(self.value, expected_receiver=self.value["receiver"] | {"approved": True})

    def test_rendezvous_original_clocks_canonical_transcript_and_no_approval_override(self):
        for changes in ({"now_boottime_ns": 1_800_000_000}, {"now_boottime_ns": 999_999},
                {"now_unix_ns": self.value["listener"]["expiresAtUnixNanos"]},
                {"boot": (self.value["clocks"]["boot"][0], 4, 6)}):
            with self.subTest(changes=changes), self.assertRaises(FAILURES): rendezvous(self.value, **changes)
        changed = self.value | {"request_raw": self.value["request_raw"] + b"\n"}
        with self.assertRaises(FAILURES): rendezvous(changed)
        with self.assertRaises(TypeError): rendezvous(self.value, approval={"approved": True})


if __name__ == "__main__":
    unittest.main()

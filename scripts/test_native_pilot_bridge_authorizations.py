#!/usr/bin/env python3
"""Synthetic bridge signature chains; no provisioning or native acceptance.

All keys, clocks, processes, activations, peers and ciphertext pins are synthetic
in-memory data. Signatures use deterministic test keys, never signer entrypoints.
The nested operational-runtime/history fixtures exercise the public producer
contract only, not native full-runtime authentication or independent approval.
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))

from catchplate import native_pilot_bridge_authority as authority
from catchplate import native_pilot_bridge_key_profile as profile
from catchplate import native_pilot_closure_authority as closure
from catchplate import native_pilot_encrypted_authority as endpoint_encrypted
from catchplate import native_pilot_key_profile as endpoint_keys
from catchplate import native_pilot_measured_configuration as measured
from catchplate import native_pilot_verifier_authority as endpoint_verifier
from test_native_pilot_bridge_runtime import fixture as runtime_fixture
from test_native_pilot_closure_set import canonical, sha, synthetic
from test_native_pilot_generation_scope import fixture as scope_fixture, key_fixture, signed_message, encoded, NOW
from test_native_pilot_key_authorizations import public_keys, key_root

SERVICES = ("durable-recovery-store", "cleanup-authorization-consumer", "recovery-target-provider",
    "current-signature-authority", "bounded-cleanup-helper")
NATIVE_SIGNERS = {
    "ledger-append": ("commit-request", "commit-request-peer-directory"),
    "ingress-admission": ("ingress-admission", "ingress-admission-peer-directory"),
    "terminal-append": ("terminal-append", "terminal-append-peer-directory"),
    "dispatch-barrier": ("dispatch-barrier", "dispatch-barrier-peer-directory"),
    "active-effect-barrier": ("active-effect-barrier", "active-effect-barrier-peer-directory"),
    "active-effect-commit": ("active-effect-commit", "active-effect-commit-peer-directory"),
}
PROOFS = {"retrieval": ("retrieval", "retrieval-peer-directory"),
    "persistence": ("persistence", "persistence-peer-directory"),
    "trusted-time": ("trusted-time", "trusted-time-peer-directory"),
    "generation-install-envelope": ("generation-install", "shadow-generation-install-directory")}
EXTERNAL = ("unavailable-ingress", "spool-compaction", "publication-reconciliation", "activation-publication")
WINDOW = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")
DOMAINS = {"role-keys": "catchplate.nativeShadowRoleKeyAssignment.signature/v2",
    "admission": "catchplate.nativeShadowBridgeAdmissionAssignment.signature/v1",
    "encrypted-delivery": "catchplate.nativeShadowEncryptedKeyDelivery.signature/v1",
    "verifier-transport": "catchplate.nativeShadowVerifierTransport.signature/v1"}


def clocks():
    return {"boot": (encoded(b"synthetic-boot16"), 4, 5), "now_boottime_ns": 1_000_000_000, "now_unix_ns": NOW}


def _cold_key(label):
    private, public = key_fixture(label)
    raw = base64.urlsafe_b64decode(public["publicKeyBase64url"] + "==")
    return private, {"keyId": sha(raw), "publicKeyBase64url": encoded(raw)}


def fixture(*, large=False, ciphertext_matches=True):
    _, source, _ = scope_fixture()
    originals, result = source["recipe_originals"], source["measured"]
    selected = json.loads(originals["closureSetOriginal"])
    manifest = selected["members"][-1]["manifest"]
    config = json.loads(source["bootstrap_configuration_original"])
    image = config["image"]
    image["bootstrapRuntimeSha256"] = manifest["runtimeConfigurationSha256"]
    for target, field in (("dependencyLockSha256", "dependencyLockSha256"),
            ("buildRecipeSha256", "buildRecipeSha256"), ("provenanceSha256", "provenanceStatementSha256")):
        image[target] = manifest["buildProvenance"][field]
    private, cold_key = _cold_key("bridge-c9")
    cold = {"apiVersion": "catchplate.policyCustodyGuestConfiguration/v1", "authority": cold_key,
        "serviceRole": "production-bridge", "uid": config["uid"], "gid": config["gid"]}
    cold_raw = canonical(cold)
    config["deliveryConfiguration"]["sha256"] = sha(cold_raw)
    config_raw = canonical(config)
    window = {"configurationSha256": sha(config_raw), "signingKeyId": config["bootstrapAuthority"]["keyId"],
        "bootIdBase64url": clocks()["boot"][0], "timeNamespaceDevice": 4, "timeNamespaceInode": 5,
        "issuedAtBoottimeNs": "1000", "startupDeadlineBoottimeNs": "2000000000",
        "lifetimeDeadlineBoottimeNs": "60000000000", "invocationId": "1" * 32}
    window_raw = canonical({"apiVersion": "catchplate.nativeShadowDriverBootstrapWindow/v1", "payload": window,
        "signatureBase64url": encoded(key_fixture("window")[0].sign(
            b"catchplate.nativeShadowDriverBootstrapWindow.signature/v1\0" + canonical(window)))})
    observed = json.loads(source["driver_observation_original"])
    observed.update(configurationSha256=sha(config_raw), windowSha256=sha(window_raw))
    control = canonical({"apiVersion": "catchplate.nativeShadowDriverBootstrapControl/v1",
        "supervisorExecutableSha256": synthetic("supervisor"),
        "configurationSha256": sha(config_raw), "windowSha256": sha(window_raw)})

    runtime = runtime_fixture()
    peer = {"uid": 62000, "gid": 62000, "pid": 101,
        **{name: 1 for name in ("startTimeTicks", "executableDevice", "executableInode", "executableLength", "cgroupMountId", "cgroupInode")},
        **{name: synthetic("peer/" + name) for name in ("processIdentitySha256", "executableSha256", "cgroupPathSha256",
            "securityLabelSha256", "configurationGenerationSha256")}}
    runtime["serviceSessions"] = [{"serviceRole": role, "activationFdName": "service-" + str(index),
        "expectedSocketPath": "/run/synthetic/" + role + ".sock", "expectedPeer": copy.deepcopy(peer), "handshakes": [{}]}
        for index, role in enumerate(SERVICES)]
    runtime["parentSignerEndpoints"], runtime["proofEndpoints"] = [], []
    inventory = {"production-listener": stat.S_IFSOCK, "production-journal": stat.S_IFDIR, "generation-origin": stat.S_IFSOCK}
    other = [row["activationFdName"] for row in runtime["serviceSessions"]]
    for role in (*NATIVE_SIGNERS, *EXTERNAL):
        name = "signer-" + role
        path = "/run/catchplate-shadow-" + NATIVE_SIGNERS[role][0] + "/listener.sock" if role in NATIVE_SIGNERS else "/run/synthetic/" + role + ".sock"
        runtime["parentSignerEndpoints"].append({"signerRole": role, "activationFdName": name,
            "expectedSocketPath": path, "expectedPeer": copy.deepcopy(peer), "authorityBindingCredential": name,
            "authorityKeyId": synthetic(name + "/key"), "authorityKeySpkiSha256": synthetic(name + "/spki")})
        if role in NATIVE_SIGNERS:
            inventory[name] = stat.S_IFSOCK; inventory[NATIVE_SIGNERS[role][1]] = stat.S_IFDIR
        else:
            other.append(name)
    for role, (directory, activation) in PROOFS.items():
        name = "proof-" + role
        runtime["proofEndpoints"].append({"endpointKind": role, "activationFdName": name,
            "expectedSocketPath": "/run/catchplate-shadow-" + directory + "/listener.sock", "expectedPeer": copy.deepcopy(peer),
            "authorityBindingCredential": name, "authorityKeyId": synthetic(name + "/key"),
            "authorityKeySpkiSha256": synthetic(name + "/spki")})
        inventory[name] = stat.S_IFSOCK; inventory[activation] = stat.S_IFDIR
    for index, name in enumerate(sorted(other)):
        inventory[name] = stat.S_IFSOCK; inventory["bridge-outgoing-directory-" + str(index)] = stat.S_IFDIR
    if large:
        runtime["spool"]["currentGrantOriginal"] = canonical({"syntheticPadding": "x" * 70000}).decode("ascii")
    runtime_raw = canonical(runtime)
    activation = [{"name": name, "fd": fd, "device": 7, "inode": 9000 + fd,
        "mode": kind | 0o700, "uid": cold["uid"], "gid": cold["gid"]}
        for fd, (name, kind) in enumerate(sorted(inventory.items()), 6)]
    transport = config["continuation"]["keyTransport"]
    payload = {"configurationSha256": sha(cold_raw), "authorityKeyId": cold_key["keyId"],
        **{name: cold[name] for name in ("serviceRole", "uid", "gid")}, **{name: window[name] for name in WINDOW},
        "runtimeConfig": {"path": "/etc/catchplate/native-pilot-inputs/bridge-runtime.json", "sha256": sha(runtime_raw)},
        "activation": activation, "credentials": [{"name": "shadow-encrypted-role-inventory", "length": 256, "signing": None,
            "original": {"path": "/etc/catchplate/synthetic-encrypted-bridge.json", "sha256": transport["encryptedInventorySha256"]
                if ciphertext_matches else synthetic("different-unprovisioned-ciphertext")}}]}
    delivery_raw = canonical({"apiVersion": "catchplate.policyCustodyGuestDelivery/v1", "payload": payload,
        "signatureBase64url": encoded(private.sign(b"catchplate.policyCustodyGuestDelivery.signature/v1\0" + canonical(payload)))})
    delivery_input = canonical({"apiVersion": "catchplate.nativePilotDeliverySigningInput/v1", "role": "bridge",
        "configurationOriginal": cold_raw.decode("ascii"), "ownerConfigurationOriginal": config_raw.decode("ascii"),
        "windowOriginal": window_raw.decode("ascii"), "observationOriginal": canonical(observed).decode("ascii"),
        "runtimeOriginal": runtime_raw.decode("ascii"), "payloadOriginal": canonical(payload).decode("ascii"),
        "activationOriginal": canonical(activation).decode("ascii")})
    value = {"apiVersion": "catchplate.nativePilotBridgeKeyAuthorityInput/v1", "operation": "role-keys",
        "controlOriginal": control.decode("ascii"), "deliveryInputOriginal": delivery_input.decode("ascii"),
        "deliveryOriginal": delivery_raw.decode("ascii"), "recipeOriginals": originals, "measured": result,
        "policy": {"localRoles": ["custody-result-envelope"], "challengeBase64url": encoded(b"synthetic-bridge-challenge-32!!!".ljust(32, b"!")),
            "issuedAtUnixNanos": NOW - 500_000_000, "expiresAtUnixNanos": NOW + 500_000_000}}
    guest = {name: payload[name] for name in ("configurationSha256", "serviceRole", "uid", "gid", *WINDOW)}
    guest.update(deliverySha256=sha(delivery_raw), runtimeConfigurationSha256=sha(runtime_raw))
    return value, guest, manifest


def expected_key(value, guest, manifest):
    envelope = json.loads(value["recipeOriginals"]["assignmentOriginal"])
    trust = json.loads(value["recipeOriginals"]["trustOriginal"])
    supervisor = public_keys()[-1]
    return {"apiVersion": "catchplate.nativeShadowRoleKeyAssignment/v2", "profile": "preassigned-encrypted-local-v1",
        "purpose": "shadow-role-key-possession", "assignmentId": envelope["payload"]["assignmentId"],
        "assignmentPayloadSha256": envelope["payloadSha256"], "assignmentRevision": envelope["payload"]["assignmentRevision"],
        "guest": guest, "executionClosureManifestSha256": manifest["manifestSha256"], "fullKeySetRootSha256": key_root(public_keys()),
        "challengeBase64url": value["policy"]["challengeBase64url"],
        **{name: trust["checkpoint"][name] for name in ("revocationGeneration", "revocationRootSha256")},
        "trustCheckpointId": trust["checkpoint"]["checkpointId"],
        **{name: value["policy"][name] for name in ("issuedAtUnixNanos", "expiresAtUnixNanos", "localRoles")},
        "signingKeyId": supervisor["keyId"], "signingKeySpkiSha256": supervisor["keySpkiSha256"]}


def signed(operation, payload, *, domain=None):
    signature = encoded(key_fixture("custody-supervisor-capability")[0].sign(signed_message(domain or DOMAINS[operation], payload)))
    value = {"payload": payload, "signature": signature}
    if operation in ("encrypted-delivery", "verifier-transport"):
        value = {"apiVersion": "catchplate.nativeShadow" + ("EncryptedKeyDelivery" if operation == "encrypted-delivery" else "VerifierTransport") + "/v1",
            "authorization": value}
    raw = canonical(value)
    return raw, {"original": raw.decode("ascii"), "sha256": sha(raw)}


def pair(value, guest, manifest):
    first_input = canonical(value)
    first_payload = expected_key(value, guest, manifest)
    first_raw, _ = signed("role-keys", first_payload)
    second = copy.deepcopy(value); second.update(operation="admission", roleKeyOriginal=first_raw.decode("ascii"))
    payload = {name: item for name, item in first_payload.items() if name not in ("apiVersion", "purpose", "profile", "assignmentId", "localRoles")}
    payload.update(apiVersion="catchplate.nativeShadowBridgeAdmissionAssignment/v1", purpose="native-shadow-context-and-production-admission",
        keyAuthorizationSha256=sha(first_raw), localKeySetRootSha256=key_root([record for record in public_keys()
            if record["role"] in value["policy"]["localRoles"]]),
        productionConfigurationBindingSha256=value["measured"]["configurationBindingSha256"])
    second_raw, _ = signed("admission", payload)
    return dict(zip(authority.PAIR_FIELDS, (raw.decode("ascii") for raw in
        (first_input, first_raw, canonical(second), second_raw)), strict=True))


def late_input(operation, pair_value):
    value = {"apiVersion": "catchplate.nativePilotBridgeLateAuthorityInput/v1", "operation": operation, **pair_value,
        "issuedAtUnixNanos": NOW - 100_000_000, "expiresAtUnixNanos": NOW + 100_000_000}
    if operation == "verifier-transport": value["parentPort"] = 11443
    return value


class BridgeAuthorizationControls(unittest.TestCase):
    def test_complete_key_and_bridge_admission_signatures_bind_measured_production(self):
        value, guest, manifest = fixture(); frozen = copy.deepcopy(value)
        records = pair(value, guest, manifest)
        for operation, prefix in (("role-keys", "roleKey"), ("admission", "admission")):
            raw = records[prefix + "Original"].encode("ascii")
            self.assertEqual(authority.checked_result(operation, records[prefix + "InputOriginal"].encode("ascii"),
                {"original": raw.decode("ascii"), "sha256": sha(raw)}, **clocks()), raw)
        admitted = profile.admitted_pair(*(records[name].encode("ascii") for name in authority.PAIR_FIELDS), **clocks())
        self.assertEqual(admitted["expectedScope"]["productionConfigurationBindingSha256"], value["measured"]["configurationBindingSha256"])
        self.assertEqual(admitted["expectedScope"]["apiVersion"], "catchplate.nativeShadowBridgeAdmissionScope/v1")
        self.assertEqual(value, frozen)

    def test_encrypted_and_verifier_exact_outputs_use_original_transport_and_keys(self):
        value, guest, manifest = fixture(); records = pair(value, guest, manifest)
        key = json.loads(records["roleKeyOriginal"])["payload"]
        for operation in ("encrypted-delivery", "verifier-transport"):
            supplied = late_input(operation, records)
            common = {name: key[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "guest",
                "fullKeySetRootSha256", "challengeBase64url", "trustCheckpointId", "revocationGeneration", "revocationRootSha256",
                "signingKeyId", "signingKeySpkiSha256")}
            common.update(keyAuthorizationSha256=sha(records["roleKeyOriginal"].encode("ascii")),
                issuedAtUnixNanos=supplied["issuedAtUnixNanos"], expiresAtUnixNanos=supplied["expiresAtUnixNanos"])
            if operation == "encrypted-delivery":
                config = json.loads(json.loads(value["deliveryInputOriginal"])["ownerConfigurationOriginal"])
                expected = dict(common, apiVersion="catchplate.nativeShadowEncryptedKeyDeliveryAssignment/v1",
                    purpose="kms-recipient-shadow-local-keys", transport=config["continuation"]["keyTransport"],
                    localKeySetRootSha256=json.loads(records["admissionOriginal"])["payload"]["localKeySetRootSha256"])
            else:
                verifier = public_keys()[-2]
                expected = dict(common, apiVersion="catchplate.nativeShadowVerifierTransportAssignment/v1",
                    purpose="public-shadow-nitro-verification", parentPort=11443, verifierKeyId=verifier["keyId"],
                    verifierKeySpkiSha256=verifier["keySpkiSha256"], verifierKeyMaterialSha256=verifier["keyMaterialSha256"])
            raw, result = signed(operation, expected)
            context = authority.prepare_input(operation, canonical(supplied), **clocks())
            self.assertEqual(context["payload"], expected)
            self.assertEqual(context["deadline"], 2_000_000_000)
            self.assertEqual(authority.checked_result(operation, canonical(supplied), result, **clocks()), raw)

    def test_signed_original_and_complete_delivery_input_associations_are_required(self):
        original, _, _ = fixture()
        for change in ("assignment-signature", "window-signature", "c9-signature", "activation", "control"):
            value = copy.deepcopy(original); source = json.loads(value["deliveryInputOriginal"])
            if change == "assignment-signature":
                signed_value = json.loads(value["recipeOriginals"]["assignmentOriginal"]); signed_value["signature"] = encoded(b"x" * 64)
                value["recipeOriginals"]["assignmentOriginal"] = canonical(signed_value).decode("ascii")
            elif change == "window-signature":
                signed_value = json.loads(source["windowOriginal"]); signed_value["signatureBase64url"] = encoded(b"x" * 64)
                source["windowOriginal"] = canonical(signed_value).decode("ascii")
            elif change == "c9-signature":
                signed_value = json.loads(value["deliveryOriginal"]); signed_value["signatureBase64url"] = encoded(b"x" * 64)
                value["deliveryOriginal"] = canonical(signed_value).decode("ascii")
            elif change == "activation":
                records = json.loads(source["activationOriginal"]); records[0]["inode"] += 1
                source["activationOriginal"] = canonical(records).decode("ascii")
            else:
                control = json.loads(value["controlOriginal"]); control["configurationSha256"] = synthetic("other-control")
                value["controlOriginal"] = canonical(control).decode("ascii")
            value["deliveryInputOriginal"] = canonical(source).decode("ascii")
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                authority.prepare_input("role-keys", canonical(value), **clocks())

    def test_measured_binding_is_rederived_not_promoted_from_an_input_digest(self):
        original, _, _ = fixture()
        for change in ("digest", "production", "proof", "kernel"):
            value = copy.deepcopy(original)
            if change == "digest": value["measured"]["configurationBindingSha256"] = synthetic("unbound")
            elif change == "production": value["measured"]["production"]["maximumInFlightCalls"] = 2
            elif change == "proof": value["measured"]["proofScopeOriginal"] = "{}"
            else:
                binding = json.loads(value["measured"]["configurationBindingOriginal"])
                binding["kernelRetainedDriverIdentitySha256"] = synthetic("other-driver")
                value["measured"]["configurationBindingOriginal"] = canonical(binding).decode("ascii")
            with self.subTest(change=change), self.assertRaises(ValueError):
                authority.prepare_input("role-keys", canonical(value), **clocks())

    def test_prior_admission_domain_production_and_result_hash_cannot_be_substituted(self):
        value, guest, manifest = fixture(); records = pair(value, guest, manifest)
        for change in ("endpoint-domain", "production", "hash"):
            supplied = late_input("verifier-transport", records)
            admitted = json.loads(supplied["admissionOriginal"])
            if change == "endpoint-domain":
                raw, _ = signed("admission", admitted["payload"], domain="catchplate.nativeShadowKeyAdmissionAssignment.signature/v1")
                supplied["admissionOriginal"] = raw.decode("ascii")
            elif change == "production":
                admitted["payload"]["productionConfigurationBindingSha256"] = synthetic("unbound-production")
                raw, _ = signed("admission", admitted["payload"]); supplied["admissionOriginal"] = raw.decode("ascii")
            else:
                raw = records["roleKeyOriginal"].encode("ascii")
                with self.assertRaises(ValueError):
                    authority.checked_result("role-keys", records["roleKeyInputOriginal"].encode("ascii"),
                        {"original": raw.decode("ascii"), "sha256": synthetic("wrong-result")}, **clocks())
                continue
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                authority.prepare_input("verifier-transport", canonical(supplied), **clocks())

    def test_ciphertext_selection_and_original_intervals_are_not_replaceable(self):
        value, guest, manifest = fixture(ciphertext_matches=False)
        records = pair(value, guest, manifest)
        with self.assertRaises(ValueError):
            authority.prepare_input("encrypted-delivery", canonical(late_input("encrypted-delivery", records)), **clocks())
        value, guest, manifest = fixture(); records = pair(value, guest, manifest)
        for change in ("expiry", "port", "transport"):
            supplied = late_input("verifier-transport" if change == "port" else "encrypted-delivery", records)
            if change == "expiry": supplied["expiresAtUnixNanos"] = NOW + 600_000_000
            elif change == "port": supplied["parentPort"] = 0
            else: supplied["transportOriginal"] = "{}"
            with self.subTest(change=change), self.assertRaises(ValueError):
                authority.prepare_input(supplied["operation"], canonical(supplied), **clocks())
        with self.assertRaises(ValueError):
            authority.prepare_input("role-keys", canonical(value), **dict(clocks(), now_boottime_ns=2_000_000_000))

    def test_v10_closure_uses_original_large_runtime_without_widening_legacy(self):
        value, guest, manifest = fixture(large=True); source = json.loads(value["deliveryInputOriginal"])
        authority.prepare_input("role-keys", canonical(value), **clocks())
        key = expected_key(value, guest, manifest); selected = json.loads(value["recipeOriginals"]["closureSetOriginal"])
        member = profile.assignments.closure_binding(json.loads(value["recipeOriginals"]["assignmentOriginal"]),
            canonical(selected), "bridge")
        payload = {name: key[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "guest",
            "trustCheckpointId", "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos",
            "signingKeyId", "signingKeySpkiSha256")}
        payload.update(apiVersion="catchplate.nativeCustodyClosureAssignment/v3", purpose="shadow-custody-closure-set-member",
            profile="native-multi-guest-closure-set-v1", guestRole="bridge",
            **{name: member[name] for name in ("manifestSha256", "setRootSha256", "seccompSetRootSha256", "leafSha256")})
        supplied = {"apiVersion": "catchplate.nativePilotClosureAuthorityInput/v2", "guestRole": "bridge",
            "controlOriginal": value["controlOriginal"], "configurationOriginal": source["ownerConfigurationOriginal"],
            "windowOriginal": source["windowOriginal"], "observationOriginal": source["observationOriginal"],
            "deliveryConfigurationOriginal": source["configurationOriginal"], "deliveryOriginal": value["deliveryOriginal"],
            "runtimeOriginal": source["runtimeOriginal"], **value["recipeOriginals"],
            "manifestOriginal": canonical(manifest).decode("ascii"), "payloadOriginal": canonical(payload).decode("ascii")}
        prepared = closure.prepare_input(canonical(supplied), **clocks())
        self.assertEqual(prepared["payload"], payload)
        signature = encoded(key_fixture("custody-supervisor-capability")[0].sign(signed_message(
            "catchplate.nativeCustodyClosureAssignment.signature/v3", payload)))
        raw = canonical({"apiVersion": "catchplate.nativeCustodyClosure/v3", "manifest": manifest,
            "closureSet": selected, "authorization": {"payload": payload, "signature": signature}})
        self.assertEqual(closure.checked_result(canonical(supplied), {"original": raw.decode("ascii"), "sha256": sha(raw)}, **clocks()), raw)
        old = json.loads(source["runtimeOriginal"]); old["apiVersion"] = "catchplate.policyCustodyProductionRpcRuntime/v9"
        old.pop("ordinaryInitialHistories"); supplied["runtimeOriginal"] = canonical(old).decode("ascii")
        with self.assertRaises(ValueError): closure.prepare_input(canonical(supplied), **clocks())

    def test_closed_bridge_input_and_endpoint_role_sets_remain_separate(self):
        value, _, _ = fixture()
        for change in ("role", "version", "operation", "noncanonical"):
            supplied = copy.deepcopy(value)
            if change == "role": supplied["role"] = "bridge"
            elif change == "version": supplied["apiVersion"] = endpoint_keys.API
            elif change == "operation": supplied["operation"] = "request-commitment"
            raw = canonical(supplied) + (b"\n" if change == "noncanonical" else b"")
            with self.subTest(change=change), self.assertRaises(ValueError): authority.prepare_input("role-keys", raw, **clocks())
        for module in (endpoint_keys, endpoint_encrypted, endpoint_verifier):
            self.assertEqual(len(module.ROLES), 10); self.assertNotIn("bridge", module.ROLES)
        self.assertEqual(closure.MAX_INPUT, 8 * 1024 * 1024)
        self.assertEqual(closure.MAX_BRIDGE_INPUT, 16 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()

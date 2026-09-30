#!/usr/bin/env python3
"""Synthetic pure key-authorization controls, not approval or native evidence.

All credentials, processes, images, clock samples and authority originals below
are in-memory fixtures. Actual test-key signatures exercise public verifiers;
no signer entrypoint, live owner, protected file, verifier verdict or network is
used. The reused assignment has deliberately empty unrelated policy fields and
does not establish complete native assignment, provenance or runtime admission.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_key_profile as profile
from test_native_pilot_closure_set import (KEY_ROLES, MANIFEST_FIELDS, canonical, frame,
    merkle_fixture, sha, synthetic)
from test_native_pilot_generation_scope import NOW, encoded, key_fixture, signed_message
from test_native_pilot_native_deliveries import (ALL_ROLES, WINDOW_FIELDS, bind_set, cold_key,
    fixture as delivery_fixture, result_for)

ROLES = ("retrieval", "persistence", "trustedTime", "generationInstall", "commitRequest",
    "ingressAdmission", "terminalAppend", "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
REQUIRED = {
    "retrieval": "custody-retrieval-response", "persistence": "custody-store-response",
    "trustedTime": "custody-trusted-time-response", "generationInstall": "custody-result-envelope",
    "commitRequest": "custody-ledger-append", "ingressAdmission": "custody-ingress-admission",
    "terminalAppend": "custody-terminal-append", "dispatchBarrier": "custody-dispatch-barrier",
    "activeEffectBarrier": "custody-active-effect-barrier", "activeEffectCommit": "custody-active-effect-commit",
}
ROW_FIELDS = ("localRoles", "challengeBase64url", "issuedAtUnixNanos", "expiresAtUnixNanos")
INPUT_FIELDS = ("apiVersion", "operation", "role", "deliveryInputOriginal", "deliveryOriginal",
    "recipeOriginals", "measured", "policy")
KEY_DOMAIN = "serverware.nativeShadowRoleKeyAssignment.signature/v2"
ADMISSION_DOMAIN = "serverware.nativeShadowKeyAdmissionAssignment.signature/v1"
GUEST_FIELDS = ("configurationSha256", "deliverySha256", "runtimeConfigurationSha256", "serviceRole", "uid", "gid") + WINDOW_FIELDS
FIRST_ACTIVATIONS = {
    "retrieval": (("retrieval-listener", stat.S_IFSOCK), ("retrieval-objects", stat.S_IFDIR),
        ("ledger-spool-store", stat.S_IFDIR), ("ledger-spool-lock", stat.S_IFREG)),
    "persistence": (("persistence-listener", stat.S_IFSOCK), ("persistence-journal", stat.S_IFDIR),
        ("persistence-lock", stat.S_IFREG)),
    "trustedTime": (("trusted-time-listener", stat.S_IFSOCK),),
}


def public_keys():
    return [{"role": role, **key_fixture(role)[1]} for role in KEY_ROLES[7:]]


def key_root(keys):
    # Independent exact frame/Merkle arithmetic; no production key-root helper.
    return merkle_fixture([frame("serverware.policyShadowCustodyAssertedKey/v1",
        [row[name] for name in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")]) for row in keys])


def fixture():
    f = delivery_fixture()
    for index, role in enumerate(ROLES[:3]):
        cold = json.loads(f["cold"][role])
        runtime = canonical({"apiVersion": "serverware.nativePilotEndpointRuntime/v1", "role": role})
        f["fragment"][role] = {"runtimeOriginal": runtime.decode("ascii"),
            "runtimeConfig": {"path": "/etc/serverware/native-pilot-inputs/native-runtime-" + role + ".json",
                "sha256": sha(runtime)},
            "credentials": copy.deepcopy(f["fragment"]["generationInstall"]["credentials"])}
        f["activations"][role] = [{"name": name, "fd": fd, "device": 7, "inode": 8000 + index * 10 + fd,
            "mode": kind | (0o700 if kind == stat.S_IFDIR else 0o600), "uid": cold["uid"], "gid": cold["gid"]}
            for fd, (name, kind) in enumerate(FIRST_ACTIVATIONS[role], 6)]
    selected = json.loads(f["recipe_originals"]["closureSetOriginal"])
    for member in selected["members"]:
        if member["role"] in ROLES:
            manifest = member["manifest"]
            manifest["runtimeConfigurationSha256"] = f["fragment"][member["role"]]["runtimeConfig"]["sha256"]
            manifest["workerExecutableSha256"] = f["config"]["executableSha256"]
            manifest["manifestSha256"] = frame(manifest["apiVersion"], [manifest[name] for name in MANIFEST_FIELDS[:-1]])
    bind_set(f, selected)
    f["policy"], f["delivery_inputs"], f["deliveries"], f["guests"] = {}, {}, {}, {}
    for role in ROLES:
        row, cold = f["fragment"][role], json.loads(f["cold"][role])
        payload = {"configurationSha256": sha(f["cold"][role].encode("ascii")),
            "authorityKeyId": cold["authority"]["keyId"],
            **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
            **{name: f["window"][name] for name in WINDOW_FIELDS}, "runtimeConfig": row["runtimeConfig"],
            "credentials": row["credentials"], "activation": f["activations"][role]}
        raw = canonical({"apiVersion": "serverware.nativePilotDeliverySigningInput/v1", "role": role,
            "configurationOriginal": f["cold"][role],
            "ownerConfigurationOriginal": f["owner_configuration_raw"].decode("ascii"),
            "windowOriginal": f["window_raw"].decode("ascii"), "observationOriginal": f["observation_raw"].decode("ascii"),
            "runtimeOriginal": row["runtimeOriginal"], "payloadOriginal": canonical(payload).decode("ascii"),
            "activationOriginal": canonical(payload["activation"]).decode("ascii")})
        signed = result_for(f, role, raw)["original"].encode("ascii")
        f["delivery_inputs"][role], f["deliveries"][role] = raw, signed
        f["guests"][role] = {name: payload[name] for name in GUEST_FIELDS
            if name not in ("deliverySha256", "runtimeConfigurationSha256")}
        f["guests"][role].update(deliverySha256=sha(signed), runtimeConfigurationSha256=row["runtimeConfig"]["sha256"])
        f["policy"][role] = {"localRoles": [REQUIRED[role]],
            "challengeBase64url": encoded(hashlib.sha256(("SYNTHETIC KEY CHALLENGE / " + role).encode("ascii")).digest()),
            "issuedAtUnixNanos": NOW - 1_000_000_000, "expiresAtUnixNanos": NOW + 1_000_000_000}
    return f


def clocks(f):
    return {"boot": f["boot"], "now_boottime_ns": f["now_boottime_ns"], "now_unix_ns": NOW}


def build(f, operation, role, *, role_key_raw=None, **changes):
    args = {"fragment": f["policy"], "delivery_input_raw": f["delivery_inputs"][role],
        "delivery_raw": f["deliveries"][role], "measured": f["measured"],
        "recipe_originals": f["recipe_originals"], **clocks(f), "role_key_raw": role_key_raw}
    args.update(changes)
    return profile.build(operation, role, **args)


def expected_payload(f, operation, role, *, role_key_raw=None):
    envelope = json.loads(f["recipe_originals"]["assignmentOriginal"])
    assignment, row = envelope["payload"], f["policy"][role]
    trust = json.loads(f["recipe_originals"]["trustOriginal"])
    selected = json.loads(f["recipe_originals"]["closureSetOriginal"])
    manifest = next(member["manifest"] for member in selected["members"] if member["role"] == role)
    keys = public_keys(); supervisor = keys[-1]
    common = {"assignmentPayloadSha256": envelope["payloadSha256"], "assignmentRevision": assignment["assignmentRevision"],
        "guest": f["guests"][role], "executionClosureManifestSha256": manifest["manifestSha256"],
        "fullKeySetRootSha256": key_root(keys), "challengeBase64url": row["challengeBase64url"],
        "trustCheckpointId": trust["checkpoint"]["checkpointId"],
        "revocationGeneration": trust["checkpoint"]["revocationGeneration"],
        "revocationRootSha256": trust["checkpoint"]["revocationRootSha256"],
        "issuedAtUnixNanos": row["issuedAtUnixNanos"], "expiresAtUnixNanos": row["expiresAtUnixNanos"],
        "signingKeyId": supervisor["keyId"], "signingKeySpkiSha256": supervisor["keySpkiSha256"]}
    if operation == "role-keys":
        return {"apiVersion": "serverware.nativeShadowRoleKeyAssignment/v2", "profile": "preassigned-encrypted-local-v1",
            "purpose": "shadow-role-key-possession", "assignmentId": assignment["assignmentId"],
            "localRoles": row["localRoles"], **common}
    return {"apiVersion": "serverware.nativeShadowKeyAdmissionAssignment/v1", "purpose": "native-shadow-key-admission",
        "keyAuthorizationSha256": sha(role_key_raw),
        "localKeySetRootSha256": key_root([key for key in keys if key["role"] in row["localRoles"]]), **common}


def signed_result(payload, operation, *, key=None, domain=None):
    key = key or key_fixture("custody-supervisor-capability")[0]
    domain = domain or (KEY_DOMAIN if operation == "role-keys" else ADMISSION_DOMAIN)
    raw = canonical({"payload": payload, "signature": encoded(key.sign(signed_message(domain, payload)))})
    return raw, {"original": raw.decode("ascii"), "sha256": sha(raw)}


class KeyAuthorizationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()

    def setUp(self):
        self.f = {name: value if name == "key" else copy.deepcopy(value) for name, value in self.original.items()}

    def test_ten_role_policy_is_closed_and_copied(self):
        self.assertEqual(profile.ROLES, ROLES); self.assertEqual(ALL_ROLES, ROLES)
        self.assertEqual(profile.OPERATIONS, ("role-keys", "admission"))
        checked = profile.validate_policy(self.f["policy"])
        self.assertEqual(tuple(checked), ROLES); self.assertEqual(checked, self.f["policy"])
        self.assertTrue(all(set(row) == set(ROW_FIELDS) for row in checked.values()))
        checked[ROLES[0]]["localRoles"].clear()
        self.assertEqual(self.f["policy"][ROLES[0]]["localRoles"], [REQUIRED[ROLES[0]]])
        for change in ("missing", "extra-role", "extra-row", "null"):
            candidate = copy.deepcopy(self.f["policy"])
            if change == "missing": candidate.pop(ROLES[0])
            elif change == "extra-role": candidate["bridge"] = candidate[ROLES[0]]
            elif change == "extra-row": candidate[ROLES[0]]["approved"] = True
            else: candidate[ROLES[0]] = None
            with self.subTest(change=change), self.assertRaises(ValueError): profile.validate_policy(candidate)

    def test_local_roles_exclude_unknown_verifier_supervisor_and_wrong_endpoint(self):
        for local in ([], ["custody-not-a-role"], ["custody-attestation-verifier"], ["custody-supervisor-capability"],
                [REQUIRED["persistence"]], [REQUIRED["retrieval"], REQUIRED["retrieval"]],
                [REQUIRED["retrieval"], REQUIRED["persistence"]]):
            candidate = copy.deepcopy(self.f["policy"]); candidate["retrieval"]["localRoles"] = local
            with self.subTest(local=local), self.assertRaises(ValueError): profile.validate_policy(candidate)

    def test_challenge_and_original_interval_types_are_explicit(self):
        for field, value in (("challengeBase64url", encoded(bytes(32))), ("challengeBase64url", encoded(b"short")),
                ("challengeBase64url", "not canonical="), ("issuedAtUnixNanos", True),
                ("issuedAtUnixNanos", 0), ("expiresAtUnixNanos", None),
                ("expiresAtUnixNanos", NOW - 1_000_000_000)):
            candidate = copy.deepcopy(self.f["policy"]); candidate[ROLES[0]][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): profile.validate_policy(candidate)

    def test_all_ten_role_key_payloads_bind_exact_c9_guest_and_leaf(self):
        keys = public_keys()
        for role in ROLES:
            with self.subTest(role=role):
                raw = build(self.f, "role-keys", role)
                value = json.loads(raw)
                self.assertEqual(set(value), set(INPUT_FIELDS)); self.assertEqual(len(value), 8)
                self.assertEqual(value["policy"], self.f["policy"][role])
                self.assertEqual(value["deliveryOriginal"].encode("ascii"), self.f["deliveries"][role])
                prepared = profile.prepare_input("role-keys", role, raw, **clocks(self.f))
                self.assertEqual(set(prepared), {"payload", "authorityKeys", "trustCheckpoint", "manifest", "window"})
                expected = expected_payload(self.f, "role-keys", role)
                self.assertEqual(prepared["payload"], expected); self.assertEqual(len(expected), 18)
                self.assertEqual(prepared["authorityKeys"], keys)
                self.assertEqual(expected["guest"], self.f["guests"][role])
                self.assertEqual(prepared["manifest"]["manifestSha256"], expected["executionClosureManifestSha256"])
                signed, result = signed_result(expected, "role-keys")
                self.assertEqual(profile.checked_result("role-keys", role, raw, result, **clocks(self.f)), signed)

    def test_all_ten_admissions_bind_exact_prior_original_and_public_pair(self):
        for role in ROLES:
            with self.subTest(role=role):
                key_input = build(self.f, "role-keys", role)
                key_raw, _ = signed_result(expected_payload(self.f, "role-keys", role), "role-keys")
                admission_input = build(self.f, "admission", role, role_key_raw=key_raw)
                value = json.loads(admission_input)
                self.assertEqual(set(value), set(INPUT_FIELDS) | {"roleKeyOriginal"})
                self.assertEqual(len(value), 9); self.assertEqual(value["roleKeyOriginal"].encode("ascii"), key_raw)
                prepared = profile.prepare_input("admission", role, admission_input, **clocks(self.f))
                expected = expected_payload(self.f, "admission", role, role_key_raw=key_raw)
                self.assertEqual(prepared["payload"], expected); self.assertEqual(len(expected), 17)
                self.assertNotEqual(expected["keyAuthorizationSha256"], sha(canonical(json.loads(key_raw)["payload"])))
                admission_raw, result = signed_result(expected, "admission")
                self.assertEqual(profile.checked_result("admission", role, admission_input, result, **clocks(self.f)), admission_raw)
                pair = profile.admitted_pair(role, key_input, key_raw, admission_input, admission_raw, **clocks(self.f))
                self.assertEqual(set(pair), {"authorization", "admissionAuthorization", "expectedScope", "authorityKeys", "trustCheckpoint"})
                self.assertEqual(pair["authorization"], json.loads(key_raw))
                self.assertEqual(pair["admissionAuthorization"], json.loads(admission_raw))
                self.assertEqual(pair["authorityKeys"], public_keys())
                scope = pair["expectedScope"]
                self.assertEqual(scope["keyAuthorizationSha256"], sha(key_raw))
                self.assertEqual(scope["admissionAuthorizationSha256"], sha(admission_raw))
                self.assertEqual(scope["guest"], self.f["guests"][role])
                self.assertEqual(scope["localKeySetRootSha256"], expected["localKeySetRootSha256"])
                self.assertEqual(scope["localKeys"], [key for key in public_keys() if key["role"] == REQUIRED[role]])

    def test_c9_signature_payload_pin_and_role_are_not_replaceable(self):
        role = ROLES[0]
        bad_signature = result_for(self.f, role, self.f["delivery_inputs"][role], key=cold_key("wrong-c9")[0])["original"].encode("ascii")
        with self.assertRaises(InvalidSignature): build(self.f, "role-keys", role, delivery_raw=bad_signature)
        for change in ("payload", "runtime-pin", "other-role"):
            value = json.loads(self.f["delivery_inputs"][role]); payload = json.loads(value["payloadOriginal"])
            if change == "payload": payload["uid"] += 1
            elif change == "runtime-pin": payload["runtimeConfig"]["path"] = "/etc/serverware/other.json"
            else: value["role"] = ROLES[1]
            value["payloadOriginal"] = canonical(payload).decode("ascii")
            candidate = canonical(value); signed = result_for(self.f, role, candidate)["original"].encode("ascii")
            with self.subTest(change=change), self.assertRaises(ValueError):
                build(self.f, "role-keys", role, delivery_input_raw=candidate, delivery_raw=signed)

    def test_only_assignment_authenticated_supervisor_signs_both_protocols(self):
        role = ROLES[0]
        key_input = build(self.f, "role-keys", role)
        key_payload = expected_payload(self.f, "role-keys", role)
        key_raw, _ = signed_result(key_payload, "role-keys")
        admission_input = build(self.f, "admission", role, role_key_raw=key_raw)
        for operation, raw, payload in (("role-keys", key_input, key_payload),
                ("admission", admission_input, expected_payload(self.f, "admission", role, role_key_raw=key_raw))):
            for name, key in (("c9", self.f["key"]), ("verifier", key_fixture("custody-attestation-verifier")[0])):
                _, result = signed_result(payload, operation, key=key)
                with self.subTest(operation=operation, key=name), self.assertRaises(InvalidSignature):
                    profile.checked_result(operation, role, raw, result, **clocks(self.f))

    def test_domains_result_hash_and_payload_are_exact(self):
        role = ROLES[0]; raw = build(self.f, "role-keys", role)
        payload = expected_payload(self.f, "role-keys", role)
        for field, value in (("apiVersion", "serverware.nativePilotKeyAuthorityInput/v2"),
                ("operation", "sign-arbitrary"), ("role", "bridge"), ("payloadOriginal", canonical(payload).decode("ascii"))):
            candidate = json.loads(raw); candidate[field] = value
            with self.subTest(input_field=field), self.assertRaises(ValueError):
                profile.prepare_input("role-keys", role, canonical(candidate), **clocks(self.f))
        for domain in ("serverware.nativeShadowRoleKeyAssignment.signature/v1", ADMISSION_DOMAIN):
            _, result = signed_result(payload, "role-keys", domain=domain)
            with self.subTest(domain=domain), self.assertRaises(InvalidSignature):
                profile.checked_result("role-keys", role, raw, result, **clocks(self.f))
        for change in ("hash", "extra", "full-root", "signer"):
            modified = copy.deepcopy(payload)
            if change == "full-root": modified["fullKeySetRootSha256"] = synthetic("not-full-root")
            elif change == "signer": modified["signingKeyId"] = key_fixture("custody-attestation-verifier")[1]["keyId"]
            _, result = signed_result(modified, "role-keys")
            if change == "hash": result["sha256"] = synthetic("wrong-output")
            elif change == "extra": result["approved"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.checked_result("role-keys", role, raw, result, **clocks(self.f))

    def test_prior_role_key_original_is_required_and_cannot_be_cross_guest(self):
        role = ROLES[0]; payload = expected_payload(self.f, "role-keys", role)
        good, _ = signed_result(payload, "role-keys")
        wrong, _ = signed_result(payload, "role-keys", key=self.f["key"])
        other, _ = signed_result(expected_payload(self.f, "role-keys", ROLES[1]), "role-keys")
        with self.assertRaises(ValueError): build(self.f, "admission", role)
        with self.assertRaises(ValueError): build(self.f, "role-keys", role, role_key_raw=good)
        with self.assertRaises(InvalidSignature): build(self.f, "admission", role, role_key_raw=wrong)
        with self.assertRaises(ValueError): build(self.f, "admission", role, role_key_raw=other)
        raw = build(self.f, "admission", role, role_key_raw=good)
        payload = expected_payload(self.f, "admission", role, role_key_raw=good)
        payload["keyAuthorizationSha256"] = sha(canonical(json.loads(good)["payload"]))
        _, result = signed_result(payload, "admission")
        with self.assertRaises(ValueError): profile.checked_result("admission", role, raw, result, **clocks(self.f))

    def test_original_clock_limits_are_never_extended(self):
        role = ROLES[0]
        for field, value in (("now_boottime_ns", 20_000_000_000), ("now_boottime_ns", 999_999_999),
                ("now_unix_ns", NOW + 1_000_000_000), ("boot", (encoded(b"fedcba9876543210"), 4, 5))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                build(self.f, "role-keys", role, **{field: value})
        for field, value in (("issuedAtUnixNanos", NOW + 1), ("issuedAtUnixNanos", NOW - 11_000_000_000),
                ("expiresAtUnixNanos", NOW + 61_000_000_000)):
            fragment = copy.deepcopy(self.f["policy"]); fragment[role][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                build(self.f, "role-keys", role, fragment=fragment)

    def test_authenticated_assignment_leaf_full_root_and_measured_scope_are_joined(self):
        role = ROLES[0]
        for change in ("assignment-signature", "leaf-runtime", "leaf-executable", "measured-hash", "set-root"):
            f = {name: value if name == "key" else copy.deepcopy(value) for name, value in self.f.items()}
            if change == "assignment-signature":
                envelope = json.loads(f["recipe_originals"]["assignmentOriginal"])
                envelope["signature"] = encoded(self.f["key"].sign(signed_message(
                    "serverware.policyShadowAssignment/v2", envelope["payload"])))
                f["recipe_originals"]["assignmentOriginal"] = canonical(envelope).decode("ascii")
            elif change == "measured-hash": f["measured"]["configurationBindingSha256"] = synthetic("other-binding")
            else:
                selected = json.loads(f["recipe_originals"]["closureSetOriginal"])
                if change == "set-root":
                    selected["setRootSha256"] = synthetic("other-set")
                    f["recipe_originals"]["closureSetOriginal"] = canonical(selected).decode("ascii")
                else:
                    manifest = selected["members"][0]["manifest"]
                    if change == "leaf-runtime":
                        manifest["runtimeConfigurationSha256"] = f["fragment"][ROLES[1]]["runtimeConfig"]["sha256"]
                    else:
                        manifest["workerExecutableSha256"] = synthetic("other-worker")
                    manifest["manifestSha256"] = frame(manifest["apiVersion"], [manifest[name] for name in MANIFEST_FIELDS[:-1]])
                    bind_set(f, selected)
            expected = InvalidSignature if change == "assignment-signature" else ValueError
            with self.subTest(change=change), self.assertRaises(expected): build(f, "role-keys", role)

    def test_current_pinned_trust_and_key_intervals_are_required(self):
        role = ROLES[0]
        for change in ("pin", "expired", "checkpoint", "key-expired", "interval-exceeds-key"):
            originals = copy.deepcopy(self.f["recipe_originals"])
            trust = json.loads(originals["trustOriginal"])
            if change == "expired": trust["expiresAtUnixNanos"] = NOW
            elif change == "checkpoint": trust["checkpoint"]["asOfUnixNanos"] = NOW + 1
            elif change == "key-expired": trust["roleKeys"][-1]["key"]["notAfterUnixNanos"] = NOW
            elif change == "interval-exceeds-key": trust["roleKeys"][-1]["key"]["notAfterUnixNanos"] = NOW + 1
            originals["trustOriginal"] = canonical(trust).decode("ascii")
            originals["trustSha256"] = synthetic("other-trust") if change == "pin" else sha(canonical(trust))
            with self.subTest(change=change), self.assertRaises(ValueError):
                build(self.f, "role-keys", role, recipe_originals=originals)


if __name__ == "__main__":
    unittest.main()

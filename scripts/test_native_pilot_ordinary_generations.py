#!/usr/bin/env python3
"""Synthetic pure grant controls, never live approval or native acceptance.

All signatures are deterministic in-memory test data. No owner, protected file,
signing entrypoint, service, database or network is used. The scope fixture here
tests the payload/result contract, not measured-scope provenance.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))
from serverware import custody_generation_grants as grants
from serverware import native_pilot_ordinary_generation_profile as profile
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_install as installer
from serverware import native_pilot_publication as publication
from serverware import native_pilot_service_authority as authority
from serverware import native_pilot_supervisor_ordinary_generations as composer
from serverware import native_pilot_supervisor_policy as policy
from test_native_pilot_ordinary_commissioning import fixture, plan, private, runtimes
from test_native_pilot_ordinary_keys import ROLES, canonical, encoded, labelled, sha

SCOPE_FIELDS = ("previousConfigurationBindingSha256", "successorConfigurationBindingSha256", "dispatchManifestSha256",
    "kernelDriverIdentitySha256", "retainedDescriptorSetSha256", "driverGenerationReceiptSha256", "assignmentId",
    "assignmentPayloadSha256", "assignmentRevision", "operationCoverageRootSha256", "fiveServiceProtocolSetSha256",
    "envelopeAuthorityKeyId", "envelopeAuthorityKeySpkiSha256", "trustedTimeCheckpointSha256",
    "trustedTimeRevocationGeneration", "trustedTimeRevocationRootSha256", "installationIssuedAtUnixNanos",
    "installationExpiresAtUnixNanos")


def policy_fragment():
    return {"apiVersion": "serverware.nativePilotOrdinaryGenerationPolicy/v1",
        "installationIssuedAtUnixNanos": 1000, "installationExpiresAtUnixNanos": 2000}


def scope_fixture():
    value = {name: labelled("generation-scope/" + name) for name in SCOPE_FIELDS}
    value.update(previousConfigurationBindingSha256=None, assignmentRevision=1,
        trustedTimeRevocationGeneration=1, installationIssuedAtUnixNanos=1000,
        installationExpiresAtUnixNanos=2000, fiveServiceProtocolSetSha256=labelled("protocol-set"))
    return value


def context():
    f = fixture()
    built = runtimes(f)
    files = plan(f, built)
    signed = {}
    business = (("listener", "journal"), ("listener", "state", "journal"),
        ("listener", "journal"), ("listener",), ("listener", "journal"))
    for index, role in enumerate(ROLES):
        names = business[index] + ("generation-journal", "generation-grant")
        if index in (0, 3):
            names += ("dispatch-journal", "dispatch-grant")
        prefix = {0: "spool-head", 1: "active-effect-cleanup", 3: "spool-current"}.get(index)
        if prefix:
            names += (prefix + "-journal", prefix + "-grant")
        cold = f["cold"][role]
        activation = [{"name": name, "fd": number + 6, "device": 8, "inode": 910000 + index * 100 + number,
            "mode": (stat.S_IFSOCK if name == "listener" else stat.S_IFREG) | 0o600,
            "uid": cold["uid"], "gid": cold["gid"]} for number, name in enumerate(names)]
        credentials = copy.deepcopy(f["fragment"]["services"][role]["credentials"])
        for kind, name in (("history", "authority-history"), ("inspection", "peer-inspection-policy")):
            item = next(item for item in files if item["role"] == role and item["kind"] == kind)
            credentials.append({"name": name, "original": {"path": item["path"], "sha256": sha(item["raw"])},
                "length": len(item["raw"]), "signing": None})
        payload = {"configurationSha256": sha(canonical(cold)), "authorityKeyId": cold["authority"]["keyId"],
            **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
            **{name: f["launch"][name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")},
            "issuedAtBoottimeNs": "1200", "runtimeConfig": {"path": installer.RUNTIME_PATHS[role], "sha256": sha(built[role])},
            "credentials": credentials, "activation": activation}
        signature = f["delivery_keys"][role].sign(b"serverware.policyCustodyGuestDelivery.signature/v1\0" + canonical(payload))
        signed[role] = canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1", "payload": payload,
            "signatureBase64url": encoded(signature)})
    f.update(runtimes=built, deliveries=signed)
    return f


def build(f, role, **changes):
    values = dict(launch_raw=canonical(f["launch"]), configuration_raw=canonical(f["cold"][role]),
        delivery_raw=f["deliveries"][role], runtime_raw=f["runtimes"][role], history_raw=f["histories"][role],
        scope=scope_fixture(), issued_boottime_ns=1300, expires_boottime_ns=int(f["launch"]["lifetimeDeadlineBoottimeNs"]))
    return profile.build(role, **(values | changes))


def root_pin(f, role):
    return {name: f["initial_policy"]["services"][role]["authorities"]["root"][name]
        for name in ("keyId", "keySpkiSha256")}


def result(role, payload, *, key=None):
    raw = canonical(payload)
    domain = b"serverware.custodyServiceGenerationGrant.signature/v1"
    message = b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain + len(raw).to_bytes(8, "big") + raw
    signature = (key or private(role + "/root")).sign(message)
    signed = canonical({"payload": payload, "signatureBase64url": encoded(signature)})
    return {"original": signed.decode("ascii"), "sha256": sha(signed),
        "pin": {"path": publication.DESTINATIONS["ordinary-generation-" + role], "sha256": sha(signed)}}


class OrdinaryGenerationControls(unittest.TestCase):
    def test_policy_is_closed_explicit_positive_i64_and_copied(self):
        original = policy_fragment()
        selected = profile.validate_policy(original)
        self.assertEqual(selected, original)
        selected["installationExpiresAtUnixNanos"] += 1
        self.assertNotEqual(selected, original)
        for field in ("installationIssuedAtUnixNanos", "installationExpiresAtUnixNanos"):
            for invalid in (0, -1, True, "1000", 1 << 63):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    profile.validate_policy(original | {field: invalid})
        for field in ("driverGenerationReceiptSha256", "scope", "issuedAtBoottimeNanos"):
            with self.assertRaises(ValueError):
                profile.validate_policy(original | {field: labelled("unapproved")})
        with self.assertRaises(ValueError):
            profile.validate_policy(original | {"installationExpiresAtUnixNanos": 1000})

    def test_all_five_inputs_keep_exact_originals_and_root_signed_results(self):
        f = context()
        for role in ROLES:
            raw = build(f, role)
            value = json.loads(raw)
            payload = json.loads(value["payloadOriginal"])
            signed = result(role, payload)
            with self.subTest(role=role):
                self.assertEqual(set(value), {"apiVersion", "operation", "serviceRole", "launchOriginal", "payloadOriginal", "services"})
                self.assertEqual(set(value["services"]), {role})
                self.assertEqual(value["services"][role]["historyOriginal"].encode("ascii"), f["histories"][role])
                self.assertEqual(payload["guest"]["deliverySha256"], sha(f["deliveries"][role]))
                self.assertEqual(payload["runtimeConfigurationSha256"], sha(f["runtimes"][role]))
                self.assertEqual(payload["scope"], scope_fixture())
                self.assertEqual(composer.checked_result(role, raw, signed, root_pin=root_pin(f, role)),
                    signed["original"].encode("ascii"))
                wrapper = initial.runtime_manifest(f["histories"][role], runtime=json.loads(f["runtimes"][role])["runtime"],
                    guest=payload["guest"])
                self.assertEqual(wrapper["rootAuthority"]["keyId"], root_pin(f, role)["keyId"])

    def test_result_refuses_wrong_publication_root_and_signing_key(self):
        f = context(); role = ROLES[0]; raw = build(f, role)
        payload = json.loads(json.loads(raw)["payloadOriginal"])
        signed = result(role, payload)
        wrong = copy.deepcopy(signed); wrong["pin"]["path"] += ".wrong"
        with self.assertRaises(ValueError):
            profile.checked_result(role, raw, wrong, root_pin=root_pin(f, role))
        with self.assertRaises(ValueError):
            profile.checked_result(role, raw, signed, root_pin=root_pin(f, ROLES[1]))
        with self.assertRaises(InvalidSignature):
            profile.checked_result(role, raw, result(role, payload, key=private("other-root")), root_pin=root_pin(f, role))

    def test_valid_resigned_changed_scope_does_not_match_approved_payload(self):
        f = context(); role = ROLES[1]; raw = build(f, role)
        payload = json.loads(json.loads(raw)["payloadOriginal"])
        payload["scope"]["installationExpiresAtUnixNanos"] += 1
        with self.assertRaises(ValueError):
            profile.checked_result(role, raw, result(role, payload), root_pin=root_pin(f, role))

    def test_original_boottime_window_cannot_be_extended_or_backdated(self):
        f = context(); role = ROLES[2]
        for change in ({"issued_boottime_ns": 1199}, {"expires_boottime_ns": 1300},
                {"expires_boottime_ns": int(f["launch"]["lifetimeDeadlineBoottimeNs"]) + 1},
                {"issued_boottime_ns": int(f["launch"]["startupDeadlineBoottimeNs"])}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                build(f, role, **change)

    def test_generation_profile_refuses_history_and_scope_substitution(self):
        f = context(); role = ROLES[3]
        history = json.loads(f["histories"][role]); history["history"]["manifestSha256"] = labelled("replaced")
        with self.assertRaises(ValueError):
            build(f, role, history_raw=canonical(history))
        for changed in (scope_fixture() | {"previousConfigurationBindingSha256": labelled("historical")},
                scope_fixture() | {"futureObservation": {}},
                scope_fixture() | {"fiveServiceProtocolSetSha256": labelled("other-protocol")}):
            with self.assertRaises(ValueError):
                build(f, role, scope=changed)

    def test_v6_keeps_literal_policy_and_old_integer_boundary(self):
        f = fixture()
        value = {"apiVersion": policy.GENERATION_POLICY_API, "ordinaryInitialHistories": f["initial_policy"],
            "ordinaryGenerationsOriginal": canonical(policy_fragment()).decode("ascii")}
        self.assertEqual(policy._policy_document(canonical(value)), value)
        self.assertEqual(len(policy.GENERATION_FIELDS), 14)
        self.assertNotIn("ordinaryGenerationsOriginal", policy.DELIVERY_FIELDS)
        with self.assertRaises(ValueError):
            policy._policy_document(canonical(value | {"unrelatedInteger": (1 << 64) - 1}))


if __name__ == "__main__":
    unittest.main(verbosity=2)

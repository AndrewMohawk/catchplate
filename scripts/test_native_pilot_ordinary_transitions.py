#!/usr/bin/env python3
"""Eight bounded pure transition controls; fixtures are NOT pilot evidence.

Existing deterministic in-memory C9/history/generation signatures authenticate
the ordinary fixture. Native rows in the head projection test are explicitly
unsigned projection inputs, not accepted grants. These controls do not claim a
complete eleven-native/five-transition transcript, live owner, signing entrypoint,
protected file, service start, receipt or resource observation.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from catchplate import native_pilot_ordinary_transition_profile as profile
from catchplate import native_pilot_service_authority as authority
from catchplate import native_pilot_native_service_profile as native
from test_native_pilot_ordinary_generations import context, build as generation_input, result as generation_result
from test_native_pilot_ordinary_commissioning import private
from test_native_pilot_ordinary_initial import refresh_hashes
from test_native_pilot_ordinary_keys import ROLES, canonical, encoded, labelled, sha

DRS, CLEANUP, _, CURRENT, _ = ROLES
EXPECTED_JOBS = (("dispatch", DRS), ("dispatch", CURRENT), ("head", DRS), ("cleanup", CLEANUP), ("current", CURRENT))
REFERENCE_FIELDS = ("apiVersion", "authorityRole", "authorityEpochSequence", "authorityEpochSha256",
    "checkpointSequence", "checkpointSha256", "checkpointAuthorityKeyId", "checkpointAuthorityKeySpkiSha256",
    "serviceSigningKeyId", "serviceSigningKeySpkiSha256", "endpointProcessIdentitySha256", "endpointGeneration",
    "serviceGeneration", "operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")


def fragment():
    return {"apiVersion": "catchplate.nativePilotOrdinaryTransitionPolicy/v1",
        "dispatch": {role: {"initialHeadSha256": labelled("authorized-start/dispatch/" + role)} for role in (DRS, CURRENT)},
        "spool": {role: {"initialTransitionHeadSha256": labelled("authorized-start/spool/" + role)} for role in (DRS, CLEANUP, CURRENT)},
        "regularAppendCapacity": 8}


def ordinary_fixture():
    f = context()
    boot = tuple(f["launch"][name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"))
    launch, startup, lifetime = authority._launch(canonical(f["launch"]), boot, 1400)
    items = {}
    for role in ROLES:
        value = json.loads(generation_input(f, role))
        signed = generation_result(role, json.loads(value["payloadOriginal"]))
        row = value["services"][role] | {"generationGrantOriginal": signed["original"]}
        items[role] = authority._service(row, role, launch, boot, startup, lifetime, 1400, granted=True)
    return f, items


def unsigned_projection_rows():
    # Only _head_payload projection consumes these; they never enter build or
    # any shared input/result admission path and are not authentic native grants.
    names = ("ingress", "ledger", "retrieval", "terminal", "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
    keys = {name: {"role": "SYNTHETIC-PROJECTION-ONLY/" + name, "keyId": labelled(name + "/id"),
        "keySpkiSha256": labelled(name + "/spki"), "publicKeyBase64url": encoded(bytes([index + 1]) * 32),
        "grantSha256": labelled(name + "/grant")} for index, name in enumerate(names)}
    payloads = {"ingress": {"scope": {"syntheticProjectionOnly": True},
        "originVerifier": {"syntheticProjectionOnly": True}, "proofScopeOriginal": "{\"syntheticProjectionOnly\":true}"}}
    return payloads, keys


class OrdinaryTransitionControls(unittest.TestCase):
    def test_closed_explicit_policy_and_fixed_five_routes(self):
        self.assertEqual(profile.JOBS, EXPECTED_JOBS)
        value = fragment()
        checked = profile.validate_policy(value)
        self.assertEqual(checked, value)
        checked["dispatch"][DRS]["initialHeadSha256"] = labelled("different")
        self.assertNotEqual(checked, value)
        for changed in (value | {"apiVersion": "catchplate.nativePilotOrdinaryTransitionPolicy/v2"},
                value | {"futureReceipt": {}}, {name: item for name, item in value.items() if name != "spool"}):
            with self.assertRaises(ValueError):
                profile.validate_policy(changed)

    def test_anchors_and_capacity_are_not_defaulted_or_receipts(self):
        value = fragment()
        for section, role, field in (("dispatch", DRS, "initialHeadSha256"), ("spool", CLEANUP, "initialTransitionHeadSha256")):
            for invalid in (None, True, "sha256:" + "0" * 64, sha(b""), "bad"):
                changed = copy.deepcopy(value); changed[section][role][field] = invalid
                with self.subTest(section=section, invalid=invalid), self.assertRaises(ValueError):
                    profile.validate_policy(changed)
            for rows in ({}, value[section] | {ROLES[2]: {field: labelled("unexpected")}}):
                with self.assertRaises(ValueError):
                    profile.validate_policy(value | {section: rows})
            changed = copy.deepcopy(value); changed[section][role]["receiptOriginal"] = "{}"
            with self.assertRaises(ValueError):
                profile.validate_policy(changed)
        for capacity in (0, 33, True, "8", None):
            with self.assertRaises(ValueError):
                profile.validate_policy(value | {"regularAppendCapacity": capacity})
        for capacity in (1, 32):
            self.assertEqual(profile.validate_policy(value | {"regularAppendCapacity": capacity})["regularAppendCapacity"], capacity)

    def test_authenticated_epoch_projects_exact_native_seventeen_fields(self):
        f, items = ordinary_fixture()
        for role, item in items.items():
            epoch = json.loads(f["histories"][role])["history"]["firstRetainedEpoch"]["retainedEpoch"]
            expected = {"apiVersion": "catchplate.policyCustodyAuthorityHistory/v3", "authorityRole": epoch["authorityRole"],
                "authorityEpochSequence": epoch["authorityEpochSequence"], "authorityEpochSha256": epoch["epochSha256"],
                "checkpointSequence": epoch["checkpointSequence"], "checkpointSha256": epoch["checkpointSha256"],
                "checkpointAuthorityKeyId": epoch["checkpointAuthority"]["keyId"],
                "checkpointAuthorityKeySpkiSha256": epoch["checkpointAuthority"]["keySpkiSha256"],
                "serviceSigningKeyId": epoch["serviceSigningKey"]["keyId"],
                "serviceSigningKeySpkiSha256": epoch["serviceSigningKey"]["keySpkiSha256"],
                **{name: epoch[name] for name in ("endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration",
                    "operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")}}
            actual, public = profile.epoch_reference(item["history_raw"], runtime=item["header"], guest=item["guest"])
            with self.subTest(role=role):
                self.assertEqual(set(actual), set(REFERENCE_FIELDS))
                self.assertEqual(actual, expected)
                self.assertEqual(public, encoded(authority._public(private(role + "/service").public_key())))
                self.assertNotIn("predecessorEpochSha256", actual)
                self.assertNotIn("endpointProcessIdentity", actual)

    def test_epoch_projection_rejects_legacy_tampering_wrong_root_and_window(self):
        _, items = ordinary_fixture(); item = items[DRS]
        wrapper = json.loads(item["history_raw"])
        changed = copy.deepcopy(wrapper)
        changed["history"]["firstRetainedEpoch"]["rootSignatureBase64"] = encoded(bytes(64))
        refresh_hashes(changed["history"])
        for raw in (canonical(wrapper["history"]), canonical(changed)):
            with self.assertRaises((ValueError, InvalidSignature)):
                profile.epoch_reference(raw, runtime=item["header"], guest=item["guest"])
        with self.assertRaises((ValueError, InvalidSignature)):
            profile.epoch_reference(item["history_raw"], runtime=items[CLEANUP]["header"], guest=item["guest"])
        for name, replacement in (("serviceRole", CLEANUP), ("invocationId", "f" * 32),
                ("startupDeadlineBoottimeNs", "5001"), ("lifetimeDeadlineBoottimeNs", "9001")):
            with self.subTest(name=name), self.assertRaises(ValueError):
                profile.epoch_reference(item["history_raw"], runtime=item["header"], guest=item["guest"] | {name: replacement})

    def test_base_retains_guest_and_semantic_history_not_wrapper_hash(self):
        _, items = ordinary_fixture()
        for item in items.values():
            value = profile._base(item)
            wrapper = json.loads(item["history_raw"])
            self.assertEqual(set(value), {"guest", "runtimeConfigurationSha256", "authorityHistoryManifestSha256"})
            self.assertEqual(value["guest"], item["guest"])
            self.assertEqual(value["runtimeConfigurationSha256"], sha(item["runtime_raw"]))
            self.assertEqual(value["authorityHistoryManifestSha256"], wrapper["history"]["manifestSha256"])
            self.assertNotEqual(value["authorityHistoryManifestSha256"], sha(item["history_raw"]))

    def test_head_projection_keeps_explicit_anchors_and_authenticated_cleanup_epoch(self):
        _, items = ordinary_fixture(); selected = fragment(); payloads, keys = unsigned_projection_rows()
        before = copy.deepcopy((selected, payloads, keys))
        value = profile._head_payload(selected, items, payloads, keys)
        epoch, public = profile.epoch_reference(items[CLEANUP]["history_raw"], runtime=items[CLEANUP]["header"], guest=items[CLEANUP]["guest"])
        self.assertEqual(set(value), set(authority.HEAD_FIELDS))
        self.assertEqual(value["apiVersion"], "catchplate.nativeSpoolHeadGrant/v3")
        self.assertEqual(value["scope"], payloads["ingress"]["scope"])
        self.assertEqual(value["completion"], {"terminal": keys["terminal"], "regularAppendCapacity": 8})
        self.assertEqual(value["effects"]["cleanupAuthorityEpoch"], epoch)
        self.assertEqual(value["effects"]["cleanupPublicKeyBase64url"], public)
        self.assertEqual(value["effects"]["cleanupInitialTransitionHeadSha256"], selected["spool"][CLEANUP]["initialTransitionHeadSha256"])
        self.assertEqual(value["initialTransitionHeadSha256"], selected["spool"][DRS]["initialTransitionHeadSha256"])
        self.assertEqual((selected, payloads, keys), before)

    def test_exact_signature_frames_remain_distinct_existing_domains(self):
        raw = canonical({"syntheticFramingOnly": True, "counter": (1 << 64) - 1})
        domains = {"head": b"catchplate.nativeSpoolHeadGrant.signature/v3",
            "cleanup": b"catchplate.nativeActiveEffectCleanupGrant.signature/v1",
            "current": b"catchplate.nativeSpoolCurrentGrant.signature/v3"}
        key = private("pure-transition-framing")
        for operation, domain in domains.items():
            expected = b"catchplate-signature-v1\0" + len(domain).to_bytes(8, "big") + domain + len(raw).to_bytes(8, "big") + raw
            self.assertEqual(authority._message(operation, raw), expected)
            signature = key.sign(expected)
            key.public_key().verify(signature, authority._message(operation, raw))
            other = next(name for name in domains if name != operation)
            with self.assertRaises(InvalidSignature):
                key.public_key().verify(signature, authority._message(other, raw))

    def test_build_refuses_incomplete_context_and_wrong_prior_map_before_any_authority(self):
        clocks = {"boot": ("synthetic", 1, 2), "now_boottime_ns": 1400, "now_unix_ns": 1500}
        for operation, role in EXPECTED_JOBS:
            prior = {name: b"{}" for name in (("head", "cleanup") if operation == "current" else ("head",) if operation == "cleanup" else ())}
            for context_value in ({}, {name: {"inputOriginal": b"{}", "grantOriginal": bytearray(b"{}")}
                    for name in native.OPERATIONS}):
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    profile.build(operation, role, fragment=fragment(), ordinary_context={}, native_context=context_value,
                        prior_transition_originals=prior, **clocks)
            with self.assertRaises(ValueError):
                profile.build(operation, role, fragment=fragment(), ordinary_context={}, native_context={},
                    prior_transition_originals=prior | {"unapproved": b"{}"}, **clocks)


if __name__ == "__main__":
    unittest.main(verbosity=2)

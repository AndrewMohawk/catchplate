#!/usr/bin/env python3
"""Nine pure SYNTHETIC current-head controls, never currentness evidence.

All request entropy, consume cursors, observations, timestamps, approvals and
keys below are deterministic test-only values. Signatures are independently
framed in memory; no production signer entrypoint, request owner, protected FD,
service, network or currentness decision acquisition is exercised.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from catchplate import native_pilot_current_head_profile as profile
from test_native_pilot_generation_scope import fixture as scope_fixture, key_fixture
from test_native_pilot_ordinary_initial import (fixture as initial_fixture, checkpoint,
    sign_anchor, signature_preimage, DOMAINS)
from test_native_pilot_ordinary_keys import canonical, encoded, framed, labelled, sha

HEAD_DOMAIN = b"catchplate.policyCustodyTrustedHostCurrentHeadAttestation/v3"
REQUEST_DOMAIN = b"catchplate.policyCustodyEndpointRequest/v3"
HANDSHAKE_DOMAIN = b"catchplate.policyCustodyTrustedHostServiceHandshakeRequest/v3"
WINDOW_DOMAIN = b"catchplate.nativeShadowDriverBootstrapWindow.signature/v1\0"


@lru_cache(maxsize=1)
def configuration_raw():
    # Reuse the complete existing static image/transport grammar fixture.
    return scope_fixture()[1]["bootstrap_configuration_original"]


def refresh_request(value):
    value["requestNonceSha256"] = sha(canonical([value[name] for name in (
        "apiVersion", "endpointRole", "requestEntropyBase64", "requestedAtBoottimeNanos", "deadline", "operation")]))


def refresh_decision(value):
    """TEST ONLY: manufacture a labelled decision, never used by production."""
    request = json.loads(value["requestOriginal"])
    value["currentness"].update(requestSha256=framed(REQUEST_DOMAIN, (value["requestOriginal"].encode("ascii"),)),
        requestNonceSha256=request["requestNonceSha256"])


def fixture():
    f = initial_fixture()
    configuration = json.loads(configuration_raw())
    # Keep the synthetic original startup deadline; allow its fixed cleanup reserve.
    for item in (f["window"], f["launch"], f["preparation"], f["state"]):
        item["lifetimeDeadlineBoottimeNs"] = "9000000"
    f["preparation"]["configurationSha256"] = sha(canonical(f["launch"]))
    f["resources"]["preparationSha256"] = sha(canonical(f["preparation"]))
    f["state"].update(preparationSha256=sha(canonical(f["preparation"])),
        resourcesSha256=sha(canonical(f["resources"])), launchSha256=sha(canonical(f["launch"])))
    commitments = {name: framed(domain, (canonical(f["state"]),)) for name, domain in DOMAINS.items()}
    wrapper = f["wrapper"]
    payload = wrapper["initialCheckpoint"]["payload"]
    payload["predecessorCheckpointSha256"] = commitments["predecessorCheckpointSha256"]
    wrapper["initialCheckpoint"] = checkpoint(payload, f["public"]["checkpoint"], f["keys"]["checkpoint"])
    anchor = wrapper["history"]["firstRetainedEpoch"]
    anchor["retainedEpoch"].update(checkpointSha256=wrapper["initialCheckpoint"]["checkpointSha256"],
        durableEpochHeadSha256=commitments["durableEpochHeadSha256"])
    anchor["prunedHistoryRootSha256"] = commitments["prunedHistoryRootSha256"]
    sign_anchor(wrapper["history"], f["keys"])
    f["window"].update(configurationSha256=sha(configuration_raw()),
        signingKeyId=configuration["bootstrapAuthority"]["keyId"])
    signed_window = {"apiVersion": "catchplate.nativeShadowDriverBootstrapWindow/v1", "payload": f["window"],
        "signatureBase64url": encoded(key_fixture("window")[0].sign(WINDOW_DOMAIN + canonical(f["window"])))}
    request = {"apiVersion": "catchplate.policyCustodyProtocol/v3", "endpointRole": "settlement-store",
        "requestEntropyBase64": encoded(bytes(range(32))), "requestedAtBoottimeNanos": 1190,
        "deadline": {"domain": copy.deepcopy(payload["validFromBoottime"]["domain"]), "absoluteBoottimeNanos": 4000},
        "operation": {"operation": "current-endpoint-trust", "body": {"accepted_floor": {
            "checkpointSequence": 1, "checkpointSha256": wrapper["initialCheckpoint"]["checkpointSha256"],
            "consumeCursor": {"sequenceHighWater": 0, "expectedNextSequence": 1,
                "expectedPredecessorReceiptSha256": labelled("SYNTHETIC cursor anchor NOT a real receipt")}}}}}
    refresh_request(request)
    value = {"apiVersion": "catchplate.nativePilotCurrentHeadAuthorityInput/v1", "serviceRole": f["state"]["serviceRole"],
        "driverConfigurationOriginal": configuration_raw().decode("ascii"),
        "driverWindowOriginal": canonical(signed_window).decode("ascii"),
        "launchOriginal": canonical(f["launch"]).decode("ascii"),
        "configurationOriginal": canonical(f["cold"][f["state"]["serviceRole"]]).decode("ascii"),
        "preparationOriginal": canonical(f["preparation"]).decode("ascii"),
        "resourcesOriginal": canonical(f["resources"]).decode("ascii"),
        "initialHistoryOriginal": canonical(wrapper).decode("ascii"), "rootAuthority": f["root_pin"],
        "requestOriginal": canonical(request).decode("ascii"),
        "currentness": {"profile": "initial-checkpoint-current-for-exact-request-v1",
            "initialHistorySha256": sha(canonical(wrapper)), "checkpointSha256": wrapper["initialCheckpoint"]["checkpointSha256"],
            "requestSha256": framed(REQUEST_DOMAIN, (canonical(request),)), "requestNonceSha256": request["requestNonceSha256"],
            "issuedAtBoottimeNanos": 1200}}
    statement = {"apiVersion": "catchplate.policyCustodyProtocol/v3", "endpointRole": "settlement-store",
        "requestNonceSha256": request["requestNonceSha256"], "requestSha256": value["currentness"]["requestSha256"],
        "checkpointSequence": 1, "checkpointSha256": wrapper["initialCheckpoint"]["checkpointSha256"],
        "endpointGeneration": payload["exactEndpointGeneration"],
        "revocationGenerationHighWater": payload["revocationGenerationHighWater"],
        "revocationRootSha256": payload["revocationRootSha256"], "issuedAtBoottimeNanos": 1200,
        "deadline": copy.deepcopy(request["deadline"])}
    clocks = {"boot": tuple(f["window"][name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")),
        "now_boottime_ns": 1200}
    return f, value, statement, clocks


def signed_result(statement, public, signing_key):
    raw = canonical([statement, public["keyId"], public["keySpkiSha256"]])
    signature = encoded(signing_key.sign(signature_preimage(HEAD_DOMAIN, raw)))
    signed = {"statement": copy.deepcopy(statement), "authorityKeyId": public["keyId"],
        "authorityKeySpkiSha256": public["keySpkiSha256"], "authoritySignatureBase64": signature,
        "attestationSha256": framed(HEAD_DOMAIN, (raw, signature.encode("ascii")))}
    original = canonical(signed)
    return {"original": original.decode("ascii"), "sha256": sha(original)}


class CurrentHeadControls(unittest.TestCase):
    def test_real_synthetic_history_and_exact_current_head_signature(self):
        f, value, expected, clocks = fixture()
        raw = canonical(value)
        prepared = profile.prepare_input(raw, **clocks)
        self.assertEqual(set(prepared), {"statement", "authority", "window", "deadline"})
        self.assertEqual(prepared["statement"], expected)
        self.assertEqual(prepared["authority"], f["public"]["checkpoint"])
        self.assertEqual(prepared["deadline"], 4000)
        signed = signed_result(expected, f["public"]["checkpoint"], f["keys"]["checkpoint"])
        self.assertEqual(profile.checked_result(raw, signed, **clocks), signed["original"].encode("ascii"))
        preimage = signature_preimage(HEAD_DOMAIN, canonical([expected,
            f["public"]["checkpoint"]["keyId"], f["public"]["checkpoint"]["keySpkiSha256"]]))
        self.assertEqual(profile.signature_preimage(expected, f["public"]["checkpoint"]["keyId"],
            f["public"]["checkpoint"]["keySpkiSha256"]), preimage)

    def test_request_and_handshake_are_distinct_non_circular_transcripts(self):
        f, value, statement, _ = fixture()
        request_raw = value["requestOriginal"].encode("ascii")
        self.assertEqual(profile.request_sha256(request_raw), framed(REQUEST_DOMAIN, (request_raw,)))
        signed = json.loads(signed_result(statement, f["public"]["checkpoint"], f["keys"]["checkpoint"])["original"])
        binding = {"signedCurrentHead": signed, "exactAttestationSha256": sha(canonical(signed))}
        self.assertEqual(profile.binding(signed), binding)
        self.assertNotEqual(binding["exactAttestationSha256"], signed["attestationSha256"])
        handshake = ["catchplate.policyCustodyTrustedHostService/v4", value["serviceRole"],
            labelled("SYNTHETIC handshake ID"), labelled("SYNTHETIC handshake nonce"),
            labelled("SYNTHETIC client process"), labelled("SYNTHETIC client generation"),
            statement["deadline"], binding, 0, 0]
        self.assertNotEqual(statement["requestSha256"], framed(HANDSHAKE_DOMAIN, (canonical(handshake),)))

    def test_history_alone_or_changed_independent_decision_is_refused(self):
        _, value, _, clocks = fixture()
        for field in profile.CURRENTNESS_FIELDS:
            changed = copy.deepcopy(value)
            changed["currentness"][field] = (True if field == "issuedAtBoottimeNanos" else
                "automatic-history-current" if field == "profile" else labelled("wrong-decision/" + field))
            with self.subTest(field=field), self.assertRaises(ValueError):
                profile.prepare_input(canonical(changed), **clocks)
        for absent in (None, {}):
            changed = copy.deepcopy(value); changed["currentness"] = absent
            with self.assertRaises(ValueError):
                profile.prepare_input(canonical(changed), **clocks)
        changed = copy.deepcopy(value); del changed["currentness"]
        with self.assertRaises(ValueError):
            profile.prepare_input(canonical(changed), **clocks)

    def test_request_closed_grammar_nonce_and_cursor(self):
        _, value, _, _ = fixture()
        request = json.loads(value["requestOriginal"])
        for mutation in ("nonce", "entropy", "cursor", "role", "bool", "extra", "historical"):
            changed = copy.deepcopy(request)
            if mutation == "nonce": changed["requestNonceSha256"] = labelled("changed nonce")
            elif mutation == "entropy": changed["requestEntropyBase64"] = encoded(bytes(31))
            elif mutation == "cursor": changed["operation"]["body"]["accepted_floor"]["consumeCursor"]["expectedNextSequence"] = 2
            elif mutation == "role": changed["endpointRole"] = "durable-recovery-store"
            elif mutation == "bool": changed["requestedAtBoottimeNanos"] = True
            elif mutation == "extra": changed["liveOwner"] = True
            else: changed["operation"]["operation"] = "verify-historical-durable-consume"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profile.request(canonical(changed))
        raw = canonical(request)
        for changed in (raw + b"\n", raw[:-1] + b',"apiVersion":"duplicate"}', b" " + raw):
            with self.assertRaises(ValueError): profile.request(changed)

    def test_actual_clock_domain_and_original_deadline_cannot_be_extended(self):
        _, value, _, clocks = fixture()
        for changed_clocks in ({**clocks, "now_boottime_ns": 1199}, {**clocks, "now_boottime_ns": 4000},
                {**clocks, "boot": (clocks["boot"][0], 11, 13)}):
            with self.assertRaises(ValueError): profile.prepare_input(canonical(value), **changed_clocks)
        for bound in (1100, 5001):
            changed = copy.deepcopy(value); request = json.loads(changed["requestOriginal"])
            request["deadline"]["absoluteBoottimeNanos"] = bound
            refresh_request(request); changed["requestOriginal"] = canonical(request).decode("ascii"); refresh_decision(changed)
            with self.assertRaises(ValueError): profile.prepare_input(canonical(changed), **clocks)

    def test_bootstrap_history_and_retained_ceremony_originals_are_required(self):
        _, value, _, clocks = fixture()
        for field in ("driverWindowOriginal", "initialHistoryOriginal", "resourcesOriginal", "preparationOriginal"):
            changed = copy.deepcopy(value); original = json.loads(changed[field])
            if field == "driverWindowOriginal": original["signatureBase64url"] = encoded(bytes(64))
            elif field == "initialHistoryOriginal": original["initialCheckpoint"]["authoritySignatureBase64"] = encoded(bytes(64))
            elif field == "resourcesOriginal": original["issuedAtBoottimeNs"] = "1151"
            else: original["services"][value["serviceRole"]]["startTimeTicks"] += 1
            changed[field] = canonical(original).decode("ascii")
            with self.subTest(field=field), self.assertRaises((ValueError, InvalidSignature)):
                profile.prepare_input(canonical(changed), **clocks)
        changed = copy.deepcopy(value); changed["rootAuthority"]["keyId"] = labelled("unapproved root")
        with self.assertRaises(ValueError): profile.prepare_input(canonical(changed), **clocks)

    def test_result_requires_checkpoint_key_exact_payload_and_canonical_bytes(self):
        f, value, statement, clocks = fixture(); raw = canonical(value)
        wrong_key = signed_result(statement, f["public"]["checkpoint"], f["keys"]["service"])
        changed_statement = copy.deepcopy(statement); changed_statement["requestSha256"] = labelled("other request")
        wrong_payload = signed_result(changed_statement, f["public"]["checkpoint"], f["keys"]["checkpoint"])
        valid = signed_result(statement, f["public"]["checkpoint"], f["keys"]["checkpoint"])
        extra = {**valid, "approved": True}
        for result in (wrong_key, wrong_payload, {**valid, "sha256": labelled("wrong original")}, extra,
                {**valid, "original": valid["original"] + "\n"}):
            with self.assertRaises((ValueError, InvalidSignature)):
                profile.checked_result(raw, result, **clocks)

    def test_changed_checkpoint_floor_or_role_cannot_be_reapproved_as_same_ceremony(self):
        _, value, _, clocks = fixture()
        for mutation in ("floor", "role", "domain"):
            changed = copy.deepcopy(value); request = json.loads(changed["requestOriginal"])
            if mutation == "floor": request["operation"]["body"]["accepted_floor"]["checkpointSha256"] = labelled("another checkpoint")
            elif mutation == "role": request["endpointRole"] = "cleanup-watchdog"
            else: request["deadline"]["domain"]["timeNamespaceInode"] += 1
            refresh_request(request); changed["requestOriginal"] = canonical(request).decode("ascii"); refresh_decision(changed)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profile.prepare_input(canonical(changed), **clocks)

    def test_native_enum_field_spelling_and_u64_shape_vs_signed_canonical_limit(self):
        f, value, statement, _ = fixture()
        request = json.loads(value["requestOriginal"])
        body = request["operation"]["body"]
        body["acceptedFloor"] = body.pop("accepted_floor")
        refresh_request(request)
        with self.assertRaises(ValueError): profile.request(canonical(request))
        public = f["public"]["checkpoint"]
        maximum_signed = {**statement, "checkpointSequence": (1 << 63) - 1}
        self.assertEqual(profile.signature_preimage(maximum_signed, public["keyId"], public["keySpkiSha256"]),
            signature_preimage(HEAD_DOMAIN, canonical([maximum_signed, public["keyId"], public["keySpkiSha256"]])))
        for name in ("checkpointSequence", "endpointGeneration", "revocationGenerationHighWater", "issuedAtBoottimeNanos"):
            large = copy.deepcopy(statement)
            large[name] = (1 << 64) - (2 if name == "issuedAtBoottimeNanos" else 1)
            large["deadline"]["absoluteBoottimeNanos"] = (1 << 64) - 1
            self.assertEqual(profile.validate_statement(large), large)
            with self.subTest(field=name), self.assertRaises(ValueError):
                profile.signature_preimage(large, public["keyId"], public["keySpkiSha256"])
            for bad in (True, -1, 1 << 64):
                with self.subTest(field=name, value=bad), self.assertRaises(ValueError):
                    profile.validate_statement({**statement, name: bad})


if __name__ == "__main__":
    unittest.main()

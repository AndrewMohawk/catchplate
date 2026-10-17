#!/usr/bin/env python3
"""Synthetic signed-head/native-framing controls, not live handshake evidence."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_native_pilot_current_head import fixture, signed_result, canonical, labelled
from catchplate import native_pilot_service_handshakes as profile
from catchplate import native_pilot_helper_bootstrap_profile as helper

p = profile.p


def prepared():
    f, value, statement, clocks = fixture()
    result = signed_result(statement, f["public"]["checkpoint"], f["keys"]["checkpoint"])
    pins = dict(client_process_identity_sha256=labelled("SYNTHETIC client"),
        client_configuration_generation_sha256=labelled("SYNTHETIC client configuration"))
    return value, result, clocks, pins


def check(raw, value, pins):
    return profile.shape(raw, service_role=value["serviceRole"], endpoint_role="settlement-store", **pins)


class ServiceHandshakeControls(unittest.TestCase):
    def test_authenticate_then_exact_native_ten_field_hash_and_distinct_domains(self):
        value, result, clocks, pins = prepared()
        raw = profile.build(canonical(value), result, **clocks, **pins)
        request = check(raw, value, pins)
        fields = ("apiVersion", "serviceRole", "requestIdSha256", "handshakeNonceSha256",
            "clientProcessIdentitySha256", "clientConfigurationGenerationSha256", "deadline",
            "expectedCurrentHead", "requestRightsCount", "replyRightsCount")
        array = canonical([request[name] for name in fields])
        expected = "sha256:" + hashlib.sha256(b"catchplate.policyCustodyTrustedHostServiceHandshakeRequest/v3\0"
            + len(array).to_bytes(8, "big") + array).hexdigest()
        self.assertEqual(request["apiVersion"], "catchplate.policyCustodyTrustedHostService/v4")
        self.assertEqual(request["requestSha256"], expected)
        self.assertNotEqual(request["requestSha256"], value["currentness"]["requestSha256"])
        self.assertNotEqual(request["requestIdSha256"], request["handshakeNonceSha256"])
        self.assertEqual(raw, profile.build(canonical(value), result, **clocks, **pins))

    def test_wrong_signature_cannot_be_framed_as_authenticated_result(self):
        value, result, clocks, pins = prepared()
        signed = json.loads(result["original"])
        signed = profile.head.envelope(signed["statement"], signed["authorityKeyId"], signed["authorityKeySpkiSha256"], p.encoded(bytes(64)))
        raw = canonical(signed)
        with self.assertRaises((ValueError, InvalidSignature)):
            profile.build(canonical(value), dict(original=raw.decode(), sha256=p.sha(raw)), **clocks, **pins)

    def test_wrong_currentness_expired_request_or_result_hash_refused(self):
        value, result, clocks, pins = prepared()
        changed = copy.deepcopy(value); changed["currentness"]["requestSha256"] = labelled("wrong currentness")
        with self.assertRaises(ValueError): profile.build(canonical(changed), result, **clocks, **pins)
        with self.assertRaises(ValueError):
            profile.build(canonical(value), result, **dict(clocks, now_boottime_ns=4000), **pins)
        with self.assertRaises(ValueError):
            profile.build(canonical(value), dict(result, sha256=labelled("wrong result")), **clocks, **pins)

    def test_actual_native_operation_rights_for_all_five_roles(self):
        value, result, _, pins = prepared()
        expected = {"durable-recovery-store": (0, 0), "cleanup-authorization-consumer": (0, 0),
            "recovery-target-provider": (6, 2), "current-signature-authority": (0, 0), "bounded-cleanup-helper": (2, 0)}
        # Public framing only: this head is not claimed as authority for the
        # other four services. Actual build() requires their own approved input.
        for role, rights in expected.items():
            raw = profile.frame(service_role=role, trust_request_original=value["requestOriginal"].encode(),
                signed_current_head=json.loads(result["original"]), **pins)
            request = json.loads(raw)
            self.assertEqual((request["requestRightsCount"], request["replyRightsCount"]), rights)

    def test_wrong_rights_and_client_pins_refused_even_after_rehash(self):
        value, result, clocks, pins = prepared()
        request = json.loads(profile.build(canonical(value), result, **clocks, **pins))
        for name, replacement in (("requestRightsCount", 1), ("replyRightsCount", True),
                ("clientProcessIdentitySha256", labelled("other client")),
                ("clientConfigurationGenerationSha256", labelled("other configuration"))):
            changed = copy.deepcopy(request); changed[name] = replacement
            changed["requestSha256"] = p.framed(profile.DOMAIN,
                (canonical([changed[field] for field in profile.FIELDS[:-1]]),))
            with self.assertRaises(ValueError): check(canonical(changed), value, pins)

    def test_exact_head_checkpoint_and_earlier_request_binding_required(self):
        value, result, _, pins = prepared()
        for name in ("requestSha256", "requestNonceSha256", "checkpointSha256"):
            signed = json.loads(result["original"])
            signed["statement"][name] = labelled("other/" + name)
            changed = profile.head.envelope(signed["statement"], signed["authorityKeyId"],
                signed["authorityKeySpkiSha256"], signed["authoritySignatureBase64"])
            with self.assertRaises(ValueError):
                profile.frame(service_role=value["serviceRole"], trust_request_original=value["requestOriginal"].encode(),
                    signed_current_head=changed, **pins)

    def test_closed_wire_and_no_version_or_digest_substitution(self):
        value, result, clocks, pins = prepared()
        request = json.loads(profile.build(canonical(value), result, **clocks, **pins))
        for name, replacement in (("apiVersion", "catchplate.policyCustodyTrustedHostService/v3"),
                ("requestSha256", labelled("wrong frame")), ("requestIdSha256", "sha256:" + "0" * 64),
                ("extraApproval", True)):
            changed = copy.deepcopy(request); changed[name] = replacement
            with self.assertRaises(ValueError): check(canonical(changed), value, pins)

    def test_initial_helper_manifest_closed_native_array_framing(self):
        from test_native_pilot_bridge_runtime import helper_fixture
        value = helper_fixture()
        self.assertEqual(helper.shape(canonical(value)), value)
        for name, replacement in (("initialization", "recovered-effects"), ("manifestSha256", labelled("wrong manifest")),
                ("operationGeneration", 0), ("journalHead", labelled("invented prior journal"))):
            changed = copy.deepcopy(value); changed[name] = replacement
            with self.assertRaises(ValueError): helper.shape(canonical(changed))
        del value["initialEndpointHistorySha256"]["cgroup-executor"]
        with self.assertRaises(ValueError): helper.shape(canonical(value))


if __name__ == "__main__":
    unittest.main()

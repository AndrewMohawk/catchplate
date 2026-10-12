#!/usr/bin/env python3
"""Capture real Python helper bytes for private Rust validator component tests.

--emit-fixture runs all checks, writes unittest results to stderr and emits one
bounded canonical JSON fixture to stdout only on success. Every value is a
public synthetic fixture, including private-channel canaries and the test KEK.
The two children use real FD3/RSA-CMS/service-token/JIT crypto without replacing
production clocks or functions. Saved clock samples are historical observations
for a pure Rust validator, NEVER current Owner/Prepared or custody admission.
No KMS, native quote, authenticated configuration, SQL or approval is exercised.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import test_native_jit_broker_channel as channel
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA = "serverware.nativeJitRustContractFixture/v1"
BOUNDARY = "synthetic-local-process-no-native-admission"
MAX_FIXTURE_BYTES = 128 * 1024
CASE_FIELDS = {"name", "configurationOriginal", "commandOriginal", "responseOriginal",
    "validationNowEpochNs", "validationBoottimeNs", "brokerDeadlineBoottimeNs"}
C, H = channel.canonical, channel.sha


def numeric_peer(test):
    peer = channel.Peer(test)
    values = channel.ingress.source_values()
    # In particular, Python's 1e-05 spelling and integers beyond u64 must not
    # be silently rewritten/lossily parsed by the receiving Rust adapter.
    values["canonical_request"]["numbers"] = [1.25, 1e-5, 1e20, 2**64 + 17]
    values["redacted_display"]["numbers"] = [-0.5, 1e-5, 1e20, -(2**64 + 17)]
    operation, peer.envelope = channel.ingress.original.dispatch_input(values)
    test.assertEqual(operation, "jit.request")
    public, explicit, peer.documents = channel.ingress.extracted(peer.envelope)
    test.assertIsNone(explicit)
    peer.request = channel.ingress.typed_request(public)
    test.assertEqual(public["policy_hash"], peer.config["identity"]["policyHash"])
    return peer


def capture_fixture(test):
    channel.NativeJitBrokerChannelTests.setUpClass()  # Wrong UID/PID fails, never skips.
    cases = []
    for name in ("ordinary", "clipped"):
        with numeric_peer(test) as peer:
            peer.ready()
            command = peer.command()
            if name == "clipped":
                issued = command["issuedAtEpochNs"]
                command["sealExpiresAtEpochNs"] = issued + 20 * channel.SECOND
                command["documentExpiresAtEpochNs"] = issued + 120 * channel.SECOND
            peer.send(command)
            response = peer.receive()
            wall = time.time_ns()
            boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            # Peer.receive already checked actual raw == canonical(response).
            # These strings therefore preserve the actual wire, including its
            # numeric spellings, without adding a transport/parser replacement.
            cases.append({"name": name, "configurationOriginal": C(peer.config).decode("ascii"),
                "commandOriginal": C(command).decode("ascii"), "responseOriginal": C(response).decode("ascii"),
                "validationNowEpochNs": wall, "validationBoottimeNs": boot,
                "brokerDeadlineBoottimeNs": peer.deadline})
    value = {"schema": SCHEMA, "boundary": BOUNDARY, "cases": cases}
    test.assertLessEqual(len(C(value)), MAX_FIXTURE_BYTES)
    return value


class NativeJitRustContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = capture_fixture(unittest.TestCase())

    def originals(self):
        for case in self.fixture["cases"]:
            yield case, *(json.loads(case[name]) for name in
                ("configurationOriginal", "commandOriginal", "responseOriginal"))

    def test_actual_command_response_originals_and_independent_statement_joins(self):
        self.assertEqual(set(self.fixture), {"schema", "boundary", "cases"})
        self.assertEqual((self.fixture["schema"], self.fixture["boundary"]), (SCHEMA, BOUNDARY))
        self.assertEqual([case["name"] for case in self.fixture["cases"]], ["ordinary", "clipped"])
        for case, config, command, response in self.originals():
            with self.subTest(case=case["name"]):
                self.assertEqual(set(case), CASE_FIELDS)
                for name, parsed in (("configurationOriginal", config), ("commandOriginal", command), ("responseOriginal", response)):
                    self.assertTrue(C(parsed).decode("ascii") == case[name], "captured canonical original changed")
                public, explicit, _private = channel.ingress.extracted(command["runtimeInput"])
                self.assertIsNone(explicit)
                self.assertTrue(command["publicRequest"] == channel.ingress.typed_request(public),
                    "actual public extraction/request join changed")
                self.assertEqual(set(response), {"apiVersion", "phase", "operation", "pair", "statementBindings"})
                self.assertEqual((response["apiVersion"], response["phase"], response["operation"]),
                    (channel.CHANNEL, "prepared", "jit.request"))
                scope, request = response["pair"]["scope"], command["publicRequest"]
                self.assertTrue(scope["publicRequest"] == request, "pair changed the public request")
                self.assertEqual(scope["sourceContractDigest"], config["sourceContractDigest"])
                self.assertEqual(scope["controlPlaneConfigurationDigest"], config["controlPlaneConfigurationDigest"])
                self.assertEqual(scope["ownerScopeDigest"], H(C(config)))
                expected = {"sourceContractDigest": config["sourceContractDigest"],
                    "controlPlaneConfigurationDigest": config["controlPlaneConfigurationDigest"],
                    "ownerScopeDigest": H(C(config)), "deploymentId": config["deploymentId"],
                    "instanceId": config["instanceId"], "requestDigest": request["requestDigest"],
                    "operationId": request["operationId"], "publicRequestSha256": H(C(request)),
                    "pairSha256": H(C(response["pair"])), "secretKekId": config["secretKekId"],
                    "challenge": command["challenge"], "issuedAtEpochNs": command["issuedAtEpochNs"],
                    "expiresAtEpochNs": scope["sealExpiresAtEpochNs"],
                    "documentExpiresAtEpochNs": scope["documentExpiresAtEpochNs"], **config["identity"]}
                self.assertTrue(response["statementBindings"] == expected, "prepared bindings differ")
                for canary in channel.ingress.CANARIES:
                    self.assertTrue(canary not in case["responseOriginal"], "private canary escaped ciphertext")

    def test_actual_aead_readback_wrapper_hashes_and_exact_number_spellings(self):
        for case, config, command, response in self.originals():
            with self.subTest(case=case["name"]):
                documents = command["runtimeInput"]["privateDocuments"]
                scope = response["pair"]["scope"]
                opened = channel.material.open_pair(response["pair"], expected_scope=scope,
                    key_id=config["secretKekId"], kek=AESGCM(channel.KEY), now_epoch_ns=case["validationNowEpochNs"])
                self.assertTrue(opened == documents, "actual AESGCM did not preserve original private documents")
                self.assertEqual(opened["canonical_request"]["numbers"], [1.25, 1e-5, 1e20, 2**64 + 17])
                self.assertEqual(opened["redacted_display"]["numbers"], [-0.5, 1e-5, 1e20, -(2**64 + 17)])
                for spelling in ("1e-05", "1e+20", "18446744073709551633", "-18446744073709551633"):
                    self.assertTrue(spelling in case["commandOriginal"], "canonical private number spelling changed")
                wrapper = {"schema": "serverware.jitCanonicalReviewPayload/v1",
                    "url": documents["url"], "canonical_request": documents["canonical_request"]}
                self.assertEqual(len(response["pair"]["items"]), 2)
                for item, plaintext in zip(response["pair"]["items"], (C(wrapper), C(documents["redacted_display"]))):
                    self.assertEqual(item["plaintextSha256"], H(plaintext))
                    self.assertEqual(item["plaintextBytes"], len(plaintext))
                    for name in ("wrappedKeyNonce", "wrappedKey", "ciphertextNonce", "ciphertext"):
                        raw = base64.b64decode(item[name], altchars=b"-_", validate=True)
                        self.assertTrue(base64.urlsafe_b64encode(raw).decode("ascii") == item[name],
                            "pair requires canonical padded base64url")
                self.assertNotEqual(response["pair"]["items"][0]["plaintextSha256"],
                    command["runtimeInput"]["arguments"]["canonical_request_digest"])
                self.assertNotIn("=", command["challenge"])  # Separate channel unpadded format.

    def test_observed_original_deadlines_and_real_owner_clipping_not_current_admission(self):
        for case, _config, command, response in self.originals():
            with self.subTest(case=case["name"]):
                scope = response["pair"]["scope"]
                for name in ("validationNowEpochNs", "validationBoottimeNs", "brokerDeadlineBoottimeNs"):
                    self.assertIs(type(case[name]), int)
                    self.assertGreater(case[name], 0)
                self.assertEqual(scope["issuedAtEpochNs"], command["issuedAtEpochNs"])
                self.assertLessEqual(scope["issuedAtEpochNs"], case["validationNowEpochNs"])
                self.assertLess(case["validationNowEpochNs"], scope["sealExpiresAtEpochNs"])
                self.assertLessEqual(scope["sealExpiresAtEpochNs"], scope["documentExpiresAtEpochNs"])
                self.assertLess(case["validationBoottimeNs"], case["brokerDeadlineBoottimeNs"])
                self.assertEqual(command["deadlineBoottimeNs"], case["brokerDeadlineBoottimeNs"])
                self.assertLessEqual(scope["sealExpiresAtEpochNs"], command["sealExpiresAtEpochNs"])
                self.assertLessEqual(scope["documentExpiresAtEpochNs"], command["documentExpiresAtEpochNs"])
                if case["name"] == "clipped":
                    self.assertLess(scope["sealExpiresAtEpochNs"], command["sealExpiresAtEpochNs"])
                    self.assertLess(scope["documentExpiresAtEpochNs"], command["documentExpiresAtEpochNs"])


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--emit-fixture"]):
        raise SystemExit("usage: test_native_jit_rust_contract.py [--emit-fixture]")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeJitRustContractTests)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    if sys.argv[1:] == ["--emit-fixture"]:
        sys.stdout.buffer.write(C(NativeJitRustContractTests.fixture) + b"\n")

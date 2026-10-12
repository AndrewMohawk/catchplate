#!/usr/bin/env python3
"""Real JIT sealing state machine/crypto with synthetic owner dependencies.

The broker, channel, public fixture KEK and clocks below are NOT native custody
or authenticated configuration. No dispatcher, quote, signature, approval,
database, review disclosure, provider or release admission is exercised.
"""
from __future__ import annotations

import base64
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_DATA = tempfile.TemporaryDirectory(prefix="jit-review-owner-component-")
os.environ["SERVERWARE_PROCESS_MODE"] = "serverware-control-plane"
os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
os.environ["SERVERWARE_DATA_DIR"] = _DATA.name


def no_external_io(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
    }:
        raise AssertionError("JIT owner component attempted external I/O")


sys.addaudithook(no_external_io)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import test_authority_jit_private_request as ingress
from serverware import authority_contract as contract
from serverware import authority_jit_private_request as private
from serverware import native_jit_review_material as material
from serverware import native_jit_review_owner as native


SECOND = 1_000_000_000
KEY = bytes(range(32))  # Public synthetic material, never an admitted native KEK.
IDENTITY_FIELDS = {"holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
    "caPublicKeySpkiSha256", "expectedBinaryDigest"}


def encoded(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class Clock:
    wall = 1_791_720_000 * SECOND
    boot = 100 * SECOND

    def wall_now(self):
        return self.wall

    def boot_now(self, kind):
        if kind != native.time.CLOCK_BOOTTIME:
            raise AssertionError("owner selected another clock")
        return self.boot


class Channel:
    """Synthetic endpoint only; neither peer credentials nor native admission."""
    def __init__(self, clock, lifetime):
        self.clock, self.deadline = clock, clock.boot + lifetime
        self.messages, self.deadlines = [], []
        self.prepared_failure = None
        self.after_prepared = None

    def check(self, deadline=None):
        if self.clock.boot >= min(self.deadline, deadline or self.deadline):
            raise ValueError("synthetic channel expired")

    def send(self, value, deadline=None):
        self.check(deadline)
        self.messages.append(copy.deepcopy(value))
        self.deadlines.append(deadline)
        if value.get("phase") == "prepared":
            if self.after_prepared is not None:
                self.after_prepared()
            if self.prepared_failure is not None:
                raise self.prepared_failure


class Broker:
    def __init__(self, channel):
        self.channel, self.kek = channel, AESGCM(KEY)
        self.commitment = ingress.original.sha(KEY)
        self.key_id = "attested-memory-kek:" + self.commitment[7:31]
        self.rsa, self.service_tokens_opened = None, True
        self.configuration_checks = 0
        self.allow_configuration = True

    def require_owner_configuration(self):
        self.configuration_checks += 1
        if not self.allow_configuration:
            raise ValueError("synthetic configuration refused")
        self.channel.check()


class Fixture:
    def __init__(self, *, lifetime=600 * SECOND, capacity=2):
        self.clock = Clock()
        self.channel = Channel(self.clock, lifetime)
        self.broker = Broker(self.channel)
        self.envelope = private.prepare(ingress.raw_arguments())
        self.request = ingress.typed_request(self.envelope["arguments"])
        identity = {name: ingress.original.sha(name.encode("ascii")) for name in IDENTITY_FIELDS}
        boot = b"b" * 32
        identity.update(bootId=encoded(boot), policyHash=self.envelope["arguments"]["policy_hash"])
        identity["holderId"] = ingress.original.sha(
            b"serverware/credential-currentness-holder/v1\0" + boot + bytes.fromhex(identity["keyId"][7:]))
        self.config = {"apiVersion": native.CONFIG,
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": ingress.original.sha(b"synthetic configuration"),
            "deploymentId": "synthetic-offline", "instanceId": "spiffe://synthetic.invalid/native",
            "secretKekId": self.broker.key_id, "identity": identity, "attemptCapacity": capacity}
        self.command = {"apiVersion": native.CHANNEL, "phase": "seal-pair",
            "runtimeInput": self.envelope, "publicRequest": self.request,
            "issuedAtEpochNs": self.clock.wall, "sealExpiresAtEpochNs": self.clock.wall + 20 * SECOND,
            "documentExpiresAtEpochNs": self.clock.wall + 120 * SECOND,
            "deadlineBoottimeNs": self.clock.boot + 25 * SECOND, "challenge": encoded(b"c" * 32)}

    def configure(self, value=None):
        # Only the clock observations are synthetic. Real owner checks, request
        # reconstruction, digest verification and encryption remain unchanged.
        with patch.object(native.time, "time_ns", self.clock.wall_now), \
                patch.object(native.time, "clock_gettime_ns", self.clock.boot_now):
            return native.Owner(self.broker, value if value is not None else {
                "apiVersion": native.CHANNEL, "phase": "configure", "configuration": self.config})


class NativeJitReviewOwnerTests(unittest.TestCase):
    def refused(self, owner, command, *, spent=False):
        before = len(owner._spent)
        with patch.object(material, "seal_pair", wraps=material.seal_pair) as sealing:
            with self.assertRaises(native.OwnerError) as error:
                owner.handle(command)
            sealing.assert_not_called()
        self.assertTrue(owner._poisoned)
        self.assertIsNone(error.exception.__cause__)
        self.assertEqual(str(error.exception), "native JIT review owner unavailable")
        self.assertEqual(len(owner._spent), before)
        if spent:
            self.assertGreater(before, 0)

    def test_cold_configuration_closed_and_actual_broker_prerequisites(self):
        changes = [lambda f: setattr(f.broker, "allow_configuration", False),
            lambda f: setattr(f.broker, "rsa", object()),
            lambda f: setattr(f.broker, "service_tokens_opened", False),
            lambda f: setattr(f.broker, "kek", object()),
            lambda f: f.config.update(extra=True),
            lambda f: f.config.update(sourceContractDigest=ingress.PIN),
            lambda f: f.config.update(secretKekId="attested-memory-kek:" + "0" * 24),
            lambda f: f.config.update(attemptCapacity=True),
            lambda f: f.config.update(attemptCapacity=17),
            lambda f: f.config["identity"].update(bootId=encoded(bytes(32))),
            lambda f: f.config["identity"].update(holderId=ingress.PIN)]
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                f = Fixture()
                change(f)
                with self.assertRaises(native.OwnerError):
                    f.configure()
                self.assertEqual(f.broker.configuration_checks, 1)
                self.assertEqual(f.channel.messages, [])

    def test_actual_private_reconstruction_public_digest_and_real_encrypted_pair(self):
        f = Fixture()
        original_config, original_command = copy.deepcopy(f.config), copy.deepcopy(f.command)
        owner = f.configure()
        self.assertEqual(f.channel.messages, [{"apiVersion": native.CHANNEL, "phase": "configured"}])
        self.assertEqual(owner.owner_scope_digest, ingress.original.sha(ingress.original.canonical(original_config)))
        f.config["deploymentId"] = "caller-mutated-after-construction"
        owner.handle(f.command)
        result = f.channel.messages[-1]
        self.assertEqual(set(result), {"apiVersion", "phase", "operation", "pair", "statementBindings"})
        self.assertEqual((result["apiVersion"], result["phase"], result["operation"]),
            (native.CHANNEL, "prepared", "jit.request"))
        scope = result["pair"]["scope"]
        self.assertEqual(scope, {"schema": "serverware.nativeJitReviewScope/v1", "publicRequest": f.request,
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": original_config["controlPlaneConfigurationDigest"],
            "ownerScopeDigest": owner.owner_scope_digest,
            **{name: f.command[name] for name in ("issuedAtEpochNs", "sealExpiresAtEpochNs", "documentExpiresAtEpochNs")}})
        self.assertEqual(material.open_pair(result["pair"], expected_scope=scope,
            key_id=f.broker.key_id, kek=f.broker.kek, now_epoch_ns=f.clock.wall), f.envelope["privateDocuments"])
        bindings = result["statementBindings"]
        expected = {"sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": original_config["controlPlaneConfigurationDigest"],
            "ownerScopeDigest": owner.owner_scope_digest, "deploymentId": original_config["deploymentId"],
            "instanceId": original_config["instanceId"], "requestDigest": f.request["requestDigest"],
            "operationId": f.request["operationId"],
            "publicRequestSha256": ingress.original.sha(ingress.original.canonical(f.request)),
            "pairSha256": ingress.original.sha(ingress.original.canonical(result["pair"])),
            "secretKekId": f.broker.key_id, "challenge": f.command["challenge"],
            "issuedAtEpochNs": f.clock.wall, "expiresAtEpochNs": f.command["sealExpiresAtEpochNs"],
            "documentExpiresAtEpochNs": f.command["documentExpiresAtEpochNs"], **original_config["identity"]}
        self.assertEqual(bindings, expected)
        wire = ingress.original.canonical(result)
        for canary in ingress.CANARIES:
            self.assertNotIn(canary.encode(), wire)
        self.assertEqual(f.command, original_command)
        self.assertEqual(owner._spent, {f.request["requestDigest"]})
        self.assertIsNone(owner.operation)

    def test_tampered_private_public_and_command_fields_refuse_before_sealing(self):
        def unrelated_public(f):
            public = copy.deepcopy(f.envelope["arguments"])
            public["route_id"] = "other-route"
            f.command["publicRequest"] = ingress.typed_request(public)
        changes = [lambda f: f.envelope["privateDocuments"].update(url="https://changed.invalid/"),
            lambda f: f.envelope["arguments"].update(original_arguments_digest=ingress.PIN),
            lambda f: f.request.update(requestDigest=ingress.PIN),
            lambda f: f.request.update(operationId=ingress.PIN), unrelated_public,
            lambda f: f.envelope.update(schema="serverware.policyAuthorityControlledWriterInput/v1"),
            lambda f: f.command.update(extra=True),
            lambda f: f.command.update(challenge=encoded(bytes(32))),
            lambda f: f.envelope["privateDocuments"].update(redacted_display=("tuple",)),
            lambda f: f.command.pop("runtimeInput")]
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                f = Fixture()
                owner = f.configure()
                change(f)
                self.refused(owner, f.command)
                self.assertEqual(len(f.channel.messages), 1)

    def test_fixed_scope_and_original_deadline_clamping(self):
        f = Fixture(lifetime=12 * SECOND)
        owner = f.configure()
        f.command["deadlineBoottimeNs"] = f.clock.boot + 5 * SECOND
        owner.handle(f.command)
        result = f.channel.messages[-1]
        scope = result["pair"]["scope"]
        self.assertEqual(scope["sealExpiresAtEpochNs"], f.clock.wall + 5 * SECOND)
        self.assertEqual(scope["documentExpiresAtEpochNs"], f.clock.wall + 12 * SECOND)
        self.assertEqual(f.channel.deadlines[-1], f.command["deadlineBoottimeNs"])
        changes = [lambda f: f.command.update(sealExpiresAtEpochNs=f.clock.wall + 31 * SECOND),
            lambda f: f.command.update(documentExpiresAtEpochNs=f.clock.wall + 301 * SECOND),
            lambda f: f.command.update(issuedAtEpochNs=f.clock.wall + 1),
            lambda f: f.command.update(deadlineBoottimeNs=f.clock.boot),
            lambda f: f.command.update(sealExpiresAtEpochNs=f.clock.wall)]
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                f = Fixture()
                owner = f.configure()
                change(f)
                self.refused(owner, f.command)

    def test_retained_key_channel_config_policy_and_clock_changes_poison(self):
        changes = [lambda f, o: setattr(f.broker, "kek", AESGCM(KEY)),
            lambda f, o: setattr(f.broker, "key_id", "attested-memory-kek:" + "1" * 24),
            lambda f, o: setattr(f.broker, "commitment", ingress.PIN),
            lambda f, o: setattr(f.broker, "channel", Channel(f.clock, 600 * SECOND)),
            lambda f, o: setattr(f.channel, "deadline", f.channel.deadline + 1),
            lambda f, o: o.config["identity"].update(policyHash=ingress.PIN),
            lambda f, o: setattr(o, "owner_scope_digest", ingress.PIN),
            lambda f, o: setattr(o, "_pid", os.getpid() + 1),
            lambda f, o: setattr(f.clock, "wall", f.clock.wall - 1),
            lambda f, o: setattr(f.clock, "boot", f.clock.boot - 1),
            lambda f, o: setattr(f.clock, "boot", f.channel.deadline)]
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                f = Fixture()
                owner = f.configure()
                change(f, owner)
                with self.assertRaises(native.OwnerError):
                    owner.check()
                self.assertTrue(owner._poisoned)
                self.refused(owner, f.command)
        f = Fixture()
        f.config["identity"]["policyHash"] = ingress.PIN
        owner = f.configure()
        self.refused(owner, f.command)

    def test_exact_request_spent_once_and_capacity_never_rearms(self):
        for capacity in (1, 2):
            with self.subTest(capacity=capacity):
                f = Fixture(capacity=capacity)
                owner = f.configure()
                with patch.object(material, "seal_pair", wraps=material.seal_pair) as sealing:
                    owner.handle(f.command)
                    self.assertEqual(sealing.call_count, 1)
                    self.refused(owner, f.command, spent=True)
                    self.assertEqual(sealing.call_count, 1)
                self.assertEqual(len(f.channel.messages), 2)
        f = Fixture(capacity=1)
        owner = f.configure()
        owner.handle(f.command)
        raw = ingress.raw_arguments()
        raw["route_id"] = "another-valid-request"
        envelope = private.prepare(raw)
        command = {**f.command, "runtimeInput": envelope, "publicRequest": ingress.typed_request(envelope["arguments"])}
        self.refused(owner, command, spent=True)

    def test_output_uncertainty_and_cancellation_poison_after_real_encryption(self):
        class Cancelled(BaseException):
            pass
        for failure in (OSError("synthetic lost reply"), Cancelled("synthetic cancellation")):
            with self.subTest(failure=type(failure).__name__):
                f = Fixture()
                owner = f.configure()
                f.channel.prepared_failure = failure
                with patch.object(material, "seal_pair", wraps=material.seal_pair) as sealing:
                    with self.assertRaises(native.OwnerError if isinstance(failure, Exception) else Cancelled):
                        owner.handle(f.command)
                    self.assertEqual(sealing.call_count, 1)
                self.assertTrue(owner._poisoned)
                self.assertEqual(owner._spent, {f.request["requestDigest"]})
                self.assertEqual(f.channel.messages[-1]["phase"], "prepared")
                f.channel.prepared_failure = None
                self.refused(owner, f.command, spent=True)
        f = Fixture()
        owner = f.configure()

        def encryption_failure(*_arguments, **_keywords):
            self.assertEqual(owner._spent, {f.request["requestDigest"]})
            raise OSError("synthetic encryption failure after attempt fence")

        with patch.object(material, "seal_pair", side_effect=encryption_failure) as sealing:
            with self.assertRaises(native.OwnerError):
                owner.handle(f.command)
            self.assertEqual(sealing.call_count, 1)
        self.assertTrue(owner._poisoned)
        self.assertEqual(owner._spent, {f.request["requestDigest"]})
        self.assertEqual(f.channel.messages, [{"apiVersion": native.CHANNEL, "phase": "configured"}])
        self.refused(owner, f.command, spent=True)

        f = Fixture()
        owner = f.configure()
        real_seal_pair = material.seal_pair
        encrypted_pairs = []

        def expiry_after_real_encryption(*arguments, **keywords):
            pair = real_seal_pair(*arguments, **keywords)
            encrypted_pairs.append(pair)
            self.assertEqual(owner._spent, {f.request["requestDigest"]})
            f.clock.wall = f.command["sealExpiresAtEpochNs"]
            return pair

        with patch.object(material, "seal_pair", side_effect=expiry_after_real_encryption) as sealing:
            with self.assertRaises(native.OwnerError):
                owner.handle(f.command)
            self.assertEqual(sealing.call_count, 1)
        self.assertEqual(len(encrypted_pairs), 1)
        self.assertEqual(f.clock.wall, f.command["sealExpiresAtEpochNs"])
        self.assertTrue(owner._poisoned)
        self.assertEqual(owner._spent, {f.request["requestDigest"]})
        self.assertEqual(f.channel.messages, [{"apiVersion": native.CHANNEL, "phase": "configured"}])
        self.refused(owner, f.command, spent=True)

        f = Fixture()
        owner = f.configure()
        f.channel.after_prepared = lambda: setattr(f.clock, "wall", f.command["sealExpiresAtEpochNs"])
        with self.assertRaises(native.OwnerError):
            owner.handle(f.command)
        self.assertTrue(owner._poisoned)
        self.refused(owner, f.command, spent=True)

    def test_no_open_review_release_or_reconfigure_handler(self):
        for phase in ("open", "open-pair", "review", "release", "configure"):
            with self.subTest(phase=phase):
                f = Fixture()
                owner = f.configure()
                self.refused(owner, {**f.command, "phase": phase})
                self.assertEqual(len(f.channel.messages), 1)


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        _DATA.cleanup()

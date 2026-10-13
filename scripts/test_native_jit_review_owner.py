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
from scripts import test_authority_release_private_request as release_fixture
from serverware import authority_contract as contract
from serverware import authority_jit_private_request as private
from serverware import authority_release_private_request as release_private
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
        if value.get("phase") in {"prepared", "prepared-release-pair"}:
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


class ReleaseFixture(Fixture):
    def __init__(self, raw=None, **kwargs):
        super().__init__(**kwargs)
        self.raw = release_fixture.native_raw_arguments() if raw is None else copy.deepcopy(raw)
        self.envelope = release_private.prepare(self.raw)
        expected = release_fixture.expected_envelope(self.raw)
        if release_fixture.canonical(self.envelope) != release_fixture.canonical(expected):
            raise AssertionError("release fixture original projection changed")
        # Independent literal domains/handlers/adapters, not the owner's actual
        # derive_native_requests call. Public synthetic originals only.
        self.parent = release_fixture.native_request_oracle("release.reserve", expected["arguments"])
        self.request = release_fixture.native_request_oracle("jit.request", expected["arguments"]["jit_approval_request"])
        self.config["identity"]["policyHash"] = self.raw["policy_hash"]
        self.command.update(phase="seal-release-pair", runtimeInput=self.envelope,
            parentRequest=self.parent, publicRequest=self.request)

    def standalone(self):
        envelope = private.prepare(release_fixture.child_original(self.raw))
        command = {key: value for key, value in self.command.items() if key != "parentRequest"}
        return {**command, "phase": "seal-pair", "runtimeInput": envelope}


class NativeReleaseJitReviewOwnerTests(unittest.TestCase):
    def refused(self, owner, command):
        before = set(owner._spent)
        with patch.object(material, "seal_pair", wraps=material.seal_pair) as standalone, \
                patch.object(material, "seal_release_pair", wraps=material.seal_release_pair) as compound:
            with self.assertRaises(native.OwnerError) as caught:
                owner.handle(command)
            standalone.assert_not_called()
            compound.assert_not_called()
        self.assertTrue(owner._poisoned)
        self.assertEqual(owner._spent, before)
        self.assertEqual(str(caught.exception), "native JIT review owner unavailable")
        self.assertIsNone(caught.exception.__cause__)
        for canary in release_fixture.CANARIES:
            self.assertNotIn(canary, str(caught.exception))

    def test_compound_exact_literal_scope_response_bindings_and_real_aead(self):
        f = ReleaseFixture(); owner = f.configure()
        before = release_fixture.canonical(f.command)
        with patch.object(material, "seal_pair", wraps=material.seal_pair) as standalone:
            owner.handle(f.command)
            standalone.assert_not_called()
        result = f.channel.messages[-1]
        self.assertEqual(set(result), {"apiVersion", "phase", "operation", "pair", "statementBindings"})
        self.assertEqual((result["apiVersion"], result["phase"], result["operation"]),
            (native.CHANNEL, "prepared-release-pair", "release.reserve"))
        scope = {"schema": "serverware.nativeJitReviewScope/v2", "publicRequest": f.request,
            "parentRequestSha256": release_fixture.sha(release_fixture.canonical(f.parent)),
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": f.config["controlPlaneConfigurationDigest"],
            "ownerScopeDigest": owner.owner_scope_digest,
            **{name: f.command[name] for name in ("issuedAtEpochNs", "sealExpiresAtEpochNs", "documentExpiresAtEpochNs")}}
        self.assertEqual(result["pair"]["scope"], scope)
        self.assertEqual(result["pair"]["schema"], "serverware.nativeJitReviewPair/v2")
        self.assertEqual(material.open_release_pair(result["pair"], expected_scope=scope,
            key_id=f.broker.key_id, kek=f.broker.kek, now_epoch_ns=f.clock.wall), f.envelope["privateDocuments"])
        expected = {"sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": f.config["controlPlaneConfigurationDigest"],
            "ownerScopeDigest": owner.owner_scope_digest, "deploymentId": f.config["deploymentId"],
            "instanceId": f.config["instanceId"], "requestDigest": f.request["requestDigest"],
            "operationId": f.request["operationId"], "publicRequestSha256": release_fixture.sha(release_fixture.canonical(f.request)),
            "parentRequestSha256": scope["parentRequestSha256"], "parentRequestDigest": f.parent["requestDigest"],
            "parentOperationId": f.parent["operationId"], "pairSha256": release_fixture.sha(release_fixture.canonical(result["pair"])),
            "secretKekId": f.broker.key_id, "challenge": f.command["challenge"], "issuedAtEpochNs": f.clock.wall,
            "expiresAtEpochNs": f.command["sealExpiresAtEpochNs"],
            "documentExpiresAtEpochNs": f.command["documentExpiresAtEpochNs"], **f.config["identity"]}
        self.assertEqual(len(expected), 27)
        self.assertEqual(result["statementBindings"], expected)
        for canary in release_fixture.CANARIES:
            self.assertNotIn(canary.encode(), release_fixture.canonical(result))
        self.assertEqual(release_fixture.canonical(f.command), before)
        self.assertEqual(owner._spent, {f.request["requestDigest"]})
        self.assertIsNone(owner.operation)

    def test_compound_parent_child_private_source_policy_and_closed_fields(self):
        changes = []
        for root in ((), ("runtimeInput",), ("runtimeInput", "arguments"),
                ("runtimeInput", "arguments", "jit_approval_request"), ("runtimeInput", "privateDocuments"),
                ("parentRequest",), ("parentRequest", "arguments"),
                ("parentRequest", "arguments", "businessIntent"), ("publicRequest",), ("publicRequest", "arguments")):
            sample = ReleaseFixture().command
            for part in root: sample = sample[part]
            for field in (*sample, "unexpected"):
                changes.append((root, field))
        for root, field in changes:
            with self.subTest(root=root, field=field):
                f = ReleaseFixture(); owner = f.configure(); target = f.command
                for part in root: target = target[part]
                if field == "unexpected": target[field] = release_fixture.CANARIES[0]
                else: del target[field]
                self.refused(owner, f.command)
                self.assertEqual(len(f.channel.messages), 1)
        mutations = (
            lambda f: f.parent.update(requestDigest=ingress.PIN),
            lambda f: f.parent.update(operationId=ingress.PIN),
            lambda f: f.parent.update(operationManifestDigest=ingress.PIN),
            lambda f: f.parent.update(operation="release.v1.reserve"),
            lambda f: f.request.update(requestDigest=ingress.PIN),
            lambda f: f.envelope.update(operationManifestDigest=ingress.PIN),
            lambda f: f.envelope["arguments"].update(original_arguments_digest=ingress.PIN),
            lambda f: f.envelope["arguments"].update(expected_approver_policy_sha256=ingress.PIN),
            lambda f: f.envelope["arguments"]["approver_credential_policy"].update(maxAssertionAgeSeconds=31),
            lambda f: f.envelope["arguments"]["jit_approval_request"].update(canonical_request_digest=ingress.PIN),
            lambda f: f.envelope["privateDocuments"].update(url="https://different.invalid/"),
            lambda f: f.envelope["privateDocuments"].update(canonical_request={"different": True}),
            lambda f: f.envelope["privateDocuments"].update(redacted_display={"different": True}),
            lambda f: f.parent["arguments"].update(privateDocuments=f.envelope["privateDocuments"]),
            lambda f: f.config["identity"].update(policyHash=ingress.PIN),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                f = ReleaseFixture(); mutate(f); owner = f.configure()
                self.refused(owner, f.command)
        # Coherent but unrelated parent, rather than only a broken outer hash.
        f = ReleaseFixture(); owner = f.configure()
        other = ReleaseFixture({**f.raw, "actor_id": "oidc:another-parent"})
        self.assertEqual(other.request, f.request)
        self.refused(owner, {**f.command, "parentRequest": other.parent})

    def test_profiles_are_explicit_and_spent_child_is_shared_across_parents(self):
        for compound_first in (False, True):
            with self.subTest(compound_first=compound_first):
                f = ReleaseFixture(); owner = f.configure()
                first, second = (f.command, f.standalone()) if compound_first else (f.standalone(), f.command)
                owner.handle(first)
                self.assertEqual(owner._spent, {f.request["requestDigest"]})
                self.refused(owner, second)
                self.assertEqual(len(f.channel.messages), 2)
        f = ReleaseFixture(); owner = f.configure(); owner.handle(f.command)
        other = ReleaseFixture({**f.raw, "actor_id": "oidc:another-parent"})
        self.assertEqual(other.request, f.request)
        self.assertNotEqual(other.parent["requestDigest"], f.parent["requestDigest"])
        self.refused(owner, other.command)
        for phase in ("seal-pair", "prepared-release-pair", "release", "open-release-pair"):
            f = ReleaseFixture(); owner = f.configure()
            self.refused(owner, {**f.command, "phase": phase})
        for raw in (release_fixture.raw_arguments(),
                {**release_fixture.native_raw_arguments(), "native_profile": False, "policy_aware_profile": True}):
            f = ReleaseFixture(raw); owner = f.configure()
            self.refused(owner, f.command)
        f = ReleaseFixture(capacity=1); owner = f.configure(); owner.handle(f.command)
        other = ReleaseFixture({**f.raw, "route_id": "different-valid-child"})
        self.assertNotEqual(other.request["requestDigest"], f.request["requestDigest"])
        self.refused(owner, other.command)

    def test_release_original_deadlines_clamp_and_never_renew(self):
        f = ReleaseFixture(lifetime=12 * SECOND); owner = f.configure()
        f.command["deadlineBoottimeNs"] = f.clock.boot + 5 * SECOND
        owner.handle(f.command); result = f.channel.messages[-1]
        self.assertEqual(result["pair"]["scope"]["sealExpiresAtEpochNs"], f.clock.wall + 5 * SECOND)
        self.assertEqual(result["pair"]["scope"]["documentExpiresAtEpochNs"], f.clock.wall + 12 * SECOND)
        self.assertEqual(f.channel.deadlines[-1], f.command["deadlineBoottimeNs"])
        self.assertEqual(result["statementBindings"]["expiresAtEpochNs"], f.clock.wall + 5 * SECOND)
        for field, value in (("issuedAtEpochNs", Clock.wall + 1),
                ("sealExpiresAtEpochNs", Clock.wall), ("sealExpiresAtEpochNs", Clock.wall + 31 * SECOND),
                ("documentExpiresAtEpochNs", Clock.wall + 301 * SECOND), ("deadlineBoottimeNs", Clock.boot)):
            f = ReleaseFixture(); owner = f.configure()
            self.refused(owner, {**f.command, field: value})

    def test_release_uncertain_write_cancellation_and_both_clock_expiry_poison(self):
        class Cancelled(BaseException): pass
        for failure in (OSError("synthetic lost reply"), Cancelled("synthetic cancellation")):
            f = ReleaseFixture(); owner = f.configure(); f.channel.prepared_failure = failure
            with patch.object(material, "seal_release_pair", wraps=material.seal_release_pair) as sealing:
                with self.assertRaises(native.OwnerError if isinstance(failure, Exception) else Cancelled):
                    owner.handle(f.command)
                self.assertEqual(sealing.call_count, 1)
            self.assertEqual(f.channel.messages[-1]["phase"], "prepared-release-pair")
            self.assertEqual(owner._spent, {f.request["requestDigest"]})
            f.channel.prepared_failure = None
            self.refused(owner, f.command)
        real_seal = material.seal_release_pair
        for clock in ("wall", "boot"):
            with self.subTest(clock=clock):
                f = ReleaseFixture(); owner = f.configure(); encrypted = []
                def expires_after_encrypt(*args, **kwargs):
                    encrypted.append(real_seal(*args, **kwargs))
                    self.assertEqual(owner._spent, {f.request["requestDigest"]})
                    if clock == "wall": f.clock.wall = f.command["sealExpiresAtEpochNs"]
                    else: f.clock.boot += 20 * SECOND  # Actual seal-clamped original deadline.
                    return encrypted[-1]
                with patch.object(material, "seal_release_pair", side_effect=expires_after_encrypt):
                    with self.assertRaises(native.OwnerError): owner.handle(f.command)
                self.assertEqual(len(encrypted), 1)
                self.assertEqual(len(f.channel.messages), 1)
                self.refused(owner, f.standalone())

    def test_compound_owns_deep_originals_before_encryption_and_response(self):
        f = ReleaseFixture(); owner = f.configure(); before = copy.deepcopy(f.command)
        real_seal = material.seal_release_pair
        def mutate_caller_after_checked_copy(*args, **kwargs):
            f.parent["arguments"]["jit_approval_request"]["approver_credential_policy"]["origins"].append("https://mutated.invalid")
            f.envelope["privateDocuments"]["canonical_request"]["literal"]["base64Url"] = "mutated secret graph"
            f.request["arguments"]["businessIntent"]["arguments"]["route_id"] = "mutated-child"
            return real_seal(*args, **kwargs)
        with patch.object(material, "seal_release_pair", side_effect=mutate_caller_after_checked_copy):
            owner.handle(f.command)
        result = f.channel.messages[-1]; scope = result["pair"]["scope"]
        self.assertEqual(scope["publicRequest"], before["publicRequest"])
        self.assertEqual(scope["parentRequestSha256"], release_fixture.sha(release_fixture.canonical(before["parentRequest"])))
        self.assertEqual(material.open_release_pair(result["pair"], expected_scope=scope,
            key_id=f.broker.key_id, kek=f.broker.kek, now_epoch_ns=f.clock.wall), before["runtimeInput"]["privateDocuments"])

    def test_real_decoder_and_owner_preserve_allowed_floats_and_large_integers(self):
        from serverware import native_secret_broker_helper as helper
        raw = release_fixture.native_raw_arguments()
        values = {"finite": [1.25, -0.0, 1e100], "large": 2**100, "negative": -(2**100)}
        for field in ("operation_context", "durable_policy_binding"):
            raw[field] = copy.deepcopy(values)
        raw["shared_quotas"] = [copy.deepcopy(values)]
        raw["jit_approval_request"]["canonical_request"]["numbers"] = copy.deepcopy(values)
        raw["jit_approval_request"]["redacted_display"]["numbers"] = copy.deepcopy(values)
        f = ReleaseFixture(raw); owner = f.configure(); wire = release_fixture.canonical(f.command)
        self.assertLess(len(wire), 512 * 1024)
        decoded = helper._document(wire, allow_jit_seal=True)
        self.assertEqual(release_fixture.canonical(decoded), wire)
        owner.handle(decoded)
        result = f.channel.messages[-1]; scope = result["pair"]["scope"]
        self.assertEqual(result["statementBindings"]["parentRequestSha256"], release_fixture.sha(release_fixture.canonical(f.parent)))
        self.assertEqual(material.open_release_pair(result["pair"], expected_scope=scope,
            key_id=f.broker.key_id, kek=f.broker.kek, now_epoch_ns=f.clock.wall), f.envelope["privateDocuments"])
        with self.assertRaises(ValueError): helper._document(wire)
        with self.assertRaises(ValueError):
            helper._document(release_fixture.canonical({**f.command, "phase": "seal-pair"}), allow_jit_seal=True)
        for token in (b"NaN", b"Infinity", b"-Infinity", b"1e999"):
            malformed = wire.replace(b"1.25", token, 1)
            with self.subTest(token=token), self.assertRaises(ValueError):
                helper._document(malformed, allow_jit_seal=True)

    def test_control_floats_and_full_command_size_stay_closed(self):
        from serverware import native_secret_broker_helper as helper
        paths = [(field,) for field in ("issuedAtEpochNs", "sealExpiresAtEpochNs", "documentExpiresAtEpochNs", "deadlineBoottimeNs")]
        paths += [("runtimeInput", "arguments", field) for field in ("credential_version", "reservation_ttl_seconds", "now_epoch_ms", "approval_threshold")]
        paths += [("parentRequest", "arguments", "native_profile"), ("publicRequest", "arguments", "credential_version"),
            ("publicRequest", "arguments", "approver_credential_policy", "maxAssertionAgeSeconds")]
        for path in paths:
            with self.subTest(path=path):
                f = ReleaseFixture(); owner = f.configure(); target = f.command
                for name in path[:-1]: target = target[name]
                target[path[-1]] = 1.0
                with self.assertRaises(ValueError): helper._document(release_fixture.canonical(f.command), allow_jit_seal=True)
                self.refused(owner, f.command)
        raw = release_fixture.native_raw_arguments()
        # Unlike the separately 64KiB-bounded operation_context, this original
        # durable mapping fits its 4MiB parent bound; repeated public framing
        # alone then exceeds the tighter 512KiB channel command limit.
        raw["durable_policy_binding"] = {"padding": "x" * (180 * 1024)}
        f = ReleaseFixture(raw); owner = f.configure(); wire = release_fixture.canonical(f.command)
        self.assertEqual(native.MAX_COMMAND_BYTES, 512 * 1024)
        self.assertGreater(len(wire), native.MAX_COMMAND_BYTES)
        with self.assertRaises(ValueError): helper._document(wire, allow_jit_seal=True)
        self.refused(owner, f.command)


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        _DATA.cleanup()

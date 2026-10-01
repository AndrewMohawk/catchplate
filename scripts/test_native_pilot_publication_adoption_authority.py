#!/usr/bin/env python3
"""Framing controls and a rootless real pipe/PIDFD/reap probe, not validation.

Synthetic public packets deliberately do not contain a valid cold/current
chain. No protected executable, successful native validator, admitted owner,
private-key loader or adoption signer is mocked or invoked. The kernel probe
tests the exact production exit matcher only; it grants no signing capability.
"""
from __future__ import annotations

import copy
import fcntl
import os
from pathlib import Path
import select
import signal
import sys
import time
from types import SimpleNamespace
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from serverware import native_pilot_publication_adoption_profile as profile
from serverware import native_pilot_publication_adoption_authority as authority

p, g = profile.p, profile.g


def fixture(version=2):
    digest = p.sha(b"SYNTHETIC ADOPTION FRAMING ONLY")
    key = Ed25519PrivateKey.from_private_bytes(bytes([91]) * 32)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pin = p.sha(bytes.fromhex("302a300506032b6570032100") + public)
    selected = {"keyId": pin, "keySpkiSha256": pin, "publicKeyBase64url": p.encoded(public)}
    boot = (p.encoded(bytes([2]) * 16), 5, 6)
    scope = {name: digest for name in profile.cold.GENESIS_FIELDS}
    scope.update(apiVersion=profile.cold.GENESIS_API, assignmentRevision=1, initialPublicationRevision=1,
        proofScopeOriginal="{}", bootIdBase64url=boot[0], timeNamespaceDevice=boot[1], timeNamespaceInode=boot[2],
        issuedAtBoottimeNanos=100, expiresAtBoottimeNanos=1000)
    configuration = dict(apiVersion="serverware.nativePublicationGenesisCoordinatorRuntime/v" + str(version),
        scope=scope, durableGrantOriginal="{}", currentGrantOriginal="{}", histories=[], serviceSessions=[],
        nativeEndpoints=[], resultPeer={})
    payload = {name: digest for name in profile.PAYLOAD_FIELDS}
    payload.update(apiVersion="serverware.nativePublicationAdoptionAuthorization/v" + str(version),
        purpose="cold-publication-to-operational", coldConfigurationOriginal=g.canonical(configuration).decode("ascii"),
        coldBundleOriginal="{}", coldNativeGrantOriginal="{}", coldRetrievalGrantOriginal="{}",
        priorSupervisor=selected, assignmentRevision=1, proofScopeOriginal="{}", native=selected, retrieval=selected,
        targetHistories=[], authority=selected, revocationGeneration=1, issuedAtUnixNanos=1000,
        expiresAtUnixNanos=2000, issuedAtBoottimeNanos=200, expiresAtBoottimeNanos=900)
    value = dict(apiVersion="serverware.nativePublicationAdoptionValidationInput/v" + str(version),
        payloadOriginal=g.canonical(payload).decode("ascii"), currentTrustOriginal="{}", currentTrustSha256=p.sha(b"{}"),
        currentAssignmentOriginal="{}", currentClosureSetOriginal="{}", currentConfigurationBindingSha256=digest,
        currentProofScopeOriginal="{}", targetHistories=[dict(serviceRole=role, runtimeOriginal="{}", historyOriginal="{}",
            rootKeyId=digest, rootKeySpkiSha256=digest) for role in ("durable-recovery-store", "current-signature-authority")])
    clocks = dict(boot=boot, now_boottime_ns=300, now_unix_ns=1100)
    return value, clocks, key


def prepare(value, clocks):
    raw = p.canonical(value)
    return profile.prepare_input(raw, expected_input_sha256=p.sha(raw), **clocks)


def packet(context):
    key = context["payload"]["authority"]
    return dict(apiVersion=context["resultApi"], inputSha256=context["inputSha256"],
        payloadOriginal=context["payloadOriginal"].decode("ascii"), payloadSha256=p.sha(context["payloadOriginal"]),
        signingKeyId=key["keyId"], signingKeySpkiSha256=key["keySpkiSha256"], publicKeyBase64url=key["publicKeyBase64url"],
        deadlineBoottimeNanos=context["deadline"], expiresAtUnixNanos=context["epochLimit"])


class AdoptionAuthorityControls(unittest.TestCase):
    def test_exact_two_profiles_and_native_domain_framing(self):
        messages = []
        for version in (1, 2):
            value, clocks, key = fixture(version)
            held = prepare(value, clocks)
            expected = (b"serverware.signedEnvelope/v1\0serverware.nativePublicationAdoptionAuthorization.signature/v"
                + str(version).encode("ascii") + b"\0serverware.canonicalJson/ascii-integer-v1\0" + held["payloadOriginal"])
            self.assertEqual(profile.message(held), expected)
            signature = key.sign(expected)
            profile.authority(held["payload"]["authority"]).verify(signature, expected)
            with self.assertRaises(InvalidSignature):
                key.public_key().verify(signature, expected.replace(b".signature/v" + str(version).encode(), b".signature/v9"))
            messages.append(expected)
        self.assertNotEqual(*messages)

    def test_mixed_unknown_profiles_and_changed_cold_runtime_refuse(self):
        for field, replacement in (("apiVersion", "serverware.nativePublicationAdoptionValidationInput/v1"),
                ("apiVersion", "serverware.nativePublicationAdoptionValidationInput/v3")):
            value, clocks, _ = fixture(); value[field] = replacement
            with self.assertRaises(ValueError): prepare(value, clocks)
        value, clocks, _ = fixture()
        payload = g.document(value["payloadOriginal"].encode(), profile.MAX_AUTHORIZATION)
        cold = g.document(payload["coldConfigurationOriginal"].encode(), profile.MAX_AUTHORIZATION)
        cold["apiVersion"] = "serverware.nativePublicationGenesisCoordinatorRuntime/v1"
        payload["coldConfigurationOriginal"] = g.canonical(cold).decode()
        value["payloadOriginal"] = g.canonical(payload).decode()
        with self.assertRaises(ValueError): prepare(value, clocks)

    def test_exact_control_input_pin_and_canonical_shape(self):
        value, clocks, _ = fixture(); raw = p.canonical(value)
        pin = p.sha(raw)
        control = dict(apiVersion=profile.CONTROL_API, validatorExecutableSha256=p.sha(b"synthetic ELF pin"), inputSha256=pin)
        self.assertEqual(profile.control(p.canonical(control), pin), control)
        with self.assertRaises(ValueError): profile.control(p.canonical(control), p.sha(b"different input"))
        control["executablePath"] = "/unapproved/validator"
        with self.assertRaises(ValueError): profile.control(p.canonical(control), pin)
        for changed in (raw + b"\n", b'{"apiVersion":"duplicate",' + raw[1:]):
            with self.assertRaises(ValueError): profile.prepare_input(changed, expected_input_sha256=p.sha(changed), **clocks)

    def test_actual_clock_namespace_and_original_window_boundaries(self):
        value, clocks, _ = fixture()
        for updates in ({"now_boottime_ns": 199}, {"now_boottime_ns": 900}, {"now_unix_ns": 999},
                {"now_unix_ns": 2000}, {"boot": (clocks["boot"][0], 5, 7)}):
            with self.assertRaises(ValueError): prepare(value, {**clocks, **updates})
        held = prepare(value, clocks)
        self.assertEqual((held["issued"], held["deadline"], held["epochIssued"], held["epochLimit"]), (200, 900, 1000, 2000))

    def test_each_output_binding_is_exact_and_no_extra_success_status(self):
        value, clocks, _ = fixture(); held = prepare(value, clocks); expected = packet(held)
        self.assertEqual(profile.result(g.canonical(expected), held), expected)
        mutations = dict(apiVersion="serverware.nativePublicationAdoptionValidation/v1", inputSha256=p.sha(b"other"),
            payloadSha256=p.sha(b"other payload"), payloadOriginal="{}", signingKeyId=p.sha(b"other key"),
            signingKeySpkiSha256=p.sha(b"other spki"), publicKeyBase64url=p.encoded(bytes([7]) * 32),
            deadlineBoottimeNanos=901, expiresAtUnixNanos=2001)
        for field, replacement in mutations.items():
            with self.assertRaises(ValueError): profile.result(g.canonical({**expected, field: replacement}), held)
        with self.assertRaises(ValueError): profile.result(g.canonical({**expected, "success": True}), held)

    def test_key_spki_original_trust_and_proof_associations(self):
        value, clocks, _ = fixture()
        for field, replacement in (("currentTrustSha256", p.sha(b"wrong trust")),
                ("currentConfigurationBindingSha256", p.sha(b"wrong current configuration")), ("currentProofScopeOriginal", "[]")):
            with self.assertRaises(ValueError): prepare({**value, field: replacement}, clocks)
        payload = g.document(value["payloadOriginal"].encode(), profile.MAX_AUTHORIZATION)
        payload["authority"]["keySpkiSha256"] = p.sha(b"not this key")
        value["payloadOriginal"] = g.canonical(payload).decode()
        with self.assertRaises(ValueError): prepare(value, clocks)

    def test_no_public_packet_or_constructor_token_mints_owner(self):
        value, clocks, _ = fixture(); held = prepare(value, clocks)
        profile.result(g.canonical(packet(held)), held)  # Framing only, deliberately invalid semantic chain.
        with self.assertRaises(ValueError): authority.AdoptionAuthority(held)
        with self.assertRaises(ValueError): authority.AdoptionAuthority(object())

    def test_terminal_matcher_refuses_nonzero_signal_other_pid_and_absence(self):
        for observed in (None, SimpleNamespace(si_pid=11, si_code=os.CLD_EXITED, si_status=1),
                SimpleNamespace(si_pid=11, si_code=os.CLD_KILLED, si_status=signal.SIGTERM),
                SimpleNamespace(si_pid=12, si_code=os.CLD_EXITED, si_status=0)):
            with self.assertRaises(ValueError): profile.successful_reap(observed, 11)

    def test_partial_executable_sealing_preserves_stable_close_ownership(self):
        # Actual mutable memfd metadata is not the immutable ownership origin.
        # This is not a admitted executable or a constructed authority owner.
        fd = os.memfd_create("adoption-close-identity-probe", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            before = authority._ownership_identity(os.fstat(fd))
            os.pwrite(fd, b"not an executable; identity probe only", 0)
            self.assertEqual(authority._ownership_identity(os.fstat(fd)), before)
            os.fchmod(fd, 0o500)
            self.assertEqual(authority._ownership_identity(os.fstat(fd)), before)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, authority.io.public_io.SEALS)
            self.assertEqual(authority._ownership_identity(os.fstat(fd)), before)
        finally:
            retired, fd = fd, None
            os.close(retired)

    def test_real_pipe_eof_same_child_pidfd_and_consuming_wait_only(self):
        # A local child writes test bytes and exits; it is NOT the admitted
        # native validator and this probe never constructs a signing owner.
        read, write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        pidfd = None; reaped = False
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read); os.write(write, b"kernel-probe-only"); os.close(write)
            finally:
                os._exit(0)
        os.close(write)
        try:
            pidfd = os.pidfd_open(pid, 0)
            deadline, raw, eof = time.monotonic() + 2.0, bytearray(), False
            observed = None
            while time.monotonic() < deadline:
                try:
                    part = os.read(read, 64)
                    if part: raw.extend(part)
                    else: eof = True
                except BlockingIOError:
                    pass
                observed = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if eof and observed is not None: break
                select.select([read, pidfd], [], [], 0.001)
            self.assertTrue(eof); self.assertEqual(bytes(raw), b"kernel-probe-only")
            self.assertIsNotNone(observed)
            actual = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
            reaped = actual is not None
            profile.successful_reap(actual, pid)
            with self.assertRaises(ChildProcessError): os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
        finally:
            if not reaped:
                if pidfd is None: pidfd = os.pidfd_open(pid, 0)
                try: signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                except ProcessLookupError: pass
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    actual = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
                    if actual is not None:
                        reaped = True; break
                    select.select([pidfd], [], [], 0.001)
                self.assertTrue(reaped, "kernel probe child cleanup unknown")
            if pidfd is not None: os.close(pidfd)
            os.close(read)


if __name__ == "__main__":
    unittest.main()

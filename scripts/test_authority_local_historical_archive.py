#!/usr/bin/env python3
"""Synthetic codec/routing/custody controls, not populated package admission."""
from copy import deepcopy
import ast
import fcntl
import inspect
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import local_historical_archive as cli
from serverware import authority_local_historical_archive as subject


def fixture():
    key = Ed25519PrivateKey.from_private_bytes(b"H" * 32)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    originals = {name: subject.canonical({"synthetic": name}) for name in subject.ORIGINAL_NAMES}
    selected = dict(schema=subject.SCHEMA, purpose=subject.PURPOSE, rootDelegation=subject.DELEGATION,
        originalSha256={name: subject.sha(raw) for name, raw in originals.items()},
        configurationRootPublicKeyBase64Url=subject.spec.strict_base64url_encode(public),
        previousConfigurationRootPublicKeyBase64Url=subject.spec.strict_base64url_encode(public),
        bootIdDigest=subject.sha(b"synthetic-boot"), issuedAtBoottimeNs=100, deadlineBoottimeNs=200,
        issuedAtUnixNanos=100, expiresAtUnixNanos=200,
        runtimeValidity=dict(issuedAtEpochNs=100, expiresAtEpochNs=300))
    return key, public, selected, originals


def approve(selected, **changes):
    return subject.approval(subject.canonical(selected), **dict(
        boot=selected["bootIdDigest"], now_boottime_ns=150, now_unix_ns=150, **changes))


class ArchiveControls(unittest.TestCase):
    def test_closed_independent_selection_and_original_bounds(self):
        _, _, selected, _ = fixture()
        self.assertEqual(approve(selected), selected)
        changes = (lambda x: x.update(extra=True), lambda x: x.update(rootDelegation="implicit"),
            lambda x: x["originalSha256"].pop("previousTrustState"),
            lambda x: x.update(issuedAtBoottimeNs=True), lambda x: x.update(expiresAtUnixNanos=150),
            lambda x: x["runtimeValidity"].update(issuedAtEpochNs=101),
            lambda x: x["runtimeValidity"].update(expiresAtEpochNs=subject.LOCAL_SESSION_MAX_NS + 101))
        for mutate in changes:
            bad = deepcopy(selected); mutate(bad)
            with self.subTest(change=mutate), self.assertRaises(ValueError):
                approve(bad)
        with self.assertRaises(ValueError):
            subject.approval(subject.canonical(selected), boot=subject.sha(b"other"),
                now_boottime_ns=150, now_unix_ns=150)

    def test_original_pins_closure_and_actual_package_refusal(self):
        _, _, selected, originals = fixture()
        for mutate in (lambda x: x.pop("previousConfiguration"), lambda x: x.update(extra=b"{}"),
                       lambda x: x.update(previousTrustState=b"{}")):
            bad = dict(originals); mutate(bad)
            with self.assertRaises(ValueError):
                subject.prepare(subject.canonical(selected), bad, boot=selected["bootIdDigest"],
                    now_boottime_ns=150, now_unix_ns=150)
        # No fake VerifiedArtifactPackage: the real contract rejects these
        # deliberately incomplete public originals before any signing path.
        with self.assertRaises(subject.spec.ArtifactContractError):
            subject.prepare(subject.canonical(selected), originals, boot=selected["bootIdDigest"],
                now_boottime_ns=150, now_unix_ns=150)

    def test_prior_current_interval_includes_original_archive(self):
        key, public, selected, _ = fixture()
        archive_payload = dict(schema=subject.history.SCHEMA, purpose=subject.history.PURPOSE,
            sourceRevision=subject.cohort.authority.SOURCE_REVISION,
            configurationDigest=subject.sha(b"previous-config"), generationDigest=subject.sha(b"previous-generation"),
            issuedAtEpochNs=2_000_000_000, expiresAtEpochNs=3_000_000_000, entries=[])
        archive = subject.history._canonical_document(subject._sign_archive(
            dict(rootPublic=public, payload=archive_payload), key))
        cohort_payload = {name: None for name in subject.cohort._PAYLOAD_FIELDS}
        cohort_payload.update(schema=subject.cohort.SCHEMA, issuedAtEpochNs=1_000_000_000,
            expiresAtEpochNs=4_000_000_000)
        documents = dict(previousPackage=dict(generation=dict(validFrom="1970-01-01T00:00:01Z",
            validUntil="1970-01-01T00:00:05Z")), previousTrustState={"retained": "state"},
            previousConfiguration={"retained": "configuration"}, previousRuntimeEvidence=dict(
                schema=subject.RUNTIME_SCHEMA, currentCohort=dict(schema=subject.cohort.SCHEMA,
                    payload=cohort_payload, signature="not-admitted"), historicalArchive=archive))
        class ReachedRealEntryBoundary(Exception):
            pass
        # Stop at—not bypass—the genuine entry validator. This control proves
        # only exact routing/interval derivation, never successful admission.
        with patch.object(subject.history, "_entry_snapshot", side_effect=ReachedRealEntryBoundary) as verify:
            with self.assertRaises(ReachedRealEntryBoundary):
                subject._previous(documents, selected)
            entry = verify.call_args.args[0]
            self.assertEqual((entry["validFromEpochNs"], entry["validUntilEpochNs"]), (2_000_000_000, 3_000_000_000))
            self.assertIs(entry["artifactTrustState"], documents["previousTrustState"])
            self.assertIs(entry["attestationCohort"], documents["previousRuntimeEvidence"]["currentCohort"])
        bad = deepcopy(selected)
        bad["previousConfigurationRootPublicKeyBase64Url"] = subject.spec.strict_base64url_encode(
            Ed25519PrivateKey.from_private_bytes(b"X" * 32).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        with self.assertRaises((ValueError, InvalidSignature)):
            subject._previous(documents, bad)

    def test_complete_merge_preserves_entries_and_refuses_duplicates_overflow(self):
        # Plain synthetic records test only the merge operation, not an owner
        # or an admitted HistoryArchive. No authentication API is patched.
        record = lambda value: SimpleNamespace(configuration_digest=value, planner_receipt_digest="receipt")
        old = [{"literal": "a", "validFromEpochNs": 1, "validUntilEpochNs": 2}, {"literal": "c"}]
        before = [subject.canonical(value) for value in old]
        entry = {"literal": "b"}
        admitted = SimpleNamespace(records=(record("b"), record("a"), record("c")))
        merged = subject._complete_entries(entry, admitted, old)
        self.assertEqual(merged, [old[0], entry, old[1]])
        self.assertIs(merged[0], old[0]); self.assertIs(merged[2], old[1])
        self.assertEqual([subject.canonical(value) for value in old], before)
        with self.assertRaises(ValueError):
            subject._complete_entries(entry, SimpleNamespace(records=(record("a"), record("a"))), old[:1])
        too_many = [{} for _ in range(subject.history.MAX_ENTRIES)]
        with self.assertRaises(ValueError):
            subject._complete_entries(entry, SimpleNamespace(records=tuple(record(str(x))
                for x in range(len(too_many) + 1))), too_many)

    def test_existing_archive_signature_domain_and_root_binding(self):
        key, public, _, _ = fixture()
        payload = {"synthetic": "signature-codec-only"}
        raw = subject._sign_archive(dict(rootPublic=public, payload=payload), key)
        envelope = subject.history._canonical_document(raw)
        subject.cohort._verify_signature(envelope, key.public_key())
        self.assertEqual(envelope["payload"], payload)
        with self.assertRaises(ValueError):
            subject._sign_archive(dict(rootPublic=b"x" * 32, payload=payload), key)

    def test_fixed_cli_form_alias_and_pin_refusal(self):
        flags = ("--approval-fd", "--approval-sha256", "--signing-key-fd", *cli.ORIGINAL_FLAGS)
        values = ("3", subject.sha(b"approval"), "4", *map(str, range(5, 12)))
        argv = [value for row in zip(flags, values) for value in row]
        result = cli.arguments(argv)
        self.assertEqual(tuple(result["original_fds"]), subject.ORIGINAL_NAMES)
        for position, value in ((1, "03"), (3, "sha256:" + "A" * 64), (5, "3"), (7, "-1")):
            bad = list(argv); bad[position] = value
            with self.assertRaises(ValueError):
                cli.arguments(bad)
        with self.assertRaises(ValueError):
            cli.arguments(argv + ["--retry", "yes"])

    def test_actual_protected_fd_refusal_closes_only_owned_duplicates(self):
        if os.geteuid() != 0 or os.getegid() != 0 or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            self.skipTest("requires actual isolated root -I -B, not simulated")
        fds = []
        try:
            for index in range(9):
                writable = os.memfd_create("synthetic-archive", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                try:
                    os.write(writable, b"H" * 32 if index == 1 else b"{}")
                    os.fchmod(writable, 0o400)
                    fcntl.fcntl(writable, fcntl.F_ADD_SEALS, subject.io.SEALS)
                    fds.append(os.open("/proc/self/fd/" + str(writable), os.O_RDONLY | os.O_CLOEXEC))
                finally:
                    os.close(writable)
            before = set(os.listdir("/proc/self/fd"))
            with patch.object(subject.io, "signing_key", side_effect=AssertionError("key must not be read")):
                with self.assertRaises(ValueError):
                    subject.LocalHistoricalArchiveIssuer(approval_fd=fds[0], approval_sha256=subject.sha(b"wrong"),
                        signing_key_fd=fds[1], original_fds=dict(zip(subject.ORIGINAL_NAMES, fds[2:])))
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)
            for fd in fds:
                os.fstat(fd)  # Borrowed originals survived failed construction.
        finally:
            for fd in fds:
                os.close(fd)

    def test_signing_order_and_final_admission_remain_distinct(self):
        method = ast.parse(inspect.getsource(subject.LocalHistoricalArchiveIssuer)).body[0]
        issue = next(node for node in method.body if isinstance(node, ast.FunctionDef) and node.name == "issue")
        source = ast.unparse(issue)
        self.assertLess(source.index("self._used = True"), source.index("prepare("))
        self.assertLess(source.index("prepare("), source.index("io.signing_key("))
        self.assertLess(source.index("_sign_archive("), source.rindex("self.check()"))
        self.assertIn("history._admit_on_startup", inspect.getsource(subject._previous))
        self.assertIn("history._entry_snapshot", inspect.getsource(subject._previous))


if __name__ == "__main__":
    unittest.main()

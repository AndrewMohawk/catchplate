#!/usr/bin/env python3
"""Synthetic receipt codec/source controls, not live cohort admission."""
from copy import deepcopy
from pathlib import Path
import ast
import fcntl
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_local_cohort as subject
from serverware import authority_local_limits as limits
from scripts.authority import local_cohort as cli


def digest(label):
    return subject.sha(label.encode("ascii"))


def fixture():
    # Explicit synthetic codec fixture. No actual owner or VerifiedArtifactPackage
    # is created, and this is never passed off as a positive producer run.
    key = Ed25519PrivateKey.from_private_bytes(b"\x21" * 32)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    service = dict(schema=subject.history.configuration.CONFIG_SCHEMA,
        sourceRevision=subject.cohort.authority.SOURCE_REVISION,
        roles={role: dict(processMode="policy-authority-" + role,
            measurementDigest=digest(role + "-measurement"), responseSigningSpkiDigest=digest(role + "-response"))
            for role in subject.cohort.ROLES},
        roleBindingDigests={role: digest(role + "-binding") for role in subject.cohort.ROLES},
        packageVersions={"synthetic-test": "1"},
        credentialReleaseTrust=dict(schema="serverware.trustedHostLocalCredentialReleaseTrust/v1",
            trustMode="trusted-host-local", maximumReceiptAgeNs=200),
        issuerCredentialIssuanceDigest=digest("issuer-issuance"), executorCredentialIssuanceDigest=digest("executor-issuance"))
    selected = dict(schema=subject.SCHEMA, purpose=subject.PURPOSE, rootDelegation=subject.DELEGATION,
        historicalArchiveSelection=subject.INITIAL_HISTORY,
        configurationRootPublicKeyBase64Url=subject.spec.strict_base64url_encode(public),
        serviceConfigurationOriginal="{}", serviceConfigurationSha256=subject.sha(b"{}"),
        bootIdDigest=digest("boot"), issuedAtBoottimeNs=100, deadlineBoottimeNs=200,
        issuedAtUnixNanos=100, expiresAtUnixNanos=200,
        roles={role: dict({name + "Sha256": digest(role + name) for name in subject.ORIGINAL_NAMES},
            exchangeDirectory=dict(device=1, inode=index + 1)) for index, role in enumerate(subject.cohort.ROLES)})
    context = dict(selected=selected, rootPublic=public, service=service,
        static=subject.cohort._static_configuration(service), configurationDigest=digest("config"),
        packageDigest=digest("package"), generationDigest=digest("generation"), generationSequence=0,
        generationInterval=(1, 300),
        generationContext=dict(schema=subject.history.configuration.GENERATION_SCHEMA,
            sequence=0, digest=digest("generation"), predecessorDigest=None, minimumRollbackSequence=0,
            operationManifestDigest=subject.cohort.authority.OPERATION_MANIFEST_DIGEST,
            configurationPayloadBindings=[], configurationBindingDigest=digest("binding"),
            roleBindingDigests=service["roleBindingDigests"]),
        identities={role: (digest(role + "-manifest"), digest(role + "-request")) for role in subject.cohort.ROLES})
    return key, selected, context


def verify(raw, context, key, now=150):
    return subject.cohort._verify_cohort_against_scope(held_bytes=raw, held_digest=context["configurationDigest"],
        held_key=key.public_key(), static_configuration=context["static"], generation_sequence=context["generationSequence"],
        generation_digest=context["generationDigest"], package_digest=context["packageDigest"],
        local_binding=("verifier", *context["identities"]["verifier"]), evaluation_epoch_ns=now)


def retained_fixture():
    # Public synthetic codec context, not a VerifiedArtifactPackage/live owner.
    key, selected, context = fixture()
    selected.update(schema=subject.RETAINED_SCHEMA, rootDelegation=subject.RETAINED_DELEGATION,
        historicalArchiveSelection=subject.RETAINED_HISTORY,
        runtimeValidity=dict(issuedAtEpochNs=100, expiresAtEpochNs=200))
    context["generationSequence"] = 1
    context["generationContext"].update(sequence=1, predecessorDigest=digest("prior"))
    payload = dict(schema=subject.history.SCHEMA, purpose=subject.history.PURPOSE,
        sourceRevision=subject.cohort.authority.SOURCE_REVISION,
        configurationDigest=context["configurationDigest"], generationDigest=context["generationDigest"],
        issuedAtEpochNs=120, expiresAtEpochNs=180, entries=[])
    select_archive(context, key, payload)
    return key, selected, context


def select_archive(context, key, payload):
    envelope = dict(schema=subject.history.SCHEMA, payload=payload,
        signature=subject.spec.strict_base64url_encode(key.sign(subject.cohort._domain_digest(
            subject.history.SCHEMA, subject.canonical(payload)).encode("ascii"))))
    context["archiveOriginal"] = subject.canonical(envelope)
    context["selected"]["historicalArchiveSha256"] = subject.sha(context["archiveOriginal"])


class LocalCohortTests(unittest.TestCase):
    def test_scope_inventory_bytes_reused_only_within_one_verification(self):
        # Actual signed codec admission, not live child or database evidence.
        results = []
        for version in ("first", "second"):
            key, _, context = fixture()
            context["service"]["packageVersions"] = {"synthetic-test": version}
            context["static"] = subject.cohort._static_configuration(context["service"])
            raw, _ = subject._signed_cohort(context, key, now_unix_ns=150)
            packages = context["static"][2]
            with patch.object(subject.cohort, "canonical_json_bytes",
                    wraps=subject.cohort.canonical_json_bytes) as serialize, \
                 patch.object(subject.cohort, "_verify_signature",
                    wraps=subject.cohort._verify_signature) as signatures:
                admitted, payload, _ = verify(raw, context, key)
            self.assertEqual(sum(call.args[0] is packages for call in serialize.call_args_list), 1)
            self.assertEqual([call.args[0]["schema"] for call in signatures.call_args_list],
                [subject.cohort.SCHEMA, *[subject.cohort.RECEIPT_SCHEMA] * 5])
            self.assertEqual(admitted.cohort_bytes, raw)
            self.assertEqual(admitted.receipts, tuple((row["payload"]["role"], subject.canonical(row),
                subject.cohort._domain_digest(subject.cohort.RECEIPT_SCHEMA, subject.canonical(row)))
                for row in payload["receipts"]))
            results.append(admitted)
        self.assertNotEqual(results[0].cohort_digest, results[1].cohort_digest)
        self.assertNotEqual(results[0].receipts, results[1].receipts)

    def test_scope_inventory_reuse_keeps_signature_refusal_order(self):
        key, _, context = fixture()
        raw, _ = subject._signed_cohort(context, key, now_unix_ns=150)
        for index in (0, 4):
            envelope = subject.document(raw, subject.cohort.MAX_BYTES)
            envelope["payload"]["receipts"][index]["signature"] = subject.spec.strict_base64url_encode(bytes(64))
            envelope["signature"] = subject.spec.strict_base64url_encode(key.sign(subject.cohort._domain_digest(
                subject.cohort.SCHEMA, subject.canonical(envelope["payload"])).encode("ascii")))
            changed = subject.canonical(envelope)
            packages = context["static"][2]
            with self.subTest(receipt=index), \
                 patch.object(subject.cohort, "canonical_json_bytes",
                    wraps=subject.cohort.canonical_json_bytes) as serialize, \
                 patch.object(subject.cohort, "_verify_signature",
                    wraps=subject.cohort._verify_signature) as signatures:
                with self.assertRaisesRegex(subject.cohort.AttestationCohortError,
                        "attestation root signature is invalid"):
                    verify(changed, context, key)
            self.assertEqual(signatures.call_count, index + 2)
            self.assertEqual(sum(call.args[0] is packages for call in serialize.call_args_list),
                0 if index == 0 else 1)

    def _prepare_payload_codec(self, payload, declared, manifest, key):
        # Execute only the actual byte equality/signature/digest expressions.
        # This synthetic codec control does not claim package or live admission.
        tree = ast.parse(Path(subject.__file__).read_text())
        prepare = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "prepare")
        loop = next(node for node in prepare.body if isinstance(node, ast.For) and ast.unparse(node.target) == "role")
        assignments = {ast.unparse(node.targets[0]): node for node in loop.body if isinstance(node, ast.Assign)}
        raw = assignments["payload_raw"]
        self.assertLess(assignments["context"].lineno, raw.lineno)
        self.assertEqual(ast.unparse(assignments["context"].value.func), "pair.prepare")
        manifest_at = loop.body.index(assignments["manifest"])
        body = [raw, *loop.body[manifest_at:manifest_at + 3]]
        identity = assignments["identities[role]"].value.elts[0]
        namespace = dict(subject.__dict__, payload=payload, declared=declared,
            source={"manifest": manifest}, root=key.public_key())
        exec(compile(ast.Module(body=body, type_ignores=[]), subject.__file__, "exec"), namespace)
        return eval(compile(ast.Expression(identity), subject.__file__, "eval"), namespace)

    def test_prepare_reuses_canonical_payload_bytes_only_within_invocation(self):
        key = Ed25519PrivateKey.from_private_bytes(b"\x24" * 32)
        results = []
        for label in ("first", "second"):
            payload = {"publicSyntheticPayload": label}
            raw = subject.canonical(payload)
            declared = {"payloadOriginal": raw.decode("ascii")}
            manifest = subject.canonical(dict(schema=subject.launch.LAUNCH_MANIFEST_SCHEMA,
                payload=payload, signature=subject.spec.strict_base64url_encode(key.sign(
                    subject.launch._domain_digest(subject.launch.LAUNCH_MANIFEST_SCHEMA, raw).encode("ascii")))))
            expected = subject.launch._domain_digest(subject.launch.LAUNCH_PAYLOAD_SCHEMA, raw)
            with patch.object(subject, "canonical", wraps=subject.canonical) as serialize:
                result = self._prepare_payload_codec(payload, declared, manifest, key)
                # The manifest equality still serializes its independently
                # parsed payload; neither domain hash serializes it again.
                serialize.assert_called_once_with(payload)
            self.assertEqual(result, expected)
            results.append(result)
        self.assertNotEqual(*results)

    def test_prepare_payload_reuse_keeps_manifest_and_signature_refusals(self):
        key = Ed25519PrivateKey.from_private_bytes(b"\x24" * 32)
        payload = {"publicSyntheticPayload": "original"}
        raw = subject.canonical(payload)
        declared = {"payloadOriginal": raw.decode("ascii")}
        envelope = dict(schema=subject.launch.LAUNCH_MANIFEST_SCHEMA, payload=payload,
            signature=subject.spec.strict_base64url_encode(key.sign(subject.launch._domain_digest(
                subject.launch.LAUNCH_MANIFEST_SCHEMA, raw).encode("ascii"))))
        changed = deepcopy(envelope)
        changed["payload"]["publicSyntheticPayload"] = "different"
        with self.assertRaises(ValueError):
            self._prepare_payload_codec(payload, declared, subject.canonical(changed), key)
        changed = deepcopy(envelope)
        changed["signature"] = subject.spec.strict_base64url_encode(bytes(64))
        from cryptography.exceptions import InvalidSignature
        with self.assertRaises(InvalidSignature):
            self._prepare_payload_codec(payload, declared, subject.canonical(changed), key)

    def test_retained_v4_requires_exact_selection_pin_and_original(self):
        _, selected, context = retained_fixture()
        self.assertEqual(subject.approval(subject.canonical(selected), boot=digest("boot"),
            now_boottime_ns=150, now_unix_ns=150), selected)
        for mutate in (lambda value: value.pop("historicalArchiveSha256"),
                       lambda value: value.update(historicalArchiveSha256="unselected"),
                       lambda value: value.update(rootDelegation=subject.DELEGATION),
                       lambda value: value.update(historicalArchiveSelection=subject.INITIAL_HISTORY),
                       lambda value: value.update(extra=True)):
            bad = deepcopy(selected); mutate(bad)
            with self.assertRaises(ValueError):
                subject.approval(subject.canonical(bad), boot=digest("boot"), now_boottime_ns=150, now_unix_ns=150)
        for schema in (subject.SCHEMA, subject.RUNTIME_SCHEMA):
            _, legacy, _ = fixture()
            legacy["schema"] = schema
            if schema == subject.RUNTIME_SCHEMA:
                legacy["runtimeValidity"] = dict(issuedAtEpochNs=100, expiresAtEpochNs=200)
            with self.assertRaises(ValueError): subject._archive_original(legacy, context["archiveOriginal"])
            legacy["historicalArchiveSha256"] = selected["historicalArchiveSha256"]
            with self.assertRaises(ValueError):
                subject.approval(subject.canonical(legacy), boot=digest("boot"), now_boottime_ns=150, now_unix_ns=150)
        for original in (None, b"", context["archiveOriginal"] + b" ", b"x" * (subject.history.MAX_BYTES + 1)):
            with self.assertRaises(ValueError): subject._archive_original(selected, original)

    def test_retained_archive_is_consumed_unchanged_and_not_resigned(self):
        key, _, context = retained_fixture()
        signed_messages = []
        class CountingKey:
            def public_key(self): return key.public_key()
            def sign(self, raw):
                signed_messages.append(raw)
                return key.sign(raw)
        with patch.object(subject.history, "_admit_on_startup", wraps=subject.history._admit_on_startup) as admit:
            _, _, delivery = subject._signed_runtime_evidence(context, CountingKey(), now_unix_ns=150)
        self.assertEqual(len(signed_messages), 6)  # Five receipts and cohort; never the archive.
        self.assertEqual(subject.canonical(subject.document(delivery, subject.io.MAX_PUBLIC)["historicalArchive"]),
            context["archiveOriginal"])
        admit.assert_called_once()
        self.assertEqual(admit.call_args.kwargs["original_bytes"], context["archiveOriginal"])
        snapshot = admit.call_args.kwargs["current_snapshot"]
        self.assertEqual(snapshot.generation["sequence"], 1)
        self.assertEqual(snapshot.runtime_role_identities["generationSequence"], 1)
        self.assertEqual((snapshot.valid_from_epoch_ns, snapshot.valid_until_epoch_ns), (100, 200))

    def test_retained_wrong_root_scope_or_interval_refuses_before_signing(self):
        for change in (dict(configurationDigest=digest("wrong-config")), dict(generationDigest=digest("wrong-generation")),
                       dict(issuedAtEpochNs=99), dict(issuedAtEpochNs=151), dict(expiresAtEpochNs=150),
                       dict(expiresAtEpochNs=201), dict(purpose="other"), dict(sourceRevision="other")):
            key, _, context = retained_fixture()
            payload = subject.document(context["archiveOriginal"], subject.history.MAX_BYTES)["payload"]
            payload.update(change); select_archive(context, key, payload)
            with self.subTest(change=change), patch.object(subject, "_signed_cohort") as signed:
                with self.assertRaises(ValueError): subject._signed_runtime_evidence(context, key, now_unix_ns=150)
                signed.assert_not_called()
        key, _, context = retained_fixture()
        payload = subject.document(context["archiveOriginal"], subject.history.MAX_BYTES)["payload"]
        select_archive(context, Ed25519PrivateKey.from_private_bytes(b"\x23" * 32), payload)
        with patch.object(subject, "_signed_cohort") as signed:
            with self.assertRaises(ValueError): subject._signed_runtime_evidence(context, key, now_unix_ns=150)
            signed.assert_not_called()

    def test_retained_invalid_entries_reach_real_admission_and_never_become_empty(self):
        key, _, context = retained_fixture()
        payload = subject.document(context["archiveOriginal"], subject.history.MAX_BYTES)["payload"]
        payload["entries"] = [{"not": "an admitted historical entry"}]
        select_archive(context, key, payload)
        with patch.object(subject.history, "_admit_on_startup", wraps=subject.history._admit_on_startup) as admit:
            with self.assertRaises(ValueError): subject._signed_runtime_evidence(context, key, now_unix_ns=150)
            admit.assert_called_once()
            self.assertEqual(admit.call_args.kwargs["original_bytes"], context["archiveOriginal"])

    def test_retained_readonly_fd_identity_bytes_expiry_and_extra_input_controls(self):
        # Actual sealed public memfd custody only, not a live cohort owner.
        _, selected, context = retained_fixture()
        writer = os.memfd_create("public-history-unit", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        reader = None
        try:
            raw = context["archiveOriginal"]
            self.assertEqual(os.write(writer, raw), len(raw))
            os.fchmod(writer, 0o400)
            fcntl.fcntl(writer, fcntl.F_ADD_SEALS, subject.io.SEALS)
            reader = os.open("/proc/self/fd/" + str(writer), os.O_RDONLY | os.O_CLOEXEC)
            owner = object.__new__(subject.LocalCohortIssuer)
            owner.value, owner.archive_fd, owner.archive_raw = selected, reader, raw
            owner.archive_identity = subject.io._input(reader, subject.history.MAX_BYTES)
            owner.archive_interval = (120, 180)
            with patch.object(subject.time, "time_ns", return_value=150):
                owner._check_archive()
                for changes in (dict(archive_fd=writer), dict(archive_raw=raw + b" "),
                                dict(archive_identity=()), dict(value=dict(schema=subject.SCHEMA))):
                    previous = {name: getattr(owner, name) for name in changes}
                    for name, value in changes.items(): setattr(owner, name, value)
                    with self.assertRaises(ValueError): owner._check_archive()
                    for name, value in previous.items(): setattr(owner, name, value)
            with patch.object(subject.time, "time_ns", return_value=180):
                with self.assertRaises(ValueError): owner._check_archive()
        finally:
            if reader is not None: os.close(reader)
            os.close(writer)

    def test_runtime_v3_is_prospective_not_extended_issuance(self):
        _, value, _ = fixture()
        value.update(schema=subject.RUNTIME_SCHEMA,
            runtimeValidity=dict(issuedAtEpochNs=100, expiresAtEpochNs=250))
        self.assertEqual(subject.approval(subject.canonical(value), boot=digest("boot"),
            now_boottime_ns=150, now_unix_ns=150), value)
        self.assertEqual(subject.runtime_interval(value), (100, 250))
        for boot, epoch in ((200, 150), (150, 200), (225, 225)):
            with self.assertRaises(ValueError):
                subject.approval(subject.canonical(value), boot=digest("boot"),
                    now_boottime_ns=boot, now_unix_ns=epoch)
        value["schema"] = subject.SCHEMA
        with self.assertRaises(ValueError):
            subject.approval(subject.canonical(value), boot=digest("boot"), now_boottime_ns=150, now_unix_ns=150)

    def test_runtime_v3_existing_signatures_remain_valid_after_setup(self):
        key, _, context = fixture()
        context["selected"].update(schema=subject.RUNTIME_SCHEMA,
            runtimeValidity=dict(issuedAtEpochNs=100, expiresAtEpochNs=250))
        raw, _, delivery_raw = subject._signed_runtime_evidence(context, key, now_unix_ns=150)
        _, _, receipts = verify(raw, context, key, now=225)
        self.assertTrue(all((row["issuedAtEpochNs"], row["expiresAtEpochNs"]) == (100, 250) for row in receipts))
        self.assertTrue(all(row["coLocated"] and not row["nativeStageZero"] for row in receipts))
        archive = subject.document(delivery_raw, subject.pair.LATE_LIMITS["evidence.json"])["historicalArchive"]
        self.assertEqual(archive["payload"]["expiresAtEpochNs"], 250)
        with self.assertRaises(ValueError):
            verify(raw, context, key, now=250)

    def test_runtime_v3_closed_bounds_and_short_issuance_cap(self):
        _, original, _ = fixture()
        original.update(schema=subject.RUNTIME_SCHEMA,
            runtimeValidity=dict(issuedAtEpochNs=100, expiresAtEpochNs=250))
        for mutate in (lambda v: v["runtimeValidity"].update(issuedAtEpochNs=101),
                       lambda v: v["runtimeValidity"].update(issuedAtEpochNs=True),
                       lambda v: v["runtimeValidity"].update(expiresAtEpochNs=199),
                       lambda v: v["runtimeValidity"].update(expiresAtEpochNs=101 + subject.MAX_RUNTIME_NS),
                       lambda v: v["runtimeValidity"].update(renew=True),
                       lambda v: v.update(deadlineBoottimeNs=100 + limits.LOCAL_SETUP_MAX_NS + 1),
                       lambda v: v.update(expiresAtUnixNanos=100 + limits.LOCAL_SETUP_MAX_NS + 1)):
            value = deepcopy(original); mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                subject.approval(subject.canonical(value), boot=digest("boot"), now_boottime_ns=150, now_unix_ns=150)

    def test_new_local_setup_and_session_bounds_remain_original_and_expire_exactly(self):
        _, value, _ = fixture()
        self.assertEqual(subject.MAX_RUNTIME_NS, limits.LOCAL_SESSION_MAX_NS)
        value.update(schema=subject.RUNTIME_SCHEMA,
            deadlineBoottimeNs=100 + limits.LOCAL_SETUP_MAX_NS,
            expiresAtUnixNanos=100 + limits.LOCAL_SETUP_MAX_NS,
            runtimeValidity=dict(issuedAtEpochNs=100, expiresAtEpochNs=100 + limits.LOCAL_SESSION_MAX_NS))
        raw = subject.canonical(value)
        for now in (300_000_000_101, value["expiresAtUnixNanos"] - 1):
            with self.subTest(now=now):
                self.assertEqual(subject.approval(raw, boot=digest("boot"),
                    now_boottime_ns=now, now_unix_ns=now), value)
        for boot, monotonic, epoch in ((digest("foreign"), 150, 150),
                (digest("boot"), value["deadlineBoottimeNs"], 150),
                (digest("boot"), 150, value["expiresAtUnixNanos"]),
                (digest("boot"), True, 150), (digest("boot"), 150, True)):
            with self.subTest(boot=boot, monotonic=monotonic, epoch=epoch), self.assertRaises(ValueError):
                subject.approval(raw, boot=boot, now_boottime_ns=monotonic, now_unix_ns=epoch)
        for change in (lambda v: v.update(deadlineBoottimeNs=v["deadlineBoottimeNs"] + 1),
                lambda v: v.update(expiresAtUnixNanos=v["expiresAtUnixNanos"] + 1),
                lambda v: v["runtimeValidity"].update(expiresAtEpochNs=101 + limits.LOCAL_SESSION_MAX_NS),
                lambda v: v["runtimeValidity"].update(issuedAtEpochNs=101),
                lambda v: v["runtimeValidity"].update(expiresAtEpochNs=True)):
            bad = deepcopy(value); change(bad)
            with self.subTest(value=bad), self.assertRaises(ValueError):
                subject.approval(subject.canonical(bad), boot=digest("boot"), now_boottime_ns=150, now_unix_ns=150)

    def test_closed_five_role_approval(self):
        _, value, _ = fixture()
        result = subject.approval(subject.canonical(value), boot=digest("boot"), now_boottime_ns=150, now_unix_ns=150)
        self.assertEqual(result, value)
        for mutate in (lambda v: v["roles"].pop("verifier"),
                       lambda v: v["roles"].update(runtime=deepcopy(v["roles"]["issuer"])),
                       lambda v: v.update(rootDelegation="*"),
                       lambda v: v.update(schema="serverware.authorityTrustedHostLocalCohortApproval/v1"),
                       lambda v: v.pop("historicalArchiveSelection"),
                       lambda v: v.update(historicalArchiveSelection="discard-prior-history"),
                       lambda v: v["roles"]["verifier"].update(exchangeDirectory=v["roles"]["issuer"]["exchangeDirectory"])):
            bad = deepcopy(value); mutate(bad)
            with self.assertRaises(ValueError):
                subject.approval(subject.canonical(bad), boot=digest("boot"), now_boottime_ns=150, now_unix_ns=150)

    def test_original_caps_and_boot_are_not_renewed(self):
        _, value, _ = fixture()
        for boot, monotonic, epoch in ((digest("other"), 150, 150), (digest("boot"), 200, 150),
                                       (digest("boot"), 150, 200), (digest("boot"), 99, 150)):
            with self.assertRaises(ValueError):
                subject.approval(subject.canonical(value), boot=boot, now_boottime_ns=monotonic, now_unix_ns=epoch)
        value["issuedAtBoottimeNs"] = True
        with self.assertRaises(ValueError):
            subject.approval(subject.canonical(value), boot=digest("boot"), now_boottime_ns=150, now_unix_ns=150)

    def test_existing_six_signatures_and_verifier_original(self):
        key, _, context = fixture()
        raw, verifier = subject._signed_cohort(context, key, now_unix_ns=150)
        admitted, _, receipts = verify(raw, context, key)
        self.assertEqual(tuple(row["role"] for row in receipts), subject.cohort.ROLES)
        self.assertEqual(verifier, next(row[1] for row in admitted.receipts if row[0] == "verifier"))
        for row in receipts:
            self.assertEqual((row["issuedAtEpochNs"], row["expiresAtEpochNs"]), (100, 200))
            self.assertIs(row["coLocated"], True)
            self.assertIs(row["nativeStageZero"], False)

    def test_separate_root_and_expired_receipts_refuse(self):
        key, _, context = fixture()
        with self.assertRaises(ValueError):
            subject._signed_cohort(context, Ed25519PrivateKey.from_private_bytes(b"\x22" * 32), now_unix_ns=150)
        with self.assertRaises(ValueError):
            subject._signed_cohort(context, key, now_unix_ns=200)

    def test_dynamic_closure_and_local_binding_not_static_alias(self):
        key, _, context = fixture()
        raw, _ = subject._signed_cohort(context, key, now_unix_ns=150)
        changed = deepcopy(context)
        changed["identities"]["verifier"] = (digest("other-manifest"), context["identities"]["verifier"][1])
        with self.assertRaises(ValueError):
            verify(raw, changed, key)
        envelope = subject.document(raw, subject.cohort.MAX_BYTES)
        receipt = envelope["payload"]["receipts"][0]
        receipt["payload"]["runtimeClosureDigest"] = digest("static-closure-not-dynamic")
        for value in (receipt, envelope):
            value["signature"] = subject.spec.strict_base64url_encode(key.sign(subject.cohort._domain_digest(
                value["schema"], subject.canonical(value["payload"])).encode("ascii")))
        with self.assertRaises(ValueError):
            verify(subject.canonical(envelope), context, key)

    def test_nonlocal_claims_refused_even_with_signature(self):
        key, _, context = fixture()
        raw, _ = subject._signed_cohort(context, key, now_unix_ns=150)
        envelope = subject.document(raw, subject.cohort.MAX_BYTES)
        receipt = envelope["payload"]["receipts"][0]
        receipt["payload"]["teeVerified"] = True
        for value in (receipt, envelope):
            value["signature"] = subject.spec.strict_base64url_encode(key.sign(subject.cohort._domain_digest(
                value["schema"], subject.canonical(value["payload"])).encode("ascii")))
        with self.assertRaises(ValueError):
            verify(subject.canonical(envelope), context, key)

    def test_existing_runtime_delivery_contains_real_signed_empty_initial_archive(self):
        key, _, context = fixture()
        raw, verifier, delivery_raw = subject._signed_runtime_evidence(context, key, now_unix_ns=150)
        delivery = subject.document(delivery_raw, subject.pair.LATE_LIMITS["evidence.json"])
        self.assertEqual(set(delivery), {"schema", "currentCohort", "historicalArchive"})
        self.assertEqual(delivery["schema"], "serverware.authorityRuntimeEvidence/v1")
        self.assertEqual(subject.canonical(delivery["currentCohort"]), raw)
        self.assertEqual(verifier, next(row[1] for row in verify(raw, context, key)[0].receipts if row[0] == "verifier"))
        archive = delivery["historicalArchive"]
        subject.cohort._verify_signature(archive, key.public_key())
        self.assertEqual(archive["payload"]["entries"], [])
        self.assertEqual(archive["payload"]["configurationDigest"], context["configurationDigest"])
        self.assertEqual(archive["payload"]["generationDigest"], context["generationDigest"])
        self.assertEqual((archive["payload"]["issuedAtEpochNs"], archive["payload"]["expiresAtEpochNs"]), (100, 200))

    def test_empty_history_cannot_discard_later_generation_or_extend_interval(self):
        key, _, original = fixture()
        for mutate in (lambda c: c.update(generationSequence=1),
                       lambda c: c["generationContext"].update(sequence=1),
                       lambda c: c["generationContext"].update(predecessorDigest=digest("prior")),
                       lambda c: c["generationContext"].update(minimumRollbackSequence=1),
                       lambda c: c.update(generationInterval=(110, 190)),
                       lambda c: c["selected"].update(historicalArchiveSelection="implicit-empty")):
            context = deepcopy(original); mutate(context)
            with self.assertRaises(ValueError):
                subject._signed_runtime_evidence(context, key, now_unix_ns=150)
        with self.assertRaises(ValueError):
            subject._signed_runtime_evidence(original, key, now_unix_ns=200)

    def test_actual_service_delivery_parser_reaches_refusing_guard_only_for_wrapper(self):
        # Exercise the real outer consumer, but deliberately refuse at the
        # first live guard. This is not a mocked successful process admission.
        # Import through the existing non-authority control-plane mode; do not
        # pretend a measured role has an active launch guard.
        with patch.dict("os.environ", {"SERVERWARE_PROCESS_MODE": "serverware-control-plane"}):
            from serverware.authority_service import MeasuredConfiguration, AuthorityServiceError
        key, _, context = fixture()
        cohort_raw, _, delivery_raw = subject._signed_runtime_evidence(context, key, now_unix_ns=150)
        with patch.object(subject.cohort.guard, "require_active", side_effect=ValueError("deliberate guard refusal")) as guard:
            with self.assertRaises(AuthorityServiceError):
                MeasuredConfiguration._verify_trusted_host_local_attestation(
                    None, role="verifier", attestation_value=cohort_raw)
            guard.assert_not_called()
            with self.assertRaises(AuthorityServiceError):
                MeasuredConfiguration._verify_trusted_host_local_attestation(
                    None, role="verifier", attestation_value=delivery_raw)
            guard.assert_called_once_with("verifier")

    def test_cli_exact_roster_and_no_alias(self):
        argv = ["--approval-fd", "3", "--approval-sha256", digest("approval"), "--signing-key-fd", "4"]
        for index, role in enumerate(cli.ROLES):
            argv += [f"--{role}-approval-fd", str(5 + index * 2), f"--{role}-exchange-directory-fd", str(6 + index * 2)]
        self.assertEqual(set(cli.arguments(argv)["role_inputs"]), set(subject.cohort.ROLES))
        for bad in (argv[:-2], argv + ["--command", "anything"], argv[:-1] + ["3"], argv[:1] + ["03"] + argv[2:]):
            with self.assertRaises(ValueError):
                cli.arguments(bad)

    def test_cli_retained_archive_is_optional_final_canonical_and_distinct(self):
        argv = ["--approval-fd", "3", "--approval-sha256", digest("approval"), "--signing-key-fd", "4"]
        for index, role in enumerate(cli.ROLES):
            argv += [f"--{role}-approval-fd", str(5 + index * 2), f"--{role}-exchange-directory-fd", str(6 + index * 2)]
        legacy = cli.arguments(argv)
        self.assertNotIn("archive_fd", legacy)
        option = ["--historical-archive-fd", "20"]
        self.assertEqual(cli.arguments(argv + option), dict(legacy, archive_fd=20))
        for bad in (option + argv, argv + option + option, argv + option[:1],
                    argv + ["--archive-fd", "20"],
                    *(argv + [option[0], value] for value in
                      [*(str(fd) for fd in range(3, 15)), "2", "020", "+20", "20 ", str(2**31)])):
            with self.subTest(argv=bad), self.assertRaises(ValueError):
                cli.arguments(bad)

    def test_source_live_check_sign_release_and_output_order(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalCohortIssuer")
        issue = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "issue")
        publish = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "publish")
        calls = [(node.lineno, ast.unparse(node.func)) for node in ast.walk(issue) if isinstance(node, ast.Call)]
        signed = next(line for line, name in calls if name == "_signed_runtime_evidence")
        live = sorted(line for line, name in calls if name == "self.verify_live")
        self.assertEqual(len(live), 2)
        self.assertLess(live[0], signed)
        self.assertGreater(live[1], signed)
        self.assertNotIn("self.bootstrap_originals", [name for _, name in calls])
        self.assertGreater(next(line for line, name in calls if name == "self._format_bootstrap_originals"), live[-1])
        self.assertNotIn("pair.publish_late_original", [name for _, name in calls])
        bootstrap = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "bootstrap_originals")
        calls = sorted((node.lineno, ast.unparse(node.func)) for node in ast.walk(bootstrap) if isinstance(node, ast.Call))
        self.assertEqual([name for _, name in calls], ["self.verify_live", "self._format_bootstrap_originals"])
        calls = [(node.lineno, ast.unparse(node.func)) for node in ast.walk(publish) if isinstance(node, ast.Call)]
        self.assertNotIn("_signed_runtime_evidence", [name for _, name in calls])
        live = sorted(line for line, name in calls if name == "self.verify_live")
        self.assertGreater(next(line for line, name in calls if name == "pair.publish_late_original"), live[-1])
        source = ast.unparse(owner)
        self.assertIn("open_observer", source)
        self.assertIn("observer.check_sources() if role in self.released else observer.check()", source)
        self.assertIn("if role in self.released:", source)
        self.assertIn("'evidence.json', self.delivery_raw", source)
        self.assertNotIn("os.kill", source)
        cli_source = Path(cli.__file__).read_text()
        self.assertLess(cli_source.index("owner.publish()"), cli_source.index("io.write_public(owner.verifier_original()"))

    def _held_codec_owner(self):
        # State/codec unit fixture only. The no-op live check is not runtime
        # evidence and this fixture never performs a real publication.
        key, _, context = fixture()
        owner = object.__new__(subject.LocalCohortIssuer)
        owner.used = owner.issued = True
        owner.publication_started = False
        owner.released = set()
        owner.verify_live = lambda: None
        owner.cohort_raw, owner.verifier_raw, owner.delivery_raw = subject._signed_runtime_evidence(context, key, now_unix_ns=150)
        return owner

    def test_held_bootstrap_returns_exact_independent_receipt_copies(self):
        owner = self._held_codec_owner()
        result = owner.bootstrap_originals()
        self.assertEqual(result["runtimeEvidenceOriginal"], owner.delivery_raw)
        self.assertEqual(result["cohortOriginal"], owner.cohort_raw)
        self.assertEqual(result["receiptOriginals"]["verifier"], owner.verifier_raw)
        self.assertEqual(set(result["receiptOriginals"]), set(subject.cohort.ROLES))
        result["receiptOriginals"].clear()
        self.assertEqual(len(owner.bootstrap_originals()["receiptOriginals"]), 5)
        self.assertFalse(owner.released or owner.publication_started)

    def test_held_bootstrap_refuses_unsigned_released_and_stale_state(self):
        for change in (dict(issued=False), dict(publication_started=True),
                       dict(released={"executor"}), dict(cohort_raw=None), dict(delivery_raw=None),
                       dict(verifier_raw=b"different synthetic receipt")):
            owner = self._held_codec_owner()
            for name, value in change.items():
                setattr(owner, name, value)
            with self.assertRaises(ValueError):
                owner.bootstrap_originals()
        owner = self._held_codec_owner()
        with patch.object(owner, "verify_live", side_effect=ValueError("expired or child changed")):
            with self.assertRaises(ValueError):
                owner.bootstrap_originals()

    def _unissued_codec_owner(self):
        # Synthetic control-flow owner: preparation/key acquisition/live
        # measurement are substituted below, never evidence of admission.
        key, _, context = fixture()
        owner = self._held_codec_owner()
        owner.used = owner.issued = False
        owner.cohort_raw = owner.verifier_raw = owner.delivery_raw = None
        owner.raw, owner.originals, owner.boot, owner.key_fd = b"synthetic approval", {}, digest("boot"), -1
        owner.archive_raw = None
        return owner, key, context

    def test_synthetic_issue_two_checks_public_bootstrap_rechecks_and_single_use(self):
        owner, key, context = self._unissued_codec_owner()
        with patch.object(subject, "prepare", return_value=context), \
             patch.object(subject.io, "signing_key", return_value=key), \
             patch.object(subject.io, "_clock", return_value=150), \
             patch.object(subject.time, "time_ns", return_value=150), \
             patch.object(subject, "_signed_runtime_evidence", wraps=subject._signed_runtime_evidence) as signed, \
             patch.object(owner, "verify_live") as live:
            result = owner.issue()
            self.assertEqual(live.call_count, 2)
            self.assertEqual(result, owner.bootstrap_originals())
            self.assertEqual(live.call_count, 3)
            self.assertTrue(owner.used and owner.issued)
            self.assertFalse(owner.publication_started or owner.released)
            with self.assertRaises(subject.LocalCohortError):
                owner.issue()
            self.assertEqual(live.call_count, 3)
            signed.assert_called_once()

    def test_synthetic_issue_pre_and_post_sign_refusal_remain_single_use(self):
        for fail_at in (1, 2):
            owner, key, context = self._unissued_codec_owner()
            with self.subTest(fail_at=fail_at), \
                 patch.object(subject, "prepare", return_value=context), \
                 patch.object(subject.io, "signing_key", return_value=key), \
                 patch.object(subject.io, "_clock", return_value=150), \
                 patch.object(subject.time, "time_ns", return_value=150), \
                 patch.object(subject, "_signed_runtime_evidence", wraps=subject._signed_runtime_evidence) as signed, \
                 patch.object(owner, "verify_live", side_effect=[None] * (fail_at - 1) + [ValueError("synthetic refusal")]) as live, \
                 patch.object(owner, "_format_bootstrap_originals") as formatted:
                with self.assertRaises(subject.LocalCohortError):
                    owner.issue()
                self.assertTrue(owner.used)
                self.assertFalse(owner.issued or owner.publication_started or owner.released)
                self.assertEqual(live.call_count, fail_at)
                self.assertEqual(signed.call_count, fail_at - 1)
                formatted.assert_not_called()
                with self.assertRaises(subject.LocalCohortError):
                    owner.issue()
                self.assertEqual(live.call_count, fail_at)
                self.assertEqual(signed.call_count, fail_at - 1)

    def test_held_publication_cannot_resign_or_retry_a_failed_release(self):
        from types import SimpleNamespace
        owner = self._held_codec_owner()
        owner.observers = {role: SimpleNamespace(directory=-1, _hold=None) for role in subject.cohort.ROLES}
        owner.named = []
        owner.check = lambda: None
        with patch.object(owner, "issue", side_effect=AssertionError("must not renew")) as issue, \
             patch.object(subject.pair, "publish_late_original", side_effect=ValueError("deliberate release refusal")) as publish:
            with self.assertRaises(subject.LocalCohortError):
                owner.publish()
            self.assertTrue(owner.publication_started)
            issue.assert_not_called()
            publish.assert_called_once()
            self.assertEqual(publish.call_args.args[2], owner.delivery_raw)
            with self.assertRaises(subject.LocalCohortError):
                owner.publish()
            publish.assert_called_once()


if __name__ == "__main__":
    unittest.main()

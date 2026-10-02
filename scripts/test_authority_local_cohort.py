#!/usr/bin/env python3
"""Synthetic receipt codec/source controls, not live cohort admission."""
from copy import deepcopy
from pathlib import Path
import ast
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_local_cohort as subject
from scripts.authority import local_cohort as cli


def digest(label):
    return subject.sha(label.encode("ascii"))


def fixture():
    # Explicit synthetic codec fixture. No actual owner or VerifiedArtifactPackage
    # is created, and this is never passed off as a positive producer run.
    key = Ed25519PrivateKey.from_private_bytes(b"\x21" * 32)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    service = dict(sourceRevision=subject.cohort.authority.SOURCE_REVISION,
        roles={role: dict(processMode="policy-authority-" + role,
            measurementDigest=digest(role + "-measurement"), responseSigningSpkiDigest=digest(role + "-response"))
            for role in subject.cohort.ROLES},
        roleBindingDigests={role: digest(role + "-binding") for role in subject.cohort.ROLES},
        packageVersions={"synthetic-test": "1"},
        credentialReleaseTrust=dict(schema="serverware.trustedHostLocalCredentialReleaseTrust/v1",
            trustMode="trusted-host-local", maximumReceiptAgeNs=200),
        issuerCredentialIssuanceDigest=digest("issuer-issuance"), executorCredentialIssuanceDigest=digest("executor-issuance"))
    selected = dict(schema=subject.SCHEMA, purpose=subject.PURPOSE, rootDelegation=subject.DELEGATION,
        configurationRootPublicKeyBase64Url=subject.spec.strict_base64url_encode(public),
        serviceConfigurationOriginal="{}", serviceConfigurationSha256=subject.sha(b"{}"),
        bootIdDigest=digest("boot"), issuedAtBoottimeNs=100, deadlineBoottimeNs=200,
        issuedAtUnixNanos=100, expiresAtUnixNanos=200,
        roles={role: dict({name + "Sha256": digest(role + name) for name in subject.ORIGINAL_NAMES},
            exchangeDirectory=dict(device=1, inode=index + 1)) for index, role in enumerate(subject.cohort.ROLES)})
    context = dict(selected=selected, rootPublic=public, service=service,
        static=subject.cohort._static_configuration(service), configurationDigest=digest("config"),
        packageDigest=digest("package"), generationDigest=digest("generation"), generationSequence=0,
        identities={role: (digest(role + "-manifest"), digest(role + "-request")) for role in subject.cohort.ROLES})
    return key, selected, context


def verify(raw, context, key, now=150):
    return subject.cohort._verify_cohort_against_scope(held_bytes=raw, held_digest=context["configurationDigest"],
        held_key=key.public_key(), static_configuration=context["static"], generation_sequence=context["generationSequence"],
        generation_digest=context["generationDigest"], package_digest=context["packageDigest"],
        local_binding=("verifier", *context["identities"]["verifier"]), evaluation_epoch_ns=now)


class LocalCohortTests(unittest.TestCase):
    def test_closed_five_role_approval(self):
        _, value, _ = fixture()
        result = subject.approval(subject.canonical(value), boot=digest("boot"), now_boottime_ns=150, now_unix_ns=150)
        self.assertEqual(result, value)
        for mutate in (lambda v: v["roles"].pop("verifier"),
                       lambda v: v["roles"].update(runtime=deepcopy(v["roles"]["issuer"])),
                       lambda v: v.update(rootDelegation="*"),
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

    def test_cli_exact_roster_and_no_alias(self):
        argv = ["--approval-fd", "3", "--approval-sha256", digest("approval"), "--signing-key-fd", "4"]
        for index, role in enumerate(cli.ROLES):
            argv += [f"--{role}-approval-fd", str(5 + index * 2), f"--{role}-exchange-directory-fd", str(6 + index * 2)]
        self.assertEqual(set(cli.arguments(argv)["role_inputs"]), set(subject.cohort.ROLES))
        for bad in (argv[:-2], argv + ["--command", "anything"], argv[:-1] + ["3"], argv[:1] + ["03"] + argv[2:]):
            with self.assertRaises(ValueError):
                cli.arguments(bad)

    def test_source_live_check_sign_release_and_output_order(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalCohortIssuer")
        publish = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "publish")
        calls = [(node.lineno, ast.unparse(node.func)) for node in ast.walk(publish) if isinstance(node, ast.Call)]
        signed = next(line for line, name in calls if name == "_signed_cohort")
        live = sorted(line for line, name in calls if name == "self.verify_live")
        self.assertLess(live[0], signed)
        self.assertGreater(live[1], signed)
        self.assertGreater(next(line for line, name in calls if name == "pair.publish_late_original"), live[1])
        source = ast.unparse(owner)
        self.assertIn("open_observer", source)
        self.assertIn("observer.check_sources() if role in self.released else observer.check()", source)
        self.assertIn("if role in self.released:", source)
        self.assertNotIn("os.kill", source)
        cli_source = Path(cli.__file__).read_text()
        self.assertLess(cli_source.index("owner.publish()"), cli_source.index("io.write_public(owner.verifier_original()"))


if __name__ == "__main__":
    unittest.main()

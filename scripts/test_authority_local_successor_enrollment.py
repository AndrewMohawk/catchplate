#!/usr/bin/env python3
"""Synthetic crypto/source controls; not live source custody or DB installation."""
import ast
import copy
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import local_successor_enrollment as cli
from scripts.test_authority_local_database_credentials import fixture as tls_fixture
from catchplate import authority_local_successor_enrollment as local


def fixture():
    tls = tls_fixture(now_unix_ns=time.time_ns())
    key = Ed25519PrivateKey.from_private_bytes(b"S" * 32)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    root = Path(__file__).resolve().parents[1]
    files = {name: (root / name).read_bytes() for name in local.SOURCE_PATHS}
    selected = dict(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE, rootDelegation=local.DELEGATION,
        configurationRootPublicKeyBase64Url=local.spec.strict_base64url_encode(public),
        sourceRoot=dict(device=1, inode=2), sourceFiles={name: dict(size=len(raw), sha256=local.sha(raw)) for name, raw in files.items()},
        issuanceOriginals={name: tls["originals"][name].decode("ascii") for name in local.ROLES},
        bootIdDigest="sha256:" + "a" * 64, issuedAtBoottimeNs=100, deadlineBoottimeNs=1000,
        issuedAtUnixNanos=tls["now_unix_ns"], expiresAtUnixNanos=tls["now_unix_ns"] + 1000)
    clocks = dict(boot=selected["bootIdDigest"], now_boottime_ns=101, now_unix_ns=tls["now_unix_ns"] + 1)
    return dict(selected=selected, clocks=clocks, tls=tls, key=key, public=public)


def signed(source):
    original = local.canonical(source["selected"])
    context = local.prepare(original, **source["clocks"])
    envelopes = {}
    for role in local.ROLES:
        payload = local._payload(context, role)
        envelopes[role] = dict(schema=local.SCHEMA, payload=payload,
            signature=local.spec.strict_base64url_encode(source["key"].sign(local.signature_message(payload))))
    environment, owners = local._projections(envelopes)
    return dict(schema=local.BUNDLE_SCHEMA, approvalOriginal=original.decode("ascii"),
        enrollments=envelopes, environment=environment, ownerBindings=owners)


class ColdSuccessorEnrollmentTests(unittest.TestCase):
    def test_real_synthetic_signatures_produce_exact_eighteen_pins_without_runtime_claim(self):
        source = fixture(); value = signed(source)
        self.assertEqual(local.verify_bundle(local.canonical(value), root_public=source["public"], **source["clocks"]), value)
        self.assertEqual(len(value["environment"]), 18)
        for row in value["enrollments"].values():
            self.assertFalse(row["payload"]["claims"]["hardwareBacked"])
            self.assertFalse(row["payload"]["claims"]["runningProcessObserved"])
            self.assertFalse(row["payload"]["claims"]["completeRuntimeClosure"])

    def test_actual_private_key_must_match_exact_authenticated_role_certificate(self):
        source = fixture(); material = source["tls"]["material"]
        for role in local.ROLES:
            self.assertTrue(local._matching_tls_public(material[role + ".key.pem"], source["tls"]["originals"][role]))
        with self.assertRaises(ValueError):
            local._matching_tls_public(material["successor-issuer.key.pem"], source["tls"]["originals"]["successor-executor"])

    def test_closed_source_and_role_rosters_refuse_substitution(self):
        source = fixture()
        for field in ("sourceFiles", "issuanceOriginals"):
            changed = copy.deepcopy(source["selected"]); changed[field]["extra"] = "not-selected"
            with self.subTest(field=field), self.assertRaises(ValueError):
                local.prepare(local.canonical(changed), **source["clocks"])
        changed = copy.deepcopy(source["selected"])
        changed["issuanceOriginals"]["successor-issuer"] = changed["issuanceOriginals"]["successor-executor"]
        with self.assertRaises(ValueError): local.prepare(local.canonical(changed), **source["clocks"])

    def test_original_clock_boot_and_noncanonical_original_refused(self):
        source = fixture(); raw = local.canonical(source["selected"])
        for clocks in (dict(source["clocks"], now_boottime_ns=1000), dict(source["clocks"], boot="sha256:" + "b" * 64),
                       dict(source["clocks"], now_unix_ns=source["selected"]["expiresAtUnixNanos"])):
            with self.subTest(clocks=clocks), self.assertRaises(ValueError): local.prepare(raw, **clocks)
        with self.assertRaises(ValueError): local.prepare(raw + b"\n", **source["clocks"])

    def test_signature_root_and_domain_are_not_interchangeable(self):
        source = fixture(); value = signed(source)
        with self.assertRaises(ValueError):
            local.verify_bundle(local.canonical(value), root_public=b"X" * 32, **source["clocks"])
        envelope = value["enrollments"]["successor-issuer"]
        envelope["signature"] = local.spec.strict_base64url_encode(source["key"].sign(local.canonical(envelope["payload"])))
        with self.assertRaises(InvalidSignature):
            local.verify_bundle(local.canonical(value), root_public=source["public"], **source["clocks"])

    def test_environment_and_owner_tls_projection_cannot_be_replaced(self):
        source = fixture()
        for field in ("environment", "ownerBindings"):
            value = signed(source); value[field] = {}
            with self.subTest(field=field), self.assertRaises(ValueError):
                local.verify_bundle(local.canonical(value), root_public=source["public"], **source["clocks"])

    def test_cli_fixed_roster_nonalias_and_no_paths_or_key_values(self):
        args = []
        fd = 3
        for name in cli.OPTIONS:
            args += ["--" + name, "sha256:" + "a" * 64 if name == "approval-sha256" else str(fd)]
            if name != "approval-sha256": fd += 1
        self.assertEqual(len(cli.arguments(args)), 7)
        for changed in (args + ["--command", "anything"], args[:-1] + ["3"], args[:-1] + ["/private/key"]):
            with self.assertRaises(ValueError): cli.arguments(changed)

    def test_actual_owner_orders_source_and_private_match_before_signing(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "catchplate/authority_local_successor_enrollment.py").read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalSuccessorColdEnrollment")
        issue = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "issue")
        calls = [node for node in ast.walk(issue) if isinstance(node, ast.Call)]
        matching = next(node.lineno for node in calls if isinstance(node.func, ast.Name) and node.func.id == "_matching_tls_public")
        signing = next(node.lineno for node in calls if isinstance(node.func, ast.Attribute) and node.func.attr == "signing_key")
        measurement = next(node.lineno for node in calls if isinstance(node.func, ast.Name) and node.func.id == "sha")
        self.assertLess(measurement, matching); self.assertLess(matching, signing)


if __name__ == "__main__": unittest.main()

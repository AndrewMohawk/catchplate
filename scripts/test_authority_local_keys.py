#!/usr/bin/env python3
"""Real disposable key-file controls; no authority/custody acceptance claims."""
from __future__ import annotations

import ast
import fcntl
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import local_keys as cli
from serverware import authority_local_keys as local

DIGEST = "sha256:" + "1" * 64


def selected(directory):
    info = os.stat(directory)
    boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    return dict(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE, directory=dict(device=info.st_dev,inode=info.st_ino),
        bootIdDigest=local.trust._boot(), issuedAtBoottimeNs=boot, deadlineBoottimeNs=boot+60_000_000_000,
        issuedAtUnixNanos=unix, expiresAtUnixNanos=unix+60_000_000_000)


def open_owner(directory, *, genesis_inventory=None, enrollment_audit_inventory=None, chain_enrollment_inventory=None):
    value = selected(directory)
    if genesis_inventory is not None:
        value.update(schema=local.GENESIS_AUDIT_APPROVAL_SCHEMA, purpose=local.GENESIS_AUDIT_PURPOSE,
            pilotKeyInventoryOriginal=genesis_inventory.decode("ascii"))
    if enrollment_audit_inventory is not None:
        value.update(schema=local.ENROLLMENT_APPROVAL_SCHEMA, purpose=local.ENROLLMENT_PURPOSE,
            genesisAuditKeyInventoryOriginal=enrollment_audit_inventory.decode("ascii"))
    if chain_enrollment_inventory is not None:
        value.update(schema=local.CHAIN_APPROVAL_SCHEMA, purpose=local.CHAIN_PURPOSE,
            enrollmentKeyInventoryOriginal=chain_enrollment_inventory.decode("ascii"))
    raw = local.trust.spec.canonical_json_bytes(value)
    fd = os.memfd_create("synthetic-local-key-approval", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    if os.write(fd, raw) != len(raw): raise RuntimeError("fixture short write")
    os.fchmod(fd, 0o400); fcntl.fcntl(fd, fcntl.F_ADD_SEALS, local.io.SEALS)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    return local.LocalKeyProvisioner(approval_fd=fd, approval_sha256=local.trust.sha(raw), directory_fd=directory_fd)


def synthetic_inventory_original():
    """Real public-key calculations, explicitly not an observed file owner."""
    rows, roster = [], {}
    for index, row in enumerate(local.roster(), 1):
        key = Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        encoded = local.trust.spec.strict_base64url_encode(public)
        rows.append(dict(row, publicKeyBase64Url=encoded, publicKeySha256=local.trust.sha(public),
            publicKeySpkiSha256=local.trust.sha(key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))))
        if row["family"] == "artifact": roster[row["purpose"]] = encoded
    return local.trust.spec.canonical_json_bytes(dict(schema=local.INVENTORY_SCHEMA,
        approvalSha256=DIGEST, directory=dict(device=1, inode=2),
        publicRosterSha256=local.trust.sha(local.trust.spec.canonical_json_bytes(roster)), keys=rows, claims=local.CLAIMS))


def synthetic_audit_inventory_original(pilot_original):
    key = Ed25519PrivateKey.from_private_bytes(bytes([21]) * 32).public_key()
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    encoded = local.trust.spec.strict_base64url_encode(raw)
    row = dict(local.genesis_audit_roster()[0], publicKeyBase64Url=encoded, publicKeySha256=local.trust.sha(raw),
        publicKeySpkiSha256=local.trust.sha(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    return local.trust.spec.canonical_json_bytes(dict(schema=local.GENESIS_AUDIT_INVENTORY_SCHEMA,
        approvalSha256=DIGEST, directory=dict(device=1, inode=3),
        publicRosterSha256=local.trust.sha(local.trust.spec.canonical_json_bytes({"audit-inclusion": encoded})),
        keys=[row], claims=local.CLAIMS, pilotKeyInventorySha256=local.trust.sha(pilot_original)))


def synthetic_enrollment_inventory_original(pilot_original, audit_original):
    rows, roster = [], {}
    for index, row in enumerate(local.enrollment_roster(), 22):
        public = Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32).public_key()
        raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        encoded = local.trust.spec.strict_base64url_encode(raw)
        rows.append(dict(row, publicKeyBase64Url=encoded, publicKeySha256=local.trust.sha(raw),
            publicKeySpkiSha256=local.trust.sha(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))))
        roster[row["purpose"]] = encoded
    return local.trust.spec.canonical_json_bytes(dict(schema=local.ENROLLMENT_INVENTORY_SCHEMA,
        approvalSha256=DIGEST, directory=dict(device=1, inode=4), keys=rows, claims=local.CLAIMS,
        publicRosterSha256=local.trust.sha(local.trust.spec.canonical_json_bytes(roster)),
        pilotKeyInventorySha256=local.trust.sha(pilot_original), genesisAuditKeyInventorySha256=local.trust.sha(audit_original)))


class KeyContractTests(unittest.TestCase):
    def test_first_registration_chain_is_fixed_six_and_prior_three_profiles_unchanged(self):
        self.assertEqual(tuple(len(factory()) for factory in (local.roster, local.genesis_audit_roster,
            local.enrollment_roster, local.chain_roster)), (20, 1, 2, 6))
        self.assertEqual([row["purpose"] for row in local.chain_roster()],
            ["execution-caller", "finalization-caller", "computation", "completion", "state", "grant-authorizer"])
        pilot = synthetic_inventory_original(); audit = synthetic_audit_inventory_original(pilot)
        enrollment = synthetic_enrollment_inventory_original(pilot, audit)
        value = dict(schema=local.CHAIN_APPROVAL_SCHEMA, purpose=local.CHAIN_PURPOSE,
            directory=dict(device=1, inode=5), bootIdDigest=DIGEST, issuedAtBoottimeNs=100,
            deadlineBoottimeNs=200, issuedAtUnixNanos=100, expiresAtUnixNanos=200,
            pilotKeyInventoryOriginal=pilot.decode("ascii"), genesisAuditKeyInventoryOriginal=audit.decode("ascii"),
            enrollmentKeyInventoryOriginal=enrollment.decode("ascii"))
        self.assertEqual(local.approval(local.trust.spec.canonical_json_bytes(value)), value)
        for changed in (dict(value, purpose=local.ENROLLMENT_PURPOSE), dict(value, keyCount=6),
                dict(value, directory=dict(device=1, inode=4)), {k:v for k,v in value.items() if k != "enrollmentKeyInventoryOriginal"}):
            with self.assertRaises(ValueError): local.approval(local.trust.spec.canonical_json_bytes(changed))
        self.assertEqual(local.MAX_APPROVAL, 8192)

    def test_chain_rejects_rebound_prior_enrollment_or_a_shared_prior_key(self):
        pilot = synthetic_inventory_original(); audit = synthetic_audit_inventory_original(pilot)
        original = synthetic_enrollment_inventory_original(pilot, audit)
        value = local.trust.document(original, local.MAX_PUBLIC)
        value["pilotKeyInventorySha256"] = "sha256:" + "2" * 64
        with self.assertRaises(ValueError): local.enrollment_inventory(local.trust.spec.canonical_json_bytes(value).decode("ascii"),
            pilot.decode("ascii"), audit.decode("ascii"))
        value = local.trust.document(original, local.MAX_PUBLIC)
        prior = local.trust.document(audit, local.MAX_PUBLIC)["keys"][0]
        value["keys"][0].update({field:prior[field] for field in ("publicKeyBase64Url", "publicKeySha256", "publicKeySpkiSha256")})
        with self.assertRaises(ValueError): local.enrollment_inventory(local.trust.spec.canonical_json_bytes(value).decode("ascii"),
            pilot.decode("ascii"), audit.decode("ascii"))

    def test_enrollment_profile_is_exactly_two_new_purposes_and_preserves_both_prior_profiles(self):
        pilot = synthetic_inventory_original()
        audit = synthetic_audit_inventory_original(pilot)
        value = dict(schema=local.ENROLLMENT_APPROVAL_SCHEMA, purpose=local.ENROLLMENT_PURPOSE,
            directory=dict(device=1, inode=4), bootIdDigest=DIGEST, issuedAtBoottimeNs=100,
            deadlineBoottimeNs=200, issuedAtUnixNanos=100, expiresAtUnixNanos=200,
            pilotKeyInventoryOriginal=pilot.decode("ascii"), genesisAuditKeyInventoryOriginal=audit.decode("ascii"))
        self.assertEqual(local.approval(local.trust.spec.canonical_json_bytes(value)), value)
        self.assertEqual([row["purpose"] for row in local._selected_roster(value)], ["authorization", "registration-evidence"])
        self.assertEqual(len(local.roster()), 20)
        self.assertEqual(len(local.genesis_audit_roster()), 1)
        self.assertEqual(local.MAX_APPROVAL, 8192)
        for change in (dict(value, schema=local.APPROVAL_SCHEMA), dict(value, schema=local.GENESIS_AUDIT_APPROVAL_SCHEMA),
                dict(value, directory=dict(device=1, inode=2)), dict(value, directory=dict(device=1, inode=3)),
                dict(value, keyCount=3), {name: item for name, item in value.items() if name != "genesisAuditKeyInventoryOriginal"}):
            with self.assertRaises(ValueError): local.approval(local.trust.spec.canonical_json_bytes(change))

    def test_enrollment_requires_literal_distinct_genesis_inventory_with_matching_pilot_pin(self):
        pilot = synthetic_inventory_original()
        audit = synthetic_audit_inventory_original(pilot)
        self.assertEqual(len(local.genesis_audit_inventory(audit.decode("ascii"), pilot.decode("ascii"))[1]), 21)
        for field in ("pilotKeyInventorySha256", "publicRosterSha256", "publicKeySpkiSha256"):
            value = local.trust.document(audit, local.MAX_PUBLIC)
            if field == "publicKeySpkiSha256": value["keys"][0][field] = DIGEST
            else: value[field] = DIGEST
            with self.assertRaises(ValueError):
                local.genesis_audit_inventory(local.trust.spec.canonical_json_bytes(value).decode("ascii"), pilot.decode("ascii"))

    def test_closed_approval_and_original_window(self):
        value = dict(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE, directory=dict(device=1,inode=2),
            bootIdDigest=DIGEST, issuedAtBoottimeNs=100, deadlineBoottimeNs=200,
            issuedAtUnixNanos=100, expiresAtUnixNanos=200)
        self.assertEqual(local.approval(local.trust.spec.canonical_json_bytes(value)), value)
        for changed in (dict(value, reset=True), dict(value, deadlineBoottimeNs=101+local.trust.MAX_OPERATION_NS),
                        dict(value, issuedAtUnixNanos=True), dict(value, purpose="grant-authority")):
            with self.assertRaises(ValueError): local.approval(local.trust.spec.canonical_json_bytes(changed))

    def test_fixed_twenty_separate_public_and_private_paths(self):
        rows = local.roster()
        self.assertEqual(len(rows), 20)
        self.assertEqual({row["purpose"] for row in rows if row["family"] == "artifact"}, set(local.trust.PURPOSES))
        self.assertEqual(len({row["keyId"] for row in rows}), 20)
        self.assertEqual(len({row["publicPath"] for row in rows}), 20)
        self.assertEqual(len({row["privatePath"] for row in rows}), 20)
        self.assertTrue(all(row["privatePath"].startswith("private/") and row["privatePath"].endswith(".seed") for row in rows))
        self.assertFalse(local.CLAIMS["trustGranted"] or local.CLAIMS["hardwareBacked"] or local.CLAIMS["installationAccepted"])

    def test_explicit_genesis_profile_preserves_default_twenty_and_closed_fields(self):
        value = dict(schema=local.GENESIS_AUDIT_APPROVAL_SCHEMA, purpose=local.GENESIS_AUDIT_PURPOSE,
            directory=dict(device=1, inode=3), bootIdDigest=DIGEST,
            issuedAtBoottimeNs=100, deadlineBoottimeNs=200, issuedAtUnixNanos=100, expiresAtUnixNanos=200,
            pilotKeyInventoryOriginal=synthetic_inventory_original().decode("ascii"))
        self.assertEqual(local.approval(local.trust.spec.canonical_json_bytes(value)), value)
        self.assertEqual(local._selected_roster(value), (dict(family="genesis", purpose="audit-inclusion",
            keyId="local-genesis-audit-inclusion-v1", publicPath="keys/genesis/audit-inclusion.pub",
            privatePath="private/genesis/audit-inclusion.seed"),))
        self.assertEqual(local.MAX_APPROVAL, 8192)
        self.assertEqual(len(local.roster()), 20)
        self.assertEqual(local.INVENTORY_SCHEMA, "serverware.authorityTrustedHostLocalKeyInventory/v1")
        for changed in (dict(value, schema=local.APPROVAL_SCHEMA), dict(value, purpose=local.PURPOSE),
                dict(value, directory=dict(device=1, inode=2)), dict(value, keyCount=2),
                {name: item for name, item in value.items() if name != "pilotKeyInventoryOriginal"}):
            with self.assertRaises(ValueError): local.approval(local.trust.spec.canonical_json_bytes(changed))

    def test_genesis_rejects_rebound_or_incomplete_existing_public_inventory(self):
        original = synthetic_inventory_original()
        inventory, seen = local._pilot_inventory(original.decode("ascii"))
        self.assertEqual(len(seen), 20)
        self.assertEqual(local.trust.spec.canonical_json_bytes(inventory), original)
        for change in ("raw-pin", "spki-pin", "roster-pin", "count", "row-purpose", "duplicate"):
            value = local.trust.document(original, local.MAX_PUBLIC)
            if change == "raw-pin": value["keys"][0]["publicKeySha256"] = DIGEST
            elif change == "spki-pin": value["keys"][0]["publicKeySpkiSha256"] = DIGEST
            elif change == "roster-pin": value["publicRosterSha256"] = DIGEST
            elif change == "count": value["keys"].pop()
            elif change == "row-purpose": value["keys"][0]["purpose"] = "audit-inclusion"
            else:
                for name in ("publicKeyBase64Url", "publicKeySha256", "publicKeySpkiSha256"):
                    value["keys"][1][name] = value["keys"][0][name]
            with self.assertRaises(ValueError):
                local._pilot_inventory(local.trust.spec.canonical_json_bytes(value).decode("ascii"))

    def test_fixed_cli_and_dump_guard_precedes_generation(self):
        args = ["--approval-fd","3","--approval-sha256",DIGEST,"--directory-fd","4"]
        self.assertEqual(cli.arguments(args)["directory_fd"], 4)
        for wrong in (args+["--key","secret"], args[:-1]+["3"], [args[0],"03",*args[2:]]):
            with self.assertRaises(ValueError): cli.arguments(wrong)
        tree = ast.parse(Path(local.__file__).read_text())
        owner = next(row for row in tree.body if isinstance(row,ast.ClassDef) and row.name == "LocalKeyProvisioner")
        run = next(row for row in owner.body if isinstance(row,ast.FunctionDef) and row.name == "run")
        calls = [(row.lineno,row.func.attr) for row in ast.walk(run) if isinstance(row,ast.Call) and isinstance(row.func,ast.Attribute)]
        generation = min(line for line,name in calls if name == "generate")
        self.assertLess(max(line for line,name in calls if name == "setrlimit"), generation)
        self.assertLess(max(line for line,name in calls if name == "prctl"), generation)
        publishes = [row for row in ast.walk(run) if isinstance(row,ast.Call) and isinstance(row.func,ast.Attribute) and row.func.attr == "_publish"]
        last = max(publishes,key=lambda row: row.lineno)
        self.assertEqual(last.args[0].value, "inventory.json")


@unittest.skipUnless(os.getresuid() == os.getresgid() == (0,0,0) and sys.flags.isolated and sys.flags.dont_write_bytecode,
    "real protected key-file controls require isolated root -I -B")
class KeyStorageTests(unittest.TestCase):
    def test_actual_chain_profile_creates_six_new_keys_and_retains_all_prior_originals(self):
        pilot = synthetic_inventory_original(); audit = synthetic_audit_inventory_original(pilot)
        enrollment = synthetic_enrollment_inventory_original(pilot, audit)
        with tempfile.TemporaryDirectory(prefix="local-registration-chain-") as directory:
            owner = open_owner(directory, genesis_inventory=pilot, enrollment_audit_inventory=audit,
                chain_enrollment_inventory=enrollment)
            try:
                raw = owner.run()
                inventory, public_keys = local.chain_inventory(raw.decode("ascii"), pilot.decode("ascii"),
                    audit.decode("ascii"), enrollment.decode("ascii"))
                self.assertEqual(len(public_keys), 29)
                self.assertEqual(len(inventory["keys"]), 6)
                expected = {"public-roster.json", "inventory.json"}
                for row in inventory["keys"]:
                    expected.update((row["publicPath"], row["privatePath"]))
                    path = Path(directory) / row["privatePath"]
                    key = Ed25519PrivateKey.from_private_bytes(path.read_bytes())
                    self.assertEqual(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                        (Path(directory) / row["publicPath"]).read_bytes())
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                self.assertEqual({str(path.relative_to(directory)) for path in Path(directory).rglob("*") if path.is_file()}, expected)
                self.assertEqual(inventory["enrollmentKeyInventorySha256"], local.trust.sha(enrollment))
                self.assertFalse(inventory["claims"]["trustGranted"])
                owner.check()
            finally: owner.close()

    def test_chain_collision_with_existing_evidence_key_refuses_before_private_publication(self):
        pilot = synthetic_inventory_original(); audit = synthetic_audit_inventory_original(pilot)
        enrollment = synthetic_enrollment_inventory_original(pilot, audit)
        with tempfile.TemporaryDirectory(prefix="local-registration-chain-collision-") as directory:
            owner = open_owner(directory, genesis_inventory=pilot, enrollment_audit_inventory=audit,
                chain_enrollment_inventory=enrollment)
            try:
                collision = Ed25519PrivateKey.from_private_bytes(bytes([23]) * 32)
                with patch.object(local.Ed25519PrivateKey, "generate", return_value=collision):
                    with self.assertRaises(local.LocalKeyProvisionerError) as caught: owner.run()
                self.assertIsInstance(caught.exception.__cause__, ValueError)
                self.assertTrue((Path(directory) / "private/registration-chain").is_dir())
                self.assertFalse(any(path.is_file() for path in Path(directory).rglob("*")))
            finally: owner.close()

    def test_actual_enrollment_profile_creates_only_two_new_private_keys(self):
        pilot = synthetic_inventory_original()
        audit = synthetic_audit_inventory_original(pilot)
        with tempfile.TemporaryDirectory(prefix="local-enrollment-keys-") as directory:
            owner = open_owner(directory, genesis_inventory=pilot, enrollment_audit_inventory=audit)
            try:
                raw = owner.run()
                inventory, seen = local.enrollment_inventory(raw.decode("ascii"), pilot.decode("ascii"), audit.decode("ascii"))
                self.assertEqual(len(seen), 23)
                self.assertEqual([row["purpose"] for row in inventory["keys"]], ["authorization", "registration-evidence"])
                self.assertEqual((Path(directory) / "inventory.json").read_bytes(), raw)
                expected = {"public-roster.json", "inventory.json"}
                for row in inventory["keys"]:
                    expected.update((row["publicPath"], row["privatePath"]))
                    seed = (Path(directory) / row["privatePath"]).read_bytes()
                    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    self.assertEqual(public, (Path(directory) / row["publicPath"]).read_bytes())
                    self.assertEqual(stat.S_IMODE((Path(directory) / row["privatePath"]).stat().st_mode), 0o400)
                self.assertEqual({str(path.relative_to(directory)) for path in Path(directory).rglob("*") if path.is_file()}, expected)
                self.assertFalse(inventory["claims"]["trustGranted"])
                owner.check()
            finally: owner.close()
            with self.assertRaises(local.LocalKeyProvisionerError) as caught:
                open_owner(directory, genesis_inventory=pilot, enrollment_audit_inventory=audit)
            caught.exception.owner.close()

    def test_enrollment_collision_with_actual_audit_public_key_refuses_before_private_write(self):
        pilot = synthetic_inventory_original()
        audit = synthetic_audit_inventory_original(pilot)
        collision = Ed25519PrivateKey.from_private_bytes(bytes([21]) * 32)
        with tempfile.TemporaryDirectory(prefix="local-enrollment-collision-") as directory:
            owner = open_owner(directory, genesis_inventory=pilot, enrollment_audit_inventory=audit)
            try:
                with patch.object(local.Ed25519PrivateKey, "generate", return_value=collision):
                    with self.assertRaises(local.LocalKeyProvisionerError) as caught: owner.run()
                self.assertIsInstance(caught.exception.__cause__, ValueError)
                self.assertTrue((Path(directory) / "private/enrollment").is_dir())
                self.assertFalse(any(path.is_file() for path in Path(directory).rglob("*")))
            finally: owner.close()

    def test_actual_genesis_profile_creates_only_one_distinct_key_and_new_inventory(self):
        original = synthetic_inventory_original()
        with tempfile.TemporaryDirectory(prefix="local-genesis-audit-key-") as directory:
            owner = open_owner(directory, genesis_inventory=original)
            try:
                raw = owner.run()
                inventory = local.trust.document(raw, local.MAX_PUBLIC)
                self.assertEqual(inventory["schema"], local.GENESIS_AUDIT_INVENTORY_SCHEMA)
                self.assertEqual(set(inventory), {"schema", "approvalSha256", "directory", "publicRosterSha256",
                    "keys", "claims", "pilotKeyInventorySha256"})
                self.assertEqual(inventory["pilotKeyInventorySha256"], local.trust.sha(original))
                self.assertEqual(inventory["claims"], local.CLAIMS)
                self.assertEqual(len(inventory["keys"]), 1)
                row = inventory["keys"][0]
                self.assertTrue(all(row[name] == item for name, item in local.genesis_audit_roster()[0].items()))
                private = Path(directory) / row["privatePath"]
                public_path = Path(directory) / row["publicPath"]
                key = Ed25519PrivateKey.from_private_bytes(private.read_bytes())
                public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                self.assertEqual(public_path.read_bytes(), public)
                self.assertNotIn(public, local._pilot_inventory(original.decode("ascii"))[1])
                self.assertEqual(row["publicKeySha256"], local.trust.sha(public))
                self.assertEqual(row["publicKeySpkiSha256"], local.trust.sha(key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
                roster_raw = (Path(directory) / "public-roster.json").read_bytes()
                self.assertEqual(local.trust.document(roster_raw, local.MAX_PUBLIC), {"audit-inclusion": row["publicKeyBase64Url"]})
                self.assertEqual(inventory["publicRosterSha256"], local.trust.sha(roster_raw))
                self.assertEqual({str(path.relative_to(directory)) for path in Path(directory).rglob("*") if path.is_file()},
                    {row["publicPath"], row["privatePath"], "public-roster.json", "inventory.json"})
                self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o400)
                self.assertEqual(stat.S_IMODE(public_path.stat().st_mode), 0o400)
                owner.check()
                with self.assertRaises(local.LocalKeyProvisionerError): owner.run()
                self.assertEqual((Path(directory) / "inventory.json").read_bytes(), raw)
            finally: owner.close()
            with self.assertRaises(local.LocalKeyProvisionerError) as caught:
                open_owner(directory, genesis_inventory=original)
            caught.exception.owner.close()

    def test_genesis_collision_with_existing_public_key_refuses_before_private_write(self):
        original = synthetic_inventory_original()
        collision = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
        with tempfile.TemporaryDirectory(prefix="local-genesis-collision-") as directory:
            owner = open_owner(directory, genesis_inventory=original)
            try:
                with patch.object(local.Ed25519PrivateKey, "generate", return_value=collision):
                    with self.assertRaises(local.LocalKeyProvisionerError) as caught: owner.run()
                self.assertIs(caught.exception.owner, owner)
                self.assertIsInstance(caught.exception.__cause__, ValueError)
                self.assertFalse(any(path.is_file() for path in Path(directory).rglob("*")))
                self.assertTrue((Path(directory) / "private/genesis").is_dir())
            finally: owner.close()

    def test_actual_distinct_generation_private_readback_and_public_inventory(self):
        with tempfile.TemporaryDirectory(prefix="local-keys-") as directory:
            owner = open_owner(directory)
            try:
                raw = owner.run()
                inventory = local.trust.document(raw, local.MAX_PUBLIC)
                self.assertEqual(raw, (Path(directory)/"inventory.json").read_bytes())
                self.assertEqual(set(inventory), {"schema","approvalSha256","directory","publicRosterSha256","keys","claims"})
                self.assertEqual(inventory["claims"], local.CLAIMS)
                public_roster = local.trust.public_roster((Path(directory)/"public-roster.json").read_bytes())
                self.assertEqual(local.trust.sha((Path(directory)/"public-roster.json").read_bytes()), inventory["publicRosterSha256"])
                observed = set()
                for row in inventory["keys"]:
                    self.assertEqual(set(row), {"family","purpose","keyId","publicPath","privatePath",
                        "publicKeyBase64Url","publicKeySha256","publicKeySpkiSha256"})
                    private_path, public_path = (Path(directory)/row[name] for name in ("privatePath","publicPath"))
                    self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o400)
                    self.assertEqual(stat.S_IMODE(public_path.stat().st_mode), 0o400)
                    key = Ed25519PrivateKey.from_private_bytes(private_path.read_bytes())
                    public = key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
                    self.assertTrue(public == public_path.read_bytes())
                    self.assertEqual(row["publicKeySha256"], local.trust.sha(public))
                    self.assertEqual(row["publicKeySpkiSha256"], local.trust.sha(key.public_key().public_bytes(
                        serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)))
                    observed.add(public)
                    if row["family"] == "artifact": self.assertEqual(public_roster[row["purpose"]], row["publicKeyBase64Url"])
                self.assertEqual(len(observed), 20)
                owner.check()
            finally: owner.close()
            self.assertEqual(owner.handles, [])

    def test_actual_nonempty_input_is_preserved_without_generation(self):
        with tempfile.TemporaryDirectory(prefix="local-keys-") as directory:
            path = Path(directory)/"preserved"; path.write_bytes(b"actual original")
            with self.assertRaises(local.LocalKeyProvisionerError) as caught: open_owner(directory)
            caught.exception.owner.close()
            self.assertEqual(path.read_bytes(), b"actual original")
            self.assertEqual(set(os.listdir(directory)), {"preserved"})

    def test_actual_successful_owner_cannot_regenerate_or_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="local-keys-") as directory:
            owner = open_owner(directory)
            try:
                original = owner.run()
                with self.assertRaises(local.LocalKeyProvisionerError): owner.run()
                self.assertEqual((Path(directory)/"inventory.json").read_bytes(), original)
            finally: owner.close()
            with self.assertRaises(local.LocalKeyProvisionerError) as caught: open_owner(directory)
            caught.exception.owner.close()

    def test_actual_named_public_mutation_refuses_retained_readback(self):
        with tempfile.TemporaryDirectory(prefix="local-keys-") as directory:
            owner = open_owner(directory)
            try:
                owner.run()
                path = Path(directory)/local.roster()[0]["publicPath"]
                os.chmod(path, 0o600)
                with self.assertRaises(ValueError): owner.check()
            finally: owner.close()

    def test_injected_inventory_failure_retains_actual_keys_and_owner(self):
        with tempfile.TemporaryDirectory(prefix="local-keys-") as directory:
            owner = open_owner(directory)
            original = owner._publish
            def failure(path, raw, **kwargs):
                if path == "inventory.json": raise OSError("injected final publication failure")
                return original(path,raw,**kwargs)
            try:
                with patch.object(owner, "_publish", side_effect=failure):
                    with self.assertRaises(local.LocalKeyProvisionerError) as caught: owner.run()
                self.assertIs(caught.exception.owner, owner)
                self.assertGreater(len(owner.handles), 2)
                self.assertTrue(all((Path(directory)/row["privatePath"]).is_file() for row in local.roster()))
                self.assertFalse((Path(directory)/"inventory.json").exists())
                with self.assertRaises(local.LocalKeyProvisionerError): owner.run()
            finally: owner.close()
            self.assertTrue((Path(directory)/"public-roster.json").is_file())


if __name__ == "__main__": unittest.main()

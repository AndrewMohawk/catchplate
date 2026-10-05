#!/usr/bin/env python3
"""Focused synthetic controls; actual key creation requires a private sandbox.

No live trust, service, database, enrollment or cryptographic grant is created.
Runtime controls require root -I -B, an explicit flag and disposable /run.
Only deterministic failures/collision sources are doubled; protected descriptors,
file publication, actual key readback, prior inventories and CLI remain genuine.
"""
import ast
import copy
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import test_authority_local_keys as fixtures
from scripts.authority import local_activation_keys as cli
from serverware import authority_local_activation_keys as local

SANDBOX = "SERVERWARE_TEST_LOCAL_ACTIVATION_KEYS_SANDBOX"
canonical = local.trust.spec.canonical_json_bytes


def prior_originals():
    """Real deterministic public-key inventories, not actual prior file custody."""
    pilot = fixtures.synthetic_inventory_original()
    audit = fixtures.synthetic_audit_inventory_original(pilot)
    enrollment = fixtures.synthetic_enrollment_inventory_original(pilot, audit)
    chain = fixtures.synthetic_chain_inventory_original(pilot, audit, enrollment)
    rows, roster = [], {}
    for index, row in enumerate(local.prior.startup_roster(), 30):
        key = Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32).public_key()
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        encoded = local.trust.spec.strict_base64url_encode(raw)
        rows.append(dict(row, publicKeyBase64Url=encoded, publicKeySha256=local.trust.sha(raw),
            publicKeySpkiSha256=local.trust.sha(key.public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo))))
        roster[row["purpose"]] = encoded
    startup = canonical(dict(schema=local.prior.STARTUP_INVENTORY_SCHEMA,
        approvalSha256=fixtures.DIGEST, directory=dict(device=1, inode=6),
        publicRosterSha256=local.trust.sha(canonical(roster)), keys=rows, claims=local.prior.CLAIMS,
        pilotKeyInventorySha256=local.trust.sha(pilot), genesisAuditKeyInventorySha256=local.trust.sha(audit),
        enrollmentKeyInventorySha256=local.trust.sha(enrollment), registrationChainKeyInventorySha256=local.trust.sha(chain)))
    return tuple(raw.decode("ascii") for raw in (pilot, audit, enrollment, chain, startup))


def selection(directory, originals):
    info = os.stat(directory)
    boot, epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    return dict(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE,
        directory=dict(device=info.st_dev, inode=info.st_ino), bootIdDigest=local.trust._boot(),
        issuedAtBoottimeNs=boot, deadlineBoottimeNs=boot + 60_000_000_000,
        issuedAtUnixNanos=epoch, expiresAtUnixNanos=epoch + 60_000_000_000,
        **dict(zip(local.PRIOR_FIELDS, originals, strict=True)))


def descriptors(directory, originals):
    raw = canonical(selection(directory, originals))
    approval = os.memfd_create("synthetic-activation-key-approval", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        if os.write(approval, raw) != len(raw):
            raise RuntimeError("fixture short write")
        os.fchmod(approval, 0o400)
        fcntl.fcntl(approval, fcntl.F_ADD_SEALS, local.io.SEALS)
        target = os.open(directory, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
        return dict(approval_fd=approval, approval_sha256=local.trust.sha(raw), directory_fd=target)
    except BaseException:
        os.close(approval)
        raise


def owner(directory, originals):
    return local.LocalActivationKeyProvisioner(**descriptors(directory, originals))


class ActivationKeyContractControls(unittest.TestCase):
    def test_exact_typed_roster_cli_and_unchanged_old_profiles(self):
        rows = local.roster()
        self.assertEqual(len(rows), 15)
        self.assertEqual(tuple(row["keyType"] for row in rows), ("Ed25519",) * 10 + ("raw32",) * 5)
        self.assertEqual(len({row["keyId"] for row in rows}), 15)
        self.assertTrue(all("publicPath" not in row for row in rows[10:]))
        self.assertFalse(any("root-signing" in row["purpose"] or row["purpose"] == "state" for row in rows))
        self.assertEqual(tuple(len(fn()) for fn in (local.prior.roster, local.prior.genesis_audit_roster,
            local.prior.enrollment_roster, local.prior.chain_roster, local.prior.startup_roster)), (20, 1, 2, 6, 8))
        args = ["--approval-fd", "3", "--approval-sha256", fixtures.DIGEST, "--directory-fd", "4"]
        self.assertEqual(cli.arguments(args)["directory_fd"], 4)
        for changed in (args + ["--purpose", "root"], args[:-1] + ["3"], [args[0], "03", *args[2:]]):
            with self.assertRaises(ValueError):
                cli.arguments(changed)
        tree = ast.parse(Path(local.__file__).read_text())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalActivationKeyProvisioner")
        run = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "run")
        calls = [(node.lineno, node.func.attr) for node in ast.walk(run)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        first_rng = min(line for line, name in calls if name in ("generate", "urandom"))
        self.assertLess(max(line for line, name in calls if name in ("setrlimit", "prctl")), first_rng)
        publications = [node for node in ast.walk(run) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "_publish"]
        self.assertEqual(max(publications, key=lambda node: node.lineno).args[0].value, "inventory.json")
        snapshot = ast.parse((Path(local.__file__).parent / "authority_local_snapshot.py").read_text())
        issuer = next(node for node in snapshot.body if isinstance(node, ast.ClassDef)
            and node.name == "LocalSnapshotIssuer")
        issue = next(node for node in issuer.body if isinstance(node, ast.FunctionDef) and node.name == "issue")
        generator_imports = [node for node in ast.walk(snapshot) if isinstance(node, ast.ImportFrom)
            and node.module == "scripts.authority.generate_artifact_bundle"]
        self.assertEqual(generator_imports, [issue.body[0]])
        self.assertEqual([(name.name, name.asname) for name in generator_imports[0].names],
            [("_verification_key", None)])
        self.assertLess(generator_imports[0].lineno,
            min(node.lineno for node in ast.walk(issue) if isinstance(node, ast.Call)))

    def test_approval_requires_all_five_exact_prior_inventories_and_original_bounds(self):
        originals = prior_originals()
        value = dict(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE, directory=dict(device=1, inode=7),
            bootIdDigest=fixtures.DIGEST, issuedAtBoottimeNs=100, deadlineBoottimeNs=200,
            issuedAtUnixNanos=100, expiresAtUnixNanos=200, **dict(zip(local.PRIOR_FIELDS, originals)))
        self.assertEqual(local.approval(canonical(value)), value)
        changed_startup = local.trust.document(originals[-1].encode("ascii"), local.MAX_PUBLIC)
        changed_startup["registrationChainKeyInventorySha256"] = fixtures.DIGEST
        for changed in (dict(value, directory=dict(device=1, inode=6)), dict(value, purpose="grant-authority"),
                dict(value, issuedAtUnixNanos=True), dict(value, deadlineBoottimeNs=101 + local.trust.MAX_OPERATION_NS),
                {name: item for name, item in value.items() if name != "startupKeyInventoryOriginal"},
                dict(value, startupKeyInventoryOriginal=canonical(changed_startup).decode("ascii"))):
            with self.assertRaises(ValueError):
                local.approval(canonical(changed))


class ActivationKeyNativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (os.environ.get(SANDBOX) == "1" and Path("/.dockerenv").is_file()
                and os.getresuid() == os.getresgid() == (0, 0, 0)
                and sys.flags.isolated and sys.flags.dont_write_bytecode and tempfile.gettempdir() == "/run"):
            raise RuntimeError("explicit isolated root activation-key sandbox with private /run required")
        cls.originals = prior_originals()

    def test_actual_ten_signing_and_five_raw_files_with_public_only_completion(self):
        with tempfile.TemporaryDirectory(prefix="activation-keys-") as directory:
            held = owner(directory, self.originals)
            try:
                raw = held.run()
                value = local.inventory(raw, prior_originals=self.originals)
                self.assertEqual((Path(directory) / "inventory.json").read_bytes(), raw)
                expected = {"public-roster.json", "inventory.json"}
                seen = set()
                for row in value["keys"]:
                    path = Path(directory) / row["privatePath"]
                    private = path.read_bytes()
                    self.assertEqual(len(private), 32)
                    self.assertNotIn(private, seen)
                    seen.add(private)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                    self.assertNotIn(private.hex().encode(), raw)
                    self.assertNotIn(local.trust.spec.strict_base64url_encode(private).encode(), raw)
                    expected.add(row["privatePath"])
                    if row["keyType"] == "Ed25519":
                        expected.add(row["publicPath"])
                        public = Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
                            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                        self.assertEqual(public, (Path(directory) / row["publicPath"]).read_bytes())
                    else:
                        self.assertEqual(row["keySha256"], local.trust.sha(private))
                        self.assertNotIn("publicKeyBase64Url", row)
                self.assertEqual({str(p.relative_to(directory)) for p in Path(directory).rglob("*") if p.is_file()}, expected)
                self.assertEqual(len(expected), 27)
                self.assertFalse(value["claims"]["trustGranted"] or value["claims"]["installationAccepted"])
                for change in ("raw-type", "raw-alias", "extra-root"):
                    changed = copy.deepcopy(value)
                    if change == "raw-type": changed["keys"][10]["keyType"] = "Ed25519"
                    elif change == "raw-alias": changed["keys"][10]["keySha256"] = changed["keys"][0]["publicKeySha256"]
                    else: changed["keys"].append(dict(changed["keys"][0], purpose="runtime-root"))
                    with self.assertRaises(ValueError): local.inventory(canonical(changed), prior_originals=self.originals)
                held.check()
                with self.assertRaises(local.LocalActivationKeyProvisionerError): held.run()
            finally:
                held.close()

    def test_startup_public_collision_refuses_before_first_secret_publication(self):
        with tempfile.TemporaryDirectory(prefix="activation-key-collision-") as directory:
            held = owner(directory, self.originals)
            try:
                existing = Ed25519PrivateKey.from_private_bytes(bytes([37]) * 32)
                with patch.object(local.Ed25519PrivateKey, "generate", return_value=existing):
                    with self.assertRaises(local.LocalActivationKeyProvisionerError) as caught: held.run()
                self.assertIs(caught.exception.owner, held)
                self.assertFalse(any(p.is_file() for p in Path(directory).rglob("*")))
                with self.assertRaises(local.LocalActivationKeyProvisionerError): held.run()
            finally:
                held.close()

    def test_raw_rng_cannot_alias_actual_new_signing_seed_and_partial_state_survives(self):
        with tempfile.TemporaryDirectory(prefix="activation-raw-collision-") as directory:
            held = owner(directory, self.originals)
            first = Path(directory) / local.roster()[0]["privatePath"]
            try:
                with patch.object(local.os, "urandom", side_effect=lambda count: first.read_bytes()):
                    with self.assertRaises(local.LocalActivationKeyProvisionerError) as caught: held.run()
                self.assertIs(caught.exception.owner, held)
                self.assertEqual(len([p for p in Path(directory).rglob("*") if p.is_file()]), 20)
                self.assertFalse((Path(directory) / "inventory.json").exists())
                self.assertEqual(list((Path(directory) / "private/activation-encryption").iterdir()), [])
                held.check()
            finally:
                held.close()

    def test_interrupted_publication_is_not_overwritten_adopted_or_retried(self):
        with tempfile.TemporaryDirectory(prefix="activation-key-partial-") as directory:
            held = owner(directory, self.originals)
            original = held._publish
            count = 0

            def interrupted(path, raw, **kwargs):
                nonlocal count
                count += 1
                if count == 3: raise KeyboardInterrupt()
                return original(path, raw, **kwargs)

            try:
                with patch.object(held, "_publish", side_effect=interrupted):
                    with self.assertRaises(local.LocalActivationKeyProvisionerError) as caught: held.run()
                self.assertIs(caught.exception.owner, held)
                self.assertEqual(len(held.completed), 2)
                self.assertFalse((Path(directory) / "inventory.json").exists())
                with self.assertRaises(local.LocalActivationKeyProvisionerError): held.run()
                with self.assertRaises(local.LocalActivationKeyProvisionerError) as refused:
                    owner(directory, self.originals)
                refused.exception.owner.close()
            finally:
                held.close()

    def test_real_file_and_directory_identity_changes_refuse(self):
        with tempfile.TemporaryDirectory(prefix="activation-key-held-") as directory:
            held = owner(directory, self.originals)
            try:
                held.run()
                private = Path(directory) / local.roster()[-1]["privatePath"]
                os.chmod(private, 0o600)
                with self.assertRaises(ValueError): held.check()
                # Closing uses retained descriptor ownership, not renewed content admission.
            finally:
                held.close()
        with tempfile.TemporaryDirectory(prefix="activation-key-directory-") as directory:
            held = owner(directory, self.originals)
            try:
                held._mkdir("keys")
                os.rename(Path(directory) / "keys", Path(directory) / "displaced")
                (Path(directory) / "keys").mkdir(mode=0o700)
                with self.assertRaises(ValueError): held.check()
            finally:
                held.close()

    def test_original_expiry_rollback_boot_environment_and_thread_guards(self):
        with tempfile.TemporaryDirectory(prefix="activation-key-clock-") as directory:
            held = owner(directory, self.originals)
            try:
                original = held._original
                for boot in (held.previous_boot - 1, held.deadline_boottime_ns):
                    with patch.object(local.time, "clock_gettime_ns", return_value=boot):
                        with self.assertRaises(ValueError): held.check()
                with patch.object(local.time, "time_ns", return_value=original[4][4]):
                    with self.assertRaises(ValueError): held.check()
                with patch.object(local.trust, "_boot", return_value=fixtures.DIGEST):
                    with self.assertRaises(ValueError): held.check()
                with patch.dict(os.environ, {"ACTIVATION_TEST_CHANGED": "1"}):
                    with self.assertRaises(ValueError): held.check()
                errors = []

                def other_thread():
                    try: held.check()
                    except BaseException as error: errors.append(type(error))

                thread = threading.Thread(target=other_thread)
                thread.start(); thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [ValueError])
                self.assertIs(held._original, original)
                self.assertFalse(any(Path(directory).iterdir()))
            finally:
                held.close()

    def test_actual_fd_only_cli_publishes_public_inventory_and_exits_zero(self):
        with tempfile.TemporaryDirectory(prefix="activation-key-cli-") as directory:
            inputs = descriptors(directory, self.originals)
            fds = inputs["approval_fd"], inputs["directory_fd"]
            try:
                result = subprocess.run([sys.executable, "-I", "-B", cli.__file__,
                    "--approval-fd", str(fds[0]), "--approval-sha256", inputs["approval_sha256"],
                    "--directory-fd", str(fds[1])], pass_fds=fds, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, "CLI failed without exposing captured diagnostics")
                self.assertEqual(result.stderr, b"")
                value = local.inventory(result.stdout, prior_originals=self.originals)
                self.assertEqual(value["approvalSha256"], inputs["approval_sha256"])
                self.assertEqual((Path(directory) / "inventory.json").read_bytes(), result.stdout)
            finally:
                for descriptor in fds: os.close(descriptor)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Real isolated static-file/socket/signature controls, never signer launch."""
import ast
import copy
import hashlib
import os
from pathlib import Path
import socket
import stat
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from scripts.authority import local_enrollment_attestation as cli
from scripts.test_authority_local_enrollment_configuration import fixture
from scripts.test_authority_local_configuration import sealed
from serverware import authority_local_enrollment_attestation as local

PIN = "sha256:" + "1" * 64


def selected():
    source, _, _, root = fixture()
    now, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    rows = [dict(path="/run/source/serverware/" + name, kind="python", bytes=1, sha256=PIN)
        for name in sorted(local.REQUIRED_MODULES)]
    rows.extend(dict(path=path, kind="native", bytes=1, sha256=PIN) for path in (
        "/usr/local/bin/python3.11", "/usr/local/lib/libpython3.11.so.1.0"))
    value = dict(schema=local.SCHEMA, purpose=local.PURPOSE,
        **{name: source[name] for name in ("pilotKeyInventoryOriginal", "genesisAuditKeyInventoryOriginal", "enrollmentKeyInventoryOriginal")},
        runtimeFiles=sorted(rows, key=lambda row: row["path"]),
        listener=dict(descriptor=dict(device=1, inode=2), path=dict(device=1, inode=3)), replay=dict(device=1, inode=4),
        bootIdDigest=local.configuration.configuration.launcher._boot_identity_digest(),
        issuedAtBoottimeNs=now, deadlineBoottimeNs=now + 60_000_000_000,
        issuedAtUnixNanos=unix, expiresAtUnixNanos=unix + 60_000_000_000)
    return value, root


class EnrollmentAttestationTests(unittest.TestCase):
    def test_closed_static_selection_has_no_process_claim_and_keeps_original_window(self):
        value, _ = selected()
        self.assertEqual(local.approval(local.canonical(value)), value)
        self.assertNotIn("pid", value)
        for changed in (dict(value, pid=123), dict(value, schema=local.signer.ATTESTATION_SCHEMA),
                dict(value, expiresAtUnixNanos=value["issuedAtUnixNanos"] + local.signer.MAX_RECEIPT_AGE_NS + 1)):
            with self.assertRaises(ValueError): local.approval(local.canonical(changed))

    def test_missing_required_runtime_original_arbitrary_path_and_prior_key_substitution_refuse(self):
        value, _ = selected()
        for mode in ("missing", "path", "inventory"):
            changed = copy.deepcopy(value)
            if mode == "missing": changed["runtimeFiles"].pop(0)
            elif mode == "path": changed["runtimeFiles"][0]["path"] = "/root/private-key.seed"
            else: changed["enrollmentKeyInventoryOriginal"] = changed["genesisAuditKeyInventoryOriginal"]
            with self.assertRaises(ValueError): local.approval(local.canonical(changed))

    def test_exact_cli_requires_five_distinct_handles_without_command_or_caller_claims(self):
        args = ["--approval-fd", "3", "--approval-sha256", PIN, "--signing-key-fd", "4",
            "--signer-public-key-fd", "5", "--listener-fd", "6", "--replay-directory-fd", "7"]
        self.assertEqual(cli.arguments(args)["listener_fd"], 6)
        for changed in (args[:-1] + ["3"], args + ["--pid", "9"], [args[0], "03", *args[2:]]):
            with self.assertRaises(ValueError): cli.arguments(changed)

    def test_real_observation_and_original_checks_precede_key_access_and_existing_receipt_codec(self):
        tree = ast.parse(Path(local.__file__).read_bytes())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalEnrollmentSignerAttestationIssuer")
        issue = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "issue")
        calls = [(node.lineno, node.func.attr) for node in ast.walk(issue) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        keyline = next(line for line, name in calls if name == "signing_key")
        self.assertLess(next(line for line, name in calls if name == "_hash"), keyline)
        self.assertLess(next(line for line, name in calls if name == "check"), keyline)
        self.assertGreater(next(line for line, name in calls if name == "_produce_attestation_on_work"), keyline)
        self.assertNotIn("execve", {name for _, name in calls})

    @unittest.skipUnless(os.environ.get("SERVERWARE_TEST_LOCAL_ENROLLMENT_SANDBOX") == "1"
        and os.getresuid() == os.getresgid() == (0, 0, 0) and sys.flags.isolated and sys.flags.dont_write_bytecode,
        "requires task-owned readonly container, CAP_CHOWN, disposable /run and root0700 replay tmpfs")
    def test_actual_retained_files_listener_replay_and_root_signature_then_mutation_refusal(self):
        value, root = selected()
        source_root = Path(local.__file__).parent
        made_files, made_dirs, descriptors = [], [], []
        owner = listener = replay_fd = None
        source = Path("/run/source/serverware")
        endpoint_parent = Path(local.entrypoint.LISTENER_PATH).parent
        replay = Path(local.entrypoint.REPLAY_PATH)
        require_empty = lambda path: self.assertEqual(list(path.iterdir()), [])
        self.assertTrue(os.statvfs("/").f_flag & os.ST_RDONLY)
        self.assertEqual((replay.stat().st_uid, replay.stat().st_gid, stat.S_IMODE(replay.stat().st_mode)), (0, 0, 0o700))
        require_empty(replay)
        try:
            for target in (Path("/run/source"), source, Path("/run/serverware"), endpoint_parent):
                self.assertFalse(target.exists())
                target.mkdir(mode=0o755); made_dirs.append(target)
            for name in sorted(local.REQUIRED_MODULES):
                target = source / name
                with target.open("xb") as out: out.write((source_root / name).read_bytes())
                target.chmod(0o444); made_files.append(target)
            for row in value["runtimeFiles"]:
                path = Path(row["path"])
                raw = path.read_bytes()
                row.update(bytes=len(raw), sha256="sha256:" + hashlib.sha256(raw).hexdigest())
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.setblocking(False); listener.bind(local.entrypoint.LISTENER_PATH); listener.listen(1)
            os.chmod(local.entrypoint.LISTENER_PATH, 0o660); os.chown(local.entrypoint.LISTENER_PATH, 65517, 65532)
            fd_stat, path_stat = os.fstat(listener.fileno()), os.stat(local.entrypoint.LISTENER_PATH, follow_symlinks=False)
            value["listener"] = dict(descriptor=dict(device=fd_stat.st_dev, inode=fd_stat.st_ino),
                path=dict(device=path_stat.st_dev, inode=path_stat.st_ino))
            replay_fd = os.open(replay, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC); descriptors.append(replay_fd)
            self.assertEqual(os.listdir(replay_fd), [])
            os.fchown(replay_fd, 65517, 65517)
            replay_stat = os.fstat(replay_fd); value["replay"] = dict(device=replay_stat.st_dev, inode=replay_stat.st_ino)
            enrollment = local.document(value["enrollmentKeyInventoryOriginal"].encode("ascii"), local.keys.MAX_PUBLIC)
            encoded = next(row["publicKeyBase64Url"] for row in enrollment["keys"] if row["purpose"] == "registration-evidence")
            public_fd = sealed(local.configuration.configuration._public(encoded)); descriptors.append(public_fd)
            root_fd = sealed(root.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())); descriptors.append(root_fd)
            raw = local.canonical(value)
            approval_fd = sealed(raw); descriptors.append(approval_fd)
            try:
                owner = local.LocalEnrollmentSignerAttestationIssuer(approval_fd=approval_fd, approval_sha256=local.sha(raw),
                    signing_key_fd=root_fd, signer_public_key_fd=public_fd, listener_fd=listener.fileno(), replay_directory_fd=replay_fd)
            except local.EnrollmentAttestationError as error:
                owner = error.owner
                raise
            receipt = owner.issue()
            _envelope, claims, interval, _opening, _digest = local.signer._read_attestation(receipt, root.public_key(),
                local.signer.MAX_RECEIPT_AGE_NS, local.configuration._ValidationWork(local.configuration.QueryReadValidationLimits()))
            self.assertEqual(interval, (value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]))
            self.assertFalse(claims["hardwareBacked"] or claims["nativeStageZero"] or claims["teeVerified"])
            observed = local.document(owner.observation_original, local.io.MAX_PUBLIC)
            self.assertFalse(observed["liveProcessObserved"] or observed["completeImportClosure"] or observed["authorityPackageInstalled"])
            self.assertEqual(len(observed["closure"]["files"]), 8)
            owner.check()
            target = made_files[0]
            target.chmod(0o644)
            with target.open("ab") as out: out.write(b"\n# changed synthetic sandbox file\n")
            target.chmod(0o444)
            with self.assertRaises(ValueError): owner.check()
            owner.close()
            self.assertTrue(owner.closed)
            for fd in descriptors: os.fstat(fd)
        finally:
            if owner is not None and not owner.closed: owner.close()
            if replay_fd is not None: os.fchown(replay_fd, 0, 0)
            for fd in descriptors: os.close(fd)
            if listener is not None: listener.close()
            endpoint = Path(local.entrypoint.LISTENER_PATH)
            if endpoint.exists(): endpoint.unlink()
            for path in reversed(made_files): path.unlink()
            for path in reversed(made_dirs): path.rmdir()


if __name__ == "__main__": unittest.main()

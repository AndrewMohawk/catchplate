#!/usr/bin/env python3
"""Closed inputs and real atomic-file mechanics, not admitted service evidence."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import select
import signal
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import authority_local_startup as startup
from scripts.authority import local_startup as cli


def fixture():
    """Synthetic public selection only; no installed owner/receipt is asserted."""
    return dict(schema=startup.PLAN_SCHEMA, role="runtime", bootIdDigest="sha256:" + "1" * 64,
        issuedAtBoottimeNs=100, deadlineBoottimeNs=200,
        issuedAtUnixNanos=1000, expiresAtUnixNanos=1100,
        credentialDirectory=dict(path="/run/credentials/test-authority", device=1, inode=2),
        exchangeDirectory=dict(path="/run/serverware/test-exchange", device=1, inode=3),
        retainedFiles=[dict(path=path, sha256="sha256:" + "2" * 64)
            for path in sorted((startup.INTERPRETER, startup.ENTRYPOINT, startup.BOOTSTRAP))],
        retainedDirectories=[dict(path=path, device=1, inode=index + 10)
            for index, path in enumerate(("/runtime", "/runtime/python/bin", "/usr/bin"))],
        mutableStateDescriptors=[], environment={name: "sha256:" + "3" * 64 for name in startup.ENVIRONMENT})


class LocalStartupTests(unittest.TestCase):
    def test_closed_plan_preserves_original_windows_and_fixed_role(self):
        value = fixture()
        self.assertEqual(startup.plan(startup.encode(value)), value)
        self.assertEqual(startup.MAX_STARTUP_NS, 300_000_000_000)
        for key, wrong in (("deadlineBoottimeNs", 100 + startup.MAX_STARTUP_NS + 1),
                           ("issuedAtBoottimeNs", True), ("role", "control-plane")):
            changed = copy.deepcopy(value); changed[key] = wrong
            with self.subTest(key=key), self.assertRaises(startup.LocalStartupError):
                startup.plan(startup.encode(changed))

    def test_plan_cannot_select_command_keys_environment_or_missing_runtime(self):
        value = fixture()
        changes = []
        row = copy.deepcopy(value); row["argv"] = ["/bin/sh"]; changes.append(row)
        row = copy.deepcopy(value); row["environment"]["SERVERWARE_METADATA_STORE_POSTGRES_DSN"] = "not-a-credential"; changes.append(row)
        row = copy.deepcopy(value); row["retainedFiles"] = row["retainedFiles"][1:]; changes.append(row)
        row = copy.deepcopy(value); row["retainedDirectories"] = row["retainedDirectories"][:-1]; changes.append(row)
        row = copy.deepcopy(value); row["exchangeDirectory"]["path"] = "/run/../tmp"; changes.append(row)
        for index, row in enumerate(changes):
            with self.subTest(index=index), self.assertRaises(startup.LocalStartupError):
                startup.plan(startup.encode(row))

    def test_closed_cli_only_accepts_plan_pin_and_actual_listener_slot(self):
        args = ["--plan-fd", "4", "--plan-sha256", "sha256:" + "1" * 64, "--listener-fd", "3"]
        self.assertEqual(cli.arguments(args), dict(plan_fd=4, plan_sha256=args[3], listener_fd=3))
        for bad in ([], args + ["--key-fd", "5"], [*args[:-1], "4"], [args[0], "04", *args[2:]],
                    ["--command", "/bin/sh", *args[2:]]):
            with self.subTest(args=bad), self.assertRaises(ValueError):
                cli.arguments(bad)

    def _effect(self, directory, raw, *, existing=False, process_churn=False):
        # Actual FD custody for the filesystem primitive only. No fake launcher,
        # process, signature, installation receipt or successful owner is used.
        handles, refreshes, checkpoints = [], [], []
        child, release, child_pidfd = None, None, None
        def hold(fd):
            row = [fd, None]; handles.append(row)
            row[1] = startup._identity(os.fstat(fd)); return fd
        def refresh(fd):
            info = startup._identity(os.fstat(fd))
            next(row for row in handles if row[0] == fd)[1] = info
            refreshes.append((stat.S_IMODE(info[2]), info[5]))
        def check():
            nonlocal child, release, child_pidfd
            # The primitive has now retained /proc, this process, and its fd
            # directory. Keep one genuine child alive across the next checks.
            if process_churn and child is None and len(handles) >= 4:
                read_end, release = os.pipe2(os.O_CLOEXEC)
                child = os.fork()
                if child == 0:
                    os.close(release)
                    signal.signal(signal.SIGALRM, signal.SIG_DFL)
                    signal.alarm(5)
                    os.read(read_end, 1)
                    os._exit(0)
                os.close(read_end)
                child_pidfd = os.pidfd_open(child, 0)
                self.assertTrue(stat.S_ISDIR(os.stat(str(child), dir_fd=handles[1][0]).st_mode))
            for fd, identity in handles:
                startup._check_handle(fd, identity)
            checkpoints.append(len(handles))
        target = Path(directory) / startup.OBSERVATION_NAME
        if existing:
            target.write_bytes(b"unchanged"); target.chmod(0o400)
            before = startup._identity(target.stat())
        root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            if existing:
                with self.assertRaises(startup.LocalStartupError):
                    startup._publish_effect(root_fd, raw, hold=hold, refresh=refresh, check=check)
                self.assertEqual(target.read_bytes(), b"unchanged")
                self.assertEqual(startup._identity(target.stat()), before)
                self.assertEqual(refreshes, [(0o400, 0)])
            else:
                fd = startup._publish_effect(root_fd, raw, hold=hold, refresh=refresh, check=check)
                self.assertEqual(target.read_bytes(), raw)
                self.assertEqual(startup._identity(target.stat()), startup._identity(os.fstat(fd)))
                self.assertEqual(refreshes, [(0o400, 0), (0o400, 1)])
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o400)
                if process_churn:
                    self.assertIsNotNone(child)
                    self.assertFalse(select.select([child_pidfd], [], [], 0)[0])
                    # Deterministic companion: a real directory's link count
                    # changes, while a different actual inode must still refuse.
                    root_identity = startup._identity(os.fstat(root_fd))
                    os.mkdir("link-count-change", dir_fd=root_fd)
                    self.assertNotEqual(os.fstat(root_fd).st_nlink, root_identity[5])
                    startup._check_handle(root_fd, root_identity)
                    other = os.open("link-count-change", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=root_fd)
                    try:
                        with self.assertRaises(startup.LocalStartupError):
                            startup._check_handle(other, root_identity)
                    finally:
                        os.close(other)
            self.assertGreaterEqual(len(checkpoints), 3)
        finally:
            if release is not None:
                os.close(release)
            if child is not None:
                if child_pidfd is not None:
                    if not select.select([child_pidfd], [], [], 2)[0]:
                        signal.pidfd_send_signal(child_pidfd, signal.SIGKILL)
                    os.waitpid(child, 0)
                    os.close(child_pidfd)
                else:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
            for fd, _ in reversed(handles):
                os.close(fd)
            os.close(root_fd)

    def test_real_atomic_observation_publication_refreshes_mode_and_link_identity(self):
        self.assertEqual(os.geteuid(), 0, "this focused storage control requires the root test container")
        with tempfile.TemporaryDirectory(prefix="serverware-local-observation-") as directory:
            self._effect(directory, startup.encode({"syntheticObservation": True}), process_churn=True)

    def test_real_atomic_observation_never_replaces_an_existing_original(self):
        self.assertEqual(os.geteuid(), 0, "this focused storage control requires the root test container")
        with tempfile.TemporaryDirectory(prefix="serverware-local-observation-") as directory:
            self._effect(directory, b"{}", existing=True)

    def test_boot_pin_uses_existing_request_domain_not_plain_boot_hash(self):
        self.assertEqual(startup._boot(), startup.launcher._boot_identity_digest())
        raw = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()
        self.assertNotEqual(startup._boot(), startup.sha(raw))


if __name__ == "__main__":
    unittest.main()

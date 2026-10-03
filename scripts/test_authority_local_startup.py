#!/usr/bin/env python3
"""Closed inputs and real atomic-file mechanics, not admitted service evidence."""
from __future__ import annotations

import ast
import copy
import os
import resource
from pathlib import Path
import select
import signal
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import authority_local_startup as startup
from serverware import authority_local_limits as limits
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
    def test_idle_wait_preserves_checks_fd_sets_readiness_and_deadline_clipping(self):
        # Synthetic scheduling only, not an admitted owner or child lifetime.
        for write in (False, True):
            for ready in (False, True):
                for boot_remaining, epoch_remaining, timeout in ((5.0, 5.0, 1.0), (0.25, 5.0, 0.25), (5.0, 0.125, 0.125)):
                    with self.subTest(write=write, ready=ready, boot=boot_remaining, epoch=epoch_remaining):
                        calls, channel = [], object()
                        owner = SimpleNamespace(child_pidfd=41, channel=channel,
                            value=dict(deadlineBoottimeNs=1_000_000_000 + int(boot_remaining * 1e9),
                                expiresAtUnixNanos=2_000_000_000 + int(epoch_remaining * 1e9)),
                            check=lambda *, child_live: calls.append(("check", child_live)))

                        def selected(readable, writable, exceptional, seconds):
                            calls.append(("select", readable, writable, exceptional, seconds))
                            return ([channel] if ready and not write else [],
                                [channel] if ready and write else [], [])

                        with patch.object(startup.time, "clock_gettime_ns", return_value=1_000_000_000), \
                                patch.object(startup.time, "time_ns", return_value=2_000_000_000), \
                                patch.object(startup.select, "select", side_effect=selected):
                            self.assertIs(startup.LocalAuthorityStartup._wait(owner, write=write), ready)
                        self.assertEqual(calls, [("check", True),
                            ("select", [41] if write else [41, channel], [channel] if write else [], [], timeout),
                            ("check", True)])

    def test_idle_wait_propagates_precheck_and_postcheck_refusal(self):
        for effects, selected_count in (([ValueError("precheck")], 0), ([None, ValueError("postcheck")], 1)):
            with self.subTest(selected_count=selected_count):
                owner = SimpleNamespace(child_pidfd=41, channel=object(),
                    value=dict(deadlineBoottimeNs=5_000_000_000, expiresAtUnixNanos=5_000_000_000),
                    check=Mock(side_effect=effects))
                with patch.object(startup.time, "clock_gettime_ns", return_value=0), \
                        patch.object(startup.time, "time_ns", return_value=0), \
                        patch.object(startup.select, "select", return_value=([], [], [])) as selected:
                    with self.assertRaises(ValueError):
                        startup.LocalAuthorityStartup._wait(owner)
                self.assertEqual(selected.call_count, selected_count)
                self.assertEqual(owner.check.call_count, selected_count + 1)
                self.assertTrue(all(call.kwargs == {"child_live": True} for call in owner.check.call_args_list))

    def test_late_idle_wait_clips_original_deadlines_and_rechecks_ready_pidfd(self):
        for boot_remaining, epoch_remaining, timeout in ((5.0, 5.0, 1.0), (0.25, 5.0, 0.25), (5.0, 0.125, 0.125)):
            with self.subTest(boot=boot_remaining, epoch=epoch_remaining):
                calls = []

                def checked(*, child_live):
                    calls.append(("check", child_live))
                    if len(calls) > 1:
                        raise ValueError("child guard refused after PIDFD readiness")

                def selected(readable, writable, exceptional, seconds):
                    calls.append(("select", readable, writable, exceptional, seconds))
                    return [41], [], []

                owner = SimpleNamespace(child_pidfd=41, purposes=("manifest",),
                    directory_fds={"exchangeDirectory": 73}, check=checked,
                    value=dict(deadlineBoottimeNs=1_000_000_000 + int(boot_remaining * 1e9),
                        expiresAtUnixNanos=2_000_000_000 + int(epoch_remaining * 1e9)))
                with patch.object(startup.time, "clock_gettime_ns", return_value=1_000_000_000), \
                        patch.object(startup.time, "time_ns", return_value=2_000_000_000), \
                        patch.object(startup.select, "select", side_effect=selected), \
                        patch.object(startup.os, "scandir") as scanned:
                    scanned.return_value.__enter__.return_value = iter(())
                    with self.assertRaises(ValueError):
                        startup.LocalAuthorityStartup._late(owner)
                    scanned.assert_called_once_with(73)
                self.assertEqual(calls, [("check", True),
                    ("select", [41], [], [], timeout), ("check", True)])

    def test_plan_accepts_existing_full_closure_bound_not_an_arbitrary_128(self):
        value = fixture()
        value["retainedFiles"] += [dict(path=f"/runtime/source/selected-{index:05d}.py", sha256="sha256:" + "2" * 64)
            for index in range(startup.launcher.MAX_CLOSURE_FILES - len(value["retainedFiles"]))]
        value["retainedFiles"].sort(key=lambda row: row["path"])
        raw = startup.encode(value)
        self.assertGreater(len(raw), 1024 * 1024)
        self.assertEqual(len(startup.plan(raw)["retainedFiles"]), startup.launcher.MAX_CLOSURE_FILES)
        self.assertEqual(startup.MAX_PLAN, startup.launcher.MAX_LOCAL_OBSERVATION)
        value["retainedFiles"].append(dict(path="/runtime/zzz-over-limit.py", sha256="sha256:" + "2" * 64))
        with self.assertRaises(startup.LocalStartupError):
            startup.plan(startup.encode(value))

    def test_descriptor_budget_counts_shared_ancestors_once(self):
        value = fixture()
        before = startup._descriptor_requirement(value, [0, 1, 2, 3, 4])
        value["retainedFiles"] += [dict(path=f"/runtime/python/bin/sibling-{index}", sha256="sha256:" + "2" * 64)
            for index in range(3653)]
        self.assertEqual(startup._descriptor_requirement(value, [0, 1, 2, 3, 4]), before + 3653)
        self.assertEqual(startup._descriptor_requirement(value, [4095]), before + 3653 + 4096 - startup.STATIC_FD_MIN)

    def test_actual_path_walker_retains_shared_high_fds_and_refuses_rebound_ancestor(self):
        # Real pathname/FD custody primitive only; no installed package, startup
        # admission, signature, or serving result is fabricated by this control.
        self.assertEqual(os.geteuid(), 0)
        limits = resource.getrlimit(resource.RLIMIT_NOFILE)
        with tempfile.TemporaryDirectory(prefix="local-retained-paths-", dir="/run") as temporary:
            root = Path(temporary)
            selected = root / "selected"
            selected.mkdir(mode=0o700)
            owner = startup.LocalAuthorityStartup(startup._TOKEN)
            try:
                value = fixture()
                value["retainedFiles"] += [dict(path=str(selected / f"{index:03d}.py"), sha256="sha256:" + "2" * 64)
                    for index in range(64)]
                value["retainedFiles"].sort(key=lambda row: row["path"])
                startup._prepare_descriptor_limit(startup.plan(startup.encode(value)))
                self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE)[1], limits[1])
                descriptors = []
                for index in range(64):
                    path = selected / f"{index:03d}.py"
                    path.write_bytes(b"public roster bytes\n")
                    path.chmod(0o400)
                    descriptors.append(owner._open(str(path)))
                self.assertEqual(len(owner.handles), 64 + len(owner.path_directories))
                self.assertTrue(all(fd >= startup.STATIC_FD_MIN for fd in descriptors))
                before = len(owner.handles)
                self.assertEqual(owner._open(str(selected), directory=True), owner.path_directories[str(selected)])
                self.assertEqual(len(owner.handles), before)
                selected.rename(root / "original")
                selected.mkdir(mode=0o700)
                with self.assertRaises(startup.LocalStartupError):
                    owner._open(str(selected), directory=True)
            finally:
                owner.close()
                resource.setrlimit(resource.RLIMIT_NOFILE, limits)

    def test_empty_retained_module_hash_is_allowed_but_documents_stay_nonempty(self):
        with tempfile.TemporaryFile() as source:
            with self.assertRaises(startup.LocalStartupError):
                startup._read(source.fileno(), 64)
            self.assertEqual(startup._read(source.fileno(), 64, allow_empty=True), b"")
            self.assertEqual(startup.sha(startup._read(source.fileno(), 64, allow_empty=True)),
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            source.write(b"nonempty public original"); source.flush()
            self.assertEqual(startup._read(source.fileno(), 64), b"nonempty public original")
        tree = ast.parse((ROOT / "serverware" / "authority_local_startup.py").read_text())
        opted_in = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "_read"
            and any(keyword.arg == "allow_empty" for keyword in node.keywords)]
        self.assertEqual(len(opted_in), 2)
        self.assertTrue(all(isinstance(node.args[1], ast.Attribute)
            and node.args[1].attr == "MAX_CLOSURE_FILE_BYTES" for node in opted_in))

    def test_closed_plan_preserves_original_windows_and_fixed_role(self):
        value = fixture()
        self.assertEqual(startup.plan(startup.encode(value)), value)
        self.assertEqual(startup.MAX_STARTUP_NS, limits.LOCAL_SETUP_MAX_NS)
        for key, wrong in (("deadlineBoottimeNs", 100 + startup.MAX_STARTUP_NS + 1),
                           ("issuedAtBoottimeNs", True), ("role", "control-plane")):
            changed = copy.deepcopy(value); changed[key] = wrong
            with self.subTest(key=key), self.assertRaises(startup.LocalStartupError):
                startup.plan(startup.encode(changed))

    def test_prospective_local_setup_accepts_new_bound_without_normalizing_inputs(self):
        self.assertEqual(limits.LOCAL_SETUP_MAX_NS, 3_600_000_000_000)
        self.assertEqual(limits.LOCAL_SESSION_MAX_NS, 7_200_000_000_000)
        for duration in (300_000_000_001, limits.LOCAL_SETUP_MAX_NS):
            value = fixture()
            value["deadlineBoottimeNs"] = value["issuedAtBoottimeNs"] + duration
            value["expiresAtUnixNanos"] = value["issuedAtUnixNanos"] + duration
            with self.subTest(duration=duration):
                self.assertEqual(startup.plan(startup.encode(value)), value)
        for first, last in (("issuedAtBoottimeNs", "deadlineBoottimeNs"),
                            ("issuedAtUnixNanos", "expiresAtUnixNanos")):
            for wrong in (True, fixture()[first], fixture()[first] + limits.LOCAL_SETUP_MAX_NS + 1):
                value = fixture(); value[last] = wrong
                with self.subTest(field=last, value=wrong), self.assertRaises(startup.LocalStartupError):
                    startup.plan(startup.encode(value))

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

    def _effect(self, directory, raw, *, existing=False, process_churn=False, name=startup.OBSERVATION_NAME):
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
        target = Path(directory) / name
        if existing:
            target.write_bytes(b"unchanged"); target.chmod(0o400)
            before = startup._identity(target.stat())
        root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            if existing:
                with self.assertRaises(startup.LocalStartupError):
                    startup._publish_effect(root_fd, raw, hold=hold, refresh=refresh, check=check, name=name)
                self.assertEqual(target.read_bytes(), b"unchanged")
                self.assertEqual(startup._identity(target.stat()), before)
                self.assertEqual(refreshes, [(0o400, 0)])
            else:
                fd = startup._publish_effect(root_fd, raw, hold=hold, refresh=refresh, check=check, name=name)
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

    def test_real_admission_notice_publication_is_no_replace_and_after_authenticated_receive(self):
        # Real storage primitive plus source ordering, not a successful role
        # admission fixture or a caller-supplied readiness acknowledgement.
        self.assertEqual(os.geteuid(), 0, "this focused storage control requires the root test container")
        for existing in (False, True):
            with tempfile.TemporaryDirectory(prefix="serverware-local-admitted-") as directory:
                self._effect(directory, b'{"syntheticNotice":true}', existing=existing, name=startup.ADMITTED_NAME)
        source = Path(startup.__file__).read_text()
        receive = source.index("notice, _ = self._receive(admitted=True)")
        admitted = source.index("self.admitted = True", receive)
        published = source.index("name=ADMITTED_NAME", admitted)
        self.assertLess(receive, admitted)
        self.assertLess(admitted, published)
        self.assertIn("self.check(full=True, child_live=True)", source[receive:admitted])
        self.assertIn("_require(notice ==", source[receive:admitted])
        self.assertIn("name in (OBSERVATION_NAME, ADMITTED_NAME)", source)

    def test_boot_pin_uses_existing_request_domain_not_plain_boot_hash(self):
        self.assertEqual(startup._boot(), startup.launcher._boot_identity_digest())
        raw = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()
        self.assertNotEqual(startup._boot(), startup.sha(raw))


if __name__ == "__main__":
    unittest.main()

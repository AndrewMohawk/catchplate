#!/usr/bin/env python3
"""Offline wrapper controls and one finite synthetic faulthandler child.

No app, real custody initializer, provider, Docker, or network is started. The
child tests stack-only output, not production startup or a live stall diagnosis.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import operator_private_stack_diagnostic as diagnostic


def fixture_environment():
    # Deliberately literal fixture identity, not a copy of the allowlist tested.
    return {
        "CATCHPLATE_OPERATOR_DEMO": "1", "CATCHPLATE_RELEASE_CHANNEL": "dev",
        "CATCHPLATE_DATA_DIR": "/data",
        "CATCHPLATE_PUBLIC_URL": "https://catchplate-demo.example.com",
        "CATCHPLATE_OPERATOR_DEMO_UPSTREAMS": '["https://registry.npmjs.org"]',
        "CATCHPLATE_OPERATOR_DEMO_PROXY_URL": "https://catchplate-proxy.example.com",
        "CATCHPLATE_DIRECT_CA_DOWNLOAD_ENABLED": "1",
        "CATCHPLATE_ADMIN_USER": "user:operator-demo-operator",
        "CATCHPLATE_DATA_PLANE_INSTANCE_ID": "spiffe://operator-demo.catchplate/decision-gate/local",
        "CATCHPLATE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "0",
        "CATCHPLATE_DECISION_GATE_BASE": "http://127.0.0.1:9091",
        "CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST": "sha256:" + "a" * 64,
        **{"CATCHPLATE_" + prefix + "_TOKEN_FILE": "/run/secrets/catchplate/" + role + ".token"
           for role, prefix in (("admin", "ADMIN"), ("credential-lease", "DATA_PLANE_CREDENTIAL_LEASE"),
               ("audit", "DATA_PLANE_AUDIT"), ("grant-consume", "DATA_PLANE_GRANT_CONSUME"),
               ("rate-limit-consume", "DATA_PLANE_RATE_LIMIT_CONSUME"),
               ("release-authorization", "DATA_PLANE_RELEASE_AUTHORIZATION"), ("management", "DATA_PLANE_MANAGEMENT"))},
    }


class OsView:
    """Module-local overrides: do not replace shared os functions process-wide."""
    def __init__(self, **overrides):
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(os, name)


class PrivateStackDiagnosticTests(unittest.TestCase):
    def configuration(self, environment, **changes):
        view = OsView(environ=environment, **{name: (lambda: 10001)
            for name in ("getuid", "geteuid", "getgid", "getegid")})
        view.__dict__.update(changes)
        return patch.object(diagnostic, "os", view)

    def test_closed_configuration_rejects_native_production_custody_and_unpinned_inputs(self):
        argv = ["/diagnostic/operator_private_stack_diagnostic.py"]
        with patch.object(diagnostic.sys, "argv", argv), self.configuration(fixture_environment()):
            self.assertIsNone(diagnostic._admit_configuration())
        optional = {"CATCHPLATE_PROCESS_MODE": "catchplate-control-plane",
            "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite", "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
            "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite", "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
            "CATCHPLATE_KEY_RELEASE_REQUIRED": "0", "CATCHPLATE_DEV_AUTHENTICATOR": "0",
            "CATCHPLATE_DEV_DEMO_SEED": "0", "CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED": "0",
            "CATCHPLATE_DEVELOPMENT_SANDBOX": "0", "CATCHPLATE_PRODUCTION_IMAGE": "0"}
        with patch.object(diagnostic.sys, "argv", argv), self.configuration({**fixture_environment(), **optional}):
            diagnostic._admit_configuration()
        mutations = [(key, None) for key in fixture_environment()]
        mutations += [(key, "unexpected") for key in fixture_environment()]
        mutations += [(key, "unexpected") for key in optional]
        mutations += [(key, value) for key, value in (
            ("CATCHPLATE_RELEASE_CHANNEL", "production"), ("CATCHPLATE_PRODUCTION_IMAGE", "1"),
            ("CATCHPLATE_PROCESS_MODE", "native"), ("CATCHPLATE_KEY_RELEASE_REQUIRED", "1"),
            ("CATCHPLATE_CONTROL_PLANE_CUSTODY_CONFIG_FD", ""),
            ("CATCHPLATE_CONTROL_PLANE_CUSTODY_CONFIG_FD", "12"),
            ("CATCHPLATE_CONTROL_PLANE_CUSTODY_CONFIG_PATH", "/synthetic/canary-secret"),
            ("CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR", "/synthetic/canary-secret"),
            ("CATCHPLATE_UNKNOWN_SETTING", "canary-secret"),
            ("CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST", "sha256:" + "A" * 64))]
        for key, value in mutations:
            environment = fixture_environment()
            if value is None:
                environment.pop(key)
            else:
                environment[key] = value
            with self.subTest(key=key, value=value), patch.object(diagnostic.sys, "argv", argv), \
                    self.configuration(environment), self.assertRaises(diagnostic.DiagnosticRefused) as raised:
                diagnostic._admit_configuration()
            self.assertEqual(str(raised.exception), "private stack diagnostic refused")
        for name in ("getuid", "geteuid", "getgid", "getegid"):
            with patch.object(diagnostic.sys, "argv", argv), \
                    self.configuration(fixture_environment(), **{name: lambda: 0}), \
                    self.assertRaises(diagnostic.DiagnosticRefused):
                diagnostic._admit_configuration()
        for arguments in ([], ["/tmp/other.py"], argv + ["--repeat"], argv + ["--delay", "1"]):
            with patch.object(diagnostic.sys, "argv", arguments), self.configuration(fixture_environment()), \
                    self.assertRaises(diagnostic.DiagnosticRefused):
                diagnostic._admit_configuration()

    def test_marker_and_isolation_admission_are_closed_before_output(self):
        from scripts import operator_npm_metadata_fixture_network as network
        good = b'{"schema":"catchplate.privateOperatorAuditFixture/v1","syntheticOnly":true}'
        good_status = b"NoNewPrivs:\t1\nCapEff:\t0\nCapPrm:\t0\nCapInh:\t0\nCapAmb:\t0\nCapBnd:\t0\n"
        with tempfile.TemporaryDirectory(prefix="catchplate-stack-marker-") as directory:
            marker = Path(directory) / "marker.json"
            marker.write_bytes(good)
            marker.chmod(0o400)
            descriptors, closed = [], []
            def opened(*args, **kwargs):
                fd = os.open(*args, **kwargs)
                descriptors.append(fd)
                return fd
            def metadata(fd):
                value = os.fstat(fd)
                return SimpleNamespace(st_mode=value.st_mode, st_uid=10001, st_gid=10001,
                    st_nlink=value.st_nlink, st_size=value.st_size)
            def close(fd):
                closed.append(fd)
                os.close(fd)
            with patch.object(diagnostic, "MARKER_PATH", str(marker)), \
                    patch.object(diagnostic, "os", OsView(open=opened, fstat=metadata, close=close)), \
                    patch.object(diagnostic, "_read_bounded", return_value=good_status) as proc, \
                    patch.object(network, "assert_isolated_network") as isolated:
                diagnostic._admit_fixture()
                isolated.assert_called_once_with()
                proc.assert_called_once_with("/proc/self/status", 32768)
                self.assertEqual(descriptors, closed)
                for raw in (b"[]", b"{}", good[:-1] + b',"extra":true}',
                        good.replace(b"true", b"1"), good[:-1] + b',"syntheticOnly":true}', b"x" * 1025):
                    marker.chmod(0o600)
                    marker.write_bytes(raw)
                    marker.chmod(0o400)
                    isolated.reset_mock()
                    proc.reset_mock()
                    with self.assertRaises((diagnostic.DiagnosticRefused, ValueError)):
                        diagnostic._admit_fixture()
                    isolated.assert_not_called()
                    proc.assert_not_called()
                    self.assertEqual(descriptors, closed)
                marker.chmod(0o600)
                marker.write_bytes(good)
                marker.chmod(0o400)
                for status in (good_status.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0"),
                        *(good_status.replace(name + b":\t0", name + b":\t1")
                            for name in (b"CapEff", b"CapPrm", b"CapInh", b"CapAmb", b"CapBnd"))):
                    proc.return_value = status
                    isolated.reset_mock()
                    with self.assertRaises(diagnostic.DiagnosticRefused):
                        diagnostic._admit_fixture()
                    isolated.assert_not_called()
                proc.return_value = good_status
                isolated.side_effect = ValueError("synthetic unisolated namespace")
                with self.assertRaises(ValueError):
                    diagnostic._admit_fixture()
                self.assertEqual(descriptors, closed)

    def test_main_requires_custody_opt_out_before_descriptors_and_watchdog(self):
        for failed_stage in (None, "configuration", "custody", "configured_custody", "fixture", "open", "runner"):
            with self.subTest(stage=failed_stage):
                events = []
                failure = RuntimeError("synthetic-secret-error-must-not-be-projected")
                def step(stage, result=None):
                    def call(*args, **kwargs):
                        events.append(stage)
                        if failed_stage == stage:
                            raise failure
                        return result
                    return call
                frames = SimpleNamespace(close=step("close"))
                custody = ModuleType("catchplate.control_plane_custody_startup")
                custody.initialize_from_environment = step("custody", object() if failed_stage == "configured_custody" else None)
                package = ModuleType("catchplate")
                package.control_plane_custody_startup = custody
                result = object()
                with ExitStack() as stack:
                    stack.enter_context(patch.dict(sys.modules, {"catchplate": package,
                        "catchplate.control_plane_custody_startup": custody}))
                    for name, stage, value in (("_admit_configuration", "configuration", None),
                            ("_admit_fixture", "fixture", None), ("_open_frames", "open", frames),
                            ("_run_runner", "runner", result)):
                        stack.enter_context(patch.object(diagnostic, name, side_effect=step(stage, value)))
                    if failed_stage is None:
                        self.assertIs(diagnostic.main(), result)
                    elif failed_stage == "runner":
                        with self.assertRaises(RuntimeError) as raised:
                            diagnostic.main()
                        self.assertIs(raised.exception, failure)
                    else:
                        with self.assertRaises(diagnostic.DiagnosticRefused) as raised:
                            diagnostic.main()
                        self.assertEqual(str(raised.exception), "private stack diagnostic refused")
                order = ["configuration", "custody", "fixture", "open", "runner", "close"]
                stop = "custody" if failed_stage == "configured_custody" else failed_stage
                expected = order if stop in (None, "runner") else order[:order.index(stop) + 1]
                self.assertEqual(events, expected)

    def test_private_output_requires_fresh_exact_tmpfs_and_owns_only_created_fd(self):
        mount = ("5 1 0:77 / /run/catchplate-private-diagnostic rw,nosuid,nodev,noexec"
                 " - tmpfs tmpfs rw,size=2048k\n").encode()
        mutations = ({}, {"directory_mode": 0o755}, {"uid": 0}, {"gid": 0}, {"existing": ["old.txt"]},
            {"capacity": 1024 * 1024}, {"mount": b""}, {"mount": mount * 2},
            {"mount": mount.replace(b"tmpfs tmpfs", b"ext4 /dev/test")},
            {"mount": mount.replace(b",noexec", b"")}, {"mount": mount.replace(b"0:77", b"0:78")},
            {"mount": mount + mount.replace(b" /run/catchplate-private-diagnostic ", b" /run/catchplate-private-diagnostic/sub ")},
            {"file_mode": 0o644}, {"nlink": 2}, {"size": 1})
        for changes in mutations:
            with self.subTest(changes=changes):
                opened, closed = [], []
                dev = os.makedev(0, 77)
                def open_fd(name, flags, mode=None, *, dir_fd=None):
                    fd = 30 if name == "frames.txt" else 10 + len(opened)
                    opened.append((name, flags, mode, dir_fd, fd))
                    return fd
                def metadata(fd):
                    return SimpleNamespace(st_mode=(stat.S_IFREG | changes.get("file_mode", 0o600)) if fd == 30
                        else (stat.S_IFDIR | changes.get("directory_mode", 0o700)),
                        st_uid=changes.get("uid", 10001), st_gid=changes.get("gid", 10001),
                        st_nlink=changes.get("nlink", 1), st_size=changes.get("size", 0), st_dev=dev)
                frame = object()
                fdopen = Mock(return_value=frame)
                view = OsView(open=open_fd, close=closed.append, fstat=metadata,
                    listdir=lambda fd: changes.get("existing", []), fdopen=fdopen,
                    fstatvfs=lambda fd: SimpleNamespace(f_frsize=4096,
                        f_blocks=changes.get("capacity", 2 * 1024 * 1024) // 4096))
                with patch.object(diagnostic, "os", view), \
                        patch.object(diagnostic, "_read_bounded", return_value=changes.get("mount", mount)):
                    if changes:
                        with self.assertRaises(diagnostic.DiagnosticRefused):
                            diagnostic._open_frames()
                        fdopen.assert_not_called()
                        self.assertCountEqual(closed, [row[4] for row in opened])
                    else:
                        self.assertIs(diagnostic._open_frames(), frame)
                        fdopen.assert_called_once_with(30, "wb", buffering=0)
                        self.assertCountEqual(closed, [10, 11, 12])
                        self.assertEqual(opened[-1][:4], ("frames.txt",
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, 12))
                        for name, flags, mode, parent, fd in opened[:-1]:
                            self.assertEqual(flags, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                self.assertEqual(len(closed), len(set(closed)))

    def test_one_shot_timer_uses_original_entrypoint_and_cancels_after_return(self):
        events, frames = [], object()
        with patch.object(diagnostic.faulthandler, "dump_traceback_later",
                side_effect=lambda *args, **kwargs: events.append("arm")) as arm, \
                patch.object(diagnostic.runpy, "run_module",
                    side_effect=lambda *args, **kwargs: events.append("runner")) as runner, \
                patch.object(diagnostic.faulthandler, "cancel_dump_traceback_later",
                    side_effect=lambda: events.append("cancel")) as cancel:
            diagnostic._run_runner(frames)
        self.assertEqual(events, ["arm", "runner", "cancel"])
        self.assertEqual(diagnostic.DUMP_AFTER_SECONDS, 50)
        self.assertEqual(diagnostic.ENTRYPOINT, "catchplate.operator_demo_runner")
        arm.assert_called_once_with(50, repeat=False, file=frames, exit=False)
        runner.assert_called_once_with("catchplate.operator_demo_runner", run_name="__main__")
        cancel.assert_called_once_with()

    def test_runner_exception_is_preserved_and_timer_cancelled_without_reentry(self):
        failure, frames = RuntimeError("synthetic runner exception"), object()
        for cleanup_error in (None, OSError("synthetic diagnostic cleanup")):
            with patch.object(diagnostic.faulthandler, "dump_traceback_later") as arm, \
                    patch.object(diagnostic.runpy, "run_module", side_effect=failure) as runner, \
                    patch.object(diagnostic.faulthandler, "cancel_dump_traceback_later", side_effect=cleanup_error) as cancel:
                with self.assertRaises(RuntimeError) as raised:
                    diagnostic._run_runner(frames)
            self.assertIs(raised.exception, failure)
            arm.assert_called_once_with(50, repeat=False, file=frames, exit=False)
            runner.assert_called_once_with("catchplate.operator_demo_runner", run_name="__main__")
            cancel.assert_called_once_with()
        with patch.object(diagnostic.faulthandler, "dump_traceback_later", side_effect=OSError("synthetic-secret")), \
                patch.object(diagnostic.runpy, "run_module") as runner, \
                patch.object(diagnostic.faulthandler, "cancel_dump_traceback_later") as cancel:
            with self.assertRaises(diagnostic.DiagnosticRefused) as raised:
                diagnostic._run_runner(frames)
            self.assertEqual(str(raised.exception), "private stack diagnostic refused")
            runner.assert_not_called()
            cancel.assert_not_called()

    def test_real_finite_child_dumps_frames_once_without_locals_or_source_values(self):
        # The fixed production delay is shortened ONLY in this isolated child;
        # entrypoint execution is replaced by a bounded synthetic waiting frame.
        code = r'''
import faulthandler, os, resource, signal, socket, sys, threading
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from scripts import operator_private_stack_diagnostic as diagnostic
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
signal.alarm(5)
def forbidden(*args, **kwargs):
    raise AssertionError("synthetic child attempted network")
def synthetic_waiting_entrypoint(module, *, run_name):
    assert module == "catchplate.operator_demo_runner" and run_name == "__main__"
    secret_local = "synthetic-local-must-not-appear-6f34"
    secret_mapping = {"token": "synthetic-mapping-must-not-appear-981a"}
    assert secret_local and secret_mapping
    threading.Event().wait(0.5)
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "wb", buffering=0) as frames, \
        patch.object(diagnostic, "DUMP_AFTER_SECONDS", 0.05), \
        patch.object(diagnostic.runpy, "run_module", synthetic_waiting_entrypoint), \
        patch.object(socket, "socket", forbidden), \
        patch.object(socket, "create_connection", forbidden), \
        patch.object(socket, "getaddrinfo", forbidden):
    diagnostic._run_runner(frames)
assert not any(name == "catchplate" or name.startswith("catchplate.") for name in sys.modules)
signal.alarm(0)
'''
        with tempfile.TemporaryDirectory(prefix="catchplate-stack-child-") as directory:
            frames = Path(directory) / "frames.txt"
            result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(ROOT), str(frames)],
                capture_output=True, timeout=8, check=False,
                env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(result.returncode, 0, "synthetic faulthandler child failed")
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"")
            info = frames.stat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(info.st_nlink, 1)
            self.assertTrue(0 < info.st_size <= 65536)
            raw = frames.read_bytes()
            self.assertEqual(raw.count(b"Timeout ("), 1)
            self.assertIn(b"synthetic_waiting_entrypoint", raw)
            self.assertIn(b"_run_runner", raw)
            self.assertIn(b"<string>", raw)
            for forbidden in (b"synthetic-local-must-not-appear-6f34",
                    b"synthetic-mapping-must-not-appear-981a", b"secret_local",
                    b"secret_mapping", b"AssertionError(", b"sys.argv[2]"):
                self.assertNotIn(forbidden, raw)


if __name__ == "__main__":
    unittest.main()

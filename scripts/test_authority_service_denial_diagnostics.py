#!/usr/bin/env python3
"""Inert source-extracted diagnostics and exact denial-catch controls only.

No authority import/admission, sockets, database, or real stderr changes. The
catch fixtures retain the actual exception/finally bodies, replacing only the
try body with a synthetic failure. They do not test the transport as a whole.
"""
import ast
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "serverware/authority_service.py"
SECRET = "synthetic-secret-message-token-and-dsn"
SECRET_PATH = "/synthetic-private-path-token/"


class DenialDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE.stat().st_size > 2 * 1024 * 1024:
            raise AssertionError("source exceeds focused fixture bound")
        cls.tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        cls.helper = next(node for node in cls.tree.body
                          if isinstance(node, ast.FunctionDef)
                          and node.name == "_denial_diagnostics")
        cls.catches = {}
        for name in ("AuthorityRuntimeRelay", "AuthorityServer"):
            owner = next(node for node in cls.tree.body
                         if isinstance(node, ast.ClassDef) and node.name == name)
            method = next(node for node in owner.body
                          if isinstance(node, ast.FunctionDef)
                          and node.name == "_serve_connection")
            tries = [node for node in method.body if isinstance(node, ast.Try)]
            if len(tries) != 1 or len(tries[0].handlers) != 1:
                raise AssertionError("denial catch shape changed")
            cls.catches[name] = tries[0]

    def diagnostic(self, *, mode=stat.S_IFREG | 0o600, uid=0, nlink=1,
                   effective_uid=65524, flags=0, write_failure=False):
        writes = []
        flag_reads = []

        def write(fd, encoded):
            self.assertEqual(fd, 2)
            if write_failure:
                raise OSError(SECRET)
            writes.append(encoded)
            return 1  # A short write is not retried.

        def read_flags(fd, command):
            flag_reads.append((fd, command))
            return flags

        namespace = dict(
            os=SimpleNamespace(fstat=lambda fd: SimpleNamespace(
                st_mode=mode, st_uid=uid, st_nlink=nlink),
                geteuid=lambda: effective_uid, O_NONBLOCK=os.O_NONBLOCK, write=write),
            stat=stat,
            fcntl=SimpleNamespace(fcntl=read_flags, F_GETFL=fcntl.F_GETFL),
        )
        exec(compile(ast.Module(body=[copy.deepcopy(self.helper)], type_ignores=[]),
                     str(SOURCE), "exec"), namespace)
        return namespace["_denial_diagnostics"], writes, flag_reads, namespace

    @staticmethod
    def error(depth=0, *, filename=SECRET_PATH + "authority_service.py", name="fail"):
        namespace = {"secret": SECRET}
        code = (f"def {name}(depth):\n"
                f"    if depth: return {name}(depth - 1)\n"
                "    raise ValueError(secret, {'requestId': secret})\n")
        exec(compile(code, filename, "exec"), namespace)
        try:
            namespace[name](depth)
        except ValueError as error:
            return error
        raise AssertionError("synthetic failure did not raise")

    def test_private_root_owned_inherited_sink_and_message_path_redaction(self):
        # Exact real pilot metadata: root-owned 0600/nlink1, lower-UID role.
        # This is an fstat/eUID fixture, not a live role or log-file read.
        diagnostic, writes, flags, _namespace = self.diagnostic()
        diagnostic("runtime-relay", self.error())
        self.assertEqual(len(writes), 1)
        self.assertEqual(flags, [])
        output = writes[0].decode("ascii")
        self.assertIn("AUTHORITY_DENIAL_STAGE=runtime-relay\n", output)
        self.assertIn("AUTHORITY_DENIAL_TYPE=0:ValueError\n", output)
        self.assertIn(":authority_service.py:fail:3\n", output)
        for secret in (SECRET, SECRET_PATH, "requestId", "{'", "ValueError("):
            self.assertNotIn(secret, output)
        self.assertLessEqual(len(writes[0]), 4096)

    def test_cause_frame_symbol_bounds_and_cycle_stop(self):
        diagnostic, writes, _flags, _namespace = self.diagnostic()
        namespace = {"secret": SECRET}
        exec(compile("def innermost_guard():\n    raise ValueError(secret)\n"
                     "def outer(depth):\n    if depth: return outer(depth - 1)\n"
                     "    innermost_guard()\n", SECRET_PATH + "authority_service.py", "exec"),
             namespace)
        try:
            namespace["outer"](40)
        except ValueError as error:
            innermost_error = error
        errors = [innermost_error, self.error(20)] + [RuntimeError(SECRET) for _ in range(9)]
        for first, second in zip(errors, errors[1:]):
            first.__cause__ = second
        errors[-1].__cause__ = errors[0]
        diagnostic("authority-server", errors[0])
        output = writes.pop().decode("ascii")
        self.assertEqual(output.count("AUTHORITY_DENIAL_TYPE="), 8)
        self.assertEqual(output.count("AUTHORITY_DENIAL_FRAME="), 12)
        self.assertIn("AUTHORITY_DENIAL_FRAME=0:authority_service.py:innermost_guard:2\n", output)
        self.assertIn("AUTHORITY_DENIAL_FRAME=1:authority_service.py:fail:3\n", output)
        self.assertNotIn(SECRET, output)
        self.assertLessEqual(len(output), 4096)
        diagnostic("authority-server", self.error(140))
        self.assertIn(b"AUTHORITY_DENIAL_FRAME=0:unavailable:unavailable:0\n", writes.pop())
        cyclic = RuntimeError(SECRET)
        cyclic.__context__ = cyclic
        diagnostic("authority-server", cyclic)
        self.assertEqual(writes.pop().count(b"AUTHORITY_DENIAL_TYPE="), 1)
        for invalid in ("bad token", "X" * 97, "nonascii_é"):
            diagnostic("authority-server", type(invalid, (Exception,), {})(SECRET))
            self.assertIn(b"AUTHORITY_DENIAL_TYPE=0:unavailable\n", writes.pop())
        diagnostic("authority-server", self.error(filename=SECRET_PATH + "bad name.py",
                                                  name="X" * 97))
        self.assertIn(b":unavailable:unavailable:3\n", writes.pop())

    def test_sink_skips_no_flag_mutation_or_retry_and_introspection_failure(self):
        for options in ({"mode": stat.S_IFIFO | 0o600},
                        {"mode": stat.S_IFSOCK | 0o600},
                        {"mode": stat.S_IFREG | 0o640}, {"uid": 1234}, {"nlink": 2}):
            diagnostic, writes, _flags, _namespace = self.diagnostic(**options)
            diagnostic("runtime-relay", ValueError(SECRET))
            self.assertEqual(writes, [])
        diagnostic, writes, flags, _namespace = self.diagnostic(
            mode=stat.S_IFIFO | 0o600, flags=os.O_NONBLOCK)
        diagnostic("runtime-relay", ValueError(SECRET))
        self.assertEqual(len(writes), 1)
        self.assertEqual(flags, [(2, fcntl.F_GETFL)])
        diagnostic("unapproved-stage", ValueError(SECRET))
        self.assertEqual(len(writes), 1)

        class BrokenTrace(Exception):
            @property
            def __traceback__(self):
                raise RuntimeError(SECRET)

        diagnostic, writes, _flags, namespace = self.diagnostic()
        diagnostic("runtime-relay", BrokenTrace(SECRET))
        self.assertEqual(writes, [])
        namespace["os"].fstat = lambda fd: (_ for _ in ()).throw(OSError(SECRET))
        diagnostic("runtime-relay", ValueError(SECRET))
        self.assertEqual(writes, [])

    def catch_fixture(self, name, diagnostic, *, omit_diagnostic=False, send_failure=False):
        original = self.catches[name]
        handler = copy.deepcopy(original.handlers[0])
        self.assertEqual(ast.unparse(handler.type), "Exception")
        self.assertEqual(ast.unparse(handler.body[0]), "if detached:\n    return")
        stage = "runtime-relay" if name == "AuthorityRuntimeRelay" else "authority-server"
        self.assertEqual(ast.unparse(handler.body[1]), f"_denial_diagnostics({stage!r}, exc)")
        if omit_diagnostic:
            del handler.body[1]
        function = ast.parse("def run(connection, detached, error, deadline_ns):\n    pass").body[0]
        function.body = [ast.Try(body=ast.parse("raise error").body, handlers=[handler],
                                 orelse=[], finalbody=copy.deepcopy(original.finalbody))]
        events = []

        def send(connection, value, *, deadline_ns):
            events.append(("send", value, deadline_ns))
            if send_failure:
                raise OSError(SECRET)

        namespace = dict(_denial_diagnostics=diagnostic,
                         writer_transport=SimpleNamespace(_check_deadline=lambda value:
                                                          events.append(("deadline", value))),
                         _send_message_until=send,
                         _sha256=lambda value: "sha256:" + hashlib.sha256(value).hexdigest())
        exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
                     str(SOURCE), "exec"), namespace)
        connection = SimpleNamespace(close=lambda: events.append(("close",)))
        return namespace["run"], connection, events

    def test_both_exact_catches_preserve_wire_deadline_cleanup_when_diagnostics_fail(self):
        for name in self.catches:
            for send_failure in (False, True):
                error = ValueError(SECRET)
                baseline, connection, expected = self.catch_fixture(
                    name, None, omit_diagnostic=True, send_failure=send_failure)
                baseline(connection, False, error, 123456)
                diagnostic, writes, _flags, _namespace = self.diagnostic(write_failure=True)
                candidate, connection, actual = self.catch_fixture(
                    name, diagnostic, send_failure=send_failure)
                candidate(connection, False, error, 123456)
                self.assertEqual(actual, expected)
                self.assertEqual(writes, [])
                self.assertEqual(actual[-1], ("close",))
                sends = [event for event in actual if event[0] == "send"]
                self.assertEqual(len(sends), 1)
                self.assertEqual(sends[0][1], {
                    "schema": "serverware.policyAuthorityError/v1",
                    "code": "authority_denied",
                    "detailDigest": "sha256:" + hashlib.sha256(SECRET.encode()).hexdigest(),
                })
                self.assertEqual(sends[0][2], 123456)

    def test_detached_early_return_no_diagnostic_no_second_frame_and_registration(self):
        for name in self.catches:
            diagnostic, writes, _flags, _namespace = self.diagnostic()
            candidate, connection, actual = self.catch_fixture(name, diagnostic)
            candidate(connection, True, ValueError(SECRET), 123456)
            self.assertEqual(actual, [("close",)])
            self.assertEqual(writes, [])
        calls = [node for node in ast.walk(self.tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "_denial_diagnostics"]
        self.assertEqual(len(calls), 2)
        self.assertEqual((ROOT / "Makefile").read_text().count(
            "scripts/test_authority_service_denial_diagnostics.py"), 1)


if __name__ == "__main__":
    unittest.main()

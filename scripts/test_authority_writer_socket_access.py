#!/usr/bin/env python3
"""Role-table and real Unix DAC controls; no authority or database execution.

The kernel control requires an explicitly selected disposable root container
with no network, no-new-privileges, and only SETUID/SETGID/CHOWN/FOWNER/DAC_OVERRIDE.
It creates only a temporary synthetic socket and a public credential fixture.
"""
from __future__ import annotations

import os
from pathlib import Path
import select
import signal
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import authority_fd_entrypoint as entrypoint
from catchplate import authority_launcher as launcher


class WriterSocketAccessTests(unittest.TestCase):
    def test_both_launchers_have_the_same_exact_role_groups(self):
        expected = {
            "runtime": (65520,),
            "verifier": (65518, 65519, 65521, 65522, 65523),
            "planner": (65519,),
            "planner-writer": (),
            "issuer": (65523,),
            "executor": (65523,),
            "witness": (),
        }
        self.assertEqual(launcher.ROLE_SUPPLEMENTARY_GIDS, expected)
        self.assertEqual(entrypoint.ROLE_SUPPLEMENTARY_GIDS,
                         {"control-plane": (65530, 65524), **expected})

    @unittest.skipUnless(os.environ.get("CATCHPLATE_ISOLATED_SOCKET_FIXTURE") == "1",
                         "requires explicitly selected disposable root container")
    def test_real_dac_after_actual_role_drops(self):
        self.assertEqual((os.getuid(), os.getgid()), (0, 0))
        with tempfile.TemporaryDirectory(prefix="writer-socket-fixture-") as directory:
            os.chmod(directory, 0o755)
            writer = Path(directory) / "writer"
            writer.mkdir(mode=0o750)
            credential = writer / "public-credential-fixture"
            credential.write_bytes(b"public fixture, not a credential")
            os.chown(credential, 65519, 65519)
            os.chmod(credential, 0o400)
            os.chown(writer, 65519, 65519)
            path = str(writer / "authority.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                os.chown(path, 65519, 65519)
                os.chmod(path, 0o660)
                listener.listen(32)
                for drop in (launcher._drop_role_identity, entrypoint._drop_identity):
                    for role in ("verifier", "planner", "runtime", "issuer", "executor", "witness"):
                        with self.subTest(drop=drop.__name__, role=role):
                            self._child(listener, path, credential, drop, role,
                                        allowed=role in {"verifier", "planner"})
                # Negative control reproduces the old verifier group omission.
                self._child(listener, path, credential, self._old_verifier_identity,
                            "verifier", allowed=False)

    @staticmethod
    def _old_verifier_identity(role):
        uid, gid = launcher.ROLE_IDENTITIES[role]
        os.setgroups([value for value in launcher.ROLE_SUPPLEMENTARY_GIDS[role] if value != 65519])
        os.setgid(gid)
        os.setuid(uid)

    def _child(self, listener, path, credential, drop, role, *, allowed):
        pid = os.fork()
        if pid == 0:
            try:
                listener.close()
                drop(role)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(1)
                    try:
                        client.connect(path)
                    except PermissionError:
                        if allowed:
                            raise AssertionError("permitted role cannot connect")
                    else:
                        if not allowed:
                            raise AssertionError("unselected role can connect")
                try:
                    credential.read_bytes()
                except PermissionError:
                    pass
                else:
                    raise AssertionError("socket access also exposed writer-only material")
            except BaseException:
                os._exit(1)
            os._exit(0)
        descriptor = os.pidfd_open(pid)
        try:
            ready, _, _ = select.select([descriptor], [], [], 10)
            if not ready:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
            self.assertTrue(ready, "fixture child did not terminate")
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()

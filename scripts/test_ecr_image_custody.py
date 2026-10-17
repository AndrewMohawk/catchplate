"""Actual Linux memfd/seal component controls; no AWS, files or authority proof."""
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import select
import signal
import sys
import threading
import traceback
import unittest
from unittest import mock

def _no_network(event, _arguments):
    if event.startswith("socket."):
        raise PermissionError("custody tests forbid sockets and DNS")


sys.addaudithook(_no_network)
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import ecr_image_artifact as artifact
from catchplate import ecr_image_custody as custody


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def fixture(*, layer=True, repeated=False):
    config, content = b'{"architecture":"amd64"}', b"opaque layer content\x00\xff"
    config_row = {"mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": digest(config), "size": len(config)}
    layer_row = {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "digest": digest(content), "size": len(content)}
    layers = ([layer_row, dict(layer_row)] if repeated else [layer_row]) if layer else []
    raw = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": config_row, "layers": layers}, indent=2).encode()
    values = {digest(config): config}
    if layer:
        values[digest(content)] = content
    return raw, values


def streams(values):
    return {key: io.BytesIO(value) for key, value in values.items()}


class FunctionReader:
    def __init__(self, function):
        self.read = function


class EcrImageCustodyTests(unittest.TestCase):
    def setUp(self):
        self.created = []
        original = os.memfd_create

        def create(*args, **kwargs):
            fd = original(*args, **kwargs)
            self.created.append(fd)
            return fd

        self.creator = mock.patch.object(custody.os, "memfd_create", side_effect=create)
        self.creator.start()
        self.addCleanup(self.creator.stop)

    def assert_closed(self):
        for fd in self.created:
            with self.assertRaises(OSError) as raised:
                os.fstat(fd)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def safe_failure(self, function):
        with self.assertRaises(custody.CustodyError) as raised:
            function()
        self.assertEqual(str(raised.exception), "ECR image custody unavailable")
        self.assertEqual(repr(raised.exception), "CustodyError('ECR image custody unavailable')")
        return raised.exception

    def test_verified_bytes_survive_source_mutation_and_repeated_layers(self):
        raw, values = fixture(repeated=True)
        readers = streams(values)
        with custody.capture(raw, readers) as held:
            self.assertIs(type(held.image), artifact.VerifiedImage)
            self.assertIs(held.image.manifest_bytes, raw)
            self.assertEqual(held.image.manifest.digest, digest(raw))
            self.assertEqual(len(self.created), 2)
            self.assertEqual(held.image.layers[0], held.image.layers[1])
            for reader in readers.values():
                reader.seek(0)
                reader.write(b"MUTATED")
                reader.truncate(7)
            for key, value in values.items():
                self.assertEqual(held.read_blob(key, 0, len(value)), value)
                self.assertEqual(held.read_blob(key, 1, 4), value[1:5])
                self.assertEqual(held.read_blob(key, len(value), 0), b"")
            self.assertNotIn("MUTATED", repr(held))
            self.assertFalse(hasattr(held, "readers"))
        self.assertTrue(all(not reader.closed for reader in readers.values()))
        self.assert_closed()

    def test_actual_kernel_seals_deny_write_shrink_and_growth(self):
        raw, values = fixture()
        with custody.capture(raw, streams(values)) as held:
            for key, blob in held._blobs.items():
                expected = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
                self.assertEqual(fcntl.fcntl(blob.fd, fcntl.F_GET_SEALS) & expected, expected)
                self.assertTrue(fcntl.fcntl(blob.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
                for operation in (lambda: os.write(blob.fd, b"x"),
                        lambda: os.pwrite(blob.fd, b"x", 0),
                        lambda: os.ftruncate(blob.fd, blob.size - 1),
                        lambda: os.ftruncate(blob.fd, blob.size + 1)):
                    with self.assertRaises(OSError) as raised:
                        operation()
                    self.assertEqual(raised.exception.errno, errno.EPERM)
                self.assertEqual(held.read_blob(key, 0, blob.size), values[key])
        self.assert_closed()

    def test_range_types_bounds_and_short_pread(self):
        raw, values = fixture(layer=False)
        key, value = next(iter(values.items()))
        with custody.capture(raw, streams(values)) as held:
            bad = [(None, 0, 1), ("sha256:" + "0" * 64, 0, 1), (key, True, 1),
                (key, 0, False), (key, -1, 1), (key, 0, -1), (key, 0.0, 1),
                (key, len(value) + 1, 0), (key, len(value), 1),
                (key, 0, custody.MAX_RANGE_BYTES + 1)]
            for args in bad:
                self.safe_failure(lambda args=args: held.read_blob(*args))
            original = os.pread
            with mock.patch.object(custody.os, "pread", side_effect=lambda fd, n, offset: original(fd, min(3, n), offset)):
                self.assertEqual(held.read_blob(key, 0, len(value)), value)
            with mock.patch.object(custody.os, "pread", return_value=b""):
                self.safe_failure(lambda: held.read_blob(key, 0, 1))
            with mock.patch.object(custody.os, "pread", return_value=b"xx"):
                self.safe_failure(lambda: held.read_blob(key, 0, 1))
            with mock.patch.object(custody, "MAX_RANGE_READ_CALLS", 1), mock.patch.object(
                    custody.os, "pread", side_effect=lambda fd, n, offset: original(fd, 1, offset)):
                self.safe_failure(lambda: held.read_blob(key, 0, 2))
        self.assert_closed()

    def test_context_exception_idempotent_close_and_no_public_constructor(self):
        raw, values = fixture()
        marker = KeyboardInterrupt("test cancellation")
        with self.assertRaises(KeyboardInterrupt) as raised:
            with custody.capture(raw, streams(values)) as held:
                raise marker
        self.assertIs(raised.exception, marker)
        held.close()
        held.close()
        self.safe_failure(lambda: held.image)
        self.safe_failure(lambda: held.read_blob(next(iter(values)), 0, 0))
        self.safe_failure(held.__enter__)
        self.safe_failure(custody.SealedImage)
        self.assert_closed()

    def test_exact_ten_mib_range_and_read_guard_rechecks(self):
        raw, values = fixture()
        document = json.loads(raw)
        body = b"x" * (10 * 1024 * 1024)
        old = document["layers"][0]["digest"]
        document["layers"][0].update(digest=digest(body), size=len(body))
        del values[old]
        values[digest(body)] = body
        raw = json.dumps(document).encode()
        with custody.capture(raw, streams(values)) as held:
            self.assertEqual(held.read_blob(digest(body), 0, len(body)), body)
            self.safe_failure(lambda: held.read_blob(digest(body), 0, len(body) + 1))
            original = fcntl.fcntl
            checked = 0

            def missing_seal_after_read(fd, command, *args):
                nonlocal checked
                result = original(fd, command, *args)
                if command == fcntl.F_GET_SEALS:
                    checked += 1
                    if checked == 2:
                        return result & ~fcntl.F_SEAL_WRITE
                return result

            with mock.patch.object(custody.fcntl, "fcntl", side_effect=missing_seal_after_read):
                self.safe_failure(lambda: held.read_blob(digest(body), 0, 1))
            self.assertEqual(checked, 2)
        self.assert_closed()

    def test_bad_manifest_and_rosters_refuse_before_allocation(self):
        raw, values = fixture()
        for body, readers in [(b"{}", streams(values)), (raw + b"{}", streams(values)),
                (bytearray(raw), streams(values)), (raw, {}),
                (raw, {**streams(values), "sha256:" + "0" * 64: io.BytesIO(b"extra")}),
                (raw, {key: object() for key in values}), (raw, list(values.items()))]:
            self.safe_failure(lambda body=body, readers=readers: custody.capture(body, readers))
        self.assertEqual(self.created, [])

    def test_invalid_reader_output_is_not_copied_and_cleanup_is_complete(self):
        raw, values = fixture(layer=False)
        key, value = next(iter(values.items()))
        for result in (None, bytearray(value), "secret-canary", value + b"extra"):
            with mock.patch.object(custody.os, "write", wraps=os.write) as write:
                self.safe_failure(lambda: custody.capture(raw, {key: FunctionReader(lambda n: result)}))
                write.assert_not_called()
            self.assert_closed()
        for bad in (value[:-1], b"x" * len(value), value + b"trailing"):
            self.safe_failure(lambda bad=bad: custody.capture(raw, {key: io.BytesIO(bad)}))
            self.assert_closed()

    def test_bounded_short_writes_and_invalid_write_results(self):
        raw, values = fixture(layer=False)
        original = os.write
        with mock.patch.object(custody.os, "write", side_effect=lambda fd, body: original(fd, body[:2])):
            with custody.capture(raw, streams(values)) as held:
                key, value = next(iter(values.items()))
                self.assertEqual(held.read_blob(key, 0, len(value)), value)
        for result in (0, -1, True, None, 10**6):
            with mock.patch.object(custody.os, "write", return_value=result):
                self.safe_failure(lambda: custody.capture(raw, streams(values)))
            self.assert_closed()
        with mock.patch.object(custody, "MAX_WRITE_CALLS_PER_BLOB", 1), mock.patch.object(
                custody.os, "write", side_effect=lambda fd, body: original(fd, body[:1])):
            self.safe_failure(lambda: custody.capture(raw, streams(values)))
        self.assert_closed()

    def test_allocation_and_sealing_failures_close_partial_capture_and_redact(self):
        raw, values = fixture()
        first_create = custody.os.memfd_create
        count = 0

        def allocation(*args):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("secret-allocation-canary")
            return first_create(*args)

        with mock.patch.object(custody.os, "memfd_create", side_effect=allocation):
            error = self.safe_failure(lambda: custody.capture(raw, streams(values)))
            self.assertNotIn("secret-allocation-canary", "".join(traceback.format_exception(error)))
        self.assert_closed()
        original = fcntl.fcntl
        sealed = 0

        def seal(fd, command, *args):
            nonlocal sealed
            if command == fcntl.F_ADD_SEALS:
                sealed += 1
                if sealed == 2:
                    raise OSError("secret-sealing-canary")
            return original(fd, command, *args)

        with mock.patch.object(custody.fcntl, "fcntl", side_effect=seal):
            error = self.safe_failure(lambda: custody.capture(raw, streams(values)))
            self.assertNotIn("secret-sealing-canary", "".join(traceback.format_exception(error)))
        self.assert_closed()

    def test_reader_exception_redacted_and_baseexception_cleanup_preserved(self):
        raw, values = fixture(layer=False)
        key = next(iter(values))

        def reject(_amount):
            raise RuntimeError("secret-reader-canary")

        error = self.safe_failure(lambda: custody.capture(raw, {key: FunctionReader(reject)}))
        self.assertNotIn("secret-reader-canary", "".join(traceback.format_exception(error)))
        self.assert_closed()
        for boundary in ("reader", "write", "seal"):
            marker = KeyboardInterrupt("cancel")

            def cancel(*_args):
                raise marker

            patcher = mock.patch.object(custody.os, "write", side_effect=cancel) if boundary == "write" else (
                mock.patch.object(custody.fcntl, "fcntl", side_effect=cancel) if boundary == "seal" else mock.patch.object(
                    custody, "MAX_WRITE_CALLS_PER_BLOB", custody.MAX_WRITE_CALLS_PER_BLOB))
            with patcher, self.assertRaises(KeyboardInterrupt) as raised:
                custody.capture(raw, {key: FunctionReader(cancel)} if boundary == "reader" else streams(values))
            self.assertIs(raised.exception, marker)
            self.assert_closed()

    def test_current_owner_and_replaced_inode_refused(self):
        raw, values = fixture(layer=False)
        key = next(iter(values))
        with custody.capture(raw, streams(values)) as held:
            for name, current in (("getpid", os.getpid()), ("getuid", os.getuid()), ("geteuid", os.geteuid())):
                with mock.patch.object(custody.os, name, return_value=current + 1):
                    self.safe_failure(lambda: held.read_blob(key, 0, 1))
                    self.safe_failure(lambda: held.image)
            replacement = os.memfd_create("custody-test", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
            try:
                os.dup2(replacement, held._blobs[key].fd, inheritable=False)
                self.safe_failure(lambda: held.read_blob(key, 0, 0))
            finally:
                os.close(replacement)
        self.assert_closed()

    def test_forked_handle_refuses_reads_child_cleanup_preserves_parent(self):
        raw, values = fixture(layer=False)
        key, value = next(iter(values.items()))
        with custody.capture(raw, streams(values)) as held:
            read_end, write_end = os.pipe()
            child = os.fork()
            if child == 0:
                try:
                    os.close(read_end)
                    try:
                        held.read_blob(key, 0, 1)
                    except custody.CustodyError:
                        held.close()
                        held.close()
                        os.write(write_end, b"refused")
                    else:
                        os.write(write_end, b"bad")
                finally:
                    os._exit(0)
            os.close(write_end)
            reaped = False
            try:
                ready, _, _ = select.select([read_end], [], [], 5)
                self.assertTrue(ready, "bounded child did not report")
                self.assertEqual(os.read(read_end, 16), b"refused")
                _, status = os.waitpid(child, 0)
                reaped = True
                self.assertEqual(status, 0)
            finally:
                os.close(read_end)
                if not reaped:
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(child, 0)
            self.assertEqual(held.read_blob(key, 0, len(value)), value)
        self.assert_closed()

    def test_close_serializes_with_in_progress_range(self):
        raw, values = fixture(layer=False)
        key, value = next(iter(values.items()))
        held = custody.capture(raw, streams(values))
        entered, release, closing, closed = (threading.Event() for _ in range(4))
        results, failures = [], []
        original = os.pread

        def pread(*args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test synchronization timeout")
            return original(*args)

        def read():
            try:
                results.append(held.read_blob(key, 0, len(value)))
            except BaseException as error:
                failures.append(error)

        def close():
            closing.set()
            held.close()
            closed.set()

        reader, closer = threading.Thread(target=read), threading.Thread(target=close)
        with mock.patch.object(custody.os, "pread", side_effect=pread):
            reader.start()
            try:
                self.assertTrue(entered.wait(5))
                closer.start()
                self.assertTrue(closing.wait(5))
                self.assertFalse(closed.is_set())
            finally:
                release.set()
                reader.join(5)
                if closer.ident is not None:
                    closer.join(5)
                held.close()
        self.assertFalse(reader.is_alive() or closer.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(results, [value])
        self.assertTrue(closed.is_set())
        self.assert_closed()


if __name__ == "__main__":
    unittest.main(verbosity=2)

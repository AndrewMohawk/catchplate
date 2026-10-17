#!/usr/bin/env python3
"""Real bytes/FDs and SDK callers; synthetic ext4/verity/root component fixtures.

No kernel seal, admitted startup or signed assembly is claimed. A catalog pin
must come from protected selection; hashing our synthetic document is only a
test input, not an authentication scheme. No authority or receipt is cached.
"""
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import test_authority_local_artifact_measure_cache as files
from scripts.test_authority_local_startup_content_cache import RetainedFile
from catchplate import authority_local_artifact_measure as measure
from catchplate import authority_local_content_catalog as catalog
from catchplate import authority_local_startup as startup


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def document(rows):
    return json.dumps({"schema": "catchplate.sealedContentCatalog/v1", "entries": rows},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def activate(raw):
    return measure.pinned_content_catalog(raw, sha(raw))


@contextmanager
def kernel():
    fixture = files.ArtifactMeasureCacheTests(methodName="runTest")
    fixture.setUp()
    try: yield fixture
    finally:
        if not fixture.doCleanups(): raise AssertionError("file fixture cleanup failed")


def observe(path, fixture):
    fixture.reads.clear()
    with path.open("rb") as stream:
        return measure.observe_catalog_entry(stream.fileno(), check=lambda: None)


def cold_worker(value):
    raw = bytes.fromhex(value["body"])
    encoded = value["catalog"].encode("ascii")
    # A genuinely fresh interpreter and new real files; kernel identity alone
    # is synthetic. Neither caller's content hash result is replaced.
    with RetainedFile(raw) as item:
        assert not measure._FILE_DIGEST_CACHE
        with measure.pinned_content_catalog(encoded, value["pin"]):
            assert item.read() == sha(raw)
            assert item.kernel.reads == [(1, len(raw), 0)] and item.reader_calls == 0
            assert item.kernel.read(item.path)["sha256"] == sha(raw)
            assert item.kernel.reads == [(1, len(raw), 0)]
            item.owner.check(full=True)
            assert not measure._FILE_DIGEST_CACHE
        assert item.read() == sha(raw) and item.reader_calls == 1
        assert sum(length for _, _, length in item.kernel.reads) == len(raw)
        measure._FILE_DIGEST_CACHE.clear()
        item.kernel.read(item.path)
        item.kernel.assert_full_read(len(raw))
    return {"both_cold_hits": True, "full_reads_after_exit": True}


class ContentCatalogTests(unittest.TestCase):
    def test_fresh_process_both_real_callers_and_full_reads_after_exit(self):
        for body in (b"public\x00\xffcontent", b""):
            with self.subTest(empty=not body), kernel() as fixture:
                path = fixture.file(raw=body)
                row = observe(path, fixture)
                self.assertEqual(row, {"fsVerityDigest": "sha256:" + fixture.verity[path.stat().st_ino].hex(),
                    "size": len(body), "sha256": sha(body)})
                encoded = document([row])
                result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker"],
                    input=json.dumps({"body": body.hex(), "catalog": encoded.decode(), "pin": sha(encoded)}),
                    text=True, capture_output=True, timeout=15, cwd=ROOT)
                self.assertEqual(result.returncode, 0, "cold catalog component worker refused")
                self.assertEqual(json.loads(result.stdout), {"both_cold_hits": True, "full_reads_after_exit": True})

    def test_producer_observes_actual_bytes_not_claims_and_refuses_active_catalog(self):
        with kernel() as fixture:
            raw = b"actual-public-content" * 60000
            path = fixture.file(raw=raw)
            row = observe(path, fixture)
            fixture.assert_full_read(len(raw))
            self.assertEqual(row["sha256"], sha(raw))
            row["sha256"] = "sha256:" + "0" * 64  # Returned value is not an LRU reference.
            current = observe(path, fixture)
            self.assertEqual(current["sha256"], sha(raw))
            fixture.assert_hit(len(raw))
            fixture.reads.clear()
            with activate(document([current])), path.open("rb") as stream:
                calls = []
                with self.assertRaises(ValueError):
                    measure.observe_catalog_entry(stream.fileno(), check=lambda: calls.append(None))
                self.assertEqual((calls, fixture.reads), ([], []))
            fixture.verity[path.stat().st_ino] = OSError(errno.ENODATA, "synthetic unsealed")
            with self.assertRaises(ValueError): observe(path, fixture)

    def test_exact_canonical_pin_types_and_json_grammar(self):
        row = {"fsVerityDigest": "sha256:" + "1" * 64, "size": 0, "sha256": sha(b"")}
        raw = document([row])
        for pin in ("sha256:" + "0" * 64, sha(raw).upper(), sha(raw)[7:], None, True):
            with self.subTest(pin=pin), self.assertRaises(ValueError): measure.pinned_content_catalog(raw, pin)
        for value in (raw.decode(), bytearray(raw), None):
            with self.assertRaises(ValueError): measure.pinned_content_catalog(value, sha(raw))
        invalid = [raw + b"\n", b" " + raw, raw.replace(b'"schema"', b'"sche\\u006da"'),
            raw.replace(b'"size":0', b'"size":0,"size":0'),
            raw.replace(b'"schema":"catchplate.sealedContentCatalog/v1"',
                b'"schema":"catchplate.sealedContentCatalog/v1","schema":"catchplate.sealedContentCatalog/v1"'),
            b'[]', b'null', b'{"schema":"\xff","entries":[]}', raw.replace(b'"size":0', b'"size":0.0'),
            raw.replace(b'"size":0', b'"size":NaN')]
        for value in ({"schema": "wrong", "entries": [row]}, {"schema": catalog.SCHEMA, "entries": [row], "extra": 0},
                {"entries": [row]}, {"schema": catalog.SCHEMA, "entries": {}},
                {"schema": catalog.SCHEMA, "entries": []}):
            invalid.append(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
        for changed in ({**row, "size": True}, {**row, "size": -1}, {**row, "size": measure.spec.MAX_FILE_BYTES + 1},
                {**row, "sha256": "sha256:" + "A" * 64}, {**row, "fsVerityDigest": "1" * 64},
                {**row, "unknown": 1}, {key: value for key, value in row.items() if key != "size"}):
            invalid.append(document([changed]))
        for value in invalid:
            with self.subTest(size=len(value)), self.assertRaises(ValueError): activate(value)

    def test_sorted_unique_rows_and_fixed_size_bounds(self):
        rows = [{"fsVerityDigest": "sha256:" + "1" * 64, "size": size, "sha256": sha(b"public")}
            for size in (0, 1, measure.spec.MAX_FILE_BYTES)]
        with activate(document(rows)): pass
        for changed in (list(reversed(rows)), [rows[0], rows[0]],
                [rows[0], {**rows[0], "sha256": sha(b"different")} ]):
            with self.assertRaises(ValueError): activate(document(changed))
        self.assertEqual(catalog.MAX_BYTES, 8 * 1024 * 1024)
        self.assertEqual(measure.spec.MAX_BUNDLE_FILES, 32768)
        many = [{**rows[0], "size": index} for index in range(32768)]
        with activate(document(many)): pass
        with self.assertRaises(ValueError): activate(document([*many, {**rows[0], "size": 32768}]))
        oversized = b" " * (8 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError): activate(oversized)

    def test_catalog_miss_changed_identity_and_unsupported_fallback_read_actual_bytes(self):
        with kernel() as fixture:
            known = fixture.file("known", b"known")
            raw = document([observe(known, fixture)])
            measure._FILE_DIGEST_CACHE.clear()
            changed = fixture.file("other", b"different")
            with activate(raw):
                self.assertEqual(fixture.read(changed)["sha256"], sha(b"different"))
                fixture.assert_full_read(9)
            for unsupported in ("unsealed", "unknown-fs"):
                measure._FILE_DIGEST_CACHE.clear()
                if unsupported == "unsealed":
                    fixture.verity[known.stat().st_ino] = OSError(errno.ENODATA, "synthetic unsealed")
                else: fixture.eligible.return_value = False
                with activate(raw):
                    for _ in range(2):
                        self.assertEqual(fixture.read(known)["sha256"], sha(b"known"))
                        fixture.assert_full_read(5)
                self.assertFalse(measure._FILE_DIGEST_CACHE)

    def test_conflicting_catalog_and_actual_observation_refuse_in_both_callers(self):
        with RetainedFile() as item:
            row = observe(item.path, item.kernel)
            observed = dict(measure._FILE_DIGEST_CACHE)
            wrong = document([{**row, "sha256": sha(b"different") }])
            with activate(wrong):
                with self.assertRaises(ValueError): item.read()
                with self.assertRaises(ValueError): item.kernel.read(item.path)
            self.assertEqual(dict(measure._FILE_DIGEST_CACHE), observed)
            self.assertEqual(item.reader_calls, 0)

    def test_current_metadata_name_custody_and_lifetime_still_checked_on_hits(self):
        for change in ("mode", "owner", "hardlink", "name", "closed", "deadline"):
            with self.subTest(change=change), RetainedFile() as item:
                row = observe(item.path, item.kernel)
                measure._FILE_DIGEST_CACHE.clear()
                with activate(document([row])):
                    self.assertEqual(item.read(), sha(item.raw)); item.assert_hit(self)
                    if change == "mode": item.path.chmod(0o600)
                    elif change == "owner": item.metadata[item.real_fstat(item.fd).st_ino] = {"st_uid": 23}
                    elif change == "hardlink": os.link(item.path, item.path.with_name("linked"))
                    elif change == "name":
                        item.path.rename(item.path.with_name("old"))
                        item.kernel.file(item.path.name, item.raw)
                    elif change == "closed": item.owner.closed = True
                    else: item.boot = item.owner.value["deadlineBoottimeNs"]
                    with self.assertRaises(startup.LocalStartupError): item.read()
                self.assertEqual(item.reader_calls, 0)
                self.assertFalse(measure._FILE_DIGEST_CACHE)
        with kernel() as fixture:
            path = fixture.file()
            row = observe(path, fixture)
            measure._FILE_DIGEST_CACHE.clear()
            with activate(document([row])), self.assertRaises(ValueError):
                fixture.read(path, selected={**files.entry(path), "mode": 0o600})
            self.assertFalse(measure._FILE_DIGEST_CACHE)

    def test_eof_verity_and_final_cancellation_fail_without_catalog_lru_population(self):
        for change in ("append", "verity", "cancel", "deadline"):
            with self.subTest(change=change), RetainedFile() as item:
                row = observe(item.path, item.kernel)
                measure._FILE_DIGEST_CACHE.clear()
                sentinel = KeyboardInterrupt("synthetic cancellation")
                def after_read(fd, body):
                    self.assertEqual(body, b"")  # Only the real EOF probe on a hit.
                    if change == "cancel": raise sentinel
                    if change == "verity": item.kernel.verity[item.real_fstat(fd).st_ino] = b"v" * 32
                    elif change == "deadline": item.boot = item.owner.value["deadlineBoottimeNs"]
                    else:
                        item.path.chmod(0o600)
                        item.path.write_bytes(item.raw + b"x")
                        item.path.chmod(0o400)
                with activate(document([row])):
                    item.kernel.after_read = after_read
                    with self.assertRaises((ValueError, startup.LocalStartupError, KeyboardInterrupt)) as caught:
                        item.read()
                    if change == "cancel": self.assertIs(caught.exception, sentinel)
                self.assertFalse(measure._FILE_DIGEST_CACHE)
                self.assertEqual(item.reader_calls, 0)

    def test_single_use_nested_refusal_and_exception_cleanup(self):
        with kernel() as fixture:
            path = fixture.file()
            raw = document([observe(path, fixture)])
            measure._FILE_DIGEST_CACHE.clear()
            context, nested = activate(raw), activate(raw)
            sentinel = KeyboardInterrupt("synthetic cancellation")
            with self.assertRaises(KeyboardInterrupt) as caught:
                with context:
                    with self.assertRaises(ValueError): context.__enter__()
                    with self.assertRaises(ValueError): nested.__enter__()
                    fixture.read(path); fixture.assert_hit(path.stat().st_size)
                    raise sentinel
            self.assertIs(caught.exception, sentinel)
            for used in (context, nested):
                with self.assertRaises(ValueError): used.__enter__()
            fixture.read(path); fixture.assert_full_read(path.stat().st_size)

    def test_other_thread_has_no_catalog_and_cannot_enter_or_exit_foreign_context(self):
        with kernel() as fixture:
            path = fixture.file()
            raw = document([observe(path, fixture)])
            measure._FILE_DIGEST_CACHE.clear()
            active, foreign = activate(raw), activate(raw)
            results = []
            def work():
                try:
                    for operation in (foreign.__enter__, lambda: active.__exit__(None, None, None)):
                        try: operation()
                        except ValueError: pass
                        else: raise AssertionError("cross-thread catalog ownership admitted")
                    measured = fixture.read(path)
                    results.append((measured["sha256"], sum(size for _, _, size in fixture.reads)))
                except BaseException as error: results.append(error)
            with active:
                thread = threading.Thread(target=work, daemon=True)
                thread.start(); thread.join(5)
                self.assertFalse(thread.is_alive(), "bounded synthetic read did not complete")
                self.assertEqual(results, [(sha(path.read_bytes()), path.stat().st_size)])
                measure._FILE_DIGEST_CACHE.clear()
                fixture.read(path); fixture.assert_hit(path.stat().st_size)

    def test_fork_drops_activation_and_parent_context_survives(self):
        with kernel() as fixture:
            path = fixture.file()
            raw = document([observe(path, fixture)])
            measure._FILE_DIGEST_CACHE.clear()
            context = activate(raw)
            with context:
                read_fd, write_fd = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(read_fd)
                    try:
                        try: context.__enter__()
                        except ValueError: pass
                        else: raise AssertionError("inherited context admitted")
                        fixture.read(path); fixture.assert_full_read(path.stat().st_size)
                        os.write(write_fd, b"full-read")
                        os._exit(0)
                    except BaseException: os._exit(1)
                os.close(write_fd)
                try:
                    ready, _, _ = select.select([read_fd], [], [], 5)
                    if not ready: os.kill(pid, signal.SIGKILL)
                    result = os.read(read_fd, 32) if ready else b""
                    _, status = os.waitpid(pid, 0)
                    self.assertEqual((result, status), (b"full-read", 0))
                finally: os.close(read_fd)
                self.assertFalse(measure._FILE_DIGEST_CACHE)
                fixture.read(path); fixture.assert_hit(path.stat().st_size)

    def test_final_callback_cannot_remove_catalog_or_enable_producer_context(self):
        for retained in (False, True):
            with self.subTest(retained=retained), RetainedFile() as item:
                raw = document([observe(item.path, item.kernel)])
                measure._FILE_DIGEST_CACHE.clear()
                context = activate(raw)
                context.__enter__()
                try:
                    item.kernel.after_read = lambda _fd, _body: context.__exit__(None, None, None)
                    with self.assertRaises(ValueError):
                        item.read() if retained else item.kernel.read(item.path)
                    self.assertFalse(measure._FILE_DIGEST_CACHE)
                finally:
                    if context._active: context.__exit__(None, None, None)
        with kernel() as fixture:
            path = fixture.file()
            raw = document([observe(path, fixture)])
            context = activate(raw)
            fixture.reads.clear()
            with path.open("rb") as stream:
                try:
                    with self.assertRaises(ValueError):
                        measure.observe_catalog_entry(stream.fileno(), check=context.__enter__)
                    self.assertEqual(fixture.reads, [])
                finally:
                    if context._active: context.__exit__(None, None, None)


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        try:
            value = json.loads(sys.stdin.read(4097))
            print(json.dumps(cold_worker(value), sort_keys=True))
        except BaseException:
            print('{"component_worker_failed":true}')
            raise SystemExit(1) from None
    else:
        unittest.main(verbosity=2)

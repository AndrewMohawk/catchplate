#!/usr/bin/env python3
"""Cold pinned catalog through the actual prepared-static adoption readers.

Real bytes, descriptors, hashes and new interpreters; ownership, ext4 eligibility
and kernel seals are the existing PreparedTree fixture's SYNTHETIC observations.
This is not signed installer admission, real-kernel proof or startup timing.
The parent observes public content; the child's cache starts empty. No package,
authorization result, deadline or physical file identity is reused.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.test_authority_local_prepared_install import PreparedTree, digest
from serverware import authority_artifact_spec as spec
from serverware import authority_local_artifact_measure as measure
from serverware import authority_local_content_catalog as catalog


def observed_catalog():
    """Use the real producer, not a remembered/claimed source SHA, in the parent."""
    with PreparedTree() as fixture:
        rows = []
        for name, raw in sorted(fixture.STATIC.items()):
            with (fixture.source / name).open("rb") as source:
                row = measure.observe_catalog_entry(source.fileno(), check=fixture.check)
            assert row["sha256"] == digest(raw)
            rows.append(row)
        assert sum(size for _, _, size in fixture.reads) == sum(map(len, fixture.STATIC.values()))
    rows.sort(key=lambda row: (row["fsVerityDigest"], row["size"]))
    return spec.canonical_json_bytes({"schema": catalog.SCHEMA, "entries": rows})


def worker(value):
    if sys.flags.optimize:
        raise RuntimeError("component worker requires assertions")
    raw, case = value["catalog"].encode("ascii"), value["case"]
    assert case in {"success", "pin", "digest", "mode", "roster", "cancel"}
    with PreparedTree() as fixture:
        assert not measure._FILE_DIGEST_CACHE
        cancellation = TimeoutError("synthetic original owner deadline")
        if case == "digest":
            next(row for row in fixture.entries if row["path"] == "code/main.py")["sourceSha256"] = "sha256:" + "0" * 64
        elif case == "mode":
            (fixture.prepared / "code/main.py").chmod(0o400)
        elif case == "roster":
            fixture.write(fixture.prepared / "unlisted", b"unlisted public content")
        elif case == "cancel":
            def cancel_after_eof():
                if fixture.reads:
                    raise cancellation
            fixture.cancel = cancel_after_eof
        before = fixture.identities()
        pin = "sha256:" + "0" * 64 if case == "pin" else value["pin"]
        refused = False
        try:
            with measure.pinned_content_catalog(raw, pin):
                parents, installed = fixture.adopt()
                assert case == "success", "invalid prepared tree was accepted"
                assert set(parents) == {"", "code", "code/nested"}
                assert set(installed) == set(fixture.STATIC)
                for name, content in fixture.STATIC.items():
                    info = fixture.real_stat(fixture.prepared / name)
                    row = installed[name]
                    assert row["sha256"] == digest(content)
                    assert (row["device"], row["inode"], row["size"]) == (info.st_dev, info.st_ino, len(content))
                    assert row["action"] == "adopt-prepared-static"
                assert sorted(fixture.reads) == sorted(
                    (fixture.real_stat(fixture.prepared / name).st_ino, len(content), 0)
                    for name, content in fixture.STATIC.items())
                assert not measure._FILE_DIGEST_CACHE
        except (ValueError, TimeoutError) as error:
            assert case != "success", "valid cold adoption refused"
            if case == "cancel" and error is not cancellation:
                raise AssertionError("original deadline callback was not observed") from error
            refused = True
        assert refused == (case != "success")
        assert fixture.identities() == before
        assert fixture.prepared.is_dir() and not (fixture.directory / ".incoming").exists()
        assert fixture.chowns == [] and not measure._FILE_DIGEST_CACHE
        if case == "pin":
            assert fixture.reads == [] and not hasattr(fixture.owner, "tree")
        if case == "cancel":
            assert fixture.reads and all(size == 0 for _, _, size in fixture.reads)
        if case == "success":
            # The catalog scope must not seed the observed memo or silently
            # make subsequent unscoped adoption trust the earlier observation.
            fixture.reads.clear()
            fixture.adopt()
            for name, content in fixture.STATIC.items():
                inode = fixture.real_stat(fixture.prepared / name).st_ino
                assert sum(size for actual, _, size in fixture.reads if actual == inode) == len(content)
            assert fixture.identities() == before
        return {"case": case, "refused": refused, "no_consumption": True,
                "cold_catalog_hit": case == "success", "unscoped_full_read": case == "success"}


class PreparedContentCatalogTests(unittest.TestCase):
    def cold(self, case):
        raw = observed_catalog()
        result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker"],
            input=json.dumps({"catalog": raw.decode("ascii"), "pin": digest(raw), "case": case}),
            text=True, capture_output=True, timeout=15, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"case": case, "refused": case != "success",
            "no_consumption": True, "cold_catalog_hit": case == "success", "unscoped_full_read": case == "success"})

    def test_two_fresh_interpreters_adopt_with_eof_only_then_fully_read_after_scope(self):
        for index in range(2):
            with self.subTest(interpreter=index):
                self.cold("success")

    def test_wrong_catalog_pin_refuses_before_opening_prepared_tree(self):
        self.cold("pin")

    def test_ambient_python_optimization_cannot_disable_worker_assertions(self):
        with patch.dict(os.environ, {"PYTHONOPTIMIZE": "1"}):
            self.cold("success")

    def test_catalog_hit_preserves_digest_metadata_roster_and_original_deadline_guards(self):
        for case in ("digest", "mode", "roster", "cancel"):
            with self.subTest(case=case):
                self.cold(case)


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        value = sys.stdin.read(4097)
        assert len(value) <= 4096
        print(json.dumps(worker(json.loads(value)), sort_keys=True))
    else:
        unittest.main(verbosity=2)

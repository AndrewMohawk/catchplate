#!/usr/bin/env python3
"""Fixed public-write-plan safety controls; no protected installation or owner.

The fixed job planner independently authenticates complete predecessors. These
controls cover the writer's additional closed path/order/metadata/codec contract,
not that planner, native admission, fsync, retained descriptors or live cleanup.
The parent example additionally uses a genuine synthetic precreation signature.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_publication as publication
import test_native_pilot_genesis_parent_authority as parents

p = g.p


def row(path, raw, uid=0, gid=0):
    return dict(path=path, uid=uid, gid=gid, mode=0o400, raw=raw, sha256=p.sha(raw))


def ordinary_plan(role):
    # Explicitly grammar-only values: these are not valid native service
    # artifacts and can never bypass jobs.publication_plan's authentication.
    raw = g.canonical({"apiVersion": "synthetic-writer-codec-control/v1", "nativeU64": (1 << 63) + 7})
    files = tuple(row(path, raw, 62001, 62101) if index in (1, 2) else row(path, raw)
        for index, path in enumerate(publication._paths("install-ordinary-" + role)))
    return dict(files=files, launchPin={"path": files[-1]["path"], "sha256": files[-1]["sha256"]},
        deadline=5_000_000_000, epochLimit=9_000_000_000)


class GenesisPublicPublicationTests(unittest.TestCase):
    def refused(self, job, value):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            publication._plan(job, value)

    def test_real_synthetic_precreation_has_one_fixed_root_owned_destination(self):
        f = parents.fixture()
        input_raw = g.canonical(f["pre_input"])
        raw = parents.authority.checked_result(input_raw,
            {"original": f["precreation_raw"].decode("ascii"), "sha256": p.sha(f["precreation_raw"])},
            boot=f["boot"], now_boottime_ns=f["now"])
        plan = dict(files=(row(publication.PARENT_PATH, raw),), launchPin=None,
            deadline=5_000_000_000, epochLimit=None)
        checked = publication._plan("install-precreation", plan)
        self.assertEqual(checked, plan)
        self.assertIsNone(checked["launchPin"])
        self.assertIsNone(checked["epochLimit"])
        self.assertEqual(checked["files"][0]["uid"], 0)

    def test_full_u64_codec_accepts_small_rows_with_the_actual_bounded_codec(self):
        for role in publication.ROLES:
            job = "install-ordinary-" + role
            plan = publication._plan(job, ordinary_plan(role))
            self.assertEqual(len(plan["files"]), 5)
            for item in plan["files"]:
                self.assertEqual(g.document(item["raw"], g.MAX_BYTES)["nativeU64"], (1 << 63) + 7)

    def test_runtime_delivery_and_launch_are_root_owned_credentials_are_role_owned(self):
        job = "install-ordinary-" + publication.ROLES[0]
        for index in range(5):
            value = ordinary_plan(publication.ROLES[0])
            item = value["files"][index]
            item["uid"], item["gid"] = (0, 0) if index in (1, 2) else (62001, 62101)
            self.refused(job, value)
        value = ordinary_plan(publication.ROLES[0]); value["files"][0]["mode"] = 0o600
        self.refused(job, value)

    def test_only_fixed_paths_exact_order_and_complete_file_set_are_accepted(self):
        role = publication.ROLES[0]; job = "install-ordinary-" + role
        value = ordinary_plan(role); value["files"] = tuple(reversed(value["files"]))
        self.refused(job, value)
        value = ordinary_plan(role); value["files"] = value["files"][:-1]
        self.refused(job, value)
        value = ordinary_plan(role); value["files"][0]["path"] += ".replacement"
        self.refused(job, value)
        self.refused("install-ordinary-bridge", ordinary_plan(role))

    def test_literal_digest_size_and_launch_pin_drift_are_refused(self):
        role = publication.ROLES[0]; job = "install-ordinary-" + role
        value = ordinary_plan(role); value["files"][0]["sha256"] = p.sha(b"changed")
        self.refused(job, value)
        value = ordinary_plan(role); value["launchPin"]["path"] = publication.PARENT_PATH
        self.refused(job, value)
        value = ordinary_plan(role)
        large = b'{"value":"' + b"x" * publication.LIMITS["peer-inspection"] + b'"}'
        value["files"][2].update(raw=large, sha256=p.sha(large))
        self.refused(job, value)
        value = ordinary_plan(role)
        # The old 16-MiB maximum was not a larger supported codec: it refused
        # every input. Large public rows must still obey the actual 4-MiB cap.
        large = b'{"value":"' + b"x" * g.MAX_BYTES + b'"}'
        value["files"][0].update(raw=large, sha256=p.sha(large))
        self.refused(job, value)

    def test_closed_plan_copies_bytes_metadata_and_has_no_overwrite_switch(self):
        role = publication.ROLES[0]; job = "install-ordinary-" + role
        value = ordinary_plan(role); snapshot = copy.deepcopy(value)
        checked = publication._plan(job, value)
        value["files"][0]["path"] = "/unexpected"
        self.assertEqual(checked, snapshot)
        value = ordinary_plan(role); value["overwrite"] = True
        self.refused(job, value)
        value = ordinary_plan(role); value["files"][0]["privateSeed"] = "not accepted"
        self.refused(job, value)


if __name__ == "__main__": unittest.main()

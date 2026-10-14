#!/usr/bin/env python3
"""Derive candidate .350/.351 pins from actual isolated ordinary startups."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

import derive_operator_authority_source_revision as historical
import migrate_operator_authority_frames as frames

_spec = importlib.util.spec_from_file_location("_frames_derivation", historical.__file__)
worker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(worker)
worker.migration = migration = frames.engine
worker.COMMITS = {"old": migration.OLD_COMMIT, "target": migration.TARGET_COMMIT}
worker.IMAGE = migration.IMAGE
worker.SCHEMA = "serverware.operatorAuthorityFramesDerivation/v1"
worker.PIN_SCHEMA = migration.PIN_SCHEMA
require, sha, canonical = migration.require, migration.sha, migration.canonical


def join(old_path, target_path):
    values = []
    for side, filename in (("old", old_path), ("target", target_path)):
        path = Path(filename)
        require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= worker.MAX_OUTPUT)
        value = migration.strict_json(path.read_bytes())
        require(value["schema"] == worker.SCHEMA and value["side"] == side
            and value["sourceCommit"] == worker.COMMITS[side] and value["derivationImage"] == worker.IMAGE)
        pins, evidence = value["pins"], value["evidence"]
        require(pins["emittedDdlSha256"] == sha(evidence["emittedDdl"].encode())
            and pins["structuralManifestJsonSha256"] == sha(evidence["structuralManifestJson"].encode()))
        for field, key in (("sqliteObjectsSha256", "sqliteObjects"),
                ("optionalSqliteObjectsSha256", "optionalSqliteObjects"), ("witnessObjectsSha256", "witnessObjects")):
            require(pins[field] == sha(canonical(evidence[key])))
        values.append(value)
    old, target = values
    rebuild, additions = None, None
    for field in ("sqliteObjects", "optionalSqliteObjects"):
        left = {(row[0], row[1]): row for row in old["evidence"][field]}
        right = {(row[0], row[1]): row for row in target["evidence"][field]}
        require(left.keys() <= right.keys())
        changed = {}
        for key, row in left.items():
            if row != right[key]:
                require(row[:3] == right[key][:3] and row[0] == "table" and row[1] in migration.CHANGED_TABLES)
                changed[row[1]] = {"old": row[3], "target": right[key][3]}
        added = sorted(right[key] for key in right.keys() - left.keys())
        require(rebuild is None or (rebuild == changed and additions == added))
        rebuild, additions = changed, added
    result = {"schema": migration.PIN_SCHEMA, "transitionId": migration.TRANSITION,
        "oldCommit": migration.OLD_COMMIT, "targetBaseCommit": migration.TARGET_COMMIT,
        "derivationImage": migration.IMAGE, "old": old["pins"], "target": target["pins"],
        "rebuildTables": rebuild, "addedObjects": additions}
    return frames.validate_pins(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--side", choices=tuple(worker.COMMITS))
    action.add_argument("--join", nargs=2, metavar=("OLD_JSON", "TARGET_JSON"))
    args = parser.parse_args()
    value = worker.derive(args.side, expected_counts=(217, 218, 186) if args.side == "old" else (218, 219, 187)) \
        if args.side else join(*args.join)
    raw = canonical(value)
    require(len(raw) <= worker.MAX_OUTPUT)
    sys.stdout.buffer.write(raw + b"\n")

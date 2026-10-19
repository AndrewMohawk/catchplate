#!/usr/bin/env python3
"""One-shot labels-only maintenance for existing, active local smoke fixtures.

Run in the existing app's environment as its data owner. Capture a private
manifest with --capture FILE --run-stem STEM (repeat for up to six runs), review
it, then use --manifest FILE for a dry-run. Only --manifest FILE --apply writes
application state. No initialization, provider request, policy publication,
credential replacement, token renewal, or historical-record rewrite occurs.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
SCHEMA = "catchplate.syntheticFixtureLabelRename/v1"
STEM = re.compile(r"serverware-live-(?:smoke|basic)-[0-9a-f]{32}\Z")
KINDS = {"credentials": "credential", "applications": "application", "access_rules": "access_rule"}
UPSTREAM = "https://demo-upstream:8443/echo"


def need(condition):
    if not condition:
        raise ValueError("Synthetic fixture rename refused: reviewed state or scope differs")


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def rows(conn, table):
    # Table names are fixed callers below, never manifest input.
    return [dict(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]


def capture(conn, stems):
    from catchplate import config, operator_catalog_schema as schema, operator_catalog_policy as policy
    need(isinstance(stems, list) and 1 <= len(stems) <= 6 and len(set(stems)) == len(stems)
         and all(type(stem) is str and STEM.fullmatch(stem) for stem in stems))
    catalog = schema.read_catalog(conn)
    schema.validate_bindings(conn, catalog)
    policy.verify_retained_policy(conn, catalog)
    changes, selected = [], {key: set() for key in KINDS}
    for stem in sorted(stems):
        triplet = {}
        for collection, suffix in KINDS.items():
            found = [row for row in catalog[collection] if row["name"] == stem + "-" + suffix]
            need(len(found) == 1 and found[0]["status"] == "active")
            row = triplet[collection] = found[0]
            selected[collection].add(row["id"])
            item = {"collection": collection, "id": row["id"], "old_name": row["name"],
                    "new_name": row["name"].replace("serverware-", "catchplate-", 1),
                    "record_sha256": digest(row)}
            if collection == "credentials":
                need(row["auth_type"] == "bearer" and row["header_name"] == "Authorization"
                     and "connection_type" not in row and "app_preset" not in row)
                core = conn.execute("SELECT * FROM credentials WHERE id=?", (row["id"],)).fetchone()
                need(core is not None and core["kind"] == "bearer")
                item["core_sha256"] = digest(dict(core))
            changes.append(item)
        rule = triplet["access_rules"]
        need(rule["credential_id"] == triplet["credentials"]["id"]
             and rule["application_id"] == triplet["applications"]["id"]
             and rule["upstream_url"] == UPSTREAM and rule["methods"] == ["POST"]
             and "operation_bundle" not in rule and "app_preset" not in rule)
    # Do not rename fixture-labelled credentials/clients used by other workloads.
    for rule in catalog["access_rules"]:
        if rule["status"] == "active" and (rule["credential_id"] in selected["credentials"]
                or rule["application_id"] in selected["applications"]):
            need(rule["id"] in selected["access_rules"])
    state = rows(conn, "operator_demo_policy")
    need(len(state) == 1)
    return {"schema": SCHEMA, "data_directory": str(config.DATA_DIR), "run_stems": sorted(stems),
            "expected_revision": catalog["revision"], "expected_policy_hash": state[0]["policy_hash"],
            "changes": changes}


def operate(*, stems=None, manifest=None, apply=False):
    from catchplate import config, db, operator_publication as publication
    from catchplate import operator_catalog_schema as schema, operator_catalog_policy as policy
    need(type(apply) is bool and (stems is None) != (manifest is None) and not (stems and apply))
    with publication.exclusive(startup=True), closing(db.connect()) as conn:
        conn.execute("BEGIN IMMEDIATE" if apply else "BEGIN")
        try:
            if stems is not None:
                return capture(conn, stems)
            need(type(manifest) is dict and manifest.get("schema") == SCHEMA)
            need(type(manifest.get("expected_revision")) is int)
            current = capture(conn, manifest.get("run_stems"))
            need(current == manifest)  # Exact IDs, names, versions, core rows, revision and policy.
            result = {"status": "ready", "manifest_sha256": digest(manifest),
                      "resources": len(current["changes"]), "revision": current["expected_revision"],
                      "policy_hash": current["expected_policy_hash"], "applied": False}
            if not apply:
                return result
            before = schema.read_catalog(conn)
            expected = deepcopy(before)
            core_before = {row["id"]: row for row in rows(conn, "credentials")}
            policy_before = rows(conn, "operator_demo_policy")
            generations_before = rows(conn, "credential_generations")
            policy_file = config.POLICY_BUNDLE_PATH.read_bytes()
            renamed_credentials = set()
            for item in current["changes"]:
                collection = item["collection"]
                record = next(row for row in expected[collection] if row["id"] == item["id"])
                record["name"] = item["new_name"]
                if collection == "credentials":
                    need(db.update_credential(record["id"], {"name": record["name"]}, _connection=conn) is not None)
                    renamed_credentials.add(record["id"])
                stored = schema.save_resource(conn, collection, record)
                record["version"] += 1
                need(stored == record)
            schema.validate_bindings(conn)
            policy.verify_retained_policy(conn, schema.read_catalog(conn))
            expected["revision"] = schema.advance_revision(conn, current["expected_revision"])
            need(schema.read_catalog(conn) == expected)  # Includes every token verifier and permission field.
            core_after = {row["id"]: row for row in rows(conn, "credentials")}
            need(core_after.keys() == core_before.keys())
            for identifier, old in core_before.items():
                changed = core_after[identifier]
                if identifier in renamed_credentials:
                    need(changed["name"] == old["name"].replace("serverware-", "catchplate-", 1))
                    changed = {**changed, "name": old["name"], "updated_at": old["updated_at"]}
                need(changed == old)  # Ciphertexts, envelope versions and all other core fields remain exact.
            need(rows(conn, "credential_generations") == generations_before
                 and rows(conn, "operator_demo_policy") == policy_before
                 and config.POLICY_BUNDLE_PATH.read_bytes() == policy_file)
            receipt = db.append_audit_event(conn, event_type="operator_catalog.synthetic_fixture_labels_renamed",
                actor_type="system", actor_id="catchplate-fixture-label-maintenance",
                event={"schema": SCHEMA, "manifest_sha256": result["manifest_sha256"],
                       "revision": expected["revision"], "policy_hash": current["expected_policy_hash"],
                       "changes": [{key: item[key] for key in ("collection", "id", "old_name", "new_name")}
                                   for item in current["changes"]]})
            publication.assert_held()
            conn.commit()
            return {**result, "status": "applied", "applied": True, "revision": expected["revision"],
                    "audit_event_id": receipt["id"], "authority_secrets_tokens_unchanged": True}
        finally:
            if conn.in_transaction:
                conn.rollback()


def private_file(path, *, write=None):
    flags = os.O_CLOEXEC | os.O_NOFOLLOW | (os.O_WRONLY | os.O_CREAT | os.O_EXCL if write is not None else os.O_RDONLY)
    with os.fdopen(os.open(path, flags, 0o600), "wb" if write is not None else "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= 32768)
        if write is not None:
            need(len(write) <= 32768)
            stream.write(write)
            stream.flush()
            os.fsync(stream.fileno())
            return None
        return stream.read(32769)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--capture", type=Path)
    mode.add_argument("--manifest", type=Path)
    parser.add_argument("--run-stem", action="append")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        need((args.capture is not None and args.run_stem is not None and not args.apply)
             or (args.manifest is not None and args.run_stem is None))
        # Refuse an empty/fresh path before activate() can create profile state.
        root = Path(os.environ.get("CATCHPLATE_DATA_DIR", ""))
        need(root.is_absolute())
        for name in (".catchplate-operator-demo.json", ".operator-publication.lock", "catchplate.sqlite3", "policy-bundle.json"):
            info = (root / name).lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid())
        from catchplate import operator_demo
        operator_demo.activate()
        if args.capture:
            manifest = operate(stems=args.run_stem)
            private_file(args.capture, write=(json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
            result = {"status": "captured", "applied": False, "resources": len(manifest["changes"]),
                      "manifest_sha256": digest(manifest)}
        else:
            raw = private_file(args.manifest)
            need(len(raw) <= 32768)
            manifest = json.loads(raw, object_pairs_hook=unique_object)
            result = operate(manifest=manifest, apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"status": "refused_or_outcome_unknown",
                          "message": "Inspect current catalog and audit before retrying; no automatic retry is safe."}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Derive fixed c11/349 and 1052/350 public pins in isolated disposable startups.

Separate --side workers mount immutable corresponding Git sources at /app and
this reviewed tool at /migration-tools. No live state or provider material.
--join checks the closed 34-table delta and emits CANDIDATE pins only: it cannot
arm the migration. Review/commit of the artifact and exact migration digest is
a separate human-controlled step before the focused migration test phase.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import sqlite3
import sys
import tempfile

import migrate_operator_authority_source_revision as migration

COMMITS = {"old": migration.OLD_COMMIT, "target": migration.TARGET_COMMIT}
IMAGE = migration.IMAGE
SCHEMA = "serverware.operatorAuthoritySourceRevisionDerivation/v1"
PIN_SCHEMA = migration.PIN_SCHEMA
MAX_OUTPUT = 32 * 1024 * 1024


def require(value):
    if not value:
        raise ValueError("ordinary schema derivation refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def objects(conn):
    return [list(row) for row in conn.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")]


def derive(side):
    source = Path("/app")
    require(source.is_dir() and not source.is_symlink()
        and not any(name == "serverware" or name.startswith("serverware.")
            or name == "serverware_agent_trust" or name.startswith("serverware_agent_trust.")
            for name in sys.modules))
    for name in tuple(os.environ):
        if name.startswith("SERVERWARE_"):
            del os.environ[name]
    os.umask(0o077)
    os.environ["TMPDIR"] = "/tmp"
    tempfile.tempdir = "/tmp"
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    signal.alarm(110)
    sys.dont_write_bytecode = True
    compiled = {}
    with tempfile.TemporaryDirectory(prefix="ordinary-source-revision-derivation-", dir="/tmp") as temporary:
        base = Path(temporary).resolve(strict=True)
        # Ignore any archived bytecode; observe the actual source compiled.
        sys.pycache_prefix = str(base / "unused-bytecode")

        def audit(event, args):
            if event.startswith("socket.") or event in {
                    "subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.exec", "os.posix_spawn"}:
                raise RuntimeError("derivation network/process access refused")
            if event == "sqlite3.connect":
                raw = args[0]
                require(raw == ":memory:" or raw == (base / "data/serverware.sqlite3").as_uri() + "?mode=ro"
                    or (isinstance(raw, (str, os.PathLike))
                    and Path(raw).is_absolute() and Path(raw).resolve().is_relative_to(base)))
            if event == "compile" and isinstance(args[1], str) and args[1].startswith("/app/"):
                path = Path(args[1]).resolve(strict=True)
                require(path.is_relative_to(source) and path.suffix == ".py")
                raw = args[0].encode() if isinstance(args[0], str) else args[0]
                require(type(raw) is bytes and raw == path.read_bytes())
                compiled[str(path.relative_to(source))] = sha(raw)

        sys.addaudithook(audit)
        sys.path[:0] = [str(source / "scripts"), str(source)]
        # Reuse the real existing managed-X/quota selection and startup owners,
        # not that fixture's historical migration pins or its test class.
        import test_operator_authority_contract_migration_x_quota as ordinary
        import test_operator_authority_contract_migration as historical
        require(Path(ordinary.__file__).resolve().is_relative_to(source)
            and Path(historical.__file__).resolve().is_relative_to(source))
        directory = base / "data"
        _workspace, x_custody = ordinary.selected_environment(source, directory, create=True)
        directory.mkdir(mode=0o700)
        provider_custody = base / "provider-custody"
        provider_custody.mkdir(mode=0o700)
        os.environ.update(SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED="1",
            SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR=str(provider_custody),
            SERVERWARE_DECISION_GATE_BASE="")
        from serverware import operator_google_managed_config
        operator_google_managed_config.bootstrap()
        config, db, _store, _bundles, _catalog, _inputs, _mutations = ordinary.backend()
        require(os.environ.get("SERVERWARE_CONTROL_PLANE_STARTUP_VALIDATED_PID") == str(os.getpid()))
        require(not operator_google_managed_config.selected())
        from serverware import authority_contract
        from serverware.authority_store import metadata_schema_source
        from serverware.authority_store.metadata_schema import configure_sqlite_metadata_connection
        ddl = metadata_schema_source.metadata_schema_source()
        with closing(sqlite3.connect(config.DB_PATH)) as conn:
            configure_sqlite_metadata_connection(conn)
            conn.row_factory = sqlite3.Row
            tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
            prefixes = ("policy_authority_", "policy_activation_", "policy_candidate_", "policy_canar",
                "policy_compiler_", "policy_runtime_", "policy_native_", "policy_shadow_", "policy_control_plane_",
                "setup_", "webauthn_", "oidc_", "jit_", "approval_", "recovery_", "rbac_", "control_plane_",
                "release_authorization_")
            additional = set(authority_contract.V9_ADDITIONAL_PROTECTED_TABLES) - {"credential_generations"}
            additional |= {"policy_high_water", "policy_publications", "policy_state_bundles"}
            empty = sorted(name for name in tables if name != "policy_authority_schema_contracts"
                and (name.startswith(prefixes) or name in additional))
            require(not any(conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone() for name in empty))
            manifest, manifest_digest = db._validate_policy_candidate_authority_structure(conn,
                require_recorded_contract=True, source_schema_program=ddl)
            contracts = conn.execute("SELECT * FROM policy_authority_schema_contracts").fetchall()
            require(len(contracts) == 1)
            contract = dict(contracts[0])
            require(contract["source_contract_digest"] == db._policy_candidate_authority_source_contract_digest()
                and contract["structural_manifest_json"] == manifest
                and contract["structural_manifest_digest"] == manifest_digest)
            base_objects = objects(conn)
            require([row[0] for row in conn.execute("PRAGMA quick_check")] == ["ok"]
                and not conn.execute("PRAGMA foreign_key_check").fetchall())
        # The real optional setup owner creates its history table; cancellation
        # leaves the startup's ordinary upstream configuration unchanged.
        historical.upstream_fixture()
        with closing(sqlite3.connect(config.DB_PATH)) as conn:
            optional_objects = objects(conn)
            optional_tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
            require(set(optional_tables) - set(tables) == {"operator_upstream_setups"})
        witness = directory / "webauthn-recovery-witness.sqlite3"
        require(witness.is_file())
        with closing(sqlite3.connect(witness)) as conn:
            witness_objects = objects(conn)
            witness_tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
            require(witness_tables == ["recovery_authorization_claims", "recovery_witness_heads"]
                and not any(conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone() for name in witness_tables))
        operation_document = authority_contract.operation_contract_document()
        for name, module in tuple(sys.modules.items()):
            if name == "serverware" or name.startswith("serverware.") or name == "serverware_agent_trust" or name.startswith("serverware_agent_trust."):
                path = Path(module.__file__).resolve(strict=True)
                require(path.is_relative_to(source) and path.suffix == ".py")
                relative = str(path.relative_to(source))
                require(relative in compiled and compiled[relative] == sha(path.read_bytes()))
        require(compiled and any(name.startswith("serverware_agent_trust/") for name in compiled))
        require(all(sha((source / name).read_bytes()) == digest for name, digest in compiled.items()))
        require(not list(provider_custody.iterdir()) and not list(x_custody.iterdir()))
        require(len(tables) == 217 and len(optional_tables) == 218 and len(empty) == 186)
        pins = {"sourceContractDigest": contract["source_contract_digest"],
            "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
            "sourceRevision": authority_contract.SOURCE_REVISION, "schemaVersion": authority_contract.SCHEMA_VERSION,
            "sourceDdlSha256": sha((source / "serverware/authority_store/metadata_schema_source.py").read_bytes()),
            "emittedDdlSha256": sha(ddl.encode()), "structuralManifestDigest": manifest_digest,
            "structuralManifestJsonSha256": sha(manifest.encode()), "sqliteObjectsSha256": sha(canonical(base_objects)),
            "tables": tables, "emptyTables": empty, "optionalSqliteObjectsSha256": sha(canonical(optional_objects)),
            "optionalTables": optional_tables, "witnessObjectsSha256": sha(canonical(witness_objects)),
            "sourceFiles": dict(sorted(compiled.items()))}
        return {"schema": SCHEMA, "side": side, "sourceCommit": COMMITS[side], "derivationImage": IMAGE,
            "pins": pins, "evidence": {"emittedDdl": ddl,
                "structuralManifestJson": manifest, "operationContractDocument": operation_document,
                "sqliteObjects": base_objects, "optionalSqliteObjects": optional_objects,
                "witnessObjects": witness_objects, "actualOrdinaryStartup": True,
                "googleConfigured": False, "providerCustodyEmpty": True, "xCustodyEmpty": True,
                "liveStateMounted": False, "nativeProfileEnabled": False}}


def join(old_path, target_path):
    values = []
    for side, filename in (("old", old_path), ("target", target_path)):
        path = Path(filename)
        require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_OUTPUT)
        value = migration.strict_json(path.read_bytes())
        require(value["schema"] == SCHEMA and value["side"] == side
            and value["sourceCommit"] == COMMITS[side] and value["derivationImage"] == IMAGE)
        pins, evidence = value["pins"], value["evidence"]
        require(pins["emittedDdlSha256"] == sha(evidence["emittedDdl"].encode())
            and pins["structuralManifestJsonSha256"] == sha(evidence["structuralManifestJson"].encode()))
        for field, key in (("sqliteObjectsSha256", "sqliteObjects"),
                ("optionalSqliteObjectsSha256", "optionalSqliteObjects"), ("witnessObjectsSha256", "witnessObjects")):
            require(pins[field] == sha(canonical(evidence[key])))
        values.append(value)
    old, target = values
    before, after = old["pins"], target["pins"]
    left_ddl, right_ddl = (item["evidence"]["emittedDdl"] for item in values)
    require(left_ddl.count(migration.OLD_REVISION) == 34
        and migration.TARGET_REVISION not in left_ddl
        and right_ddl == left_ddl.replace(migration.OLD_REVISION, migration.TARGET_REVISION))
    rebuild = {}
    for field in ("sqliteObjects", "optionalSqliteObjects"):
        left, right = old["evidence"][field], target["evidence"][field]
        require(len(left) == len(right))
        seen = {}
        for old_row, new_row in zip(left, right):
            require(old_row[:3] == new_row[:3])
            kind, name, owner, sql = old_row
            if old_row != new_row:
                require(kind == "table" and name == owner and name in migration.CHANGED_TABLES
                    and sql.count(migration.OLD_REVISION) == 1
                    and new_row[3] == sql.replace(migration.OLD_REVISION, migration.TARGET_REVISION, 1))
                seen[name] = {"old": sql, "target": new_row[3]}
        require(set(seen) == set(migration.CHANGED_TABLES))
        require(not rebuild or rebuild == seen)
        rebuild = seen
    result = {"schema": PIN_SCHEMA, "transitionId": migration.TRANSITION, "oldCommit": COMMITS["old"],
        "targetBaseCommit": COMMITS["target"], "derivationImage": IMAGE,
        "old": before, "target": after, "rebuildTables": rebuild}
    return migration.validate_pins(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--side", choices=tuple(COMMITS))
    action.add_argument("--join", nargs=2, metavar=("OLD_JSON", "TARGET_JSON"))
    args = parser.parse_args()
    value = derive(args.side) if args.side else join(*args.join)
    raw = canonical(value)
    require(len(raw) <= MAX_OUTPUT)
    sys.stdout.buffer.write(raw + b"\n")


if __name__ == "__main__":
    main()

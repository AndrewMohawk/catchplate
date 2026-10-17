"""Fixed historical-capture primitives for the v349-to-v350 rehearsal only.

No Docker, live path, host lifecycle, promotion or retry entry point. Extraction,
recovery and startup checks retain the reviewed pending-actions primitives.
"""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time

COMMIT = "cb326c64de920aa3eeca692b6b9b8e411a8a0cd1"
BINARY_SHA = "e30fe08b97815970aaa08c0317d74ccf96e525a0c3a9957a0b351c69e12f6626"
BUILD_COMMIT = "3052e0515f3a4a9d01eb9eadc0a2b4e2a67f037b"
PIN_SHA = "72ce5ebdb7f422e881987749310493451f6d19fa397bb39157313bb85b7472e4"
CONTRACT_DIGEST = "sha256:abbbb18744e256391a9891c052c64cca216c06d8c56c1eeddf66f1246ffa2d8f"
SOURCE, PROOFS, CAPTURE, WORK = map(Path, ("/app", "/proofs", "/captured", "/job"))
BASE = WORK
CANDIDATE = COMMIT
ROOTS = (("data-root.tar", "persistent", "persistent"),
    ("notification-custody.tar", "notification", "custody"),
    ("provider-custody.tar", "provider", "provider_custody"),
    ("x-custody.tar", "x", "x_custody"))
SIDES = {name + suffix for name in ("catchplate.sqlite3", "webauthn-recovery-witness.sqlite3")
    for suffix in ("", "-wal", "-shm", "-journal")}
AUXILIARY = "app-data/.public-proxy-check/public-proxy-e6e3da6abe224166863fcc3eab20254d/positive-result-import-root.json"
AUXILIARY_INFO = {"kind": "file", "uid": 1000, "gid": 1000, "mode": 0o644, "size": 865,
    "sha256": "cbf4b8d08e49eae482ee8b05e2bc8c323e2938d47359f29bf9dc2dfc8d70a863"}
DERIVED_CA_FILES = frozenset({"app-data/decision-gate-ca-cert.pem", "app-data/decision-gate-ca-key.pem"})
CAPTURE_NAMES = {"result.json", "capture-proof.json", "raw/inventory.json", "app.env",
    "fence.json", "after-capture-inspect.stdout", "preservation-baseline.json"}
CAPTURE_PINS = {}
SNAPSHOT = ""
cfg = {}


def need(value):
    if not value:
        raise ValueError("fixed retained rehearsal refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False))


def raw_file(path, limit=16 * 1024**2):
    path = Path(path)
    before = path.lstat()
    need(path.is_absolute() and path.resolve(strict=True) == path and stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1 and 0 <= before.st_size <= limit)
    value = path.read_bytes()
    identify = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink,
        item.st_uid, item.st_gid, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    need(len(value) == before.st_size and identify(path.lstat()) == identify(before))
    return value


def pinned(path, digest, limit=16 * 1024**2):
    need(type(digest) is str and re.fullmatch("[a-f0-9]{64}", digest) is not None)
    value = raw_file(path, limit)
    need(sha(value) == digest)
    return value


def read(path):
    return strict_json(raw_file(path))


def save(path, value, owner=None):
    value = value if type(value) is bytes else canon(value) + b"\n"
    need(len(value) <= 16 * 1024**2)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    if owner is not None:
        os.chown(path, owner, owner)


def source_proof(*, git=False):
    del git
    global CAPTURE_PINS, SNAPSHOT
    need(cfg["candidateCommit"] == COMMIT and cfg["normalBinarySha256"] == BINARY_SHA)
    files = strict_json(pinned(PROOFS / "source-files.json", cfg["sourceFilesSha256"]))
    join = strict_json(pinned(PROOFS / "source-join.json", cfg["sourceJoinSha256"]))
    need(set(join) == {"schema", "sourceCommit", "sourceFiles", "sourceBytes", "sourceFilesSha256",
        "readOnlyFrozen", "gitBlobEquality", "normalBinarySha256", "compilerInputGitAndSha256Equality"})
    need(join["schema"] == "catchplate.sourceRevisionRetainedSourceJoin/v1"
        and join["sourceCommit"] == COMMIT and join["sourceFilesSha256"] == cfg["sourceFilesSha256"]
        and join["normalBinarySha256"] == BINARY_SHA
        and all(join[key] is True for key in ("readOnlyFrozen", "gitBlobEquality", "compilerInputGitAndSha256Equality")))
    need(type(files) is dict and 1 <= len(files) <= 16384 and join["sourceFiles"] == len(files))
    actual, total = set(), 0
    need(SOURCE.resolve(strict=True) == SOURCE and SOURCE.is_dir())
    for directory, dirs, names in os.walk(SOURCE, followlinks=False):
        path = Path(directory)
        need(not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o555)
        need(all(not (path / name).is_symlink() for name in dirs))
        for name in names:
            relative = (path / name).relative_to(SOURCE).as_posix()
            need(relative in files and relative not in actual)
            actual.add(relative)
            item = files[relative]
            need(set(item) == {"mode", "sha256", "gitBlob"} and item["mode"] in ("100644", "100755"))
            value = pinned(path / name, item["sha256"], 64 * 1024**2)
            need(stat.S_IMODE((path / name).stat().st_mode) == (0o444 if item["mode"] == "100644" else 0o555))
            need(hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest() == item["gitBlob"])
            total += len(value)
            need(total <= 512 * 1024**2)
    need(actual == set(files) and total == join["sourceBytes"])
    migration_pins = strict_json(pinned(SOURCE / "scripts/operator_authority_source_revision_migration_pins.json", PIN_SHA))
    need(len(migration_pins["target"]["sourceFiles"]) == 509
        and migration_pins["target"]["sourceContractDigest"] == CONTRACT_DIGEST)
    need(all(files[name]["sha256"] == digest.removeprefix("sha256:")
        for name, digest in migration_pins["target"]["sourceFiles"].items()))
    normal = strict_json(pinned(PROOFS / "normal.json", cfg["normalReceiptSha256"]))
    selection = strict_json(pinned(PROOFS / "selection.json", cfg["normalSelectionSha256"]))
    need(normal["schema"] == "catchplate.hostedNormalRust/v1" and normal["ok"] is True
        and normal["normalBinary"] is True and normal["sourceRevision"] == BUILD_COMMIT
        and normal["binary"]["sha256"] == BINARY_SHA and normal["binary"]["bytes"] == 42683568
        and normal["cleanup"]["allOwnedContainersRemoved"] is True)
    need(selection["schema"] == "catchplate.selectedNormalRust/v1" and selection["ok"] is True
        and selection["buildCommit"] == BUILD_COMMIT and selection["binarySha256"] == BINARY_SHA
        and selection["receiptSha256"] == cfg["normalReceiptSha256"] and selection["reusedArtifact"] is True
        and selection["compiledInThisRun"] is False and selection["buildInputIdentity"] == normal["buildInputIdentity"])
    for mapping in (normal["buildInputs"]["files"], normal["compilerInputs"]["binary"]["files"],
            normal["compilerInputs"]["library"]["files"]):
        need(type(mapping) is dict and mapping)
        need(all(files.get(name) == item for name, item in mapping.items()))
    CAPTURE_PINS = cfg["capturePins"]
    need(type(CAPTURE_PINS) is dict and set(CAPTURE_PINS) == CAPTURE_NAMES
        and all(type(value) is str and re.fullmatch("[a-f0-9]{64}", value) for value in CAPTURE_PINS.values()))
    SNAPSHOT = files["scripts/operator_rollout_snapshot.py"]["sha256"]
    return {"commit": COMMIT, "files": len(files), "bytes": total, "sourceFilesSha256": cfg["sourceFilesSha256"],
        "sourceJoinSha256": cfg["sourceJoinSha256"], "fixedTargetSourceFiles": 509,
        "fixedMigrationPinsSha256": PIN_SHA, "normalBinarySha256": BINARY_SHA,
        "normalReceiptSha256": cfg["normalReceiptSha256"], "normalSelectionSha256": cfg["normalSelectionSha256"]}


def startup_environment():
    original = pinned("/startup.env", cfg["capturePins"]["app.env"], 65536).decode("utf-8")
    selected = {}
    for line in original.splitlines():
        need("=" in line and not line.startswith("#"))
        key, value = line.split("=", 1)
        need(key not in selected and re.fullmatch("[A-Z][A-Z0-9_]*", key) is not None)
        selected[key] = value
    selected["CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST"] = "sha256:" + BINARY_SHA
    need({key: value for key, value in os.environ.items() if key.startswith("CATCHPLATE_")}
        == {key: value for key, value in selected.items() if key.startswith("CATCHPLATE_")})


def archives():
    for name, digest in CAPTURE_PINS.items():
        need(type(digest) is str and len(digest) == 64 and sha(raw_file(CAPTURE / name, 128 * 1024**2)) == digest)
    result = read(CAPTURE / 'result.json')
    need(set(result) == {'schema', 'captured', 'restored', 'fenced', 'captureContainerRemoved',
        'originalIds', 'baselineMatched', 'automaticRetry', 'seconds'})
    need(result['schema'] == 'catchplate.authorityPromotionCapture/v1'
        and all(result[key] is True for key in ('captured', 'fenced', 'captureContainerRemoved', 'baselineMatched'))
        and result['restored'] is False and result['automaticRetry'] is False
        and len(result['originalIds']) == len(set(result['originalIds'])) == 4)
    proof = read(CAPTURE / 'capture-proof.json')
    need(proof['schema'] == 'catchplate.authorityPromotionRawCapture/v1'
        and proof['originalIds'] == result['originalIds'] and proof['sqliteOpened'] is False
        and proof['providerNetwork'] is False and proof['inventorySha256'] == CAPTURE_PINS['raw/inventory.json']
        and proof['appEnvSha256'] == CAPTURE_PINS['app.env']
        and proof['fenceSha256'] == CAPTURE_PINS['fence.json']
        and proof['archiveManifestSha256'] == sha(raw_file(CAPTURE / 'raw/archive-sha256.txt', 4096)))
    need(raw_file(CAPTURE / 'raw/inventory.json') == raw_file(CAPTURE / 'raw/inventory-after-archive.json'))
    hashes = {}
    for line in raw_file(CAPTURE / 'raw/archive-sha256.txt', 4096).decode().splitlines():
        digest, name = line.split('  ')
        need(name in {item[0] for item in ROOTS} and name not in hashes
            and sha(raw_file(CAPTURE / 'raw' / name, 128 * 1024**2)) == digest)
        hashes[name] = digest
    need(len(hashes) == 4)
    return hashes

def extract(archive, destination, inventory, *, omit_database=False):
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, 'r:') as stream:
        members, names, selected = stream.getmembers(), set(), []
        need(len(members) <= 512)
        for member in members:
            name = str(PurePosixPath(member.name))
            need(not name.startswith('/') and '..' not in PurePosixPath(name).parts and name not in names)
            names.add(name)
            need(name in inventory and (member.isdir() or member.isfile()))
            item = inventory[name]
            need((member.uid, member.gid, member.mode) == (item['uid'], item['gid'], item['mode']))
            need(member.isdir() == (item['kind'] == 'directory'))
            if member.isfile():
                need(member.size == item['size'] and member.size <= 256 * 1024**2)
                with stream.extractfile(member) as handle: need(sha(handle.read()) == item['sha256'])
            if not (omit_database and name.startswith('app-data/') and name[len('app-data/'):] in SIDES):
                selected.append(member.name)
        need(names == set(inventory))
    subprocess.run(['/usr/bin/tar', '--numeric-owner', '--same-owner', '--same-permissions', '--acls', '--xattrs',
        '--xattrs-include=*', '--no-recursion', '--null', '-xpf', str(archive), '-C', str(destination), '-T', '-'],
        input=('\0'.join(selected) + '\0').encode(), check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    sys.path.insert(0, str(SOURCE / 'scripts'))
    import operator_rollout_snapshot as snapshot
    actual = snapshot.tree(destination, empty_placeholders=snapshot.GATE_PLACEHOLDERS)
    wanted = {name: item for name, item in inventory.items() if not
        (omit_database and name.startswith('app-data/') and name[len('app-data/'):] in SIDES)}
    fields = ('kind', 'uid', 'gid', 'mode', 'size', 'sha256')
    need({name: {key: value[key] for key in fields if key in value} for name, value in actual.items()}
        == {name: {key: value[key] for key in fields if key in value} for name, value in wanted.items()})

def require_auxiliary(relative, info):
    need(relative == AUXILIARY and set(info) == set(AUXILIARY_INFO) | {'dev', 'ino'}
        and {key: info[key] for key in AUXILIARY_INFO} == AUXILIARY_INFO)

def require_auxiliary_move(before, after, preserved):
    require_auxiliary(AUXILIARY, before[AUXILIARY])
    need(preserved == before[AUXILIARY]
        and after == {name: info for name, info in before.items() if name != AUXILIARY})

def preserve_auxiliary():
    sys.path.insert(0, str(SOURCE / 'scripts'))
    import operator_rollout_snapshot as snapshot
    root = WORK / 'candidate/persistent'
    before = snapshot.tree(root, empty_placeholders=snapshot.GATE_PLACEHOLDERS)
    require_auxiliary(AUXILIARY, before[AUXILIARY])
    destination = WORK / 'preserved-artifacts'; destination.mkdir(mode=0o700)
    os.rename(root / AUXILIARY, destination / Path(AUXILIARY).name)
    for directory in ((root / AUXILIARY).parent, destination):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    after = snapshot.tree(root, empty_placeholders=snapshot.GATE_PLACEHOLDERS)
    saved = snapshot.tree(destination)
    need(set(saved) == {'.', Path(AUXILIARY).name})
    require_auxiliary_move(before, after, saved[Path(AUXILIARY).name])
    save(WORK / 'auxiliary-preserved.json', {'beforeTree': before, 'preserved': saved,
        'relativePath': AUXILIARY, 'stagingOnly': True}, 1000)

def require_non_database_tree(before, after):
    # Only the two derived CA leaves may be atomically replaced with identical
    # bytes. All other retained files and directories keep their copied inode.
    def admitted(tree):
        return {name: {key: value for key, value in info.items()
            if name not in DERIVED_CA_FILES or key != 'ino'}
            for name, info in tree.items()}
    need(admitted(before) == admitted(after))

def verify_auxiliary():
    sys.path.insert(0, str(SOURCE / 'scripts'))
    import operator_rollout_snapshot as snapshot
    record = read(WORK / 'auxiliary-preserved.json')
    need(record['relativePath'] == AUXILIARY and record['stagingOnly'] is True)
    saved = snapshot.tree(WORK / 'preserved-artifacts')
    need(saved == record['preserved'] and set(saved) == {'.', Path(AUXILIARY).name})
    preserved = saved[Path(AUXILIARY).name]
    require_auxiliary(AUXILIARY, preserved)
    need(preserved == record['beforeTree'][AUXILIARY])
    current = snapshot.tree(WORK / 'candidate/persistent', empty_placeholders=snapshot.GATE_PLACEHOLDERS)
    need(AUXILIARY not in current)
    merged = {name: info for name, info in current.items()
        if not (name.startswith('app-data/') and name[len('app-data/'):] in SIDES)}
    merged[AUXILIARY] = preserved
    require_non_database_tree(record['beforeTree'], merged)
    recovery_leaf = WORK / 'recovery/persistent' / AUXILIARY
    info, _ = snapshot.metadata(recovery_leaf); info['sha256'] = sha(recovery_leaf.read_bytes())
    require_auxiliary(AUXILIARY, info)
    return {'relativePath': AUXILIARY, **AUXILIARY_INFO, 'copiedInodePreserved': True,
        'candidateOmission': 'preserved-artifacts/' + Path(AUXILIARY).name,
        'reconstructedNonDatabaseTreeExact': True, 'rawAndRecoveryLeafUnchanged': True,
        'liveAuxiliaryTouched': False}

def prepare():
    need(os.geteuid() == 0)
    signal.alarm(60)
    original, proof = archives(), source_proof(git=False)
    need(proof == read(WORK / 'source-proof.json'))
    required = 2 * sum((CAPTURE / 'raw' / name).stat().st_size for name in original)
    need(shutil.disk_usage(BASE).free >= 16 * 1024**3 + required)
    root = WORK
    inventory = read(CAPTURE / 'raw/inventory.json')
    for phase in ('recovery', 'candidate'):
        stage = root / phase; stage.mkdir(mode=0o700)
        for filename, name, key in ROOTS:
            extract(CAPTURE / 'raw' / filename, stage / name, inventory[key], omit_database=phase == 'candidate')
    preserve_auxiliary()  # Only after both full extraction inventories have matched.
    (root / 'out').mkdir(mode=0o700); os.chown(root / 'out', 10001, 10001)
    environment = pinned(CAPTURE / 'app.env', CAPTURE_PINS['app.env'], 65536)
    save(WORK / 'startup.env', environment, 10001)
    (WORK / 'startup.env').chmod(0o400)
    need(pinned(WORK / 'startup.env', CAPTURE_PINS['app.env'], 65536) == environment)
    need(archives() == original and source_proof(git=False) == proof)
    save(WORK / 'prepared.json', {'ok': True, 'rawArchives': original,
        'scriptSha256': sha(Path(__file__).read_bytes()), 'originalOwnershipAndModesPreserved': True,
        'candidateDatabasesAbsent': True, 'candidateCommit': CANDIDATE, 'sourceProof': proof, 'capturePins': CAPTURE_PINS}, 1000)
    return None

def decode_journal_format(header):
    need(type(header) is bytes and len(header) == 100 and header[:16] == b'SQLite format 3\x00')
    versions = tuple(header[18:20])
    need(versions in {(1, 1), (2, 2)})
    return 'wal' if versions == (2, 2) else 'rollback'

def persistent_journal_format(conn):
    # immutable=1 reports connection-local DELETE even for a persisted WAL DB.
    # Bind the format observation to this real connection's main database file.
    rows = [row for row in conn.execute('PRAGMA database_list') if row[1] == 'main']
    need(len(rows) == 1 and rows[0][2])
    path = Path(rows[0][2])
    need(path.is_absolute() and path.resolve(strict=True) == path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size >= 100)
        header = os.pread(fd, 100, 0)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        need(identity(before) == identity(os.fstat(fd)) == identity(path.stat(follow_symlinks=False)))
        return decode_journal_format(header)
    finally:
        os.close(fd)

def db_snapshot(conn, migration):
    # Load the real pure function without importing the authority package before
    # the actual managed-configuration bootstrap has selected its environment.
    configure_sqlite_metadata_connection = runpy.run_path(
        '/app/catchplate/authority_store/metadata_schema.py')['configure_sqlite_metadata_connection']
    configure_sqlite_metadata_connection(conn)
    need([row[0] for row in conn.execute('PRAGMA integrity_check')] == ['ok'])
    need(not conn.execute('PRAGMA foreign_key_check').fetchall())
    objects = migration.objects(conn)
    tables = sorted(row[1] for row in objects if row[0] == 'table')
    return {'objects': objects, 'rows': migration.row_commitments(conn, tables, normalize_contract=False),
        'orderedAudit': sha(canon([[migration.typed(cell) for cell in row]
            for row in conn.execute('SELECT rowid,* FROM audit_events ORDER BY rowid')])) if 'audit_events' in tables else None,
        'persistentJournalFormat': persistent_journal_format(conn)}

def recovery(migration):
    before_files = migration.tree(Path('/data'))
    summaries = {}
    save('/out/custody-baseline.json', custody_snapshot())
    for name in ('catchplate.sqlite3', 'webauthn-recovery-witness.sqlite3'):
        source, target = Path('/recovery-data') / name, Path('/data') / name
        need(not target.exists())
        with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=0)) as src:
            src.execute('PRAGMA query_only=ON'); src.execute('BEGIN')
            before = db_snapshot(src, migration)
            journal_mode = src.execute('PRAGMA journal_mode').fetchone()[0]
            need(journal_mode in {'wal', 'delete'})
            if name == migration.DATABASE:
                need(len(before['rows']) == 218 and all('operator_x_quota_' + part in before['rows']
                    for part in ('state', 'accounts', 'buckets', 'attempts')))
                src.row_factory = sqlite3.Row
                save('/out/baseline-contract.json', dict(src.execute('SELECT * FROM policy_authority_schema_contracts').fetchone()))
                src.row_factory = None
            exact_rows = migration.row_commitments(src, sorted(before['rows']), normalize_contract=False)
            with closing(sqlite3.connect(target)) as dst:
                src.backup(dst, pages=256)
                need(dst.execute('PRAGMA journal_mode=' + journal_mode).fetchone()[0] == journal_mode)
                need(db_snapshot(dst, migration) == before)
                need(migration.row_commitments(dst, sorted(before['rows']), normalize_contract=False) == exact_rows)
            src.rollback()
        target.chmod(0o600)
        summaries[name] = {'tables': len(before['rows']), 'snapshotSha256': sha(canon(before)), 'journalMode': journal_mode}
        save(Path('/out') / (name + '.baseline.json'), before)
    migration.sidecars_absent(Path('/data'))
    after_files = migration.tree(Path('/data'))
    need({name: value for name, value in after_files.items() if name != migration.WITNESS} == before_files)
    save('/out/recovered-files.json', after_files)
    save('/out/recovered-main.backup', Path('/data/catchplate.sqlite3').read_bytes())
    need(read('/out/catchplate.sqlite3.baseline.json') == read('/out/capture-baseline.json')['snapshot'])
    return summaries

def custody_snapshot():
    need(sha(Path('/app/scripts/operator_rollout_snapshot.py').read_bytes()) == SNAPSHOT)
    snapshot = runpy.run_path('/app/scripts/operator_rollout_snapshot.py')
    return {name: snapshot['tree'](Path('/' + name + '-custody'))
        for name in ('provider', 'notification', 'x')}

def require_startup_preservation(before, after, timestamps, current, wall_start, wall_finished):
    name = 'policy_candidate_authority'
    old_time, new_time = (datetime.fromisoformat(rows[name]['applied_at']) for rows in (timestamps, current))
    need(old_time.utcoffset() is not None and new_time.utcoffset() is not None
        and wall_start <= new_time <= wall_finished and new_time >= old_time)
    normalized = {key: dict(value) for key, value in current.items()}
    normalized[name]['applied_at'] = timestamps[name]['applied_at']
    need(normalized == timestamps)
    need(after['objects'] == before['objects'] and after['orderedAudit'] == before['orderedAudit']
        and after['persistentJournalFormat'] == before['persistentJournalFormat'])
    need([name for name in after['rows'] if after['rows'][name] != before['rows'][name]] == ['catchplate_store_migrations']
        and set(after['rows']) == set(before['rows']))

def startup(role, migration):
    startup_environment()
    if role == 'startup2': need(read('/out/observe1.json')['ok'] is True)
    expected = {'CATCHPLATE_OPERATOR_DEMO': '1', 'CATCHPLATE_RELEASE_CHANNEL': 'dev',
        'CATCHPLATE_PROCESS_MODE': 'catchplate-control-plane', 'CATCHPLATE_METADATA_STORE_BACKEND': 'sqlite',
        'CATCHPLATE_AUDIT_STORE_BACKEND': 'sqlite', 'CATCHPLATE_GRANT_STORE_BACKEND': 'sqlite',
        'CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED': '0', 'CATCHPLATE_KEY_RELEASE_REQUIRED': '0',
        'CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED': '1', 'CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED': '1',
        'CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR': '/provider-custody', 'CATCHPLATE_DATA_DIR': '/data',
        'CATCHPLATE_OPERATOR_MANAGED_X_ENABLED': '1', 'CATCHPLATE_OPERATOR_X_CUSTODY_DIR': '/x-custody',
        'CATCHPLATE_OPERATOR_X_POST_ATTEMPT_QUOTA_ENABLED': '1'}
    need(all(os.environ.get(key) == value for key, value in expected.items()))
    expected_contract = read('/out/expected-contract.json')
    need(expected_contract['source_contract_digest'] == CONTRACT_DIGEST)
    before_files = migration.tree(Path('/data'))
    need(before_files == read('/out/recovered-files.json'))
    need(custody_snapshot() == read('/out/custody-baseline.json'))
    migration.sidecars_absent(Path('/data'))
    with closing(sqlite3.connect('file:/data/catchplate.sqlite3?mode=ro&immutable=1', uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        before = db_snapshot(conn, migration)
        timestamps = {row['migration']: dict(row) for row in conn.execute('SELECT rowid,* FROM catchplate_store_migrations')}
        contract = dict(conn.execute('SELECT * FROM policy_authority_schema_contracts').fetchone())
    need(contract == expected_contract)
    need(before['objects'] == read('/out/migrated-database.json')['objects'])
    prior_rows = read('/out/migrated-database.json')['rows']
    need(all(before['rows'][name] == prior_rows[name] for name in prior_rows
        if name != 'catchplate_store_migrations'))
    if role == 'startup1': need(before['rows']['catchplate_store_migrations'] == prior_rows['catchplate_store_migrations'])
    else: need(before == read('/out/startup1-after.json'))
    need(before['orderedAudit'] == read('/out/migrated-database.json')['orderedAudit'])
    wall_start = datetime.now(timezone.utc)
    started = time.monotonic()
    from catchplate import operator_google_managed_config, operator_demo
    operator_google_managed_config.bootstrap(); operator_demo.activate()
    from catchplate.control_plane_startup import validate_control_plane_startup
    validate_control_plane_startup()
    startup_seconds = time.monotonic() - started
    wall_finished = datetime.now(timezone.utc)
    from catchplate import db, operator_catalog_schema as catalog, operator_demo_store as store, policy_bundle as policy, config
    with closing(db.connect()) as conn:
        catalog.validate_bindings(conn)
        value = catalog.read_catalog(conn)
        retained = dict(conn.execute('SELECT * FROM operator_demo_policy WHERE singleton=1').fetchone())
        after = db_snapshot(conn, migration)
        current = {row['migration']: dict(row) for row in conn.execute('SELECT rowid,* FROM catchplate_store_migrations')}
        need(dict(conn.execute('SELECT * FROM policy_authority_schema_contracts').fetchone()) == contract)
    require_startup_preservation(before, after, timestamps, current, wall_start, wall_finished)
    raw = retained['signed_bundle_json'].encode()
    need(config.POLICY_BUNDLE_PATH.read_bytes() == raw)
    compiled = policy.compile_policy_bundle(json.loads(raw), verify_signature=True, validate_schema=True)
    loaded = policy.get_policy_snapshot()
    need(loaded is not None and loaded.hash == compiled.hash == retained['policy_hash'])
    need(policy.verify_policy_high_water(compiled) == store.get_policy_high_water())
    audit = db.verify_audit_chain(); need(audit['ok'] and audit['complete'])
    # Real SQLite startup may retain WAL connections until interpreter teardown.
    # The separate observer enforces exact stopped-state file preservation.
    save('/out/' + role + '-after.json', after)
    need(custody_snapshot() == read('/out/custody-baseline.json'))
    result = {'phase': role, 'ok': True, 'revision': value['revision'], 'sequence': retained['sequence'],
        'policyHash': retained['policy_hash'], 'counts': {key: len(value[key]) for key in ('credentials', 'applications', 'access_rules')},
        'auditVerified': True, 'auditCount': audit['count'], 'onlyStartupTimestampChanged': True,
        'startupUnix': wall_start.timestamp(), 'observedUnix': wall_finished.timestamp(), 'tables': len(after['rows']),
        'quotaRows': {key: after['rows'][key] for key in after['rows'] if key.startswith('operator_x_quota_')},
        'postExitPreservation': 'pending', 'startupSeconds': round(startup_seconds, 6), 'providerCalls': 0}
    save('/out/' + role + '.json', result)
    return result

def observe(role, migration):
    startup_role = 'startup' + role[-1]
    need(read('/out/' + startup_role + '.json')['ok'] is True)
    migration.sidecars_absent(Path('/data'))
    need(migration.tree(Path('/data')) == read('/out/recovered-files.json'))
    for name in ('catchplate.sqlite3', 'webauthn-recovery-witness.sqlite3'):
        with closing(sqlite3.connect('file:/data/' + name + '?mode=ro&immutable=1', uri=True)) as conn:
            conn.execute('PRAGMA query_only=ON'); conn.execute('BEGIN')
            snapshot = db_snapshot(conn, migration)
        expected = read('/out/' + startup_role + '-after.json') if name == migration.DATABASE else read('/out/' + name + '.baseline.json')
        need(snapshot == expected)
    migration.sidecars_absent(Path('/data'))
    need(custody_snapshot() == read('/out/custody-baseline.json'))
    result = {'phase': role, 'ok': True, 'startupPhase': startup_role, 'exactPostExitRowsAndFiles': True,
        'witnessByteIdentical': True, 'noSidecars': True, 'custodyUnchanged': True}
    save('/out/' + role + '.json', result)
    return result

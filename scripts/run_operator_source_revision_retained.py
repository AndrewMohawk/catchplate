#!/usr/bin/env python3
"""One fixed copied-state role; the external parent owns all container lifecycle.

Nothing here stops/captures live services, promotes a database, runs the Rust
binary, retries a claim, restores a backup or declares its own container removed.
"""
from contextlib import closing, contextmanager, redirect_stdout
import importlib
import json
import os
from pathlib import Path
import re
import resource
import runpy
import signal
import sqlite3
import stat
import sys

import operator_source_revision_retained as h

ROOT = Path("/srv/catchplate-archive/homelab_data/serverware-source350-release.6kZhpc9d")
SOURCE_ROOT = ROOT / ("source-" + h.COMMIT)
PROOFS = ROOT / "proofs"
COMMIT = h.COMMIT
IMAGE = "sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01"
ROLES = ("prepare", "recover", "plan", "apply", "freeze", "startup1", "observe1", "startup2", "observe2", "result")
MAX_FILE_BYTES = 64 * 1024**2
INPUT_KEYS = {"schema", "candidateCommit", "sourceFilesSha256", "sourceJoinSha256", "capturePins",
    "normalReceiptSha256", "normalSelectionSha256", "normalBinarySha256", "workerSha256", "helpersSha256"}
INPUT_SCHEMA = "serverware.sourceRevisionRetainedInputs/v1"
PROMOTION_ROOT_FILES = ("source-proof.json", "prepared.json", "auxiliary-preserved.json")
PROMOTION_OUT_FILES = ("plan.json", "apply.json", "migrated-database.json", "migrated-database-bytes.json",
    "freeze.json", "expected-contract.json", "serverware.sqlite3.baseline.json", "baseline-contract.json",
    "recovered-files.json", "phase-prepare.json", "phase-recover.json", "phase-plan.json", "phase-apply.json", "phase-freeze.json")
cfg = {}
pinned = h.pinned
selected_role = "unselected"
stage = "arguments"


def validate_inputs(value):
    h.need(type(value) is dict and set(value) == INPUT_KEYS and value["schema"] == INPUT_SCHEMA
        and value["candidateCommit"] == COMMIT and value["normalBinarySha256"] == h.BINARY_SHA)
    for key in INPUT_KEYS - {"schema", "candidateCommit", "capturePins"}:
        h.need(type(value[key]) is str and re.fullmatch("[a-f0-9]{64}", value[key]))
    h.need(type(value["capturePins"]) is dict and set(value["capturePins"]) == h.CAPTURE_NAMES
        and all(type(item) is str and re.fullmatch("[a-f0-9]{64}", item)
            for item in value["capturePins"].values()))


def source_proof():
    h.SOURCE, h.PROOFS, h.cfg = SOURCE_ROOT, PROOFS, cfg
    return h.source_proof()


def host_receipt(role, inputs_sha):
    value = h.read(Path("/host-receipts") / (role + ".json"))
    h.need(value["schema"] == "serverware.sourceRevisionRetainedHost/v1"
        and value["ok"] is True and value["role"] == role and value["inputsSha256"] == inputs_sha
        and value["workerSha256"] == cfg["workerSha256"] and value["exitCode"] == 0
        and value["oomKilled"] is False and value["restartCount"] == 0
        and value["containerRemoved"] is True and re.fullmatch("[a-f0-9]{64}", value["containerId"]))
    return value


def preflight(role):
    h.need(__debug__ and sys.dont_write_bytecode and sys.platform == "linux")
    root_role = role in ("prepare", "result")
    h.need(os.getuid() == os.geteuid() == (0 if root_role else 10001))
    h.need(resource.getrlimit(resource.RLIMIT_FSIZE) == (MAX_FILE_BYTES, MAX_FILE_BYTES))
    h.need({path.name for path in Path("/sys/class/net").iterdir()} == {"lo"})
    h.need(not any(Path(path).exists() for path in ("/var/run/docker.sock", "/run/docker.sock")))
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    allowed = 11 if root_role else 0  # CHOWN, DAC_OVERRIDE, FOWNER only.
    h.need(status["NoNewPrivs"].strip() == "1" and int(status["CapInh"].strip(), 16) == 0)
    h.need(all(int(status[key].strip(), 16) & ~allowed == 0 for key in ("CapPrm", "CapEff", "CapBnd", "CapAmb")))
    for path in ("/", "/app", "/runner", "/proofs", "/inputs.json", "/host-receipts"):
        h.need(os.statvfs(path).f_flag & os.ST_RDONLY)
    if root_role:
        h.need(os.statvfs("/captured").f_flag & os.ST_RDONLY)
        h.need(not os.statvfs("/job").f_flag & os.ST_RDONLY)
    else:
        h.need(not os.statvfs("/out").f_flag & os.ST_RDONLY)
        readonly = role in ("plan", "freeze", "observe1", "observe2")
        h.need(bool(os.statvfs("/data").f_flag & os.ST_RDONLY) == readonly)
        for leaf in ("provider", "notification", "x"):
            h.need(bool(os.statvfs("/" + leaf + "-custody").f_flag & os.ST_RDONLY)
                == (not role.startswith("startup")))
        if role == "recover":
            h.need(not os.statvfs("/recovery-data").f_flag & os.ST_RDONLY)
        if role.startswith("startup"):
            for path in ("/startup.env", "/run/secrets/serverware", "/demo-upstream"):
                h.need(os.statvfs(path).f_flag & os.ST_RDONLY)


def observer():
    # Both shared ROOT and fixed migration ROOT must derive from /app/scripts.
    sys.path[:0] = ["/app/scripts", "/app"]
    shared = importlib.import_module("migrate_operator_authority_contract")
    h.need(Path(shared.__file__) == Path("/app/scripts/migrate_operator_authority_contract.py")
        and shared.ROOT == Path("/app"))
    return shared


def migration_cli(role):
    shared = observer()  # run_path does not add the migration's sibling import directory.
    path = Path("/app/scripts/migrate_operator_authority_source_revision.py")
    sys.argv = [str(path), "--data-directory", "/data"]
    if role == "apply":
        plan = h.read("/out/plan.json")
        sys.argv += ["--apply", "--plan", "/out/plan.json", "--expected-plan-sha256",
            shared.sha(shared.canonical(plan)), "--backup", "/out/recovered-main.backup",
            "--acknowledge-stopped-copied-store"]
    fd = os.open("/out/" + role + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output, redirect_stdout(output):
        runpy.run_path(str(path), run_name="__main__")


@contextmanager
def held_database_bytes(shared, directory, output):
    """Hold the pre-start generation; this is not database/schema admission."""
    directory, output = Path(directory), Path(output)
    path = directory / shared.DATABASE
    shared.sidecars_absent(directory)
    h.need(not any(os.path.lexists(output / (role + ".claim.json"))
        for role in ("startup1", "startup2")))
    with shared.held_file(path) as (fd, original, raw):
        commitment = {"name": shared.DATABASE, "sha256": h.sha(raw),
            "bytes": len(raw), "identity": list(original)}

        def verify():
            shared.sidecars_absent(directory)
            h.need(not any(os.path.lexists(output / (role + ".claim.json"))
                for role in ("startup1", "startup2")))
            h.need(shared.identity(os.fstat(fd)) == original
                and shared.identity(path.stat(follow_symlinks=False)) == original)
            current = os.pread(fd, shared.MAX_FILE + 1, 0)
            h.need(len(current) == commitment["bytes"] and h.sha(current) == commitment["sha256"]
                and shared.identity(os.fstat(fd)) == original
                and shared.identity(path.stat(follow_symlinks=False)) == original)
            shared.sidecars_absent(directory)

        verify()
        yield commitment, verify
        verify()  # Includes the generation after the byte receipt has been fsynced.


def save_database_bytes(output, value):
    """Exclusive, read-only receipt; failed role/host receipts never authorize use."""
    path = Path(output) / "migrated-database-bytes.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(h.canon(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def freeze_migrated(inputs_sha, proof):
    shared = observer()
    migration = importlib.import_module("migrate_operator_authority_source_revision")
    h.need(Path(migration.__file__) == Path("/app/scripts/migrate_operator_authority_source_revision.py")
        and migration.ROOT == Path("/app"))
    pins = migration.pins()
    helpers = migration.source(pins, Path("/data"))
    shared.sidecars_absent(Path("/data"))
    before = h.read("/out/serverware.sqlite3.baseline.json")
    plan_raw, receipt_raw = h.raw_file("/out/plan.json"), h.raw_file("/out/apply.json")
    plan, receipt = h.strict_json(plan_raw), h.strict_json(receipt_raw)
    h.need(plan["schema"] == migration.SCHEMA and plan["transitionId"] == migration.TRANSITION
        and plan["pinsSha256"] == migration.PIN_SHA256 == "sha256:" + h.PIN_SHA
        and plan["targetContractDigest"] == pins["target"]["sourceContractDigest"])
    h.need(receipt["schema"] == migration.RECEIPT_SCHEMA and receipt["status"] == "committed"
        and receipt["transitionId"] == migration.TRANSITION and receipt["pinsSha256"] == migration.PIN_SHA256
        and receipt["planSha256"] == shared.sha(shared.canonical(plan))
        and receipt["backupSha256"] == shared.sha(h.raw_file("/out/recovered-main.backup"))
        and receipt["beforeContract"] == h.read("/out/baseline-contract.json")
        and receipt["rebuiltTables"] == list(migration.CHANGED_TABLES))
    with held_database_bytes(shared, Path("/data"), Path("/out")) as (commitment, verify):
        with closing(sqlite3.connect("file:/data/serverware.sqlite3?mode=ro&immutable=1", uri=True, timeout=0)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            admitted = migration.inspect(conn, pins, helpers, target=True)
            after = h.db_snapshot(conn, shared)
            conn.rollback()
        migration.require_delta(before["objects"], after["objects"], pins)
        h.need(after["orderedAudit"] == before["orderedAudit"]
            and after["persistentJournalFormat"] == before["persistentJournalFormat"]
            and set(after["rows"]) == set(before["rows"])
            and all(after["rows"][name] == row for name, row in before["rows"].items() if name != shared.CONTRACT_TABLE))
        h.need(admitted["contract"] == receipt["afterContract"] and admitted["contractRowid"] == plan["contractRowid"]
            and admitted["orderedAudit"] == plan["orderedAudit"] == receipt["orderedAudit"]
            and receipt["preservedOldRowsSha256"] == shared.sha(shared.canonical(
                {name: row for name, row in before["rows"].items() if name != shared.CONTRACT_TABLE})))
        h.need({key: value for key, value in receipt["beforeContract"].items() if key not in migration.CONTRACT_FIELDS}
            == {key: value for key, value in receipt["afterContract"].items() if key not in migration.CONTRACT_FIELDS})
        h.need(shared.tree(Path("/data")) == h.read("/out/recovered-files.json")
            and h.custody_snapshot() == h.read("/out/custody-baseline.json"))
        h.save("/out/migrated-database.json", after)
        h.save("/out/expected-contract.json", admitted["contract"])
        h.need(h.raw_file("/out/plan.json") == plan_raw and h.raw_file("/out/apply.json") == receipt_raw)
        verify()
        save_database_bytes("/out", {"schema": "serverware.sourceRevisionRetainedDatabaseBytes/v1",
            "candidateCommit": COMMIT, "inputsSha256": inputs_sha, "sourceProof": proof,
            "transitionId": migration.TRANSITION, "pinsSha256": migration.PIN_SHA256,
            "planSha256": receipt["planSha256"], "planFileSha256": h.sha(plan_raw),
            "migrationReceiptSha256": h.sha(receipt_raw), "migratedBaselineSha256": h.sha(h.canon(after)),
            "database": commitment, "observation": "freeze-before-first-startup",
            "sidecarsAbsent": True, "startupClaimsAbsent": True, "databasePromoted": False,
            "requiredPhaseReceipt": "phase-freeze.json", "hostCleanupVerification": "required"})
    h.save("/out/freeze.json", {"ok": True, "tables": len(after["rows"]),
        "auditCount": after["rows"]["audit_events"]["count"], "orderedAudit": after["orderedAudit"],
        "migratedBaselineSha256": h.sha(h.canon(after)), "migrationReceiptSha256": h.sha(receipt_raw),
        "migratedDatabaseBytesSha256": h.sha(h.raw_file("/out/migrated-database-bytes.json")),
        "exactFourContractFieldsOnly": True, "allOtherRowsExact": True, "custodyExact": True})


def final_result(inputs_sha, proof):
    h.need(os.geteuid() == 0)
    original = h.archives()
    h.need(proof == h.read("/job/source-proof.json"))
    prior = [host_receipt(role, inputs_sha) for role in ROLES[:-1]]
    h.need(len({value["containerId"] for value in prior}) == len(prior))
    out = Path("/job/out")
    baseline = h.read(out / "migrated-database.json")
    frozen = h.read(out / "freeze.json")
    captured = h.read(out / "capture-baseline.json")["snapshot"]
    h.need(frozen["ok"] is True and frozen["migratedBaselineSha256"] == h.sha(h.canon(baseline))
        and baseline["orderedAudit"] == captured["orderedAudit"]
        and baseline["rows"]["audit_events"] == captured["rows"]["audit_events"])
    starts = [h.read(out / (role + ".json")) for role in ("startup1", "observe1", "startup2", "observe2")]
    h.need(all(value["ok"] is True for value in starts))
    h.need(all(value["tables"] == len(captured["rows"])
        and value["auditCount"] == captured["rows"]["audit_events"]["count"] for value in (starts[0], starts[2])))
    auxiliary = h.verify_auxiliary()
    h.need(h.archives() == original)
    result = {"schema": "serverware.sourceRevisionRetainedResult/v1", "ok": True,
        "candidateCommit": COMMIT, "inputsSha256": inputs_sha, "sourceProof": proof,
        "capturePins": cfg["capturePins"], "migrationPinsSha256": h.PIN_SHA,
        "migrationReceiptSha256": h.sha(h.raw_file(out / "apply.json")),
        "migratedBaselineSha256": h.sha(h.canon(baseline)), "tableCount": len(captured["rows"]),
        "auditCount": captured["rows"]["audit_events"]["count"], "orderedAudit": captured["orderedAudit"],
        "twoActualStarts": True, "allRetainedRowsPreserved": True, "onlyFourMigrationContractFields": True,
        "onlyBoundedStartupTimestamp": True, "custodyAndNonDatabaseBytesExact": True,
        "auxiliaryPreservation": auxiliary, "migrationExecuted": True, "databasePromoted": False,
        "normalBinaryExecuted": False, "liveAccess": False, "providerCalls": 0, "nativeAdmission": False,
        "automaticRetry": False, "automaticRollback": False, "priorContainersRemoved": len(prior),
        "hostCleanupVerification": "required"}
    h.save("/job/result.json", result, 1000)


def phase_stdout(role):
    """Hash-only handoff from each existing UID; never broaden private mounts."""
    h.need(role in ROLES)
    value = {"schema": "serverware.sourceRevisionRetainedPhase/v1", "ok": True, "role": role,
        "liveAccess": False, "hostCleanupVerification": "required"}
    if role == "prepare":
        value["promotionFileSha256"] = {"copy/" + name: h.sha(h.raw_file(Path("/job") / name))
            for name in PROMOTION_ROOT_FILES}
    elif role == "freeze":
        value["promotionFileSha256"] = {"copy/out/" + name: h.sha(h.raw_file(Path("/out") / name))
            for name in PROMOTION_OUT_FILES}
    return value


def main():
    global cfg, SOURCE_ROOT, PROOFS, selected_role, stage
    h.need(len(sys.argv) == 3 and sys.argv[1] in ROLES)
    role, inputs_sha = sys.argv[1:]
    selected_role, stage = role, "inputs"
    cfg = h.strict_json(pinned("/inputs.json", inputs_sha))
    validate_inputs(cfg)
    pinned(Path(__file__).resolve(), cfg["workerSha256"])
    pinned(Path(h.__file__).resolve(), cfg["helpersSha256"])
    stage = "preflight"
    preflight(role)
    signal.alarm(90)
    os.umask(0o077)
    SOURCE_ROOT, PROOFS = Path("/app"), Path("/proofs")
    stage = "source_before"
    proof = source_proof()
    stage = "previous_receipt"
    if role != "prepare":
        host_receipt(ROLES[ROLES.index(role) - 1], inputs_sha)
    claim_root = Path("/job") if role in ("prepare", "result") else Path("/out")
    stage = "claim"
    h.save(claim_root / (role + ".claim.json"), {"role": role, "inputsSha256": inputs_sha, "automaticRetry": False})
    sys.addaudithook(lambda event, _arguments: h.need(not event.startswith("socket.")))
    if not role.startswith("startup"):
        for key in tuple(os.environ):
            if key.startswith("SERVERWARE_"):
                del os.environ[key]
    stage = "selected_role"
    if role == "prepare":
        h.save("/job/source-proof.json", proof)
        h.prepare()
        baseline = pinned("/captured/preservation-baseline.json", cfg["capturePins"]["preservation-baseline.json"])
        value = h.strict_json(baseline)
        h.need(value["schema"] == "serverware.authorityUpgradeDatabaseObservation/v1"
            and len(value["snapshot"]["rows"]) == 218)
        h.save("/job/out/capture-baseline.json", baseline, 10001)
    elif role == "recover":
        h.recovery(observer())
    elif role in ("plan", "apply"):
        migration_cli(role)
    elif role == "freeze":
        freeze_migrated(inputs_sha, proof)
    elif role.startswith("startup"):
        h.startup(role, observer())
    elif role.startswith("observe"):
        h.observe(role, observer())
    else:
        final_result(inputs_sha, proof)
    stage = "source_after"
    h.need(source_proof() == proof and h.sha(h.raw_file("/inputs.json")) == inputs_sha)
    stage = "phase_receipt"
    output = Path("/job/out") if role in ("prepare", "result") else Path("/out")
    h.save(output / ("phase-" + role + ".json"), {"schema": "serverware.sourceRevisionRetainedPhase/v1",
        "ok": True, "role": role, "inputsSha256": inputs_sha, "workerSha256": cfg["workerSha256"],
        "sourceProof": proof, "liveAccess": False, "hostCleanupVerification": "required"}, 10001 if role == "prepare" else None)
    print(json.dumps(phase_stdout(role), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print(json.dumps({"schema": "serverware.sourceRevisionRetainedPhase/v1", "ok": False,
            "role": selected_role, "stage": stage, "reason": "rehearsal_refused",
            "automaticRetry": False}, sort_keys=True))
        raise SystemExit(1) from None

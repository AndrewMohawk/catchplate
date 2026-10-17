#!/usr/bin/env python3
"""One bounded local PG component job; outer container ownership is mandatory.

No Docker, downloads, arbitrary DSNs, retained clusters or host mounts are used
here. Run only in the reviewed cached image, network-none/read-only, with fresh
/scratch tmpfs. The external owner must enforce 2 CPUs/4 GiB/256 PIDs/240 seconds,
retain output and destroy the entire container even after success. This is not
the prepared native-PG suite or production authority/bootstrap acceptance.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path("/scratch/native-jit-storage")
TEST = "scripts/test_authority_native_jit_retention_postgres.py"
FIXED_READS = ("scripts/run_native_jit_retention_postgres.py", TEST,
    "catchplate/db.py", "catchplate/authority_store/executor_v9.py")
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
sys.pycache_prefix = "/scratch/unused-pycache"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_pins():
    return {name: sha((ROOT / name).read_bytes()) for name in FIXED_READS}


def fixture_child():
    """Observe the actual imported Python closure and the AST-read originals."""
    before, compiled, conflicting = source_pins(), {}, []

    def audit(event, arguments):
        if event == "compile" and len(arguments) >= 2:
            raw, filename = arguments[:2]
            if isinstance(filename, str) and filename.startswith(str(ROOT) + "/") and isinstance(raw, (str, bytes)):
                name = str(Path(filename).relative_to(ROOT))
                digest = sha(raw.encode() if isinstance(raw, str) else raw)
                if name in compiled and compiled[name] != digest:
                    conflicting.append(name)
                compiled[name] = digest

    sys.addaudithook(audit)
    code = 1
    try:
        sys.argv = [str(ROOT / TEST), "--postgres-dsn",
            "host=/scratch/native-jit-storage/socket port=5432 dbname=postgres user=catchplate_fixture_admin"]
        runpy.run_path(sys.argv[0], run_name="__main__")
    except SystemExit as error:
        code = error.code if isinstance(error.code, int) else int(error.code is not None)
    finally:
        after = source_pins()
        rehashed = {name: sha((ROOT / name).read_bytes()) for name in compiled}
        imported = {str(Path(module.__file__).relative_to(ROOT)) for module in list(sys.modules.values())
            if getattr(module, "__file__", None) and str(module.__file__).startswith(str(ROOT) + "/")
            and str(module.__file__).endswith(".py")}
        # This driver was compiled before its hook; its complete bytes have a
        # separate before/after pin, not a fabricated compile observation.
        missing = sorted(imported - set(compiled) - {FIXED_READS[0]})
        passed = code == 0 and before == after and compiled == rehashed and not conflicting and not missing
        print(json.dumps({"schema": "catchplate.nativeJitStorageComponentSource/v1", "passed": passed,
            "testExitCode": code, "fixedSourcesBefore": before, "fixedSourcesAfter": after,
            "actualCompiledPython": compiled, "sourceUnchanged": compiled == rehashed,
            "conflictingCompilations": conflicting, "unobservedImports": missing}, sort_keys=True), flush=True)
    return 0 if passed else 1


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run():
    from scripts.run_ordinary_regression import require_offline_network
    from catchplate.native_postgres_process import ProcessSet
    import psycopg

    require_offline_network()
    require(ROOT == Path("/app") and Path.cwd() == ROOT, "source mount differs")
    require(os.getuid() == os.geteuid() == 10001 and os.getgid() == os.getegid() == 10001,
        "fixture must run as the cached image's unprivileged catchplate identity")
    require(os.statvfs(ROOT).f_flag & os.ST_RDONLY, "source mount is not read-only")
    require(any(line.split()[4] == "/scratch" and " - tmpfs " in line
        for line in Path("/proc/self/mountinfo").read_text().splitlines()), "scratch is not isolated tmpfs")
    require(not any(name.startswith("PG") for name in os.environ), "ambient PostgreSQL settings are forbidden")
    candidates = [Path("/usr/lib/postgresql") / version / "bin" for version in ("16", "17")
        if (Path("/usr/lib/postgresql") / version / "bin" / "postgres").is_file()]
    require(len(candidates) == 1, "cached PostgreSQL 16/17 binary selection is not exact")
    bindir = candidates[0]
    for name in ("initdb", "postgres"):
        binary = bindir / name
        info = binary.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0
            and os.statvfs(binary).f_flag & os.ST_RDONLY, "cached engine is not root-owned read-only source")
    os.umask(0o077)
    SCRATCH.mkdir(mode=0o700)  # Refuse any prior directory or retained cluster.
    data, socket = SCRATCH / "pgdata", SCRATCH / "socket"
    data.mkdir(mode=0o700)
    socket.mkdir(mode=0o700)
    before = source_pins()
    environment = {"PATH": str(bindir) + ":/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "TZ": "UTC", "TMPDIR": str(SCRATCH), "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1", "CATCHPLATE_DATA_DIR": str(SCRATCH / "app-data"),
        "CATCHPLATE_PROCESS_MODE": "metadata-bootstrap", "CATCHPLATE_RELEASE_CHANNEL": "dev"}
    init_command = (str(bindir / "initdb"), "--pgdata=" + str(data), "--username=catchplate_fixture_admin",
        "--encoding=UTF8", "--locale=C", "--auth-local=trust", "--auth-host=reject", "--data-checksums",
        "--no-instructions", "--no-clean")
    settings = {"listen_addresses": "", "unix_socket_directories": str(socket), "unix_socket_permissions": "0700",
        "port": "5432", "ssl": "off", "fsync": "on", "full_page_writes": "on", "synchronous_commit": "on",
        "max_connections": "16", "max_locks_per_transaction": "256",
        "shared_buffers": "32MB", "work_mem": "4MB", "maintenance_work_mem": "32MB",
        "max_wal_size": "128MB", "min_wal_size": "32MB", "temp_file_limit": "64MB", "jit": "off",
        "restart_after_crash": "off", "logging_collector": "off"}
    server_command = (str(bindir / "postgres"), "-D", str(data)) + tuple(
        item for name, value in settings.items() for item in ("-c", name + "=" + value))
    processes, server, child = ProcessSet(), None, None
    began, passed, normal_stop, error = time.monotonic(), False, False, None
    old_signals = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    for number in old_signals:
        signal.signal(number, lambda _number, _frame: setattr(processes, "cancelled", True))
    try:
        init = processes.start(init_command, env=environment, cwd=str(ROOT))
        require(processes.wait(init, began + 45) == "exited" and init.returncode == 0 and init.complete_log,
            "isolated initialization failed")
        server = processes.start(server_command, env=environment, cwd=str(ROOT))
        ready = False
        while time.monotonic() < began + 60:
            processes.pump(0.05)
            require(not processes.cancelled and server.returncode is None and not server.overflow and not server.lost,
                "isolated postmaster failed before readiness")
            try:
                connection = psycopg.connect(host=str(socket), port=5432, dbname="postgres", user="catchplate_fixture_admin",
                    connect_timeout=1, passfile="/dev/null", sslmode="disable", gssencmode="disable",
                    options="-cstatement_timeout=1000", autocommit=True)
            except psycopg.OperationalError:
                continue
            with connection:
                observed = connection.execute("SELECT current_setting('server_version_num')::int, inet_server_addr(), "
                    "current_setting('data_checksums'), current_setting('fsync'), current_setting('full_page_writes'), "
                    "current_setting('synchronous_commit'), current_setting('listen_addresses'), "
                    "current_setting('max_locks_per_transaction')").fetchone()
            require(observed[0] // 10000 == int(bindir.parent.name)
                and observed[1:] == (None, "on", "on", "on", "on", "", "256"), "isolated engine profile differs")
            ready = True
            break
        require(ready, "isolated engine readiness timed out")
        child = processes.start((sys.executable, "-B", str(Path(__file__)), "--fixture-child"),
            env=environment, cwd=str(ROOT))
        termination = processes.wait(child, began + 210, must_remain_alive=server)
        require(termination == "exited" and child.returncode == 0 and child.complete_log,
            "isolated component tests failed or timed out")
        passed = True
    except Exception as failure:
        error = type(failure).__name__ + ":" + str(failure)
    finally:
        if server is not None:
            processes.stop(server, initial_signal=signal.SIGINT, deadline=min(began + 230, time.monotonic() + 15))
            normal_stop = server.returncode == 0 and server.complete_log
        try:
            processes.close()
        finally:
            for number, handler in old_signals.items():
                signal.signal(number, handler)
        after = source_pins()
        passed = passed and normal_stop and before == after and all(item.returncode is not None for item in processes.children)
        print(json.dumps({"schema": "catchplate.nativeJitStorageIsolatedPostgres/v1", "passed": passed,
            "elapsedSeconds": round(time.monotonic() - began, 3), "error": error,
            "postgresVersion": bindir.parent.name, "normalPostmasterStop": normal_stop,
            "fixedSourcesUnchanged": before == after, "externalContainerDestructionRequired": True,
            "logs": [{"sha256": sha(bytes(item.log)), "bytes": len(item.log), "complete": item.complete_log,
                "exitCode": item.returncode, "base64": base64.b64encode(bytes(item.log)).decode("ascii")}
                for item in processes.children],
            "scope": "real SQL/storage/kernel components with synthetic custody, not whole authority admission"},
            sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--fixture-child"]:
        raise SystemExit(fixture_child())
    if sys.argv[1:]:
        raise SystemExit("this focused storage runner accepts no public arguments")
    raise SystemExit(run())

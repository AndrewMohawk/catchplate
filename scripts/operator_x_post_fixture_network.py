"""Fixed managed-X network-none namespace, empty custody and unchanged TLS relay.

No host interfaces/routes, public DNS, configurable destination or production
configuration is changed. Initialization accepts only the pinned fresh-root
initializer. PKI is created by the separate offline provider setup phase.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import socket
import sqlite3
import ssl
import stat
import struct
import threading
import time
import uuid
import re

from scripts import operator_github_fixture_network as isolated

FIXTURE_IP, LOOPBACK, PROXY_HOST = isolated.FIXTURE_IP, isolated.LOOPBACK, isolated.PROXY_HOST
CONTROL_HOST = "catchplate-x.example.com"
CONTROL_ORIGIN = "https://" + CONTROL_HOST
PROVIDER_HOSTS = ("x.com", "api.x.com")
KEEPER_SECONDS, EDGE_SECONDS = 300, 240
ROOT, NETWORK_ROOT = Path("/fixture-runtime"), Path("/fixture-network")
HOSTS = ("127.0.0.1 localhost catchplate decision-gate-rs " + PROXY_HOST + " " + CONTROL_HOST
    + "\n" + FIXTURE_IP + " " + " ".join(PROVIDER_HOSTS) + "\n").encode("ascii")
FAULT_GATE_IP, FAULT_GATE_HOSTS_NAME = "127.0.0.2", "hosts-fault-gate"
FAULT_GATE_HOSTS = ("127.0.0.1 localhost decision-gate-rs " + PROXY_HOST + " " + CONTROL_HOST
    + "\n" + FIXTURE_IP + " " + " ".join(PROVIDER_HOSTS)
    + "\n" + FAULT_GATE_IP + " catchplate\n").encode("ascii")
RESOLV = isolated.RESOLV
QUOTA_REQUEST = "x-quota-restart.request.json"
QUOTA_ACK = "x-quota-restart.ack.json"
QUOTA_TABLES = ("operator_x_quota_state", "operator_x_quota_accounts",
    "operator_x_quota_buckets", "operator_x_quota_attempts")
QUOTA_KEY_FILES = ("/data/master.key", "/data/policy-signing-ed25519.pem",
    "/data/response-signing-ed25519.pem", "/x-custody/provider-key.json")


def require(condition):
    if not condition:
        raise ValueError("isolated managed X namespace refused")


def assert_isolated_network(*, attached=True, view="ordinary"):
    require(view in ("ordinary", "fault-gate") and (attached or view == "ordinary"))
    isolated.assert_isolated_network(attached=False)
    if attached:
        gate = view == "fault-gate"
        require(Path("/etc/hosts").read_bytes() == (FAULT_GATE_HOSTS if gate else HOSTS)
            and Path("/etc/resolv.conf").read_bytes() == RESOLV)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((FIXTURE_IP, 0))
            if gate:
                # The relay uses an existing loopback address, not a new route.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as relay_probe:
                    relay_probe.bind((FAULT_GATE_IP, 0))
        for host, address in [(host, FIXTURE_IP) for host in PROVIDER_HOSTS] + [
                (host, LOOPBACK) for host in (CONTROL_HOST, PROXY_HOST, "decision-gate-rs")] + [
                ("catchplate", FAULT_GATE_IP if gate else LOOPBACK)]:
            require({item[4][0] for item in socket.getaddrinfo(host, 443, socket.AF_INET,
                socket.SOCK_STREAM)} == {address})


def _write(path, raw, mode=0o400):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw); output.flush(); os.fchmod(output.fileno(), mode); os.fsync(output.fileno())


def quota_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def quota_checkpoint(value, *, ack=False):
    """Closed public rendezvous, never a URL, command or ceremony capability."""
    require(type(value) is dict and type(ack) is bool)
    if ack:
        require(set(value) == {"schema", "request_sha256", "status"}
            and value["schema"] == "catchplate.privateXQuotaRestartAck/v1"
            and value["status"] == "retained_restarted"
            and type(value["request_sha256"]) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value["request_sha256"]))
    else:
        require(set(value) == {"schema", "run_id", "phase", "policy_hash", "credential_id",
            "application_ids", "initial_access_expires_at_epoch_ms"}
            and value["schema"] == "catchplate.privateXQuotaRestartRequest/v1"
            and value["phase"] == "after_three"
            and type(value["policy_hash"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value["policy_hash"])
            and type(value["application_ids"]) is list and len(value["application_ids"]) == 2)
        identifiers = [value["run_id"], value["credential_id"], *value["application_ids"]]
        require(all(type(item) is str and len(item) == 36 and str(uuid.UUID(item)) == item for item in identifiers)
            and len(set(identifiers)) == 4)
        expiry = value["initial_access_expires_at_epoch_ms"]
        require(type(expiry) is int and 0 < expiry < 2**53)
    require(len(quota_json(value)) <= 4096)
    return value


def read_quota_checkpoint(*, ack=False):
    root = Path("/client-work")
    info = root.lstat()
    require(os.geteuid() == os.getegid() == 10001 and stat.S_ISDIR(info.st_mode)
        and info.st_uid == info.st_gid == 10001 and stat.S_IMODE(info.st_mode) == 0o700)
    path = root / (QUOTA_ACK if ack else QUOTA_REQUEST)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == before.st_gid == 10001 and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= 4096)
        raw = stream.read(4097)
        after = path.lstat()
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        require(identity(before) == identity(after) and len(raw) == before.st_size)
    value = quota_checkpoint(json.loads(raw), ack=ack)
    require(raw == quota_json(value))
    return value


def acknowledge_quota_restart(request_sha256):
    request = read_quota_checkpoint()
    require(request is not None and request_sha256 == "sha256:" + hashlib.sha256(quota_json(request)).hexdigest())
    value = quota_checkpoint({"schema": "catchplate.privateXQuotaRestartAck/v1",
        "request_sha256": request_sha256, "status": "retained_restarted"}, ack=True)
    root = Path("/client-work")
    stage, target = root / (QUOTA_ACK + ".pending"), root / QUOTA_ACK
    _write(stage, quota_json(value), 0o600)
    os.link(stage, target, follow_symlinks=False)  # Exclusive publication; never replaces an ACK.
    stage.unlink()
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(read_quota_checkpoint(ack=True) == value)
    return value


def quota_preservation_snapshot():
    """Fixed synthetic read-only snapshot; only counts, inode pins and hashes escape.

    Run while the gate is stopped, before and after the app's single restart.
    No app imports, schema creation, secret decryption or SQLite writes.
    """
    import fcntl
    require(os.geteuid() == os.getegid() == 10001)
    require(json.loads(Path("/private-audit-fixture.json").read_bytes()) == {
        "schema": "catchplate.privateOperatorAuditFixture/v1", "syntheticOnly": True})
    def identity(path):
        row = path.lstat()
        require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and row.st_uid == row.st_gid == 10001)
        return [row.st_dev, row.st_ino, stat.S_IMODE(row.st_mode)]
    def file_hash(path):
        before = identity(path)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as stream:
            raw = stream.read(4 * 1024**2 + 1)
        require(0 < len(raw) <= 4 * 1024**2 and identity(path) == before)
        return {"identity": before, "sha256": hashlib.sha256(raw).hexdigest()}
    lock = Path("/data/.operator-publication.lock")
    before_lock = identity(lock)
    descriptor = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        until = time.monotonic() + 2
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < until)
                time.sleep(.025)
        require([os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino] == before_lock[:2])
        database = identity(Path("/data/catchplate.sqlite3"))
        conn = sqlite3.connect("file:/data/catchplate.sqlite3?mode=ro", uri=True, timeout=2)
        try:
            conn.execute("PRAGMA query_only=ON"); conn.execute("BEGIN")
            tables = (*QUOTA_TABLES, "operator_catalog_state", "operator_catalog_credentials",
                "operator_catalog_applications", "operator_catalog_rules", "operator_demo_settings",
                "operator_demo_policy", "credentials", "credential_generations", "operator_x_configuration",
                "operator_x_provider_custody", "operator_x_provider_custody_meta",
                "operator_x_account_intents", "operator_x_account_work", "operator_x_account_captures")
            projected = {}
            for table in tables:
                rows = conn.execute('SELECT * FROM "' + table + '" LIMIT 257').fetchall()
                require(len(rows) <= 256)
                normalized = [[{"bytes": item.hex()} if isinstance(item, bytes) else item for item in row] for row in rows]
                raw = quota_json(sorted(normalized, key=quota_json))
                require(len(raw) <= 4 * 1024**2)
                projected[table] = {"rows": len(rows), "sha256": hashlib.sha256(raw).hexdigest()}
            buckets = conn.execute("SELECT provider_subject,utc_day,claimed,outstanding FROM operator_x_quota_buckets").fetchall()
            require(len(buckets) == 1 and buckets[0][0] == "18446744073709551001"
                and type(buckets[0][2]) is int and buckets[0][2:] == (3, 0))
            states = conn.execute("SELECT state FROM operator_x_quota_attempts").fetchall()
            require(states == [("claimed",)] * 3)
            policy = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
            credentials = conn.execute("SELECT id,data_json FROM operator_catalog_credentials").fetchall()
            applications = conn.execute("SELECT id,data_json FROM operator_catalog_applications").fetchall()
            require(policy is not None and len(credentials) == 1 and json.loads(credentials[0][1])["status"] == "active"
                and len(applications) == 2 and all(json.loads(row[1])["status"] == "active" for row in applications))
        finally:
            conn.close()
        keys = {name: file_hash(Path(name)) for name in QUOTA_KEY_FILES}
        require(identity(lock) == before_lock and identity(Path("/data/catchplate.sqlite3")) == database)
        return {"schema": "catchplate.privateXQuotaPreservation/v1", "database": database,
            "lock": before_lock, "tables": projected, "keys": keys, "claimed": 3, "outstanding": 0,
            "policy_hash": policy[0], "credential_id": credentials[0][0],
            "application_ids": sorted(row[0] for row in applications)}
    finally:
        os.close(descriptor)


def prepare_network_files(*, fault_gate=False):
    root = Path("/upstream-data/x-network")
    require(type(fault_gate) is bool and os.geteuid() == 10001
        and not root.exists() and not root.is_symlink())
    assert_isolated_network(attached=False)
    root.mkdir(mode=0o700)
    for name, raw in (("hosts", HOSTS), ("resolv.conf", RESOLV)) + (
            ((FAULT_GATE_HOSTS_NAME, FAULT_GATE_HOSTS),) if fault_gate else ()):
        _write(root / name, raw, 0o444)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def initialize():
    from scripts.prepare_operator_catalog_fixture import INITIALIZER_SHA256
    require(os.geteuid() == 0)
    assert_isolated_network(attached=False)
    source = Path("/initialize.py")
    require(not source.is_symlink() and source.is_file()
        and hashlib.sha256(source.read_bytes()).hexdigest() == INITIALIZER_SHA256)
    runpy.run_path(str(source))["initialize"](ROOT)
    custody = ROOT / "x-custody"
    require(not custody.exists() and not custody.is_symlink())
    custody.mkdir(mode=0o700)
    os.chown(custody, 10001, 10001)
    for path in (custody, ROOT):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def keep_namespace():
    require(os.geteuid() == 0)
    assert_isolated_network(attached=False)
    require(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text().strip() == "0")
    index = socket.if_nametoindex("lo")
    address = socket.inet_aton(FIXTURE_IP)
    payload = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, index)
    payload += struct.pack("=HH4s", 8, 1, address) + struct.pack("=HH4s", 8, 2, address)
    packet = struct.pack("=IHHII", 16 + len(payload), 20, 1 | 4 | 0x400 | 0x200, 1, 0) + payload
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(3); channel.bind((0, 0)); channel.sendto(packet, (0, 0)); response = channel.recv(4096)
    require(len(response) >= 20)
    length, kind, _, sequence, _ = struct.unpack_from("=IHHII", response)
    require(length == len(response) and kind == 2 and sequence == 1
        and struct.unpack_from("=i", response, 16)[0] == 0)
    os.setgroups([]); os.setgid(10001); os.setuid(10001)
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(all(int(status[key].strip(), 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
        and status["NoNewPrivs"].strip() == "1")
    assert_isolated_network()
    _write(NETWORK_ROOT / "ready", json.dumps({"schema": "catchplate.xPostFixtureNetwork/v1",
        "network": "none", "interfaces": ["lo"], "address": FIXTURE_IP,
        "effectiveCapabilities": 0}, sort_keys=True).encode("ascii"))
    stop = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stop.set())
    stop.wait(KEEPER_SECONDS)


def edge():
    from scripts.operator_proxy_basic_tls import Server
    require(os.geteuid() == os.getegid() == 10001)
    assert_isolated_network()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain("/edge/cert.pem", "/edge/key.pem")
    stop = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stop.set())
    with Server(LOOPBACK, LOOPBACK, context, EDGE_SECONDS) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            print('{"ready":true,"syntheticOnly":true,"headerRewriting":false}', flush=True)
            stop.wait(EDGE_SECONDS)
        finally:
            server.shutdown(); worker.join(timeout=4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("initialize", "network", "edge", "quota-request", "quota-ack", "quota-snapshot"))
    parser.add_argument("--request-sha256")
    args = parser.parse_args()
    operation = args.operation
    require((args.request_sha256 is not None) == (operation == "quota-ack"))
    os.umask(0o077)
    if operation == "initialize":
        signal.alarm(30); initialize()
    elif operation == "network":
        keep_namespace()
    elif operation == "edge":
        edge()
    else:
        signal.alarm(6)
        value = (read_quota_checkpoint() if operation == "quota-request" else
            acknowledge_quota_restart(args.request_sha256) if operation == "quota-ack" else quota_preservation_snapshot())
        print(quota_json(value).decode("ascii"), flush=True)


if __name__ == "__main__":
    main()

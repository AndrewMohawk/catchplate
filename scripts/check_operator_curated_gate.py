#!/usr/bin/env python3
"""Read-only mount proof around the unchanged private Basic-client acceptance.

Root runs this before and after the existing one-shot checker. This script
never starts containers, mutates policy, imports the app or contacts providers.
Only fixed Docker inspect/exec observations and one exclusive evidence write.
After mode joins the original probe and successful actual-client receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

from scripts import prepare_operator_curated_gate_fixture as fixture

base, basic = fixture.base, fixture.basic
DEADLINE = 0.0
FORMAT = ('{"id":{{json .Id}},"image":{{json .Config.Image}},"user":{{json .Config.User}},'
    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"running":{{json .State.Running}},"health":{{json .State.Health.Status}},"pid":{{json .State.Pid}},'
    '"started":{{json .State.StartedAt}},"restarts":{{json .RestartCount}},"oom":{{json .State.OOMKilled}},'
    '"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},'
    '"pid_mode":{{json .HostConfig.PidMode}},"cap_add":{{json .HostConfig.CapAdd}},"cap_drop":{{json .HostConfig.CapDrop}},'
    '"security":{{json .HostConfig.SecurityOpt}},"mounts":{{json .Mounts}},'
    '"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}}}')

# Sent to the already-running exact fixture containers. All file paths are
# authored constants; no app import, key byte output or filesystem write.
PROBE = r'''
import fcntl, hashlib, json, os, signal, stat, sys, time
from pathlib import Path

def need(value):
    if not value: raise ValueError("curated observation refused")
def deadline(*_): raise TimeoutError("bounded")
signal.signal(signal.SIGALRM, deadline); signal.alarm(15)
mode, expected_binary = sys.argv[1:]
need(mode in {"app", "gate"} and os.geteuid() == os.getegid() == 10001)
leaves = (".operator-publication.lock", ".serverware-operator-demo.json", "mitmproxy/mitmproxy-ca-cert.pem", "mitmproxy/mitmproxy-ca.pem")
private = ("serverware.sqlite3", "master.key",
    "policy-signing-ed25519.pem", "serverware.sqlite3-wal", "serverware.sqlite3-shm",
    "response-signing-ed25519.pem", "dev-tee-quote-ed25519.pem", "webauthn-trust-signing-ed25519.pem")
def identity(path):
    info = os.lstat(path)
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 10001)
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode), "size": info.st_size, "links": info.st_nlink}
def directory(path):
    info = os.lstat(path)
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == info.st_gid == 10001)
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
def digest(path):
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""): result.update(block)
    return result.hexdigest()
def policy(path):
    prior = identity(path); need(prior["mode"] == 0o600 and 0 < prior["size"] <= 4194304)
    with open(path, "rb") as stream: raw = stream.read(4194305)
    need(len(raw) == prior["size"] and identity(path) == prior)
    document = json.loads(raw)
    need(document.get("apiVersion") == "serverware.policy/v1" and isinstance(document.get("metadata"), dict))
    sequence = document["metadata"]["sequence"]
    need(type(sequence) is int and sequence >= 1 and "signature" in document["metadata"])
    document["metadata"].pop("signature")
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    return {"file_sha256": hashlib.sha256(raw).hexdigest(), "policy_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(), "sequence": sequence}
try:
    directory("/data")
    lock = os.open("/data/.operator-publication.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        until = time.monotonic() + 3
        while True:
            try: fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB); break
            except BlockingIOError:
                need(time.monotonic() < until); time.sleep(0.025)
        leaf_state = {name: identity("/data/" + name) for name in leaves}
        need(leaf_state[leaves[0]]["mode"] == 0o600 and leaf_state[leaves[0]]["size"] == 0)
        need(os.fstat(lock).st_ino == leaf_state[leaves[0]]["inode"] and os.fstat(lock).st_dev == leaf_state[leaves[0]]["device"])
        need(leaf_state[leaves[1]]["mode"] == 0o600 and leaf_state[leaves[1]]["size"] > 0)
        need(leaf_state[leaves[2]]["size"] > 0 and leaf_state[leaves[3]]["mode"] == 0o600 and leaf_state[leaves[3]]["size"] > 0)
        root = Path("/data/gate-runtime") if mode == "app" else Path("/data")
        export_directory = directory(root); directory(root / "mitmproxy")
        need(set(os.listdir(root)) == {"policy-bundle.json", leaves[0], leaves[1], "mitmproxy"})
        need(set(os.listdir(root / "mitmproxy")) == {"mitmproxy-ca-cert.pem", "mitmproxy-ca.pem"})
        current = policy(root / "policy-bundle.json")
        if mode == "app":
            need(os.environ.get("SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED") == "1")
            need(policy("/data/policy-bundle.json") == current)
            for name in leaves:
                item = identity(root / name); need(item["mode"] == 0 and item["size"] == 0)
            visible = {}
            for name in private:
                try: visible[name] = identity("/data/" + name)
                except FileNotFoundError: pass
            # A fresh app has no master key until its first credential is saved.
            # Never create a dummy credential merely to satisfy an observer.
            need({private[0], private[2]} <= visible.keys())
        else:
            visible = {}
            for name in private:
                try:
                    descriptor = os.open("/data/" + name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                except FileNotFoundError: visible[name] = "absent"
                else: os.close(descriptor); raise ValueError("private path exposed")
        mounts = {}
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            fields = line.split(); target = fields[4]
            if target in {"/data", *("/data/" + name for name in leaves)}:
                need(target not in mounts)
                mounts[target] = {"device": fields[2], "root": fields[3], "options": fields[5].split(",")}
        need("/data" in mounts and ("rw" if mode == "app" else "ro") in mounts["/data"]["options"])
        if mode == "gate":
            need(set(mounts) == {"/data", *("/data/" + name for name in leaves)} and all("ro" in item["options"] for item in mounts.values()))
            executable = []
            for pid in os.listdir("/proc"):
                if not pid.isdecimal(): continue
                try: target = os.readlink("/proc/" + pid + "/exe")
                except OSError: continue
                if target == "/usr/local/bin/serverware-decision-gate": executable.append((int(pid), digest("/proc/" + pid + "/exe")))
            need(len(executable) == 1 and executable[0][1] == digest("/usr/local/bin/serverware-decision-gate") == expected_binary)
        else: executable = None
        need({name: identity("/data/" + name) for name in leaves} == leaf_state)
        result = {"ok": True, "uid": os.geteuid(), "leaves": leaf_state, "policy": current, "export_directory": export_directory,
            "private_files": visible, "mountinfo": mounts, "actual_executable": executable}
    finally: os.close(lock)
    print(json.dumps(result, sort_keys=True))
except Exception:
    print('{"ok":false,"error":"curated container observation refused"}'); raise SystemExit(2) from None
finally: signal.alarm(0)
'''


def command(arguments, source=None):
    remaining = DEADLINE - time.monotonic()
    base.require(remaining > 0, "observation deadline exceeded")
    result = subprocess.run(arguments, input=source, capture_output=True, text=True, timeout=min(20, remaining), check=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    base.require(len(result.stdout) <= 262144, "bounded observation required")
    return json.loads(result.stdout)


def document(path, maximum=4194304):
    base.require(path.is_absolute() and path.resolve() == path and not path.is_symlink(), "exact evidence file required")
    info = path.lstat()
    base.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum, "bounded evidence file required")
    return json.loads(path.read_text())


def inspect(identifier, name, config):
    base.require(re.fullmatch(r"[0-9a-f]{64}", identifier), "full fixture container identity required")
    value = command(["/usr/bin/docker", "inspect", "--format", FORMAT, identifier])
    expected = config["services"][name]
    base.require(value["id"] == identifier and value["service"] == name and value["project"] == config["name"] and
        value["image"] == expected["image"] and value["user"] == "10001:10001" and value["running"] is True and
        value["health"] == "healthy" and value["restarts"] == 0 and value["oom"] is False and value["pid"] > 0,
        "running private fixture identity differs")
    base.require(value["readonly"] is True and value["privileged"] is False and not value["pid_mode"] and not value["cap_add"] and
        value["cap_drop"] == ["ALL"] and value["security"] == ["no-new-privileges:true"] and not any((value["ports"] or {}).values()),
        "private runtime isolation differs")
    observed = sorted((row["Source"], row["Destination"], row["Type"], row["RW"]) for row in value["mounts"])
    intended = sorted((row["source"], row["target"], "bind", not row["read_only"]) for row in expected["volumes"])
    base.require(observed == intended, "actual mount set differs")
    networks = value["networks"]
    base.require(len(networks) == 1, "single isolated network required")
    network = next(iter(networks.values()))
    base.require(network["IPAddress"] == expected["networks"]["fixture"]["ipv4_address"], "fixture address differs")
    actual = command(["/usr/bin/docker", "network", "inspect", "--format",
        '{"id":{{json .Id}},"internal":{{json .Internal}},"project":{{json (index .Labels "com.docker.compose.project")}}}', network["NetworkID"]])
    base.require(actual["id"] == network["NetworkID"] and actual["internal"] is True and actual["project"] == config["name"],
        "fixture network is not private")
    return {key: value[key] for key in ("id", "service", "pid", "started")}


def verify_transition(before, after, client):
    base.require("master.key" in after["app_private_files_present"],
        "real client credential custody was not observed after the check")
    base.require(before.get("schema") == "serverware.privateCuratedGateObservation/v1" and before.get("ok") is True and
        before.get("phase") == "before" and before["preparation_sha256"] == after["preparation_sha256"] and
        before["containers"] == after["containers"] and before["shared_leaves"] == after["shared_leaves"] and
        before["gate_executable"] == after["gate_executable"] and before["export_directory"] == after["export_directory"],
        "original observed fixture identity changed")
    base.require(client.get("schema") == "serverware.operatorProxyBasicCheck/v1" and client.get("ok") is True and
        client.get("syntheticOnly") is True and client.get("dataPlaneBinaryDigest") == "sha256:" + after["binary_sha256"] and
        client.get("upstreamDispatches") == 4 and client.get("authenticationDenials") == 8 and client.get("functionalRetries") == 0,
        "actual unchanged Basic checker did not pass")
    observations = client.get("policyObservations", [])
    base.require(len(observations) == 3 and [row["stage"] for row in observations] == ["initial", "assigned_rule_0", "assigned_rule_1"] and
        len({row["policyHash"] for row in observations}) == 3 and
        [row["sequence"] for row in observations] == list(range(before["policy"]["sequence"], before["policy"]["sequence"] + 3)) and
        observations[0]["policyHash"] == before["policy"]["policy_hash"] and observations[-1]["policyHash"] == after["policy"]["policy_hash"] and
        after["policy"]["sequence"] == before["policy"]["sequence"] + 2 and after["policy"]["file_sha256"] != before["policy"]["file_sha256"] and
        client.get("namedAuditInventory", {}).get("data_plane.policy.reloaded") == 2, "two exact actual policy reloads not joined")
    features = client.get("featureObservations", [])
    base.require(len(features) == 4 and {row["client"] for row in features} == {"requests", "curl", "bearer_opt_in", "bearer_default"},
        "Basic and Bearer forward regressions not proved")
    return {"policy_updates_observed": 2, "clients": sorted(row["client"] for row in features),
        "upstream_dispatches": 4, "authentication_denials": 8, "client_receipt_passed": True}


def run(args):
    root = args.job_root
    base.require(bool(args.before_receipt) == bool(args.client_receipt), "after mode needs both original receipts")
    base.require(root.resolve() == root and root.parent == base.SCRATCH and re.fullmatch(
        r"serverware-curated-gate-private\.[A-Za-z0-9]{6,32}", root.name), "exact private fixture root required")
    prep = basic.pinned_json(root / "preparation.json", args.expected_preparation_sha256)
    base.require(prep.get("schema") == "serverware.privateCuratedGatePreparation/v1" and prep["jobRoot"] == str(root), "preparation differs")
    source, binary, initializer = (Path(prep[name]) for name in ("source", "binary", "initializer"))
    sources = basic.source_inventory(source, Path(prep["sourceManifest"]), prep["sourceManifestSha256"], prep["sourceCommit"])
    base.require(base.digest(binary) == prep["binarySha256"] and base.digest(initializer) == base.INITIALIZER_SHA256 and
        sources[basic.CHECKER] == prep["clientCheckerSha256"] and base.digest(root / "compose.json") == prep["composeSha256"], "fixture source differs")
    config = document(root / "compose.json")
    fixture.validate(config, source, binary, initializer, root, prep["subnet"], expected_binary_sha256=prep["binarySha256"])
    identities, observations = {}, {}
    for mode, identifier, service in (("app", args.app_container_id, "serverware"), ("gate", args.gate_container_id, "decision-gate-rs")):
        identities[mode] = inspect(identifier, service, config)
        observations[mode] = command(["/usr/bin/docker", "exec", "-i", "--user", "10001:10001", identifier,
            "python", "-I", "-B", "-", mode, prep["binarySha256"]], PROBE)
        base.require(observations[mode].get("ok") is True, "runtime filesystem observation refused")
    app, gate = observations["app"], observations["gate"]
    base.require(app["leaves"] == gate["leaves"] and app["policy"] == gate["policy"] and
        app["export_directory"] == gate["export_directory"], "original leaf/directory identity or policy differs")
    for mode, identifier, service in (("app", args.app_container_id, "serverware"), ("gate", args.gate_container_id, "decision-gate-rs")):
        base.require(inspect(identifier, service, config) == identities[mode], "runtime changed while observed")
    result = {"ok": True, "schema": "serverware.privateCuratedGateObservation/v1", "phase": "after" if args.before_receipt else "before",
        "preparation_sha256": args.expected_preparation_sha256, "binary_sha256": prep["binarySha256"], "containers": identities,
        "shared_leaves": gate["leaves"], "policy": gate["policy"], "gate_executable": gate["actual_executable"], "export_directory": gate["export_directory"],
        "gate_mountinfo": gate["mountinfo"], "app_private_files_present": sorted(app["private_files"]),
        "gate_private_files_absent": sorted(gate["private_files"]), "source_files_verified": len(sources),
        "productionReady": False, "realProviderVerified": False, "isolatedFixtureOnly": True}
    if args.before_receipt:
        result.update(verify_transition(document(args.before_receipt), result, document(args.client_receipt)))
        result["before_receipt_sha256"] = base.digest(args.before_receipt)
        result["client_receipt_sha256"] = base.digest(args.client_receipt)
    return result


def main():
    global DEADLINE
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("job-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("app-container-id", "gate-container-id", "expected-preparation-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("before-receipt", "client-receipt"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args(); DEADLINE = time.monotonic() + 90
    def expired(*_): raise TimeoutError("bounded")
    signal.signal(signal.SIGALRM, expired); signal.alarm(90)
    try:
        base.require(args.output.is_absolute() and args.output.parent.resolve() == args.output.parent and not args.output.exists(), "fresh evidence output required")
        result = run(args)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(result, stream, sort_keys=True, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        print(json.dumps(result, sort_keys=True))
    except Exception:
        raise SystemExit("Curated fixture observation refused; no private data or raw errors emitted") from None
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()

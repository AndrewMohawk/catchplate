#!/usr/bin/env python3
"""Fixed isolated keeper and read-only probes for the retained rehearsal.

No Docker, Git, HTTP mutations, provider or proxy requests. Root owns namespace
creation, app-first/gate-second startup, inspect receipts, cold stops, archive
comparison and cleanup. `emit-probe` emits the existing managed/curated oracle
for root to pass on stdin to the exact app/gate container (python -I -B -).
An observation alone is NOT preservation or rollout acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import threading

from scripts import prepare_operator_managed_retained_fixture as recipe
from scripts import check_operator_managed_google_gate_mounts as managed


# Also included verbatim in the stdin oracle: stdlib only, no source/app import
# inside the gate. No external address or resolver is contacted.
NETWORK_PROBE = r'''
def retained_network():
    import socket
    need({name for _, name in socket.if_nameindex()} == {"lo"})
    need(Path("/etc/hosts").read_bytes() == HOSTS and Path("/etc/resolv.conf").read_bytes() == RESOLV)
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    need(all(len(row.split()) >= 8 and row.split()[0] == "lo" and row.split()[1] != "00000000" for row in routes))
    need(all(row.split()[-1] == "lo" for row in Path("/proc/net/ipv6_route").read_text().splitlines() if row.strip()))
    need(Path("/proc/sys/net/ipv4/ip_nonlocal_bind").read_text().strip() == "0")
    for address in ADDRESSES:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((address, 0))
    # fib_trie contains both main/local views; sets remove that duplication.
    addresses, previous = set(), ""
    for line in Path("/proc/net/fib_trie").read_text().splitlines():
        if "/32 host LOCAL" in line:
            addresses.add(previous.split()[-1])
        previous = line
    need(addresses == {"127.0.0.1", *ADDRESSES})
    for host, address in zip(("demo-upstream", "serverware", "decision-gate-rs"), ADDRESSES):
        need({row[4][0] for row in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)} == {address})
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    need(os.geteuid() == os.getegid() == 10001 and status["NoNewPrivs"].strip() == "1"
        and all(int(status[key].strip(), 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb")))
    return {"namespace": os.readlink("/proc/self/ns/net"), "interfaces": ["lo"],
        "ipv4_local_addresses": sorted(addresses), "default_route": False, "effective_capabilities": 0}
'''


READINESS_PROBE = r'''
def retained_readiness(policy, identity_value):
    import urllib.request
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            raise ValueError("redirect refused")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def get(url, token=None):
        headers = {"Accept": "application/json"}
        if token is not None:
            headers.update(Authorization="Bearer " + token, Origin="https://serverware-demo.example.com")
        with opener.open(urllib.request.Request(url, headers=headers, method="GET"), timeout=3) as response:
            need(response.status == 200 and response.geturl() == url)
            raw = response.read(2097153)
            need(len(raw) <= 2097152 and (token is None or token.encode() not in raw))
            return json.loads(raw)
    health = get("http://172.16.249.20:9091/healthz")
    shadow = health.get("policy_shadow", {})
    need(health.get("ok") is True and health.get("policy_shadow_serving_ready") is True
        and health.get("data_plane_binary_digest") == "sha256:" + expected_binary
        and health.get("policy_hash") == policy["policy_hash"] == shadow.get("operator_policy_sha256")
        and shadow.get("managed_google") == identity_value and shadow.get("mode") == "operator-demo"
        and shadow.get("enabled") is False and shadow.get("readiness") is False
        and shadow.get("production_custody_bound") is False
        and health.get("policy_trust_root_source") == "attested-control-plane"
        and bool(health.get("policy_signing_key_id")) and health.get("connect_mitm_interceptor") is True
        and health.get("audit", {}).get("enabled") is True
        and health.get("release_authorization", {}).get("enabled") is False)
    result = {"actual_gate_ready": True, "binary_digest": health["data_plane_binary_digest"],
        "managed_google": identity_value, "policy_hash": policy["policy_hash"]}
    if mode == "app":
        need(os.environ.get("SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED") == "1"
            and os.environ.get("SERVERWARE_OPERATOR_NOTIFICATIONS_PRIVATE_DESTINATIONS_JSON") == '{"bindings":[]}'
            and os.environ.get("SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR") == "/notification-custody")
        directory("/notification-custody"); need(not os.listdir("/notification-custody"))
        path = "/run/secrets/serverware/admin.token"
        before = identity(path); need(before["mode"] == 0o400 and before["size"] == 64)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(descriptor)
            need((opened.st_dev, opened.st_ino) == (before["device"], before["inode"]))
            token = os.read(descriptor, 4097).decode("ascii").strip()
        finally: os.close(descriptor)
        need(identity(path) == before and token and "\n" not in token and "\r" not in token)
        catalog = get("http://172.16.249.19:3000/api/operator-demo/catalog", token)
        need(catalog.get("schema") == "serverware.operatorCatalog/v1" and catalog.get("mode") == "operator-development"
            and catalog.get("productionReady") is False and catalog.get("hardwareVerified") is False
            and catalog.get("allowed_upstreams") == expected_manifest["effective_settings"]["allowed_upstreams"]
            and catalog.get("capabilities", {}).get("google_oauth") is None
            and type(catalog.get("revision")) is int and catalog["revision"] >= 1)
        retained = catalog.get("policy", {})
        need(retained.get("activation") == "active" and retained.get("loaded_policy_hash")
            == retained.get("policy_hash") == policy["policy_hash"] and retained.get("sequence") == policy["sequence"])
        notifications = get("http://172.16.249.19:3000/api/operator-demo/notifications", token)
        slots = notifications.get("slots", [])
        need(notifications.get("available") is True and len(slots) == 4
            and {row.get("slot") for row in slots} == {"action_required.slack", "action_required.webhook", "audit_log.slack", "audit_log.webhook"}
            and all(type(row.get("revision")) is int and row["revision"] == 0 and row.get("enabled") is False
                and row.get("secret_present") is False and row.get("last_delivery") is None for row in slots)
            and notifications.get("cursor") is None and notifications.get("queue")
            and all(type(value) is int and value == 0 for value in notifications["queue"].values())
            and notifications.get("capabilities", {}).get("native_hardware", {}).get("configured") is False
            and notifications.get("worker", {}).get("state") == "running"
            and type(notifications["worker"].get("last_cycle_at_epoch_ms")) is int)
        result.update(catalog_revision=catalog["revision"], catalog_resources={key: len(catalog[key])
            for key in ("credentials", "applications", "access_rules")}, notifications_unconfigured_running=True)
        chain = get("http://172.16.249.19:3000/api/audit/verify?limit=1000", token)
        need(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite")
        result["audit_chain_verified"] = True
        need(not os.listdir("/notification-custody") and not os.listdir("/provider-custody"))
    return result
'''


def emit_probe(mode, binary_sha256):
    recipe.base.require(mode in {"app", "gate"}, "closed mode required")
    recipe.base.validated_binary_sha256(binary_sha256)
    source = managed.probe_source()
    edits = (
        ("mode, expected_binary, expected_manifest_json = sys.argv[1:]\nexpected_manifest = json.loads(expected_manifest_json)",
         "mode = " + repr(mode) + "\nexpected_binary = " + repr(binary_sha256) + "\nexpected_manifest = " + repr(recipe.manifest())),
        ('try:\n    directory("/data")',
         "HOSTS = " + repr(recipe.HOSTS) + "\nRESOLV = " + repr(recipe.RESOLV) + "\nADDRESSES = " + repr(recipe.ADDRESSES)
         + "\n" + NETWORK_PROBE + READINESS_PROBE + '\ntry:\n    network_observation = retained_network()\n    directory("/data")'),
        ('    print(json.dumps(result, sort_keys=True))',
         '    result["network"] = network_observation\n'
         '    result["readiness"] = retained_readiness(result["policy"], result["managed"]["identity"])\n'
         '    result["schema"] = "serverware.managedRetainedRuntimeObservation/v1"\n'
         '    result["mode"] = mode\n'
         '    result["preservation_claimed"] = False\n'
         '    print(json.dumps(result, sort_keys=True))'),
    )
    for old, new in edits:
        recipe.base.require(source.count(old) == 1, "managed probe anchor changed")
        source = source.replace(old, new)
    return source


def keeper():
    need = lambda value: recipe.base.require(value, "retained namespace refused")
    need(os.geteuid() == 0 and {name for _, name in socket.if_nameindex()} == {"lo"})
    # Same reviewed NETLINK operation as the npm fixture, now exactly the three
    # retained private /32s. It cannot modify host or live Docker networking.
    for sequence, address in enumerate(recipe.ADDRESSES, 1):
        payload = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, socket.if_nametoindex("lo"))
        packed = socket.inet_aton(address)
        payload += struct.pack("=HH4s", 8, 1, packed) + struct.pack("=HH4s", 8, 2, packed)
        packet = struct.pack("=IHHII", 16 + len(payload), 20, 1 | 4 | 0x400 | 0x200, sequence, 0) + payload
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
            channel.settimeout(3); channel.bind((0, 0)); channel.sendto(packet, (0, 0)); response = channel.recv(4096)
        need(len(response) >= 20)
        length, kind, _, observed, _ = struct.unpack_from("=IHHII", response)
        need(length == len(response) and kind == 2 and observed == sequence and struct.unpack_from("=i", response, 16)[0] == 0)
    os.setgroups([]); os.setgid(10001); os.setuid(10001)
    scope = {"need": need, "os": os, "Path": Path, "HOSTS": recipe.HOSTS,
        "RESOLV": recipe.RESOLV, "ADDRESSES": recipe.ADDRESSES}
    exec(compile(NETWORK_PROBE, "<retained-network-probe>", "exec"), scope)
    observation = scope["retained_network"]()
    descriptor = os.open("/tmp/retained-network-ready", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(b"1"); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({"ok": True, **observation, "lifetime_seconds": recipe.KEEPER_SECONDS}), flush=True)
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    stop.wait(recipe.KEEPER_SECONDS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("network")
    probe = commands.add_parser("emit-probe")
    probe.add_argument("--mode", choices=("app", "gate"), required=True)
    probe.add_argument("--expected-binary-sha256", type=recipe.base.validated_binary_sha256, required=True)
    args = parser.parse_args(); os.umask(0o077)
    try:
        if args.command == "network":
            keeper()
        else:
            print(emit_probe(args.mode, args.expected_binary_sha256), end="")
    except Exception:
        raise SystemExit("Managed retained rehearsal observation refused; no private values emitted") from None


if __name__ == "__main__":
    main()

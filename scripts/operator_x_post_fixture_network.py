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
import ssl
import struct
import threading

from scripts import operator_github_fixture_network as isolated

FIXTURE_IP, LOOPBACK, PROXY_HOST = isolated.FIXTURE_IP, isolated.LOOPBACK, isolated.PROXY_HOST
CONTROL_HOST = "serverware-x.example.com"
CONTROL_ORIGIN = "https://" + CONTROL_HOST
PROVIDER_HOSTS = ("x.com", "api.x.com")
KEEPER_SECONDS, EDGE_SECONDS = 300, 240
ROOT, NETWORK_ROOT = Path("/fixture-runtime"), Path("/fixture-network")
HOSTS = ("127.0.0.1 localhost serverware decision-gate-rs " + PROXY_HOST + " " + CONTROL_HOST
    + "\n" + FIXTURE_IP + " " + " ".join(PROVIDER_HOSTS) + "\n").encode("ascii")
RESOLV = isolated.RESOLV


def require(condition):
    if not condition:
        raise ValueError("isolated managed X namespace refused")


def assert_isolated_network(*, attached=True):
    isolated.assert_isolated_network(attached=False)
    if attached:
        require(Path("/etc/hosts").read_bytes() == HOSTS and Path("/etc/resolv.conf").read_bytes() == RESOLV)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((FIXTURE_IP, 0))
        for host, address in [(host, FIXTURE_IP) for host in PROVIDER_HOSTS] + [
                (host, LOOPBACK) for host in (CONTROL_HOST, PROXY_HOST, "serverware", "decision-gate-rs")]:
            require({item[4][0] for item in socket.getaddrinfo(host, 443, socket.AF_INET,
                socket.SOCK_STREAM)} == {address})


def _write(path, raw, mode=0o400):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw); output.flush(); os.fchmod(output.fileno(), mode); os.fsync(output.fileno())


def prepare_network_files():
    root = Path("/upstream-data/x-network")
    require(os.geteuid() == 10001 and not root.exists() and not root.is_symlink())
    assert_isolated_network(attached=False)
    root.mkdir(mode=0o700)
    for name, raw in (("hosts", HOSTS), ("resolv.conf", RESOLV)):
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
    _write(NETWORK_ROOT / "ready", json.dumps({"schema": "serverware.xPostFixtureNetwork/v1",
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
    parser.add_argument("operation", choices=("initialize", "network", "edge"))
    operation = parser.parse_args().operation
    os.umask(0o077)
    if operation == "initialize":
        signal.alarm(30); initialize()
    elif operation == "network":
        keep_namespace()
    else:
        edge()


if __name__ == "__main__":
    main()

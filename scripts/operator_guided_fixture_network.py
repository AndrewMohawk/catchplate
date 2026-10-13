"""Fixed loopback-only fixture plumbing; no host routes or provider access.

The ordinary demo upstream and TLS relay are unchanged. Only namespace files,
the existing supported proxy certificate name and finite lifetimes are selected.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import threading

from scripts.operator_github_fixture_network import assert_isolated_network as base_isolation

CONTROL_HOST = "serverware-guided.example.com"
PROXY_HOST = "serverware-gmail-proxy.example.com"
UPSTREAM_HOST, UPSTREAM_IP, LOOPBACK = "demo-upstream", "127.0.0.2", "127.0.0.1"
KEEPER_SECONDS, EDGE_SECONDS = 300, 240
HOSTS = ("127.0.0.1 localhost serverware decision-gate-rs " + CONTROL_HOST + " " + PROXY_HOST + "\n"
    + UPSTREAM_IP + " " + UPSTREAM_HOST + "\n").encode("ascii")
RESOLV = b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n"


def require(condition):
    if not condition:
        raise ValueError("private guided namespace refused")


def assert_isolated_network(*, attached=True):
    base_isolation(attached=False)
    if attached:
        require(Path("/etc/hosts").read_bytes() == HOSTS and Path("/etc/resolv.conf").read_bytes() == RESOLV)
        for name, expected in [(UPSTREAM_HOST, UPSTREAM_IP)] + [(name, LOOPBACK) for name in
                ("serverware", "decision-gate-rs", CONTROL_HOST, PROXY_HOST)]:
            require({row[4][0] for row in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)} == {expected})
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((UPSTREAM_IP, 0))


def write_once(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw); stream.flush(); os.fchmod(stream.fileno(), 0o400); os.fsync(stream.fileno())


def prepare_files():
    require(os.geteuid() == os.getegid() == 10001)
    assert_isolated_network(attached=False)
    root = Path("/upstream-data/guided-network")
    require(not root.exists() and not root.is_symlink())
    root.mkdir(mode=0o700)
    for name, raw in (("hosts", HOSTS), ("resolv.conf", RESOLV)):
        write_once(root / name, raw)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def keep_namespace():
    require(os.geteuid() == os.getegid() == 10001)
    assert_isolated_network()
    require(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text().strip() == "0")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(all(int(status[key].strip(), 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
        and status["NoNewPrivs"].strip() == "1")
    write_once(Path("/fixture-network/ready"), json.dumps({"schema": "serverware.guidedFixtureNetwork/v1",
        "network": "none", "interfaces": ["lo"], "effectiveCapabilities": 0}, sort_keys=True).encode("ascii"))
    stopped = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stopped.set())
    stopped.wait(KEEPER_SECONDS)


def edge():
    from scripts.operator_proxy_basic_tls import Server
    require(os.geteuid() == os.getegid() == 10001)
    assert_isolated_network()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain("/edge/cert.pem", "/edge/key.pem")
    stopped = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stopped.set())
    with Server(LOOPBACK, LOOPBACK, context, EDGE_SECONDS, port=443) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            print('{"ready":true,"syntheticOnly":true,"headerRewriting":false}', flush=True)
            stopped.wait(EDGE_SECONDS)
        finally:
            server.shutdown(); worker.join(timeout=4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("files", "network", "edge", "pki"))
    selected = parser.parse_args().operation
    os.umask(0o077)
    if selected in {"files", "pki"}:
        signal.alarm(30)
    if selected == "pki":
        from scripts.operator_proxy_basic_fixture_setup import prepare
        prepare(proxy_hostname=PROXY_HOST)
    else:
        {"files": prepare_files, "network": keep_namespace, "edge": edge}[selected]()


if __name__ == "__main__":
    main()

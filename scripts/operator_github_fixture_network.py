"""Fixed loopback-only namespace and HTTPS edge for the synthetic GitHub job.

The public-looking /32 exists ONLY on lo in a new network-none namespace.
There is no host address/route change, bridge, external interface or default
route. No production resolver, destination guard, TLS or credential code changes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import threading

FIXTURE_IP = "93.184.216.34"
LOOPBACK = "127.0.0.1"
PROXY_HOST = "proxy.operator-basic.example.test"
HOSTS = ("127.0.0.1 localhost catchplate decision-gate-rs " + PROXY_HOST + "\n"
         + FIXTURE_IP + " api.github.com\n").encode("ascii")
RESOLV = b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n"
NETWORK_ROOT = Path("/fixture-network")
KEEPER_SECONDS, EDGE_SECONDS = 300, 240


def require(condition):
    if not condition:
        raise ValueError("isolated GitHub namespace refused")


def assert_isolated_network(*, attached=True):
    require({name for _, name in socket.if_nameindex()} == {"lo"})
    routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    require(all(len(row.split()) >= 8 and row.split()[0] == "lo"
                and row.split()[1] != "00000000" for row in routes))
    ipv6 = Path("/proc/net/ipv6_route").read_text(encoding="ascii").splitlines()
    require(all(row.split()[-1] == "lo" for row in ipv6 if row.strip()))
    require(Path("/proc/sys/net/ipv4/ip_nonlocal_bind").read_text().strip() == "0")
    if attached:
        require(Path("/etc/hosts").read_bytes() == HOSTS
                and Path("/etc/resolv.conf").read_bytes() == RESOLV)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((FIXTURE_IP, 0))
        for hostname, expected in (("api.github.com", FIXTURE_IP), (PROXY_HOST, LOOPBACK),
                                   ("catchplate", LOOPBACK), ("decision-gate-rs", LOOPBACK)):
            require({item[4][0] for item in socket.getaddrinfo(
                hostname, 443, socket.AF_INET, socket.SOCK_STREAM)} == {expected})


def prepare_network_files():
    """Called only by the offline GitHub PKI phase, below existing upstream-data."""
    root = Path("/upstream-data/github-network")
    require(os.geteuid() == 10001 and not root.exists() and not root.is_symlink())
    assert_isolated_network(attached=False)
    root.mkdir(mode=0o700)
    for name, raw in (("hosts", HOSTS), ("resolv.conf", RESOLV)):
        descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())


def keep_namespace():
    require(os.geteuid() == 0)
    assert_isolated_network(attached=False)
    require(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text().strip() == "0")
    index = socket.if_nametoindex("lo")
    address = socket.inet_aton(FIXTURE_IP)
    payload = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, index)
    payload += struct.pack("=HH4s", 8, 1, address) + struct.pack("=HH4s", 8, 2, address)
    # One exclusive RTM_NEWADDR, identical mechanism to the isolated Google job.
    packet = struct.pack("=IHHII", 16 + len(payload), 20, 1 | 4 | 0x400 | 0x200, 1, 0) + payload
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(3)
        channel.bind((0, 0))
        channel.sendto(packet, (0, 0))
        response = channel.recv(4096)
    require(len(response) >= 20)
    length, kind, _, sequence, _ = struct.unpack_from("=IHHII", response)
    require(length == len(response) and kind == 2 and sequence == 1
            and struct.unpack_from("=i", response, 16)[0] == 0)
    os.setgroups([])
    os.setgid(10001)
    os.setuid(10001)
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(all(int(status[name].strip(), 16) == 0 for name in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
            and status["NoNewPrivs"].strip() == "1")
    assert_isolated_network()
    ready = NETWORK_ROOT / "ready"
    descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "w", encoding="ascii") as output:
        json.dump({"schema": "catchplate.githubFixtureNetwork/v1", "network": "none",
            "interfaces": ["lo"], "address": FIXTURE_IP, "effectiveCapabilities": 0}, output)
        output.flush()
        os.fsync(output.fileno())
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    stop.wait(KEEPER_SECONDS)


def edge():
    # Dedicated fixed loopback entrypoint; old Basic private_pair stays unchanged.
    from scripts.operator_proxy_basic_tls import Server

    require(os.geteuid() == 10001)
    assert_isolated_network()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain("/edge/cert.pem", "/edge/key.pem")
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    with Server(LOOPBACK, LOOPBACK, context, EDGE_SECONDS) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            print('{"ready":true,"syntheticOnly":true,"headerRewriting":false}', flush=True)
            stop.wait(EDGE_SECONDS)
        finally:
            server.shutdown()
            worker.join(timeout=4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("network", "edge"))
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "network":
        keep_namespace()
    else:
        edge()


if __name__ == "__main__":
    main()

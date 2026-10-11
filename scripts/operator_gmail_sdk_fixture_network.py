"""Closed Gmail SDK fixture glue; no host networking or provider configuration.

Google's existing initializer and 300-second loopback keeper are unchanged.
The additional PKI root contains no application data or credentials: it is the
empty scaffold required by the existing, unchanged Basic-proxy PKI producer.
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

from scripts import operator_google_fixture_setup as google
from scripts.operator_google_fixture import assert_isolated_network, require
from scripts.operator_proxy_basic_tls import PROXY_HOST, Server

KEEPER_SECONDS = 300
EDGE_SECONDS = 240
ROOT = Path("/fixture-runtime")
HOSTS = Path("/etc/hosts")


def initialize():
    google.initialize()
    # Do not alter Google's original hosts file, marker, or private state.
    original = (ROOT / "fixture-hosts").read_bytes()
    require(original.startswith(b"127.0.0.1 localhost serverware decision-gate-rs "))
    first, rest = original.split(b"\n", 1)
    google._write(ROOT / "gmail-sdk-hosts", first + b" " + PROXY_HOST.encode("ascii") + b"\n" + rest, 0o444)
    scaffold = ROOT / "https-proxy"
    scaffold.mkdir(mode=0o700)
    os.chown(scaffold, 10001, 10001)
    for name in ("app-data", "gate-data", "upstream-data", "service-secrets"):
        (scaffold / name).mkdir(mode=0o700)
        os.chown(scaffold / name, 10001, 10001)
    marker = {"schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True}
    google._write(scaffold / ".private-fixture.json", (json.dumps(marker, sort_keys=True) + "\n").encode("ascii"))
    for directory in (scaffold, ROOT):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def edge():
    require(os.geteuid() == os.getegid() == 10001)
    assert_isolated_network()
    require({row[4][0] for row in socket.getaddrinfo(PROXY_HOST, 8443, socket.AF_INET,
        socket.SOCK_STREAM)} == {"127.0.0.1"})
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain("/edge/cert.pem", "/edge/key.pem")
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    with Server("127.0.0.1", "127.0.0.1", context, EDGE_SECONDS) as server:
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
    parser.add_argument("operation", choices=("initialize", "edge"))
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "initialize":
        signal.alarm(30)
        initialize()
    else:
        edge()


if __name__ == "__main__":
    main()

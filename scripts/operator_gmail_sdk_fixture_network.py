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
BROWSER_PROXY_HOST = "catchplate-gmail-proxy.example.com"
BROWSER_PROXY_ADDRESS = "127.0.0.2"
BROWSER_PROXY_URL = "https://" + BROWSER_PROXY_HOST


def hosts_bytes(original, *, browser_permission=False):
    require(type(browser_permission) is bool)
    require(original.startswith(b"127.0.0.1 localhost catchplate decision-gate-rs "))
    first, rest = original.split(b"\n", 1)
    if browser_permission:
        # The control front already owns 127.0.0.1:443. This independent
        # loopback address serves only the copied browser recipe's proxy URL.
        return original + (BROWSER_PROXY_ADDRESS + " " + BROWSER_PROXY_HOST + "\n").encode("ascii")
    return first + b" " + PROXY_HOST.encode("ascii") + b"\n" + rest


def initialize(*, browser_permission=False):
    require(type(browser_permission) is bool)
    google.initialize()
    # Do not alter Google's original hosts file, marker, or private state.
    original = (ROOT / "fixture-hosts").read_bytes()
    google._write(ROOT / "gmail-sdk-hosts", hosts_bytes(original, browser_permission=browser_permission), 0o444)
    scaffold = ROOT / "https-proxy"
    scaffold.mkdir(mode=0o700)
    os.chown(scaffold, 10001, 10001)
    for name in ("app-data", "gate-data", "upstream-data", "service-secrets"):
        (scaffold / name).mkdir(mode=0o700)
        os.chown(scaffold / name, 10001, 10001)
    marker = {"schema": "catchplate.privateOperatorAuditFixture/v1", "syntheticOnly": True}
    google._write(scaffold / ".private-fixture.json", (json.dumps(marker, sort_keys=True) + "\n").encode("ascii"))
    for directory in (scaffold, ROOT):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def edge(*, browser_permission=False):
    require(type(browser_permission) is bool)
    require(os.geteuid() == os.getegid() == 10001)
    assert_isolated_network()
    host, address, port = (BROWSER_PROXY_HOST, BROWSER_PROXY_ADDRESS, 443) if browser_permission else (PROXY_HOST, "127.0.0.1", 8443)
    require({row[4][0] for row in socket.getaddrinfo(host, port, socket.AF_INET,
        socket.SOCK_STREAM)} == {address})
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain("/edge/cert.pem", "/edge/key.pem")
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    with Server(address, "127.0.0.1", context, EDGE_SECONDS, port=port) as server:
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
    parser.add_argument("operation", choices=("initialize", "edge", "browser-initialize", "browser-edge"))
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation in {"initialize", "browser-initialize"}:
        signal.alarm(30)
        initialize(browser_permission=args.operation == "browser-initialize")
    else:
        edge(browser_permission=args.operation == "browser-edge")


if __name__ == "__main__":
    main()

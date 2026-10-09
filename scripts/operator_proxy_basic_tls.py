#!/usr/bin/env python3
"""Finite private TLS terminator: unchanged bytes to one normal Rust gate.

No HTTP parser, authentication, header rewriting, DNS, certificate generation,
container control or public listener. The executor supplies throwaway PKI and
an isolated network. This is an HTTPS edge fixture, not a production gateway.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import select
import signal
import socket
import socketserver
import ssl
import threading
import time

PROXY_HOST = "proxy.operator-basic.example.test"
PROXY_PORT = 8443
GATE_PORT = 9090
MAX_CONNECTIONS = 32
MAX_CONNECTION_BYTES = 262144
CONNECTION_SECONDS = 15


def private_pair(listen, gate):
    left, right = ipaddress.IPv4Address(listen), ipaddress.IPv4Address(gate)
    network = ipaddress.ip_network(str(left) + "/28", strict=False)
    if (left == right or not network.subnet_of(ipaddress.ip_network("172.16.0.0/12"))
            or right not in network or left in {network.network_address, network.broadcast_address}
            or right in {network.network_address, network.broadcast_address}):
        raise ValueError("distinct addresses in one private fixture /28 required")
    return str(left), str(right)


class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        deadline = min(self.server.deadline, time.monotonic() + CONNECTION_SECONDS)
        remaining = MAX_CONNECTION_BYTES
        try:
            with socket.create_connection((self.server.gate, GATE_PORT), timeout=3) as gate:
                peers = {self.request: gate, gate: self.request}
                while remaining:
                    timeout = min(3, deadline - time.monotonic())
                    if timeout <= 0:
                        return
                    ready = ([self.request] if self.request.pending()
                             else select.select(list(peers), [], [], timeout)[0])
                    for source in ready:
                        source.settimeout(timeout)
                        data = source.recv(min(16384, remaining))
                        if not data:
                            return
                        remaining -= len(data)
                        peers[source].settimeout(timeout)
                        peers[source].sendall(data)
        except (OSError, ssl.SSLError):
            # A negative certificate/authentication case may close either end.
            # Never log bytes, TLS exceptions, HTTP fields or client secrets.
            return


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, listen, gate, context, lifetime):
        self.gate, self.context = gate, context
        self.deadline = time.monotonic() + lifetime
        self.slots = threading.BoundedSemaphore(8)
        self.accepted = 0
        super().__init__((listen, PROXY_PORT), Relay)

    def get_request(self):
        raw, peer = super().get_request()
        self.accepted += 1
        if self.accepted > MAX_CONNECTIONS or time.monotonic() >= self.deadline:
            raw.close()
            raise OSError("private relay connection budget exhausted")
        raw.settimeout(3)
        try:
            return self.context.wrap_socket(raw, server_side=True), peer
        except BaseException:
            raw.close()
            raise

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # No default traceback containing transport inputs.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-address", required=True)
    parser.add_argument("--gate-address", required=True)
    parser.add_argument("--cert-file", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--lifetime-seconds", type=int, default=240)
    args = parser.parse_args()
    if not 30 <= args.lifetime_seconds <= 300:
        raise ValueError("private relay lifetime must be 30..300 seconds")
    listen, gate = private_pair(args.listen_address, args.gate_address)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(args.cert_file, args.key_file)
    stopped = threading.Event()
    for name in (signal.SIGINT, signal.SIGTERM):
        signal.signal(name, lambda *_: stopped.set())
    with Server(listen, gate, context, args.lifetime_seconds) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            print(json.dumps({"ready": True, "syntheticOnly": True, "hostname": PROXY_HOST,
                "port": PROXY_PORT, "fixedGatePort": GATE_PORT, "headerRewriting": False}), flush=True)
            stopped.wait(args.lifetime_seconds)
        finally:
            server.shutdown()
            worker.join(timeout=4)


if __name__ == "__main__":
    main()

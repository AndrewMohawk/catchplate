#!/usr/bin/env python3
"""Finite actual-nginx relay exercise; no Docker authority or live endpoints.

1. --render-config emits the actual stream block with ONLY listener, backend and
   allowed-peer addresses mapped to loopback. Console HTTP is not exercised.
2. --exercise runs in a fresh network-none Python container with writable empty
   /results. After backend-ready.json, start pinned nginx sharing its namespace.
3. After ready-to-stop.json, the external owner stops that exact nginx container.
   The worker requires held-connection closure, new-connection refusal and a live
   backend. Join its result with the owner's exact-ID stop/cleanup receipt.

No TLS or real gate/Traefik/provider acceptance is claimed. Both configurations'
timeouts stay unchanged. Only this test worker has a 90s absolute lifetime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import sys
import threading
import time

EDGE = ('127.0.0.1', 19090)
BACKEND = ('127.0.0.1', 19091)
READY = b'relay-ready\n'
OPAQUE = (b'CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n'
          b'Proxy-Authorization: Bearer synthetic-relay-canary\r\n\r\n'
          + bytes(range(256)) * 4)
RESPONSE = b'HTTP/1.1 200 Connection Established\r\n\r\n' + bytes(reversed(range(256))) * 3
PAYLOADS = (READY, OPAQUE, b'drop-once\n', b'hold-open\n', b'backend-still-alive\n')
REPLIES = (b'ready\n', RESPONSE, b'', b'holding\n', b'alive\n')


def require(condition):
    if not condition:
        raise RuntimeError('isolated relay assertion failed')


def render_config():
    root = Path(__file__).resolve().parents[1]
    template = (root / 'docker/catchplate-operator-demo/config/nginx.conf.template').read_text()
    blocks = re.findall(r'(?ms)^stream \{\n.*?^\}', template)
    require(len(blocks) == 1)
    block = blocks[0]
    for old, new in (('listen 9090;', 'listen 127.0.0.1:19090;'),
                     ('allow ${TRAEFIK_IPV4}/32;', 'allow 127.0.0.1/32;'),
                     ('proxy_pass 172.16.249.20:9090;', 'proxy_pass 127.0.0.1:19091;')):
        require(block.count(old) == 1)
        block = block.replace(old, new)
    require('proxy_half_close on;' in block and 'proxy_timeout 10m;' in block)
    return 'worker_processes 1;\npid /tmp/nginx.pid;\nerror_log /dev/null;\nevents { worker_connections 128; }\n' + block + '\n'


def network_boundary():
    require({entry.name for entry in Path('/sys/class/net').iterdir()} == {'lo'})
    require(all(row.split()[0] == 'lo' for row in Path('/proc/net/route').read_text().splitlines()[1:]))
    require(all(row.split()[-1] == 'lo' for row in Path('/proc/net/ipv6_route').read_text().splitlines()))

    def guard(event, args):
        if event in {'socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostbyaddr'}:
            raise RuntimeError('DNS unavailable in relay exercise')
        if event == 'socket.__new__':
            require(args[1] == socket.AF_INET and args[2] == socket.SOCK_STREAM)
        if event == 'socket.connect':
            require(args[1] in (EDGE, BACKEND))
        if event == 'socket.bind':
            require(args[1] in (BACKEND, ('127.0.0.1', 0), ('127.0.0.2', 0)))
    sys.addaudithook(guard)


def write_new(root, name, document):
    raw = json.dumps(document, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())


def read_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        require(part)
        result.extend(part)
    return bytes(result)


class Backend(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self):
        self.rows, self.lock = [], threading.Lock()
        super().__init__(BACKEND, Handler)

    def process_request(self, request, client_address):
        with self.lock:
            require(len(self.rows) < 8)
            ordinal = len(self.rows)
            self.rows.append({'ordinal': ordinal, 'done': False, 'ok': False})
        thread = threading.Thread(target=self.perform, args=(request, ordinal), daemon=True)
        thread.start()

    def perform(self, connection, ordinal):
        try:
            connection.settimeout(65 if ordinal == 3 else 5)
            require(ordinal < len(PAYLOADS))
            payload = read_exact(connection, len(PAYLOADS[ordinal]))
            require(payload == PAYLOADS[ordinal])
            if ordinal == 1:
                # A response is intentionally withheld until client write EOF.
                require(connection.recv(1) == b'')
            if REPLIES[ordinal]:
                connection.sendall(REPLIES[ordinal])
            if ordinal == 3:
                require(connection.recv(1) == b'')
            with self.lock:
                self.rows[ordinal].update(ok=True, bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest())
        except Exception:
            pass  # Never print transport data or parser exception contents.
        finally:
            self.shutdown_request(connection)
            with self.lock:
                self.rows[ordinal]['done'] = True

    def handle_error(self, *_):
        pass

    def snapshot(self):
        with self.lock:
            return [dict(row) for row in self.rows]


class Handler(socketserver.BaseRequestHandler):
    pass  # Backend owns a bounded thread per connection instead of dispatching.


def connect(address=EDGE, source='127.0.0.1'):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.settimeout(5)
        connection.bind((source, 0))
        connection.connect(address)
        return connection
    except BaseException:
        connection.close()
        raise


def eof(connection):
    try:
        require(connection.recv(1) == b'')
    except ConnectionResetError:
        pass


def complete(backend, count):
    end = time.monotonic() + 2
    while True:
        rows = backend.snapshot()
        require(len(rows) <= count)
        if len(rows) == count and all(row['done'] for row in rows):
            require(all(row['ok'] for row in rows))
            return rows
        require(time.monotonic() < end)
        time.sleep(0.01)


def exercise(results):
    require(results == Path('/results') and not results.is_symlink() and results.is_dir()
        and not list(results.iterdir()))
    network_boundary()
    phase = 'start'
    try:
        with Backend() as backend:
            worker = threading.Thread(target=backend.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
            worker.start()
            try:
                write_new(results, 'backend-ready.json', {'ready': True, 'syntheticOnly': True})
                phase = 'nginx-start'
                end = time.monotonic() + 20
                while True:
                    try:
                        connection = connect()
                        break
                    except ConnectionRefusedError:
                        require(time.monotonic() < end)
                        time.sleep(0.05)
                with connection:
                    connection.sendall(READY)
                    require(read_exact(connection, len(REPLIES[0])) == REPLIES[0]); eof(connection)
                complete(backend, 1)
                phase = 'opaque-half-close'
                with connect() as connection:
                    for offset in range(0, len(OPAQUE), 37):
                        connection.sendall(OPAQUE[offset:offset + 37])
                    connection.shutdown(socket.SHUT_WR)
                    require(read_exact(connection, len(RESPONSE)) == RESPONSE); eof(connection)
                complete(backend, 2)
                phase = 'denied-peer'
                with connect(source='127.0.0.2') as connection:
                    try:
                        connection.sendall(OPAQUE)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    eof(connection)
                require(len(backend.snapshot()) == 2)
                phase = 'no-replay'
                with connect() as connection:
                    connection.sendall(PAYLOADS[2]); eof(connection)
                complete(backend, 3)
                phase = 'wait-exact-nginx-stop'
                with connect() as connection:
                    connection.sendall(PAYLOADS[3])
                    require(read_exact(connection, len(REPLIES[3])) == REPLIES[3])
                    write_new(results, 'ready-to-stop.json', {'ready': True, 'heldConnection': True,
                        'completed': ['opaque-half-close', 'denied-peer', 'no-replay']})
                    connection.settimeout(60)
                    eof(connection)
                complete(backend, 4)
                phase = 'fenced-backend-alive'
                try:
                    with connect():
                        raise RuntimeError('edge still accepts connections')
                except ConnectionRefusedError:
                    pass
                with connect(BACKEND) as connection:
                    connection.sendall(PAYLOADS[4])
                    require(read_exact(connection, len(REPLIES[4])) == REPLIES[4]); eof(connection)
                rows = complete(backend, 5)
                result = {'schema': 'catchplate.proxyIngressRelayExercise/v1', 'ok': True,
                    'syntheticOnly': True, 'liveVerified': False, 'dockerStopProofRequired': True,
                    'opaqueBytesEqual': True, 'halfCloseResponseReceived': True,
                    'deniedPeerBackendConnections': 0, 'backendConnections': len(rows),
                    'noReplay': True, 'heldConnectionClosed': True, 'newConnectionRefused': True,
                    'backendAliveAfterFence': True, 'rows': rows}
            finally:
                backend.shutdown(); worker.join(timeout=2)
    except Exception:
        result = {'schema': 'catchplate.proxyIngressRelayExercise/v1', 'ok': False,
            'syntheticOnly': True, 'phase': phase, 'error': 'bounded relay exercise failed'}
    write_new(results, 'result.json', result)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['ok'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--render-config', action='store_true')
    group.add_argument('--exercise', action='store_true')
    parser.add_argument('--results', type=Path, default=Path('/results'))
    args = parser.parse_args()
    if args.render_config:
        print(render_config(), end='')
        return 0
    # SIGALRM uses its terminating default: even cleanup cannot extend the
    # original worker lifetime. The external owner must treat no receipt as fail.
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(90)
    return exercise(args.results)


if __name__ == '__main__':
    raise SystemExit(main())

"""Bounded internal relay to the real receiver; faults only audit ACK delivery.

The operator profile requires the canonical catchplate:3000 service name. This
fixture owns that name only in its separate internal Compose network and sends
three explicitly allowed operations to control-plane:3000. No signing key or
live state is mounted. The checker alone can arm/release the one-shot fault.
"""
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import socket
import threading
from urllib.parse import urlsplit

MAX_BODY = 2 * 1024 * 1024
AUDIT = '/api/data-plane/audit'
LEASE = '/api/data-plane/credential-leases'
INSTANCE = 'spiffe://operator-demo.catchplate/decision-gate/local'
SHA = re.compile(r'sha256:[0-9a-f]{64}\Z')
FORWARD_HEADERS = ('Content-Type', 'Accept', 'X-Catchplate-Data-Plane-Token',
                   'X-Catchplate-Response-Nonce')
HOP_HEADERS = frozenset(('connection', 'keep-alive', 'transfer-encoding', 'upgrade',
                         'proxy-authenticate', 'proxy-authorization', 'te', 'trailer'))
PROOF_HEADERS = ('x-catchplate-response-key-id', 'x-catchplate-response-statement-b64',
                 'x-catchplate-response-statement-sha256', 'x-catchplate-response-signature')


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def batch_identity(raw, nonce):
    value = json.loads(raw)
    events = value.get('events') if isinstance(value, dict) else None
    if not isinstance(events, list) or not 1 <= len(events) <= 200:
        raise ValueError('bounded audit batch required')
    ids = [event.get('eventId') for event in events if isinstance(event, dict)]
    if len(ids) != len(events) or any(not isinstance(v, str) or not SHA.fullmatch(v) for v in ids) or len(ids) != len(set(ids)):
        raise ValueError('canonical audit event IDs required')
    if not isinstance(nonce, str) or not 1 <= len(nonce) <= 256:
        raise ValueError('bounded response nonce required')
    return {'bodyDigest': digest(raw), 'eventIds': ids,
            'nonceDigest': digest(nonce.encode('ascii')),
            'requiredCredentialRelease': len(events) == 1 and
                events[0].get('eventType') == 'data_plane.credential.release_started'}


def real_ack(status, headers, body, identity):
    lowered = {key.lower(): value for key, value in headers}
    if status != 200 or not all(lowered.get(key) for key in PROOF_HEADERS):
        raise ValueError('real receiver signed success required before fault')
    value = json.loads(body)
    if value != {'apiVersion': 'catchplate.dataPlaneAuditAck/v1', 'ok': True,
        'accepted': len(identity['eventIds']), 'batchDigest': identity['bodyDigest'], 'instanceId': INSTANCE}:
        raise ValueError('real receiver ACK does not match exact original batch')


class FaultState:
    def __init__(self):
        self.lock = threading.Lock()
        self.armed = False
        self.released = False
        self.dropped = False
        self.original = None
        self.records = []
        self.required_records = []
        self.failure = None

    def control(self, action):
        with self.lock:
            if action == 'arm':
                if self.armed or self.records or self.failure:
                    raise ValueError('fault fixture can be armed only once')
                self.armed = True
            elif action == 'release':
                if not self.dropped or self.released:
                    raise ValueError('release requires exactly one committed lost ACK')
                self.released = True
            else:
                raise ValueError('unknown fixture operation')

    def before(self, identity):
        with self.lock:
            if not self.armed:
                return 'pass', None
            if len(self.records) + len(self.required_records) >= 128:
                raise ValueError('fixture attempt bound exhausted')
            ids = set(identity['eventIds'])
            queued_ids = {event_id for record in self.records for event_id in record['eventIds']}
            required_ids = {event_id for record in self.required_records for event_id in record['eventIds']}
            if identity.get('requiredCredentialRelease'):
                # Each new proxy request must durably record this synchronous
                # singleton before it can enqueue its response event. It is not
                # a retry of the asynchronous queued batch whose ACK we hold.
                if ids & queued_ids or ids & required_ids:
                    self.failure = 'required singleton reused a retained audit identity'
                    raise ValueError(self.failure)
                record = dict(identity, forwarded=False, acknowledged=False, responseDropped=False)
                self.required_records.append(record)
                return 'required', record
            if ids & required_ids:
                self.failure = 'queued batch reused a required singleton identity'
                raise ValueError(self.failure)
            if self.original is None and len(identity['eventIds']) < 2:
                return 'pass', None
            record = dict(identity, forwarded=False, acknowledged=False, responseDropped=False)
            self.records.append(record)
            if self.original is None:
                self.original = dict(identity)
                return 'first', record
            if not self.released:
                if identity['bodyDigest'] != self.original['bodyDigest'] or identity['eventIds'] != self.original['eventIds']:
                    self.failure = 'pending retry mutated original batch'
                    raise ValueError(self.failure)
                record['responseDropped'] = True
                return 'hold', record
            return 'forward', record

    def committed(self, record, first):
        with self.lock:
            record['forwarded'] = True
            record['acknowledged'] = True
            if first:
                record['responseDropped'] = True
                self.dropped = True

    def fail(self, message):
        with self.lock:
            self.failure = message

    def snapshot(self):
        with self.lock:
            # Only fixed labels, body/nonce hashes and synthetic audit IDs escape.
            return json.loads(json.dumps({'schema': 'catchplate.privateAuditRelay/v1',
                'armed': self.armed, 'released': self.released, 'dropped': self.dropped,
                'original': self.original, 'attempts': self.records,
                'requiredAttempts': self.required_records, 'failure': self.failure}))


class RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, token):
        self.token = token
        self.fault = FaultState()
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, RelayHandler)

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


class RelayHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass

    def send_json(self, status, value):
        body = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def close_without_response(self):
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def forward(self, body):
        # Destination and operation whitelist are code constants, never input URLs.
        connection = http.client.HTTPConnection('control-plane', 3000, timeout=4)
        headers = {name: self.headers[name] for name in FORWARD_HEADERS if name in self.headers}
        headers.update({'Host': 'catchplate:3000', 'Connection': 'close'})
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            result = response.read(MAX_BODY + 1)
            if len(result) > MAX_BODY:
                raise ValueError('bounded receiver response required')
            return response.status, response.getheaders(), result
        finally:
            connection.close()

    def handle_operation(self):
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment or len(self.path) > 4096:
            return self.send_json(400, {'error': 'fixture_path_refused'})
        if len(self.headers) > 32 or sum(len(k) + len(v) for k, v in self.headers.items()) > 16384:
            return self.send_json(431, {'error': 'fixture_headers_refused'})
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) > 1:
            return self.send_json(400, {'error': 'fixture_framing_refused'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.send_json(400, {'error': 'fixture_framing_refused'})
        if not 0 <= length <= MAX_BODY:
            return self.send_json(413, {'error': 'fixture_body_bound'})
        body = self.rfile.read(length)
        if len(body) != length:
            return self.close_without_response()
        if parsed.path == '/__fixture/health' and self.command == 'GET' and not parsed.query and not body:
            return self.send_json(200, {'ok': True, 'syntheticOnly': True})
        if parsed.path.startswith('/__fixture/'):
            token = self.headers.get('X-Private-Fixture-Token', '')
            if not hmac.compare_digest(token, self.server.token):
                return self.send_json(403, {'error': 'fixture_auth_required'})
            if parsed.query or body:
                return self.send_json(400, {'error': 'fixture_control_framing'})
            if parsed.path == '/__fixture/status' and self.command == 'GET':
                return self.send_json(200, self.server.fault.snapshot())
            if parsed.path in ('/__fixture/arm', '/__fixture/release') and self.command == 'POST':
                self.server.fault.control(parsed.path.rsplit('/', 1)[1])
                return self.send_json(200, self.server.fault.snapshot())
            return self.send_json(404, {'error': 'fixture_operation_refused'})
        allowed = ((self.command == 'GET' and parsed.path == '/attestation' and not body)
            or (self.command == 'POST' and parsed.path in (AUDIT, LEASE) and not parsed.query))
        if not allowed:
            return self.send_json(404, {'error': 'fixture_operation_refused'})
        mode, record, identity = 'pass', None, None
        if parsed.path == AUDIT:
            identity = batch_identity(body, self.headers.get('X-Catchplate-Response-Nonce'))
            mode, record = self.server.fault.before(identity)
            if mode == 'hold':
                return self.close_without_response()
        status, headers, response_body = self.forward(body)
        if record is not None:
            real_ack(status, headers, response_body, identity)
            self.server.fault.committed(record, mode == 'first')
        if mode == 'first':
            return self.close_without_response()
        self.send_response_only(status)
        for name, value in headers:
            if name.lower() not in HOP_HEADERS | {'content-length'}:
                self.send_header(name, value)
        self.send_header('Content-Length', str(len(response_body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(response_body)
        self.close_connection = True

    def do_GET(self):
        try:
            self.handle_operation()
        except (ValueError, OSError, http.client.HTTPException, UnicodeError):
            self.server.fault.fail('bounded relay operation failed')
            self.close_without_response()

    do_POST = do_GET


if __name__ == '__main__':
    token_path = Path('/fixture-control.token')
    token = token_path.read_text(encoding='ascii')
    if not re.fullmatch(r'[A-Za-z0-9_-]{64}', token):
        raise SystemExit('fixture control token refused')
    RelayServer(('0.0.0.0', 3000), token).serve_forever(poll_interval=0.2)

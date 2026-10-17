"""Real operator acceptance plus committed-lost-ACK proof in the new fixture.

Run only inside its control-plane container. No real credentials, provider
traffic, live root, bypassed application guard, or substituted DB receiver.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_operator_demo import OperatorDemoCheck, CheckFailure, require
from check_development_sandbox import token_file

INSTANCE = 'spiffe://operator-demo.catchplate/decision-gate/local'
RUN_CLAIM = Path('/data/.private-operator-audit-run.claim')


def claim_run(digest, *, path=RUN_CLAIM):
    """Consume this fixture once, durably, before any acceptance mutation.

    Even an incomplete or failed run keeps the claim. Recovery requires a new
    independently prepared fixture, never removing this file or replaying the
    checker against existing state.
    """
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', digest) is not None, 'exact binary digest required')
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=directory)
        except FileExistsError:
            raise CheckFailure('private fixture run already claimed; prepare a new fixture') from None
        with os.fdopen(fd, 'w', encoding='ascii') as out:
            json.dump({'schema': 'catchplate.privateOperatorAuditRunClaim/v1',
                'binarySha256': digest, 'replayAllowed': False}, out, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)


def row_id(event_id):
    value = {'eventId': event_id, 'instanceId': INSTANCE, 'version': 'catchplate.dataPlaneAuditRow/v1'}
    return 'sha256:' + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class RetryCheck:
    def __init__(self, check):
        self.check = check
        self.token = token_file(Path('/run/secrets/catchplate/fixture-control.token'))

    def relay(self, action, method='GET'):
        connection = http.client.HTTPConnection('catchplate', 3000, timeout=self.check.timeout())
        try:
            connection.request(method, '/__fixture/' + action,
                headers={'X-Private-Fixture-Token': self.token, 'Connection': 'close'})
            response = connection.getresponse()
            body = response.read(262145)
            require(response.status == 200 and len(body) <= 262144, 'bounded relay control failed')
            require(self.token.encode() not in body, 'fixture control token escaped')
            self.check.clean(body)
            value = json.loads(body)
            require(value.get('failure') is None, 'relay rejected retry identity or real receiver response')
            return value
        finally:
            connection.close()

    def wait(self, predicate, label):
        while True:
            self.check.timeout()
            value = predicate()
            if value:
                return value
            time.sleep(min(0.1, self.check.timeout()))

    def drained(self):
        status = self.check.health()['audit']
        fields = ('queue_depth', 'reserved', 'in_flight_optional', 'pending_retry_batches', 'pending_retry_events')
        require(all(type(status.get(field)) is int for field in fields), 'integrated retry counters unavailable')
        return status if all(status[field] == 0 for field in fields) else None

    def burst(self, count):
        def request(_):
            status, body = self.check.request('/echo')
            require(status == 200 and body.get('authorization_present') is True
                and body.get('proxy_authorization_seen') is False, 'synthetic retry traffic failed')
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(request, range(count)))

    def rows(self, ids):
        expected = [row_id(event_id) for event_id in ids]
        require(0 < len(expected) <= 200 and len(expected) == len(set(expected)), 'bounded unique audit rows required')
        with sqlite3.connect('file:/data/catchplate.sqlite3?mode=ro', uri=True) as connection:
            connection.execute('PRAGMA query_only=ON')
            rows = list(connection.execute('SELECT * FROM audit_events WHERE id IN (' + ','.join('?' for _ in expected) + ') ORDER BY id', expected))
        require(len(rows) == len(expected), 'committed audit IDs missing or duplicated')
        raw = json.dumps(rows, separators=(',', ':'), sort_keys=True).encode()
        self.check.clean(raw)
        return hashlib.sha256(raw).hexdigest()

    def run(self):
        before = self.wait(self.drained, 'pre-fault audit drain')
        self.relay('arm', 'POST')
        self.burst(4)

        def lost():
            value = self.relay('status')
            return value if value.get('dropped') and len(value.get('attempts', [])) >= 2 else None
        pending = self.wait(lost, 'committed ACK loss and immutable retry')
        original = pending['original']
        require(len(original['eventIds']) >= 2, 'lost-ACK original must be a multi-event batch')
        retained_hash = self.rows(original['eventIds'])
        pending_health = self.check.health()['audit']
        require(pending_health['pending_retry_events'] >= len(original['eventIds'])
            and pending_health['pending_retry_batches'] >= 1, 'real gate did not retain unresolved original')
        self.burst(2)
        fresh_health = self.check.health()['audit']
        require(fresh_health['enqueued'] > pending_health['enqueued'] and fresh_health['queue_depth'] > 0
            and fresh_health['pending_retry_events'] >= len(original['eventIds']),
            'new traffic was not queued separately during the pending retry')
        held = self.relay('status')
        fresh_required = held['requiredAttempts'][len(pending['requiredAttempts']):]
        require(len(fresh_required) == 2 and all(record['requiredCredentialRelease']
            and record['forwarded'] and record['acknowledged'] and not record['responseDropped']
            for record in fresh_required), 'fresh traffic required singletons did not commit separately')
        require(all(record['bodyDigest'] == original['bodyDigest'] and record['eventIds'] == original['eventIds']
            for record in held['attempts']), 'fresh events merged into uncertain original')
        self.relay('release', 'POST')
        after = self.wait(self.drained, 'post-ACK audit drain')
        final = self.relay('status')
        attempts = final['attempts']
        original_retries = [record for record in attempts if record['bodyDigest'] == original['bodyDigest']]
        require(len(original_retries) >= 3 and original_retries[0]['responseDropped']
            and original_retries[0]['acknowledged'] and original_retries[0]['forwarded']
            and any(r['acknowledged'] and not r['responseDropped'] for r in original_retries[1:]),
            'real committed original did not receive a fresh authenticated ACK after loss')
        require(len({record['nonceDigest'] for record in original_retries}) == len(original_retries),
            'retry reused response nonce instead of obtaining a fresh signed ACK')
        require(self.rows(original['eventIds']) == retained_hash, 'idempotent retry changed retained original rows')
        fresh = [record for record in attempts if record['bodyDigest'] != original['bodyDigest']]
        require(bool(fresh), 'new queued events never became a separate batch')
        original_ids = set(original['eventIds'])
        required_ids = set()
        for record in final['requiredAttempts']:
            ids = set(record['eventIds'])
            require(len(ids) == 1 and record['requiredCredentialRelease']
                and not ids & original_ids and not ids & required_ids and record['acknowledged']
                and record['forwarded'] and not record['responseDropped'],
                'required singleton identity or acknowledgement changed')
            self.rows(record['eventIds'])
            required_ids.update(ids)
        seen = set()
        for record in fresh:
            ids = set(record['eventIds'])
            require(not ids & original_ids and not ids & required_ids and not ids & seen and record['acknowledged']
                and record['forwarded'] and not record['responseDropped'],
                'fresh batch was mixed, duplicated or unacknowledged')
            self.rows(record['eventIds'])
            seen.update(ids)
        chain = self.check.control_json('/api/audit/verify?limit=1000', authenticated=True)
        require(chain.get('ok') is True and chain.get('complete') is True and chain.get('backend') == 'sqlite',
            'complete real receiver audit chain did not verify')
        require(after['dropped'] == before['dropped'] and after['required_failed'] == before['required_failed']
            and after['send_failed'] > before['send_failed'] and after['sent'] > before['sent'],
            'retry counters show dropped events, failed reservations or no recovered delivery')
        return {'ok': True, 'schema': 'catchplate.privateOperatorAuditRetry/v1',
            'original': original, 'originalRetainedRowsSha256': retained_hash,
            'attempts': attempts, 'requiredAttempts': final['requiredAttempts'],
            'before': before, 'whilePending': pending_health,
            'freshWhilePending': fresh_health, 'after': after,
            'freshEventCount': len(seen), 'completeSqliteChainVerified': True,
            'productionReady': False, 'durableCrashRecoveryClaimed': False}


def run(digest):
    require(os.getenv('PRIVATE_OPERATOR_AUDIT_FIXTURE') == '1', 'dedicated private fixture required')
    marker = json.loads(Path('/private-audit-fixture.json').read_text())
    require(marker == {'schema': 'catchplate.privateOperatorAuditFixture/v1', 'syntheticOnly': True},
        'fresh private fixture marker required')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', digest) is not None, 'exact binary digest required')
    claim_run(digest)
    args = argparse.Namespace(control_base='http://control-plane:3000', management_base='http://decision-gate-rs:9091',
        proxy_url='http://decision-gate-rs:9090', operator_origin='https://catchplate-demo.example.com',
        expected_binary_sha256=digest, ca_file=Path('/data/mitmproxy/mitmproxy-ca-cert.pem'),
        upstream_ca_file=Path('/demo-upstream/ca.pem'), admin_token_file=Path('/run/secrets/catchplate/admin.token'),
        proxy_ca_file=None, control_ca_file=None, management_ca_file=None, upstream_address=None, timeout_seconds=180)
    check = OperatorDemoCheck(args)
    acceptance = check.run()
    retry = RetryCheck(check).run()
    result = {'ok': True, 'schema': 'catchplate.privateOperatorAuditIntegration/v1',
        'acceptance': acceptance, 'retry': retry, 'productionReady': False, 'publicDnsVerified': False}
    check.clean(json.dumps(result).encode())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-binary-sha256', required=True)
    args = parser.parse_args()
    def expired(_signal, _frame):
        raise CheckFailure('private integration process deadline expired')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 180)
    try:
        result = run(args.expected_binary_sha256)
    except Exception as error:
        result = {'ok': False, 'error': str(error) if isinstance(error, CheckFailure) else type(error).__name__}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['ok'] else 1)

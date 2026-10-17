#!/usr/bin/env python3
"""Pure joins, real protected FDs, and actual missing-admission refusal.

Synthetic request/result dictionaries below are data-check fixtures only: they
are never injected into a client/owner or represented as committed authority.
No positive PostgreSQL, audit-inclusion or WebAuthn ceremony is claimed.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import commission_development_policy as cli

CHILD = r'''
import copy
import fcntl
import os
from pathlib import Path
import sys
import time
sys.path.insert(0, sys.argv[1])
from catchplate import development_policy_commissioning as m

scenario = sys.argv[2]
def refuses(call):
    try:
        call()
    except Exception as error:
        return error
    raise AssertionError('expected refusal')

def memfd(raw, sealed=True):
    fd = os.memfd_create('commissioning-public-test', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(fd, raw); os.fchmod(fd, 0o400)
    if sealed:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, m.SEALS)
    return fd

if scenario == 'protected-fd':
    fd = memfd(b'{}')
    try:
        raw, identity = m._read(fd, 100)
        assert raw == b'{}' and identity[:2] == m._identity(os.fstat(fd))[:2]
        refuses(lambda: os.write(fd, b'x'))
        refuses(lambda: m._read(fd, 1))
    finally:
        os.close(fd)
elif scenario == 'late-fd':
    fd = memfd(b'', sealed=False)
    try:
        original = m._late_descriptor(fd)
        assert os.fstat(fd).st_size == 0
        refuses(lambda: m._read(fd, m.MAX_INPUT))
        os.write(fd, b'{"independent":"literal"}')
        assert m._late_descriptor(fd) == original
        refuses(lambda: m._read(fd, m.MAX_INPUT))
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, m.SEALS)
        assert m._late_descriptor(fd) == original
        assert m._read(fd, m.MAX_INPUT)[0] == b'{"independent":"literal"}'
        refuses(lambda: os.ftruncate(fd, 0))
    finally:
        os.close(fd)
    fd = memfd(b'', sealed=False)
    try:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW)
        refuses(lambda: m._late_descriptor(fd))
    finally:
        os.close(fd)
elif scenario == 'missing-runtime':
    policy, prepare, late = memfd(b'{}'), memfd(b'{}'), memfd(b'', sealed=False)
    reader, writer = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        error = refuses(lambda: m.DevelopmentPolicyCommissioning.open(policy_fd=policy,
            policy_sha256=m._sha(b'{}'), prepare_fd=prepare, prepare_sha256=m._sha(b'{}'),
            finalize_fd=late, result_fd=writer, deadline_monotonic_ns=time.monotonic_ns()+30*10**9,
            expires_at_unix_ns=time.time_ns()+30*10**9))
        owner = error.owner
        assert type(owner) is m.DevelopmentPolicyCommissioning and owner.failed
        assert owner.client is None and owner.trust is None and not owner.sources
        assert owner.prepared is None and owner.finalized is None and not owner.used
        owner.close(); assert owner.closed and not owner.handles
        assert os.read(reader, 1) == b''
        for fd in (policy, prepare, late, writer):
            refuses(lambda fd=fd: os.fstat(fd))
    finally:
        os.close(reader)
elif scenario == 'modes':
    m.require_development()
    os.environ['CATCHPLATE_PROCESS_MODE'] = 'metadata-bootstrap'
    refuses(m.require_development)
    os.environ['CATCHPLATE_PROCESS_MODE'] = 'catchplate-control-plane'
    os.environ['CATCHPLATE_PRODUCTION_IMAGE'] = '1'
    refuses(m.require_development)
    os.environ['CATCHPLATE_PRODUCTION_IMAGE'] = '0'
    os.environ['CATCHPLATE_METADATA_STORE_ADMIN_POSTGRES_DSN'] = 'not-a-real-dsn'
    refuses(m.require_development)
    assert 'catchplate.authority_service' not in sys.modules
else:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from catchplate import policy_bundle as bundles
    # The demo policy signature is genuine, from an explicitly synthetic key.
    # Other request/evidence fields are only local shape fixtures, NOT authority.
    key = Ed25519PrivateKey.from_private_bytes(b'q' * 32)
    public = key.public_key()
    bundles.POLICY_SIGNING_PUBLIC_KEY_PATH.write_bytes(public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    os.chmod(bundles.POLICY_SIGNING_PUBLIC_KEY_PATH, 0o644)
    policy = bundles.demo_policy_bundle()
    policy['metadata']['signingKeyId'] = bundles._public_key_id(public)
    policy['metadata'].pop('signature', None)
    policy['metadata']['signature'] = 'ed25519:' + bundles._b64e(key.sign(bundles.policy_signature_bytes(policy)))
    policy_raw = bundles.canonical_json(policy).encode('utf-8')
    from catchplate.development_policy_genesis import signed_demo
    _, bound = signed_demo(policy_raw)
    now = time.time_ns()
    record = dict(genesis_preparation_digest='sha256:'+'1'*64,
        policy_id=bound['policyId'], policy_sequence=bound['sequence'], rollback_epoch=bound['rollbackEpoch'],
        policy_hash=bound['policyHash'], high_water_digest=m._sha(m._canonical(dict(scope='active', **bound))),
        genesis_envelope_json='{"fixture":"not-authority"}',
        genesis_envelope_digest=m._sha(b'{"fixture":"not-authority"}'),
        genesis_payload_json='{"fixture":"not-authority"}',
        genesis_payload_digest=m._sha(b'{"fixture":"not-authority"}'),
        signature_algorithm='Ed25519', signing_key_id='sha256:'+'2'*64,
        signature='synthetic-request-data-only', signature_digest='sha256:'+'3'*64,
        prepared_by='synthetic-test', prepared_at_epoch_ns=now-10**9, expires_at_epoch_ns=now+10**9)
    authorization = dict(challengeId='synthetic-only', credentialRecordId='synthetic-only',
        assertion={'synthetic': 'not-an-authenticated-assertion'})
    request = dict(input=dict(record=record, policySignatureEvidenceDigest='sha256:'+'4'*64),
        webauthnAuthorization=authorization)
    parsed, actual, trust = m.prepare_input(policy_raw, m._canonical(request), now_unix_ns=now)
    assert parsed == request and actual == record and trust.signing_key_id == policy['metadata']['signingKeyId']
    assert 'businessIntent' not in parsed['input'] and m._canonical(parsed) == m._canonical(request)
    if scenario == 'prepare':
        changed = copy.deepcopy(request); changed['input']['record']['policy_hash'] = 'sha256:'+'5'*64
        changed['input']['record']['high_water_digest'] = m._sha(m._canonical(dict(scope='active',
            policyId=bound['policyId'], sequence=bound['sequence'], rollbackEpoch=bound['rollbackEpoch'], policyHash='sha256:'+'5'*64)))
        refuses(lambda: m.prepare_input(policy_raw, m._canonical(changed), now_unix_ns=now))
        refuses(lambda: m.prepare_input(policy_raw, m._canonical(request), now_unix_ns=record['expires_at_epoch_ns']))
        changed = copy.deepcopy(request); changed['input']['businessIntent'] = {}
        refuses(lambda: m.prepare_input(policy_raw, m._canonical(changed), now_unix_ns=now))
        changed = copy.deepcopy(request); changed['webauthnAuthorization'] = {}
        refuses(lambda: m.prepare_input(policy_raw, m._canonical(changed), now_unix_ns=now))
    elif scenario == 'finalize':
        prepared = dict(record, ok=True, idempotent=False, genesis_transition_digest='sha256:'+'6'*64,
            audit_submission={'transition_digest':'sha256:'+'6'*64})
        assert m._prepared_result(prepared, record) is prepared
        final = dict(input=dict(genesisPreparationDigest=record['genesis_preparation_digest'],
            inclusionEvidenceDigest='sha256:'+'7'*64, auditStoreIdentityDigest='sha256:'+'8'*64,
            inclusionReceipt=dict(inclusion_receipt_envelope_digest='sha256:'+'9'*64,
                transition_digest=prepared['genesis_transition_digest'], audit_store_identity_digest='sha256:'+'8'*64)),
            webauthnAuthorization=authorization)
        assert m.finalize_input(m._canonical(final), prepared) == final
        assert 'businessIntent' not in final['input']
        changed = copy.deepcopy(final); changed['input']['businessIntent'] = {}
        refuses(lambda: m.finalize_input(m._canonical(changed), prepared))
        for key in ('genesisPreparationDigest', 'auditStoreIdentityDigest'):
            changed = copy.deepcopy(final); changed['input'][key] = 'sha256:'+'a'*64
            refuses(lambda: m.finalize_input(m._canonical(changed), prepared))
        changed = copy.deepcopy(final); changed['input']['inclusionReceipt']['transition_digest'] = 'sha256:'+'a'*64
        refuses(lambda: m.finalize_input(m._canonical(changed), prepared))
        response = {key: prepared[key] for key in ('genesis_preparation_digest','policy_id','policy_sequence',
            'rollback_epoch','policy_hash','high_water_digest','genesis_transition_digest')}
        response.update(ok=True, idempotent=False, inclusion_receipt_envelope_digest='sha256:'+'9'*64,
            finalization_digest='sha256:'+'b'*64)
        assert m._finalized_result(response, prepared, final) is response
        response['policy_hash'] = 'sha256:'+'a'*64
        refuses(lambda: m._finalized_result(response, prepared, final))
    else:
        raise AssertionError('unknown case')
'''


class DevelopmentPolicyCommissioningTests(unittest.TestCase):
    def scenario(self, name):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("CATCHPLATE_")}
        with tempfile.TemporaryDirectory(prefix="catchplate-commissioning-") as directory:
            environment.update(CATCHPLATE_DATA_DIR=directory, CATCHPLATE_RELEASE_CHANNEL="dev",
                CATCHPLATE_PROCESS_MODE="catchplate-control-plane")
            result = subprocess.run([sys.executable, "-I", "-B", "-c", CHILD, str(ROOT), name],
                cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_closed_cli_roster_and_distinct_fds(self):
        values = ("11", "sha256:"+"1"*64, "12", "sha256:"+"2"*64, "13", "14", "100", "200")
        args = [item for key, value in zip(cli.FIELDS, values) for item in ("--"+key, value)]
        self.assertEqual(cli.arguments(args)["finalize_fd"], 13)
        for changed in (args+["--phase", "finalize"], args[:-2], ["--operation"]+args[1:]):
            with self.assertRaises(ValueError):
                cli.arguments(changed)
        for index, value in ((1,"011"), (9,"11"), (3,"sha256:"+"A"*64), (13,"0")):
            changed = list(args); changed[index] = value
            with self.assertRaises(ValueError):
                cli.arguments(changed)

    def test_actual_protected_fd_not_mocked_owner(self):
        self.scenario("protected-fd")

    def test_actual_late_memfd_requires_one_complete_seal(self):
        self.scenario("late-fd")

    def test_real_missing_runtime_admission_precedes_inputs_and_effects(self):
        self.scenario("missing-runtime")

    def test_production_privileged_sql_and_wrong_modes_refused(self):
        self.scenario("modes")

    def test_signed_demo_and_exact_prepare_source_joins(self):
        self.scenario("prepare")

    def test_pure_final_request_joins_only_not_authority_evidence(self):
        self.scenario("finalize")

    def test_actual_owner_source_connects_two_fixed_calls_without_restore_or_sql(self):
        tree = ast.parse((ROOT / "catchplate/development_policy_commissioning.py").read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "DevelopmentPolicyCommissioning")
        methods = {node.name: node for node in owner.body if isinstance(node, ast.FunctionDef)}
        calls = [node for node in ast.walk(methods["run"]) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "request"]
        self.assertEqual([next(k.value.value for k in node.keywords if k.arg == "operation") for node in calls],
            ["policy.genesis.prepare", "policy.genesis.finalize"])
        self.assertTrue(all(any(k.arg == "deadline_ns" for k in node.keywords) for node in calls))
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in {"connect", "execute", "sign"}
            for node in ast.walk(tree)))
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "from_environment" for node in ast.walk(methods["open"])))
        self.assertNotIn("prepared", {argument.arg for argument in methods["open"].args.kwonlyargs})


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Signed-source/real-storage controls; no successful PostgreSQL admission claim."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import materialize_development_policy_genesis as cli

CHILD = r'''
import copy
import os
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import development_policy_genesis as module
from serverware import policy_bundle as bundles

scenario = sys.argv[2]
root = Path(os.environ['SERVERWARE_DATA_DIR'])
# An actual signature with a synthetic fixture key, not authority/genesis state.
key = Ed25519PrivateKey.from_private_bytes(b'g' * 32)
public = key.public_key()
bundles.POLICY_SIGNING_PUBLIC_KEY_PATH.write_bytes(public.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
os.chmod(bundles.POLICY_SIGNING_PUBLIC_KEY_PATH, 0o644)
value = bundles.demo_policy_bundle()
value['metadata']['signingKeyId'] = bundles._public_key_id(public)

def signed(candidate):
    candidate = copy.deepcopy(candidate)
    candidate['metadata'].pop('signature', None)
    candidate['metadata']['signature'] = 'ed25519:' + bundles._b64e(
        key.sign(bundles.policy_signature_bytes(candidate)))
    return bundles.canonical_json(candidate).encode('utf-8')

raw = signed(value)
original = root / 'supplied-policy.json'
original.write_bytes(raw); os.chmod(original, 0o400)
fd = os.open(original, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
kwargs = dict(policy_fd=fd, policy_sha256=module._sha(raw),
    genesis_preparation_digest='sha256:' + '1' * 64,
    genesis_finalization_digest='sha256:' + '2' * 64)

def refusal(call):
    try:
        call()
    except Exception as error:
        return error
    raise AssertionError('expected refusal')

if scenario == 'signed':
    trust, bound = module.signed_demo(raw)
    assert trust.signing_key_id == value['metadata']['signingKeyId']
    assert bound['policyId'] == 'serverware-demo' and bound['sequence'] == 1
    assert not bundles.POLICY_SIGNING_KEY_PATH.exists()
    tampered = raw.replace(b'demo-upstream', b'evil-upstream')
    refusal(lambda: module.signed_demo(tampered))
    changed = copy.deepcopy(value); changed['routes'][0]['match']['host'] = 'other-upstream'
    refusal(lambda: module.signed_demo(signed(changed)))
    os.environ['SERVERWARE_POLICY_REVOKED_SIGNING_KEY_IDS'] = trust.signing_key_id
    refusal(lambda: module.signed_demo(raw))
elif scenario == 'open':
    owner = module.OfflineDevelopmentGenesis.open(**kwargs)
    assert owner.authority is None and owner.raw == raw
    owner.check(); owner.close()
    assert owner.closed and not owner.handles
    assert not bundles.POLICY_BUNDLE_PATH.exists() and not (root / module.STAGE).exists()
    assert 'serverware.authority_service' not in sys.modules
    refusal(lambda: module.OfflineDevelopmentGenesis.open(**kwargs))
elif scenario == 'missing-dsn':
    owner = module.OfflineDevelopmentGenesis.open(**kwargs)
    error = refusal(owner.run)
    assert error.owner is owner and owner.failed
    assert type(owner.authority) is module.GenesisRead and owner.authority.connection is None
    assert not bundles.POLICY_BUNDLE_PATH.exists() and not (root / module.STAGE).exists()
    owner.close(); assert owner.closed
elif scenario in ('existing-target', 'existing-stage', 'journal-history', 'wrong-hash', 'wrong-mode'):
    retained = None
    if scenario in ('existing-target', 'existing-stage'):
        retained = bundles.POLICY_BUNDLE_PATH if scenario == 'existing-target' else root / module.STAGE
        retained.write_bytes(b'keep'); os.chmod(retained, 0o600)
    elif scenario == 'journal-history':
        directory = root / module.publication.JOURNAL
        directory.mkdir(mode=0o700)
        retained = directory / 'unrecognized-history'
        retained.write_bytes(b'keep')
    elif scenario == 'wrong-hash':
        kwargs['policy_sha256'] = 'sha256:' + '3' * 64
    else:
        os.chmod(original, 0o600)
    error = refusal(lambda: module.OfflineDevelopmentGenesis.open(**kwargs))
    assert type(error.owner) is module.OfflineDevelopmentGenesis and error.owner.failed
    error.owner.close(); assert error.owner.closed
    if retained is not None:
        assert retained.read_bytes() == b'keep'
elif scenario == 'no-replace':
    # Exercise the exact shared kernel mechanism, not a fabricated PG owner.
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        stage = root / module.STAGE
        target = bundles.POLICY_BUNDLE_PATH
        stage.write_bytes(b'complete'); os.chmod(stage, 0o600)
        target.write_bytes(b'existing'); os.chmod(target, 0o600)
        refusal(lambda: module._rename_noreplace(parent, module.STAGE, target.name))
        assert target.read_bytes() == b'existing' and stage.read_bytes() == b'complete'
        # Separate absent name proves successful atomic no-replace mechanics.
        module._rename_noreplace(parent, module.STAGE, 'primitive-output.json')
        assert (root / 'primitive-output.json').read_bytes() == b'complete' and not stage.exists()
    finally:
        os.close(parent)
else:
    raise AssertionError('unknown test scenario')
os.close(fd)
'''


class DevelopmentPolicyGenesisTests(unittest.TestCase):
    def scenario(self, name):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("SERVERWARE_")}
        with tempfile.TemporaryDirectory(prefix="serverware-development-genesis-") as directory:
            environment.update(SERVERWARE_DATA_DIR=directory, SERVERWARE_RELEASE_CHANNEL="dev",
                               SERVERWARE_PROCESS_MODE="metadata-bootstrap")
            result = subprocess.run([sys.executable, "-I", "-B", "-c", CHILD, str(ROOT), name],
                cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_signature_exact_demo_semantics_and_revocation(self):
        self.scenario("signed")

    def test_real_protected_input_owner_prepares_without_authority_or_private_key(self):
        self.scenario("open")

    def test_missing_actual_genesis_dsn_retains_partial_owner_before_any_effect(self):
        self.scenario("missing-dsn")

    def test_target_stage_and_publication_history_are_never_overwritten(self):
        for name in ("existing-target", "existing-stage", "journal-history"):
            with self.subTest(name=name):
                self.scenario(name)

    def test_original_pin_and_permissions_are_required(self):
        for name in ("wrong-hash", "wrong-mode"):
            with self.subTest(name=name):
                self.scenario(name)

    def test_real_shared_no_replace_primitive_preserves_existing_target(self):
        self.scenario("no-replace")

    def test_cli_has_closed_public_only_arguments(self):
        arguments = ["--policy-fd", "32", "--policy-sha256", "sha256:" + "1" * 64,
            "--genesis-preparation-digest", "sha256:" + "2" * 64,
            "--genesis-finalization-digest", "sha256:" + "3" * 64]
        self.assertEqual(cli.arguments(arguments)["policy_fd"], 32)
        for value in ([], arguments + ["--key-fd", "33"], ["--output", "/tmp/policy.json"] + arguments,
                      [arguments[0], "032", *arguments[2:]], [arguments[0], "2", *arguments[2:]]):
            with self.subTest(arguments=value), self.assertRaises(ValueError):
                cli.arguments(value)

    def test_actual_mode_guard_refuses_production_wrong_mode_and_admin_configuration(self):
        base = {key: value for key, value in os.environ.items() if not key.startswith("SERVERWARE_")}
        # No invalid descriptor stands in for the mode refusal: call the actual
        # pre-effect guard before any input, storage or PostgreSQL acquisition.
        code = """
import sys
sys.path.insert(0, sys.argv[1])
from serverware.development_policy_genesis import require_development, DevelopmentGenesisError
try:
    require_development()
except DevelopmentGenesisError:
    raise SystemExit(0)
raise AssertionError('forbidden mode admitted')
"""
        for changed in ({"SERVERWARE_PRODUCTION_IMAGE": "1"}, {"SERVERWARE_RELEASE_CHANNEL": "production"},
                        {"SERVERWARE_PROCESS_MODE": "serverware-control-plane"},
                        {"SERVERWARE_METADATA_STORE_ADMIN_POSTGRES_DSN": "never-contact-this"}):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(prefix="serverware-genesis-refusal-") as directory:
                environment = {**base, "SERVERWARE_DATA_DIR": directory, "SERVERWARE_RELEASE_CHANNEL": "dev",
                    "SERVERWARE_PROCESS_MODE": "metadata-bootstrap", **changed}
                result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(ROOT)],
                    cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("never-contact-this", result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertFalse((Path(directory) / "policy-bundle.json").exists())


if __name__ == "__main__":
    unittest.main()

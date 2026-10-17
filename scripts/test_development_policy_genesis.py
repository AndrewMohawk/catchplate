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
from catchplate import development_policy_genesis as module
from catchplate import policy_bundle as bundles

scenario = sys.argv[2]
root = Path(os.environ['CATCHPLATE_DATA_DIR'])
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
    assert bound['policyId'] == 'catchplate-demo' and bound['sequence'] == 1
    assert not bundles.POLICY_SIGNING_KEY_PATH.exists()
    tampered = raw.replace(b'demo-upstream', b'evil-upstream')
    refusal(lambda: module.signed_demo(tampered))
    changed = copy.deepcopy(value); changed['routes'][0]['match']['host'] = 'other-upstream'
    refusal(lambda: module.signed_demo(signed(changed)))
    os.environ['CATCHPLATE_POLICY_REVOKED_SIGNING_KEY_IDS'] = trust.signing_key_id
    refusal(lambda: module.signed_demo(raw))
elif scenario == 'open':
    owner = module.OfflineDevelopmentGenesis.open(**kwargs)
    assert owner.authority is None and owner.raw == raw
    owner.check(); owner.close()
    assert owner.closed and not owner.handles
    assert not bundles.POLICY_BUNDLE_PATH.exists() and not (root / module.STAGE).exists()
    assert 'catchplate.authority_service' not in sys.modules
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
    retained_identity = None if retained is None else (retained.stat().st_dev, retained.stat().st_ino)
    error = refusal(lambda: module.OfflineDevelopmentGenesis.open(**kwargs))
    assert type(error) is module.DevelopmentGenesisError
    owner = error.owner
    assert type(owner) is module.OfflineDevelopmentGenesis and owner.failed
    assert owner.authority is None and owner.stage_fd is None and not owner.installed and not owner.used
    if scenario in ('existing-target', 'existing-stage', 'journal-history'):
        # These are storage-guard controls, not merely any refusal.  The actual
        # owner must already have admitted the signed source and acquired its
        # real target parent; an earlier schema/signature rejection must fail.
        assert owner.raw == raw and owner.input_identity is not None
        assert owner.trust is not None and owner.trust.signing_key_id == value['metadata']['signingKeyId']
        assert owner.material_binding['policyId'] == 'catchplate-demo'
        assert owner.material_binding['sequence'] == 1
        assert owner.material_binding['kind'] == 'genesis-materialize'
        assert owner.parent is not None
        held_parent = os.fstat(owner.parent)
        assert (held_parent.st_dev, held_parent.st_ino) == (root.stat().st_dev, root.stat().st_ino)
        if scenario == 'journal-history':
            assert owner.directory is not None
            held_journal = os.fstat(owner.directory)
            named_journal = (root / module.publication.JOURNAL).stat()
            assert (held_journal.st_dev, held_journal.st_ino) == (named_journal.st_dev, named_journal.st_ino)
            assert not bundles.POLICY_BUNDLE_PATH.exists() and not (root / module.STAGE).exists()
            # The admitted named journal reached the actual nonempty scan.
            trace = error.__cause__.__traceback__
            reached_scan = False
            while trace is not None:
                frame = trace.tb_frame
                reached_scan |= (frame.f_code is module.OfflineDevelopmentGenesis.check.__code__
                    and frame.f_locals.get('self') is owner and 'entries' in frame.f_locals)
                trace = trace.tb_next
            assert reached_scan
        else:
            assert owner.directory is None and not (root / module.publication.JOURNAL).exists()
            rejected_name = owner.basename if scenario == 'existing-target' else module.STAGE
            trace = error.__cause__.__traceback__
            reached_absence_guard = False
            while trace is not None:
                frame = trace.tb_frame
                reached_absence_guard |= (frame.f_code is module.OfflineDevelopmentGenesis._absent.__code__
                    and frame.f_locals.get('self') is owner and frame.f_locals.get('name') == rejected_name)
                trace = trace.tb_next
            assert reached_absence_guard
            other = root / module.STAGE if scenario == 'existing-target' else bundles.POLICY_BUNDLE_PATH
            assert not other.exists()
    else:
        assert owner.trust is None and owner.material_binding is None
        assert owner.parent is None and owner.directory is None and not owner.pins
        assert not bundles.POLICY_BUNDLE_PATH.exists() and not (root / module.STAGE).exists()
        assert not (root / module.publication.JOURNAL).exists()
        if scenario == 'wrong-hash':
            # Permissions and protected-FD read succeeded; only the supplied
            # original digest is wrong, before signed-source admission.
            assert owner.input_fd is not None and owner.input_identity is not None and owner.raw == raw
            assert module._sha(owner.raw) != kwargs['policy_sha256']
            assert len(owner.handles) == 1
        else:
            # Refuse the caller's actual mode before duplicating or reading it.
            assert original.stat().st_mode & 0o7777 == 0o600
            assert owner.input_fd is None and owner.input_identity is None and owner.raw is None
            assert not owner.handles
            trace = error.__cause__.__traceback__
            reached_mode_guard = False
            while trace is not None:
                frame = trace.tb_frame
                reached_mode_guard |= (frame.f_code is module.public_io._input.__code__
                    and frame.f_locals.get('fd') == fd and 'info' in frame.f_locals
                    and frame.f_locals['info'].st_mode & 0o7777 == 0o600)
                trace = trace.tb_next
            assert reached_mode_guard
    owner.close(); assert owner.closed and not owner.handles
    if retained is not None:
        assert retained.read_bytes() == b'keep'
        assert (retained.stat().st_dev, retained.stat().st_ino) == retained_identity
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
        environment = {key: value for key, value in os.environ.items() if not key.startswith("CATCHPLATE_")}
        with tempfile.TemporaryDirectory(prefix="catchplate-development-genesis-") as directory:
            environment.update(CATCHPLATE_DATA_DIR=directory, CATCHPLATE_RELEASE_CHANNEL="dev",
                               CATCHPLATE_PROCESS_MODE="metadata-bootstrap")
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
        base = {key: value for key, value in os.environ.items() if not key.startswith("CATCHPLATE_")}
        # No invalid descriptor stands in for the mode refusal: call the actual
        # pre-effect guard before any input, storage or PostgreSQL acquisition.
        code = """
import sys
sys.path.insert(0, sys.argv[1])
from catchplate.development_policy_genesis import require_development, DevelopmentGenesisError
try:
    require_development()
except DevelopmentGenesisError:
    raise SystemExit(0)
raise AssertionError('forbidden mode admitted')
"""
        for changed in ({"CATCHPLATE_PRODUCTION_IMAGE": "1"}, {"CATCHPLATE_RELEASE_CHANNEL": "production"},
                        {"CATCHPLATE_PROCESS_MODE": "catchplate-control-plane"},
                        {"CATCHPLATE_METADATA_STORE_ADMIN_POSTGRES_DSN": "never-contact-this"}):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(prefix="catchplate-genesis-refusal-") as directory:
                environment = {**base, "CATCHPLATE_DATA_DIR": directory, "CATCHPLATE_RELEASE_CHANNEL": "dev",
                    "CATCHPLATE_PROCESS_MODE": "metadata-bootstrap", **changed}
                result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(ROOT)],
                    cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("never-contact-this", result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertFalse((Path(directory) / "policy-bundle.json").exists())


if __name__ == "__main__":
    unittest.main()

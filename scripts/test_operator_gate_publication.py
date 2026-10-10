#!/usr/bin/env python3
"""Connected curated-policy publication in disposable, network-none workers.

Real control-plane startup, SQLite, catalog mutations, signatures and Linux
flock run here. Only failing atomic steps/metadata are injected; no successful
publisher is substituted. This is not Rust reload or deployed acceptance.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_google_setup as google
import test_operator_publication as coordination
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
FLAG = "SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED"
DIRECTORY = "gate-runtime"
FILENAME = "policy-bundle.json"
PLACEHOLDERS = (".operator-publication.lock", ".serverware-operator-demo.json")
CA_PLACEHOLDERS = ("mitmproxy-ca-cert.pem", "mitmproxy-ca.pem")


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("gate publication fixture attempted network contact")


def paths(f):
    directory = f.config.DATA_DIR / DIRECTORY
    return directory, directory / FILENAME


def exact_inventory(directory):
    assert set(item.name for item in directory.iterdir()) == {FILENAME, "mitmproxy", *PLACEHOLDERS}
    ca = directory / "mitmproxy"
    info = ca.lstat()
    assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid()
    assert set(item.name for item in ca.iterdir()) == set(CA_PLACEHOLDERS)
    for path in [*(directory / name for name in PLACEHOLDERS), *(ca / name for name in CA_PLACEHOLDERS)]:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0
        assert info.st_uid == os.geteuid() and info.st_size == 0 and info.st_nlink == 1


def exact_export(f):
    directory, target = paths(f)
    for path, mode, kind in ((directory, 0o700, stat.S_ISDIR), (target, 0o600, stat.S_ISREG)):
        info = path.lstat()
        assert kind(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
        assert info.st_uid == os.geteuid()
        if path == target:
            assert info.st_nlink == 1
    exact_inventory(directory)
    row, = f.rows("operator_demo_policy")
    raw = row["signed_bundle_json"].encode("utf-8")
    assert target.read_bytes() == f.config.POLICY_BUNDLE_PATH.read_bytes() == raw
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    assert workspace.common._PROVIDER_SECRET.encode() not in raw
    assert not f.provider_calls
    return row["sequence"], row["policy_hash"]


def retained(f):
    return {"authority": f.authority(), "audit": f.rows("audit_events"),
        "settings": f.rows("operator_demo_settings"), "catalog_state": f.rows("operator_catalog_state")}


def resources(f):
    credential = workspace.create_credential(f.db, f.store, f.schema, f.inputs, f.mutations)["credential"]
    application = workspace.create_application(f.db, f.store, f.schema, f.inputs, f.mutations)["application"]
    assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == workspace.common._PROVIDER_SECRET
    return credential, application


def rule(f, credential, application):
    return workspace.create_rule(f.db, f.store, f.schema, f.inputs, f.mutations,
        application["id"], credential["id"])


def disabled():
    f = google.Fixture()
    credential, application = resources(f)
    rule(f, credential, application)
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    assert not paths(f)[0].exists() and not f.provider_calls
    from serverware import operator_gate_publication as gate
    for value in ("", "0", "1", "true", " 1", "01", "2"):
        with patch.dict(os.environ, {FLAG: value}):
            if value in {"", "0"}:
                assert gate.enabled() is False
            else:
                # Even valid "1" cannot enable an already-admitted flag-OFF
                # process: operator_demo.active() rejects environment drift.
                # Fresh flag-ON workers cover the successful enablement path.
                coordination.fail(gate.enabled)
    with patch.dict(os.environ):
        os.environ.pop(FLAG)
        assert gate.enabled() is False
    assert not paths(f)[0].exists()
    return {"disabled_keeps_canonical_only": True, "explicit_flag_grammar": True,
        "in_process_enablement_drift_refused": True}


def updates():
    f = google.Fixture()
    initial = exact_export(f)
    assert initial[0] == 1
    credential, application = resources(f)
    assert exact_export(f) == initial  # Saving resources alone grants no route.
    created = rule(f, credential, application)
    first = exact_export(f)
    assert first[0] == initial[0] + 1 and first[1] != initial[1]
    f.mutations.revoke_rule(f.inputs.TargetInput(**f.review(), id=created["access_rule"]["id"]),
        workspace.common._ACTOR)
    second = exact_export(f)
    assert second[0] == first[0] + 1 and second[1] != first[1]
    assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == workspace.common._PROVIDER_SECRET
    return {"initial_publication": True, "actual_policy_updates": 2, "sequence": second[0]}


def repair_current():
    f = google.Fixture()
    credential, application = resources(f)
    rule(f, credential, application)
    expected = exact_export(f)
    before = f.snapshot()
    directory, target = paths(f)
    target.unlink()
    f.store.materialize()
    assert exact_export(f) == expected and f.snapshot() == before
    target.write_bytes(b"synthetic stale exported artifact")
    target.chmod(0o600)
    f.store.materialize()
    assert exact_export(f) == expected and f.snapshot() == before
    temporary = directory / (".operator-policy-" + "a" * 32)
    temporary.write_bytes(b"synthetic interrupted writer")
    temporary.chmod(0o600)
    f.store.materialize()
    assert not temporary.exists()
    assert exact_export(f) == expected and f.snapshot() == before
    return {"canonical_already_current_repairs_missing_and_stale_export": True,
        "owned_interrupted_temporary_reclaimed": True}


def failed_commit_export():
    f = google.Fixture()
    credential, application = resources(f)
    old = exact_export(f)
    directory, target = paths(f)
    old_bytes = target.read_bytes()
    gate_identity = directory.stat().st_dev, directory.stat().st_ino
    original, failures = os.replace, []

    def fail_export(source, destination, *args, **kwargs):
        descriptor = kwargs.get("dst_dir_fd")
        if descriptor is not None:
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) == gate_identity and os.fspath(destination) == FILENAME:
                f.store.operator_publication.assert_held()
                assert not coordination.shared_probe(f.config.DATA_DIR / f.store.operator_publication.LOCK_NAME)
                failures.append(True)
                raise OSError("synthetic curated export replace failure")
        return original(source, destination, *args, **kwargs)

    with patch.object(os, "replace", side_effect=fail_export):
        result = rule(f, credential, application)
    assert failures == [True] and result["policy"]["activation"] == "pending"
    state = f.store.get_policy_high_water()
    assert state["sequence"] == old[0] + 1 and state["policy_hash"] != old[1]
    assert target.read_bytes() == old_bytes
    exact_inventory(directory)
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == workspace.common._PROVIDER_SECRET
    return retained(f)


def cold_repair():
    # A new process executes the actual preflight -> db -> operator bootstrap
    # startup sequence; no direct successful publisher call stands in for it.
    f = google.Fixture()
    exact_export(f)
    assert len(workspace.catalog(f.db, f.schema)["access_rules"]) == 1
    for credential in workspace.catalog(f.db, f.schema)["credentials"]:
        assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == workspace.common._PROVIDER_SECRET
    return retained(f)


def refusal(f):
    before = f.snapshot()
    coordination.fail(f.store.materialize)
    assert f.snapshot() == before


@contextmanager
def wrong_owner(path):
    """Negative owner metadata injection; not an actual cross-UID proof.

    The unprivileged fixture cannot chown. All successful publication uses real
    stat values; only this inode's owner is made unsafe for rejection checks.
    """
    identity = path.lstat().st_dev, path.lstat().st_ino
    original_stat, original_fstat = os.stat, os.fstat
    observed = []

    def alter(info):
        if (info.st_dev, info.st_ino) == identity:
            values = list(info)
            values[4] = info.st_uid + 1
            observed.append(True)
            return os.stat_result(values)
        return info

    with patch.object(os, "stat", side_effect=lambda *a, **k: alter(original_stat(*a, **k))), \
            patch.object(os, "fstat", side_effect=lambda *a, **k: alter(original_fstat(*a, **k))):
        yield
    assert observed, "negative owner metadata did not reach the actual guard"


def unsafe_directory():
    f = google.Fixture()
    directory, _ = paths(f)
    original = f.config.DATA_DIR / "retained-gate-runtime"
    directory.chmod(0o755)
    try:
        refusal(f)
    finally:
        directory.chmod(0o700)
    with wrong_owner(directory):
        refusal(f)
    unexpected = directory / "unexpected-file"
    unexpected.write_bytes(b"synthetic unexpected inventory")
    try:
        refusal(f)
        assert unexpected.read_bytes() == b"synthetic unexpected inventory"
    finally:
        unexpected.unlink()
    directory.rename(original)
    try:
        directory.symlink_to(original, target_is_directory=True)
        try:
            refusal(f)
            assert directory.is_symlink()
        finally:
            directory.unlink()
        directory.mkdir(mode=0o700)
        try:
            refusal(f)
            assert list(directory.iterdir()) == []
        finally:
            directory.rmdir()
        directory.write_bytes(b"synthetic non-directory")
        try:
            refusal(f)
            assert directory.read_bytes() == b"synthetic non-directory"
        finally:
            directory.unlink()
    finally:
        original.rename(directory)
    exact_export(f)
    return {"directory_mode_owner_symlink_type_refused": True,
        "unknown_inventory_and_replaced_directory_inode_refused": True}


def unsafe_leaf():
    f = google.Fixture()
    directory, target = paths(f)
    raw = target.read_bytes()
    for mode in (0o644, 0o640, 0o400):
        target.chmod(mode)
        try:
            refusal(f)
        finally:
            target.chmod(0o600)
    with wrong_owner(target):
        refusal(f)
    backing = f.config.DATA_DIR / "synthetic-export-backing"
    backing.write_bytes(raw)
    backing.chmod(0o600)
    target.unlink()
    try:
        for kind in ("symlink", "hardlink", "directory", "fifo"):
            if kind == "symlink":
                target.symlink_to(backing)
            elif kind == "hardlink":
                os.link(backing, target)
            elif kind == "directory":
                target.mkdir(mode=0o700)
            else:
                os.mkfifo(target, 0o600)
            try:
                refusal(f)
                assert backing.read_bytes() == raw
            finally:
                target.rmdir() if kind == "directory" else target.unlink()
    finally:
        backing.unlink()
    f.store.materialize()
    exact_export(f)
    return {"leaf_modes_owner_symlink_hardlink_type_refused": True}


def ownership_and_shared_lock():
    f = google.Fixture()
    from serverware import operator_gate_publication as gate
    publication = f.store.operator_publication
    directory, target = paths(f)
    raw = target.read_bytes()
    before = f.snapshot()
    coordination.fail(lambda: gate.materialize(raw))
    assert f.snapshot() == before and target.read_bytes() == raw
    target.unlink()
    with coordination.other_process_shared(f.config.DATA_DIR / publication.LOCK_NAME):
        with patch.object(publication, "ACQUISITION_SECONDS", 0.1), \
                patch.object(f.db, "connect", side_effect=AssertionError("publisher opened DB before EX")):
            coordination.fail(f.store.materialize, text="timed out")
        assert not target.exists()
    assert f.snapshot() == before
    original, phases = os.replace, []
    gate_identity = directory.stat().st_dev, directory.stat().st_ino

    def observe_replace(source, destination, *args, **kwargs):
        descriptor = kwargs.get("dst_dir_fd")
        if descriptor is not None:
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) == gate_identity:
                publication.assert_held()
                assert not coordination.shared_probe(f.config.DATA_DIR / publication.LOCK_NAME)
                phases.append("export_exclusive")
        return original(source, destination, *args, **kwargs)

    with patch.object(os, "replace", side_effect=observe_replace):
        f.store.materialize()
    assert phases == ["export_exclusive"]
    assert coordination.shared_probe(f.config.DATA_DIR / publication.LOCK_NAME)
    exact_export(f)
    assert f.snapshot() == before
    return {"direct_publication_requires_EX": True, "SH_blocks_before_DB": True,
        "atomic_export_holds_EX": True}


class OperatorGatePublicationTests(unittest.TestCase):
    def setUp(self):
        google.OperatorGoogleSetupTests.setUp(self)
        self.environment.update({FLAG: "1", "SERVERWARE_DECISION_GATE_BASE": ""})

    def worker(self, name, **changes):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env={**self.environment, **changes}, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)

    def test_disabled_flag_keeps_existing_canonical_publication(self):
        self.worker("disabled", **{FLAG: "0"})

    def test_initial_publication_and_two_real_catalog_policy_updates(self):
        self.worker("updates")

    def test_current_canonical_repairs_missing_and_stale_export_without_authority_changes(self):
        self.worker("repair_current")

    def test_postcommit_export_failure_retains_authority_and_fresh_startup_repairs(self):
        committed = self.worker("failed_commit_export")
        self.assertEqual(self.worker("cold_repair"), committed)

    def test_strict_directory_type_mode_owner_and_no_symlink(self):
        self.worker("unsafe_directory")

    def test_strict_leaf_type_mode_owner_links_and_no_fifo(self):
        self.worker("unsafe_leaf")

    def test_publication_requires_EX_and_excludes_shared_readers(self):
        self.worker("ownership_and_shared_lock")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        actions = {function.__name__: function for function in (disabled, updates, repair_current,
            failed_commit_export, cold_repair, unsafe_directory, unsafe_leaf, ownership_and_shared_lock)}
        print(json.dumps(actions[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)

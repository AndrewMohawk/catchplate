#!/usr/bin/env python3
"""Actual encrypted AWS opening inside the ordinary ECR transaction boundary.

Reuses the existing private workspace worker fixture. No AWS, SDK, sockets,
signing dispatch or live deployment; generic AWS credential release stays shut.
"""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_operator_aws_release_boundary as shared


def check_opening():
    config, db, store, bundles, schema, inputs, mutations = shared.workspace.workspace()
    from serverware import crypto, operator_publication, aws_ecr_signing, runtime
    f = SimpleNamespace(config=config, db=db, store=store, inputs=inputs, mutations=mutations, runtime=runtime)
    f.review = lambda: shared.workspace.review(db, store, schema)
    def call(function, *args):
        with patch.object(store, "loaded_policy_hash", return_value=None), \
                patch.object(store, "loaded_gate_status", return_value=None):
            return function(*args)
    f.call = call
    created = call(mutations.create_aws_credential, inputs.AwsSigV4CredentialInput(**f.review(),
        name="Encrypted ECR signing fixture", credential_kind="long_term", access_key_id=shared.ACCESS,
        secret_access_key=shared.SECRET, session_token=None, expires_at=None), shared.ACTOR)
    f.aws_id = created["credential"]["id"]
    before = shared.workspace.snapshot(db, catalog=True)
    f.unchanged = lambda: shared.workspace.snapshot(db, catalog=True) == before
    with closing(db.connect()) as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (f.aws_id,)).fetchone()
        assert row["encrypted_secret"] == "envelope:v2" and row["secret_ciphertext"]
        persisted = "\n".join(conn.iterdump())
        assert shared.ACCESS not in persisted and shared.SECRET not in persisted

    def opened(version):
        with operator_publication.exclusive(), f.db.metadata_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            value = f.db.open_operator_ecr_credentials(conn, f.aws_id, expected_version=version)
            assert conn.in_transaction
            return value

    def refused(callback):
        try:
            callback()
        except Exception as error:
            assert all(secret not in str(error) for secret in (shared.ACCESS, shared.SECRET, "PRIVATE-CANARY"))
            return
        raise AssertionError("ECR secret boundary admitted invalid authority")

    with patch.object(crypto, "decrypt_secret_envelope", wraps=crypto.decrypt_secret_envelope) as decrypt:
        value = opened(1)
        assert type(value) is aws_ecr_signing.Credentials
        assert value.kind == "long_term" and value.access_key_id == shared.ACCESS
        assert value.secret_access_key == shared.SECRET and value.session_token is None
        assert shared.ACCESS not in repr(value) and shared.SECRET not in repr(value)
        assert decrypt.call_count == 1
    assert f.unchanged()
    with patch.object(crypto, "decrypt_secret_envelope", side_effect=AssertionError("unexpected decrypt")) as decrypt:
        for version in (0, 2, True, "1", None, 9_007_199_254_740_992):
            refused(lambda: opened(version))
        with closing(f.db.connect()) as conn:
            refused(lambda: f.db.open_operator_ecr_credentials(conn, f.aws_id, expected_version=1))
            conn.execute("BEGIN IMMEDIATE")
            refused(lambda: f.db.open_operator_ecr_credentials(conn, f.aws_id, expected_version=1))
            conn.rollback()
        with operator_publication.exclusive(), closing(sqlite3.connect(":memory:")) as foreign:
            foreign.execute("BEGIN IMMEDIATE")
            refused(lambda: f.db.open_operator_ecr_credentials(foreign, f.aws_id, expected_version=1))
        decrypt.assert_not_called()
    with patch.object(crypto, "decrypt_secret_envelope", side_effect=ValueError("PRIVATE-CANARY")):
        refused(lambda: opened(1))
    assert f.unchanged()

    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    access, secret, token = "ASIA" + "H" * 16, "J" * 40, "SYNTHETIC-ECR-SESSION-CANARY"
    f.call(f.mutations.replace_aws_credential, f.inputs.ReplaceAwsSigV4CredentialInput(
        **f.review(), id=f.aws_id, expected_credential_generation=1, credential_kind="session",
        access_key_id=access, secret_access_key=secret, session_token=token, expires_at=expiry), shared.ACTOR)
    with patch.object(crypto, "decrypt_secret_envelope", side_effect=AssertionError("unexpected stale decrypt")) as decrypt:
        refused(lambda: opened(1))
        decrypt.assert_not_called()
    value = opened(2)
    assert (value.kind, value.access_key_id, value.secret_access_key, value.session_token, value.expires_at) == (
        "session", access, secret, token, expiry)
    assert all(item not in repr(value) for item in (access, secret, token))
    # Dedicated opening is not a generic lease or header-injection permission.
    with patch.object(f.db, "decrypt_secret_envelope", side_effect=AssertionError("generic decrypt")) as decrypt, \
            patch.object(f.runtime, "start_runtime_workers", return_value=None):
        f.runtime.invalidate_secret_leases()
        assert f.runtime.get_control_plane_credential(f.aws_id) is None
        assert f.runtime.get_credential(f.aws_id) is None
        assert f.runtime.get_bound_credential_lease(f.aws_id) is None
        decrypt.assert_not_called()
    with operator_publication.exclusive(), f.db.metadata_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE credential_generations SET last_version=3 WHERE credential_id=?", (f.aws_id,))
        with patch.object(crypto, "decrypt_secret_envelope", side_effect=AssertionError("bad floor decrypt")) as decrypt:
            refused(lambda: f.db.open_operator_ecr_credentials(conn, f.aws_id, expected_version=2))
            decrypt.assert_not_called()
        conn.rollback()
    f.call(f.mutations.revoke_credential, f.inputs.TargetInput(**f.review(), id=f.aws_id), shared.ACTOR)
    with patch.object(crypto, "decrypt_secret_envelope", side_effect=AssertionError("revoked decrypt")) as decrypt:
        refused(lambda: opened(2))
        decrypt.assert_not_called()
    assert not shared.NETWORK_ATTEMPTS
    return {"ok": True}


class EcrSecretOpeningTests(unittest.TestCase):
    def setUp(self):
        shared.workspace.common.OperatorDemoPersistenceTests.setUp(self)

    def test_encrypted_tuple_generation_transaction_and_generic_release_boundaries(self):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker"],
            cwd=shared.ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        if result.returncode:
            self.fail(shared.shared.worker_failure_summary(result))
        self.assertEqual(json.loads(result.stdout), {"ok": True})


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        os.umask(0o077)
        sys.addaudithook(shared.no_network)
        try:
            print(json.dumps(check_opening()))
        except Exception as error:
            print(json.dumps(shared.shared.safe_worker_failure(error)))
            raise SystemExit(1) from None
    else:
        unittest.main(verbosity=2)

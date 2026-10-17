#!/usr/bin/env python3
"""Actual X journal transactions/custody; no provider or fabricated token ACK.

The separate joined ASGI suite owns exchange/adoption/refresh/disconnect stories.
These focused controls exercise original consent/replay/deadline and generic
writer refusal using real SQLite, publication admission and encrypted PKCE.
"""
from contextlib import contextmanager, closing
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import uuid

import test_operator_x_configuration as fixture

ROOT = Path(__file__).resolve().parents[1]
STATE, NONCE, VERIFIER = "s" * 43, "n" * 43, "v" * 43


def refused(function, error):
    try:
        function()
    except error as exception:
        assert all(value not in str(exception) for value in (fixture.SECRET, VERIFIER, NONCE, STATE))
        return
    raise AssertionError("expected closed refusal")


def worker(name):
    config, db, _, schema, configuration = fixture.fixture()
    from catchplate import operator_x_account_store as store, operator_publication as publication
    from catchplate import operator_x_oauth_protocol as protocol
    from catchplate import operator_x_oauth_profile as profiles
    from catchplate.http_client import HttpDeadline
    configuration.configure(fixture.payload(configuration), fixture.ACTOR)

    @contextmanager
    def transaction():
        with publication.exclusive(), closing(db.connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            yield conn

    operation = str(uuid.uuid4())
    with transaction() as conn:
        selection = configuration.retained_public_binding(conn)
        revision = schema.read_catalog(conn)["revision"]
        policy = conn.execute("SELECT policy_hash FROM operator_demo_policy").fetchone()[0]
        intent = store.begin(conn, selection, operation_id=operation, actor_id=fixture.ACTOR,
            name="Synthetic X account", review={"expected_revision": revision, "expected_policy_hash": policy},
            state=STATE, browser_nonce=NONCE, verifier=VERIFIER,
            expires_at_epoch_ms=time.time_ns() // 1_000_000 + 600_000)
        assert intent["status"] == "consent_pending" and schema.read_catalog(conn)["revision"] == revision + 1
        row, _ = store._get(conn, store.INTENTS, operation)
        assert store._open(row) == {"verifier": VERIFIER}
        assert all(private not in row["metadata_json"] + row["envelope_json"] for private in (STATE, NONCE, VERIFIER))
    if name == "journal":
        with transaction() as conn:
            before = tuple(conn.iterdump())
            refused(lambda: store.status(conn, operation, fixture.ACTOR + "-other"), store.StoreNotFound)
            refused(lambda: store.consume_callback(conn, state=STATE, browser_nonce="z" * 43), store.StoreError)
            assert tuple(conn.iterdump()) == before
        with transaction() as conn:
            claim = store.consume_callback(conn, state=STATE, browser_nonce=NONCE)
            assert claim["code_verifier"] == VERIFIER and claim["intent"]["operation_id"] == operation
            assert conn.execute("SELECT count(*) FROM " + store.WORK).fetchone()[0] == 1
        with transaction() as conn:
            refused(lambda: store.consume_callback(conn, state=STATE, browser_nonce=NONCE), store.StoreError)
            before = tuple(conn.iterdump())
            public = store.status(conn, operation, fixture.ACTOR)
            assert public["status"] == "exchanging" and tuple(conn.iterdump()) == before
        assert db.verify_audit_chain()["ok"]
    elif name == "contact":
        with transaction() as conn:
            claim = store.consume_callback(conn, state=STATE, browser_nonce=NONCE)
        request = protocol.code_exchange_request(profiles.parse_profile(selection["public_profile"]),
            fixture.SECRET, "synthetic-code", VERIFIER)
        deadline = HttpDeadline.after(10)
        with transaction() as conn:
            store.claim_contact(conn, claim["work_id"], request=request, deadline=deadline)
            row = conn.execute("SELECT * FROM " + store.CAPTURES).fetchone()
            assert row["status"] == "claimed" and fixture.SECRET not in row["metadata_json"] + row["envelope_json"]
        with transaction() as conn:
            refused(lambda: store.claim_contact(conn, claim["work_id"], request=request, deadline=deadline), store.StoreError)
        with transaction() as conn:
            result = store.hold(conn, claim["work_id"], reason="exchange_failed")
            assert result["status"] == "uncertain"
        with transaction() as conn:
            refused(lambda: store.claim_contact(conn, claim["work_id"], request=request, deadline=deadline), store.StoreError)
            assert store.status(conn, operation, fixture.ACTOR)["status"] == "uncertain"
    elif name == "expired":
        with transaction() as conn:
            claim = store.consume_callback(conn, state=STATE, browser_nonce=NONCE)
        request = protocol.code_exchange_request(profiles.parse_profile(selection["public_profile"]),
            fixture.SECRET, "synthetic-code", VERIFIER)
        with transaction() as conn:
            before = tuple(conn.iterdump())
            refused(lambda: store.claim_contact(conn, claim["work_id"], request=request,
                deadline=HttpDeadline(time.monotonic() - 1)), store.StoreError)
            assert tuple(conn.iterdump()) == before
        with transaction() as conn:
            refused(lambda: store.adopt(conn, claim["work_id"], token={"accepted": True}, identity={"accepted": True}), store.StoreError)
            assert conn.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
    elif name == "generic":
        marker = {"operator_x_account": {"schema": "not-authority"}}
        for call in (
            lambda: db.create_credential("synthetic", "oauth2", "private", marker),
            lambda: db.upsert_credential_with_id(str(uuid.uuid4()), "synthetic", "oauth2", "private", marker),
            lambda: db.update_credential(str(uuid.uuid4()), {"metadata": marker}),
            lambda: db.update_credential_secret_if_version(str(uuid.uuid4()), expected_version=1,
                secret="private", metadata=marker),
        ):
            refused(call, db.MetadataStoreError)
        with transaction() as conn:
            assert conn.execute("SELECT count(*) FROM oauth_revocation_work").fetchone()[0] == 0
            assert conn.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
    elif name == "bounds":
        # Pure arithmetic controls exercise the same guard called before any
        # durable refresh claim. They do not manufacture an adopted account.
        tokens = [{"token_type_hint": "access_token", "token": "synthetic-" + str(index)} for index in range(64)]
        store._refresh_capacity(tokens[:62], False)
        refused(lambda: store._refresh_capacity(tokens[:63], False), store.StoreError)
        refused(lambda: store._refresh_capacity(tokens, False), store.StoreError)
        refused(lambda: store._refresh_capacity(tokens[:2], True), store.StoreError)
        large = [{"token_type_hint": "access_token", "token": "a" * (128 * 1024)} for _ in range(5)]
        refused(lambda: store._refresh_capacity(large, False), store.StoreError)
        with patch.object(store, "_now", return_value=120_000):
            assert store._expiry_from_contact(100_000, 60) == 160_000
        with patch.object(store, "_now", return_value=159_999):
            assert store._expiry_from_contact(100_000, 60) == 160_000
        with patch.object(store, "_now", return_value=160_000):
            refused(lambda: store._expiry_from_contact(100_000, 60), store.StoreError)
    else:
        raise AssertionError("unknown test")
    return {"control": name, "passed": True}


class StoreTests(unittest.TestCase):
    def setUp(self):
        fixture.XConfigurationTests.setUp(self)

    def run_control(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-25:]))
        self.assertNotIn(fixture.SECRET, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout), {"control": name, "passed": True})

    def test_actual_pkce_journal_browser_actor_and_one_use_state(self):
        self.run_control("journal")

    def test_contact_claim_once_and_uncertain_hold_without_replay(self):
        self.run_control("contact")

    def test_original_deadline_and_fake_success_refuse_before_custody(self):
        self.run_control("expired")

    def test_generic_writers_cannot_forge_managed_x_or_queue_retirement(self):
        self.run_control("generic")

    def test_precontact_cleanup_capacity_and_no_expiry_extension_by_capture_delay(self):
        self.run_control("bounds")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(fixture.no_network)
        print(json.dumps(worker(sys.argv[2]), sort_keys=True))
    else:
        unittest.main(verbosity=2)

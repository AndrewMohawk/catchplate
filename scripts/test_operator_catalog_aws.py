#!/usr/bin/env python3
"""Cold AWS tuple-store tests: real SQLite/encryption, no AWS or signing lane.

Run in the existing bounded network-none APP image with read-only source and
private TMPDIR. Only gate health observation is absent/synthetic. Admission,
publication ownership, encryption, generation/CAS, audit and signed empty policy
are real. No tuple save/replace/revoke is an implicit grant or lease.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

if sys.flags.optimize:
    raise RuntimeError("AWS catalog tests require enabled assertions")

import test_operator_catalog_github as shared
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "operator-aws-catalog-test"
KIND = "aws_sigv4_v1"
ACCESS = "AKIA" + "A" * 16
SESSION_ACCESS = "ASIA" + "B" * 16
SECRET = "C" * 40
OTHER_SECRET = "D" * 40
SESSION_TOKEN = "synthetic-session-token-" + "E" * 128
EXPIRY = "2100-01-01T01:00:00Z"
EXPIRY_SECONDS = int(datetime(2100, 1, 1, 1, tzinfo=timezone.utc).timestamp())
NETWORK_ATTEMPTS = []


def no_network(event, args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        NETWORK_ATTEMPTS.append(event)
        raise AssertionError("AWS catalog fixture forbids network")


sys.addaudithook(no_network)


def refused(callback, error=ValueError):
    try:
        callback()
    except error as caught:
        return caught
    raise AssertionError("invalid AWS credential operation admitted")


def tuple_fields(kind="long_term", **changes):
    return {"credential_kind": kind,
        "access_key_id": SESSION_ACCESS if kind == "session" else ACCESS,
        "secret_access_key": SECRET,
        "session_token": SESSION_TOKEN if kind == "session" else None,
        "expires_at": EXPIRY if kind == "session" else None, **changes}


def tuple_json(fields):
    # Independent public format oracle; never call the production serializer.
    return json.dumps({"schema": "catchplate.awsSigV4Credentials/v1", **fields},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Fixture:
    def __init__(self):
        (self.config, self.db, self.store, self.bundles, self.schema,
            self.inputs, self.mutations) = workspace.workspace()
        self.private = [ACCESS, SESSION_ACCESS, SECRET, OTHER_SECRET, SESSION_TOKEN]

    def call(self, function, *args, **kwargs):
        # Saving inert AWS tuple metadata does not depend on a running gate.
        # Do not replace transaction, encryption, policy or binding guards.
        with patch.object(self.store, "loaded_policy_hash", return_value=None), \
                patch.object(self.store, "loaded_gate_status", return_value=None):
            return function(*args, **kwargs)

    def review(self):
        return workspace.review(self.db, self.store, self.schema)

    def catalog(self):
        return workspace.catalog(self.db, self.schema)

    def public(self):
        return self.call(self.mutations.catalog_status)

    def snapshot(self):
        return (workspace.snapshot(self.db, catalog=True), self.config.POLICY_BUNDLE_PATH.read_bytes(),
                self.store.get_policy_high_water())

    def core(self, identifier, connection=None):
        if connection is None:
            with closing(self.db.connect()) as current:
                return self.core(identifier, current)
        row = connection.execute("SELECT * FROM credentials WHERE id=?", (identifier,)).fetchone()
        return None if row is None else dict(row)

    def floor(self, identifier):
        with closing(self.db.connect()) as connection:
            row = connection.execute("SELECT last_version FROM credential_generations WHERE credential_id=?", (identifier,)).fetchone()
        return None if row is None else row[0]

    def target(self, identifier):
        return self.inputs.TargetInput(**self.review(), id=identifier)

    def create_payload(self, fields=None, **changes):
        return self.inputs.AwsSigV4CredentialInput(**{**self.review(),
            "name": "Synthetic AWS tuple", **(fields or tuple_fields()), **changes})

    def create(self, fields=None, **changes):
        return self.call(self.mutations.create_aws_credential,
            self.create_payload(fields, **changes), ACTOR)

    def replace_payload(self, identifier, fields=None, **changes):
        return self.inputs.ReplaceAwsSigV4CredentialInput(**{**self.review(), "id": identifier,
            "expected_credential_generation": self.core(identifier)["credential_version"],
            **(fields or tuple_fields(secret_access_key=OTHER_SECRET)), **changes})

    def replace(self, payload):
        return self.call(self.mutations.replace_aws_credential, payload, ACTOR)

    def secret(self, identifier, fields):
        actual = self.db.get_credential(identifier, include_secret=True)
        assert actual is not None and actual["secret"] == tuple_json(fields), "encrypted complete tuple differs"

    def assert_public(self, row, fields, *, generation=1, expired=False, revoked=False):
        expected = {"auth_type": KIND, "header_name": None, "connection_type": KIND,
            "provider_id": "aws", "credential_kind": fields["credential_kind"],
            "expires_at": fields["expires_at"], "expired": expired, "signing_available": False,
            "credential_generation": generation, "active_rule_count": 0,
            "status": "revoked" if revoked else "active"}
        assert {key: row[key] for key in expected} == expected
        assert type(row["expired"]) is bool and row["signing_available"] is False
        assert row["credential_generation"] is None or type(row["credential_generation"]) is int
        assert set(row) <= set(expected) | {"id", "name", "created_at", "version", "key_replaced_at", "revoked_at"}

    def privacy(self, result):
        with closing(self.db.connect()) as connection:
            persisted = "\n".join(connection.iterdump()).encode()
        buffers = [persisted, json.dumps(result).encode(), json.dumps(self.public()).encode(),
            json.dumps(workspace.rows(self.db, "audit_events")).encode(), self.config.POLICY_BUNDLE_PATH.read_bytes()]
        for path in (self.config.DB_PATH, Path(str(self.config.DB_PATH) + "-wal")):
            if path.exists():
                buffers.append(path.read_bytes())
        assert not any(value.encode() in raw for value in self.private for raw in buffers), "private tuple material leaked"

    def no_authority(self, before):
        after = self.snapshot()
        assert after[1:] == before[1:], "tuple mutation changed policy bytes or high water"
        assert after[0]["operator_demo_policy"] == before[0]["operator_demo_policy"]
        for table in ("operator_catalog_applications", "operator_catalog_rules", "operator_demo_connections", "operator_demo_nonces"):
            assert after[0][table] == before[0][table], "tuple mutation changed application/request authority"
        assert all(not row["event_type"].startswith("data_plane.") for row in workspace.rows(self.db, "audit_events"))
        assert not NETWORK_ATTEMPTS, "unexpected network attempt"
        workspace.verify_signed(self.config, self.db, self.store, self.bundles)


def saved_tuple(*, session=False):
    f = Fixture()
    fields = tuple_fields("session" if session else "long_term")
    if session:
        fields["session_token"] = "T" * 8192
        f.private.append(fields["session_token"])
        assert len(tuple_json(fields)) > 8192  # Not a static bearer-size shortcut.
    before = f.snapshot()
    old_revision = f.review()["expected_revision"]
    observed = []
    helper = f.db.create_operator_aws_credential

    def create_in_transaction(conn, **kwargs):
        assert type(conn) is sqlite3.Connection and conn.in_transaction
        f.store.operator_publication.assert_held()
        observed.append(conn)
        return helper(conn, **kwargs)

    with patch.object(f.db, "create_operator_aws_credential", side_effect=create_in_transaction):
        receipt = f.create(fields)
    assert len(observed) == 1
    identifier = receipt["credential"]["id"]
    core = f.core(identifier)
    assert core["kind"] == KIND and core["credential_version"] == f.floor(identifier) == 1
    assert core["encrypted_secret"] == "envelope:v2"
    assert all(core[name] for name in ("encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id"))
    metadata = json.loads(core["metadata"])
    subject = metadata.pop("provider_subject")
    assert str(uuid.UUID(subject)) == subject
    assert metadata == {"provider_id": "operator-demo", "secret_class": "awsSigV4",
        "connection_type": KIND, "credential_kind": fields["credential_kind"], "expires_at": fields["expires_at"]}
    f.secret(identifier, fields)
    f.assert_public(receipt["credential"], fields)
    public = f.public()
    f.assert_public(public["credentials"][0], fields)
    assert public["capabilities"]["aws_credentials"] == {
        "schema": "catchplate.operatorAwsCredentials/v1", "connection_type": KIND,
        "create_path": "/api/operator-demo/credentials/aws-sigv4",
        "replace_path": "/api/operator-demo/credentials/aws-sigv4/replace",
        "revoke_path": "/api/operator-demo/credentials/revoke",
        "credential_kinds": ["long_term", "session"], "signing_available": False,
        "automatic_renewal": False}
    assert receipt["revision"] == old_revision + 1
    assert len(workspace.rows(f.db, "audit_events")) == len(before[0]["audit_events"]) + 1
    events = [row for row in workspace.rows(f.db, "audit_events")
        if row["event_type"] == "operator_catalog.credential.aws_sigv4_created"]
    assert len(events) == 1 and json.loads(events[0]["event_json"])["resource_id"] == identifier
    f.no_authority(before)
    f.privacy(receipt)
    return {"ok": True}


def strict_inputs():
    f = Fixture()
    from pydantic import ValidationError
    before = f.snapshot()
    base = {**f.review(), "name": "Strict tuple", **tuple_fields()}
    variants = [
        {**base, key: value} for key, value in (
            ("credential_kind", "role"), ("credential_kind", True),
            ("access_key_id", SESSION_ACCESS), ("access_key_id", ACCESS.lower()),
            ("access_key_id", ACCESS + "A"), ("access_key_id", True),
            ("secret_access_key", "x" * 39), ("secret_access_key", "x" * 41),
            ("secret_access_key", "x" * 39 + "!"), ("secret_access_key", None),
            ("session_token", "token"), ("expires_at", EXPIRY),
            ("expected_revision", True), ("expected_revision", "1"),
            ("expected_policy_hash", "sha256:" + "A" * 64),
            ("header_name", "Authorization"), ("provider_id", "aws"),
            ("signing_available", True), ("credential_generation", 1))]
    variants += [{key: value for key, value in base.items() if key != missing}
        for missing in tuple_fields()]
    session = {**base, **tuple_fields("session")}
    variants += [{**session, key: value} for key, value in (
        ("access_key_id", ACCESS), ("session_token", None), ("session_token", ""),
        ("session_token", "x" * 8193), ("session_token", "white space"),
        ("session_token", "token\n"), ("session_token", True),
        ("expires_at", None), ("expires_at", "2100-02-30T01:00:00Z"),
        ("expires_at", "2100-01-01T01:00:00+00:00"),
        ("expires_at", "2100-01-01T01:00:00.000Z"), ("expires_at", 4102448400))]
    for values in variants:
        error = refused(lambda: f.inputs.AwsSigV4CredentialInput(**values), ValidationError)
        assert all(value not in str(error) for value in f.private), "tuple exposed by validation error"
    for fields in (tuple_fields(), tuple_fields("session")):
        payload = f.create_payload(fields)
        assert all(value not in repr(payload) for value in f.private), "tuple exposed by DTO repr"
    assert f.snapshot() == before
    created = f.create()
    identifier = created["credential"]["id"]
    replacement = f.replace_payload(identifier).model_dump()
    for changes in ({"expected_credential_generation": True}, {"expected_credential_generation": "1"},
            {"expected_credential_generation": 0}, {"name": "rename"}, {"id": "not-an-id"}):
        refused(lambda: f.inputs.ReplaceAwsSigV4CredentialInput(**{**replacement, **changes}), ValidationError)
    assert f.catalog()["revision"] == created["revision"]
    f.no_authority(before)
    f.privacy(created)
    return {"ok": True}


def expiry():
    f = Fixture()
    from catchplate import operator_catalog_aws as aws
    fields = tuple_fields("session")
    with patch.object(aws.time, "time_ns", return_value=(EXPIRY_SECONDS - 1) * 1_000_000_000):
        payload = f.create_payload(fields)
        receipt = f.call(f.mutations.create_aws_credential, payload, ACTOR)
        f.assert_public(receipt["credential"], fields)
        delayed_create = f.create_payload(fields, name="Expired between validation and write")
        delayed_replace = f.replace_payload(receipt["credential"]["id"], fields)
    before = f.snapshot()
    for now in (EXPIRY_SECONDS, EXPIRY_SECONDS + 60):
        with patch.object(aws.time, "time_ns", return_value=now * 1_000_000_000):
            f.assert_public(f.public()["credentials"][0], fields, expired=True)
            refused(lambda: f.create_payload(fields))
            refused(lambda: f.call(f.mutations.create_aws_credential, delayed_create, ACTOR))
            refused(lambda: f.replace(delayed_replace))
        assert f.snapshot() == before, "expiry observation renewed or wrote state"
    f.secret(receipt["credential"]["id"], fields)
    f.no_authority(before)
    f.privacy(receipt)
    return {"ok": True}


def replacement():
    f = Fixture()
    receipt = f.create()
    identifier = receipt["credential"]["id"]
    origin = f.core(identifier)
    before = f.snapshot()
    helper = f.db.replace_operator_aws_credential_if_version
    calls = []

    def same_transaction(conn, item_id, **kwargs):
        assert type(conn) is sqlite3.Connection and conn.in_transaction and item_id == identifier
        f.store.operator_publication.assert_held()
        calls.append(item_id)
        return helper(conn, item_id, **kwargs)

    # Each replacement is one complete tuple, including both kind transitions.
    # The repeated final tuple must still be a replacement, not a decrypt oracle.
    second_access = "AKIA" + "F" * 16
    second_token = "different-session-" + "G" * 128
    f.private.extend([second_access, second_token])
    tuples = [tuple_fields("session", secret_access_key=OTHER_SECRET, session_token=second_token),
        tuple_fields(access_key_id=second_access, secret_access_key=OTHER_SECRET)]
    tuples.append(dict(tuples[-1]))
    for generation, fields in enumerate(tuples, start=2):
        prior = f.core(identifier)
        old_revision = f.review()["expected_revision"]
        with patch.object(f.db, "replace_operator_aws_credential_if_version", side_effect=same_transaction), \
                patch.object(f.db, "decrypt_secret_envelope", side_effect=AssertionError("old tuple decrypted")):
            receipt = f.replace(f.replace_payload(identifier, fields))
        current = f.core(identifier)
        assert current["id"] == origin["id"] and current["name"] == origin["name"]
        assert current["created_at"] == origin["created_at"] and current["kind"] == KIND
        assert json.loads(current["metadata"])["provider_subject"] == json.loads(origin["metadata"])["provider_subject"]
        assert current["secret_ciphertext"] != prior["secret_ciphertext"] and current["secret_nonce"] != prior["secret_nonce"]
        assert current["credential_version"] == f.floor(identifier) == generation
        assert receipt["revision"] == old_revision + 1
        f.assert_public(receipt["credential"], fields, generation=generation)
        assert receipt["credential"]["version"] == generation and receipt["credential"]["key_replaced_at"]
        assert receipt["key_replacement"]["previous_credential_generation"] == generation - 1
        assert receipt["key_replacement"]["credential_generation"] == generation
        f.secret(identifier, fields)
    assert len(calls) == 3
    assert len(workspace.rows(f.db, "audit_events")) == len(before[0]["audit_events"]) + 3
    events = [json.loads(row["event_json"]) for row in workspace.rows(f.db, "audit_events")
        if row["event_type"] == "operator_catalog.credential.aws_sigv4_replaced"]
    assert [item["credential_generation"] for item in events] == [2, 3, 4]
    assert all(item["resource_id"] == identifier for item in events)
    f.no_authority(before)
    f.privacy(receipt)
    return {"ok": True}


def cas():
    f = Fixture()
    created = f.create()
    identifier = created["credential"]["id"]
    stale = f.replace_payload(identifier)
    f.create(name="Second inert tuple")
    before = f.snapshot()
    for payload in (stale,
            f.replace_payload(identifier, expected_policy_hash="sha256:" + "0" * 64),
            f.replace_payload(identifier, expected_credential_generation=2)):
        refused(lambda: f.replace(payload), f.schema.CatalogConflict)
        assert f.snapshot() == before
    accepted = f.replace_payload(identifier)
    receipt = f.replace(accepted)
    after = f.snapshot()
    refused(lambda: f.replace(accepted), f.schema.CatalogConflict)
    assert f.snapshot() == after
    assert f.floor(identifier) == 2 and receipt["credential"]["credential_generation"] == 2
    # The core generation CAS is independent of catalog revision/policy review.
    # Use the dedicated owned helper, not the now-forbidden generic writer.
    stale_generation = f.replace_payload(identifier)
    with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        advanced = f.db.replace_operator_aws_credential_if_version(conn, identifier,
            expected_version=2, secret=tuple_json(tuple_fields()))
        assert advanced["credential_generation"] == 3
    changed_core = f.snapshot()
    refused(lambda: f.replace(stale_generation), f.schema.CatalogConflict)
    assert f.snapshot() == changed_core and f.floor(identifier) == 3
    f.secret(identifier, tuple_fields())
    f.no_authority(before)
    f.privacy(receipt)
    return {"ok": True}


def rollback():
    f = Fixture()
    created = f.create()
    identifier = created["credential"]["id"]
    with closing(f.db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER aws_catalog_audit_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type LIKE 'operator_catalog.credential.%' "
            "BEGIN SELECT RAISE(ABORT,'synthetic AWS audit refusal'); END")
    before = f.snapshot()
    from catchplate import runtime
    with patch.object(runtime, "invalidate_secret_leases", side_effect=AssertionError("precommit eviction")) as eviction:
        refused(lambda: f.create(name="Rolled back tuple"), sqlite3.IntegrityError)
        assert f.snapshot() == before
        refused(lambda: f.replace(f.replace_payload(identifier, tuple_fields("session"))), sqlite3.IntegrityError)
        assert f.snapshot() == before and eviction.call_count == 0
    f.secret(identifier, tuple_fields())
    assert f.floor(identifier) == 1
    f.no_authority(before)
    f.privacy(created)
    return {"ok": True}


def revoke():
    f = Fixture()
    created = f.create(tuple_fields("session"))
    identifier = created["credential"]["id"]
    f.replace(f.replace_payload(identifier, tuple_fields("session", secret_access_key=OTHER_SECRET)))
    before = f.snapshot()
    pending = f.replace_payload(identifier)
    receipt = f.call(f.mutations.revoke_credential, f.target(identifier), ACTOR)
    assert f.core(identifier) is None and f.floor(identifier) == 2
    f.assert_public(receipt["credential"], tuple_fields("session"), generation=None, revoked=True)
    after = f.snapshot()
    refused(lambda: f.replace(pending), f.schema.CatalogConflict)
    refused(lambda: f.call(f.mutations.revoke_credential, f.target(identifier), ACTOR), f.schema.CatalogConflict)
    fresh_replace = f.inputs.ReplaceAwsSigV4CredentialInput(**f.review(), id=identifier,
        expected_credential_generation=2, **tuple_fields())
    refused(lambda: f.replace(fresh_replace), f.schema.CatalogConflict)
    # Revocation removes ciphertext, not the AWS identity boundary. A generic
    # fixed-ID upsert must not resurrect this tombstone as a bearer credential.
    refused(lambda: f.db.upsert_credential_with_id(identifier, "Generic resurrection", "bearer",
        OTHER_SECRET, {}), f.db.MetadataStoreError)
    assert f.snapshot() == after
    assert f.core(identifier) is None and f.floor(identifier) == 2
    f.no_authority(before)
    f.privacy(receipt)
    return {"ok": True}


def grants():
    f = Fixture()
    created = f.create()
    identifier = created["credential"]["id"]
    application = f.call(workspace.create_application, f.db, f.store, f.schema, f.inputs, f.mutations)
    f.private.append(application["client_token"])
    before = f.snapshot()
    for replacement in (False, True):
        rule = f.inputs.RuleInput(**f.review(), name="Refused AWS static grant",
            application_id=application["application"]["id"], credential_id=identifier,
            upstream_url="https://api.example.com/v1/items", methods=["GET"], response_fields=["status"],
            **({"credential_input": "replace_exact", "placeholder": "public-dummy"} if replacement else {}))
        refused(lambda: f.call(f.mutations.create_rule, rule, ACTOR),
            (ValueError, f.schema.CatalogIntegrityError))
        assert f.snapshot() == before
    static = f.inputs.ReplaceCredentialKeyInput(**f.review(), id=identifier,
        expected_credential_generation=1, secret=OTHER_SECRET)
    refused(lambda: f.call(f.mutations.replace_credential_key, static, ACTOR), f.schema.CatalogConflict)
    assert f.snapshot() == before
    with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        refused(lambda: f.db.replace_operator_static_credential_secret_if_version(conn, identifier,
            expected_version=1, secret=OTHER_SECRET), f.db.MetadataStoreError)
        conn.rollback()
    assert f.snapshot() == before
    f.no_authority(before)
    f.privacy(created)
    return {"ok": True}


def forged():
    f = Fixture()
    identifier = f.create()["credential"]["id"]
    before = f.snapshot()
    metadata = json.loads(f.core(identifier)["metadata"])
    mutations = [("kind", "bearer"), ("lifecycle_status", "revocation_pending")]
    for key, value in (("provider_id", "aws"), ("provider_subject", str(uuid.uuid4())),
            ("secret_class", "bearerToken"), ("connection_type", "bearer"),
            ("credential_kind", "session"), ("expires_at", EXPIRY), ("extra", "not-admitted")):
        mutations.append(("metadata", json.dumps({**metadata, key: value})))
    mutations.append(("metadata", "not-json"))
    for column, value in mutations:
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE credentials SET " + column + "=? WHERE id=?", (value, identifier))
            refused(lambda: f.schema.validate_bindings(conn), f.schema.CatalogIntegrityError)
            conn.rollback()
        assert f.snapshot() == before
    for key, value in (("auth_type", "bearer"), ("header_name", "Authorization"),
            ("connection_type", "other"), ("provider_subject", "not-a-uuid"),
            ("credential_kind", "session"), ("expires_at", EXPIRY), ("access_key_id", ACCESS)):
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            raw = json.loads(conn.execute("SELECT data_json FROM operator_catalog_credentials WHERE id=?",
                (identifier,)).fetchone()[0])
            conn.execute("UPDATE operator_catalog_credentials SET data_json=? WHERE id=?",
                (json.dumps({**raw, key: value}), identifier))
            refused(lambda: f.schema.validate_bindings(conn), f.schema.CatalogIntegrityError)
            conn.rollback()
        assert f.snapshot() == before

    # Seed a genuine unrelated signed rule, then forge only an in-memory binding.
    # Both retained validation and the renderer must reject that AWS substitution.
    other = f.call(workspace.create_credential, f.db, f.store, f.schema, f.inputs, f.mutations)
    app = f.call(workspace.create_application, f.db, f.store, f.schema, f.inputs, f.mutations)
    f.private.extend([workspace.common._PROVIDER_SECRET, app["client_token"]])
    f.call(workspace.create_rule, f.db, f.store, f.schema, f.inputs, f.mutations,
        app["application"]["id"], other["credential"]["id"])
    before_rule = f.snapshot()
    fake = deepcopy(f.catalog())
    fake["access_rules"][0]["credential_id"] = identifier
    from catchplate import operator_catalog_policy
    with closing(f.db.connect()) as conn:
        refused(lambda: f.schema.validate_bindings(conn, fake), f.schema.CatalogIntegrityError)
    state = workspace.rows(f.db, "operator_demo_policy")[0]
    refused(lambda: operator_catalog_policy.render(fake, state["sequence"] + 1, state["initial_hash"]),
        (ValueError, f.schema.CatalogIntegrityError))
    assert f.snapshot() == before_rule
    f.no_authority(before_rule)
    f.privacy({"ok": True})
    return {"ok": True}


def core_refusals():
    f = Fixture()
    identifier = f.create()["credential"]["id"]
    static = f.call(workspace.create_credential, f.db, f.store, f.schema, f.inputs, f.mutations)
    static_id = static["credential"]["id"]
    f.private.append(workspace.common._PROVIDER_SECRET)
    before = f.snapshot()
    metadata = json.loads(f.core(identifier)["metadata"])
    for kind, marker in ((KIND, {}), ("bearer", {"connection_type": KIND}),
            ("header", {"secret_class": "awsSigV4"})):
        refused(lambda: f.db.create_credential("Forged AWS", kind, tuple_json(tuple_fields()), marker),
            f.db.MetadataStoreError)
        refused(lambda: f.db.upsert_credential_with_id(str(uuid.uuid4()), "Forged AWS", kind,
            tuple_json(tuple_fields()), marker), f.db.MetadataStoreError)
        assert f.snapshot() == before
    for target, payload in [(identifier, {"name": "Generic rename"}),
            (identifier, {"secret": tuple_json(tuple_fields("session"))}),
            (identifier, {"kind": "bearer", "metadata": {}}),
            (static_id, {"kind": KIND}), (static_id, {"metadata": {"connection_type": KIND}}),
            (static_id, {"metadata": {"secret_class": "awsSigV4"}})]:
        refused(lambda: f.db.update_credential(target, payload), f.db.MetadataStoreError)
        assert f.snapshot() == before
    refused(lambda: f.db.update_credential_secret_if_version(identifier, expected_version=1,
        secret=tuple_json(tuple_fields()), metadata=metadata), f.db.MetadataStoreError)
    refused(lambda: f.db.update_credential_secret_if_version(identifier, expected_version=1,
        secret=OTHER_SECRET, metadata={}), f.db.MetadataStoreError)
    refused(lambda: f.db.upsert_credential_with_id(identifier, "Generic rebind", "bearer",
        OTHER_SECRET, {}), f.db.MetadataStoreError)
    refused(lambda: f.db.delete_credential(identifier), f.db.MetadataStoreError)
    assert f.snapshot() == before

    publication = f.store.operator_publication
    from catchplate import operator_demo
    helpers = (
        lambda conn: f.db.create_operator_aws_credential(conn, name="Ownership control", secret=tuple_json(tuple_fields())),
        lambda conn: f.db.replace_operator_aws_credential_if_version(conn, identifier,
            expected_version=1, secret=tuple_json(tuple_fields())),
        lambda conn: f.db.delete_operator_aws_credential(conn, identifier))
    for helper in helpers:
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            refused(lambda: helper(conn), publication.PublicationError)
            conn.rollback()
            with publication.exclusive():
                refused(lambda: helper(conn), f.db.MetadataStoreError)
                conn.execute("BEGIN IMMEDIATE")
                with patch.object(operator_demo, "active", return_value=False):
                    refused(lambda: helper(conn), f.db.MetadataStoreError)
                conn.rollback()
                refused(lambda: helper(object()), f.db.MetadataStoreError)
                with closing(sqlite3.connect(":memory:")) as foreign:
                    foreign.execute("BEGIN")
                    refused(lambda: helper(foreign), f.db.MetadataStoreError)
        assert f.snapshot() == before
    # Retained generation drift is refused before replacement can repair it.
    with publication.exclusive(), closing(f.db.connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE credential_generations SET last_version=2 WHERE credential_id=?", (identifier,))
        changed = conn.total_changes
        refused(lambda: f.db.replace_operator_aws_credential_if_version(conn, identifier,
            expected_version=1, secret=tuple_json(tuple_fields())), f.db.MetadataStoreError)
        assert conn.total_changes == changed
        conn.rollback()
    assert f.snapshot() == before
    f.no_authority(before)
    f.privacy({"ok": True})
    return {"ok": True}


def cold_proof(f, identifier):
    f.secret(identifier, tuple_fields("session"))
    credential = next(row for row in f.public()["credentials"] if row["id"] == identifier)
    f.assert_public(credential, tuple_fields("session"))
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    f.privacy(credential)
    return {"id": identifier, "revision": f.catalog()["revision"], "generation": f.floor(identifier),
        "expiry": credential["expires_at"],
        "policy_sha256": hashlib.sha256(f.config.POLICY_BUNDLE_PATH.read_bytes()).hexdigest(),
        "rows_sha256": hashlib.sha256(json.dumps(f.snapshot()[0], sort_keys=True).encode()).hexdigest()}


def cold_seed():
    f = Fixture()
    identifier = f.create(tuple_fields("session"))["credential"]["id"]
    return cold_proof(f, identifier)


def cold_reopen():
    f = Fixture()
    records = f.catalog()["credentials"]
    assert len(records) == 1 and len(f.catalog()["access_rules"]) == 0
    return cold_proof(f, records[0]["id"])


OPERATIONS = {"long-term": saved_tuple, "session": lambda: saved_tuple(session=True),
    "inputs": strict_inputs, "expiry": expiry, "replacement": replacement, "cas": cas,
    "rollback": rollback, "revoke": revoke, "grants": grants, "forged": forged,
    "core": core_refusals, "seed": cold_seed, "reopen": cold_reopen}


class OperatorCatalogAwsTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment.pop("PYTHONOPTIMIZE", None)

    def worker(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        if result.returncode != 0:
            self.fail("isolated AWS catalog worker refused: " + shared.worker_failure_summary(result))
        self.assertLessEqual(len(result.stdout), 8192)
        return json.loads(result.stdout)

    def test_long_term_tuple_encrypted_without_authority(self): self.assertEqual(self.worker("long-term"), {"ok": True})
    def test_full_size_session_tuple_encrypted_without_authority(self): self.assertEqual(self.worker("session"), {"ok": True})
    def test_strict_tuple_types_fields_and_shapes(self): self.assertEqual(self.worker("inputs"), {"ok": True})
    def test_expiry_is_original_and_never_renewed(self): self.assertEqual(self.worker("expiry"), {"ok": True})
    def test_atomic_full_tuple_replacement_without_old_decryption(self): self.assertEqual(self.worker("replacement"), {"ok": True})
    def test_independent_revision_policy_and_generation_cas(self): self.assertEqual(self.worker("cas"), {"ok": True})
    def test_actual_audit_failure_rolls_back_create_and_replace(self): self.assertEqual(self.worker("rollback"), {"ok": True})
    def test_revocation_retains_generation_and_refuses_reuse(self): self.assertEqual(self.worker("revoke"), {"ok": True})
    def test_generic_grants_and_static_replacement_refused(self): self.assertEqual(self.worker("grants"), {"ok": True})
    def test_forged_retained_metadata_and_rule_bindings_refused(self): self.assertEqual(self.worker("forged"), {"ok": True})
    def test_generic_core_writers_and_borrowed_authority_refused(self): self.assertEqual(self.worker("core"), {"ok": True})
    def test_cold_reopen_preserves_original_tuple_and_audit(self): self.assertEqual(self.worker("seed"), self.worker("reopen"))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        try:
            outcome = OPERATIONS[sys.argv[2]]()
        except Exception as error:
            print(json.dumps(shared.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
        print(json.dumps(outcome, sort_keys=True))
    else:
        unittest.main(verbosity=2)

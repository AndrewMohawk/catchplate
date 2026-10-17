#!/usr/bin/env python3
"""Actual GitHub App and X configuration producers -> audit-only notifications.

Cold, disposable SQLite/encryption/signing fixtures; only GitHub HTTP transport
is synthetic. No settings saves, notification delivery, provider contact or
action-source admission. These checks are not live provider/deployment proof.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
import test_operator_catalog_github_app as github
import test_operator_x_configuration as xconfig

GITHUB_EVENT = "operator_catalog.credential.github_app_created"
GITHUB_KEY_EVENT = "operator_catalog.credential.github_app_key_replaced"
X_EVENT = "operator_catalog.x_oauth.configuration_saved"


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo",
                 "socket.gethostbyname", "socket.gethostbyaddr"}:
        raise AssertionError("provider notification test attempted network contact")


def prove(db, kind, expected_details, secrets):
    from catchplate import operator_notification_events as events
    from catchplate import operator_notification_store as store
    assert store.ACTION_SOURCE_AVAILABLE is False
    assert kind in events.AUDIT_EVENT_TYPES and kind not in events.ACTION_EVENT_TYPES
    with closing(db.connect()) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        before = tuple(conn.iterdump())
        original = conn.execute("SELECT id,event_type,event_json FROM audit_events WHERE event_type=?",
            (kind,)).fetchall()
        assert len(original) == 1
        cursor, observed = events.EventCursor(), []
        now = time.time_ns() // 1_000_000
        for _ in range(8):
            batch, following = events.read_batch(conn, cursor, limit=64, now_epoch_ms=now)
            observed.extend(batch)
            if following == cursor:
                break
            cursor = following
        else:
            raise AssertionError("provider audit test exceeded finite source bound")
        chosen = [item for item in observed if item.event_type == kind]
        assert len(chosen) == 1 and chosen[0].event_id == original[0]["id"]
        item, body = chosen[0], json.loads(original[0]["event_json"])
        payload = item.audit_payload
        assert item.action_payload is None and payload["channel"] == "audit_log"
        assert payload["projection"] == "approved_fields" and payload["review_path"] == "/#audit"
        assert payload["details"] == expected_details
        for key, value in expected_details.items():
            if key not in {"provider", "actor_type"}:
                assert body[key] == value
        assert events.payload_matches_source(conn, payload, now_epoch_ms=now)
        assert not events.action_is_current(conn, payload, now_epoch_ms=now)
        assert events.read_batch(conn, cursor, now_epoch_ms=now) == ((), cursor)
        assert tuple(conn.iterdump()) == before
    encoded = json.dumps(payload)
    assert all(secret not in encoded for secret in secrets)
    assert db.verify_audit_chain()["ok"]
    return {"projected": 1, "audit_only": True, "cursor_replay_empty": True,
        "source_unchanged": True, "network_attempts": 0}


def github_created():
    fixture = github.Fixture()
    with fixture.transport():
        result = fixture.create()
    assert fixture.provider.calls == ["installation", "mint-name", "repositories"]
    with closing(fixture.db.connect()) as conn:
        body = json.loads(conn.execute("SELECT event_json FROM audit_events WHERE event_type=?",
            (GITHUB_EVENT,)).fetchone()[0])
    assert set(body) == {"resource_type", "resource_id", "revision", "policy_hash", "policy_sequence"}
    assert body["resource_id"] == result["credential"]["id"]
    expected = {"actor_type": "admin", "provider": "github", **body}
    return prove(fixture.db, GITHUB_EVENT, expected,
        ["PRIVATE KEY", github.ACTOR, *fixture.provider.tokens, *fixture.provider.jwts])


def github_key_replaced():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    fixture = github.Fixture()
    replacement = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = replacement.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode("ascii")
    with fixture.transport():
        original = fixture.create()["credential"]
        fixture.provider.key = replacement
        result = fixture.mutations.replace_github_app_key(fixture.inputs.ReplaceGithubAppKeyInput(
            **fixture.review(), id=original["id"], expected_credential_generation=1,
            private_key_pem=pem), github.ACTOR)
    assert fixture.provider.calls == ["installation", "mint-name", "repositories",
        "installation", "mint-id", "repositories"]
    with closing(fixture.db.connect()) as conn:
        body = json.loads(conn.execute("SELECT event_json FROM audit_events WHERE event_type=?",
            (GITHUB_KEY_EVENT,)).fetchone()[0])
    assert set(body) == {"resource_type", "resource_id", "revision", "policy_hash", "policy_sequence",
        "previous_credential_generation", "credential_generation"}
    assert body["resource_id"] == original["id"] == result["credential"]["id"]
    assert body["previous_credential_generation"] == 1 and body["credential_generation"] == 2
    expected = {"actor_type": "admin", "provider": "github", **body}
    return prove(fixture.db, GITHUB_KEY_EVENT, expected,
        ["PRIVATE KEY", fixture.pem, pem, github.ACTOR, *fixture.provider.tokens, *fixture.provider.jwts])


def x_configured():
    _, db, _, _, service = xconfig.fixture()
    command = xconfig.payload(service)
    result = service.configure(service.profiles.XOAuthApplicationInput(**command), xconfig.ACTOR)
    assert result["status"] == "committed" and result["consent_ready"] is False
    with closing(db.connect()) as conn:
        source = conn.execute("SELECT id,event_json FROM audit_events WHERE event_type=?", (X_EVENT,)).fetchone()
    body = json.loads(source["event_json"])
    assert source["id"] == "operator-x-configuration:" + command["operation_id"]
    assert set(body) == {"operation_id", "actor_id", "config_version", "reviewed_revision",
        "committed_revision", "policy_hash", "profile_binding_digest", "created_at"}
    expected = {"actor_type": "admin", "provider": "x", "operation_id": command["operation_id"],
        "config_version": 1, "reviewed_revision": command["expected_revision"],
        "committed_revision": result["committed_revision"], "policy_hash": command["expected_policy_hash"]}
    return prove(db, X_EVENT, expected, [xconfig.CLIENT, xconfig.SECRET, body["profile_binding_digest"]])


OPERATIONS = {"github-created": github_created, "github-key-replaced": github_key_replaced,
    "x-configured": x_configured}


class ProviderNotificationIntegrationTests(unittest.TestCase):
    def setUp(self):
        github.OperatorCatalogGithubAppTests.setUp(self)
        directory = Path(self.scratch.name) / "x-custody"
        directory.mkdir(mode=0o700)
        self.environment.update({xconfig.FLAG: "1", xconfig.KEY_DIRECTORY: str(directory),
            "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED": "1"})

    def worker(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=75)
        self.assertNotIn(xconfig.SECRET, result.stdout + result.stderr)
        self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-35:]))
        self.assertEqual(json.loads(result.stdout), {"projected": 1, "audit_only": True,
            "cursor_replay_empty": True, "source_unchanged": True, "network_attempts": 0})

    def test_actual_github_app_creation_audit_projection(self):
        self.worker("github-created")

    def test_actual_github_app_key_replacement_audit_projection(self):
        self.worker("github-key-replaced")

    def test_actual_x_configuration_audit_projection(self):
        self.worker("x-configured")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker" and sys.argv[2] in OPERATIONS:
        os.umask(0o077)
        signal.alarm(70)
        sys.addaudithook(no_network)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)

#!/usr/bin/env python3
"""One old-source -> candidate-source -> reopen test of disabled-feature retention.

Run this harness separately from immutable, read-only source archives:
1deb896c35d660eb665ac57ad35789c22280edf9 at /previous-app and
8a8d4b06678193d51e2b875a471cbeb7cb1b5ddf at /candidate-app. The bounded
network-none runner must verify both full archive manifests before execution.
Only fresh synthetic data is created. One normal old-source application create
uses a module-local fixture clock to seed an already-expired active application;
all subsequent checks use the real clock. This is not natural-expiry proof.
No admission, startup, schema, signing or encryption guard is replaced. This is
not a live upgrade, proxy/gate test, provider test, or feature enablement test.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path("/candidate-app")
PREVIOUS = Path("/previous-app")
PREVIOUS_COMMIT = "1deb896c35d660eb665ac57ad35789c22280edf9"
CANDIDATE_COMMIT = "8a8d4b06678193d51e2b875a471cbeb7cb1b5ddf"
EXPIRED_APPLICATION = "Retained fixture-aged active application"
TABLES = ("credentials", "credential_generations", "operator_demo_connections",
    "operator_demo_revocations", "operator_demo_nonces", "operator_demo_settings",
    "operator_catalog_state", "operator_catalog_credentials", "operator_catalog_applications",
    "operator_catalog_rules", "operator_demo_policy", "audit_events", "metadata_audit_outbox")
FILES = ("master.key", "policy-bundle.json", "policy-signing-ed25519.pem",
    "policy-signing-ed25519.pub.pem", "mitmproxy/mitmproxy-ca.pem",
    "mitmproxy/mitmproxy-ca-cert.pem", ".operator-publication.lock", ".serverware-operator-demo.json")


def select_source(source):
    assert source.is_dir() and (source / "serverware" / "operator_demo.py").is_file()
    assert not any(name == "serverware" or name.startswith("serverware.")
        or name in {"test_operator_demo_persistence", "test_operator_workspace_store"} for name in sys.modules)
    # The edited harness is NOT an overlay on either immutable application.
    # Remove its directory, cwd and both roots before selected fixture imports.
    remaining = []
    for entry in sys.path:
        if not entry:
            continue
        resolved = Path(entry).resolve()
        if any(resolved.is_relative_to(root.resolve()) for root in (
                ROOT, PREVIOUS, Path(__file__).resolve().parent)):
            continue
        remaining.append(entry)
    sys.path[:] = [str(source / "scripts"), str(source), *remaining]


def verify_imports(source):
    count = 0
    for name, module in tuple(sys.modules.items()):
        if name == "serverware" or name.startswith("serverware.") or name in {
                "test_operator_demo_persistence", "test_operator_workspace_store"}:
            path = getattr(module, "__file__", None)
            assert path and Path(path).resolve().is_relative_to(source.resolve()), "mixed old/current application imports"
            count += 1
    assert count > 10


def seed_saved_authority(workspace, config, db, store, schema, inputs, mutations):
    first = workspace.create_credential(db, store, schema, inputs, mutations, "Retained bearer key")["credential"]
    second = mutations.create_credential(inputs.CredentialInput(**workspace.review(db, store, schema),
        name="Retained custom key", auth_type="header", header_name="X-Api-Key",
        secret=workspace.common._PROVIDER_SECRET + "-header"), workspace.common._ACTOR)["credential"]
    applications = [mutations.create_application(inputs.ApplicationInput(
        **workspace.review(db, store, schema), name="Retained active application",
        token_lifetime_seconds=3600, proxy_authentication="basic_and_bearer_v1"), workspace.common._ACTOR),
        workspace.create_application(db, store, schema, inputs, mutations, "Retained revoked application")]
    for application, credential in zip(applications, (first, second)):
        workspace.create_rule(db, store, schema, inputs, mutations,
            application["application"]["id"], credential["id"])
    # Age only the old mutation module's local clock reference during normal
    # creation. Do not patch the global time module, edit retained rows, lower
    # the admitted lifetime, or replace any policy/signature/authority guard.
    real_clock = mutations.time
    assert real_clock is time
    fixture_created_ns = time.time_ns() - 7200 * 1_000_000_000
    fixture_clock = SimpleNamespace(time_ns=lambda: fixture_created_ns)
    with patch.object(mutations, "time", fixture_clock):
        expired = mutations.create_application(inputs.ApplicationInput(
            **workspace.review(db, store, schema), name=EXPIRED_APPLICATION,
            token_lifetime_seconds=3600, proxy_authentication="basic_and_bearer_v1"), workspace.common._ACTOR)
    assert mutations.time is real_clock
    assert expired["application"]["token_expires_at_epoch_ms"] == fixture_created_ns // 1_000_000 + 3600_000
    assert expired["application"]["token_expires_at_epoch_ms"] < time.time_ns() // 1_000_000
    applications.append(expired)
    for application, response_mode, credential_input in (
            (applications[0], "unfiltered_json_or_empty_v2", "replace_exact"),
            (expired, "unfiltered_json_or_empty_v1", "insert")):
        replacement = {"placeholder": "Bearer SERVERWARE_RETAINED_FIXTURE"} if credential_input == "replace_exact" else {}
        mutations.create_rule(inputs.RuleInput(**workspace.review(db, store, schema),
            name="Retained " + response_mode, application_id=application["application"]["id"],
            credential_id=first["id"], upstream_url="https://demo-upstream:8443/echo", methods=["POST"],
            request_body_mode="preserve_json_v1", response_mode=response_mode,
            request_fields=[], response_fields=[], credential_input=credential_input, **replacement),
            workspace.common._ACTOR)
    before_policy = config.POLICY_BUNDLE_PATH.read_bytes()
    mutations.replace_credential_key(inputs.ReplaceCredentialKeyInput(**workspace.review(db, store, schema),
        id=first["id"], expected_credential_generation=1,
        secret=workspace.common._PROVIDER_SECRET + "-replacement"), workspace.common._ACTOR)
    assert config.POLICY_BUNDLE_PATH.read_bytes() == before_policy
    assert db.get_credential(first["id"], include_secret=True)["credential_version"] == 2
    mutations.revoke_application(workspace.target(db, store, schema, inputs,
        applications[1]["application"]["id"]), workspace.common._ACTOR)
    saved = workspace.catalog(db, schema)
    for application in applications:
        record = next(row for row in saved["applications"] if row["id"] == application["application"]["id"])
        assert record["token_sha256"] == "sha256:" + hashlib.sha256(application["client_token"].encode()).hexdigest()
        assert record["token_version"] == 1 and "token_rotated_at" not in record
        if record["name"] == EXPIRED_APPLICATION:
            assert record["status"] == "active"
            assert record["token_expires_at_epoch_ms"] < time.time_ns() // 1_000_000
        else:
            assert record["token_expires_at_epoch_ms"] > time.time_ns() // 1_000_000
    assert {row["status"] for row in saved["applications"]} == {"active", "revoked"}
    assert {row.get("proxy_authentication", "bearer") for row in saved["applications"]} == {
        "basic_and_bearer_v1", "bearer"}
    assert {row["status"] for row in saved["access_rules"]} == {"active", "revoked"}
    assert db.reserve_credential_lease_nonce(workspace.common._NONCE_KEY, workspace.common._NONCE,
        now_epoch_ms=int(time.time() * 1000)) is None
    with closing(db.connect()) as conn:
        persisted = "\n".join(conn.iterdump())
    for secret in (workspace.common._PROVIDER_SECRET, *(item["client_token"] for item in applications)):
        assert secret not in persisted, "plaintext synthetic credential or client token persisted"


def retained_snapshot(workspace, config, db, store, schema, profiles, mutations):
    assert profiles.selected() is False
    assert os.environ.get("SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED") == "0"
    assert "SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR" not in os.environ
    with closing(db.connect()) as conn:
        schema.validate_bindings(conn)
        catalog = schema.read_catalog(conn)
        rows = {table: [dict(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]
            for table in TABLES}
        disabled_objects = conn.execute("SELECT name FROM sqlite_master WHERE "
            "lower(name) GLOB 'operator_google_*' OR lower(name) GLOB 'operator_catalog_oauth_*' "
            "OR lower(name) GLOB 'operator_provider_custody*' OR lower(name) GLOB '*notification*'").fetchall()
        assert disabled_objects == [], "disabled-feature upgrade created Google, custody or notification schema"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert [row[0] for row in conn.execute("PRAGMA integrity_check")] == ["ok"]
    assert [len(catalog[key]) for key in ("credentials", "applications", "access_rules")] == [2, 3, 4]
    assert len(rows["operator_demo_nonces"]) == 1
    expired, = [row for row in catalog["applications"] if row["name"] == EXPIRED_APPLICATION]
    assert expired["status"] == "active" and expired["token_version"] == 1
    assert expired["token_expires_at_epoch_ms"] < time.time_ns() // 1_000_000
    observed, = [row for row in mutations.catalog_status()["applications"] if row["id"] == expired["id"]]
    assert observed["token_status"] == "expired" and observed["status"] == "active"
    assert observed["token_generation"] == 1 and observed["active_rule_count"] == 1
    assert observed["access_status"] != "active"
    assert {row.get("response_mode", "projected_json") for row in catalog["access_rules"]} == {
        "projected_json", "unfiltered_json_or_empty_v1", "unfiltered_json_or_empty_v2"}
    preserved = [row for row in catalog["access_rules"] if row.get("request_body_mode") == "preserve_json_v1"]
    assert len(preserved) == 2 and {row["credential_input"] for row in preserved} == {"insert", "replace_exact"}
    assert all(row["status"] == "active" and row["methods"] == ["POST"] for row in preserved)
    for record in catalog["credentials"]:
        core = db.get_credential(record["id"], include_secret=True)
        suffix = "-replacement" if record["name"] == "Retained bearer key" else "-header"
        assert core["secret"] == workspace.common._PROVIDER_SECRET + suffix
        assert core["credential_version"] == (2 if suffix == "-replacement" else 1)
    files = {}
    for relative in FILES:
        path = config.DATA_DIR / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 2 * 1024 * 1024
        files[relative] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": info.st_size,
            "device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid}
    return {"catalog": catalog, "rows": rows, "files": files, "high_water": store.get_policy_high_water()}


def worker(operation):
    source = PREVIOUS if operation == "seed-old" else ROOT
    assert operation in {"seed-old", "upgrade", "reopen"}
    assert PREVIOUS.resolve() != ROOT.resolve()
    select_source(source)
    import test_operator_workspace_store as workspace
    from serverware import operator_demo
    operator_demo.activate()
    from serverware import config, db, oauth, operator_demo_store as store, policy_bundle as bundles
    from serverware import operator_catalog_schema as schema, operator_catalog_inputs as inputs
    from serverware import operator_catalog_mutations as mutations, operator_catalog_oauth_profile as profiles
    from serverware.control_plane_startup import validate_control_plane_startup
    contacts = []

    def forbidden(request, **_options):
        contacts.append(request.full_url)
        raise AssertionError("Google-OFF retained startup contacted a provider")

    with patch.object(oauth, "request_bytes", side_effect=forbidden):
        validate_control_plane_startup()
        if operation == "seed-old":
            seed_saved_authority(workspace, config, db, store, schema, inputs, mutations)
        workspace.verify_signed(config, db, store, bundles)
        result = retained_snapshot(workspace, config, db, store, schema, profiles, mutations)
        assert contacts == [], "provider boundary was reached"
    verify_imports(source)
    return {"source": str(source.resolve()), "snapshot": result, "provider_contacts": 0,
        "fixture_aged_expiry": True, "natural_expiry_verified": False}


class OperatorRetainedUpgradeTests(unittest.TestCase):
    def setUp(self):
        # Environment and fresh scratch ownership use the existing bounded
        # persistence fixture, without importing application code in the parent.
        sys.path.insert(0, str(ROOT / "scripts"))
        import test_operator_demo_persistence as common
        common.OperatorDemoPersistenceTests.setUp(self)
        self.environment.update(SERVERWARE_PUBLIC_URL="https://control.example.com",
            SERVERWARE_OPERATOR_DEMO_UPSTREAMS='["https://api.example.com","https://demo-upstream:8443"]',
            SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS='["127.0.0.1/32"]',
            SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED="0")
        self.deadline = time.monotonic() + 180

    def child(self, operation):
        remaining = self.deadline - time.monotonic()
        self.assertGreater(remaining, 0, "retained upgrade deadline expired")
        source = PREVIOUS if operation == "seed-old" else ROOT
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=source, env=self.environment, capture_output=True, text=True, timeout=min(60, remaining))
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
        data = json.loads(result.stdout)
        self.assertEqual(data["source"], str(source.resolve()))
        self.assertEqual(data["provider_contacts"], 0)
        self.assertIs(data["fixture_aged_expiry"], True)
        self.assertIs(data["natural_expiry_verified"], False)
        return data["snapshot"]

    def test_old_source_saved_authority_survives_current_google_off_upgrade_and_reopen(self):
        self.assertTrue(PREVIOUS.is_dir(), "immutable old archive must be mounted read-only at /previous-app")
        self.assertTrue(ROOT.is_dir(), "immutable candidate archive must be mounted read-only at /candidate-app")
        seeded = self.child("seed-old")
        upgraded = self.child("upgrade")
        reopened = self.child("reopen")
        self.assertTrue(upgraded == seeded, "current startup changed retained authority, history, policy or key/CA bytes")
        self.assertTrue(reopened == seeded, "current reopen changed retained authority, history, policy or key/CA bytes")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(worker(sys.argv[2]), sort_keys=True))
    else:
        unittest.main(verbosity=2)

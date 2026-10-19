#!/usr/bin/env python3
"""One temporary SQLite fixture; no application, provider or live-store access."""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_operator_demo_persistence as common
import rename_synthetic_fixture_labels as rename


class FixtureLabelTests(unittest.TestCase):
    def test_exact_metadata_only_rename_and_refusals(self):
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        with tempfile.TemporaryDirectory(prefix="catchplate-fixture-label-test-") as directory:
            os.environ.update(common._ENVIRONMENT)
            os.environ.update(CATCHPLATE_DATA_DIR=directory,
                CATCHPLATE_OPERATOR_DEMO_UPSTREAMS='["https://demo-upstream:8443"]',
                CATCHPLATE_OPERATOR_DEMO_FIXTURE_CIDRS='["172.16.249.18/32"]')
            config, db, store, _ = common.backend()
            from catchplate import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
            from catchplate import operator_catalog_schema as schema

            def mutate(function, model, **values):
                with closing(db.connect()) as conn:
                    revision = schema.read_catalog(conn)["revision"]
                    policy_hash = conn.execute("SELECT policy_hash FROM operator_demo_policy").fetchone()[0]
                return function(model(expected_revision=revision, expected_policy_hash=policy_hash, **values), "fixture-test")

            def seed(stem):
                credential = mutate(mutations.create_credential, inputs.CredentialInput,
                    name=stem + "-credential", auth_type="bearer", secret="synthetic-fixture-only-secret")["credential"]
                application = mutate(mutations.create_application, inputs.ApplicationInput,
                    name=stem + "-application", token_lifetime_seconds=3600)["application"]
                rule = mutate(mutations.create_rule, inputs.RuleInput, name=stem + "-access_rule",
                    credential_id=credential["id"], application_id=application["id"],
                    upstream_url=rename.UPSTREAM, methods=["POST"], response_fields=["status"])["access_rule"]
                return credential, application, rule

            def snapshot():
                with closing(db.connect()) as conn:
                    return {"catalog": schema.read_catalog(conn), **{table: rename.rows(conn, table) for table in
                        ("credentials", "credential_generations", "operator_demo_policy", "audit_events")}}

            def files():
                return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in Path(directory).iterdir()
                        if path.is_file() and (path.suffix in {".pem", ".key"} or path == config.POLICY_BUNDLE_PATH)}

            stem = "serverware-live-smoke-" + "a" * 32
            selected, _, _ = seed(stem)
            revoked_stem = "serverware-live-basic-" + "b" * 32
            revoked = seed(revoked_stem)
            for function, item in zip((mutations.revoke_rule, mutations.revoke_application, mutations.revoke_credential),
                                      reversed(revoked)):
                mutate(function, inputs.TargetInput, id=item["id"])
            before, retained_files = snapshot(), files()
            manifest_path = Path(directory) / "rename-manifest.json"
            command = [sys.executable, "-B", str(Path(rename.__file__).resolve())]
            for arguments in (["--capture", str(manifest_path), "--run-stem", stem],
                              ["--manifest", str(manifest_path)]):
                completed = subprocess.run(command + arguments, capture_output=True, text=True, timeout=20)
                self.assertEqual(completed.returncode, 0, "CLI capture/dry-run failed")
                self.assertFalse(json.loads(completed.stdout)["applied"])
            self.assertTrue(snapshot() == before, "CLI capture/dry-run changed state")
            with patch("socket.socket", side_effect=AssertionError("No network allowed")):
                manifest = rename.operate(stems=[stem])
                self.assertEqual(json.loads(manifest_path.read_text()), manifest)
                self.assertEqual(rename.operate(manifest=manifest)["status"], "ready")
                self.assertTrue(snapshot() == before, "capture/dry-run changed state")
                self.assertNotIn("synthetic-fixture-only-secret", json.dumps(manifest))
                with self.assertRaises(ValueError):
                    rename.operate(stems=[revoked_stem])
                stale = deepcopy(manifest)
                stale["expected_revision"] += 1
                with self.assertRaises(ValueError):
                    rename.operate(manifest=stale, apply=True)
                swapped = deepcopy(manifest)
                swapped["changes"][0]["id"] = revoked[0]["id"]
                with self.assertRaises(ValueError):
                    rename.operate(manifest=swapped, apply=True)
                with closing(db.connect()) as conn, conn:
                    conn.execute("UPDATE credentials SET name=? WHERE id=?", ("counterpart mismatch", selected["id"]))
                mismatched = snapshot()
                with self.assertRaises(schema.CatalogIntegrityError):
                    rename.operate(manifest=manifest, apply=True)
                self.assertTrue(snapshot() == mismatched, "refusal changed state")
                with closing(db.connect()) as conn, conn:
                    conn.execute("UPDATE credentials SET name=? WHERE id=?", (stem + "-credential", selected["id"]))
                self.assertTrue(snapshot() == before, "negative controls changed state")
                result = rename.operate(manifest=manifest, apply=True)
                self.assertTrue(result["authority_secrets_tokens_unchanged"])
                after = snapshot()
                with self.assertRaises(ValueError):
                    rename.operate(manifest=manifest, apply=True)
            expected = deepcopy(before["catalog"])
            expected["revision"] += 1
            for collection in rename.KINDS:
                for row in expected[collection]:
                    if row["status"] == "active":
                        row["name"] = row["name"].replace("serverware-", "catchplate-", 1)
                        row["version"] += 1
            self.assertTrue(after["catalog"] == expected, "token, permission or revoked history changed")
            for old, new in zip(before["credentials"], after["credentials"]):
                self.assertTrue({**new, "name": old["name"], "updated_at": old["updated_at"]} == old,
                                "credential envelope changed")
            for table in ("operator_demo_policy", "credential_generations"):
                self.assertTrue(after[table] == before[table], "authority/generation changed")
            self.assertTrue(after["audit_events"][:-1] == before["audit_events"], "audit history changed")
            self.assertEqual(after["audit_events"][-1]["event_type"], "operator_catalog.synthetic_fixture_labels_renamed")
            self.assertTrue(files() == retained_files, "policy or key files changed")
            self.assertTrue(db.verify_audit_chain()["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Actual example/compiler/time gate; synthetic identity metadata, not TLS or JIT.

No database initialization, signing, provider request or deployed-policy claim.
The existing broad catalog is read for equivalence, not compiled or repaired.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TEMP = tempfile.TemporaryDirectory(prefix="npm-weekday-example-")
os.environ["SERVERWARE_DATA_DIR"] = TEMP.name
os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
for store in ("METADATA", "AUDIT", "GRANT"):
    os.environ[f"SERVERWARE_{store}_STORE_BACKEND"] = "sqlite"
    os.environ.pop(f"SERVERWARE_{store}_STORE_POSTGRES_DSN", None)

from serverware.constraints import _enforce_request_time_window
from serverware.policy_bundle import compile_policy_bundle


class NpmWeekdayHoursExampleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = json.loads((ROOT / "policies/npm-weekday-hours.example.json").read_text())
        cls.catalog = json.loads((ROOT / "policies/credential-limits.examples.json").read_text())
        cls.snapshot = compile_policy_bundle(cls.bundle, validate_schema=True)
        cls.principal = cls.bundle["principals"][0]
        mtls = cls.principal["mtls"]
        # Public placeholder pins supply a synthetic trusted-ingress fixture.
        # This does not authenticate a certificate or prove ingress custody.
        cls.evidence = {
            "verified": True,
            "san_spiffe_ids": mtls["sanSpiffeIds"],
            "san_dns_names": mtls["sanDnsNames"],
            "san_uris": mtls["sanUris"],
            "certificate_sha256": mtls["certificateSha256"],
            "spki_sha256": mtls["spkiSha256"],
            "issuer_spki_sha256": mtls["issuerSpkiSha256"],
        }

    def selected_route(self, headers=None):
        principal = self.snapshot.identify_principal("10.1.2.3", headers or {}, self.evidence)
        self.assertIsNotNone(principal)
        self.assertEqual(principal.id, "agent:example-mtls")
        match = self.snapshot.match_route(
            "https", "registry.npmjs.org", 443, "PUT", "/example-package", principal.id)
        self.assertIsNotNone(match)
        self.assertEqual(match.route.id, "example.npm.publish.weekday_utc.yubikey_jit")
        return match.route

    def test_self_contained_identity_and_original_npm_jit_contract(self):
        catalog_principal = next(
            p for p in self.catalog["principals"] if p["id"] == "agent:example-mtls")
        identity_fields = {"id", "sourceCidrs", "mtls"}
        self.assertEqual(len(self.bundle["principals"]), 1)
        self.assertEqual(set(self.principal), identity_fields)
        # A one-principal bundle needs no catalog-only disambiguation header.
        self.assertEqual(self.principal,
            {field: catalog_principal[field] for field in identity_fields})
        self.assertEqual(self.bundle["credentials"], [next(
            c for c in self.catalog["credentials"] if c["id"] == "cred-npm")])
        self.assertEqual(len(self.bundle["routes"]), 1)
        scheduled = self.bundle["routes"][0]
        expected = deepcopy(next(r for r in self.catalog["routes"]
            if r["id"] == "example.npm.publish.yubikey_jit"))
        expected.update(id=scheduled["id"], principals=["agent:example-mtls"])
        expected["constraints"].insert(0, scheduled["constraints"][0])
        self.assertEqual(scheduled, expected)
        self.assertTrue(scheduled["jit"]["approvers"]["authn"]["requireHardwareAttestation"])
        self.assertEqual(scheduled["adapter"]["config"]["credentialBinding"]["subjects"],
            ["replace-with-verified-npm-account"])
        legacy_header = {"X-Serverware-Agent": "example-agent"}
        for evidence in (None, {**self.evidence, "verified": False},
                {**self.evidence, "spki_sha256": "sha256:" + "0" * 64}):
            with self.subTest(evidence=evidence):
                self.assertIsNone(self.snapshot.identify_principal("10.1.2.3", legacy_header, evidence))
        self.selected_route(legacy_header)
        self.assertIsNone(self.snapshot.match_route(
            "https", "registry.npmjs.org", 443, "PUT", "/example-package", "agent:example"))

    def test_selected_example_allows_weekday_hours_and_denies_boundaries(self):
        schedules = [c for c in self.selected_route().constraints if c["type"] == "requestTimeWindow"]
        self.assertEqual(len(schedules), 1)
        schedule = schedules[0]
        self.assertEqual(schedule["timezone"], "UTC")
        self.assertEqual(schedule["weekdays"], ["mon", "tue", "wed", "thu", "fri"])
        self.assertEqual(schedule["dailyWindows"], [{"start": "09:00", "end": "17:00"}])
        self.assertIn("Illustrative", schedule["description"])
        for now, error in (
            (datetime(2026, 7, 13, 9, 0, tzinfo=timezone.utc), None),
            (datetime(2026, 7, 17, 16, 59, 59, tzinfo=timezone.utc), None),
            (datetime(2026, 7, 13, 8, 59, 59, tzinfo=timezone.utc), "request_time_daily_window_denied"),
            (datetime(2026, 7, 17, 17, 0, tzinfo=timezone.utc), "request_time_daily_window_denied"),
            (datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc), "request_time_weekday_denied"),
        ):
            with self.subTest(now=now):
                result = _enforce_request_time_window(schedule, now=now)
                self.assertEqual(result.allowed, error is None)
                if error is not None:
                    self.assertEqual(result.status_code, 403)
                    self.assertEqual(result.payload["error"], error)


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        TEMP.cleanup()

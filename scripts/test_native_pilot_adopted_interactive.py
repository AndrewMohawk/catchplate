#!/usr/bin/env python3
"""Pure selection/action/window controls, not an approved or running pilot.

The small public originals below exercise grammar and retained-window
arithmetic only. They are deliberately not signed admissions, protected
policy owners, native processes or successful application/cleanup fixtures.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import native_pilot_adopted_phase_profile as jobs
from catchplate import native_pilot_adopted_supervisor_policy as policy
from catchplate import native_pilot_interactive as interval

p = jobs.p
SECOND = 1_000_000_000
BOOT = (p.encoded(bytes(range(16))), 7, 8)
FAILURES = (ValueError, KeyError, TypeError)


def fixture(*, selected=True):
    fragment = {"apiVersion": interval.API, "stopAtBoottimeNanos": 4 * SECOND,
        "expiresAtUnixNanos": 104 * SECOND}
    value = {"apiVersion": policy.INTERACTIVE_API if selected else policy.API,
        "purpose": policy.INTERACTIVE_PURPOSE if selected else policy.PURPOSE,
        "source": {"revision": "a" * 40, "source_tree_digest": p.sha(b"tree"),
            "source_manifest_digest": p.sha(b"manifest"), "source_archive_digest": p.sha(b"archive"),
            "source_date_epoch": "1"},
        "conductorInventorySha256": p.sha(b"conductor"), "authorityInventorySha256": p.sha(b"authority"),
        "catalogueSha256": p.sha(policy.catalogue_original()),
        "bootstrapOriginals": {name: "{}" for name in policy.legacy.BOOTSTRAP_FIELDS},
        "keyBindings": {name: p.sha(name.encode("ascii")) for name in jobs.KEY_PURPOSES},
        "measuredRecipeSha256": p.sha(b"recipe"), "intakeConfigurationOriginal": "{}",
        "intakeConfigurationSha256": p.sha(b"{}")}
    if selected:
        value["interactive"] = fragment
    handoff = {"apiVersion": "catchplate.nativeGenerationOriginHandoff/v1", "okForAction": False,
        "automaticRetryAllowed": False, "originSha256": p.sha(b"origin")}
    action = {"action": "run-interactive", "originHandoffSha256": p.sha(p.canonical(handoff)),
        **{name: fragment[name] for name in interval.FIELDS[1:]}}
    options = dict(origin_handoff=handoff, deadline_boottime_ns=8 * SECOND,
        expires_at_unix_ns=105 * SECOND, now_boottime_ns=SECOND, now_unix_ns=100 * SECOND)
    return value, action, options


def window_fixture():
    window = dict(zip(("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"), BOOT, strict=True))
    window.update(issuedAtBoottimeNs="100000000", startupDeadlineBoottimeNs="500000000",
        lifetimeDeadlineBoottimeNs=str(10 * SECOND))
    originals = {
        "driverConfigurationOriginal": {"apiVersion": "catchplate.nativeShadowDriverBootstrapConfiguration/v4",
            "lifecycle": {"cleanupReserveNanos": 100_000_000}},
        "driverWindowOriginal": {"apiVersion": "catchplate.nativeShadowDriverBootstrapWindow/v1", "payload": copy.deepcopy(window)},
        "cohortPrecreationOriginal": {"apiVersion": "catchplate.nativeShadowProofCohortPrecreation/v1", "payload": copy.deepcopy(window)},
        "ordinaryLaunchOriginal": {"apiVersion": "catchplate.custodyFiveServiceLaunch/v7", **window}}
    production = {name: p.sha(name.encode("ascii")) for name in jobs.legacy.scope_authority.PRODUCTION_FIELDS}
    production.update(maximumRpcNanos=250_000_000, cleanupReserveNanos=200_000_000,
        maximumInFlightCalls=1, maximumAsyncDurabilityNanos=100_000_000)
    return originals, production


def literal_rows(originals):
    return {name: p.canonical(value).decode("ascii") for name, value in originals.items()}


class AdoptedInteractiveControls(unittest.TestCase):
    def test_explicit_successor_policy_and_unchanged_catalogue(self):
        old, _, _ = fixture(selected=False)
        new, _, _ = fixture()
        self.assertEqual(policy.shape(p.canonical(old)), old)
        self.assertEqual(policy.shape(p.canonical(new)), new)
        self.assertEqual(old["catalogueSha256"], new["catalogueSha256"])
        self.assertEqual(len(jobs.BY_NAME), 176)
        self.assertEqual(len(jobs.KEY_PURPOSES), 123)

    def test_policy_versions_purpose_and_unknown_fields_stay_closed(self):
        new, _, _ = fixture()
        cases = [dict(new, apiVersion=policy.API), dict(new, purpose=policy.PURPOSE),
            dict(new, apiVersion="catchplate.nativePilotAdoptedSupervisorPolicy/v3"),
            {name: value for name, value in new.items() if name != "interactive"},
            dict(new, command="curl"), dict(new, interactive={**new["interactive"], "durationNanos": SECOND})]
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(FAILURES):
                policy.shape(p.canonical(changed))

    def test_v1_refuses_interval_but_both_policies_can_stop(self):
        old, action, options = fixture(selected=False)
        with self.assertRaises(FAILURES):
            policy.require_shutdown(old, action, **options)
        for value in (old, fixture()[0]):
            self.assertEqual(policy.require_shutdown(value, {"action": "stop"}, **options), {"action": "stop"})
            with self.assertRaises(FAILURES):
                policy.require_shutdown(value, {"action": "stop", "approved": True}, **options)

    def test_exact_independent_interval_is_not_replaced_or_extended(self):
        value, action, options = fixture()
        self.assertEqual(policy.require_shutdown(value, action, **options), action)
        for field in interval.FIELDS[1:]:
            for delta in (-1, 1):
                with self.subTest(field=field, delta=delta), self.assertRaises(FAILURES):
                    policy.require_shutdown(value, {**action, field: action[field] + delta}, **options)

    def test_actual_origin_handoff_hash_and_nonready_flags_are_required(self):
        value, action, options = fixture()
        for field, replacement in (("originSha256", p.sha(b"another-origin")),
                ("okForAction", True), ("automaticRetryAllowed", True)):
            changed = {**options, "origin_handoff": {**options["origin_handoff"], field: replacement}}
            with self.subTest(field=field), self.assertRaises(FAILURES):
                policy.require_shutdown(value, action, **changed)

    def test_original_request_intake_and_live_clock_caps_refuse(self):
        value, action, options = fixture()
        cases = [dict(deadline_boottime_ns=action["stopAtBoottimeNanos"]),
            dict(expires_at_unix_ns=action["expiresAtUnixNanos"] - 1),
            dict(now_boottime_ns=action["stopAtBoottimeNanos"]),
            dict(now_unix_ns=action["expiresAtUnixNanos"]),
            dict(now_unix_ns=102 * SECOND)]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(FAILURES):
                policy.require_shutdown(value, action, **{**options, **change})

    def test_original_driver_cohort_and_ordinary_lifetimes_all_clip(self):
        originals, production = window_fixture()
        for field in ("driverWindowOriginal", "cohortPrecreationOriginal", "ordinaryLaunchOriginal"):
            changed = copy.deepcopy(originals)
            window = changed[field] if field == "ordinaryLaunchOriginal" else changed[field]["payload"]
            window["lifetimeDeadlineBoottimeNs"] = str(5 * SECOND)
            expected = 5 * SECOND - (interval.COHORT_REAP_RESERVE_NS if field == "cohortPrecreationOriginal" else 200_000_000)
            with self.subTest(field=field):
                self.assertEqual(jobs.interactive_deadline(literal_rows(changed), production, boot=BOOT), expected)

    def test_driver_production_and_fixed_cohort_reserves_are_preserved(self):
        originals, production = window_fixture()
        self.assertEqual(jobs.interactive_deadline(literal_rows(originals), production, boot=BOOT),
            10 * SECOND - interval.COHORT_REAP_RESERVE_NS)
        for selected in ("driver", "production"):
            changed, fields = copy.deepcopy(originals), dict(production)
            if selected == "driver": changed["driverConfigurationOriginal"]["lifecycle"]["cleanupReserveNanos"] = SECOND
            else: fields["cleanupReserveNanos"] = SECOND
            with self.subTest(selected=selected):
                self.assertEqual(jobs.interactive_deadline(literal_rows(changed), fields, boot=BOOT), 9 * SECOND)

    def test_wrong_boot_version_or_renewed_window_refused(self):
        originals, production = window_fixture()
        for field in ("driverWindowOriginal", "cohortPrecreationOriginal", "ordinaryLaunchOriginal"):
            for changed_field, replacement in (("timeNamespaceInode", 9),
                    ("startupDeadlineBoottimeNs", str(11 * SECOND))):
                changed = copy.deepcopy(originals)
                window = changed[field] if field == "ordinaryLaunchOriginal" else changed[field]["payload"]
                window[changed_field] = replacement
                with self.subTest(field=field, changed_field=changed_field), self.assertRaises(FAILURES):
                    jobs.interactive_deadline(literal_rows(changed), production, boot=BOOT)
        originals["ordinaryLaunchOriginal"]["apiVersion"] = "catchplate.custodyFiveServiceLaunch/v6"
        with self.assertRaises(FAILURES):
            jobs.interactive_deadline(literal_rows(originals), production, boot=BOOT)

    def test_retained_output_projection_keeps_all_original_caps_and_hashes(self):
        # Exercise the real multi-source reduction, not prepare_input's full
        # admission. Placeholder signature fields are deliberately never
        # passed off as valid signatures or actual retained owner evidence.
        originals, production = window_fixture()
        _, action, options = fixture()
        prior = {
            "install-precreation": {"input": p.canonical(literal_rows(originals)), "result": {}},
            "endpoint-inputs": {"input": p.canonical({"production": production}), "result": {"publicPinsOpened": True}}}

        def record(name, payload, *, ordinary=False):
            envelope = {"payload": payload,
                "signatureBase64url" if ordinary else "signature": p.encoded(bytes(64))}
            raw = p.canonical(envelope)
            prior[name] = {"input": b"{}", "result": {"original": raw.decode("ascii"), "sha256": p.sha(raw)}}

        common = {"issuedAtUnixNanos": 99 * SECOND, "expiresAtUnixNanos": 110 * SECOND}
        record("publication-adoption", {**common, "issuedAtBoottimeNanos": SECOND,
            "expiresAtBoottimeNanos": 8 * SECOND})
        for name in ("driver-bootstrap", "driver-constructed"):
            record(name, dict(common))
        for role in jobs.g.ROLES:
            record("ordinary-generation-" + role, {"apiVersion": "catchplate.custodyServiceGenerationGrant/v1",
                "purpose": "cold-service-generation-admission", "serviceRole": role,
                "issuedAtBoottimeNanos": SECOND, "expiresAtBoottimeNanos": 7 * SECOND,
                "scope": {"installationIssuedAtUnixNanos": 99 * SECOND,
                    "installationExpiresAtUnixNanos": 109 * SECOND}}, ordinary=True)
        observations = {"shutdown": {"originHandoff": options["origin_handoff"]}}
        clocks = dict(boot=BOOT, now_boottime_ns=options["now_boottime_ns"], now_unix_ns=options["now_unix_ns"])
        self.assertEqual(jobs._interactive_input(action, prior=prior, observations=observations, **clocks),
            {"deadline": action["stopAtBoottimeNanos"], "epochLimit": action["expiresAtUnixNanos"]})

        changes = [("publication-adoption", ("expiresAtBoottimeNanos",), action["stopAtBoottimeNanos"])]
        changes += [(name, ("expiresAtUnixNanos",), action["expiresAtUnixNanos"] - 1)
            for name in ("publication-adoption", "driver-bootstrap", "driver-constructed")]
        for role in jobs.g.ROLES:
            changes += [("ordinary-generation-" + role, ("expiresAtBoottimeNanos",), action["stopAtBoottimeNanos"]),
                ("ordinary-generation-" + role, ("scope", "installationExpiresAtUnixNanos"), action["expiresAtUnixNanos"] - 1),
                ("ordinary-generation-" + role, ("serviceRole",), "another-role")]
        for name, fields, replacement in changes:
            changed = copy.deepcopy(prior)
            envelope = json.loads(changed[name]["result"]["original"])
            target = envelope["payload"]
            for field in fields[:-1]: target = target[field]
            target[fields[-1]] = replacement
            raw = p.canonical(envelope)
            changed[name]["result"].update(original=raw.decode("ascii"), sha256=p.sha(raw))
            with self.subTest(name=name, fields=fields), self.assertRaises(FAILURES):
                jobs._interactive_input(action, prior=changed, observations=observations, **clocks)
        changed = copy.deepcopy(prior)
        changed["publication-adoption"]["result"]["sha256"] = p.sha(b"different-original")
        with self.assertRaises(FAILURES):
            jobs._interactive_input(action, prior=changed, observations=observations, **clocks)
        with self.assertRaises(FAILURES):
            jobs._interactive_input({**action, "originHandoffSha256": p.sha(b"different-handoff")},
                prior=prior, observations=observations, **clocks)


if __name__ == "__main__":
    unittest.main()

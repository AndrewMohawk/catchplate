#!/usr/bin/env python3
"""Pure selected wire/CLI/publication controls, never fake process owners.

These controls do not create a protected installer, sender, received core,
signer or runtime child. Synthetic pins exercise exact public selectors only.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import run_native_pilot_supervisor as cli
from scripts import native_pilot_supervisor_runtime_entrypoint as entry
from serverware import native_pilot_adopted_publication as adopted
from serverware import native_pilot_coordinator_channel as wire
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_publication as publisher
from serverware import native_pilot_publication_profiles as profiles

p = wire.p


def request(*, selected=False):
    value = {"apiVersion": "serverware.nativePilotOperatorRequest/v" + ("2" if selected else "1"),
        "sequence": 1, "phase": "bootstrap-admission", "payload": {"synthetic": True}, "deadlineBoottimeNs": "200"}
    if selected:
        value["expiresAtUnixNanos"] = "300"
    return value


def parse(value, *, selected=False):
    return wire.request_value(p.canonical(value), sequence=1, phase="bootstrap-admission", upper_deadline=200,
        adopted=selected, expires_at_unix_ns=300 if selected else None)


def arguments(*, selected=False):
    prefix = cli._PREFIX
    if selected:
        prefix = prefix[:10] + (("intake-configuration-fd", "fd"), ("intake-configuration-sha256", "sha")) + prefix[10:]
    values = ["--run-adopted-native-pilot" if selected else "--run-native-pilot"]
    for index, (name, kind) in enumerate(prefix):
        value = "sha256:" + "a" * 64 if kind == "sha" else "0" if kind == "id" else str(index + 10)
        values += ["--" + name, value]
    return values + ["--authority-key", "selected-purpose=100"]


class AdoptedOrchestrationControls(unittest.TestCase):
    def test_exact_selected_requests_keep_original_wire(self):
        for selected in (False, True):
            value = request(selected=selected)
            self.assertEqual(parse(value, selected=selected), value)

    def test_request_profiles_do_not_cross(self):
        for selected in (False, True):
            with self.assertRaises(ValueError): parse(request(selected=not selected), selected=selected)

    def test_expiry_cannot_be_missing_extended_or_noncanonical(self):
        for expiry in (None, "301", "0300", "0", 300, True):
            value = request(selected=True); value["expiresAtUnixNanos"] = expiry
            with self.assertRaises(ValueError): parse(value, selected=True)
        value = request(selected=True); value.pop("expiresAtUnixNanos")
        with self.assertRaises(ValueError): parse(value, selected=True)

    def test_phase_sequence_deadline_and_fields_are_closed(self):
        for field, changed in (("sequence", True), ("sequence", 2), ("phase", "shutdown"),
                ("deadlineBoottimeNs", "201"), ("approved", True)):
            value = request(selected=True); value[field] = changed
            with self.assertRaises(ValueError): parse(value, selected=True)

    def test_actual_supervisor_cli_has_separate_explicit_intake_input(self):
        for selected in (False, True):
            values = arguments(selected=selected)
            self.assertTrue(entry.valid_arguments(values))
            parsed = cli._arguments(values, ("selected-purpose",), adopted=selected)
            self.assertEqual("intake_configuration_fd" in parsed, selected)
            with self.assertRaises(ValueError): cli._arguments(values, ("selected-purpose",), adopted=not selected)

    def test_supervisor_refuses_extra_missing_or_duplicate_intake_fd(self):
        values = arguments(selected=True)
        self.assertFalse(entry.valid_arguments(values + ["--unknown", "9"]))
        without = values[:21] + values[25:]
        self.assertFalse(entry.valid_arguments(without))
        values[22] = values[2]
        self.assertFalse(entry.valid_arguments(values))
        with self.assertRaises(ValueError): cli._arguments(values, ("selected-purpose",), adopted=True)

    def test_adopted_publication_slots_and_limits_are_fixed(self):
        self.assertEqual(len(adopted.LIMITS), 7)
        self.assertEqual(adopted.LIMITS["publication-adoption"], 2 * 1024 * 1024)
        for role in adopted.ordinary.ROLES:
            self.assertEqual(adopted.LIMITS["ordinary-publication-" + role], 3 * 1024 * 1024)
            self.assertEqual(adopted.DESTINATIONS["ordinary-initial-history-" + role],
                profiles.DESTINATIONS["ordinary-initial-history-" + role])
        self.assertNotIn("publication-adoption", publisher.DESTINATIONS)

    def test_publication_profile_flags_are_not_interchangeable(self):
        destinations, _, _ = publisher._selected_profile(adopted=False, adopted_bridge=False, adopted_ordinary=True)
        self.assertEqual(destinations, adopted.DESTINATIONS)
        for flags in ((True, False, True), (False, True, True), (1, False, False)):
            with self.assertRaises(ValueError): publisher._selected_profile(
                adopted=flags[0], adopted_bridge=flags[1], adopted_ordinary=flags[2])

    def test_precreation_publication_selects_actual_twenty_file_profile(self):
        for purpose, mode in (("ordinary-launch", "adopted_ordinary"), ("cohort-configuration", "adopted_ordinary"),
                ("native-cold-publicationReconciliation", "adopted"), ("cohort-control", "legacy")):
            destinations, limits, _, selected = precreation._publication(purpose, adopted=True)
            self.assertEqual(selected, mode)
            self.assertIn(purpose, destinations); self.assertGreater(limits[purpose], 0)
        self.assertEqual(len(precreation.cohort.ADOPTED_ENDPOINT_ROLES) + 9, 20)

    def test_precreation_cannot_silently_upgrade_old_bundle(self):
        for selected in (False, True):
            value = dict.fromkeys(precreation.FIELDS)
            value["apiVersion"] = "serverware.nativePilotPrecreationBundle/v" + ("1" if selected else "2")
            raw = p.canonical(value)
            with self.assertRaises(ValueError): precreation._prepare(raw, p.sha(raw), adopted=selected)


if __name__ == "__main__":
    unittest.main()

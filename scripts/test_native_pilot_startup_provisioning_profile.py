#!/usr/bin/env python3
"""Pure late projections using signed synthetic sources, not live authority.

The existing startup fixture provides inert inventories and explicitly synthetic
process/socket observations. Unreached policy selections remain that fixture's
declared placeholders, not a valid full lifecycle. No owner or successful
validator is fabricated, replaced or mocked.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts import test_native_pilot_startup_profile as startup_fixture
from catchplate import native_pilot_startup_provisioning_profile as profile

p, startup = profile.p, profile.startup
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)


def fixture(parent):
    source = startup_fixture.fixture(parent)
    config = source["configuration"]
    provider = startup.policy.shape(source["sources"]["provider-policy"])
    decision = p.document(source["sources"]["decision-configuration"], startup.decisions.MAX_CONFIGURATION)
    value = dict(apiVersion=profile.API, purpose=profile.PURPOSE,
        configurationSha256=p.sha(source["configuration_raw"]), supervisorInventorySha256=p.sha(source["inventory_raw"]),
        measuredRecipeSha256=p.sha(source["sources"]["recipe"]),
        conductorInventorySha256=p.sha(source["sources"]["conductor-inventory"]),
        authorityInventorySha256=p.sha(source["sources"]["authority-inventory"]),
        **{name: config[name] for name in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos")},
        providerPolicy={name: provider[name] for name in profile.PROVIDER_FIELDS},
        decisionConfiguration={name: decision[name] for name in profile.DECISION_FIELDS})
    arguments = dict(configuration_original=source["configuration_raw"], recipe_original=source["sources"]["recipe"],
        conductor_inventory_original=source["sources"]["conductor-inventory"],
        authority_inventory_original=source["sources"]["authority-inventory"], supervisor_inventory_original=source["inventory_raw"])
    return dict(startup=source, value=value, arguments=arguments, clocks=source["clocks"])


def prepared(source, value=None, **changes):
    return profile.prepare(profile.canonical(source["value"] if value is None else value),
        **(source["arguments"] | source["clocks"] | changes))


def composed(source, value=None, **clocks):
    return profile.compose(prepared(source, value), source["startup"]["observation_raw"], **(source["clocks"] | clocks))


class StartupProvisioningProfileControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix="startup-provisioning-profile-")
        cls.addClassCleanup(directory.cleanup)
        cls.addClassCleanup(startup_fixture.policy_fixture.source_fixture.runtime_fixture.thaw, Path(directory.name))
        cls.source = fixture(Path(directory.name))

    def test_three_observed_projections_produce_exact_existing_six_sources_and_admission(self):
        source = self.source; context = prepared(source); before = copy.deepcopy(context)
        result = profile.compose(context, source["startup"]["observation_raw"], **source["clocks"])
        self.assertEqual(context, before)
        self.assertEqual(set(result), {"originals", "admissionOriginal", "deadline", "epochLimit"})
        self.assertEqual(result["originals"], source["startup"]["sources"])
        self.assertEqual(result["admissionOriginal"], p.canonical(source["startup"]["admission"]))
        admitted = startup.admission(result["admissionOriginal"], configuration_raw=source["arguments"]["configuration_original"],
            observation_raw=source["startup"]["observation_raw"], source_originals=result["originals"],
            supervisor_inventory_original=source["arguments"]["supervisor_inventory_original"], **source["clocks"])
        self.assertEqual(admitted["peers"], source["startup"]["peers"])
        self.assertEqual(set(result["originals"]), set(startup.SOURCE_NAMES))

    def test_closed_delegation_has_no_future_peers_templates_keys_or_commands(self):
        for change in ("peer", "decision-peer", "template", "command", "private-key", "purpose", "omitted"):
            value = copy.deepcopy(self.source["value"])
            if change == "peer": value["providerPolicy"]["lifecyclePeer"] = self.source["startup"]["peers"]["lifecycle"]
            elif change == "decision-peer": value["decisionConfiguration"]["providerPeer"] = {}
            elif change == "omitted": del value["providerPolicy"]["cold"]
            elif change == "purpose": value["purpose"] = "approve-everything"
            else: value[change] = "not permitted"
            with self.subTest(change=change), self.assertRaises(ERRORS): prepared(self.source, value)

    def test_all_five_fixed_original_pins_are_independent_exact_inputs(self):
        for name in self.source["arguments"]:
            with self.subTest(source=name), self.assertRaises(ERRORS):
                prepared(self.source, **{name: self.source["arguments"][name] + b" "})
        value = copy.deepcopy(self.source["value"])
        value["providerPolicy"]["measuredRecipeSha256"] = p.sha(b"other recipe")
        with self.assertRaises(ERRORS): prepared(self.source, value)

    def test_wait_uses_original_startup_while_admission_preserves_role_lifetime(self):
        source = self.source; context = prepared(source); result = composed(source)
        admission = p.document(result["admissionOriginal"], startup.MAX_ADMISSION)
        listener = p.document(result["originals"]["listener-configuration"], startup.SOURCE_LIMITS["listener-configuration"])
        self.assertLessEqual(context["deadline"], p.ns(listener["window"]["startupDeadlineBoottimeNs"]))
        self.assertLess(context["deadline"], p.ns(admission["deadlineBoottimeNs"]))
        self.assertEqual(admission["deadlineBoottimeNs"], source["value"]["deadlineBoottimeNs"])
        self.assertEqual(admission["expiresAtUnixNanos"], source["value"]["expiresAtUnixNanos"])
        self.assertLessEqual(result["deadline"], context["deadline"])
        for change in ({"now_boottime_ns": context["deadline"]}, {"now_unix_ns": context["epochLimit"]},
                {"boot": (source["clocks"]["boot"][0], 1, 999)}):
            with self.subTest(change=change), self.assertRaises(ERRORS): prepared(source, **change)

    def test_repeated_pure_projection_does_not_renew_any_clock_or_static_selection(self):
        source = self.source; now = source["clocks"]["now_boottime_ns"]
        self.assertLess(now + 1, prepared(source)["deadline"])
        first, later = composed(source), composed(source, now_boottime_ns=now + 1)
        self.assertEqual(first, later)
        provider = startup.policy.shape(first["originals"]["provider-policy"])
        decision = p.document(first["originals"]["decision-configuration"], startup.decisions.MAX_CONFIGURATION)
        self.assertEqual({name: provider[name] for name in profile.PROVIDER_FIELDS}, source["value"]["providerPolicy"])
        self.assertEqual({name: decision[name] for name in profile.DECISION_FIELDS}, source["value"]["decisionConfiguration"])

    def test_actual_observation_graph_and_retained_context_cannot_be_substituted(self):
        source = self.source; observed = p.document(source["startup"]["observation_raw"], startup.MAX_OBSERVATION)
        ready = p.document(observed["ready"]["lifecycle"].encode("ascii"), startup.MAX_MESSAGE)
        ready["sockets"]["lifecycle"]["peer"] = source["startup"]["peers"]["decisions"]
        observed["ready"]["lifecycle"] = p.canonical(ready).decode("ascii")
        with self.assertRaises(ERRORS): profile.compose(prepared(source), p.canonical(observed), **source["clocks"])
        context = prepared(source); context["deadline"] += 1
        with self.assertRaises(ERRORS): profile.compose(context, source["startup"]["observation_raw"], **source["clocks"])

    def test_full_existing_policy_validator_keeps_current_head_decisions_external(self):
        value = copy.deepcopy(self.source["value"])
        name = startup.policy.HEADS[0]
        value["providerPolicy"]["adopted"][name] = dict(rule=startup.policy.DERIVE, selection={})
        with self.assertRaises(ERRORS): composed(self.source, value)

    def test_original_admission_bounds_cannot_hide_longer_resumed_role_limits(self):
        source = self.source
        for field, value in (("deadlineBoottimeNs", str(p.ns(source["value"]["deadlineBoottimeNs"]) - 1)),
                ("expiresAtUnixNanos", source["value"]["expiresAtUnixNanos"] - 1)):
            selected = copy.deepcopy(source["value"]); selected[field] = value
            with self.subTest(field=field), self.assertRaises(ERRORS): prepared(source, selected)

    def test_provider_unsigned_source_codec_is_not_replaced_by_signed_i64_codec(self):
        value = copy.deepcopy(self.source["value"])
        # Unreached fragment only: this checks source grammar, not a valid
        # closure-set selection or permission to execute that candidate.
        row = next(row for row in value["providerPolicy"]["cold"].values() if row["selection"])
        row["selection"][next(iter(row["selection"]))] = p.MAX_U64
        raw = profile.canonical(value)
        self.assertEqual(profile._delegation(raw), value)
        with self.assertRaises(ERRORS): p.canonical(value)
        self.assertEqual(profile.MAX_DELEGATION, startup.policy.MAX_POLICY)


if __name__ == "__main__": unittest.main()

#!/usr/bin/env python3
"""Static successor selection controls; no assignment or live authority is made.

Fixtures have deliberately invalid signatures and synthetic provenance. These
tests exercise input selection and exact root/anchor joins, not native trust,
signing, measured images or operational commissioning.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import test_native_pilot_closure_set as fixtures
from catchplate import native_pilot_assignment as assignment
from catchplate import native_pilot_closure_set as closure


def selected(api):
    roles = {closure.API: closure.ROLES, closure.GENESIS_API: closure.GENESIS_ROLES,
        closure.PUBLICATION_API: closure.PUBLICATION_ROLES}[api]
    raw = closure.set_original([
        {"role": role, "manifest": fixtures.manifest_fixture(role)} for role in roles], api_version=api)
    return raw, closure.validate(raw, api_version=api), roles


def input_value(api=None):
    value = {"apiVersion": "catchplate.nativePilotAssignmentAuthorityInput/v1",
        "trustOriginal": "{}", "trustSha256": fixtures.synthetic("trust"),
        "payloadOriginal": "{}", "closureSetOriginal": "{}"}
    if api is not None:
        value.update(apiVersion="catchplate.nativePilotAssignmentAuthorityInput/v2", setApiVersion=api)
    return value


class AssignmentProfileTests(unittest.TestCase):
    def test_legacy_input_still_selects_only_eleven(self):
        value = input_value()
        self.assertEqual(assignment.input_document(fixtures.canonical(value)), (value, closure.API))
        value["setApiVersion"] = closure.GENESIS_API
        with self.assertRaises(ValueError):
            assignment.input_document(fixtures.canonical(value))

    def test_successor_requires_explicit_known_nonlegacy_selector(self):
        for api in (closure.GENESIS_API, closure.PUBLICATION_API):
            with self.subTest(api=api):
                value = input_value(api)
                self.assertEqual(assignment.input_document(fixtures.canonical(value)), (value, api))
        for api in (closure.API, "catchplate.nativeCustodyExecutionClosureSet/v3", None, 2):
            value = input_value(closure.GENESIS_API)
            value["setApiVersion"] = api
            with self.subTest(api=api), self.assertRaises(ValueError):
                assignment.input_document(fixtures.canonical(value))
        value = input_value(closure.GENESIS_API)
        del value["setApiVersion"]
        with self.assertRaises(ValueError):
            assignment.input_document(fixtures.canonical(value))

    def test_input_canonical_and_closed(self):
        value = input_value(closure.PUBLICATION_API)
        with self.assertRaises(ValueError):
            assignment.input_document(fixtures.canonical(value) + b"\n")
        value["futureGenerationSha256"] = fixtures.synthetic("not part of assignment input")
        with self.assertRaises(ValueError):
            assignment.input_document(fixtures.canonical(value))

    def test_every_explicit_successor_member_joins_exact_assignment(self):
        for api in (closure.GENESIS_API, closure.PUBLICATION_API):
            raw, value, roles = selected(api)
            envelope = fixtures.assignment_fixture(value)
            for role in roles:
                with self.subTest(api=api, role=role):
                    actual = assignment.closure_binding(envelope, raw, role, set_api_version=api)
                    self.assertEqual(actual, closure.leaf_binding(value, role, api_version=api))

    def test_no_implicit_successor_selection_or_cross_profile(self):
        for api in (closure.GENESIS_API, closure.PUBLICATION_API):
            raw, value, roles = selected(api)
            envelope = fixtures.assignment_fixture(value)
            with self.subTest(api=api), self.assertRaises(ValueError):
                assignment.closure_binding(envelope, raw, roles[0])
            other = closure.PUBLICATION_API if api == closure.GENESIS_API else closure.GENESIS_API
            with self.subTest(api=api), self.assertRaises(ValueError):
                assignment.closure_binding(envelope, raw, roles[0], set_api_version=other)

    def test_changed_anchor_and_roots_refuse_even_with_rehashed_payload(self):
        for api in (closure.GENESIS_API, closure.PUBLICATION_API):
            raw, value, roles = selected(api)
            envelope = fixtures.assignment_fixture(value)
            for field in ("executionClosureManifestSha256", "structurallyVerifiedSeccompPolicySha256"):
                changed = copy.deepcopy(envelope)
                changed["payload"]["custodyAuthority"][field] = fixtures.synthetic("wrong " + field)
                fixtures.rehash_payload(changed)
                with self.subTest(api=api, field=field), self.assertRaises(ValueError):
                    assignment.closure_binding(changed, raw, roles[0], set_api_version=api)
            for field in ("setRootSha256", "seccompSetRootSha256"):
                changed = copy.deepcopy(envelope)
                changed["payload"]["nativeClosureSet"][field] = fixtures.synthetic("wrong " + field)
                fixtures.rehash_payload(changed)
                with self.subTest(api=api, field=field), self.assertRaises(ValueError):
                    assignment.closure_binding(changed, raw, roles[0], set_api_version=api)

    def test_cold_anchor_is_coordinator_not_other_member(self):
        raw, value, roles = selected(closure.GENESIS_API)
        envelope = fixtures.assignment_fixture(value)
        wrong = value["members"][0]["manifest"]
        envelope["payload"]["custodyAuthority"].update(
            executionClosureManifestSha256=wrong["manifestSha256"],
            structurallyVerifiedSeccompPolicySha256=wrong["seccompPolicy"]["structurallyVerifiedPolicySha256"])
        fixtures.rehash_payload(envelope)
        with self.assertRaises(ValueError):
            assignment.closure_binding(envelope, raw, roles[0], set_api_version=closure.GENESIS_API)


if __name__ == "__main__":
    unittest.main()
